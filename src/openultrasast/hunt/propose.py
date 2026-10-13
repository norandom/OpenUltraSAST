"""Propose one program change using compile folds and keep a compile-only history.

Pass an optimiser name, a configured DSPy optimiser, or a callable taking
(program, examples, metric) and returning a compiled program. Callables receive
copies: neither the baseline nor the labels used for scoring can be edited.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterator, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .. import stats
from .metric import search_metric, search_outcome
from .table import FEATURE_COLUMNS, canonical_json


class _Optimisers(Mapping):
    """Load a DSPy optimiser class only when its registry entry is requested."""

    names = {"gepa": "GEPA", "miprov2": "MIPROv2", "bootstrap": "BootstrapFewShot"}

    def __getitem__(self, name: str) -> type:
        import dspy

        return getattr(dspy, self.names[name])

    def __iter__(self) -> Iterator[str]:
        return iter(self.names)

    def __len__(self) -> int:
        return len(self.names)


OPTIMISERS = _Optimisers()


@dataclass(frozen=True)
class Round:
    """Register one editable surface, the compile folds, and the run's bounds."""

    kind: str
    base_program_id: str
    compile_folds: list[int]
    seed: int
    optimiser: str
    budget: Mapping[str, float]

    def __post_init__(self) -> None:
        """Refuse ambiguous kinds, empty folds, and invalid budget bounds."""
        if self.kind not in ("instruction", "demos", "mask"):
            raise ValueError("round kind must name exactly one of instruction, demos or mask")
        if not self.compile_folds or any(type(f) is not int or f < 0 for f in self.compile_folds):
            raise ValueError("compile folds must be nonempty non-negative integers")
        if len(set(self.compile_folds)) != len(self.compile_folds):
            raise ValueError("compile folds cannot repeat")
        if set(self.budget) != {"usd", "calls"} or any(not math.isfinite(v) or v < 0 for v in self.budget.values()):
            raise ValueError("budget requires finite non-negative usd and calls")
        if int(self.budget["calls"]) != self.budget["calls"]:
            raise ValueError("call budget must be an integer")


class CompileExamples(list):
    """A list of DSPy examples with the change and fold provenance alongside it."""

    @property
    def provenance(self) -> list[dict[str, Any]]:
        """Return only the identifiers needed to audit the proposer's population."""
        return [{"change_id": e.change_id, "fold": e.fold} for e in self]


def compile_examples(
    changes: Sequence[Mapping[str, Any]],
    rows_by_change: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    compile_folds: Sequence[int],
    render: Callable,
) -> list:
    """Build examples only for compile folds, with scoring labels outside inputs.

    Render takes (change, rows) and calls program.render_rows with source texts
    bound by the caller, just as runner.hunt_change supplies its checkout texts.
    It receives only feature rows and no advisory or verification metadata.
    The returned list's provenance property is written by propose to
    proposer_inputs.json. No held-out rows are accessed or rendered.
    """
    import dspy

    from .program import INPUTS

    repo_folds, ids = {}, set()
    for change in changes:
        if change["id"] in ids:
            raise ValueError("change IDs must be unique")
        ids.add(change["id"])
        if change["repo"] in repo_folds and repo_folds[change["repo"]] != change["fold"]:
            raise ValueError("a repository cannot cross folds")
        repo_folds[change["repo"]] = change["fold"]
    examples = CompileExamples()
    for change in changes:
        if change["fold"] not in compile_folds:
            continue
        rows = rows_by_change[change["id"]]
        if any(row.get("fold", change["fold"]) != change["fold"] for row in rows):
            raise ValueError("row folds disagree with the change")
        safe_rows = [{k: deepcopy(v) for k, v in row.items() if k in (*FEATURE_COLUMNS, "path", "line")} for row in rows]
        inputs = render({"id": change["id"]}, safe_rows)
        if set(inputs) - {name for name, _, _ in INPUTS} or any(not isinstance(v, str) for v in inputs.values()):
            raise ValueError("renderer must return only the hunt signature's text inputs")
        metric_change = {k: deepcopy(change[k]) for k in ("kind", "family", "path", "function", "function_lines") if k in change}
        metric_change["files"] = [
            {k: deepcopy(file[k]) for k in ("path", "head_lines", "function_lines") if k in file} for file in change.get("files", [])
        ]
        examples.append(
            dspy.Example(**inputs, change=metric_change, change_id=change["id"], repo=change["repo"], fold=change["fold"]).with_inputs(
                *inputs
            )
        )
    return examples


@dataclass(frozen=True)
class Candidate:
    """A saved proposal and compile evidence, with enough baseline state to audit edits."""

    program_id: str
    kind: str
    change: dict[str, Any]
    compile_score: dict[str, Any]
    state: dict[str, Any]
    base_program_id: str
    base_state: dict[str, Any]
    mask: tuple[str, ...]
    base_mask: tuple[str, ...]
    out_dir: str


def changed_surfaces(base: Mapping, candidate: Mapping, base_mask: Sequence[str], mask: Sequence[str]) -> set[str]:
    """Compare saved predictor states, permitting only instructions, demos or one mask.

    Signature field removal or addition is part of masking. Every surviving
    field must retain its description. Other saved settings cannot be edited.
    """
    from .program import INPUTS, signature_for

    before, after = deepcopy(dict(base)), deepcopy(dict(candidate))
    changed = set()
    mask_changed = set(base_mask) != set(mask)
    if mask_changed:
        allowed = {name for name, _, _ in INPUTS} | set(FEATURE_COLUMNS) | {"diff", "source", "semantic", "taxonomy"}
        if (set(mask) | set(base_mask)) - allowed or len(set(base_mask) ^ set(mask)) != 1:
            raise ValueError("one mask annotation may change per round")
        changed.add("mask")
    if set(before) != set(after):
        raise ValueError("predictor structure is not an editable surface")
    for name in before:
        left, right = before[name], after[name]
        for key, kind in (("demos", "demos"),):
            if left.pop(key, []) != right.pop(key, []):
                changed.add(kind)
        ls, rs = left.get("signature", {}), right.get("signature", {})
        if ls.pop("instructions", None) != rs.pop("instructions", None):
            changed.add("instruction")
        if mask_changed:
            # Check the exact expected field transition, including ReAct's extra fields.
            old = signature_for(base_mask).dump_state()["fields"]
            new = signature_for(mask).dump_state()["fields"]
            removed = [field for field in old if field not in new]
            added = [field for field in new if field not in old]
            lf, rf = ls.get("fields", []), rs.get("fields", [])
            if [f for f in lf if f not in removed] != [f for f in rf if f not in added]:
                raise ValueError("mask changed unrelated signature fields")
            if any(f not in lf for f in removed) or any(f not in rf for f in added):
                raise ValueError("mask does not match signature fields")
            ls.pop("fields", None)
            rs.pop("fields", None)
    if before != after:
        raise ValueError("only instructions, demos or mask may change")
    return changed


def _change(kind: str, state: Mapping, examples: Sequence, mask: Sequence[str]) -> dict[str, Any]:
    """Describe the actual edit, tracing every demonstration to compile inputs."""
    if kind == "instruction":
        return {"instruction": {name: value["signature"]["instructions"] for name, value in state.items()}}
    if kind == "mask":
        return {"mask": list(mask)}
    demos = [demo for value in state.values() for demo in value.get("demos", [])]
    ids = set()
    for demo in demos:
        matches = [e.change_id for e in examples if all(demo.get(k) == v for k, v in e.inputs().items())]
        if not matches:
            raise ValueError("demonstrations must come from compile examples")
        ids.update(matches)
    return {"demos": {"count": len(demos), "change_ids": sorted(ids)}}


def _score(program: Any, examples: Sequence) -> list[dict[str, Any]]:
    """Run each example once with inputs limited to this program's mask."""
    from .program import signature_for

    wanted = signature_for(program.mask).input_fields
    outcomes = []
    for example in examples:
        inputs = {k: v for k, v in example.inputs().items() if k in wanted}
        if set(inputs) != set(wanted):
            raise ValueError("examples lack an unmasked input; render full inputs before proposing")
        prediction = program(**inputs)
        outcome = search_outcome(example.change, prediction.findings)
        outcomes.append(
            {"change_id": example.change_id, "repo": example.repo, "fold": example.fold, "kind": example.change["kind"], **asdict(outcome)}
        )
    return outcomes


def _compile(round: Round, program: Any, examples: list, optimiser: Any, metric: Callable) -> Any:
    """Adapt the named optimisers without ever supplying a held-out validation set."""
    import dspy

    if isinstance(optimiser, str):
        if optimiser != round.optimiser:
            raise ValueError("optimiser differs from the registered round")
        cls = OPTIMISERS[optimiser]
        if optimiser == "gepa":
            if dspy.settings.lm is None:
                raise ValueError("GEPA needs a configured reflection model in dspy.context")

            def feedback(example, prediction, trace=None, pred_name=None, pred_trace=None):
                """Give GEPA the same score and the metric's compile-only feedback."""
                import dspy

                outcome = search_outcome(example.change, prediction.findings)
                return dspy.Prediction(score=metric(example, prediction, trace), feedback=outcome.feedback)

            optimiser = cls(metric=feedback, max_metric_calls=int(round.budget["calls"]), seed=round.seed, reflection_lm=dspy.settings.lm)
        elif optimiser == "miprov2":
            optimiser = cls(metric=metric, seed=round.seed, max_bootstrapped_demos=0, max_labeled_demos=0)
        else:
            optimiser = cls(metric=metric, max_labeled_demos=0)
    if isinstance(optimiser, dspy.MIPROv2):
        # DSPy's dataset summary serializes whole examples, including metric labels.
        return optimiser.compile(program, trainset=examples, data_aware_proposer=False)
    if hasattr(optimiser, "compile"):
        return optimiser.compile(program, trainset=examples)
    return optimiser(program, examples, metric)


def propose(
    round: Round, program: Any, examples: list, *, optimiser: Any, metric: Callable = search_metric, out_dir: Path | str
) -> Candidate:
    """Compile a copy, validate its one edit, score against the base, and save it.

    The saved state is candidates/<program_id>.json. The history contains only
    the edit and compile score; comparisons and held-out measurements are kept
    separately by accept. A callable optimiser must respect the registered
    money and call bounds; these are recorded in round.json for audit.
    """
    from .program import program_id

    round.__post_init__()
    base_mask = tuple(program.mask)
    if round.base_program_id != program_id(program, mask=base_mask):
        raise ValueError("round base program ID does not match")
    if not examples or any(e.fold not in round.compile_folds for e in examples):
        raise ValueError("proposer examples must come only from compile folds")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _write(out / "proposer_inputs.json", [{"change_id": e.change_id, "fold": e.fold} for e in examples])
    _write(out / "round.json", asdict(round))
    base = program.deepcopy()
    scoring_examples = deepcopy(examples)
    state = deepcopy(base.dump_state())
    compiled = _compile(round, program.deepcopy(), deepcopy(scoring_examples), optimiser, metric)
    mask = tuple(compiled.mask)
    candidate_state = deepcopy(compiled.dump_state())
    if changed_surfaces(state, candidate_state, base_mask, mask) != {round.kind}:
        raise ValueError("a round must change exactly one declared surface")
    change = _change(round.kind, candidate_state, scoring_examples, mask)
    base_outcomes = _score(base, scoring_examples)
    outcomes = _score(compiled, scoring_examples)
    import pandas as pd

    paired = {}
    for kind, field, name in (("vulnerability", "hit", "recall"), ("ordinary", "suspicions", "suspicions_per_push")):
        frame = pd.DataFrame(
            [
                {"repo": b["repo"], "base": a[field], "candidate": b[field]}
                for a, b in zip(base_outcomes, outcomes, strict=True)
                if b["kind"] == kind
            ],
            columns=["repo", "base", "candidate"],
        )
        paired[name] = asdict(stats.paired_bootstrap(frame, "repo", "base", "candidate", seed=round.seed))
    positives = [o for o in outcomes if o["kind"] == "vulnerability"]
    hits = sum(o["hit"] for o in positives)
    score = {
        "recall": hits / len(positives) if positives else None,
        "ci": stats.wilson(hits, len(positives)),
        "hits": hits,
        "positive_units": len(positives),
        "ordinary_units": len(outcomes) - len(positives),
        "paired": paired,
        "outcomes": outcomes,
        "base_outcomes": base_outcomes,
    }
    candidate = Candidate(
        program_id(compiled, mask=mask), round.kind, change, score, candidate_state, round.base_program_id, state, mask, base_mask, str(out)
    )
    _write(out / "candidates" / f"{candidate.program_id}.json", asdict(candidate))
    _append(out / "candidates.jsonl", proposer_record(candidate))
    return candidate


def proposer_record(candidate: Candidate) -> dict[str, Any]:
    """Return only the fields that belong in the compile-only history."""
    return {name: deepcopy(getattr(candidate, name)) for name in ("program_id", "kind", "change", "compile_score")}


def visible_to_proposer(out_dir: Path | str) -> list[dict[str, Any]]:
    """Read every past proposal, irrespective of acceptance, without reading comparisons."""
    path = Path(out_dir) / "candidates.jsonl"
    if not path.exists():
        return []
    return [
        {key: record[key] for key in ("program_id", "kind", "change", "compile_score")}
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for record in [json.loads(line)]
    ]


def _write(path: Path, value: Any) -> None:
    """Replace one JSON record atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(canonical_json(value) + "\n", encoding="utf-8")
    temporary.replace(path)


def _append(path: Path, value: Any) -> None:
    """Append a complete JSON line to the selected journal."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(canonical_json(value) + "\n")
