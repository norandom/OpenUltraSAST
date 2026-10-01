"""Compilation of the program, DSPy-style and in-house (learned-decision-engine design 4.3, 5, Req 3.3).

``ousast learn compile --profile P --spec learn/compile.toml`` produces a compiled program from a frozen memory
snapshot. Nothing is fitted; the instruction and the demonstrations are *chosen* against the pre-registered metric
of ``compile.toml`` (the balanced Brier score of the raw score on ``C_val``):

1. **Compile split** (:func:`.folds.compile_split`): 25% of the groups, never evaluated, split into ``C_boot`` and
   ``C_val``; during the compile the memory is the compile split only, so no evaluated repository shapes it.
2. **Bootstrap few-shot**: the program without demonstrations (retrieval on, ``k = 1``, temperature 0) on up to 150
   candidates of ``C_boot``; the kept demonstrations are right, confident (>= 0.7), cite a line in range and name no
   identity -- no repository, no path, no CVE/GHSA id (:func:`identity_hits`). The rationale was produced without
   the label, so a demonstration teaches reasoning, not the answer. Four seeded sets of three (a positive, a
   negative, one of either), each demonstration with an alternate of another framework for leave-one-framework-out.
3. **Instruction search**: one proposal call (the signature, a signal glossary, 20 summarised bootstrap errors -- no
   code) for 6 instructions; with the baseline, 7 are scored with demo set 1, then the best with sets 2-4.
4. The **artifact** is one canonical JSON (sorted keys), stored as the keyed blob ``programs/<program_id>.json``,
   where ``program_id`` is the sha256 of the artifact without its own id. It records the spec's sha256, the
   memory snapshot digest, the folds digest and the response-cache digest; spend is priced from the cached usage,
   so a replay writes the identical artifact. Whether a run replayed is reported beside it, never inside it.

A compile that reaches its ceiling (``BudgetExhausted``) is ``unfinished`` and writes no artifact.

**Packaging** (maintainer decision 2026-10-01): only demonstrations from permissively licensed code (MIT, BSD,
Apache-2.0, ISC, zlib) may ship in the package; :func:`packageable` swaps the others for a permissive alternate or
drops them, and the result is a new program (its own id) to be re-evaluated as its own variant.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..plane.budget import BudgetExhausted
from ..plane.memory import MemoryStore
from .examples import Example
from .folds import CompileSplit, Fold, assert_disjoint, compile_split, folds_digest, outer_folds
from .labels import _ADVISORY
from .program import (
    BASELINE_INSTRUCTION,
    SIGNATURE,
    Caller,
    Candidate,
    Decision,
    Demo,
    Program,
    ProgramSpec,
    label_word,
)
from .schema import BY_NAME, DEFAULT_INPUTS, SCHEMA_VERSION, feature_set_digest, withheld

DEFAULT_SPEC = Path(__file__).resolve().parent / "compile.toml"
KIND = "llm-program"
PERMISSIVE = ("mit", "bsd", "0bsd", "apache-2.0", "apache 2.0", "apache2", "apache-2", "isc", "zlib")
_PATH = re.compile(r"(?<![\w.-])[\w.-]+/[\w./-]+|\b[\w-]+\.(?:py|php|js|jsx|ts|tsx|java|c|cc|cpp|h|hpp|go|rb|cs|kt|scala|groovy)\b")


class CompileError(RuntimeError):
    """A compile that cannot start: no demonstration pool, no validation candidates, or folds that overlap."""


@dataclass(frozen=True)
class CompileSpec:
    data: Mapping[str, Any]
    sha256: str

    def __getitem__(self, section: str) -> Mapping[str, Any]:
        return dict(self.data.get(section) or {})

    @property
    def seed(self) -> int:
        return int(self.data.get("seed", 0))


def load_spec(path: Path = DEFAULT_SPEC) -> CompileSpec:
    text = Path(path).read_bytes()
    return CompileSpec(tomllib.loads(text.decode("utf-8")), hashlib.sha256(text).hexdigest())


# --- the metric ----------------------------------------------------------------------------------------------------------


def balanced_brier(rows: Sequence[tuple[str, int, str, float]], *, repository_cap: int = 5) -> float | None:
    """Mean over (family, label) cells of the cell's Brier score, each repository capped at ``repository_cap``
    effective rows per cell. ``rows`` are ``(family, label, group, s)``."""
    cells: dict[tuple[str, int], list[tuple[str, float]]] = {}
    for family, label, group, s in rows:
        cells.setdefault((family, label), []).append((group, (s - label) ** 2))
    scores = []
    for members in cells.values():
        per_group: dict[str, int] = {}
        for group, _ in members:
            per_group[group] = per_group.get(group, 0) + 1
        weights = [min(1.0, repository_cap / per_group[g]) for g, _ in members]
        scores.append(sum(w * e for w, (_, e) in zip(weights, members, strict=True)) / sum(weights))
    return sum(scores) / len(scores) if scores else None


def secondary(rows: Sequence[tuple[int, float, str]], precision: float = 0.90) -> dict[str, float | None]:
    """Recall at the lowest threshold reaching ``precision`` and the share of ``unsure`` (``rows``: label, s, verdict)."""
    positives = sum(label for label, _, _ in rows)
    recall = None
    for t in sorted({s for _, s, _ in rows}):
        chosen = [label for label, s, _ in rows if s >= t]
        if chosen and sum(chosen) / len(chosen) >= precision:
            recall = sum(chosen) / positives if positives else None
            break
    share = sum(1 for _, _, v in rows if v == "unsure") / len(rows) if rows else None
    return {"recall_at_precision_0.90": recall, "unsure_share": share}


# --- identities ----------------------------------------------------------------------------------------------------------


def identity_hits(rationale: str, identities: Iterable[str] = ()) -> list[str]:
    """Identities a rationale names: CVE/GHSA ids, paths and source file names, and any given repository string."""
    hits = [m.group(0) for m in _ADVISORY.finditer(rationale)] + [m.group(0) for m in _PATH.finditer(rationale)]
    folded = rationale.casefold()
    hits += [i for i in identities if len(i) >= 4 and i.casefold() in folded]
    return hits


def group_identities(group: str) -> tuple[str, ...]:
    parts = [p for p in re.split(r"[/:]", group) if p]
    return (group, *parts)


def permissive(license_id: str) -> bool:
    text = license_id.strip().casefold().removesuffix(" license")
    return bool(text) and any(text == p or text.startswith(p + "-") or text.startswith(p + " ") for p in PERMISSIVE)


# --- bootstrap, demo sets, proposals ----------------------------------------------------------------------------------------


def _order(items: Iterable[Example], seed: int, salt: str) -> list[Example]:
    return sorted(items, key=lambda e: hashlib.sha256(f"{seed}\x00{salt}\x00{e.id}".encode()).hexdigest())


@dataclass
class Bootstrap:
    pool: list[Demo] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    rejected: dict[str, int] = field(default_factory=dict)

    def reject(self, why: str) -> None:
        self.rejected[why] = self.rejected.get(why, 0) + 1


def _signal_summary(example: Example, inputs: str = DEFAULT_INPUTS) -> dict[str, Any]:
    """The non-zero signals of a mistake for the instruction proposer, without the instruments ``inputs`` withholds."""
    hidden = withheld(inputs)
    ran = {
        k: v for k, v in example.x.items()
        if v not in (None, 0, False) and not k.startswith("lang.") and k not in hidden
        and not (k in BY_NAME and BY_NAME[k].instrument in hidden)
    }  # fmt: skip
    return dict(sorted(ran.items())[:12])


def bootstrap(
    program: Program,
    examples: Sequence[Example],
    fold: Fold,
    caller: Caller,
    candidate_of: Callable[[Example], Candidate | None],
    *,
    min_confidence: float,
    identities: Callable[[Example], Iterable[str]],
    seed: int = 0,
) -> Bootstrap:
    out = Bootstrap()
    for example in examples:
        candidate = candidate_of(example)
        if candidate is None:
            out.reject("no excerpt")
            continue
        decision = program.decide(candidate, fold, caller, seed=seed)
        answer = decision.answers[0]
        right = decision.verdict == label_word(example.label)
        if not right:
            out.errors.append({"family": example.family, "label": label_word(example.label), "verdict": decision.verdict,
                               "confidence": answer.confidence, "signals": _signal_summary(example, program.spec.inputs)})  # fmt: skip
            out.reject("wrong or unsure")
            continue
        if answer.parse_failed or answer.confidence < min_confidence:
            out.reject("not confident")
            continue
        if identity_hits(answer.rationale, identities(example)):
            out.reject("rationale names an identity")
            continue
        out.pool.append(
            Demo(
                example.id,
                example.excerpt_sha,
                example.label,
                example.family,
                answer.verdict,
                answer.confidence,
                answer.rationale,
                answer.cited_lines,
            )  # fmt: skip
        )
    return out


def draw_demo_sets(
    pool: Sequence[Demo], examples: Mapping[str, Example], *, sets: int = 4, size: int = 3, seed: int = 0
) -> list[tuple[Demo, ...]]:
    """``sets`` seeded sets of ``size``: one positive, one negative, then any, preferring a family not yet in the set;
    each demonstration carries an alternate of the same label from no shared framework (or ``None``)."""

    def ordered(salt: str, items: Iterable[Demo]) -> list[Demo]:
        return sorted(items, key=lambda d: hashlib.sha256(f"{seed}\x00{salt}\x00{d.example_id}".encode()).hexdigest())

    out: list[tuple[Demo, ...]] = []
    for n in range(sets):
        positives = ordered(f"pos{n}", [d for d in pool if d.label == 1])
        negatives = ordered(f"neg{n}", [d for d in pool if d.label == 0])
        chosen: list[Demo] = [*positives[:1], *negatives[:1]]
        families = {d.family for d in chosen}
        rest = [d for d in ordered(f"any{n}", pool) if d not in chosen]
        rest.sort(key=lambda d: d.family in families)  # stable: other families first
        chosen += rest[: max(0, size - len(chosen))]
        with_alternates = []
        for demo in chosen:
            frameworks = set(examples[demo.example_id].frameworks)
            alternate = next(
                (a for a in ordered(f"alt{n}:{demo.example_id}", pool)
                 if a.label == demo.label and a not in chosen and not frameworks & set(examples[a.example_id].frameworks)),
                None,
            )  # fmt: skip
            with_alternates.append(replace(demo, alternate=alternate))
        if with_alternates:
            out.append(tuple(with_alternates))
    return out


PROPOSAL_INSTRUCTION = (
    "Propose instructions for a classifier. It reads one function's numbered code, the signals static instruments\n"
    "emitted for it and similar labelled examples, and answers a JSON verdict (vulnerable, not_vulnerable, unsure)\n"
    'with a confidence and a rationale citing lines. Answer one JSON object {"instructions": [<strings>]}.'
)


def glossary() -> str:
    from .schema import FEATURES

    return "\n".join(f"{s.name}: {s.type}{' (prior)' if s.prior else ''} from {s.instrument}" for s in FEATURES)


def propose(caller: Caller, errors: Sequence[Mapping[str, Any]], *, n: int, shown: int) -> list[str]:
    user = (
        f"Signature fields: {json.dumps([f.__dict__ for f in SIGNATURE.fields])}\nSignal glossary:\n{glossary()}\n"
        f"Mistakes of the baseline instruction (signals and verdicts only):\n{json.dumps(list(errors)[:shown], sort_keys=True)}\n"
        f"Baseline instruction:\n{BASELINE_INSTRUCTION}\nPropose {n} different instructions that would avoid these mistakes."
    )
    messages: list[dict[str, object]] = [{"role": "system", "content": PROPOSAL_INSTRUCTION}, {"role": "user", "content": user}]
    from ..provider.openrouter import OpenRouterError, parse_json_content

    try:
        data = parse_json_content(caller.ask(messages, temperature=0.7, sample="propose"))
    except OpenRouterError:
        return []
    found = data.get("instructions") if isinstance(data, dict) else None
    texts = [t.strip() for t in found if isinstance(t, str) and t.strip()] if isinstance(found, list) else []
    return list(dict.fromkeys(texts))[:n]


# --- scoring and the artifact -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scored:
    instruction: int  # 0 = baseline, n = proposal n
    demo_set: int
    score: float | None
    secondary: Mapping[str, float | None]
    prompt_tokens: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "instruction": self.instruction,
            "demo_set": self.demo_set,
            "score": None if self.score is None else round(self.score, 6),
            "secondary": {k: None if v is None else round(v, 6) for k, v in self.secondary.items()},
            "prompt_tokens": self.prompt_tokens,
        }


def score(
    program: Program, examples: Sequence[Example], fold: Fold, caller: Caller, candidate_of: Callable[[Example], Candidate | None], *,
    repository_cap: int, seed: int, instruction: int, demo_set: int,
) -> Scored:  # fmt: skip
    rows: list[tuple[str, int, str, float]] = []
    second: list[tuple[int, float, str]] = []
    tokens = 0
    for example in examples:
        candidate = candidate_of(example)
        if candidate is None:
            continue
        prompt, _ = program.prepare(candidate, fold, seed=seed)
        tokens = max(tokens, round(len(prompt.prefix) / 4))
        decision: Decision = program.decide(candidate, fold, caller, seed=seed)
        rows.append((example.family, example.label, example.group, decision.s))
        second.append((example.label, decision.s, decision.verdict))
    return Scored(instruction, demo_set, balanced_brier(rows, repository_cap=repository_cap), secondary(second), tokens)


def best(configurations: Sequence[Scored], tolerance: float) -> Scored:
    valid = [c for c in configurations if c.score is not None]
    if not valid:
        raise CompileError("no configuration produced a score")
    top = min(c.score for c in valid if c.score is not None)
    close = [c for c in valid if c.score is not None and c.score <= top + tolerance]
    return min(close, key=lambda c: (c.prompt_tokens, configurations.index(c)))


def canonical(artifact: Mapping[str, Any]) -> bytes:
    return json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def program_id(artifact: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical({k: v for k, v in artifact.items() if k != "program_id"})).hexdigest()


def memory_snapshot_digest(examples: Iterable[Example]) -> str:
    return hashlib.sha256("\n".join(sorted(f"{e.id}:{e.label}:{e.excerpt_sha}" for e in examples)).encode()).hexdigest()


@dataclass
class CompileResult:
    status: str  # done | unfinished
    artifact: dict[str, Any] | None
    program_id: str | None
    calls: int  # client calls made by this run (0 on a full replay)
    replayed: int
    reason: str | None = None
    bootstrap: dict[str, Any] = field(default_factory=dict)


def compile_program(
    memory: Sequence[Example],
    caller: Caller,
    excerpt_text: Callable[[str], str | None],
    *,
    spec: CompileSpec,
    profile: str = "static",
    vectors: Mapping[str, Sequence[float]] | None = None,
    identities: Callable[[Example], Iterable[str]] | None = None,
    families: Sequence[str] = (),
    candidate_families: Sequence[str] = (),
    store: MemoryStore | None = None,
    created: str = "",
    code_commit: str = "",
) -> CompileResult:
    """Compile one profile's program from ``memory`` (module docstring). Deterministic given the memory, the spec and
    the response cache. ``candidate_families`` limits the bootstrap and validation candidates to those families (a
    one-family slice); retrieval still draws on every family of the compile split, for contrast examples."""
    seed = spec.seed
    pool = [e for e in memory if e.profile == profile]
    split: CompileSplit = compile_split(pool, fraction=float(spec["split"].get("compile_fraction", 0.25)),
                                        boot=float(spec["split"].get("boot_fraction", 0.6)), seed=seed)  # fmt: skip
    evaluation = outer_folds(pool, seed=seed, exclude=split.groups)
    assert_disjoint(split, evaluation)
    compile_memory = [e for e in pool if e.group in split.groups]
    fold = Fold("compile", "compile", frozenset(), phase="compile")
    asked = [e for e in compile_memory if not candidate_families or e.family in candidate_families]
    boot = _order([e for e in asked if e.group in split.boot], seed, "boot")[: int(spec["bootstrap"].get("max_candidates", 150))]
    val = _order([e for e in asked if e.group in split.val], seed, "val")[: int(spec["search"].get("val_candidates", 60))]
    if not boot or not val:
        raise CompileError(f"compile split too small: {len(boot)} bootstrap and {len(val)} validation candidates")
    retrieval, classify = spec["retrieval"], spec["classify"]
    base = ProgramSpec(
        profile=profile, model=str(classify.get("model", "deepseek-flash")), k=int(classify.get("k", 1)), k_ret=int(retrieval.get("k", 6)),
        lam=float(retrieval.get("lam", 0.5)), n1=int(retrieval.get("n1", 40)), priors=str(retrieval.get("priors", "off")),
        inputs=str(classify.get("inputs", DEFAULT_INPUTS)),
        max_output_tokens=int(classify.get("max_output_tokens", 300)),
    )  # fmt: skip
    from .evaluate import candidate_from_example

    candidate_of = candidate_from_example(excerpt_text, vectors)
    ids = identities or (lambda e: group_identities(e.group))
    tolerance = float(spec["metric"].get("tie_tolerance", 0.005))
    cap = int(spec["metric"].get("repository_cap", 5))
    try:
        boot_run = bootstrap(
            Program(base, compile_memory, excerpt_text, vectors, families), boot, fold, caller, candidate_of,
            min_confidence=float(spec["bootstrap"].get("min_confidence", 0.7)), identities=ids, seed=seed,
        )  # fmt: skip
        index = {e.id: e for e in compile_memory}
        sets = draw_demo_sets(boot_run.pool, index, sets=int(spec["bootstrap"].get("demo_sets", 4)),
                              size=int(spec["bootstrap"].get("demos_per_set", 3)), seed=seed)  # fmt: skip
        if not sets:
            raise CompileError(f"bootstrap kept no demonstration ({boot_run.rejected})")
        shown = int(spec["search"].get("errors_shown", 20))
        instructions = [BASELINE_INSTRUCTION, *propose(caller, boot_run.errors, n=int(spec["search"].get("proposals", 6)), shown=shown)]
        configurations: list[Scored] = []

        def run(i: int, d: int) -> Scored:
            program = Program(replace(base, instruction=instructions[i], demos=sets[d]), compile_memory,
                              excerpt_text, vectors, families)  # fmt: skip
            result = score(program, val, fold, caller, candidate_of, repository_cap=cap, seed=seed, instruction=i, demo_set=d)
            configurations.append(result)
            return result

        for i in range(len(instructions)):
            run(i, 0)
        chosen_instruction = best(configurations, tolerance).instruction
        for d in range(1, len(sets)):
            run(chosen_instruction, d)
        winner = best(configurations, tolerance)
    except BudgetExhausted as exc:
        return CompileResult("unfinished", None, None, caller.calls, caller.replayed, reason=str(exc))
    artifact: dict[str, Any] = {
        "kind": KIND,
        "schema_version": SCHEMA_VERSION,
        "feature_set_digest": feature_set_digest(),
        "profile": profile,
        "signature": {"digest": SIGNATURE.digest, "fields": [f.__dict__ for f in SIGNATURE.fields]},
        "instruction": instructions[winner.instruction],
        "instruction_source": "baseline" if winner.instruction == 0 else f"proposed:{winner.instruction}",
        "demos": [d.as_dict() for d in sets[winner.demo_set]],
        "retrieval": {
            "distance": "gower-v1",
            "n1": base.n1,
            "k": base.k_ret,
            "lam": base.lam,
            "priors": base.priors,
            "near_duplicate_cos": float(retrieval.get("near_duplicate_cos", 0.98)),
            "embedding_model": "openai/text-embedding-3-small" if vectors else None,
            "balance": {"per_label": base.k_ret // 2, "per_group": 2, "other_families": 2},
            "excerpt": {"candidate_lines": 80, "candidate_chars": 4000, "example_lines": 40, "example_chars": 2000},
        },
        "classify": {
            "model": base.model,
            "model_params_digest": caller.params_digest,
            "k": base.k,
            "temperature": [0.0, 0.7],
            "confidence": "vote_mean",
            "max_output_tokens": base.max_output_tokens,
            "inputs": base.inputs,
            "withheld": sorted(withheld(base.inputs)),
        },
        "calibration": None,
        "operating_points": None,
        "priors": base.priors,
        "roles": "deterministic",
        "data": {
            "memory_snapshot_digest": memory_snapshot_digest(pool),
            "compile_groups_digest": hashlib.sha256("\n".join(sorted(split.groups)).encode()).hexdigest(),
            "folds_digest": folds_digest(split, evaluation),
            "sources": sorted({e.source for e in pool}),
            "examples": len(pool),
            "groups": len({e.group for e in pool}),
        },
        "compile": {
            "spec_sha256": spec.sha256,
            "metric": str(spec["metric"].get("name", "balanced_brier_v1")),
            "configurations": [c.as_dict() for c in configurations],
            "usd": caller.usd(),
            "requests": len(set(caller.keys)),
            "usage": dict(caller.usage),
            "response_cache_digest": caller.cache_digest(),
            "bootstrap": {"kept": len(boot_run.pool), "rejected": dict(sorted(boot_run.rejected.items())), "candidates": len(boot)},
        },
        "seed": seed,
        "code_commit": code_commit,
        "created": created,
    }
    artifact["program_id"] = program_id(artifact)
    if store is not None:
        store.put_blob("programs", canonical(artifact), name=artifact["program_id"])
    return CompileResult(
        "done", artifact, artifact["program_id"], caller.calls, caller.replayed, bootstrap=artifact["compile"]["bootstrap"]
    )


def load_program(store: MemoryStore, pid: str) -> dict[str, Any]:
    data = store.get_blob("programs", pid, verify=False)
    if data is None:
        raise CompileError(f"no program {pid[:12]} in {store.describe()}")
    artifact = dict(json.loads(data))
    if program_id(artifact) != pid:
        raise CompileError(f"program {pid[:12]} does not hash to its id: the artifact changed")
    return artifact


def spec_of(artifact: Mapping[str, Any]) -> ProgramSpec:
    retrieval, classify = artifact["retrieval"], artifact["classify"]
    return ProgramSpec(
        instruction=str(artifact["instruction"]),
        demos=tuple(Demo.from_dict(d) for d in artifact["demos"]),
        profile=str(artifact["profile"]),
        model=str(classify["model"]),
        k=int(classify["k"]),
        k_ret=int(retrieval["k"]),
        lam=float(retrieval["lam"]),
        n1=int(retrieval["n1"]),
        priors=str(retrieval.get("priors", "off")),
        inputs=str(classify.get("inputs", DEFAULT_INPUTS)),
        max_output_tokens=int(classify.get("max_output_tokens", 300)),
    )


def packageable(artifact: Mapping[str, Any], examples: Mapping[str, Example]) -> tuple[dict[str, Any], dict[str, int]]:
    """The artifact with only permissively licensed demonstrations: a demonstration from other code is replaced by
    its alternate when that one is permissive, dropped otherwise. A new program id; re-evaluate before adoption."""
    kept: list[dict[str, Any]] = []
    tally = {"kept": 0, "swapped": 0, "dropped": 0}
    for demo in artifact["demos"]:
        example = examples.get(str(demo["example_id"]))
        alternate = demo.get("alternate")
        alt_example = examples.get(str(alternate["example_id"])) if isinstance(alternate, Mapping) else None
        if example is not None and permissive(example.license):
            kept.append({**demo, "alternate": None})
            tally["kept"] += 1
        elif isinstance(alternate, Mapping) and alt_example is not None and permissive(alt_example.license):
            kept.append({**alternate, "alternate": None})
            tally["swapped"] += 1
        else:
            tally["dropped"] += 1
    packaged = {k: v for k, v in artifact.items() if k != "program_id"}
    packaged["demos"] = kept
    packaged["packaged"] = {"from": artifact.get("program_id"), "licences": list(PERMISSIVE), **tally}
    packaged["program_id"] = program_id(packaged)
    return packaged, tally


__all__ = [
    "DEFAULT_SPEC", "PERMISSIVE", "Bootstrap", "CompileError", "CompileResult", "CompileSpec", "Scored", "balanced_brier", "best",
    "bootstrap", "canonical", "compile_program", "draw_demo_sets", "group_identities", "identity_hits", "load_program", "load_spec",
    "memory_snapshot_digest", "packageable", "permissive", "program_id", "propose", "score", "secondary", "spec_of",
]  # fmt: skip
