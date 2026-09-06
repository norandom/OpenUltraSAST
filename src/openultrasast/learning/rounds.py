"""Round zero and the per-family noise floor (learning-harness, Req 8).

Before anything learns, every family gets the same detector and is measured against itself. Running a
pair several times at the same settings does not give the same answer: the chat provider offers no seed,
so the spread between runs is real and unavoidable. That spread is the family's noise floor, and it
becomes the budget a later round must stay inside before a cross-family change counts as a regression.
Choosing a budget instead of measuring one would be a guess dressed as a threshold.

Artifacts are keyed by detector model, so a second model is baselined by changing the model and running
again. Configurations are never touched by a model swap, which is what makes the two numbers comparable
and what makes reconsidering the model cheap.
"""

from __future__ import annotations

import json
import math
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import StaticFinding
from ..pairs import PairCase
from .classify import classify_pair
from .detectors import FamilyConfig, write_default_configs
from .families import FamilyTaxonomy
from .journal import Archive, Attribution, LearningJournal, RoundRecord
from .proposer import Proposal, Proposer
from .scoring import FamilyMetrics, PairFamilyScore, aggregate, score_pair_family

DEFAULT_SLICES = ("vibe-py", "agent-vfc")  # the web families, where real-world code and dangerous fruit coincide
NON_GATING_FAMILIES = frozenset({"memory"})  # measured on the vendored slice, never allowed to fail a round
DEFAULT_K_RUNS = 5
Scan = Callable[[Path], list[StaticFinding]]


@dataclass(frozen=True)
class NoiseFloor:
    """How much a family disagrees with itself between runs, and the budget that follows from it."""

    family: str
    k_runs: int
    pairs: int
    flaky_pairs: int
    negative_flip_rate: float
    budget_flips: int
    gates: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "k_runs": self.k_runs,
            "pairs": self.pairs,
            "flaky_pairs": self.flaky_pairs,
            "negative_flip_rate": self.negative_flip_rate,
            "budget_flips": self.budget_flips,
            "gates": self.gates,
        }


@dataclass(frozen=True)
class BaselineReport:
    model: str
    k_runs: int
    taxonomy_version: str
    slices: tuple[str, ...]
    floors: dict[str, NoiseFloor] = field(default_factory=dict)
    metrics: dict[str, dict[str, object]] = field(default_factory=dict)
    scores: tuple[PairFamilyScore, ...] = ()
    cost_usd: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "k_runs": self.k_runs,
            "taxonomy_version": self.taxonomy_version,
            "slices": list(self.slices),
            "cost_usd": self.cost_usd,
            "floors": {name: floor.to_dict() for name, floor in sorted(self.floors.items())},
            "metrics": {name: dict(block) for name, block in sorted(self.metrics.items())},
        }


def run_baseline(
    cases: Sequence[PairCase],
    *,
    taxonomy: FamilyTaxonomy,
    configs_dir: Path,
    scan: Scan,
    model: str,
    out_dir: Path,
    slices: Sequence[str] = DEFAULT_SLICES,
    k_runs: int = DEFAULT_K_RUNS,
    prompt: str | None = None,
    spent_usd: Callable[[], float] | None = None,
) -> BaselineReport:
    """Clone one detector into every family, measure each family against itself, and write the artifacts."""
    from ..tool_hunter import _SYSTEM_PROMPT

    if not configs_dir.exists():
        write_default_configs(configs_dir, taxonomy, prompt=prompt or _SYSTEM_PROMPT, version="0")
    selected = [case for case in cases if case.slice in set(slices)]
    scores = [score_case(case, scan, taxonomy=taxonomy, runs=k_runs) for case in selected]
    metrics = aggregate(scores, taxonomy=taxonomy)
    floors = {name: _floor(name, block, [item for item in scores if item.family == name], k_runs) for name, block in metrics.items()}
    report = BaselineReport(
        model=model,
        k_runs=k_runs,
        taxonomy_version=taxonomy.version,
        slices=tuple(slices),
        floors=floors,
        metrics={name: block.to_dict() for name, block in metrics.items()},
        scores=tuple(scores),
        cost_usd=spent_usd() if spent_usd is not None else 0.0,
    )
    _write(out_dir, report)
    return report


def score_case(case: PairCase, scan: Scan, *, taxonomy: FamilyTaxonomy, runs: int, family: str | None = None) -> PairFamilyScore:
    """Run one detector over both sides of one pair ``runs`` times and score it for its family.

    A pair the corpus already marked unscorable is never run: spending model calls on a row that cannot
    be scored buys nothing and would put its noise into a floor it does not belong in.
    """
    from ..pairs import _materialize, _overlay_scan

    name = family or _family_of(case, taxonomy)
    if case.unscorable:
        return PairFamilyScore(
            pair=case.name,
            family=name,
            runs=(),
            outcome="unscorable",
            slice=case.slice,
            unscorable_reason=case.unscorable,
        )
    with tempfile.TemporaryDirectory(prefix="ousast-round-") as scratch:
        vuln_root = _materialize(Path(scratch) / "vuln", case.vuln_file, case.relpath)
        fix_root = _materialize(Path(scratch) / "fixed", case.fixed_file, case.relpath)
        ranges = _overlay_scan(vuln_root).ranges
        vuln_runs = [scan(vuln_root) for _ in range(max(runs, 1))]
        fix_runs = [scan(fix_root) for _ in range(max(runs, 1))]
    return score_pair_family(case, name, vuln_runs, fix_runs, ranges=ranges, taxonomy=taxonomy, parse_ok=bool(ranges))


def compare_baselines(out_dir: Path) -> dict[str, dict[str, dict[str, object]]]:
    """Every baseline written under ``out_dir``, model by model, so two detectors can be read side by side."""
    root = out_dir / "baseline"
    table: dict[str, dict[str, dict[str, object]]] = {}
    for directory in sorted(path for path in root.iterdir() if path.is_dir()) if root.is_dir() else []:
        report = directory / "report.json"
        if not report.is_file():
            continue
        payload = json.loads(report.read_text(encoding="utf-8"))
        table[str(payload.get("model", directory.name))] = {family: dict(block) for family, block in (payload.get("metrics") or {}).items()}
    return table


def _floor(family: str, metrics: FamilyMetrics, scores: Sequence[PairFamilyScore], k_runs: int) -> NoiseFloor:
    """A family's own disagreement between runs, as a rate and as a whole number of pairs."""
    scorable = [item for item in scores if item.outcome != "unscorable"]
    flaky = sum(1 for item in scorable if item.flips)
    rate = flaky / len(scorable) if scorable else 0.0
    return NoiseFloor(
        family=family,
        k_runs=k_runs,
        pairs=metrics.scorable,
        flaky_pairs=flaky,
        negative_flip_rate=rate,
        budget_flips=math.ceil(rate * metrics.scorable) if metrics.scorable else 0,
        gates=family not in NON_GATING_FAMILIES,
    )


def _family_of(case: PairCase, taxonomy: FamilyTaxonomy) -> str:
    for row in case.expected:
        if row.family:
            return str(row.family)
    answer = classify_pair(case, taxonomy, client=None)
    return answer.families[0] if answer.families else "unknown"


def _write(out_dir: Path, report: BaselineReport) -> None:
    directory = out_dir / "baseline" / _slug(report.model)
    directory.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict()
    (directory / "noise-floors.json").write_text(
        json.dumps({"model": report.model, "k_runs": report.k_runs, "floors": payload["floors"]}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (directory / "report.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", model).strip("-") or "unnamed"


def load_noise_floors(out_dir: Path, model: str) -> dict[str, NoiseFloor]:
    """The budgets a later round must stay inside, as round zero measured them for this model."""
    path = out_dir / "baseline" / _slug(model) / "noise-floors.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    floors: dict[str, NoiseFloor] = {}
    for name, block in (payload.get("floors") or {}).items():
        if isinstance(block, Mapping):
            floors[str(name)] = NoiseFloor(
                family=str(block.get("family", name)),
                k_runs=int(block.get("k_runs", DEFAULT_K_RUNS) or DEFAULT_K_RUNS),
                pairs=int(block.get("pairs", 0) or 0),
                flaky_pairs=int(block.get("flaky_pairs", 0) or 0),
                negative_flip_rate=float(block.get("negative_flip_rate", 0.0) or 0.0),
                budget_flips=int(block.get("budget_flips", 0) or 0),
                gates=bool(block.get("gates", True)),
            )
    return floors


MIN_K_RUNS = 3  # Req 3.5: a single run misses most real changes, so no stage may score with fewer


def run_learning_round(
    cases: Sequence[PairCase],
    *,
    family: str,
    taxonomy: FamilyTaxonomy,
    configs_dir: Path,
    proposer: Proposer,
    scan_factory: Callable[[FamilyConfig], Scan],
    model: str,
    journal: LearningJournal,
    archive: Archive,
    floors: Mapping[str, NoiseFloor],
    out_dir: Path,
    cost_cap_usd: float = 10.0,
    minibatch: int = 8,
    k_runs: int = MIN_K_RUNS,
    sweep_families: Sequence[str] = (),
    spent_usd: Callable[[], float] | None = None,
    trajectories: Callable[[], Sequence[Mapping[str, object]]] | None = None,
) -> RoundRecord:
    """One round: propose one change for one family, then let the evidence decide whether it stays.

    Staged so that the cheap answer comes first: a train minibatch, then the family's held-out pairs,
    then every other family. Each stage scores several runs per pair, because a single run misses most
    real changes. The proposer never sees a held-out pair, and the family directory is snapshotted before
    the change so any outcome other than acceptance leaves the tree exactly as it was found.
    """
    from ..redaction import redact_secrets
    from .acceptance import DirectorySnapshot, bump_version, decide, within_budget
    from .detectors import load_family_configs
    from .proposer import apply_proposal, build_failure_facts, refuse_proposal
    from .split import is_teacher

    if k_runs < MIN_K_RUNS:
        raise ValueError(f"a stage scores at least three runs per pair; {k_runs} was asked for")
    round_number = journal.next_round()  # type: ignore[attr-defined]
    directory = out_dir / "rounds" / str(round_number)
    if directory.exists():
        from .journal import JournalError

        raise JournalError(f"round {round_number} already has a directory; history is append-only")
    configs = load_family_configs(configs_dir, taxonomy)
    config = configs[family]
    train = [case for case in cases if is_teacher(case) and _family_of(case, taxonomy) == family]
    holdout = [case for case in cases if case.split == "holdout" and _family_of(case, taxonomy) == family]
    batch = train[:minibatch]

    def _score(rows: Sequence[PairCase], scan: Scan, name: str) -> list[PairFamilyScore]:
        return [score_case(case, scan, taxonomy=taxonomy, runs=k_runs, family=name) for case in rows]

    before_scan = scan_factory(config)
    before_train = _score(batch, before_scan, family)
    before_hold = _score(holdout, before_scan, family)
    facts = build_failure_facts(before_train, family=family, config=config, journal=journal, train_pairs={case.name for case in train})
    proposal = proposer.propose(facts)  # type: ignore[attr-defined]
    record = _round_record(round_number, family, proposal, taxonomy, config)
    if proposal is None:
        return _finish(journal, directory, record, outcome="rejected", reason="no_proposal", trajectories=trajectories)
    refusal = refuse_proposal(proposal, config)
    if refusal is not None:
        return _finish(journal, directory, record, outcome="rejected", reason=refusal, proposal=proposal, trajectories=trajectories)
    snapshot = DirectorySnapshot.of(configs_dir / family)
    apply_proposal(proposal, configs_dir / family)
    try:
        after_config = load_family_configs(configs_dir, taxonomy)[family]
        after_scan = scan_factory(after_config)
        after_train = _score(batch, after_scan, family)
        after_hold = _score(holdout, after_scan, family)
        sweep, flipped_unpredicted = _sweep(cases, taxonomy, configs, scan_factory, sweep_families, family, k_runs)
        cost = spent_usd() if spent_usd is not None else 0.0
        train_delta = _delta(before_train, after_train)
        holdout_delta = _delta(before_hold, after_hold)
        if not within_budget(cost, cost_cap_usd):
            snapshot.restore()
            return _finish(
                journal,
                directory,
                record,
                outcome="reverted_cost",
                reason="cost_cap_exceeded",
                proposal=proposal,
                cost=cost,
                scores=after_train + after_hold,
                trajectories=trajectories,
            )
        verdict = decide(target=family, train_delta=train_delta, holdout_delta=holdout_delta, sweep=sweep, floors=floors)  # type: ignore[arg-type]
        flipped = _flipped(before_train + before_hold, after_train + after_hold)
        attribution = Attribution(
            flipped_predicted=len(flipped),
            flipped_unpredicted=len(flipped_unpredicted),
            precision=len(flipped) / (len(flipped) + len(flipped_unpredicted)) if flipped or flipped_unpredicted else 0.0,
        )
        if not verdict.accepted:
            snapshot.restore()
            return _finish(
                journal,
                directory,
                record,
                outcome="rejected",
                reason=verdict.reason,
                proposal=proposal,
                cost=cost,
                train_delta=train_delta,
                holdout_delta=holdout_delta,
                sweep=sweep,
                attribution=attribution,
                flipped=flipped,
                unpredicted=flipped_unpredicted,
                scores=after_train + after_hold,
                trajectories=trajectories,
            )
        version = str(int(config.version) + 1) if config.version.isdigit() else f"{config.version}+1"
        bump_version(configs_dir / family, version)
        for score in after_train + after_hold:
            archive.record(family, version, score)  # type: ignore[attr-defined]
        return _finish(
            journal,
            directory,
            record,
            outcome="accepted",
            reason=verdict.reason,
            proposal=proposal,
            cost=cost,
            train_delta=train_delta,
            holdout_delta=holdout_delta,
            sweep=sweep,
            attribution=attribution,
            flipped=flipped,
            unpredicted=flipped_unpredicted,
            scores=after_train + after_hold,
            version=version,
            trajectories=trajectories,
        )
    except Exception:
        snapshot.restore()
        raise
    finally:
        del redact_secrets


def _sweep(
    cases: Sequence[PairCase],
    taxonomy: FamilyTaxonomy,
    configs: Mapping[str, FamilyConfig],
    scan_factory: Callable[[FamilyConfig], Scan],
    families: Sequence[str],
    target: str,
    k_runs: int,
) -> tuple[dict[str, int], list[str]]:
    """Every other family's held-out pairs, so a change cannot help one family by quietly breaking another."""
    flips: dict[str, int] = {}
    unpredicted: list[str] = []
    for name in families:
        if name == target or name not in configs:
            continue
        rows = [case for case in cases if case.split == "holdout" and _family_of(case, taxonomy) == name]
        scan = scan_factory(configs[name])
        broken = [
            item
            for item in (score_case(case, scan, taxonomy=taxonomy, runs=k_runs, family=name) for case in rows)
            if item.outcome != "pair_correct"
        ]
        flips[name] = len(broken)
        unpredicted.extend(item.pair for item in broken)
    return flips, unpredicted


def _delta(before: Sequence[PairFamilyScore], after: Sequence[PairFamilyScore]) -> float:
    """The change in how many pairs came out right, as a fraction of the pairs that could be scored."""
    scorable = [item for item in before if item.outcome != "unscorable"]
    if not scorable:
        return 0.0
    was = sum(1 for item in before if item.outcome == "pair_correct")
    now = sum(1 for item in after if item.outcome == "pair_correct")
    return (now - was) / len(scorable)


def _flipped(before: Sequence[PairFamilyScore], after: Sequence[PairFamilyScore]) -> list[str]:
    was = {item.pair: item.outcome for item in before}
    return [item.pair for item in after if item.outcome == "pair_correct" and was.get(item.pair) not in {"pair_correct", None}]


def _round_record(
    round_number: int, family: str, proposal: Proposal | None, taxonomy: FamilyTaxonomy, config: FamilyConfig
) -> dict[str, object]:
    return {
        "round": round_number,
        "family": family,
        "hypothesis": proposal.hypothesis if proposal is not None else "",
        "levers": (proposal.lever,) if proposal is not None else (),
        "predicted_affected": tuple(proposal.predicted_affected) if proposal is not None else (),
        "predicted_at_risk": tuple(proposal.predicted_at_risk) if proposal is not None else (),
        "taxonomy_version": taxonomy.version,
        "config_version": config.version,
    }


def _finish(
    journal: LearningJournal,
    directory: Path,
    base: dict[str, object],
    *,
    outcome: str,
    reason: str,
    proposal: Proposal | None = None,
    cost: float = 0.0,
    train_delta: float = 0.0,
    holdout_delta: float = 0.0,
    sweep: Mapping[str, int] | None = None,
    attribution: Attribution | None = None,
    flipped: Sequence[str] = (),
    unpredicted: Sequence[str] = (),
    scores: Sequence[PairFamilyScore] = (),
    version: str | None = None,
    trajectories: Callable[[], Sequence[Mapping[str, object]]] | None = None,
) -> RoundRecord:
    """Write the round directory and journal the outcome. Every outcome is journalled, not just the good ones."""
    from ..redaction import redact_secrets

    record = RoundRecord(
        **base,  # type: ignore[arg-type]
        outcome=outcome,
        reason=reason,
        target_train_delta=train_delta,
        target_holdout_delta=holdout_delta,
        sweep=dict(sweep or {}),
        attribution=attribution or Attribution(),
        cost_usd=cost,
    )
    if version is not None:
        record = RoundRecord(**{**record.__dict__, "config_version": version})
    directory.mkdir(parents=True, exist_ok=True)
    if proposal is not None:
        (directory / "proposal.json").write_text(
            redact_secrets(json.dumps(proposal.to_dict(), indent=2, sort_keys=True)) + "\n",
            encoding="utf-8",
        )
    (directory / "scores.json").write_text(
        json.dumps([{"pair": item.pair, "family": item.family, "outcome": item.outcome} for item in scores], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (directory / "attribution.json").write_text(
        json.dumps({"flipped_predicted": list(flipped), "flipped_unpredicted": list(unpredicted)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    rows = list(trajectories() if trajectories is not None else ())
    (directory / "trajectories.jsonl").write_text(
        "".join(redact_secrets(json.dumps(row, sort_keys=True)) + "\n" for row in rows), encoding="utf-8"
    )
    journal.append(record)  # type: ignore[attr-defined]
    return record


__all__ = [
    "DEFAULT_K_RUNS",
    "MIN_K_RUNS",
    "run_learning_round",
    "DEFAULT_SLICES",
    "NON_GATING_FAMILIES",
    "BaselineReport",
    "NoiseFloor",
    "Scan",
    "compare_baselines",
    "load_noise_floors",
    "run_baseline",
    "score_case",
]
