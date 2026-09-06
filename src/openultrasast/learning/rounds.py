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
from .detectors import write_default_configs
from .families import FamilyTaxonomy
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

    def to_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "k_runs": self.k_runs,
            "taxonomy_version": self.taxonomy_version,
            "slices": list(self.slices),
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


__all__ = [
    "DEFAULT_K_RUNS",
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
