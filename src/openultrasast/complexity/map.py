from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from ..findings import StaticFinding
from ..preprocess import FileTarget
from .hints import TestHint, attach_test_hints
from .ledger import apply_overlay, load_ledger
from .signals import ComplexitySignals, collect_signals

# Score cutoffs for hotspot bands; inventory density is not the rank driver.
_HIGH_SCORE = 6.0
_MEDIUM_SCORE = 3.0


@dataclass(frozen=True)
class Hotspot:
    path: str
    function_name: str | None
    score: float
    band: str  # high | medium | low
    signals: dict[str, float | int | bool | str]
    rationale: str
    test_hint: TestHint | None
    inventory_finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class ComplexityMap:
    hotspots: tuple[Hotspot, ...]
    heuristic_only: bool


def build_complexity_map(
    targets: Sequence[FileTarget],
    findings: Sequence[StaticFinding],
    output_path: Path,
    *,
    repo_files: Iterable[str] = (),
    sources: Mapping[str, str] | None = None,
    ledger_path: Path | None = None,
) -> ComplexityMap:
    collected = collect_signals(targets, findings, repo_files=repo_files, sources=sources)
    ids_by_path = _inventory_ids_by_path(findings)
    hotspots = tuple(_hotspot_from_signals(item, ids_by_path.get(item.path, ())) for item in collected)
    hotspots = attach_test_hints(hotspots, targets, repo_files=repo_files, sources=sources)
    if ledger_path is not None:
        hotspots = apply_overlay(hotspots, load_ledger(ledger_path))
    complexity_map = ComplexityMap(hotspots=hotspots, heuristic_only=True)
    write_complexity_map(complexity_map, output_path)
    return complexity_map


def write_complexity_map(complexity_map: ComplexityMap, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(complexity_map), indent=2, sort_keys=True) + "\n")


def _hotspot_from_signals(item: ComplexitySignals, inventory_finding_ids: tuple[str, ...]) -> Hotspot:
    band = _band(item.score)
    return Hotspot(
        path=item.path,
        function_name=item.function_name,
        score=item.score,
        band=band,
        signals=_signal_payload(item),
        rationale=_rationale(item, band),
        test_hint=None,
        inventory_finding_ids=inventory_finding_ids,
    )


def _band(score: float) -> str:
    if score >= _HIGH_SCORE:
        return "high"
    if score >= _MEDIUM_SCORE:
        return "medium"
    return "low"


def _signal_payload(item: ComplexitySignals) -> dict[str, float | int | bool | str]:
    return {
        "loc": item.loc,
        "nesting": item.nesting,
        "reachability": item.reachability,
        "inventory_hit_count": item.inventory_hit_count,
        "has_adjacent_test": item.has_adjacent_test,
        "tags": ",".join(item.tags),
    }


def _rationale(item: ComplexitySignals, band: str) -> str:
    tags = ",".join(item.tags) or "none"
    return (
        f"{band} band: score {item.score} against cutoffs high>={_HIGH_SCORE}, medium>={_MEDIUM_SCORE}; "
        f"loc={item.loc}, nesting={item.nesting}, tags={tags}, reachability={item.reachability}, "
        f"inventory_hit_count={item.inventory_hit_count} (density is a feature not the rank driver), "
        f"has_adjacent_test={str(item.has_adjacent_test).lower()}."
    )


def _inventory_ids_by_path(findings: Sequence[StaticFinding]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for finding in findings:
        grouped.setdefault(finding.path, []).append(finding.finding_id)
    return {path: tuple(ids) for path, ids in grouped.items()}
