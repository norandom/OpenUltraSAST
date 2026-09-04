"""Stage-2 quality gate: split-sink ranking must beat pattern-hit-count order.

The stage-1 smoke gate (``python -m openultrasast.gate``) stays on cheat-sheet
fixtures. This module is the merge gate for the complexity map: the planted
split-sink function must sit in the high band, and map order must not collapse
to sorting files by inventory-hit count.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .benchmark import BenchmarkManifest, ExpectedFinding, load_benchmark_manifest, resolve_benchmark_source
from .complexity.map import ComplexityMap, Hotspot, build_complexity_map
from .findings import StaticFinding, quick_scan_findings
from .mapping import analyze_entry_points, attach_reachability_hints
from .preprocess import preprocess_repository
from .rank import rank_targets

SPLIT_SINK_MANIFESTS = (
    "split-sink-c",
    "split-sink-java",
    "split-sink-javascript",
    "split-sink-python",
)
DEFAULT_MANIFEST_DIR = Path("benchmarks/manifests")


@dataclass(frozen=True)
class SplitSinkScan:
    name: str
    manifest: BenchmarkManifest
    target: Path
    findings: tuple[StaticFinding, ...]
    complexity_map: ComplexityMap


@dataclass(frozen=True)
class MapGateVerdict:
    passed: bool
    reasons: tuple[str, ...]


def scan_split_sink(name: str, manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> SplitSinkScan:
    manifest_path = manifest_dir / f"{name}.toml"
    manifest = load_benchmark_manifest(manifest_path)
    target = resolve_benchmark_source(manifest_path, manifest)
    _, targets = preprocess_repository(target)
    targets = attach_reachability_hints(targets, analyze_entry_points(target, targets))
    findings = tuple(quick_scan_findings(target, targets, rank_targets(targets)))
    with tempfile.TemporaryDirectory() as tmp:
        complexity_map = build_complexity_map(
            targets,
            findings,
            Path(tmp) / "complexity_map.json",
            repo_files=[item.path for item in targets],
        )
    return SplitSinkScan(name=name, manifest=manifest, target=target, findings=findings, complexity_map=complexity_map)


def planted_expected(manifest: BenchmarkManifest) -> tuple[ExpectedFinding, ...]:
    return tuple(item for item in manifest.expected if item.rule_id is None)


_BAND_RANK = {"high": 3, "medium": 2, "low": 1}


def planted_in_high_band(manifest: BenchmarkManifest, complexity_map: ComplexityMap) -> bool:
    """True when the planted sink sits in the highest band the map actually emitted."""
    if not complexity_map.hotspots:
        return False
    top = max(_BAND_RANK.get(hotspot.band, 0) for hotspot in complexity_map.hotspots)
    for expected in planted_expected(manifest):
        matches = [hotspot for hotspot in complexity_map.hotspots if hotspot.path == expected.path]
        if expected.function:
            named = [hotspot for hotspot in matches if hotspot.function_name == expected.function]
            if named:
                matches = named
        if not matches or not any(_BAND_RANK.get(hotspot.band, 0) == top for hotspot in matches):
            return False
    return bool(planted_expected(manifest))


def hit_count_path_order(findings: Sequence[StaticFinding], paths: Sequence[str]) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.path] = counts.get(finding.path, 0) + 1
    unique = list(dict.fromkeys(paths))
    return sorted(unique, key=lambda path: (-counts.get(path, 0), path))


def map_beats_hit_count(hotspots: Sequence[Hotspot], findings: Sequence[StaticFinding]) -> bool:
    map_order = list(dict.fromkeys(hotspot.path for hotspot in hotspots))
    stub_order = hit_count_path_order(findings, map_order)
    return map_order != stub_order


def split_sink_map_gate(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> MapGateVerdict:
    reasons: list[str] = []
    python: SplitSinkScan | None = None
    for name in SPLIT_SINK_MANIFESTS:
        bundle = scan_split_sink(name, manifest_dir)
        if name == "split-sink-python":
            python = bundle
        if not planted_in_high_band(bundle.manifest, bundle.complexity_map):
            reasons.append(f"{name}: planted split-sink is not in the top hotspot band")
    if python is None:
        reasons.append("split-sink-python corpus is missing")
    elif not map_beats_hit_count(python.complexity_map.hotspots, python.findings):
        reasons.append("split-sink-python: map order equals pattern-hit-count order")
    return MapGateVerdict(passed=not reasons, reasons=tuple(reasons))


def main() -> int:
    verdict = split_sink_map_gate()
    if verdict.passed:
        print("split-sink map gate: PASS")
        return 0
    print("split-sink map gate: FAIL", file=sys.stderr)
    for reason in verdict.reasons:
        print(f"  - {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
