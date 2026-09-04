"""Stage-2 map gate: planted split-sink ranks in the high band and beats hit-count order."""

from openultrasast.complexity.map import Hotspot
from openultrasast.findings import StaticFinding
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.map_gate import (
    SPLIT_SINK_MANIFESTS,
    hit_count_path_order,
    map_beats_hit_count,
    planted_in_high_band,
    scan_split_sink,
    split_sink_map_gate,
)


def test_split_sink_map_gate_passes_heuristic_map() -> None:
    verdict = split_sink_map_gate()
    assert verdict.passed, verdict.reasons


def test_hit_count_stub_fails_map_gate_on_split_sink_python() -> None:
    bundle = scan_split_sink("split-sink-python")
    unique_map = list(dict.fromkeys(hotspot.path for hotspot in bundle.complexity_map.hotspots))
    stub_order = hit_count_path_order(bundle.findings, unique_map)
    assert stub_order != unique_map
    assert map_beats_hit_count(bundle.complexity_map.hotspots, bundle.findings)


def test_planted_split_sink_function_is_in_high_band() -> None:
    bundle = scan_split_sink("split-sink-python")
    assert planted_in_high_band(bundle.manifest, bundle.complexity_map)
    names = {hotspot.function_name for hotspot in bundle.complexity_map.hotspots if hotspot.path == "app.py"}
    assert "search" in names


def test_split_sink_gate_corpus_is_not_the_stage1_smoke_gate() -> None:
    listed = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    assert not any(name in listed for name in SPLIT_SINK_MANIFESTS)


def test_map_beats_hit_count_rejects_inventory_sorted_stub() -> None:
    findings = [
        StaticFinding(
            finding_id="python-unsafe-eval:helper.py:1",
            path="helper.py",
            title="eval",
            severity="high",
            confidence="low",
            evidence_level="static_corroboration",
            rationale="hit",
            line=1,
            function_name="ping",
            reachability_status="unknown",
            reachability_evidence=[],
            reachability_conditions=[],
            tags=["syscall_entry"],
            ranking_priority=1.0,
        )
    ]
    stub = (
        Hotspot(
            path="helper.py",
            function_name="ping",
            score=0.1,
            band="low",
            signals={},
            rationale="stub",
            test_hint=None,
            inventory_finding_ids=(findings[0].finding_id,),
        ),
        Hotspot(
            path="app.py",
            function_name="search",
            score=9.0,
            band="high",
            signals={},
            rationale="stub",
            test_hint=None,
            inventory_finding_ids=(),
        ),
    )
    assert not map_beats_hit_count(stub, findings)
