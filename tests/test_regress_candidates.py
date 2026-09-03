"""Bounded regression candidate selection from hotspots and severe inventory (task 5.1)."""

from openultrasast.complexity.ledger import NOT_TRIGGERABLE_DELTA, apply_overlay, record_verdict
from openultrasast.complexity.map import Hotspot
from openultrasast.findings import StaticFinding
from openultrasast.regress.candidate import select_candidates


def _finding(
    path: str,
    finding_id: str,
    *,
    function_name: str | None = None,
    reachability: str = "unknown",
    severity: str = "low",
) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path=path,
        title="pattern hit",
        severity=severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="inventory",
        line=1,
        function_name=function_name,
        reachability_status=reachability,
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[],
        ranking_priority=1.0,
    )


def _hotspot(
    path: str,
    *,
    function_name: str | None = None,
    score: float = 4.0,
    band: str = "medium",
    inventory_finding_ids: tuple[str, ...] = (),
) -> Hotspot:
    return Hotspot(
        path=path,
        function_name=function_name,
        score=score,
        band=band,
        signals={"loc": 10, "inventory_hit_count": len(inventory_finding_ids)},
        rationale=f"{band} band: score {score}",
        test_hint=None,
        inventory_finding_ids=inventory_finding_ids,
    )


def _six_hotspots(*, sev5_id: str | None = None, sev5_score: float = 4.0) -> tuple[Hotspot, ...]:
    return (
        _hotspot("a.py", function_name="a", score=5.0),
        _hotspot("b.py", function_name="b", score=4.8),
        _hotspot("c.py", function_name="c", score=4.6),
        _hotspot("d.py", function_name="d", score=4.4),
        _hotspot("e.py", function_name="e", score=4.2),
        _hotspot(
            "f.py",
            function_name="f",
            score=sev5_score,
            inventory_finding_ids=(sev5_id,) if sev5_id else (),
        ),
    )


def test_six_hotspots_max_candidates_three_returns_three() -> None:
    noise = _finding("f.py", "print:f.py:1", function_name="f", reachability="reachable")
    selected = select_candidates(
        _six_hotspots(),
        [noise],
        max_candidates=3,
        policy_severity_by_id={noise.finding_id: 2},
    )

    assert len(selected) == 3
    assert [item.path for item in selected] == ["a.py", "b.py", "c.py"]


def test_sev5_reachable_extra_included_when_ledger_demoted_hotspot() -> None:
    sev5_id = "cmd:f.py:1"
    hotspots = _six_hotspots(sev5_id=sev5_id, sev5_score=5.2)
    ledger = record_verdict({}, path="f.py", function_name="f", verdict="not_triggerable")
    demoted = apply_overlay(hotspots, ledger)
    finding = _finding(
        "f.py",
        sev5_id,
        function_name="f",
        reachability="reachable",
        severity="critical",
    )

    selected = select_candidates(
        demoted,
        [finding],
        max_candidates=3,
        policy_severity_by_id={sev5_id: 5},
    )

    demoted_f = next(item for item in demoted if item.path == "f.py")
    assert demoted_f.score == round(5.2 + NOT_TRIGGERABLE_DELTA, 4)
    assert [item.path for item in demoted[:3]] == ["a.py", "b.py", "c.py"]
    assert demoted_f not in demoted[:3]
    assert len(selected) == 4
    assert [item.path for item in selected[:3]] == ["a.py", "b.py", "c.py"]
    assert selected[3] is demoted_f
    assert sev5_id in selected[3].inventory_finding_ids


def test_sev5_already_in_cap_is_not_duplicated() -> None:
    sev5_id = "cmd:a.py:1"
    hotspots = (
        _hotspot("a.py", function_name="a", score=5.0, inventory_finding_ids=(sev5_id,)),
        _hotspot("b.py", function_name="b", score=4.8),
        _hotspot("c.py", function_name="c", score=4.6),
        _hotspot("d.py", function_name="d", score=4.4),
        _hotspot("e.py", function_name="e", score=4.2),
        _hotspot("f.py", function_name="f", score=4.0),
    )
    finding = _finding("a.py", sev5_id, function_name="a", reachability="reachable", severity="critical")

    selected = select_candidates(
        hotspots,
        [finding],
        max_candidates=3,
        policy_severity_by_id={sev5_id: 5},
    )

    assert len(selected) == 3
    assert [item.path for item in selected] == ["a.py", "b.py", "c.py"]
    assert sev5_id in selected[0].inventory_finding_ids


def test_sev5_reachable_inventory_without_hotspot_is_still_selected() -> None:
    finding = _finding(
        "z.py",
        "cmd:z.py:1",
        function_name="z",
        reachability="reachable",
        severity="critical",
    )

    selected = select_candidates(
        _six_hotspots(),
        [finding],
        max_candidates=3,
        policy_severity_by_id={finding.finding_id: 5},
    )

    assert len(selected) == 4
    assert [item.path for item in selected[:3]] == ["a.py", "b.py", "c.py"]
    extra = selected[3]
    assert extra.path == "z.py"
    assert extra.function_name == "z"
    assert extra.inventory_finding_ids == (finding.finding_id,)
