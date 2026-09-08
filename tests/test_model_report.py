"""model-grounded-detection task 5.2: reporting that cannot flatter itself (Req 9.3, 11.1).

Three disciplines survive from the deleted publish/scoring layer, and each exists because its absence caused a
real error in this project's history:

  per-slice rows        a headline over mixed slices hid that agent-written code scored 44% while the
                        hand-written development slice scored 83%
  the overfitting gap   published beside the headline, so the distance between the development slice and the
                        real-world one is never something a reader has to compute
  the rung on every     a finding's strength is what established it; a report that omits the rung invites the
  finding               reader to treat a suspicion as a result
"""

from __future__ import annotations

import pytest


def _slice(name, pairs, covered):  # type: ignore[no-untyped-def]
    from openultrasast.model.report import SliceRow

    return SliceRow(slice=name, pairs=pairs, covered=covered)


def test_the_report_carries_a_row_per_slice() -> None:
    from openultrasast.model.report import render

    text = render([_slice("vibe-py", 30, 25), _slice("vfc-js", 17, 4)])
    assert "vibe-py" in text and "vfc-js" in text
    assert "30" in text and "17" in text


def test_a_bare_aggregate_is_refused() -> None:
    """Req 11.1: no cross-slice number without the rows it was computed from."""
    from openultrasast.model.report import render

    with pytest.raises(ValueError, match="per-slice"):
        render([])


def test_the_overfitting_gap_is_published_beside_the_headline() -> None:
    """The development slice minus the deciding real-world slice, stated rather than left to be computed."""
    from openultrasast.model.report import overfitting_gap, render

    rows = [_slice("vibe-py", 30, 24), _slice("vfc-js", 20, 4)]
    gap = overfitting_gap(rows, development="vibe-py", deciding="vfc-js")
    assert gap == pytest.approx(0.80 - 0.20)
    assert "overfitting gap" in render(rows, development="vibe-py", deciding="vfc-js").lower()
    assert "+60" in render(rows, development="vibe-py", deciding="vfc-js")


def test_the_gap_is_absent_rather_than_zero_when_a_slice_is_missing() -> None:
    """A missing slice must not read as "no overfitting" — that is the flattering failure, not a neutral one."""
    from openultrasast.model.report import overfitting_gap

    assert overfitting_gap([_slice("vibe-py", 30, 24)], development="vibe-py", deciding="vfc-js") is None


def test_every_finding_shows_its_rung() -> None:
    from openultrasast.findings import StaticFinding
    from openultrasast.model.ladder import Rung
    from openultrasast.model.report import render_findings

    finding = StaticFinding(
        finding_id="r:app.py:1", path="app.py", title="t", severity="high", confidence="medium",
        evidence_level="static_corroboration", rationale="why", line=1, function_name="run",
        reachability_status="unknown", reachability_evidence=[], reachability_conditions=[], tags=[],
        ranking_priority=1.0, rung=Rung.ENTAILED,
    )
    text = render_findings([finding])
    assert "model_entailed" in text and "app.py" in text


def test_the_deciding_slice_is_named_in_the_report() -> None:
    """Req 9.3: the real-world slice decides, and the report says which one that is."""
    from openultrasast.model.report import render

    text = render([_slice("vibe-py", 30, 24), _slice("vfc-js", 20, 4)], development="vibe-py", deciding="vfc-js")
    assert "vfc-js" in text and "decid" in text.lower()
