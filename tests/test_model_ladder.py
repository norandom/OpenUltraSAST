"""model-grounded-detection task 3.1: the evidence ladder is the verdict type (Req 5).

The rung says what ESTABLISHED a finding, so a deterministic model result is never confused with an LLM
suspicion. The integrity constraint is Req 5.4: nothing reaches a rung above `suspicion` without a `Verdict`,
and a `Verdict` above `suspicion` is only ever produced by the CPG with no model call in the establishing step.
"""

from __future__ import annotations

import json
from pathlib import Path


def _finding(**kw: object):  # type: ignore[no-untyped-def]
    from openultrasast.findings import StaticFinding

    base = dict(
        finding_id="r1:app.py:1", path="app.py", title="t", severity="high", confidence="medium",
        evidence_level="static_corroboration", rationale="why", line=1, function_name="run",
        reachability_status="unknown", reachability_evidence=[], reachability_conditions=[], tags=[],
        ranking_priority=1.0,
    )
    base.update(kw)
    return StaticFinding(**base)  # type: ignore[arg-type]


def test_the_rungs_are_ordered_and_comparable() -> None:
    from openultrasast.model.ladder import Rung, at_or_above

    assert at_or_above(Rung.ENTAILED, Rung.CORROBORATED)
    assert at_or_above(Rung.CORROBORATED, Rung.SUSPICION)
    assert not at_or_above(Rung.SUSPICION, Rung.CORROBORATED)
    assert at_or_above(Rung.EXECUTION_CONFIRMED, Rung.ENTAILED)


def test_a_finding_defaults_to_suspicion() -> None:
    """Req 5.4: a claim nothing has arbitrated is a suspicion, whatever produced it."""
    from openultrasast.model.ladder import Rung

    assert _finding().rung == Rung.SUSPICION


def test_only_a_verdict_raises_a_finding_above_suspicion() -> None:
    from openultrasast.model.ladder import Rung, Verdict, at_rung

    finding = _finding()
    verdict = Verdict(rung=Rung.ENTAILED, family="injection", witness="src -> sink")
    raised = at_rung(finding, verdict)
    assert raised.rung == Rung.ENTAILED
    assert "src -> sink" in raised.rationale, "the witness travels with the rung it justifies"
    assert raised.finding_id == finding.finding_id and raised.line == finding.line


def test_a_none_verdict_leaves_the_finding_at_suspicion() -> None:
    from openultrasast.model.ladder import Rung, at_rung

    assert at_rung(_finding(), None).rung == Rung.SUSPICION


def test_the_legacy_evidence_level_is_left_alone() -> None:
    """`static_corroboration` is the *flat IR overlay's* word and Req 4.4 demotes that path to the suspicion
    band. Restating it as `model_corroborated` would claim a CPG arbitrated something it never saw."""
    from openultrasast.model.ladder import Rung, Verdict, at_rung

    raised = at_rung(_finding(), Verdict(rung=Rung.CORROBORATED, family="injection", witness="w"))
    assert raised.evidence_level == "static_corroboration", "the legacy field keeps its own meaning"
    assert raised.rung == Rung.CORROBORATED


def test_the_rung_reaches_markdown_json_and_sarif(tmp_path: Path) -> None:
    """Req 5.3: every output format carries the rung."""
    from openultrasast.findings import write_findings
    from openultrasast.model.ladder import Rung, Verdict, at_rung
    from openultrasast.reports import write_markdown_report, write_sarif_report

    finding = at_rung(_finding(), Verdict(rung=Rung.ENTAILED, family="injection", witness="src -> sink"))
    md, js, sarif = tmp_path / "r.md", tmp_path / "r.json", tmp_path / "r.sarif"
    write_markdown_report([finding], md)
    write_findings([finding], js)
    write_sarif_report([finding], [], sarif)

    assert "model_entailed" in md.read_text()
    assert json.loads(js.read_text())["findings"][0]["rung"] == "model_entailed"
    props = json.loads(sarif.read_text())["runs"][0]["results"][0]["properties"]
    assert props["rung"] == "model_entailed"


def test_every_rung_round_trips_through_json(tmp_path: Path) -> None:
    from openultrasast.findings import write_findings
    from openultrasast.model.ladder import Rung

    for rung in Rung:
        out = tmp_path / f"{rung.value}.json"
        write_findings([_finding(rung=rung)], out)
        assert json.loads(out.read_text())["findings"][0]["rung"] == rung.value
