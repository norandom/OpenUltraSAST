"""authorization-obligations task 3.2: reports and ranking name the obligation (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.findings import StaticFinding
from openultrasast.reports import write_markdown_report, write_sarif_report


def _obligation() -> StaticFinding:
    return StaticFinding(
        finding_id="obligation:protected_read:app.py:18:identity_constraint",
        path="app.py",
        title="Obligation not discharged: protected_read on book without identity_constraint",
        severity="high",
        confidence="low",
        evidence_level="suspicion",
        rationale=(
            "protected_read on book in leaky is reached without a dominating identity_constraint (a identity_constraint is present "
            "but bound from request_input). Why the obligation exists: app.py::constrained discharges identity_constraint. "
            "Label: consistency_violation. Known fix learned from the corpus: corpus:abc."
        ),
        line=18,
        function_name="leaky",
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[
            "obligation:protected_read",
            "discharger:identity_constraint",
            "obligation_evidence:consistency_violation",
            "resource:book",
            "mechanism:corpus:abc",
        ],
        ranking_priority=0.0,
    )


def _proven() -> StaticFinding:
    return StaticFinding(
        **{
            **_obligation().__dict__,
            "finding_id": "python-os-command:app.py:3",
            "evidence_level": "crash_reproduced",
            "tags": ["injection"],
            "line": 3,
            "ranking_priority": 1.0,
        }
    )


OBLIGATIONS = {
    "obligation:protected_read:app.py:18:identity_constraint": {
        "obligation": "protected_read",
        "resource": "book",
        "missing": "identity_constraint",
        "provenance": "request_input",
        "label": "consistency_violation",
        "evidence": ["app.py::constrained"],
        "known_fix": "corpus:abc",
        "intent": None,
    }
}
MECHANISMS = {
    "corpus:abc": {
        "summary": "missing_auth_guard: protected_read without identity_constraint; fix binds authenticated_context",
        "guard": "identity_constraint",
        "pairs": ["vampi"],
        "cwe": "CWE-639",
    }
}


def test_markdown_names_obligation_missing_discharger_evidence_and_known_fix(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    write_markdown_report([_obligation()], path, mechanisms=MECHANISMS, obligations=OBLIGATIONS)
    text = path.read_text()
    assert "- Obligation: `protected_read` on `book`" in text
    assert "- Missing discharger: `identity_constraint` (`request_input`)" in text
    assert "- Evidence: `consistency_violation`" in text and "app.py::constrained" in text
    assert "- Known fix: `identity_constraint`" in text and "vampi" in text
    assert "- Evidence level: `suspicion`" in text
    assert "## Obligations" in text
    summary = {
        "sibling_sets": 2,
        "under_populated": 1,
        "sets": [{"module": "api/books", "resource": "book", "handlers": 3}],
        "policy_version": "abc123",
    }
    write_markdown_report([_obligation()], path, mechanisms=MECHANISMS, obligations=OBLIGATIONS, obligations_summary=summary)
    text = path.read_text()
    assert "Sibling sets evaluated: 2 (under-populated: 1)" in text and "- `api/books` / `book`: 3 handlers" in text
    assert "Policy version: `abc123`" in text


def test_sarif_carries_obligation_properties(tmp_path: Path) -> None:
    path = tmp_path / "report.sarif"
    write_sarif_report([_obligation()], [], path, mechanisms=MECHANISMS, obligations=OBLIGATIONS)
    (result,) = json.loads(path.read_text())["runs"][0]["results"]
    props = result["properties"]
    assert props["obligation_kind"] == "protected_read" and props["obligation_missing"] == "identity_constraint"
    assert props["obligation_label"] == "consistency_violation" and props["obligation_evidence"] == ["app.py::constrained"]
    assert props["obligation_known_fix"] == "corpus:abc" and props["evidence_level"] == "suspicion"


def test_obligation_ranking_weighs_sensitivity_and_label_but_stays_below_proven_findings() -> None:
    from openultrasast.rank import rank_obligations

    declared = StaticFinding(
        **{
            **_obligation().__dict__,
            "finding_id": "obligation:protected_read:app.py:20:identity_constraint",
            "tags": ["obligation:protected_read", "discharger:identity_constraint", "obligation_evidence:declared_policy_violation"],
            "line": 20,
        }
    )
    local = StaticFinding(
        **{
            **_obligation().__dict__,
            "finding_id": "obligation:protected_read:app.py:22:identity_constraint",
            "tags": ["obligation:protected_read", "discharger:identity_constraint", "obligation_evidence:function_local"],
            "severity": "medium",
            "line": 22,
        }
    )
    ranked = rank_obligations([_proven(), _obligation(), declared, local])
    by_id = {f.finding_id: f.ranking_priority for f in ranked}
    assert by_id[declared.finding_id] > by_id[_obligation().finding_id] > by_id[local.finding_id] > 0
    assert max(by_id[f] for f in by_id if f.startswith("obligation:")) < by_id["python-os-command:app.py:3"]
    assert by_id["python-os-command:app.py:3"] == 1.0  # non-obligation findings untouched


def test_obligation_cap_binds_on_verdict_ids_because_the_pipeline_never_sets_proof_levels_on_static_findings() -> None:
    """Round-3 finding: proof rungs live on verdicts, so the cap is keyed on the proven finding ids the sandbox returned."""
    from openultrasast.rank import rank_obligations

    proven_by_sandbox = StaticFinding(**{**_proven().__dict__, "evidence_level": "static_corroboration", "ranking_priority": 0.35})
    ranked = rank_obligations([proven_by_sandbox, _obligation()], proven_ids={proven_by_sandbox.finding_id})
    by_id = {f.finding_id: f.ranking_priority for f in ranked}
    assert 0 < by_id[_obligation().finding_id] < 0.35 and by_id[proven_by_sandbox.finding_id] == 0.35
    unproven = rank_obligations([proven_by_sandbox, _obligation()])
    assert {f.finding_id: f.ranking_priority for f in unproven}[_obligation().finding_id] > 0.35  # no verdict, no cap


def test_reports_without_obligations_are_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    write_markdown_report([_proven()], path)
    assert "Obligation:" not in path.read_text() and "## Obligations" not in path.read_text()
