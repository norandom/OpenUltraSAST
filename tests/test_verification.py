import json
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.findings import StaticFinding
from openultrasast.verification import (
    EvidenceLevel,
    VerificationStatus,
    build_independent_verifier_context,
    is_report_verified,
    validate_evidence_transition,
    verify_finding,
    write_verification_results,
)


def test_evidence_transition_rejects_backward_and_skipped_levels() -> None:
    assert validate_evidence_transition("suspicion", "static_corroboration") == EvidenceLevel.STATIC_CORROBORATION

    with pytest.raises(ValueError, match="backward"):
        validate_evidence_transition("root_cause_explained", "static_corroboration")

    with pytest.raises(ValueError, match="skip"):
        validate_evidence_transition("suspicion", "root_cause_explained")


def test_verified_status_requires_static_corroboration_and_acceptance() -> None:
    assert is_report_verified(EvidenceLevel.STATIC_CORROBORATION, VerificationStatus.ACCEPTED)
    assert not is_report_verified(EvidenceLevel.SUSPICION, VerificationStatus.ACCEPTED)
    assert not is_report_verified(EvidenceLevel.STATIC_CORROBORATION, VerificationStatus.REJECTED)


def test_independent_verifier_context_excludes_hunter_reasoning() -> None:
    finding = _finding(evidence_level="static_corroboration", reachability_status="reachable")

    context = build_independent_verifier_context(finding)

    assert "hunter_reasoning" not in context
    assert "chain_of_thought" not in context
    assert context["finding_id"] == finding.finding_id
    assert context["reachability_status"] == "reachable"


def test_verifier_accepts_reachable_static_corroborated_finding() -> None:
    finding = _finding(evidence_level="static_corroboration", reachability_status="reachable")

    result = verify_finding(finding)

    assert result.status == VerificationStatus.ACCEPTED
    assert result.verified
    assert result.evidence_level == EvidenceLevel.STATIC_CORROBORATION
    assert result.pro_case
    assert result.counter_case
    assert result.tie_breaker
    assert result.required_next_step


def test_verifier_rejects_unknown_reachability_static_finding() -> None:
    finding = _finding(evidence_level="static_corroboration", reachability_status="unknown")

    result = verify_finding(finding)

    assert result.status == VerificationStatus.REJECTED
    assert not result.verified
    assert "reach" in result.counter_case.lower()
    assert "call-graph" in result.tie_breaker


def test_verifier_does_not_verify_suspicion_only_finding() -> None:
    finding = _finding(evidence_level="suspicion", reachability_status="reachable")

    result = verify_finding(finding)

    assert result.status == VerificationStatus.NEEDS_EVIDENCE
    assert not result.verified
    assert result.required_next_step == "Collect static corroboration before reporting as verified."


def test_write_verification_results_artifact(tmp_path: Path) -> None:
    result = verify_finding(_finding(evidence_level="static_corroboration", reachability_status="reachable"))
    output = tmp_path / "verification.json"

    write_verification_results([result], output)

    payload = json.loads(output.read_text())
    assert payload["verifications"][0]["finding_id"] == "python-unsafe-eval:app.py:3"
    assert payload["verifications"][0]["status"] == "accepted"


def test_cli_scan_writes_accepted_and_rejected_verifications(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n\ndef helper(value):\n    return exec(value)\n"
    )
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "quick"]) == 0

    run_dirs = sorted((repo / ".runs").iterdir())
    verification_path = run_dirs[-1] / "verification.json"
    payload = json.loads(verification_path.read_text())
    statuses = {item["status"] for item in payload["verifications"]}

    assert statuses == {"accepted", "rejected"}


def _finding(*, evidence_level: str, reachability_status: str) -> StaticFinding:
    evidence = (
        [
            {
                "kind": "route",
                "access_level": "public",
                "line": 1,
                "end_line": 3,
                "function_name": "admin",
                "conditions": [],
            }
        ]
        if reachability_status == "reachable"
        else []
    )
    return StaticFinding(
        finding_id="python-unsafe-eval:app.py:3",
        path="app.py",
        title="Dynamic Python execution needs review",
        severity="high",
        confidence="medium",
        evidence_level=evidence_level,
        rationale="Static pattern matched.",
        line=3,
        function_name="admin" if reachability_status == "reachable" else None,
        reachability_status=reachability_status,
        reachability_evidence=evidence,
        reachability_conditions=[],
        tags=["syscall_entry"],
        ranking_priority=3.0,
    )
