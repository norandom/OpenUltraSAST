"""Fusion adjudication: trigger policy, two-panel decider, dispositions (Phase 13)."""

import json
from pathlib import Path

import pytest

from openultrasast.findings import StaticFinding
from openultrasast.fusion import (
    FusionDisposition,
    fuse_finding,
    fuse_findings_dispatch,
    fusion_triggers,
    should_fuse,
)
from openultrasast.harness_ext import has_harnessx
from openultrasast.verification import EvidenceLevel, VerificationResult, VerificationStatus


def _finding(
    *,
    finding_id: str = "python-unsafe-eval:app.py:3",
    severity: str = "critical",
    reachability: str = "reachable",
) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path="app.py",
        title="Dynamic Python execution",
        severity=severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="eval on request data",
        line=3,
        function_name="admin",
        reachability_status=reachability,
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["injection"],
        ranking_priority=3.0,
    )


def _verification(status: VerificationStatus, *, verified: bool) -> VerificationResult:
    return VerificationResult(
        finding_id="python-unsafe-eval:app.py:3",
        status=status,
        evidence_level=EvidenceLevel.STATIC_CORROBORATION,
        verified=verified,
        pro_case="reachable tainted sink",
        counter_case="input may be constant",
        tie_breaker="confirm attacker control",
        required_next_step="dynamic repro",
        context_sources=["app.py"],
    )


# ---- trigger policy ---------------------------------------------------------


def test_triggers_on_high_severity_and_reachable() -> None:
    triggers = fusion_triggers(_finding(severity="critical", reachability="reachable"))
    assert "severity:critical" in triggers
    assert "gates_risky_fix" in triggers


def test_low_severity_unreachable_does_not_trigger() -> None:
    assert not should_fuse(_finding(severity="low", reachability="unknown"))


def test_verifier_disagreement_triggers() -> None:
    triggers = fusion_triggers(
        _finding(severity="low", reachability="unknown"),
        _verification(VerificationStatus.NEEDS_EVIDENCE, verified=False),
    )
    assert triggers == ["verifier_disagreement"]


def test_evidence_conflict_triggers_when_rejected_but_reachable() -> None:
    triggers = fusion_triggers(
        _finding(severity="low", reachability="reachable"),
        _verification(VerificationStatus.REJECTED, verified=False),
    )
    assert "evidence_conflict" in triggers


def test_high_assurance_request_forces_a_trigger() -> None:
    assert should_fuse(_finding(severity="low", reachability="unknown"), high_assurance=True)


# ---- deterministic two-panel decider + dispositions -------------------------


def test_accepted_when_reachable_and_verified() -> None:
    decision = fuse_finding(_finding(), _verification(VerificationStatus.ACCEPTED, verified=True), ["severity:critical"])
    assert decision.disposition == FusionDisposition.ACCEPTED
    assert decision.decision_source == "deterministic-reconciler"
    assert {p.role for p in decision.panels} == {"panel_a", "panel_b"}
    assert sum(decision.votes.values()) == 2  # both panels voted


def test_blocked_when_reachable_high_severity_but_unverified() -> None:
    decision = fuse_finding(_finding(), _verification(VerificationStatus.NEEDS_EVIDENCE, verified=False), ["gates_risky_fix"])
    assert decision.disposition == FusionDisposition.BLOCKED


def test_rejected_when_verifier_rejects_unreachable() -> None:
    decision = fuse_finding(
        _finding(reachability="unknown"), _verification(VerificationStatus.REJECTED, verified=False), ["severity:critical"]
    )
    assert decision.disposition == FusionDisposition.REJECTED


def test_deferred_when_evidence_conflicts() -> None:
    decision = fuse_finding(_finding(severity="low"), _verification(VerificationStatus.REJECTED, verified=False), ["evidence_conflict"])
    assert decision.disposition == FusionDisposition.DEFERRED


def test_mitigated_when_finding_is_known_mitigated() -> None:
    finding = _finding()
    decision = fuse_finding(
        finding,
        _verification(VerificationStatus.ACCEPTED, verified=True),
        ["severity:critical"],
        mitigated_ids=frozenset({finding.finding_id}),
    )
    assert decision.disposition == FusionDisposition.MITIGATED


# ---- dispatch + disclosure + serialization ----------------------------------


def test_dispatch_only_fuses_triggered_findings() -> None:
    findings = [
        _finding(finding_id="hot:app.py:3", severity="critical"),
        _finding(finding_id="cold:lib.py:9", severity="low", reachability="unknown"),
    ]
    decisions = fuse_findings_dispatch(findings, [])
    assert [d.finding_id for d in decisions] == ["hot:app.py:3"]


def test_dispatch_records_degradation_when_llm_requested_but_extra_absent() -> None:
    if has_harnessx():
        pytest.skip("HarnessX extra installed; exercises the extra-absent degradation path")
    decisions = fuse_findings_dispatch([_finding()], [], panel_model="gpt-4o", use_harnessx=True)
    assert decisions and decisions[0].decision_source == "deterministic-reconciler"
    assert any("fusion_llm_unavailable" in note for note in decisions[0].degradations)


def test_decision_serializes_with_full_disclosure() -> None:
    decision = fuse_finding(_finding(), _verification(VerificationStatus.ACCEPTED, verified=True), ["severity:critical"])
    payload = json.loads(json.dumps(decision.to_dict()))
    assert payload["disposition"] == "accepted"
    assert payload["decision_source"] == "deterministic-reconciler"
    assert "votes" in payload and "model_ids" in payload and "degradations" in payload
    assert all("leaning" in panel and "disposition" in panel for panel in payload["panels"])


# ---- CLI integration: standard-mode fusion stage ----------------------------


def test_standard_scan_emits_fusion_artifact_and_manifest_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cli import main

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    fusion = json.loads((run_dir / "fusion.json").read_text())
    assert fusion and fusion[0]["disposition"] in {"accepted", "blocked", "deferred", "rejected", "mitigated"}
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["fusion"][0]["finding_id"] == fusion[0]["finding_id"]
    assert "fusion" in manifest["artifacts"]


def test_quick_scan_does_not_emit_fusion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cli import main

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    assert main(["scan", str(repo), "--mode", "quick"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    assert not (run_dir / "fusion.json").exists()
    assert "fusion" not in json.loads((run_dir / "manifest.json").read_text())
