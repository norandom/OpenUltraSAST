"""Verifier dispatcher: structural fallback (default) + judge verdict mapping (Phase 3 task 6.4)."""

from openultrasast.findings import StaticFinding
from openultrasast.verification import VerificationStatus, verify_findings
from openultrasast.verify_judge import _verdict_to_verification, verify_findings_dispatch


def _finding(reachability: str = "reachable") -> StaticFinding:
    return StaticFinding(
        finding_id="python-unsafe-eval:app.py:3",
        path="app.py",
        title="Dynamic Python execution needs review",
        severity="critical",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="Static pattern matched.",
        line=3,
        function_name="admin" if reachability == "reachable" else None,
        reachability_status=reachability,
        reachability_evidence=[{"kind": "route", "access_level": "public", "line": 1, "end_line": 3}]
        if reachability == "reachable"
        else [],
        reachability_conditions=[],
        tags=["syscall_entry"],
        ranking_priority=3.0,
    )


def test_dispatch_falls_back_to_structural_by_default() -> None:
    findings = [_finding("reachable"), _finding("unknown")]
    assert verify_findings_dispatch(findings) == verify_findings(findings)


def test_dispatch_stays_structural_when_model_unset_or_extra_absent() -> None:
    findings = [_finding("reachable")]
    # use_harnessx requested but no model -> structural; and no model -> structural.
    assert verify_findings_dispatch(findings, verifier_model=None, use_harnessx=True) == verify_findings(findings)
    assert verify_findings_dispatch(findings, verifier_model="claude-x", use_harnessx=False) == verify_findings(findings)


def test_dispatch_does_not_import_harnessx_on_fallback(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    # Even with a model and use_harnessx=True, when the capability is absent the
    # dispatch must fall back without importing the extra. Simulate absence so the
    # guarantee holds whether or not the extra is installed in this environment.
    assert_cold_of_harnessx(
        "import openultrasast.verify_judge as vj\n"
        "vj.has_harnessx = lambda: False\n"
        "from openultrasast.findings import StaticFinding\n"
        "f = StaticFinding(finding_id='x:app.py:1', path='app.py', title='t', severity='low',\n"
        "    confidence='low', evidence_level='static_corroboration', rationale='r', line=1,\n"
        "    function_name=None, reachability_status='unknown', reachability_evidence=[],\n"
        "    reachability_conditions=[], tags=[], ranking_priority=1.0)\n"
        "vj.verify_findings_dispatch([f], verifier_model='claude-x', use_harnessx=True)\n"
    )


def test_verdict_mapping_is_evidence_gated() -> None:
    finding = _finding("reachable")
    accepted = _verdict_to_verification(finding, {"verdict": "plausible", "confidence": 0.9, "cause": "tainted sink reached"})
    low_conf = _verdict_to_verification(finding, {"verdict": "plausible", "confidence": 0.3})
    rejected = _verdict_to_verification(finding, {"verdict": "unsupported", "cause": "input is constant"})
    hedging = _verdict_to_verification(finding, {"verdict": "hedging"})
    infra = _verdict_to_verification(finding, {"verdict": "no_answer"})

    assert accepted.status == VerificationStatus.ACCEPTED and accepted.verified
    assert accepted.pro_case == "tainted sink reached"
    assert low_conf.status == VerificationStatus.NEEDS_EVIDENCE
    assert rejected.status == VerificationStatus.REJECTED and rejected.counter_case == "input is constant"
    assert hedging.status == VerificationStatus.NEEDS_EVIDENCE
    assert infra.status == VerificationStatus.NEEDS_EVIDENCE  # infra failure never auto-rejects
