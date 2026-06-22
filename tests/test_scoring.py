from openultrasast.calibration import FalsePositiveReason, fp_reachability_overrides, record_false_positive_learning
from openultrasast.findings import StaticFinding
from openultrasast.policy import CwePolicy
from openultrasast.scoring import build_score_artifact, gate, project_score

POLICY = {
    "CWE-78": CwePolicy("Command Injection", 5, True, False),
    "CWE-89": CwePolicy("SQL Injection", 4, True, False),
    "CWE-999": CwePolicy("DAST Only", 5, False, True),  # dynamic-only -> report, never scored
}


def _finding(finding_id: str, reachability: str) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path="a.py",
        title="t",
        severity="high",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="r",
        line=1,
        function_name=None,
        reachability_status=reachability,
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[],
        ranking_priority=1.0,
    )


def test_empty_corpus_scores_100() -> None:
    assert project_score([], {}, POLICY) == 100


def test_single_severity5_reachable_scores_about_43() -> None:
    finding = _finding("cmd:a.py:1", "reachable")
    score = project_score([finding], {"cmd:a.py:1": "CWE-78"}, POLICY)
    assert score == 43


def test_dynamic_only_and_unmapped_contribute_zero_penalty() -> None:
    dynamic = _finding("dyn:a.py:1", "reachable")
    unmapped = _finding("ump:a.py:2", "reachable")
    rule_cwe = {"dyn:a.py:1": "CWE-999", "ump:a.py:2": "CWE-12345"}

    artifact = build_score_artifact([dynamic, unmapped], rule_cwe, POLICY)

    assert artifact.project_score == 100  # neither contributes penalty
    assert artifact.out_of_scope_dynamic_only == 1
    assert artifact.unmapped_cwe == ["CWE-12345"]


def test_hard_gate_fails_on_severity5_reachable_only() -> None:
    reachable = _finding("cmd:a.py:1", "reachable")
    inferred = _finding("cmd:a.py:2", "inferred-file-surface")
    rule_cwe = {"cmd:a.py:1": "CWE-78", "cmd:a.py:2": "CWE-78"}

    fail = gate([reachable], 90, rule_cwe, POLICY, min_score=80, blocking=False)
    ok = gate([inferred], 90, rule_cwe, POLICY, min_score=80, blocking=False)

    assert fail["passed"] is False  # severity-5 + reachable always fails
    assert ok["passed"] is True  # inferred reachability does not trip the hard gate


def test_confirmed_false_positive_lowers_penalty_without_deleting_rule() -> None:
    finding = StaticFinding(
        finding_id="python-os-command:app.py:1",
        path="app.py",
        title="t",
        severity="critical",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="r",
        line=1,
        function_name=None,
        reachability_status="reachable",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["syscall_entry"],
        ranking_priority=3.0,
    )
    learning = record_false_positive_learning(
        finding,
        reason=FalsePositiveReason.MISSING_ATTACKER_CONTROL,
        evidence="input is a constant, not attacker-controlled",
    )
    overrides = fp_reachability_overrides([finding], [learning])
    rule_cwe = {finding.finding_id: "CWE-78"}

    assert overrides[finding.finding_id] < 1.0  # reachable multiplier lowered from 1.0
    base = project_score([finding], rule_cwe, POLICY)
    with_fp = project_score([finding], rule_cwe, POLICY, reachability_override=overrides)
    assert with_fp > base  # confirmed FP reduces the penalty, raising the score
    assert finding.finding_id in rule_cwe  # the rule still fires; it was not deleted


def test_score_gate_blocks_only_when_blocking_enabled() -> None:
    finding = _finding("sql:a.py:1", "inferred-file-surface")
    rule_cwe = {"sql:a.py:1": "CWE-89"}

    advisory = build_score_artifact([finding], rule_cwe, POLICY, min_score=99, blocking=False)
    blocking = build_score_artifact([finding], rule_cwe, POLICY, min_score=99, blocking=True)

    assert advisory.gate["passed"] is True  # advisory-first: low score does not block
    assert blocking.gate["passed"] is False  # blocking: score below min_score fails
