"""Synthetic admission controls, not evidence of real capability eligibility."""

from dataclasses import replace

import pytest

from openultrasast.config import PushConfig
from openultrasast.model.contracts import QuestionIdentity, RankedQuestion, ScopeDecision
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison
from openultrasast.push.policy import (
    AdmissionCandidate,
    AdmissionResult,
    CandidateDelta,
    CapabilityAdmission,
    CapabilityKey,
    EvidenceOperation,
    admission_push_result,
    admit_candidates,
)


def control(language="javascript", framework="express"):
    q = QuestionIdentity("repository", language, "handler.src", "handler", "injection")
    op = EvidenceOperation(q, "taint", "handler.src", 4, "exec(command)", "request.input", False, "{}")
    delta = CandidateDelta(
        "injection",
        "handler.src:4:handler",
        "model_entailed",
        "request.input -> exec(command)",
        "defect",
        "new",
        "source_connection_absent_from_comparable_base",
        op,
        (),
        ("head:handler.src:2-2",),
        "base",
        "head",
        "synthetic-semantics-v1",
    )
    key = CapabilityKey(language, "server", framework, "injection", "taint", "shell-command", "synthetic-semantics-v1")
    comparison = PushComparison("head", "base", "remote", ("refs/heads/main",))
    candidate = AdmissionCandidate(delta, key, comparison)
    capability = CapabilityAdmission(
        key,
        "synthetic-only-evaluation",
        "synthetic://reviewed-controls",
        "PASS",
        "Untrusted input reaching {operation} permits command execution in {context}.",
        "At {operation}, use an argument-vector process API without a shell for {context}.",
        enabled=True,
        positive_controls=2,
        reviewed_alerts=2,
        calibration_artifact="synthetic://scorecard",
        untouched_workload="synthetic-control-population",
        operation_symbols=("exec",),
    )
    scope = ScopeDecision("v1", "static", True, (RankedQuestion(q, 1.0, ()),), (), ())
    analysis = ComparisonAnalysis(comparison, (scope,), (q,), "complete_within_scope")
    return candidate, capability, analysis


@pytest.mark.parametrize("language,framework", [("php", "wordpress"), ("javascript", "express")])
def test_equivalent_origins_admit_same_claim_and_only_block_when_enabled(language, framework):
    candidate, capability, analysis = control(language, framework)
    admission = admit_candidates((candidate,), capabilities=(capability,))
    assert len(admission.defects) == 1
    defect = admission.defects[0]
    assert defect.locations == (("handler.src", 4),)
    assert defect.witnesses == (candidate.delta.witness,)
    assert "exec(command)" in defect.repairs[0] and "shell-command" in defect.consequences[0]
    for mode, disposition in (("advisory", "allow"), ("blocking", "block")):
        result = admission_push_result(admission, (analysis,), config=PushConfig(mode=mode))
        assert result.finding_status == "actionable"
        assert result.push_disposition == disposition
        assert result.coverage_status == "complete_within_scope"
    assert AdmissionResult.from_payload(admission.to_payload()) == admission


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda c: replace(c, delta=replace(c.delta, rung="suspicion")), "insufficient_rung"),
        (lambda c: replace(c, delta=replace(c.delta, rung="model_corroborated")), "insufficient_rung"),
        (lambda c: replace(c, delta=replace(c.delta, rung="execution_confirmed")), "insufficient_rung"),
        (lambda c: replace(c, delta=replace(c.delta, novelty="unknown")), "comparison_unknown"),
        (lambda c: replace(c, delta=replace(c.delta, novelty="unchanged")), "unchanged"),
        (lambda c: replace(c, delta=replace(c.delta, witness=None)), "witness_unresolved"),
        (lambda c: replace(c, delta=replace(c.delta, site="elsewhere:1:f")), "location_unresolved"),
        (lambda c: replace(c, delta=replace(c.delta, head_operation=None)), "witness_unresolved"),
        (lambda c: replace(c, delta=replace(c.delta, change_evidence=())), "change_unsupported"),
        (lambda c: replace(c, dependency_gaps=("vendor-summary-missing",)), "dependency_unresolved"),
        (lambda c: replace(c, sanitizer_contexts=("html-output",)), "sanitizer_semantics_mismatch"),
        (lambda c: replace(c, delta=replace(c.delta, head_operation=replace(c.delta.head_operation, discharged=True))), "claim_discharged"),
        (lambda c: replace(c, capability=replace(c.capability, language="python")), "capability_unavailable"),
    ],
)
def test_rejected_claims_remain_diagnostics(mutation, reason):
    candidate, capability, _ = control()
    result = admit_candidates((mutation(candidate),), capabilities=(capability,))
    assert not result.defects
    assert reason in result.dispositions[0].reasons
    assert not result.dispositions[0].admitted


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda c: replace(c, enabled=False), "capability_disabled"),
        (lambda c: replace(c, verdict="experimental"), "capability_unevaluated"),
        (lambda c: replace(c, verdict="NO-GO"), "capability_unevaluated"),
        (lambda c: replace(c, key=replace(c.key, semantics="stale")), "capability_unavailable"),
        (lambda c: replace(c, key=replace(c.key, runtime="browser")), "capability_unavailable"),
        (lambda c: replace(c, key=replace(c.key, framework="other")), "capability_unavailable"),
        (lambda c: replace(c, repair_template="sanitize input"), "repair_unsupported"),
        (lambda c: replace(c, consequence_template="potential security issue"), "consequence_unsupported"),
    ],
)
def test_evaluated_semantics_and_grounded_repairs_required(mutation, reason):
    candidate, capability, _ = control()
    result = admit_candidates((candidate,), capabilities=(mutation(capability),))
    assert not result.defects
    assert reason in result.dispositions[0].reasons


def test_no_default_eligibility_and_unsupported_origin_is_a_coverage_gap():
    candidate, _, analysis = control()
    result = admit_candidates((candidate,))
    assert not result.defects and "capability_unavailable" in result.coverage_reasons
    push = admission_push_result(result, (analysis,), config=PushConfig(mode="blocking"))
    assert push.finding_status == "none" and push.coverage_status == "incomplete" and push.push_disposition == "allow"
    strict = admission_push_result(result, (analysis,), config=PushConfig(mode="blocking", incomplete_coverage_policy="block"))
    assert strict.push_disposition == "block" and strict.finding_status == "none"
    advisory = admission_push_result(result, (analysis,), config=PushConfig(incomplete_coverage_policy="block"))
    assert advisory.push_disposition == "allow"


def test_dedup_preserves_witnesses_and_comparisons_and_does_not_dismiss_printed_before():
    candidate, capability, _ = control()
    second = replace(
        candidate,
        delta=replace(candidate.delta, witness="request.other -> exec(command)", base_revision="other-base"),
        comparison=PushComparison("head", "other-base", "remote", ("refs/heads/release",)),
    )
    result = admit_candidates((candidate, second, candidate), capabilities=(capability,))
    assert len(result.defects) == 1 and len(result.dispositions) == 3
    defect = result.defects[0]
    assert len(defect.witnesses) == 2 and len(defect.comparisons) == 2
    assert defect.refs == ("refs/heads/main", "refs/heads/release")
    assert admit_candidates((candidate, second, candidate), capabilities=(capability,)) == result


def test_unknown_novelty_is_coverage_but_unchanged_debt_is_not():
    candidate, capability, analysis = control()
    for novelty, coverage in (("unknown", "incomplete"), ("unchanged", "complete_within_scope")):
        admission = admit_candidates((replace(candidate, delta=replace(candidate.delta, novelty=novelty)),), capabilities=(capability,))
        assert admission_push_result(admission, (analysis,)).coverage_status == coverage


def test_ambiguous_capability_declarations_fail_closed():
    candidate, capability, _ = control()
    result = admit_candidates((candidate,), capabilities=(capability, replace(capability, evaluation_id="other")))
    assert not result.defects and "capability_ambiguous" in result.coverage_reasons


def test_comparison_ownership_cannot_be_rebound_to_another_base_or_semantics():
    candidate, capability, _ = control()
    for altered in (
        replace(candidate, comparison=replace(candidate.comparison, base_oid="different-base")),
        replace(candidate, comparison=replace(candidate.comparison, head_oid="different-head")),
        replace(candidate, delta=replace(candidate.delta, semantics="other-semantics")),
        replace(candidate, delta=replace(candidate.delta, base_revision=None)),
    ):
        result = admit_candidates((altered,), capabilities=(capability,))
        assert not result.defects and "comparison_provenance_mismatch" in result.coverage_reasons


@pytest.mark.parametrize(
    "field,value", [("positive_controls", 0), ("reviewed_alerts", 0), ("calibration_artifact", None), ("untouched_workload", None)]
)
def test_pass_label_without_evaluation_population_is_not_eligibility(field, value):
    candidate, capability, _ = control()
    result = admit_candidates((candidate,), capabilities=(replace(capability, **{field: value}),))
    assert not result.defects and "capability_unevaluated" in result.coverage_reasons


def test_unchanged_on_one_base_does_not_suppress_new_on_another():
    candidate, capability, analysis = control()
    unchanged = replace(
        candidate,
        delta=replace(candidate.delta, base_revision="other-base", novelty="unchanged"),
        comparison=PushComparison("head", "other-base", "remote", ("refs/heads/debt",)),
    )
    result = admit_candidates((unchanged, candidate), capabilities=(capability,))
    assert len(result.defects) == 1 and result.defects[0].refs == candidate.comparison.refs
    assert result.defects[0].comparisons == (candidate.comparison,)
    with pytest.raises(ValueError, match="exact comparison"):
        admission_push_result(result, (replace(analysis, comparison=unchanged.comparison),))


def test_sql_operation_cannot_acquire_shell_consequence_from_same_family():
    candidate, capability, _ = control()
    operation = replace(candidate.delta.head_operation, operation="query(sql)")
    wrong_context = replace(candidate, delta=replace(candidate.delta, head_operation=operation, witness="req.query -> query(sql)"))
    result = admit_candidates((wrong_context,), capabilities=(capability,))
    assert not result.defects
    assert "operation_semantics_mismatch" in result.dispositions[0].reasons
    assert result.dispositions[0].candidate.delta.witness == "req.query -> query(sql)"


@pytest.mark.parametrize("symbols", [(), ("execSync",), ("query",)])
def test_missing_or_different_evaluated_operation_binding_is_diagnostic(symbols):
    candidate, capability, _ = control()
    result = admit_candidates((candidate,), capabilities=(replace(capability, operation_symbols=symbols),))
    assert not result.defects and "operation_semantics_mismatch" in result.coverage_reasons


@pytest.mark.parametrize("operation", ["query('exec(command)')", "custom.exec(command)", "execSync(command)"])
def test_evaluated_operation_matching_preserves_receiver_and_symbol_boundaries(operation):
    candidate, capability, _ = control()
    candidate = replace(
        candidate, delta=replace(candidate.delta, head_operation=replace(candidate.delta.head_operation, operation=operation))
    )
    assert not admit_candidates((candidate,), capabilities=(capability,)).defects
