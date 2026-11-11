"""Input and operational validation helpers for completed V3 reports."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from openultrasast.core import canonical
from openultrasast.core._admission_funnel import aggregate_funnels
from openultrasast.core.coverage import CoverageFunnel
from openultrasast.core.evaluation_combination import (
    CombinationLineageV3,
    CombinationValidationError,
    derive_combination_lineages_v3,
)
from openultrasast.core.evaluation_measurement import ArmKindV3, ScopedMetricResultV3
from openultrasast.core.evaluation_metric_derivation import validate_complete_scoped_metrics_v3
from openultrasast.core.evaluation_observation import ArmObservationSetV3
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import (
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    EvaluationReleaseError,
    derive_released_arm_case_binding,
)
from openultrasast.core.model import ModelStatus
from openultrasast.core.readiness import ReadinessResult, StageResult, validate_readiness_result

if TYPE_CHECKING:
    from openultrasast.core.evaluation_report import ArmOperationalEvidenceV3


def funnel_value(value: object) -> canonical.JsonValue:
    from openultrasast.core.evaluation_report import EvaluationReportError

    if type(value) is not CoverageFunnel:
        raise EvaluationReportError("stage funnel must use exact CoverageFunnel")
    value.__post_init__()
    return {
        "inputs_read": value.inputs_read,
        "questions_formed": value.questions_formed,
        "sites_considered": value.sites_considered,
        "sites_recognized": value.sites_recognized,
        "transitions_materialized": value.transitions_materialized,
        "security_objects_constructed": value.security_objects_constructed,
        "constraints_evaluated": value.constraints_evaluated,
        "determinate_outcomes": value.determinate_outcomes,
        "findings_emitted": value.findings_emitted,
        "relations": tuple((item.status.value, item.count) for item in value.relation_status_counts),
        "unresolved": tuple((item.reason, item.count) for item in value.unresolved_by_reason),
    }


def derive_operational_evidence(cases: tuple[ArmAdmissionCaseResultV3, ...]) -> ArmOperationalEvidenceV3:
    from openultrasast.core.evaluation_report import ArmOperationalEvidenceV3, DegradationReasonV3

    funnel = aggregate_funnels(tuple(case.coverage for case in cases))
    failures = tuple(
        sorted(
            {
                item.model_result.failure_reason
                for case in cases
                for item in case.evidence_inputs
                if item.model_result is not None
                and item.model_result.status is ModelStatus.FAILED
                and item.model_result.failure_reason is not None
            }
        )
    )
    reasons = set()
    if failures:
        reasons.add(DegradationReasonV3.MODEL)
    if any(case.total_reply_ms > case.budget.budget_ms for case in cases):
        reasons.add(DegradationReasonV3.BUDGET)
    if funnel.unresolved_by_reason:
        reasons.add(DegradationReasonV3.COVERAGE)
    completed = tuple(sorted(case.case_id_digest for case in cases))
    return ArmOperationalEvidenceV3(
        len(completed),
        0,
        completed,
        (),
        funnel,
        (),
        failures,
        sum(case.total_reply_ms for case in cases),
        tuple(reason for reason in DegradationReasonV3 if reason in reasons),
        "",
    )


def validate_report_input_types(
    plan: object,
    groups: object,
    metrics: object,
    readiness: object,
    observations: object,
    lineages: object,
    whole: object,
) -> tuple[
    EvaluationPlanManifestV3,
    tuple[ArmAdmissionCasesV3, ...],
    tuple[ScopedMetricResultV3, ...],
    tuple[ReadinessResult, ...],
    tuple[ArmObservationSetV3, ...],
    tuple[CombinationLineageV3, ...],
    WholePopulationProjectionV3,
]:
    from openultrasast.core.evaluation_report import EvaluationReportError

    if type(plan) is not EvaluationPlanManifestV3:
        raise EvaluationReportError("report plan must use exact EvaluationPlanManifestV3")
    plan.__post_init__()
    expected = (
        (groups, ArmAdmissionCasesV3, "case groups"),
        (metrics, ScopedMetricResultV3, "scoped metrics"),
        (readiness, ReadinessResult, "readiness"),
        (observations, ArmObservationSetV3, "observations"),
        (lineages, CombinationLineageV3, "combination lineages"),
    )
    for values, item_type, field in expected:
        if type(values) is not tuple or any(type(item) is not item_type for item in values):
            raise EvaluationReportError(f"{field} must use an exact tuple of {item_type.__name__}")
    if type(whole) is not WholePopulationProjectionV3:
        raise EvaluationReportError("whole coverage source must use exact WholePopulationProjectionV3")
    return (
        plan,
        cast(tuple[ArmAdmissionCasesV3, ...], groups),
        cast(tuple[ScopedMetricResultV3, ...], metrics),
        cast(tuple[ReadinessResult, ...], readiness),
        cast(tuple[ArmObservationSetV3, ...], observations),
        cast(tuple[CombinationLineageV3, ...], lineages),
        whole,
    )


def validate_complete_report_inputs(
    plan: EvaluationPlanManifestV3,
    groups: tuple[ArmAdmissionCasesV3, ...],
    metrics: tuple[ScopedMetricResultV3, ...],
    readiness: tuple[ReadinessResult, ...],
    observations: tuple[ArmObservationSetV3, ...],
    lineages: tuple[CombinationLineageV3, ...],
    whole: WholePopulationProjectionV3,
) -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    configurations = plan.declaration.arm_configurations
    if tuple(group.arm_id for group in groups) != tuple(item.arm_id for item in plan.baselines):
        raise EvaluationReportError("case groups must completely match planned baseline arms")
    for group, baseline in zip(groups, plan.baselines, strict=True):
        group.__post_init__()
        if group.baseline_digest != baseline.baseline_digest:
            raise EvaluationReportError("case group baseline differs from the reviewed plan")
    policies = tuple(policy for configuration in configurations for policy in configuration.denominator_policies)
    validate_complete_scoped_metrics_v3(policies, metrics)
    _validate_readiness(plan, readiness)
    _validate_observations(plan, observations)
    _validate_observed_cases(groups, observations)
    _validate_lineages(plan, groups, lineages)
    whole.__post_init__()
    pushes = tuple(sorted({case.underlying_push_digest for group in groups for case in group.cases}))
    if whole.underlying_push_digests != pushes:
        raise EvaluationReportError("whole population coverage differs from completed released cases")


def _validate_readiness(plan: EvaluationPlanManifestV3, readiness: tuple[ReadinessResult, ...]) -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    for item in readiness:
        validate_readiness_result(item)
    if tuple(sorted(item.result_digest for item in readiness)) != plan.readiness_digests or any(
        item.result is not StageResult.PASSED for item in readiness
    ):
        raise EvaluationReportError("completed reports require the exact reviewed passed readiness set")


def _validate_observations(plan: EvaluationPlanManifestV3, observations: tuple[ArmObservationSetV3, ...]) -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    slots = plan.declaration.expected_observation_slots
    configurations = {item.arm_id: item for item in plan.declaration.arm_configurations}
    if tuple(item.slot_digest for item in observations) != tuple(item.slot_digest for item in slots):
        raise EvaluationReportError("completed observations must exactly cover every required planned stage slot")
    for observation, slot in zip(observations, slots, strict=True):
        observation.__post_init__()
        configuration = configurations[slot.arm_id]
        expected = (
            slot.arm_id,
            slot.input_identity_digest,
            configuration.registered_budget_digest,
            configuration.configuration_identity_digest,
        )
        actual = (
            observation.arm_id,
            observation.input_identity_digest,
            observation.registered_budget_digest,
            observation.configuration_digest,
        )
        missing_evidence = observation.input_read_evidence_digest == "0" * 64 or observation.stage_execution_evidence_digest == "0" * 64
        if actual != expected or missing_evidence:
            raise EvaluationReportError("completed observation has unread input or skipped required stage evidence")


def _validate_observed_cases(groups: tuple[ArmAdmissionCasesV3, ...], observations: tuple[ArmObservationSetV3, ...]) -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    observed = {
        (observation.arm_id, reference.case_id_digest): (observation, reference)
        for observation in observations
        for reference in observation.cases
    }
    released = {(case.key.arm_id, case.case_id_digest): case for group in groups for case in group.cases}
    if len(observed) != sum(len(item.cases) for item in observations) or set(observed) != set(released):
        raise EvaluationReportError("released cases must equal the complete observed case set")
    for key, case in released.items():
        observation, reference = observed[key]
        candidate = case.proof_candidate.candidate_digest if case.proof_candidate is not None else None
        expected = (
            observation.slot_digest,
            observation.observation_digest,
            reference.underlying_push_digest,
            reference.result_digest,
            reference.case_input_digest,
            reference.outcome_projection,
            reference.proof_candidate_digest,
        )
        actual = (
            case.observation_slot_digest,
            case.observation_digest,
            case.underlying_push_digest,
            case.result_digest,
            case.case_input_digest,
            case.outcome_projection,
            candidate,
        )
        if actual != expected:
            raise EvaluationReportError("released case differs from its exact observed case")


def _validate_lineages(
    plan: EvaluationPlanManifestV3,
    groups: tuple[ArmAdmissionCasesV3, ...],
    lineages: tuple[CombinationLineageV3, ...],
) -> None:
    from openultrasast.core.evaluation_report import EvaluationReportError

    combined = tuple(item for item in plan.declaration.arm_configurations if item.kind is ArmKindV3.COMBINED)
    if not combined:
        if lineages:
            raise EvaluationReportError("a plan without combined arms requires an empty combination lineage set")
        return
    try:
        for lineage in lineages:
            lineage.__post_init__()
        bindings = tuple(
            sorted(
                (derive_released_arm_case_binding(case, plan) for group in groups for case in group.cases),
                key=lambda item: (
                    item.key.arm_id,
                    item.key.scope.family_id,
                    item.key.scope.ecosystem,
                    item.case_id_digest,
                ),
            )
        )
        expected = derive_combination_lineages_v3(plan.declaration, bindings)
    except (CombinationValidationError, EvaluationReleaseError) as exc:
        raise EvaluationReportError(f"combination lineage derivation failed for current released cases: {exc}") from exc
    if lineages != expected:
        raise EvaluationReportError("combination lineage does not equal replay from the current released cases")
