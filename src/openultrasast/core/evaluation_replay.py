"""Complete non-authorizing evaluation replay construction for admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core._evaluation_replay_report import (
    EvaluationReplayReportError,
    validate_replay_collections,
    validate_replayed_reports,
    validate_report_source,
)
from openultrasast.core.custody import (
    PopulationStatus,
    PopulationUseReceipt,
    derive_population_use_receipt_digest,
    derive_population_use_request_digest,
)
from openultrasast.core.evaluation_aggregate import EvaluationAggregateV3
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionAuthorityV3,
    EvaluationAdmissionManifestV3,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
    derive_evaluation_observation_set_digest,
    derive_evaluation_readiness_set_digest,
)
from openultrasast.core.evaluation_combination import CombinationLineageV3, derive_combination_lineages_v3
from openultrasast.core.evaluation_feasibility import EvaluationFeasibilityV3
from openultrasast.core.evaluation_measurement import ScopedMetricResultV3
from openultrasast.core.evaluation_observation import ArmObservationSetV3
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3
from openultrasast.core.evaluation_plan import (
    EvaluationPlanManifestV3,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
)
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCasesV3,
    ReleasedArmCaseBindingV3,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_released_arm_case_binding,
)
from openultrasast.core.evaluation_report import ArmEvaluationReportV3, WholePopulationCoverageV3
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.readiness import ReadinessResult

_SCHEMA = "openultrasast.detection-core.evaluation-replay.v3"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class EvaluationReplayError(ValueError):
    """A complete replay could not be assembled from the exact shared graph."""


@dataclass(frozen=True)
class EvaluationReplayReportSourceV3(EvaluationV3Contract, NonAuthorizingV3):
    """Exact source artifacts required to reproduce completed reports inside a replay."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    metrics: tuple[ScopedMetricResultV3, ...]
    readiness: tuple[ReadinessResult, ...]
    observations: tuple[ArmObservationSetV3, ...]
    whole_projection: WholePopulationProjectionV3
    source_digest: str

    def __post_init__(self) -> None:
        try:
            validate_report_source(self)
        except EvaluationReplayReportError as exc:
            raise EvaluationReplayError(f"report source is invalid: {exc}") from exc


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationReplayError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationReplayError(f"{field} does not match canonical replay content")


def _payload(value: EvaluationReplayV3) -> canonical.JsonValue:
    return {
        "plan_manifest_digest": value.plan_manifest.manifest_digest,
        "feasibility_digest": value.feasibility.feasibility_digest,
        "admission_manifest_digest": value.admission_manifest.manifest_digest,
        "authority_digest": value.authority.authority_digest,
        "preparation_digest": value.preparation.preparation_digest,
        "receipt_digest": value.receipt.receipt_digest,
        "spend_binding_digest": value.spend_binding.binding_digest,
        "case_release_digest": value.case_release.release_digest,
        "case_group_digests": tuple(group.cases_digest for group in value.cases_by_arm),
        "report_source_digest": value.report_source.source_digest,
        "report_digests": tuple(report.report_digest for report in value.reports),
        "combination_lineage_digests": tuple(lineage.lineage_digest for lineage in value.combination_lineages),
        "attempt_history_head_digest": value.attempt_history_head_digest,
        "whole_population_coverage_digest": value.whole_population_coverage.coverage_digest,
        "aggregate_digest": None if value.aggregate is None else value.aggregate.aggregate_digest,
    }


@dataclass(frozen=True)
class EvaluationReplayV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    plan_manifest: EvaluationPlanManifestV3
    feasibility: EvaluationFeasibilityV3
    admission_manifest: EvaluationAdmissionManifestV3
    authority: EvaluationAdmissionAuthorityV3
    preparation: EvaluationPreparationV3
    receipt: PopulationUseReceipt
    spend_binding: EvaluationSpendBindingV3
    case_release: AdmissionCaseReleaseV3
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...]
    report_source: EvaluationReplayReportSourceV3
    reports: tuple[ArmEvaluationReportV3, ...]
    combination_lineages: tuple[CombinationLineageV3, ...]
    attempt_history_head_digest: str
    whole_population_coverage: WholePopulationCoverageV3
    aggregate: EvaluationAggregateV3 | None
    replay_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationReplayV3, field="evaluation replay")
        _validate_complete_replay(self)
        _bind(
            self,
            "replay_digest",
            canonical.content_digest({"schema_version": _SCHEMA, "kind": "evaluation_replay", "payload": _payload(self)}),
        )


def _validate_roots(value: EvaluationReplayV3) -> None:
    exact = (
        (value.plan_manifest, EvaluationPlanManifestV3, "plan"),
        (value.feasibility, EvaluationFeasibilityV3, "feasibility"),
        (value.admission_manifest, EvaluationAdmissionManifestV3, "admission manifest"),
        (value.authority, EvaluationAdmissionAuthorityV3, "authority"),
        (value.preparation, EvaluationPreparationV3, "preparation"),
        (value.receipt, PopulationUseReceipt, "receipt"),
        (value.spend_binding, EvaluationSpendBindingV3, "spend binding"),
        (value.case_release, AdmissionCaseReleaseV3, "case release"),
        (value.whole_population_coverage, WholePopulationCoverageV3, "whole population coverage"),
    )
    for item, item_type, field in exact:
        if type(item) is not item_type:
            raise EvaluationReplayError(f"{field} must use exact {item_type.__name__}")
        item.__post_init__()
    try:
        validate_replay_collections(value)
    except EvaluationReplayReportError as exc:
        raise EvaluationReplayError(f"replay collection is invalid: {exc}") from exc


def _validate_pre_spend_graph(value: EvaluationReplayV3) -> None:
    plan = value.plan_manifest
    admission = value.admission_manifest
    if plan.payload_digest != derive_evaluation_plan_manifest_payload_digest(
        plan
    ) or plan.manifest_digest != derive_evaluation_plan_manifest_digest(plan):
        raise EvaluationReplayError("reviewed plan identity is not canonical")
    if plan.review.subject_digest != plan.payload_digest or plan.census.review.subject_digest != plan.census.payload_digest:
        raise EvaluationReplayError("reviewed plan or census review is not bound to its canonical payload")
    expected_keys = tuple(
        policy.key for configuration in plan.declaration.arm_configurations for policy in configuration.denominator_policies
    )
    if value.feasibility.plan_manifest_digest != plan.manifest_digest or tuple(row.key for row in value.feasibility.rows) != expected_keys:
        raise EvaluationReplayError("feasibility does not completely match the reviewed plan")
    if not value.feasibility.may_spend:
        raise EvaluationReplayError("complete replay requires feasible shared spend")
    if admission.plan_manifest != plan or admission.feasibility_digest != value.feasibility.feasibility_digest:
        raise EvaluationReplayError("admission manifest differs from the exact plan or feasibility")
    if admission.payload_digest != derive_evaluation_admission_manifest_payload_digest(
        admission
    ) or admission.manifest_digest != derive_evaluation_admission_manifest_digest(admission):
        raise EvaluationReplayError("admission manifest identity is not canonical")
    if admission.review.subject_digest != admission.payload_digest:
        raise EvaluationReplayError("admission review is not bound to its canonical payload")
    expected = (
        admission.manifest_digest,
        plan.manifest_digest,
        tuple(baseline.baseline_digest for baseline in plan.baselines),
        value.feasibility.feasibility_digest,
        derive_evaluation_observation_set_digest(admission.observations),
        derive_evaluation_readiness_set_digest(admission.readiness_digests),
        admission.custody_log_digest,
        admission.attempt_history.head_event_digest,
        admission.review.attestation_digest,
    )
    actual = (
        value.authority.admission_manifest_digest,
        value.authority.plan_manifest_digest,
        value.authority.baseline_digests,
        value.authority.feasibility_digest,
        value.authority.observation_set_digest,
        value.authority.readiness_set_digest,
        value.authority.custody_log_digest,
        value.authority.attempt_history_head_digest,
        value.authority.admission_review_digest,
    )
    if actual != expected:
        raise EvaluationReplayError("authority does not match the complete reviewed pre-spend graph")


def _validate_spend_graph(value: EvaluationReplayV3) -> None:
    preparation = value.preparation
    receipt = value.receipt
    spend = value.spend_binding
    baselines = tuple(item.baseline_digest for item in value.plan_manifest.baselines)
    if preparation.authority != value.authority or preparation.planned_baseline_digests != baselines:
        raise EvaluationReplayError("preparation does not cover the exact authority and planned arms")
    population = value.plan_manifest.declaration.population_digest
    if preparation.label_release_request.population_digest != population or receipt.population_digest != population:
        raise EvaluationReplayError("custody receipt population differs from the reviewed plan")
    if receipt.request != preparation.label_release_request:
        raise EvaluationReplayError("receipt request differs from the exact preparation")
    if receipt.request_digest != derive_population_use_request_digest(
        receipt.request
    ) or receipt.receipt_digest != derive_population_use_receipt_digest(receipt):
        raise EvaluationReplayError("receipt identity is not canonical")
    if receipt.prior_status is not PopulationStatus.AVAILABLE or receipt.status is not PopulationStatus.SPENT:
        raise EvaluationReplayError("receipt is not the exact available-to-spent custody transition")
    if (spend.preparation_digest, spend.receipt_digest, spend.planned_baseline_digests) != (
        preparation.preparation_digest,
        receipt.receipt_digest,
        baselines,
    ):
        raise EvaluationReplayError("spend binding differs from preparation, receipt, or planned arms")


def _validate_release_and_reports(value: EvaluationReplayV3) -> tuple[ReleasedArmCaseBindingV3, ...]:
    plan = value.plan_manifest
    release = value.case_release
    expected_release = (
        plan.manifest_digest,
        value.admission_manifest.manifest_digest,
        value.authority.authority_digest,
        value.preparation.preparation_digest,
        value.spend_binding.binding_digest,
    )
    actual_release = (
        release.plan_manifest_digest,
        release.admission_manifest_digest,
        release.authority_digest,
        release.preparation_digest,
        release.spend_binding_digest,
    )
    if actual_release != expected_release:
        raise EvaluationReplayError("case release differs from the complete shared graph")
    if release.payload_digest != derive_admission_case_release_payload_digest_v3(
        release
    ) or release.release_digest != derive_admission_case_release_digest_v3(release):
        raise EvaluationReplayError("case release identity is not canonical")
    if release.review.subject_digest != release.payload_digest:
        raise EvaluationReplayError("case release review is not bound to its canonical payload")
    group_roots = tuple((group.arm_id, group.baseline_digest) for group in value.cases_by_arm)
    planned_roots = tuple((baseline.arm_id, baseline.baseline_digest) for baseline in plan.baselines)
    if group_roots != planned_roots or tuple(report.baseline for report in value.reports) != plan.baselines:
        raise EvaluationReplayError("case groups and reports must completely match every planned arm")
    expected_bindings = tuple(
        sorted(
            (derive_released_arm_case_binding(case, plan) for group in value.cases_by_arm for case in group.cases),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    if release.bindings != expected_bindings:
        raise EvaluationReplayError("case release bindings differ from the complete replay cases")
    return expected_bindings


def _validate_reports_and_lineage(value: EvaluationReplayV3, bindings: tuple[ReleasedArmCaseBindingV3, ...]) -> None:
    plan = value.plan_manifest
    configurations = {item.arm_id: item for item in plan.declaration.arm_configurations}
    report_by_arm = {item.baseline.arm_id: item for item in value.reports}
    if len(report_by_arm) != len(value.reports):
        raise EvaluationReplayError("reports must contain every planned arm exactly once")
    for group in value.cases_by_arm:
        report = report_by_arm[group.arm_id]
        expected_keys = tuple(policy.key for policy in configurations[group.arm_id].denominator_policies)
        if tuple(result.key for result in report.scoped_results) != expected_keys:
            raise EvaluationReplayError("report scopes do not completely match the planned arm scopes")
        completed = tuple(sorted(case.case_id_digest for case in group.cases))
        if report.operational_evidence.completed_case_digests != completed or report.operational_evidence.deferred_case_digests:
            raise EvaluationReplayError("report operational cases differ from the complete released arm cases")
    expected_lineages = derive_combination_lineages_v3(plan.declaration, bindings)
    if value.combination_lineages != expected_lineages:
        raise EvaluationReplayError("combination lineage does not replay from every required component")
    by_arm = {item.rule.combined_arm_id: item for item in value.combination_lineages}
    for report in value.reports:
        if report.combination_lineage != by_arm.get(report.baseline.arm_id):
            raise EvaluationReplayError("report combination lineage differs from the complete replay")


def _validate_coverage_and_aggregate(value: EvaluationReplayV3) -> None:
    pushes = {case.underlying_push_digest for group in value.cases_by_arm for case in group.cases}
    coverage = value.whole_population_coverage
    if (
        coverage.underlying_push_count != len(pushes)
        or coverage.completed_underlying_push_count != len(pushes)
        or coverage.deferred_underlying_push_count != 0
    ):
        raise EvaluationReplayError("whole population coverage does not reconcile to released cases and census")


def _validate_complete_replay(value: EvaluationReplayV3) -> None:
    _validate_roots(value)
    _digest(value.attempt_history_head_digest, "attempt history head digest")
    _validate_pre_spend_graph(value)
    if value.attempt_history_head_digest != value.admission_manifest.attempt_history.head_event_digest:
        raise EvaluationReplayError("attempt history head differs from the reviewed admission graph")
    _validate_spend_graph(value)
    bindings = _validate_release_and_reports(value)
    _validate_reports_and_lineage(value, bindings)
    _validate_coverage_and_aggregate(value)
    try:
        validate_replayed_reports(value)
    except EvaluationReplayReportError as exc:
        raise EvaluationReplayError(f"report source replay failed: {exc}") from exc


def assemble_evaluation_replay_v3(
    plan_manifest: EvaluationPlanManifestV3,
    feasibility: EvaluationFeasibilityV3,
    admission_manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend_binding: EvaluationSpendBindingV3,
    case_release: AdmissionCaseReleaseV3,
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...],
    report_source: EvaluationReplayReportSourceV3,
    reports: tuple[ArmEvaluationReportV3, ...],
    combination_lineages: tuple[CombinationLineageV3, ...],
    attempt_history_head_digest: str,
    whole_population_coverage: WholePopulationCoverageV3,
    aggregate: EvaluationAggregateV3 | None,
) -> EvaluationReplayV3:
    """Assemble one deterministic bundle only from the complete shared evaluation graph."""
    try:
        return EvaluationReplayV3(
            plan_manifest,
            feasibility,
            admission_manifest,
            authority,
            preparation,
            receipt,
            spend_binding,
            case_release,
            cases_by_arm,
            report_source,
            reports,
            combination_lineages,
            attempt_history_head_digest,
            whole_population_coverage,
            aggregate,
            "",
        )
    except EvaluationReplayError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReplayError(f"complete evaluation replay refused invalid evidence: {exc}") from exc


__all__ = [
    "EvaluationReplayError",
    "EvaluationReplayReportSourceV3",
    "EvaluationReplayV3",
    "assemble_evaluation_replay_v3",
]
