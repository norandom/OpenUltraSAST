"""Sole public facade for the evaluation-admission V3 contract."""

from __future__ import annotations

from typing import TypeVar, cast

from openultrasast.core import canonical
from openultrasast.core._closed_graph import exact_dataclass_problem
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt, PopulationUseRequest
from openultrasast.core.evaluation_aggregate import EvaluationAggregateV3, derive_evaluation_aggregate_v3
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionManifestV3,
    authorize_evaluation_admission,
)
from openultrasast.core.evaluation_combination import CombinationLineageV3, derive_combination_lineages_v3
from openultrasast.core.evaluation_feasibility import EvaluationFeasibilityV3, derive_evaluation_feasibility
from openultrasast.core.evaluation_measurement import (
    AggregateWeightV3,
    ArmScopeKey,
    MetricId,
    ScopedMetricResultV3,
    ScopeKey,
)
from openultrasast.core.evaluation_metric_derivation import derive_scoped_metrics_v3
from openultrasast.core.evaluation_observation import ArmObservationSetV3, validate_evaluation_observations
from openultrasast.core.evaluation_ordinary_projection import WholePopulationProjectionV3, project_ordinary_pushes_v3
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
)
from openultrasast.core.evaluation_replay import (
    EvaluationReplayReportSourceV3,
    EvaluationReplayV3,
    assemble_evaluation_replay_v3,
)
from openultrasast.core.evaluation_replay_validation import validate_evaluation_replay_v3
from openultrasast.core.evaluation_report import ArmEvaluationReportV3, derive_completed_evaluation_reports_v3
from openultrasast.core.evaluation_spend import (
    EvaluationPreparationV3,
    EvaluationSpendBindingV3,
    bind_evaluation_spend,
    prepare_evaluation_spend,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    require_exact_v3_contract,
    require_v3_child_schema,
    route_evaluation_schema,
)
from openultrasast.core.readiness import ReadinessResult, validate_readiness_result

_ContractT = TypeVar("_ContractT", bound=EvaluationV3Contract)
_ExactT = TypeVar("_ExactT")
_ScoreSources = tuple[
    EvaluationSpendBindingV3,
    tuple[ScopedMetricResultV3, ...],
    WholePopulationProjectionV3,
    tuple[ArmObservationSetV3, ...],
    tuple[CombinationLineageV3, ...],
]
_ScoreRoots = tuple[
    EvaluationAdmissionManifestV3,
    EvaluationFeasibilityV3,
    EvaluationPreparationV3,
    PopulationUseReceipt,
    EvaluationSpendBindingV3,
    AdmissionCaseReleaseV3,
    tuple[ArmAdmissionCasesV3, ...],
    tuple[ReadinessResult, ...],
]


class EvaluationAdmissionV3Error(ValueError):
    """A value was refused at the public evaluation-admission V3 boundary."""


def _declared(value: object, expected_type: type[_ExactT], field: str) -> _ExactT:
    try:
        problem = exact_dataclass_problem(value, expected_type, field)
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvaluationAdmissionV3Error(f"{field} was refused at the closed boundary: {exc}") from exc
    if problem is not None:
        raise EvaluationAdmissionV3Error(problem)
    return cast(_ExactT, value)


def _receipt(value: object) -> PopulationUseReceipt:
    receipt = _declared(value, PopulationUseReceipt, "shared-spend receipt")
    request = _declared(receipt.request, PopulationUseRequest, "shared-spend receipt request")
    try:
        request.__post_init__()
        receipt.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvaluationAdmissionV3Error(f"shared-spend receipt was refused: {exc}") from exc
    return receipt


def _readiness(values: object) -> tuple[ReadinessResult, ...]:
    if type(values) is not tuple:
        raise EvaluationAdmissionV3Error("readiness must use an exact tuple of ReadinessResult values")
    items = cast(tuple[object, ...], values)
    for item in items:
        try:
            validate_readiness_result(cast(ReadinessResult, item))
        except (AttributeError, TypeError, ValueError) as exc:
            raise EvaluationAdmissionV3Error(f"readiness item was refused at the closed boundary: {exc}") from exc
    return cast(tuple[ReadinessResult, ...], values)


def _case_groups(values: object) -> tuple[ArmAdmissionCasesV3, ...]:
    if type(values) is not tuple:
        raise EvaluationAdmissionV3Error("cases must use an exact tuple of ArmAdmissionCasesV3 values")
    groups = cast(tuple[object, ...], values)
    for item in groups:
        group = _exact(item, ArmAdmissionCasesV3, "evaluation case group")
        for case in group.cases:
            _exact(case, ArmAdmissionCaseResultV3, "evaluation case item")
    return cast(tuple[ArmAdmissionCasesV3, ...], values)


def _aggregate_weights(values: object) -> tuple[AggregateWeightV3, ...] | None:
    if values is None:
        return None
    if type(values) is not tuple:
        raise EvaluationAdmissionV3Error("aggregate weights must use an exact tuple of AggregateWeightV3 values")
    weights = cast(tuple[object, ...], values)
    for item in weights:
        weight = _declared(item, AggregateWeightV3, "aggregate weight")
        key = _declared(weight.key, ArmScopeKey, "aggregate weight arm-scope key")
        _declared(key.scope, ScopeKey, "aggregate weight scope key")
    return cast(tuple[AggregateWeightV3, ...], values)


def _context(value: object) -> AdmissionValidationContext:
    if type(value) is not AdmissionValidationContext:
        raise EvaluationAdmissionV3Error("validation context must use exact AdmissionValidationContext")
    _validate_context(value)
    return value


def _exact(value: object, expected_type: type[_ContractT], field: str) -> _ContractT:
    try:
        problem = exact_dataclass_problem(value, expected_type, field)
        if problem is not None:
            raise EvaluationAdmissionV3Error(problem)
        result = require_exact_v3_contract(value, expected_type, field=field)
        require_v3_child_schema(getattr(type(result), "__evaluation_v3_contract_schema__", None), field=field)
        post_init = getattr(result, "__post_init__", None)
        if not callable(post_init):
            raise EvaluationAdmissionV3Error(f"{field} has no exact contract validator")
        post_init()
        return result
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvaluationAdmissionV3Error(f"{field} was refused at the exact V3 boundary: {exc}") from exc


def decode_evaluation_v3(schema: str, value: object, expected_type: type[_ContractT]) -> _ContractT:
    """Route one named root and accept only its exact registered V3 runtime contract."""
    try:
        route_evaluation_schema(schema)
        return _exact(value, expected_type, "decoded evaluation root")
    except EvaluationAdmissionV3Error:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvaluationAdmissionV3Error(f"evaluation root schema was refused: {exc}") from exc


def preflight_evaluation(
    manifest: EvaluationPlanManifestV3,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> EvaluationFeasibilityV3:
    """Validate one reviewed plan and derive its exact all-scope feasibility product."""
    plan = _exact(manifest, EvaluationPlanManifestV3, "evaluation plan manifest")
    validated_context = _context(context)
    return derive_evaluation_feasibility(plan, validated_context.admission_review_policy, resolver)


def authorize_evaluation(
    manifest: EvaluationAdmissionManifestV3,
    feasibility: EvaluationFeasibilityV3,
    readiness: tuple[ReadinessResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationPreparationV3:
    """Derive reviewed pre-spend authority and return only its next-phase preparation."""
    admission = _exact(manifest, EvaluationAdmissionManifestV3, "evaluation admission manifest")
    feasible = _exact(feasibility, EvaluationFeasibilityV3, "evaluation feasibility")
    validated_readiness = _readiness(readiness)
    validated_context = _context(context)
    authority = authorize_evaluation_admission(admission, feasible, validated_readiness, validated_context, custody, resolver)
    return prepare_evaluation_spend(admission, authority, validated_context, custody)


def validate_shared_spend(
    manifest: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> EvaluationSpendBindingV3:
    """Bind an externally recorded exact all-arm AVAILABLE-to-SPENT successor."""
    admission = _exact(manifest, EvaluationAdmissionManifestV3, "evaluation admission manifest")
    prepared = _exact(preparation, EvaluationPreparationV3, "evaluation preparation")
    return bind_evaluation_spend(admission, prepared, _receipt(receipt), _context(context), custody)


def _aggregate(
    metrics: tuple[ScopedMetricResultV3, ...],
    weights: tuple[AggregateWeightV3, ...] | None,
) -> EvaluationAggregateV3 | None:
    if weights is None:
        return None
    keys = tuple(sorted({metric.key for metric in metrics}))
    samples = tuple(
        next(metric.sample_count for metric in metrics if metric.key == key and metric.metric_id is MetricId.PRECISION) for key in keys
    )
    return derive_evaluation_aggregate_v3(metrics, samples, weights)


def _score_sources(
    admission: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    expected_spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    groups: tuple[ArmAdmissionCasesV3, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> _ScoreSources:
    spend = bind_evaluation_spend(admission, preparation, receipt, context, custody)
    if spend != expected_spend:
        raise EvaluationAdmissionV3Error("shared-spend binding differs from the exact current transition")
    common = (admission, preparation.authority, preparation, receipt, spend, release, groups, context, custody, resolver)
    metrics = derive_scoped_metrics_v3(*common)
    projection = project_ordinary_pushes_v3(*common)
    policy = context.admission_review_policy
    observations = validate_evaluation_observations(
        admission.plan_manifest.declaration,
        admission.observations,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_evidence_bytes,
    )
    lineages = derive_combination_lineages_v3(admission.plan_manifest.declaration, release.bindings)
    return spend, metrics, projection.whole_population, observations, lineages


def _score_roots(
    admission: object,
    feasibility: object,
    preparation: object,
    receipt: object,
    spend: object,
    release: object,
    groups: object,
    readiness: object,
) -> _ScoreRoots:
    roots = (
        _exact(admission, EvaluationAdmissionManifestV3, "evaluation admission manifest"),
        _exact(feasibility, EvaluationFeasibilityV3, "evaluation feasibility"),
        _exact(preparation, EvaluationPreparationV3, "evaluation preparation"),
    )
    exact_receipt = _receipt(receipt)
    binding = _exact(spend, EvaluationSpendBindingV3, "evaluation spend binding")
    released = _exact(release, AdmissionCaseReleaseV3, "evaluation case release")
    exact_groups = _case_groups(groups)
    exact_readiness = _readiness(readiness)
    return (*roots, exact_receipt, binding, released, exact_groups, exact_readiness)


def score_and_replay(
    admission_manifest: EvaluationAdmissionManifestV3,
    feasibility: EvaluationFeasibilityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend_binding: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...],
    readiness: tuple[ReadinessResult, ...],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
    *,
    aggregate_weights: tuple[AggregateWeightV3, ...] | None = None,
) -> EvaluationReplayV3:
    """Derive reports and assemble one complete source-rooted non-authorizing replay."""
    exact_weights = _aggregate_weights(aggregate_weights)
    admission, feasible, prepared, exact_receipt, exact_spend, released, groups, exact_readiness = _score_roots(
        admission_manifest, feasibility, preparation, receipt, spend_binding, release, cases_by_arm, readiness
    )
    validated_context = _context(context)
    spend, metrics, projection, observations, lineages = _score_sources(
        admission, prepared, exact_receipt, exact_spend, released, groups, validated_context, custody, resolver
    )
    reports, whole = derive_completed_evaluation_reports_v3(
        admission.plan_manifest, groups, metrics, exact_readiness, observations, lineages, projection
    )
    source = EvaluationReplayReportSourceV3(metrics, exact_readiness, observations, projection, "")
    return assemble_evaluation_replay_v3(
        admission.plan_manifest,
        feasible,
        admission,
        prepared.authority,
        prepared,
        exact_receipt,
        spend,
        released,
        groups,
        source,
        reports,
        lineages,
        admission.attempt_history.head_event_digest,
        whole,
        _aggregate(metrics, exact_weights),
    )


def validate_evaluation_replay(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ArmEvaluationReportV3, ...]:
    """Return reports only after independent current-source and custody replay validation."""
    exact_replay = _exact(replay, EvaluationReplayV3, "evaluation replay")
    return validate_evaluation_replay_v3(exact_replay, _context(context), custody, resolver)


__all__ = [
    "EVALUATION_ADMISSION_V3_SCHEMA",
    "EvaluationAdmissionV3Error",
    "authorize_evaluation",
    "decode_evaluation_v3",
    "preflight_evaluation",
    "score_and_replay",
    "validate_evaluation_replay",
    "validate_shared_spend",
]
