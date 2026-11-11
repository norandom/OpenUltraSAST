"""Complete non-authorizing exact-scope metric derivation for evaluation V3."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import cast

from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3, EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_measurement import (
    ArmScopeKey,
    DenominatorPolicyV3,
    EvaluationMeasurementError,
    MetricId,
    ScopedMetricResultV3,
    validate_scoped_metric_result,
)
from openultrasast.core.evaluation_ordinary_projection import (
    EvaluationOrdinaryProjectionError,
    OrdinaryPushCaseV3,
    ScopedOrdinaryProjectionV3,
    _derive_ordinary_push_projection_v3,
    _released_projection_inputs,
)
from openultrasast.core.evaluation_plan import EcosystemOrdinaryCensusV3, ExactScopeCensusV3
from openultrasast.core.evaluation_release import AdmissionCaseReleaseV3, ArmAdmissionCasesV3, ReleasedArmCaseBindingV3
from openultrasast.core.evaluation_scoped_metrics import (
    ScopedQualityPartitionError,
    ScopedQualityPartitionV3,
    partition_scoped_quality_evidence_v3,
)
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.model import ModelStatus


class EvaluationMetricDerivationError(ValueError):
    """Released scoped evidence cannot produce a complete canonical metric set."""


def _exact_tuple(value: object, expected: type[object], field: str) -> tuple[object, ...]:
    if type(value) is not tuple or not value or any(type(item) is not expected for item in value):
        raise EvaluationMetricDerivationError(f"{field} must be a nonempty exact tuple of {expected.__name__}")
    return value


def _validate_rows(
    partitions: tuple[ScopedQualityPartitionV3, ...],
    projections: tuple[ScopedOrdinaryProjectionV3, ...],
    bindings: tuple[ReleasedArmCaseBindingV3, ...],
    scope_rows: tuple[ExactScopeCensusV3, ...],
    ordinary_rows: tuple[EcosystemOrdinaryCensusV3, ...],
) -> None:
    for partition in partitions:
        partition.__post_init__()
    for projection in projections:
        projection.__post_init__()
    for binding in bindings:
        binding.__post_init__()
    for row in scope_rows:
        row.__post_init__()
    for ordinary_row in ordinary_rows:
        ordinary_row.__post_init__()
    keys = tuple(row.key for row in partitions)
    if keys != tuple(sorted(set(keys))) or tuple(row.key for row in projections) != keys:
        raise EvaluationMetricDerivationError("partition and ordinary projection keys must be identical and canonical")
    binding_keys = tuple((binding.key, binding.case_id_digest) for binding in bindings)
    expected_bindings = tuple(sorted((case.key, case.case_id_digest) for row in partitions for case in row.cases))
    if binding_keys != expected_bindings or len(set(binding_keys)) != len(binding_keys):
        raise EvaluationMetricDerivationError("released bindings must exactly cover partition cases in canonical order")
    scopes = tuple(row.scope for row in scope_rows)
    if scopes != tuple(sorted(set(scopes))) or set(scopes) != {key.scope for key in keys}:
        raise EvaluationMetricDerivationError("exact scope census rows differ from planned metric keys")
    ecosystems = tuple(row.ecosystem for row in ordinary_rows)
    if ecosystems != tuple(sorted(set(ecosystems))) or set(ecosystems) != {key.scope.ecosystem for key in keys}:
        raise EvaluationMetricDerivationError("ordinary census rows differ from planned metric ecosystems")


def _validate_inputs(
    partitions: object,
    projections: object,
    bindings: object,
    scope_rows: object,
    ordinary_rows: object,
) -> tuple[
    tuple[ScopedQualityPartitionV3, ...],
    tuple[ScopedOrdinaryProjectionV3, ...],
    tuple[ReleasedArmCaseBindingV3, ...],
    tuple[ExactScopeCensusV3, ...],
    tuple[EcosystemOrdinaryCensusV3, ...],
]:
    selected_partitions = cast(
        tuple[ScopedQualityPartitionV3, ...], _exact_tuple(partitions, ScopedQualityPartitionV3, "scoped partitions")
    )
    selected_projections = cast(
        tuple[ScopedOrdinaryProjectionV3, ...], _exact_tuple(projections, ScopedOrdinaryProjectionV3, "ordinary projections")
    )
    selected_bindings = cast(tuple[ReleasedArmCaseBindingV3, ...], _exact_tuple(bindings, ReleasedArmCaseBindingV3, "released bindings"))
    selected_scopes = cast(tuple[ExactScopeCensusV3, ...], _exact_tuple(scope_rows, ExactScopeCensusV3, "exact scope census rows"))
    selected_ordinary = cast(
        tuple[EcosystemOrdinaryCensusV3, ...], _exact_tuple(ordinary_rows, EcosystemOrdinaryCensusV3, "ordinary census rows")
    )
    typed = (selected_partitions, selected_projections, selected_bindings, selected_scopes, selected_ordinary)
    _validate_rows(*typed)
    return typed


def _reconcile_partition(
    partition: ScopedQualityPartitionV3,
    projection: ScopedOrdinaryProjectionV3,
    bindings_by_case: dict[tuple[ArmScopeKey, str], ReleasedArmCaseBindingV3],
    scope_row: ExactScopeCensusV3,
    ordinary_row: EcosystemOrdinaryCensusV3,
) -> None:
    roles = Counter(case.role for case in partition.cases)
    sites = sum(case.semantic_coverage.sites_considered for case in partition.cases)
    model_calls = sum(len(case.model_outcomes) for case in partition.cases)
    actual = (len(partition.pairs), roles[AdmissionCaseRole.VULNERABLE], roles[AdmissionCaseRole.FIXED], sites, model_calls)
    expected = (
        scope_row.pair_count,
        scope_row.vulnerable_side_count,
        scope_row.fixed_side_count,
        scope_row.semantic_site_capacity,
        scope_row.model_call_capacity,
    )
    if actual != expected:
        raise EvaluationMetricDerivationError("released scoped metric denominators differ from the reviewed exact-scope census")
    expected_projection = _expected_ordinary_projection(partition, bindings_by_case)
    if projection.cases != expected_projection or projection.ordinary_push_count != len(expected_projection):
        raise EvaluationMetricDerivationError("ordinary projection lineage differs from exact released bindings")
    if projection.ordinary_push_count != ordinary_row.ordinary_push_count:
        raise EvaluationMetricDerivationError("scoped ordinary denominator differs from the reviewed ordinary census")


def _expected_ordinary_projection(
    partition: ScopedQualityPartitionV3,
    bindings_by_case: dict[tuple[ArmScopeKey, str], ReleasedArmCaseBindingV3],
) -> tuple[OrdinaryPushCaseV3, ...]:
    expected = []
    for case in partition.cases:
        if case.role is not AdmissionCaseRole.ORDINARY:
            continue
        binding = bindings_by_case[(partition.key, case.case_id_digest)]
        if binding.role is not AdmissionCaseRole.ORDINARY or binding.binding_digest != case.binding_digest:
            raise EvaluationMetricDerivationError("ordinary partition case differs from its exact released binding")
        expected.append(OrdinaryPushCaseV3(partition.key, case.case_id_digest, binding.binding_digest, binding.underlying_push_digest, ""))
    return tuple(sorted(expected, key=lambda item: (item.underlying_push_digest, item.case_id_digest)))


def _metric_counts(
    partition: ScopedQualityPartitionV3,
    projection: ScopedOrdinaryProjectionV3,
) -> dict[MetricId, tuple[int, int]]:
    vulnerable = tuple(case for case in partition.cases if case.role is AdmissionCaseRole.VULNERABLE)
    fixed = tuple(case for case in partition.cases if case.role is AdmissionCaseRole.FIXED)
    ordinary = tuple(case for case in partition.cases if case.role is AdmissionCaseRole.ORDINARY)
    sites_considered = sum(case.semantic_coverage.sites_considered for case in partition.cases)
    model_outcomes = tuple(outcome for case in partition.cases for outcome in case.model_outcomes)
    return {
        MetricId.PAIRED_CORRECTNESS: (sum(pair.is_correct for pair in partition.pairs), len(partition.pairs)),
        MetricId.VULNERABLE_RECALL: (sum(case.has_findings for case in vulnerable), len(vulnerable)),
        MetricId.FIXED_FALSE_ALARM_RATE: (sum(case.has_findings for case in fixed), len(fixed)),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (sum(case.has_findings for case in ordinary), projection.ordinary_push_count),
        MetricId.PRECISION: (
            len(partition.precision_numerator_case_digests),
            len(partition.precision_denominator_case_digests),
        ),
        MetricId.SEMANTIC_STAGE_COVERAGE: (
            sum(case.semantic_coverage.sites_recognized for case in partition.cases),
            sites_considered,
        ),
        MetricId.MODEL_SUCCESS_RATE: (sum(outcome is ModelStatus.SUCCEEDED for outcome in model_outcomes), len(model_outcomes)),
    }


def _derive_partition_metrics(
    partition: ScopedQualityPartitionV3,
    projection: ScopedOrdinaryProjectionV3,
) -> tuple[ScopedMetricResultV3, ...]:
    counts = _metric_counts(partition, projection)
    results: list[ScopedMetricResultV3] = []
    for rule in partition.denominator_policy.rules:
        numerator, denominator = counts[rule.metric_id]
        result = _scoped_result(partition.key, rule.metric_id, numerator, denominator)
        validate_scoped_metric_result(result, rule)
        results.append(result)
    return tuple(results)


def _scoped_result(key: ArmScopeKey, metric_id: MetricId, numerator: int, denominator: int) -> ScopedMetricResultV3:
    if denominator == 0:
        raise EvaluationMetricDerivationError(f"post-spend zero denominator for {metric_id.value} is invalid")
    return ScopedMetricResultV3.from_counts(key, metric_id, numerator=numerator, denominator=denominator)


def _validate_complete_scoped_metrics(
    policies: tuple[DenominatorPolicyV3, ...],
    results: tuple[ScopedMetricResultV3, ...],
) -> None:
    _exact_tuple(policies, DenominatorPolicyV3, "denominator policies")
    _exact_tuple(results, ScopedMetricResultV3, "scoped metric results")
    for policy in policies:
        policy.__post_init__()
    policy_keys = tuple(policy.key for policy in policies)
    if policy_keys != tuple(sorted(set(policy_keys))):
        raise EvaluationMetricDerivationError("denominator policies must use unique canonical key order")
    expected = tuple((policy.key, rule.metric_id) for policy in policies for rule in policy.rules)
    actual = tuple((result.key, result.metric_id) for result in results)
    if set(actual) != set(expected) or len(actual) != len(expected):
        raise EvaluationMetricDerivationError("each standard metric must occur exactly once for every exact scope")
    if actual != expected:
        raise EvaluationMetricDerivationError("scoped metric results must use canonical order")
    rules = {(policy.key, rule.metric_id): rule for policy in policies for rule in policy.rules}
    for result in results:
        validate_scoped_metric_result(result, rules[(result.key, result.metric_id)])


def validate_complete_scoped_metrics_v3(
    policies: tuple[DenominatorPolicyV3, ...],
    results: tuple[ScopedMetricResultV3, ...],
) -> None:
    """Require every registered standard metric exactly once in canonical key order."""
    try:
        _validate_complete_scoped_metrics(policies, results)
    except EvaluationMetricDerivationError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationMetricDerivationError(f"complete scoped metric validation refused invalid evidence: {exc}") from exc


def _derive_metric_results(
    partitions: tuple[ScopedQualityPartitionV3, ...],
    projections: tuple[ScopedOrdinaryProjectionV3, ...],
    bindings: tuple[ReleasedArmCaseBindingV3, ...],
    scope_rows: tuple[ExactScopeCensusV3, ...],
    ordinary_rows: tuple[EcosystemOrdinaryCensusV3, ...],
) -> tuple[ScopedMetricResultV3, ...]:
    scopes = {row.scope: row for row in scope_rows}
    ordinary = {row.ecosystem: row for row in ordinary_rows}
    bindings_by_case = {(binding.key, binding.case_id_digest): binding for binding in bindings}
    results: list[ScopedMetricResultV3] = []
    for partition, projection in zip(partitions, projections, strict=True):
        _reconcile_partition(
            partition,
            projection,
            bindings_by_case,
            scopes[partition.key.scope],
            ordinary[partition.key.scope.ecosystem],
        )
        results.extend(_derive_partition_metrics(partition, projection))
    complete = tuple(results)
    validate_complete_scoped_metrics_v3(tuple(partition.denominator_policy for partition in partitions), complete)
    return complete


def _derive_scoped_metric_results_v3(
    partitions: tuple[ScopedQualityPartitionV3, ...],
    projections: tuple[ScopedOrdinaryProjectionV3, ...],
    bindings: tuple[ReleasedArmCaseBindingV3, ...],
    scope_rows: tuple[ExactScopeCensusV3, ...],
    ordinary_rows: tuple[EcosystemOrdinaryCensusV3, ...],
) -> tuple[ScopedMetricResultV3, ...]:
    """Derive metrics from already validated non-authorizing V3 evidence."""
    try:
        inputs = _validate_inputs(partitions, projections, bindings, scope_rows, ordinary_rows)
        return _derive_metric_results(*inputs)
    except EvaluationMetricDerivationError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationMetricDerivationError(f"scoped metric derivation refused invalid evidence: {exc}") from exc


def derive_scoped_metrics_v3(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    cases_by_arm: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ScopedMetricResultV3, ...]:
    """Revalidate the complete release before deriving the complete scoped metric set."""
    try:
        if type(cases_by_arm) is not tuple:
            raise EvaluationMetricDerivationError("cases_by_arm must use an exact tuple")
        partitions = partition_scoped_quality_evidence_v3(
            manifest, authority, preparation, receipt, spend, release, cases_by_arm, context, custody, resolver
        )
        keys, ordinary_cases, whole_pushes = _released_projection_inputs(release, cases_by_arm, partitions)
        census = manifest.plan_manifest.census
        projection = _derive_ordinary_push_projection_v3(
            census,
            keys,
            ordinary_cases,
            whole_pushes,
        )
        return _derive_scoped_metric_results_v3(
            partitions,
            projection.scoped_projections,
            release.bindings,
            census.scope_rows,
            census.ordinary_rows,
        )
    except EvaluationMetricDerivationError:
        raise
    except (EvaluationMeasurementError, EvaluationOrdinaryProjectionError, ScopedQualityPartitionError) as exc:
        raise EvaluationMetricDerivationError(f"metric derivation refused by reviewed release: {exc}") from exc
    except (
        canonical.ArtifactResolutionError,
        canonical.ArtifactValidationError,
        AttributeError,
        LookupError,
        TypeError,
        ValueError,
    ) as exc:
        raise EvaluationMetricDerivationError(f"metric derivation refused by reviewed release: {exc}") from exc


__all__ = [
    "EvaluationMetricDerivationError",
    "derive_scoped_metrics_v3",
    "validate_complete_scoped_metrics_v3",
]
