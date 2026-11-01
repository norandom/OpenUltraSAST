"""Label-blind arithmetic feasibility for admission thresholds."""

from __future__ import annotations

import re
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core.admission_review import (
    AdmissionManifestV2,
    AdmissionThreshold,
    PopulationCensus,
    ScopeCensus,
    validate_reviewed_admission_payloads,
)
from openultrasast.core.factpack import ReviewIndependencePolicy
from openultrasast.core.measurement import (
    DenominatorPolicy,
    MeasurementContractError,
    MetricId,
    MetricRule,
    ScopeKey,
    evaluate_metric,
    metric_passes,
    validate_denominator_policy,
)

FEASIBILITY_SCHEMA = "openultrasast.detection-core.threshold-feasibility.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class AdmissionFeasibilityError(ValueError):
    """An admission threshold has no reachable count assignment."""


@dataclass(frozen=True)
class FeasibleCountAssignment:
    metric_id: MetricId
    numerator: int
    denominator: int


@dataclass(frozen=True)
class ThresholdFeasibility:
    census_digest: str
    denominator_policy_digest: str
    threshold_set_digest: str
    witnesses: tuple[FeasibleCountAssignment, ...]
    feasibility_digest: str


@dataclass(frozen=True)
class _Capacities:
    pairs: int
    vulnerable: int
    fixed: int
    ordinary: int
    sites: int
    model_calls: int


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdmissionFeasibilityError(f"{field} must be a non-negative integer")
    return value


def _validate_row(row: object) -> ScopeCensus:
    if type(row) is not ScopeCensus:
        raise AdmissionFeasibilityError("census rows must be exact ScopeCensus values")
    counts = tuple(
        _count(getattr(row, field), field)
        for field in (
            "total_cases",
            "pair_count",
            "vulnerable_side_count",
            "fixed_side_count",
            "ordinary_case_count",
            "semantic_site_capacity",
            "model_call_capacity",
        )
    )
    total, pairs, vulnerable, fixed, ordinary, _, _ = counts
    if total != vulnerable + fixed + ordinary:
        raise AdmissionFeasibilityError("census total does not reconcile with aggregate roles")
    if pairs > min(vulnerable, fixed):
        raise AdmissionFeasibilityError("census pair count exceeds side capacity")
    return row


def _capacities(census: PopulationCensus) -> tuple[tuple[ScopeKey, ...], _Capacities]:
    if type(census) is not PopulationCensus or not census.rows:
        raise AdmissionFeasibilityError("census must be a nonempty PopulationCensus")
    if census.case_labels_exposed:
        raise AdmissionFeasibilityError("feasibility requires a label-blind census")
    if _DIGEST.fullmatch(census.census_digest) is None:
        raise AdmissionFeasibilityError("census digest must be a full lowercase SHA-256 digest")
    rows = tuple(_validate_row(row) for row in census.rows)
    scopes = tuple(row.scope for row in rows)
    if scopes != tuple(sorted(scopes)) or len(scopes) != len(set(scopes)):
        raise AdmissionFeasibilityError("census scopes must be unique and canonically ordered")
    return scopes, _Capacities(
        sum(row.pair_count for row in rows),
        sum(row.vulnerable_side_count for row in rows),
        sum(row.fixed_side_count for row in rows),
        sum(row.ordinary_case_count for row in rows),
        sum(row.semantic_site_capacity for row in rows),
        sum(row.model_call_capacity for row in rows),
    )


def _validated_inputs(
    manifest: AdmissionManifestV2,
    policy: DenominatorPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[_Capacities, str]:
    try:
        validate_reviewed_admission_payloads(manifest.census, manifest, review_policy, resolver)
        validate_denominator_policy(policy)
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionFeasibilityError(str(exc)) from exc
    if policy.policy_digest != manifest.denominator_policy_digest:
        raise AdmissionFeasibilityError("denominator policy does not match the reviewed manifest")
    scopes, capacities = _capacities(manifest.census)
    if any(rule.scopes != scopes for rule in policy.rules):
        raise AdmissionFeasibilityError("denominator policy scope does not match the census")
    return capacities, manifest.threshold_set_digest


def _best_counts(metric_id: MetricId, capacities: _Capacities) -> tuple[int, int]:
    """Return the jointly optimal reachable point under the fixed comparator."""

    fixed = {
        MetricId.PAIRED_CORRECTNESS: capacities.pairs,
        MetricId.VULNERABLE_RECALL: capacities.vulnerable,
        MetricId.FIXED_FALSE_ALARM_RATE: capacities.fixed,
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: capacities.ordinary,
        MetricId.SEMANTIC_STAGE_COVERAGE: capacities.sites,
        MetricId.MODEL_SUCCESS_RATE: capacities.model_calls,
    }
    if metric_id is MetricId.PRECISION:
        if capacities.vulnerable:
            return capacities.vulnerable, capacities.vulnerable
        false_positive_capacity = capacities.fixed + capacities.ordinary
        return (0, 1) if false_positive_capacity else (0, 0)
    denominator = fixed[metric_id]
    false_alarm = metric_id in {
        MetricId.FIXED_FALSE_ALARM_RATE,
        MetricId.ORDINARY_FALSE_ALARMS_PER_100,
    }
    return (0 if false_alarm else denominator), denominator


def _grouped_thresholds(
    thresholds: tuple[AdmissionThreshold, ...],
) -> tuple[tuple[MetricId, tuple[AdmissionThreshold, ...]], ...]:
    return tuple(
        (metric_id, tuple(item for item in thresholds if item.metric_id is metric_id))
        for metric_id in MetricId
        if any(item.metric_id is metric_id for item in thresholds)
    )


def _witness(
    rule: MetricRule,
    thresholds: tuple[AdmissionThreshold, ...],
    capacities: _Capacities,
) -> FeasibleCountAssignment:
    numerator, denominator = _best_counts(rule.metric_id, capacities)
    try:
        result = evaluate_metric(rule, numerator=numerator, denominator=denominator)
        outcomes = tuple(metric_passes(result, item.statistic, item.comparator, item.target) for item in thresholds)
    except MeasurementContractError as exc:
        raise AdmissionFeasibilityError(str(exc)) from exc
    if not all(outcomes):
        raise AdmissionFeasibilityError(f"{rule.metric_id.value} thresholds are arithmetically impossible")
    return FeasibleCountAssignment(rule.metric_id, numerator, denominator)


def _feasibility_value(
    census: PopulationCensus,
    policy: DenominatorPolicy,
    threshold_digest: str,
    witnesses: tuple[FeasibleCountAssignment, ...],
) -> canonical.JsonValue:
    return {
        "schema_version": FEASIBILITY_SCHEMA,
        "census_digest": census.census_digest,
        "denominator_policy_digest": policy.policy_digest,
        "threshold_set_digest": threshold_digest,
        "witnesses": tuple(
            {
                "metric_id": item.metric_id.value,
                "numerator": item.numerator,
                "denominator": item.denominator,
            }
            for item in witnesses
        ),
    }


def evaluate_threshold_feasibility(
    manifest: AdmissionManifestV2,
    policy: DenominatorPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> ThresholdFeasibility:
    capacities, threshold_digest = _validated_inputs(manifest, policy, review_policy, resolver)
    rules = {rule.metric_id: rule for rule in policy.rules}
    witnesses = tuple(_witness(rules[metric_id], group, capacities) for metric_id, group in _grouped_thresholds(manifest.thresholds))
    census = manifest.census
    digest = canonical.content_digest(_feasibility_value(census, policy, threshold_digest, witnesses))
    return ThresholdFeasibility(
        census.census_digest,
        policy.policy_digest,
        threshold_digest,
        witnesses,
        digest,
    )
