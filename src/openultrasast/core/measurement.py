"""Comparable baseline identities and the fixed detection metric algebra."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core._closed_graph import closed_graph_problem

BASELINE_IDENTITY_SCHEMA = "openultrasast.detection-core.baseline-identity.v2"
DENOMINATOR_POLICY_SCHEMA = "openultrasast.detection-core.denominator-policy.v2"
IDENTITY_SET_SCHEMA = "openultrasast.detection-core.identity-set.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_WILSON_Z_95 = 1.959963984540054


class MeasurementContractError(ValueError):
    """A baseline or metric violates the fixed measurement contract."""


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise MeasurementContractError(f"{field} must be nonempty text")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise MeasurementContractError(f"{field} must be a full lowercase SHA-256 digest")


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MeasurementContractError(f"{field} must be a non-negative integer")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise MeasurementContractError(f"{field} must be finite")
    return float(value)


@dataclass(frozen=True, order=True)
class ScopeKey:
    family_id: str
    ecosystem: str

    def __post_init__(self) -> None:
        _text(self.family_id, "family_id")
        _text(self.ecosystem, "ecosystem")


def _scope_value(value: ScopeKey) -> canonical.JsonValue:
    return {"family_id": value.family_id, "ecosystem": value.ecosystem}


def _canonical_scopes(values: tuple[ScopeKey, ...], field: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise MeasurementContractError(f"{field} must be a nonempty tuple")
    if not all(isinstance(item, ScopeKey) for item in values):
        raise MeasurementContractError(f"{field} must contain ScopeKey values")
    if values != tuple(sorted(values)):
        raise MeasurementContractError(f"{field} must use canonical order")
    if len(set(values)) != len(values):
        raise MeasurementContractError(f"{field} contains a duplicate scope")


def derive_identity_set_digest(kind: str, identities: tuple[str, ...]) -> str:
    _text(kind, "identity set kind")
    if not isinstance(identities, tuple):
        raise MeasurementContractError("identities must be a tuple")
    for identity in identities:
        _digest(identity, f"{kind} identity")
    if identities != tuple(sorted(identities)):
        raise MeasurementContractError("identities must use canonical order")
    if len(set(identities)) != len(identities):
        raise MeasurementContractError("identity set contains a duplicate")
    return canonical.content_digest({"schema_version": IDENTITY_SET_SCHEMA, "kind": kind, "identities": identities})


@dataclass(frozen=True)
class BaselineIdentity:
    arm_id: str
    population_digest: str
    freeze_digest: str
    claimed_scopes: tuple[ScopeKey, ...]
    family_contract_digests: tuple[str, ...]
    family_contract_set_digest: str
    fact_schema_digest: str
    fact_set_digest: str
    acquisition_record_digest: str
    analyzer_revision: str
    configuration_digest: str
    model_program_digests: tuple[str, ...]
    model_program_set_digest: str | None
    denominator_policy_digest: str
    threshold_set_digest: str
    outcome_mapping_digest: str

    def __post_init__(self) -> None:
        _validate_baseline(self)


def _validate_identity_tuple(values: tuple[str, ...], field: str, *, allow_empty: bool) -> None:
    if not isinstance(values, tuple) or (not values and not allow_empty):
        qualifier = "a tuple" if allow_empty else "a nonempty tuple"
        raise MeasurementContractError(f"{field} must be {qualifier}")
    for value in values:
        _digest(value, field)
    if values != tuple(sorted(values)):
        raise MeasurementContractError(f"{field} must use canonical order")
    if len(set(values)) != len(values):
        raise MeasurementContractError(f"{field} contains a duplicate identity")


def _validate_baseline(value: BaselineIdentity) -> None:
    _text(value.arm_id, "arm_id")
    _text(value.analyzer_revision, "analyzer_revision")
    for item, field in (
        (value.population_digest, "population_digest"),
        (value.freeze_digest, "freeze_digest"),
        (value.fact_schema_digest, "fact_schema_digest"),
        (value.fact_set_digest, "fact_set_digest"),
        (value.acquisition_record_digest, "acquisition_record_digest"),
        (value.configuration_digest, "configuration_digest"),
        (value.denominator_policy_digest, "denominator_policy_digest"),
        (value.threshold_set_digest, "threshold_set_digest"),
        (value.outcome_mapping_digest, "outcome_mapping_digest"),
    ):
        _digest(item, field)
    _canonical_scopes(value.claimed_scopes, "claimed_scopes")
    _validate_identity_tuple(value.family_contract_digests, "family contract digests", allow_empty=False)
    _digest(value.family_contract_set_digest, "family contract set digest")
    # Association requires the actual catalog entries and is validated by the admission context.
    _validate_identity_tuple(value.model_program_digests, "model program digests", allow_empty=True)
    expected_models = derive_identity_set_digest("model_program", value.model_program_digests) if value.model_program_digests else None
    if value.model_program_set_digest != expected_models:
        raise MeasurementContractError("model program set digest does not match exact set")


def _baseline_value(value: BaselineIdentity) -> canonical.JsonValue:
    return {
        "schema_version": BASELINE_IDENTITY_SCHEMA,
        "arm_id": value.arm_id,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "claimed_scopes": tuple(_scope_value(item) for item in value.claimed_scopes),
        "family_contract_digests": value.family_contract_digests,
        "family_contract_set_digest": value.family_contract_set_digest,
        "fact_schema_digest": value.fact_schema_digest,
        "fact_set_digest": value.fact_set_digest,
        "acquisition_record_digest": value.acquisition_record_digest,
        "analyzer_revision": value.analyzer_revision,
        "configuration_digest": value.configuration_digest,
        "model_program_digests": value.model_program_digests,
        "model_program_set_digest": value.model_program_set_digest,
        "denominator_policy_digest": value.denominator_policy_digest,
        "threshold_set_digest": value.threshold_set_digest,
        "outcome_mapping_digest": value.outcome_mapping_digest,
    }


def derive_baseline_identity_digest(value: BaselineIdentity) -> str:
    if not isinstance(value, BaselineIdentity):
        raise MeasurementContractError("baseline must be a BaselineIdentity")
    _validate_baseline(value)
    return canonical.content_digest(_baseline_value(value))


def require_comparable_baselines(values: Sequence[BaselineIdentity]) -> BaselineIdentity:
    if not isinstance(values, Sequence) or not values:
        raise MeasurementContractError("baselines must be a nonempty sequence")
    first = values[0]
    if not isinstance(first, BaselineIdentity):
        raise MeasurementContractError("baselines must contain BaselineIdentity values")
    expected = derive_baseline_identity_digest(first)
    for value in values[1:]:
        if not isinstance(value, BaselineIdentity) or derive_baseline_identity_digest(value) != expected:
            raise MeasurementContractError("cannot aggregate a non-comparable baseline")
    return first


class MetricId(Enum):
    PAIRED_CORRECTNESS = "paired_correctness"
    VULNERABLE_RECALL = "vulnerable_recall"
    FIXED_FALSE_ALARM_RATE = "fixed_false_alarm_rate"
    ORDINARY_FALSE_ALARMS_PER_100 = "ordinary_false_alarms_per_100"
    PRECISION = "precision"
    SEMANTIC_STAGE_COVERAGE = "semantic_stage_coverage"
    MODEL_SUCCESS_RATE = "model_success_rate"


class NumeratorKind(Enum):
    CORRECT_PAIRS = "correct_pairs"
    VULNERABLE_VIOLATION_CASES = "vulnerable_violation_cases"
    FIXED_DEFECT_CASES = "fixed_defect_cases"
    ORDINARY_DEFECT_CASES = "ordinary_defect_cases"
    TRUE_DEFECT_CASES = "true_defect_cases"
    SITES_RECOGNIZED = "sites_recognized"
    SUCCESSFUL_MODEL_CALLS = "successful_model_calls"


class DenominatorKind(Enum):
    PAIRS = "pairs"
    VULNERABLE_SIDES = "vulnerable_sides"
    FIXED_SIDES = "fixed_sides"
    ORDINARY_CASES = "ordinary_cases"
    ALL_DEFECT_CASES = "all_defect_cases"
    SITES_CONSIDERED = "sites_considered"
    MODEL_CALLS = "model_calls"


class IntervalMethod(Enum):
    WILSON_95 = "wilson_95"


class Statistic(Enum):
    COUNT = "count"
    RATE = "rate"
    PER_100 = "per_100"
    WILSON_LOWER = "wilson_lower"
    WILSON_UPPER = "wilson_upper"


class Comparator(Enum):
    AT_LEAST = "at_least"
    AT_MOST = "at_most"


_ALGEBRA = {
    MetricId.PAIRED_CORRECTNESS: (NumeratorKind.CORRECT_PAIRS, DenominatorKind.PAIRS, Comparator.AT_LEAST),
    MetricId.VULNERABLE_RECALL: (
        NumeratorKind.VULNERABLE_VIOLATION_CASES,
        DenominatorKind.VULNERABLE_SIDES,
        Comparator.AT_LEAST,
    ),
    MetricId.FIXED_FALSE_ALARM_RATE: (
        NumeratorKind.FIXED_DEFECT_CASES,
        DenominatorKind.FIXED_SIDES,
        Comparator.AT_MOST,
    ),
    MetricId.ORDINARY_FALSE_ALARMS_PER_100: (
        NumeratorKind.ORDINARY_DEFECT_CASES,
        DenominatorKind.ORDINARY_CASES,
        Comparator.AT_MOST,
    ),
    MetricId.PRECISION: (NumeratorKind.TRUE_DEFECT_CASES, DenominatorKind.ALL_DEFECT_CASES, Comparator.AT_LEAST),
    MetricId.SEMANTIC_STAGE_COVERAGE: (
        NumeratorKind.SITES_RECOGNIZED,
        DenominatorKind.SITES_CONSIDERED,
        Comparator.AT_LEAST,
    ),
    MetricId.MODEL_SUCCESS_RATE: (
        NumeratorKind.SUCCESSFUL_MODEL_CALLS,
        DenominatorKind.MODEL_CALLS,
        Comparator.AT_LEAST,
    ),
}


@dataclass(frozen=True)
class MetricRule:
    metric_id: MetricId
    scopes: tuple[ScopeKey, ...]
    numerator: NumeratorKind
    denominator: DenominatorKind

    def __post_init__(self) -> None:
        if not isinstance(self.metric_id, MetricId):
            raise MeasurementContractError("metric_id must be a MetricId")
        if not isinstance(self.numerator, NumeratorKind) or not isinstance(self.denominator, DenominatorKind):
            raise MeasurementContractError("metric rule kinds must use the closed enums")
        _canonical_scopes(self.scopes, "metric scopes")


def standard_metric_rules(scopes: tuple[ScopeKey, ...]) -> tuple[MetricRule, ...]:
    _canonical_scopes(scopes, "metric scopes")
    return tuple(MetricRule(metric, scopes, _ALGEBRA[metric][0], _ALGEBRA[metric][1]) for metric in MetricId)


def _rule_value(value: MetricRule) -> canonical.JsonValue:
    return {
        "metric_id": value.metric_id.value,
        "scopes": tuple(_scope_value(scope) for scope in value.scopes),
        "numerator": value.numerator.value,
        "denominator": value.denominator.value,
    }


@dataclass(frozen=True)
class DenominatorPolicy:
    rules: tuple[MetricRule, ...]
    interval_method: IntervalMethod
    policy_digest: str

    def __post_init__(self) -> None:
        _validate_policy(self)


_POLICY_TYPES: tuple[type[object], ...] = (DenominatorPolicy, MetricRule, ScopeKey)
_POLICY_ENUMS: tuple[type[object], ...] = (MetricId, NumeratorKind, DenominatorKind, IntervalMethod)


def _validate_policy(value: DenominatorPolicy) -> None:
    problem = closed_graph_problem(value, dataclass_types=_POLICY_TYPES, enum_types=_POLICY_ENUMS, path="denominator policy")
    if problem is not None:
        raise MeasurementContractError(f"closed denominator graph violation: {problem}")
    if not isinstance(value.rules, tuple) or not all(isinstance(item, MetricRule) for item in value.rules):
        raise MeasurementContractError("rules must be a tuple of MetricRule values")
    if tuple(rule.metric_id for rule in value.rules) != tuple(MetricId):
        raise MeasurementContractError("each standard metric must occur exactly once in canonical order")
    for rule in value.rules:
        rule.__post_init__()
        expected_numerator, expected_denominator, _ = _ALGEBRA[rule.metric_id]
        if (rule.numerator, rule.denominator) != (expected_numerator, expected_denominator):
            raise MeasurementContractError("metric rule violates the fixed algebra")
    if value.interval_method is not IntervalMethod.WILSON_95:
        raise MeasurementContractError("interval method must be Wilson 95%")
    expected_digest = _policy_digest(value.rules, value.interval_method)
    if value.policy_digest == "":
        object.__setattr__(value, "policy_digest", expected_digest)
        return
    _digest(value.policy_digest, "denominator policy digest")
    if value.policy_digest != expected_digest:
        raise MeasurementContractError("denominator policy digest does not match policy")


validate_denominator_policy = _validate_policy


def _policy_digest(rules: tuple[MetricRule, ...], method: IntervalMethod) -> str:
    return canonical.content_digest(
        {
            "schema_version": DENOMINATOR_POLICY_SCHEMA,
            "rules": tuple(_rule_value(rule) for rule in rules),
            "interval_method": method.value,
        }
    )


def derive_denominator_policy_digest(value: DenominatorPolicy) -> str:
    if not isinstance(value, DenominatorPolicy):
        raise MeasurementContractError("policy must be a DenominatorPolicy")
    return _policy_digest(value.rules, value.interval_method)


@dataclass(frozen=True)
class MetricResult:
    metric_id: MetricId
    numerator: int
    denominator: int
    value: float | None
    interval_method: IntervalMethod
    interval_lower: float | None
    interval_upper: float | None

    def __post_init__(self) -> None:
        _validate_result(self)


def _validate_rule(rule: MetricRule) -> None:
    if not isinstance(rule, MetricRule):
        raise MeasurementContractError("rule must be a MetricRule")
    expected = _ALGEBRA[rule.metric_id]
    if (rule.numerator, rule.denominator) != expected[:2]:
        raise MeasurementContractError("metric rule violates the fixed algebra")


def _wilson(numerator: int, denominator: int) -> tuple[float, float]:
    proportion = numerator / denominator
    z_squared = _WILSON_Z_95 * _WILSON_Z_95
    denominator_term = 1.0 + z_squared / denominator
    center = (proportion + z_squared / (2.0 * denominator)) / denominator_term
    margin = (_WILSON_Z_95 / denominator_term) * math.sqrt(
        proportion * (1.0 - proportion) / denominator + z_squared / (4.0 * denominator * denominator)
    )
    return center - margin, center + margin


def _metric_values(metric_id: MetricId, numerator: int, denominator: int) -> tuple[float | None, float | None, float | None]:
    if denominator == 0:
        return None, None, None
    lower, upper = _wilson(numerator, denominator)
    scale = 100.0 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else 1.0
    return (numerator / denominator) * scale, lower * scale, upper * scale


def _canonical_metric_float(actual: object, expected: float | None) -> bool:
    if expected is None:
        return actual is None
    return type(actual) is float and math.isfinite(actual) and actual.hex() == expected.hex()


def _validate_result(result: MetricResult) -> None:
    if not isinstance(result.metric_id, MetricId):
        raise MeasurementContractError("metric result id must use the closed enum")
    numerator = _count(result.numerator, "numerator")
    denominator = _count(result.denominator, "denominator")
    if numerator > denominator:
        raise MeasurementContractError("numerator must not exceed denominator")
    if result.interval_method is not IntervalMethod.WILSON_95:
        raise MeasurementContractError("interval method must be Wilson 95%")
    actual = (result.value, result.interval_lower, result.interval_upper)
    expected = _metric_values(result.metric_id, numerator, denominator)
    if not all(_canonical_metric_float(item, expected[index]) for index, item in enumerate(actual)):
        raise MeasurementContractError("metric values do not match the fixed Wilson algebra")


def evaluate_metric(rule: MetricRule, *, numerator: int, denominator: int) -> MetricResult:
    _validate_rule(rule)
    numerator = _count(numerator, "numerator")
    denominator = _count(denominator, "denominator")
    if numerator > denominator:
        raise MeasurementContractError("numerator must not exceed denominator")
    value, lower, upper = _metric_values(rule.metric_id, numerator, denominator)
    return MetricResult(rule.metric_id, numerator, denominator, value, IntervalMethod.WILSON_95, lower, upper)


def _statistic_value(result: MetricResult, statistic: Statistic) -> float | None:
    if statistic is Statistic.COUNT:
        return float(result.numerator)
    if statistic is Statistic.RATE:
        if result.metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100:
            raise MeasurementContractError("ordinary false alarms use the per_100 statistic")
        return result.value
    if statistic is Statistic.PER_100:
        if result.metric_id is not MetricId.ORDINARY_FALSE_ALARMS_PER_100:
            raise MeasurementContractError("per_100 statistic is only valid for ordinary false alarms")
        return result.value
    if statistic is Statistic.WILSON_LOWER:
        return result.interval_lower
    if statistic is Statistic.WILSON_UPPER:
        return result.interval_upper
    raise MeasurementContractError("statistic must use the closed enum")


def metric_passes(result: MetricResult, statistic: Statistic, comparator: Comparator, target: float) -> bool:
    if not isinstance(result, MetricResult):
        raise MeasurementContractError("result must be a MetricResult")
    _validate_result(result)
    if not isinstance(statistic, Statistic):
        raise MeasurementContractError("statistic must use the closed enum")
    if not isinstance(comparator, Comparator):
        raise MeasurementContractError("comparator must use the closed enum")
    target = _finite(target, "target")
    required = _ALGEBRA[result.metric_id][2]
    if comparator is not required:
        raise MeasurementContractError("comparator direction violates the fixed metric algebra")
    value = _statistic_value(result, statistic)
    if result.denominator == 0 or value is None:
        return False
    return value >= target if comparator is Comparator.AT_LEAST else value <= target


def metric_result_value(result: MetricResult) -> canonical.JsonValue:
    _validate_result(result)
    return {
        "metric_id": result.metric_id.value,
        "numerator": result.numerator,
        "denominator": result.denominator,
        "value": result.value,
        "interval_method": result.interval_method.value,
        "interval_lower": result.interval_lower,
        "interval_upper": result.interval_upper,
    }


__all__ = [
    "BaselineIdentity",
    "Comparator",
    "DenominatorKind",
    "DenominatorPolicy",
    "IntervalMethod",
    "MeasurementContractError",
    "MetricId",
    "MetricResult",
    "MetricRule",
    "NumeratorKind",
    "ScopeKey",
    "Statistic",
    "derive_baseline_identity_digest",
    "derive_denominator_policy_digest",
    "derive_identity_set_digest",
    "evaluate_metric",
    "metric_passes",
    "metric_result_value",
    "require_comparable_baselines",
    "standard_metric_rules",
    "validate_denominator_policy",
]
