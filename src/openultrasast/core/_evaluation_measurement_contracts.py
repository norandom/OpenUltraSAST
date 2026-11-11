"""Lower exact arm/scope measurement contracts for evaluation admission V3."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from math import gcd
from typing import cast

from openultrasast.core import canonical
from openultrasast.core._metric_algebra import metric_algebra, metric_values
from openultrasast.core.evidence import NeutralOutcome

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "openultrasast.detection-core.evaluation-measurement.v3"


class EvaluationMeasurementError(ValueError):
    """A V3 measurement value violates its exact closed contract."""


def _exact(value: object, expected: type[object], field: str) -> None:
    if type(value) is not expected:
        raise EvaluationMeasurementError(f"{field} must use exact type {expected.__name__}")


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise EvaluationMeasurementError(f"{field} must be nonempty text")
    return value


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationMeasurementError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _count(value: object, field: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        qualifier = "positive" if positive else "non-negative"
        raise EvaluationMeasurementError(f"{field} must be a {qualifier} integer")
    return value


def _finite(value: object, field: str) -> float:
    number = cast(int | float, value)
    if type(value) not in (int, float) or not math.isfinite(number):
        raise EvaluationMeasurementError(f"{field} must be finite")
    return float(number)


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _SCHEMA, "kind": kind, "payload": payload}


def _bind_digest(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    else:
        _digest(actual, field)
        if actual != expected:
            raise EvaluationMeasurementError(f"{field} does not match canonical content")


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


class CaseOutcomeProjectionPolicyV3(Enum):
    UNANIMOUS_EVIDENCE = "unanimous_evidence"
    DECLARATIVE_COMBINATION_TABLE = "declarative_combination_table"


@dataclass(frozen=True, order=True)
class ScopeKey:
    family_id: str
    ecosystem: str

    def __post_init__(self) -> None:
        _exact(self, ScopeKey, "scope")
        _text(self.family_id, "family_id")
        _text(self.ecosystem, "ecosystem")


@dataclass(frozen=True, order=True)
class ArmScopeKey:
    arm_id: str
    scope: ScopeKey

    def __post_init__(self) -> None:
        _exact(self, ArmScopeKey, "arm-scope key")
        _text(self.arm_id, "arm_id")
        _exact(self.scope, ScopeKey, "scope")
        self.scope.__post_init__()


def _key_value(key: ArmScopeKey) -> canonical.JsonValue:
    return {"arm_id": key.arm_id, "scope": {"family_id": key.scope.family_id, "ecosystem": key.scope.ecosystem}}


def _metric_parts(metric_id: MetricId) -> tuple[NumeratorKind, DenominatorKind, Comparator]:
    if type(metric_id) is not MetricId:
        raise EvaluationMeasurementError("metric_id must use the closed MetricId enum")
    numerator, denominator, comparator = metric_algebra(metric_id.value)
    return NumeratorKind(numerator), DenominatorKind(denominator), Comparator(comparator)


@dataclass(frozen=True)
class ScopedMetricRuleV3:
    key: ArmScopeKey
    metric_id: MetricId
    numerator: NumeratorKind
    denominator: DenominatorKind
    rule_digest: str

    def __post_init__(self) -> None:
        _exact(self, ScopedMetricRuleV3, "scoped metric rule")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        expected_numerator, expected_denominator, _ = _metric_parts(self.metric_id)
        if type(self.numerator) is not NumeratorKind or type(self.denominator) is not DenominatorKind:
            raise EvaluationMeasurementError("metric algebra kinds must use closed enums")
        if (self.numerator, self.denominator) != (expected_numerator, expected_denominator):
            raise EvaluationMeasurementError("metric rule violates the fixed algebra")
        payload = {
            "key": _key_value(self.key),
            "metric_id": self.metric_id.value,
            "numerator": self.numerator.value,
            "denominator": self.denominator.value,
        }
        _bind_digest(self, "rule_digest", canonical.content_digest(_value("scoped_metric_rule", payload)))


def standard_scoped_metric_rules(key: ArmScopeKey) -> tuple[ScopedMetricRuleV3, ...]:
    _exact(key, ArmScopeKey, "arm-scope key")
    key.__post_init__()
    return tuple(ScopedMetricRuleV3(key, metric_id, *_metric_parts(metric_id)[:2], "") for metric_id in MetricId)


@dataclass(frozen=True)
class DenominatorPolicyV3:
    key: ArmScopeKey
    rules: tuple[ScopedMetricRuleV3, ...]
    interval_method: IntervalMethod
    policy_digest: str

    def __post_init__(self) -> None:
        _exact(self, DenominatorPolicyV3, "denominator policy")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        if (
            type(self.rules) is not tuple
            or tuple(rule.metric_id for rule in self.rules if type(rule) is ScopedMetricRuleV3) != tuple(MetricId)
            or len(self.rules) != len(MetricId)
        ):
            raise EvaluationMeasurementError("each standard metric must occur exactly once in canonical order")
        if any(type(rule) is not ScopedMetricRuleV3 or rule.key != self.key for rule in self.rules):
            raise EvaluationMeasurementError("every policy rule must use the same arm-scope key")
        for rule in self.rules:
            rule.__post_init__()
        if self.interval_method is not IntervalMethod.WILSON_95:
            raise EvaluationMeasurementError("interval method must be Wilson 95%")
        payload = {
            "key": _key_value(self.key),
            "rule_digests": tuple(rule.rule_digest for rule in self.rules),
            "interval_method": self.interval_method.value,
        }
        _bind_digest(self, "policy_digest", canonical.content_digest(_value("denominator_policy", payload)))


@dataclass(frozen=True)
class ScopedThresholdV3:
    key: ArmScopeKey
    metric_id: MetricId
    statistic: Statistic
    comparator: Comparator
    target: float
    threshold_digest: str

    def __post_init__(self) -> None:
        _exact(self, ScopedThresholdV3, "scoped threshold")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        _, _, expected_comparator = _metric_parts(self.metric_id)
        if type(self.statistic) is not Statistic or type(self.comparator) is not Comparator:
            raise EvaluationMeasurementError("threshold fields must use closed enums")
        if self.comparator is not expected_comparator:
            raise EvaluationMeasurementError("threshold violates the fixed comparator")
        is_ordinary = self.metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100
        if self.statistic is Statistic.PER_100 and not is_ordinary:
            raise EvaluationMeasurementError("PER_100 statistic belongs only to ordinary false alarms")
        if self.statistic is Statistic.RATE and is_ordinary:
            raise EvaluationMeasurementError("ordinary false alarms require PER_100 rather than RATE")
        target = _finite(self.target, "threshold target")
        if target < 0:
            raise EvaluationMeasurementError("threshold target must be non-negative")
        payload = {
            "key": _key_value(self.key),
            "metric_id": self.metric_id.value,
            "statistic": self.statistic.value,
            "comparator": self.comparator.value,
            "target": target,
        }
        _bind_digest(self, "threshold_digest", canonical.content_digest(_value("scoped_threshold", payload)))


@dataclass(frozen=True)
class IntervalPrecisionRuleV3:
    metric_id: MetricId
    maximum_wilson_width: float
    minimum_denominator: int
    rule_digest: str

    def __post_init__(self) -> None:
        _exact(self, IntervalPrecisionRuleV3, "interval precision rule")
        _metric_parts(self.metric_id)
        width = _finite(self.maximum_wilson_width, "maximum Wilson width")
        if width <= 0:
            raise EvaluationMeasurementError("maximum Wilson width must be positive")
        _count(self.minimum_denominator, "minimum denominator", positive=True)
        payload = {"metric_id": self.metric_id.value, "maximum_wilson_width": width, "minimum_denominator": self.minimum_denominator}
        _bind_digest(self, "rule_digest", canonical.content_digest(_value("interval_precision_rule", payload)))


@dataclass(frozen=True)
class ScopeSufficiencyRuleV3:
    key: ArmScopeKey
    minimum_pairs: int
    minimum_ordinary_pushes: int
    precision_rules: tuple[IntervalPrecisionRuleV3, ...]
    rule_digest: str

    def __post_init__(self) -> None:
        _exact(self, ScopeSufficiencyRuleV3, "scope sufficiency rule")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        _count(self.minimum_pairs, "minimum pairs", positive=True)
        _count(self.minimum_ordinary_pushes, "minimum ordinary pushes", positive=True)
        if (
            type(self.precision_rules) is not tuple
            or tuple(rule.metric_id for rule in self.precision_rules if type(rule) is IntervalPrecisionRuleV3) != tuple(MetricId)
            or len(self.precision_rules) != len(MetricId)
        ):
            raise EvaluationMeasurementError("each precision metric must occur exactly once in canonical order")
        for rule in self.precision_rules:
            rule.__post_init__()
        payload = {
            "key": _key_value(self.key),
            "minimum_pairs": self.minimum_pairs,
            "minimum_ordinary_pushes": self.minimum_ordinary_pushes,
            "precision_rule_digests": tuple(rule.rule_digest for rule in self.precision_rules),
        }
        _bind_digest(self, "rule_digest", canonical.content_digest(_value("scope_sufficiency_rule", payload)))


@dataclass(frozen=True)
class ScopedMetricResultV3:
    key: ArmScopeKey
    metric_id: MetricId
    numerator: int
    denominator: int
    sample_count: int
    value: float | None
    interval_method: IntervalMethod
    interval_lower: float | None
    interval_upper: float | None

    def __post_init__(self) -> None:
        _exact(self, ScopedMetricResultV3, "scoped metric result")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        _metric_parts(self.metric_id)
        numerator = _count(self.numerator, "numerator")
        denominator = _count(self.denominator, "denominator", positive=True)
        sample_count = _count(self.sample_count, "sample count", positive=True)
        if numerator > denominator:
            raise EvaluationMeasurementError("numerator must not exceed denominator")
        if sample_count != denominator:
            raise EvaluationMeasurementError("sample count must equal the exact denominator")
        if self.interval_method is not IntervalMethod.WILSON_95:
            raise EvaluationMeasurementError("interval method must be Wilson 95%")
        expected_value, expected_lower, expected_upper = metric_values(self.metric_id.value, numerator, denominator)
        if expected_value is None or expected_lower is None or expected_upper is None:
            raise EvaluationMeasurementError("positive denominator must produce Wilson values")
        expected = (expected_value, expected_lower, expected_upper)
        actual = (self.value, self.interval_lower, self.interval_upper)
        if any(
            type(item) is not float or not math.isfinite(item) or item.hex() != expected[index].hex() for index, item in enumerate(actual)
        ):
            raise EvaluationMeasurementError("metric values must match the fixed Wilson calculation")

    @classmethod
    def from_counts(cls, key: ArmScopeKey, metric_id: MetricId, *, numerator: int, denominator: int) -> ScopedMetricResultV3:
        _exact(key, ArmScopeKey, "arm-scope key")
        key.__post_init__()
        _metric_parts(metric_id)
        numerator = _count(numerator, "numerator")
        denominator = _count(denominator, "denominator", positive=True)
        if numerator > denominator:
            raise EvaluationMeasurementError("numerator must not exceed denominator")
        value, lower, upper = metric_values(metric_id.value, numerator, denominator)
        return cls(key, metric_id, numerator, denominator, denominator, value, IntervalMethod.WILSON_95, lower, upper)


def validate_scoped_metric_result(result: ScopedMetricResultV3, rule: ScopedMetricRuleV3) -> None:
    _exact(result, ScopedMetricResultV3, "scoped metric result")
    _exact(rule, ScopedMetricRuleV3, "scoped metric rule")
    result.__post_init__()
    rule.__post_init__()
    if result.key != rule.key:
        raise EvaluationMeasurementError("scoped metric result arm-scope key does not match its rule")
    if result.metric_id is not rule.metric_id:
        raise EvaluationMeasurementError("scoped metric result identity does not match its rule")


@dataclass(frozen=True)
class AggregateWeightV3:
    key: ArmScopeKey
    numerator: int
    denominator: int
    weight_digest: str

    def __post_init__(self) -> None:
        _exact(self, AggregateWeightV3, "aggregate weight")
        _exact(self.key, ArmScopeKey, "arm-scope key")
        self.key.__post_init__()
        numerator = _count(self.numerator, "weight numerator")
        denominator = _count(self.denominator, "weight denominator", positive=True)
        if numerator > denominator:
            raise EvaluationMeasurementError("aggregate weight must not exceed one")
        if gcd(numerator, denominator) != 1:
            raise EvaluationMeasurementError("aggregate weight must use a reduced rational")
        payload = {"key": _key_value(self.key), "numerator": numerator, "denominator": denominator}
        _bind_digest(self, "weight_digest", canonical.content_digest(_value("aggregate_weight", payload)))


def validate_aggregate_weights(
    constituents: tuple[ArmScopeKey, ...], sample_counts: tuple[int, ...], weights: tuple[AggregateWeightV3, ...]
) -> None:
    if (
        type(constituents) is not tuple
        or not constituents
        or any(type(key) is not ArmScopeKey for key in constituents)
        or constituents != tuple(sorted(set(constituents)))
    ):
        raise EvaluationMeasurementError("aggregate constituents must be unique and in canonical order")
    for key in constituents:
        key.__post_init__()
    if (
        type(sample_counts) is not tuple
        or len(sample_counts) != len(constituents)
        or any(type(count) is not int or count <= 0 for count in sample_counts)
    ):
        raise EvaluationMeasurementError("aggregate sample counts must be positive and align one-to-one")
    if (
        type(weights) is not tuple
        or len(weights) != len(constituents)
        or any(type(weight) is not AggregateWeightV3 for weight in weights)
        or tuple(weight.key for weight in weights) != constituents
    ):
        raise EvaluationMeasurementError("aggregate weights must correspond one-to-one with constituents")
    for weight in weights:
        weight.__post_init__()
    if sum((Fraction(weight.numerator, weight.denominator) for weight in weights), Fraction()) != 1:
        raise EvaluationMeasurementError("aggregate weights must sum exactly to one")


__all__ = [
    "AggregateWeightV3",
    "ArmScopeKey",
    "CaseOutcomeProjectionPolicyV3",
    "Comparator",
    "DenominatorKind",
    "DenominatorPolicyV3",
    "EvaluationMeasurementError",
    "IntervalMethod",
    "IntervalPrecisionRuleV3",
    "MetricId",
    "NeutralOutcome",
    "NumeratorKind",
    "ScopeKey",
    "ScopeSufficiencyRuleV3",
    "ScopedMetricResultV3",
    "ScopedMetricRuleV3",
    "ScopedThresholdV3",
    "Statistic",
    "standard_scoped_metric_rules",
    "validate_aggregate_weights",
    "validate_scoped_metric_result",
]
