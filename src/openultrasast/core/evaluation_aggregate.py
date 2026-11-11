"""Optional non-authorizing aggregate summaries for evaluation admission V3."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import (
    AggregateWeightV3,
    ArmScopeKey,
    EvaluationMeasurementError,
    MetricId,
    ScopedMetricResultV3,
    validate_aggregate_weights,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)

_SCHEMA = "openultrasast.detection-core.evaluation-aggregate.v3"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class EvaluationAggregateError(ValueError):
    """An aggregate cannot be reproduced from complete exact-scope metrics."""


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif type(actual) is not str or _DIGEST.fullmatch(actual) is None or actual != expected:
        raise EvaluationAggregateError(f"{field} does not match canonical content")


def _key_value(key: ArmScopeKey) -> canonical.JsonValue:
    return {"arm_id": key.arm_id, "family_id": key.scope.family_id, "ecosystem": key.scope.ecosystem}


def _scoped_metric_value(metric: ScopedMetricResultV3) -> canonical.JsonValue:
    return {
        "key": _key_value(metric.key),
        "metric_id": metric.metric_id.value,
        "numerator": metric.numerator,
        "denominator": metric.denominator,
        "sample_count": metric.sample_count,
        "value": metric.value,
        "interval_method": metric.interval_method.value,
        "interval_lower": metric.interval_lower,
        "interval_upper": metric.interval_upper,
    }


def _scoped_metric_digest(metric: ScopedMetricResultV3) -> str:
    metric.__post_init__()
    return canonical.content_digest({"schema_version": _SCHEMA, "kind": "scoped_metric", "payload": _scoped_metric_value(metric)})


def _aggregate_metric_value(metric: AggregateMetricV3) -> canonical.JsonValue:
    return {
        "metric_id": metric.metric_id.value,
        "weighted_value": metric.weighted_value,
        "constituent_metric_digests": metric.constituent_metric_digests,
    }


@dataclass(frozen=True)
class AggregateMetricV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    metric_id: MetricId
    weighted_value: float
    constituent_metric_digests: tuple[str, ...]
    metric_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AggregateMetricV3, field="aggregate metric")
        if type(self.metric_id) is not MetricId:
            raise EvaluationAggregateError("aggregate metric requires a closed metric identity")
        if type(self.weighted_value) is not float or not math.isfinite(self.weighted_value):
            raise EvaluationAggregateError("aggregate metric value must be a finite float")
        digests = self.constituent_metric_digests
        if type(digests) is not tuple or not digests:
            raise EvaluationAggregateError("aggregate metric requires constituent metric identities")
        if any(type(item) is not str or _DIGEST.fullmatch(item) is None for item in digests):
            raise EvaluationAggregateError("constituent metric identities must be full lowercase SHA-256 digests")
        payload = _aggregate_metric_value(self)
        _bind(self, "metric_digest", canonical.content_digest({"schema_version": _SCHEMA, "kind": "metric", "payload": payload}))


def _weight_value(weight: AggregateWeightV3) -> canonical.JsonValue:
    return {
        "key": _key_value(weight.key),
        "numerator": weight.numerator,
        "denominator": weight.denominator,
        "weight_digest": weight.weight_digest,
    }


@dataclass(frozen=True)
class EvaluationAggregateV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    constituents: tuple[ArmScopeKey, ...]
    sample_counts: tuple[int, ...]
    weights: tuple[AggregateWeightV3, ...]
    metrics: tuple[AggregateMetricV3, ...]
    aggregate_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationAggregateV3, field="evaluation aggregate")
        try:
            validate_aggregate_weights(self.constituents, self.sample_counts, self.weights)
        except EvaluationMeasurementError as exc:
            raise EvaluationAggregateError(f"aggregate weights or sample counts are invalid: {exc}") from exc
        if type(self.metrics) is not tuple:
            raise EvaluationAggregateError("aggregate metrics must use an exact tuple")
        metric_ids = tuple(row.metric_id for row in self.metrics if type(row) is AggregateMetricV3)
        if metric_ids != tuple(MetricId):
            raise EvaluationAggregateError("aggregate requires every metric in canonical order")
        for row in self.metrics:
            row.__post_init__()
            if len(row.constituent_metric_digests) != len(self.constituents):
                raise EvaluationAggregateError("aggregate metric identities must align one-to-one with constituents")
        payload: canonical.JsonValue = {
            "constituents": tuple(_key_value(key) for key in self.constituents),
            "sample_counts": self.sample_counts,
            "weights": tuple(_weight_value(weight) for weight in self.weights),
            "metric_digests": tuple(metric.metric_digest for metric in self.metrics),
        }
        _bind(self, "aggregate_digest", canonical.content_digest({"schema_version": _SCHEMA, "kind": "aggregate", "payload": payload}))


def _validate_source_metrics(metrics: object) -> tuple[tuple[ArmScopeKey, ...], tuple[ScopedMetricResultV3, ...]]:
    if type(metrics) is not tuple or not metrics or any(type(item) is not ScopedMetricResultV3 for item in metrics):
        raise EvaluationAggregateError("aggregate source metrics must be a nonempty exact tuple")
    for metric in metrics:
        metric.__post_init__()
        if metric.value is None:
            raise EvaluationAggregateError("aggregate source metric value must be complete")
    keys = tuple(sorted({metric.key for metric in metrics}))
    expected = tuple((key, metric_id) for key in keys for metric_id in MetricId)
    actual = tuple((metric.key, metric.metric_id) for metric in metrics)
    if actual != expected:
        raise EvaluationAggregateError("aggregate source metrics must be complete and in canonical order")
    return keys, metrics


def _derive_metric_rows(
    keys: tuple[ArmScopeKey, ...],
    metrics: tuple[ScopedMetricResultV3, ...],
    weights: tuple[AggregateWeightV3, ...],
) -> tuple[AggregateMetricV3, ...]:
    metrics_by_identity = {(metric.key, metric.metric_id): metric for metric in metrics}
    rows = []
    for metric_id in MetricId:
        selected = tuple(metrics_by_identity[(key, metric_id)] for key in keys)
        weighted = math.fsum(
            metric.value * float(Fraction(weight.numerator, weight.denominator))
            for metric, weight in zip(selected, weights, strict=True)
            if metric.value is not None
        )
        rows.append(AggregateMetricV3(metric_id, weighted, tuple(_scoped_metric_digest(metric) for metric in selected), ""))
    return tuple(rows)


def derive_evaluation_aggregate_v3(
    metrics: tuple[ScopedMetricResultV3, ...],
    sample_counts: tuple[int, ...],
    weights: tuple[AggregateWeightV3, ...],
) -> EvaluationAggregateV3:
    """Derive an optional summary that has no consumer-authority capability."""
    try:
        keys, selected = _validate_source_metrics(metrics)
        validate_aggregate_weights(keys, sample_counts, weights)
        rows = _derive_metric_rows(keys, selected, weights)
        return EvaluationAggregateV3(keys, sample_counts, weights, rows, "")
    except EvaluationAggregateError:
        raise
    except (EvaluationMeasurementError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise EvaluationAggregateError(f"aggregate derivation refused invalid evidence: {exc}") from exc


def validate_evaluation_aggregate_v3(
    aggregate: EvaluationAggregateV3,
    metrics: tuple[ScopedMetricResultV3, ...],
) -> None:
    """Reproduce an aggregate exactly from its canonical scoped metric identities."""
    try:
        require_exact_v3_contract(aggregate, EvaluationAggregateV3, field="evaluation aggregate")
        aggregate.__post_init__()
        expected = derive_evaluation_aggregate_v3(metrics, aggregate.sample_counts, aggregate.weights)
        if aggregate != expected:
            raise EvaluationAggregateError("aggregate does not reproduce from exact scoped metrics")
    except EvaluationAggregateError:
        raise
    except (EvaluationMeasurementError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise EvaluationAggregateError(f"aggregate validation refused invalid evidence: {exc}") from exc


__all__ = [
    "AggregateMetricV3",
    "EvaluationAggregateError",
    "EvaluationAggregateV3",
    "derive_evaluation_aggregate_v3",
    "validate_evaluation_aggregate_v3",
]
