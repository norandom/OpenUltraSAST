"""Optional non-authorizing aggregates for evaluation V3."""

from __future__ import annotations

import math
from dataclasses import replace

import pytest

from openultrasast.core.evaluation_measurement import (
    AggregateWeightV3,
    ArmScopeKey,
    MetricId,
    ScopedMetricResultV3,
    ScopeKey,
)


def _key(arm_id: str, ecosystem: str = "python") -> ArmScopeKey:
    return ArmScopeKey(arm_id, ScopeKey("reference-family", ecosystem))


def _inputs():
    keys = (_key("arm-a"), _key("arm-b", "javascript"))
    counts = ((1, 2), (3, 4))
    metrics = tuple(
        ScopedMetricResultV3.from_counts(key, metric_id, numerator=numerator, denominator=denominator)
        for key, (numerator, denominator) in zip(keys, counts, strict=True)
        for metric_id in MetricId
    )
    sample_counts = (2, 4)
    weights = (
        AggregateWeightV3(keys[0], 1, 3, ""),
        AggregateWeightV3(keys[1], 2, 3, ""),
    )
    return keys, metrics, sample_counts, weights


def _derive(metrics, sample_counts, weights):
    from openultrasast.core.evaluation_aggregate import derive_evaluation_aggregate_v3

    return derive_evaluation_aggregate_v3(metrics, sample_counts, weights)


def test_valid_aggregate_reproduces_every_weighted_metric_and_identity() -> None:
    keys, metrics, sample_counts, weights = _inputs()

    aggregate = _derive(metrics, sample_counts, weights)

    assert aggregate.constituents == keys
    assert aggregate.sample_counts == sample_counts
    assert aggregate.weights == weights
    assert tuple(row.metric_id for row in aggregate.metrics) == tuple(MetricId)
    for row in aggregate.metrics:
        values = tuple(metric.value for metric in metrics if metric.metric_id is row.metric_id)
        assert None not in values
        expected = math.fsum((values[0] * (1 / 3), values[1] * (2 / 3)))
        assert row.weighted_value.hex() == expected.hex()
        assert len(row.constituent_metric_digests) == len(keys)


def test_aggregate_requires_complete_canonical_exact_scope_metric_sets() -> None:
    _, metrics, sample_counts, weights = _inputs()
    malformed = (metrics[:-1], tuple(reversed(metrics)), list(metrics))
    for supplied in malformed:
        with pytest.raises(ValueError, match="complete|canonical|exact tuple"):
            _derive(supplied, sample_counts, weights)


def test_aggregate_requires_canonical_one_to_one_weights_and_sample_counts() -> None:
    keys, metrics, sample_counts, weights = _inputs()
    invalid_weights = (
        AggregateWeightV3(keys[0], 1, 3, ""),
        AggregateWeightV3(keys[1], 1, 3, ""),
    )
    with pytest.raises(ValueError, match="sum exactly to one"):
        _derive(metrics, sample_counts, invalid_weights)
    with pytest.raises(ValueError, match="sample counts"):
        _derive(metrics, (2,), weights)
    with pytest.raises(ValueError, match="sample counts"):
        _derive(metrics, (2, 0), weights)


def test_aggregate_validation_rederives_values_digests_and_weight_binding() -> None:
    from openultrasast.core.evaluation_aggregate import (
        EvaluationAggregateError,
        validate_evaluation_aggregate_v3,
    )

    _, metrics, sample_counts, weights = _inputs()
    aggregate = _derive(metrics, sample_counts, weights)
    validate_evaluation_aggregate_v3(aggregate, metrics)

    changed_metric = replace(aggregate.metrics[0], weighted_value=0.75, metric_digest="")
    changed = replace(aggregate, metrics=(changed_metric,) + aggregate.metrics[1:], aggregate_digest="")
    with pytest.raises(EvaluationAggregateError, match="reproduce"):
        validate_evaluation_aggregate_v3(changed, metrics)

    swapped_weights = (
        AggregateWeightV3(aggregate.constituents[0], 2, 3, ""),
        AggregateWeightV3(aggregate.constituents[1], 1, 3, ""),
    )
    reweighted = _derive(metrics, sample_counts, swapped_weights)
    assert reweighted.aggregate_digest != aggregate.aggregate_digest
    assert reweighted.metrics[0].metric_digest != aggregate.metrics[0].metric_digest


def test_aggregate_contract_has_no_gate_decision_proof_or_authority_capability() -> None:
    from openultrasast.core.evaluation_aggregate import AggregateMetricV3, EvaluationAggregateV3
    from openultrasast.core.evaluation_version import NonAuthorizingV3

    fields = set(EvaluationAggregateV3.__dataclass_fields__) | set(AggregateMetricV3.__dataclass_fields__)
    assert not {"gate", "decision", "proof", "authorization", "consumer_authority"} & fields
    assert issubclass(EvaluationAggregateV3, NonAuthorizingV3)
    assert not any(name.startswith("authorize") for name in dir(EvaluationAggregateV3))


def test_v2_metric_algebra_remains_unchanged() -> None:
    from openultrasast.core import admission_metrics

    assert admission_metrics._metric_counts.__name__ == "_metric_counts"
