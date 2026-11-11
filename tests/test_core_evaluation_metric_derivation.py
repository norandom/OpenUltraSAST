"""Complete exact-scope metric derivation for evaluation V3."""

from __future__ import annotations

import math
from dataclasses import replace

import pytest
from test_core_evaluation_case_validation import _digest
from test_core_evaluation_ordinary_projection import _project, _valid_bundle
from test_core_evaluation_scoped_metrics import _partition

from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.evaluation_measurement import MetricId, ScopedMetricResultV3
from openultrasast.core.evaluation_plan import EcosystemOrdinaryCensusV3, ExactScopeCensusV3
from openultrasast.core.model import ModelStatus


def _derived_inputs():
    bundle = _valid_bundle()
    partition = _partition(bundle)[0]
    statuses = (ModelStatus.SUCCEEDED, ModelStatus.FAILED, ModelStatus.SUCCEEDED)
    cases = tuple(replace(case, model_outcomes=(statuses[index],)) for index, case in enumerate(partition.cases))
    partition = replace(partition, cases=cases)
    projection = next(row for row in _project(bundle).scoped_projections if row.key == partition.key)
    bindings = tuple(binding for binding in bundle[1].bindings if binding.key == partition.key)
    census = ExactScopeCensusV3(partition.key.scope, 1, 1, 1, 6, 3)
    ordinary = EcosystemOrdinaryCensusV3(partition.key.scope.ecosystem, 1)
    return partition, projection, bindings, census, ordinary


def _complete_inputs():
    bundle = _valid_bundle()
    partitions = _partition(bundle)
    statuses = (ModelStatus.SUCCEEDED, ModelStatus.FAILED, ModelStatus.SUCCEEDED)
    partitions = tuple(
        replace(
            partition,
            cases=tuple(replace(case, model_outcomes=(statuses[index],)) for index, case in enumerate(partition.cases)),
        )
        for partition in partitions
    )
    projections = _project(bundle).scoped_projections
    scopes = tuple(sorted({partition.key.scope for partition in partitions}))
    scope_rows = tuple(ExactScopeCensusV3(scope, 1, 1, 1, 6, 3) for scope in scopes)
    ecosystems = tuple(sorted({scope.ecosystem for scope in scopes}))
    ordinary_rows = tuple(EcosystemOrdinaryCensusV3(ecosystem, 1) for ecosystem in ecosystems)
    return partitions, projections, bundle[1].bindings, scope_rows, ordinary_rows


def _derive(partitions, projections, bindings, scope_rows, ordinary_rows):
    from openultrasast.core.evaluation_metric_derivation import _derive_scoped_metric_results_v3

    return _derive_scoped_metric_results_v3(partitions, projections, bindings, scope_rows, ordinary_rows)


def _by_metric(results: tuple[ScopedMetricResultV3, ...]) -> dict[MetricId, ScopedMetricResultV3]:
    return {result.metric_id: result for result in results}


def _wilson(numerator: int, denominator: int, *, scale: float = 1.0) -> tuple[float, float]:
    proportion = numerator / denominator
    z = 1.959963984540054
    z2 = z * z
    divisor = 1.0 + z2 / denominator
    center = (proportion + z2 / (2.0 * denominator)) / divisor
    margin = z / divisor * math.sqrt(proportion * (1.0 - proportion) / denominator + z2 / (4.0 * denominator**2))
    return (center - margin) * scale, (center + margin) * scale


def test_independent_count_fixture_produces_every_standard_metric_with_wilson_fields() -> None:
    partition, projection, bindings, census, ordinary = _derived_inputs()

    results = _derive((partition,), (projection,), bindings, (census,), (ordinary,))

    assert tuple(result.metric_id for result in results) == tuple(MetricId)
    expected = {
        MetricId.PAIRED_CORRECTNESS: (0, 1),
        MetricId.VULNERABLE_RECALL: (1, 1),
        MetricId.FIXED_FALSE_ALARM_RATE: (1, 1),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (1, 1),
        MetricId.PRECISION: (1, 3),
        MetricId.SEMANTIC_STAGE_COVERAGE: (6, 6),
        MetricId.MODEL_SUCCESS_RATE: (2, 3),
    }
    assert {metric: (result.numerator, result.denominator) for metric, result in _by_metric(results).items()} == expected
    for result in results:
        assert result.key == partition.key
        assert result.sample_count == result.denominator
        assert result.value is not None
        assert result.interval_lower is not None
        assert result.interval_upper is not None
    precision = _by_metric(results)[MetricId.PRECISION]
    assert precision.value == 1.0 / 3.0
    assert (precision.interval_lower, precision.interval_upper) == _wilson(1, 3)
    ordinary_metric = _by_metric(results)[MetricId.ORDINARY_FALSE_ALARMS_PER_100]
    assert ordinary_metric.value == 100.0
    assert (ordinary_metric.interval_lower, ordinary_metric.interval_upper) == _wilson(1, 1, scale=100.0)


def test_complete_metric_set_is_derived_for_every_exact_arm_scope_key() -> None:
    partitions, projections, bindings, scope_rows, ordinary_rows = _complete_inputs()

    results = _derive(partitions, projections, bindings, scope_rows, ordinary_rows)

    expected = tuple((partition.key, metric_id) for partition in partitions for metric_id in MetricId)
    assert tuple((result.key, result.metric_id) for result in results) == expected
    assert len(results) == len(partitions) * len(MetricId)


@pytest.mark.parametrize("metric_id", tuple(MetricId))
def test_every_post_spend_standard_metric_refuses_a_zero_denominator(metric_id: MetricId) -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError, _scoped_result

    partition, _, _, _, _ = _derived_inputs()
    with pytest.raises(EvaluationMetricDerivationError, match="zero denominator"):
        _scoped_result(partition.key, metric_id, 0, 0)


def test_missing_or_reordered_standard_metric_is_refused() -> None:
    from openultrasast.core.evaluation_metric_derivation import (
        EvaluationMetricDerivationError,
        validate_complete_scoped_metrics_v3,
    )

    partition, projection, bindings, census, ordinary = _derived_inputs()
    results = _derive((partition,), (projection,), bindings, (census,), (ordinary,))
    with pytest.raises(EvaluationMetricDerivationError, match="standard metric"):
        validate_complete_scoped_metrics_v3((partition.denominator_policy,), results[:-1])
    with pytest.raises(EvaluationMetricDerivationError, match="canonical order"):
        validate_complete_scoped_metrics_v3((partition.denominator_policy,), tuple(reversed(results)))


def test_post_spend_zero_precision_denominator_is_invalid() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError

    partition, projection, bindings, census, ordinary = _derived_inputs()
    cases = tuple(replace(case, has_findings=False, evidence_bases=()) for case in partition.cases)
    pairs = tuple(replace(pair, is_correct=False) for pair in partition.pairs)
    partition = replace(
        partition,
        cases=cases,
        pairs=pairs,
        precision_numerator_case_digests=(),
        precision_denominator_case_digests=(),
    )

    with pytest.raises(EvaluationMetricDerivationError, match="zero denominator"):
        _derive((partition,), (projection,), bindings, (census,), (ordinary,))


def test_post_spend_zero_pair_vulnerable_and_fixed_denominators_are_invalid() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError

    partition, projection, bindings, _, ordinary = _derived_inputs()
    case = next(case for case in partition.cases if case.role is AdmissionCaseRole.ORDINARY)
    partition = replace(
        partition,
        cases=(case,),
        pairs=(),
        precision_numerator_case_digests=(),
        precision_denominator_case_digests=(case.case_id_digest,),
    )
    census = ExactScopeCensusV3(partition.key.scope, 0, 0, 0, 2, 1)

    with pytest.raises(EvaluationMetricDerivationError, match="zero denominator"):
        selected_bindings = tuple(binding for binding in bindings if binding.role is AdmissionCaseRole.ORDINARY)
        _derive((partition,), (projection,), selected_bindings, (census,), (ordinary,))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("pair_count", 0),
        ("vulnerable_side_count", 2),
        ("fixed_side_count", 2),
        ("semantic_site_capacity", 7),
        ("model_call_capacity", 4),
    ),
)
def test_each_exact_scope_census_mismatch_is_invalid(field: str, value: int) -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError

    partition, projection, bindings, census, ordinary = _derived_inputs()
    with pytest.raises(EvaluationMetricDerivationError, match="census"):
        _derive((partition,), (projection,), bindings, (replace(census, **{field: value}),), (ordinary,))


def test_ordinary_census_or_projection_identity_mismatch_is_invalid() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError
    from openultrasast.core.evaluation_ordinary_projection import OrdinaryPushCaseV3, ScopedOrdinaryProjectionV3

    partition, projection, bindings, census, ordinary = _derived_inputs()
    with pytest.raises(EvaluationMetricDerivationError, match="ordinary census"):
        _derive((partition,), (projection,), bindings, (census,), (replace(ordinary, ordinary_push_count=2),))

    source = projection.cases[0]
    substituted = OrdinaryPushCaseV3(source.key, _digest("unrelated-case"), source.binding_digest, source.underlying_push_digest, "")
    inconsistent = ScopedOrdinaryProjectionV3(source.key, (substituted,), 1, "")
    with pytest.raises(EvaluationMetricDerivationError, match="ordinary projection"):
        _derive((partition,), (inconsistent,), bindings, (census,), (ordinary,))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("binding_digest", _digest("substituted-binding")),
        ("underlying_push_digest", _digest("substituted-underlying-push")),
    ),
)
def test_ordinary_projection_must_match_exact_released_binding_lineage(field: str, value: str) -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError
    from openultrasast.core.evaluation_ordinary_projection import ScopedOrdinaryProjectionV3

    partition, projection, bindings, census, ordinary = _derived_inputs()
    changed = replace(projection.cases[0], **{field: value, "identity_digest": ""})
    inconsistent = ScopedOrdinaryProjectionV3(projection.key, (changed,), 1, "")
    with pytest.raises(EvaluationMetricDerivationError, match="ordinary projection"):
        _derive((partition,), (inconsistent,), bindings, (census,), (ordinary,))


def test_ordinary_projection_refuses_omitted_or_duplicate_lineage() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError
    from openultrasast.core.evaluation_ordinary_projection import OrdinaryPushCaseV3, ScopedOrdinaryProjectionV3

    partition, projection, bindings, census, ordinary = _derived_inputs()
    omitted = ScopedOrdinaryProjectionV3(projection.key, (), 0, "")
    source = projection.cases[0]
    extra = OrdinaryPushCaseV3(
        source.key,
        source.case_id_digest,
        source.binding_digest,
        _digest("duplicate-lineage-push"),
        "",
    )
    duplicated = ScopedOrdinaryProjectionV3(
        projection.key,
        tuple(sorted((source, extra), key=lambda item: (item.underlying_push_digest, item.case_id_digest))),
        2,
        "",
    )
    for inconsistent in (omitted, duplicated):
        with pytest.raises(EvaluationMetricDerivationError, match="ordinary projection"):
            _derive((partition,), (inconsistent,), bindings, (census,), (ordinary,))


def test_released_bindings_must_be_exact_complete_unique_and_canonical() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError

    partition, projection, bindings, census, ordinary = _derived_inputs()
    malformed = (list(bindings), tuple(reversed(bindings)), bindings[:-1], bindings + bindings[:1])
    for supplied in malformed:
        with pytest.raises(EvaluationMetricDerivationError, match="released bindings"):
            _derive((partition,), (projection,), supplied, (census,), (ordinary,))


def test_reviewed_release_is_revalidated_before_metric_derivation() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError, derive_scoped_metrics_v3

    bundle = _valid_bundle()
    reviewed_case = bundle[5]
    with pytest.raises(EvaluationMetricDerivationError, match="census|metric"):
        derive_scoped_metrics_v3(
            bundle[3],
            bundle[6],
            bundle[7],
            bundle[8],
            bundle[9],
            bundle[1],
            bundle[2],
            reviewed_case[0].context,
            reviewed_case[0].port,
            bundle[4],
        )


def test_metric_derivation_refuses_non_exact_root_collections() -> None:
    from openultrasast.core.evaluation_metric_derivation import EvaluationMetricDerivationError

    partition, projection, bindings, census, ordinary = _derived_inputs()
    with pytest.raises(EvaluationMetricDerivationError, match="exact tuple"):
        _derive([partition], (projection,), bindings, (census,), (ordinary,))


def test_metric_results_are_non_authorizing_and_v2_algebra_is_unchanged() -> None:
    from openultrasast.core import admission_metrics

    assert not {"gate", "decision", "authorization"} & ScopedMetricResultV3.__dataclass_fields__.keys()
    assert admission_metrics._metric_counts.__name__ == "_metric_counts"
