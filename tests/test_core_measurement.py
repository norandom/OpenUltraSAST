"""Fixed measurement algebra and baseline comparability contracts."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_family_catalog import _catalog as make_family_catalog
from test_core_family_catalog import _contract as make_family_contract

from openultrasast.core import canonical
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    DenominatorKind,
    DenominatorPolicy,
    IntervalMethod,
    MeasurementContractError,
    MetricId,
    NumeratorKind,
    ScopeKey,
    Statistic,
    derive_baseline_identity_digest,
    derive_denominator_policy_digest,
    derive_identity_set_digest,
    evaluate_metric,
    metric_passes,
    metric_result_value,
    require_comparable_baselines,
    standard_metric_rules,
)


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _scopes() -> tuple[ScopeKey, ...]:
    return (ScopeKey("access_control", "python"), ScopeKey("injection", "javascript"))


def _policy() -> DenominatorPolicy:
    rules = standard_metric_rules(_scopes())
    return DenominatorPolicy(rules, IntervalMethod.WILSON_95, "")


def _baseline(*, arm_id: str = "arm-a", scopes: tuple[ScopeKey, ...] | None = None) -> BaselineIdentity:
    contracts = (_digest("contract-a"), _digest("contract-b"))
    models = (_digest("model-a"),)
    return BaselineIdentity(
        arm_id=arm_id,
        population_digest=_digest("population"),
        freeze_digest=_digest("freeze"),
        claimed_scopes=scopes or _scopes(),
        family_contract_digests=contracts,
        family_contract_set_digest=_digest("family-catalog"),
        fact_schema_digest=_digest("fact-schema"),
        fact_set_digest=_digest("fact-set"),
        acquisition_record_digest=_digest("acquisition"),
        analyzer_revision="analyzer-v7",
        configuration_digest=_digest("configuration"),
        model_program_digests=models,
        model_program_set_digest=derive_identity_set_digest("model_program", models),
        denominator_policy_digest=_policy().policy_digest,
        threshold_set_digest=_digest("thresholds"),
        outcome_mapping_digest=_digest("outcome-mapping"),
    )


def test_baseline_identity_binds_every_comparability_field() -> None:
    baseline = _baseline()
    original = derive_baseline_identity_digest(baseline)
    mutations = (
        replace(baseline, arm_id="arm-b"),
        replace(baseline, population_digest=_digest("population-b")),
        replace(baseline, freeze_digest=_digest("freeze-b")),
        _baseline(scopes=(ScopeKey("access_control", "python"),)),
        replace(baseline, family_contract_digests=(_digest("contract-c"),)),
        replace(baseline, family_contract_set_digest=_digest("family-catalog-c")),
        replace(baseline, fact_schema_digest=_digest("fact-schema-b")),
        replace(baseline, fact_set_digest=_digest("fact-set-b")),
        replace(baseline, acquisition_record_digest=_digest("acquisition-b")),
        replace(baseline, analyzer_revision="analyzer-v8"),
        replace(baseline, configuration_digest=_digest("configuration-b")),
        replace(
            baseline,
            model_program_digests=(_digest("model-b"),),
            model_program_set_digest=derive_identity_set_digest("model_program", (_digest("model-b"),)),
        ),
        replace(baseline, denominator_policy_digest=_digest("denominator-b")),
        replace(baseline, threshold_set_digest=_digest("thresholds-b")),
        replace(baseline, outcome_mapping_digest=_digest("outcome-mapping-b")),
    )
    assert len(mutations) == 15
    assert all(derive_baseline_identity_digest(item) != original for item in mutations)
    for mutation in mutations:
        with pytest.raises(MeasurementContractError, match="non-comparable baseline"):
            require_comparable_baselines((baseline, mutation))


def test_baseline_accepts_authoritative_catalog_digest_and_exact_contract_set() -> None:
    catalog = make_family_catalog(make_family_contract("alpha"), make_family_contract("zeta"))
    contracts = tuple(sorted(entry.contract_digest for entry in catalog.entries))
    baseline = replace(
        _baseline(),
        family_contract_digests=contracts,
        family_contract_set_digest=catalog.catalog_digest,
    )
    assert baseline.family_contract_set_digest == catalog.catalog_digest
    assert baseline.family_contract_digests == contracts
    mutations = (
        replace(baseline, family_contract_set_digest=_digest("substituted catalog")),
        replace(baseline, family_contract_digests=(_digest("substituted contract"),)),
    )
    for mutation in mutations:
        assert derive_baseline_identity_digest(mutation) != derive_baseline_identity_digest(baseline)
        with pytest.raises(MeasurementContractError, match="non-comparable baseline"):
            require_comparable_baselines((baseline, mutation))


def test_baseline_refuses_noncanonical_or_inconsistent_sets() -> None:
    baseline = _baseline()
    with pytest.raises(MeasurementContractError, match="canonical order"):
        replace(baseline, claimed_scopes=tuple(reversed(baseline.claimed_scopes)))
    with pytest.raises(MeasurementContractError, match="duplicate"):
        replace(
            baseline,
            family_contract_digests=(baseline.family_contract_digests[0],) * 2,
            family_contract_set_digest=derive_identity_set_digest("family_contract", (baseline.family_contract_digests[0],) * 2),
        )
    with pytest.raises(MeasurementContractError, match="model program set digest"):
        replace(baseline, model_program_digests=(), model_program_set_digest=baseline.model_program_set_digest)


def test_two_arms_and_cross_scope_results_cannot_aggregate() -> None:
    baseline = _baseline()
    assert require_comparable_baselines((baseline, baseline)) == baseline
    with pytest.raises(MeasurementContractError, match="non-comparable baseline"):
        require_comparable_baselines((baseline, _baseline(arm_id="arm-b")))
    with pytest.raises(MeasurementContractError, match="non-comparable baseline"):
        require_comparable_baselines((baseline, _baseline(scopes=(ScopeKey("access_control", "python"),))))
    with pytest.raises(MeasurementContractError, match="nonempty"):
        require_comparable_baselines(())


def test_standard_policy_is_closed_and_canonical() -> None:
    policy = _policy()
    assert tuple(rule.metric_id for rule in policy.rules) == tuple(MetricId)
    assert policy.interval_method is IntervalMethod.WILSON_95
    assert policy.policy_digest == derive_denominator_policy_digest(policy)
    expected = {
        MetricId.PAIRED_CORRECTNESS: (NumeratorKind.CORRECT_PAIRS, DenominatorKind.PAIRS),
        MetricId.VULNERABLE_RECALL: (NumeratorKind.VULNERABLE_VIOLATION_CASES, DenominatorKind.VULNERABLE_SIDES),
        MetricId.FIXED_FALSE_ALARM_RATE: (NumeratorKind.FIXED_DEFECT_CASES, DenominatorKind.FIXED_SIDES),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (NumeratorKind.ORDINARY_DEFECT_CASES, DenominatorKind.ORDINARY_CASES),
        MetricId.PRECISION: (NumeratorKind.TRUE_DEFECT_CASES, DenominatorKind.ALL_DEFECT_CASES),
        MetricId.SEMANTIC_STAGE_COVERAGE: (NumeratorKind.SITES_RECOGNIZED, DenominatorKind.SITES_CONSIDERED),
        MetricId.MODEL_SUCCESS_RATE: (NumeratorKind.SUCCESSFUL_MODEL_CALLS, DenominatorKind.MODEL_CALLS),
    }
    assert {rule.metric_id: (rule.numerator, rule.denominator) for rule in policy.rules} == expected


def test_policy_refuses_missing_duplicate_or_reversed_rules() -> None:
    policy = _policy()
    with pytest.raises(MeasurementContractError, match="exactly once"):
        DenominatorPolicy(policy.rules[:-1], policy.interval_method, policy.policy_digest)
    with pytest.raises(MeasurementContractError, match="exactly once"):
        DenominatorPolicy(policy.rules[:-1] + (policy.rules[0],), policy.interval_method, policy.policy_digest)
    wrong = replace(policy.rules[0], numerator=NumeratorKind.FIXED_DEFECT_CASES)
    with pytest.raises(MeasurementContractError, match="fixed algebra"):
        DenominatorPolicy((wrong,) + policy.rules[1:], policy.interval_method, policy.policy_digest)
    with pytest.raises(MeasurementContractError, match="canonical order"):
        DenominatorPolicy(tuple(reversed(policy.rules)), policy.interval_method, policy.policy_digest)


@pytest.mark.parametrize("metric_id", tuple(MetricId))
def test_zero_denominator_is_null_and_cannot_pass(metric_id: MetricId) -> None:
    rule = {item.metric_id: item for item in standard_metric_rules(_scopes())}[metric_id]
    result = evaluate_metric(rule, numerator=0, denominator=0)
    assert result.numerator == 0
    assert result.denominator == 0
    assert result.value is None
    assert result.interval_lower is None
    assert result.interval_upper is None
    serialized = canonical.canonical_bytes(metric_result_value(result))
    assert b'"value":null' in serialized
    assert b'"interval_lower":null' in serialized
    assert b'"interval_upper":null' in serialized
    false_alarm = metric_id in {MetricId.FIXED_FALSE_ALARM_RATE, MetricId.ORDINARY_FALSE_ALARMS_PER_100}
    comparator = Comparator.AT_MOST if false_alarm else Comparator.AT_LEAST
    statistic = Statistic.PER_100 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else Statistic.RATE
    assert not metric_passes(result, statistic, comparator, 0.0)
    assert not metric_passes(result, Statistic.COUNT, comparator, 0.0)


def test_wilson_95_interval_and_metric_scales_are_fixed() -> None:
    rules = {rule.metric_id: rule for rule in standard_metric_rules(_scopes())}
    recall = evaluate_metric(rules[MetricId.VULNERABLE_RECALL], numerator=8, denominator=10)
    assert recall.value == pytest.approx(0.8)
    assert recall.interval_lower == pytest.approx(0.4901624715)
    assert recall.interval_upper == pytest.approx(0.9433178485)
    ordinary = evaluate_metric(rules[MetricId.ORDINARY_FALSE_ALARMS_PER_100], numerator=2, denominator=40)
    assert ordinary.value == pytest.approx(5.0)
    assert ordinary.interval_lower == pytest.approx(1.3820667386)
    assert ordinary.interval_upper == pytest.approx(16.5038773691)
    assert metric_passes(recall, Statistic.WILSON_LOWER, Comparator.AT_LEAST, 0.49)
    assert metric_passes(ordinary, Statistic.PER_100, Comparator.AT_MOST, 5.0)


def test_metric_counts_and_threshold_inputs_are_strict() -> None:
    rule = standard_metric_rules(_scopes())[0]
    for numerator, denominator in ((-1, 1), (True, 1), (2, 1), (0, -1)):
        with pytest.raises(MeasurementContractError):
            evaluate_metric(rule, numerator=numerator, denominator=denominator)
    result = evaluate_metric(rule, numerator=1, denominator=1)
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, value=0.0)
    with pytest.raises(MeasurementContractError, match="finite"):
        metric_passes(result, Statistic.RATE, Comparator.AT_LEAST, float("nan"))
    with pytest.raises(MeasurementContractError, match="statistic"):
        metric_passes(result, Statistic.PER_100, Comparator.AT_LEAST, 1.0)
    with pytest.raises(MeasurementContractError, match="comparator direction"):
        metric_passes(result, Statistic.RATE, Comparator.AT_MOST, 1.0)


def test_metric_result_rejects_boolean_float_aliases() -> None:
    rule = standard_metric_rules(_scopes())[0]
    result = evaluate_metric(rule, numerator=1, denominator=1)
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, value=True)
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, interval_upper=True)


def test_metric_result_rejects_integer_float_aliases() -> None:
    rule = standard_metric_rules(_scopes())[0]
    result = evaluate_metric(rule, numerator=1, denominator=1)
    assert replace(result, value=1.0, interval_upper=1.0) == result
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, value=1)
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, interval_upper=1)


def test_metric_result_rejects_negative_signed_zero_aliases() -> None:
    rule = standard_metric_rules(_scopes())[0]
    result = evaluate_metric(rule, numerator=0, denominator=1)
    assert replace(result, value=0.0, interval_lower=0.0) == result
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, value=-0.0)
    with pytest.raises(MeasurementContractError, match="fixed Wilson algebra"):
        replace(result, interval_lower=-0.0)
