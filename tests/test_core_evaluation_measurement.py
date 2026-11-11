"""Exact V3 arm/scope measurement contracts."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from itertools import product

import pytest

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import (
    AggregateWeightV3,
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    CombinationDecisionRowV3,
    CombinationOperatorV3,
    CombinationRuleV3,
    Comparator,
    DenominatorPolicyV3,
    EvaluationMeasurementError,
    IntervalMethod,
    IntervalPrecisionRuleV3,
    MetricId,
    NeutralOutcome,
    ProofCandidatePolicyV3,
    ScopedMetricResultV3,
    ScopedThresholdV3,
    ScopeKey,
    ScopeSufficiencyRuleV3,
    Statistic,
    derive_arm_configuration_identity_digest,
    standard_scoped_metric_rules,
    validate_aggregate_weights,
    validate_scoped_metric_result,
)


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _key(arm_id: str = "arm-a", family: str = "access_control") -> ArmScopeKey:
    return ArmScopeKey(arm_id, ScopeKey(family, "python"))


def _policy(key: ArmScopeKey) -> DenominatorPolicyV3:
    return DenominatorPolicyV3(key, standard_scoped_metric_rules(key), IntervalMethod.WILSON_95, "")


def _thresholds(key: ArmScopeKey) -> tuple[ScopedThresholdV3, ...]:
    rows = []
    for metric_id in MetricId:
        comparator = (
            Comparator.AT_MOST
            if metric_id
            in {
                MetricId.FIXED_FALSE_ALARM_RATE,
                MetricId.ORDINARY_FALSE_ALARMS_PER_100,
            }
            else Comparator.AT_LEAST
        )
        statistic = Statistic.PER_100 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else Statistic.RATE
        rows.append(ScopedThresholdV3(key, metric_id, statistic, comparator, 0.5, ""))
    return tuple(rows)


def _sufficiency(key: ArmScopeKey) -> ScopeSufficiencyRuleV3:
    precision = tuple(IntervalPrecisionRuleV3(metric_id, 0.25, 4, "") for metric_id in MetricId)
    return ScopeSufficiencyRuleV3(key, 4, 8, precision, "")


def _combination_rule() -> CombinationRuleV3:
    components = ("arm-a", "arm-b")
    rows = []
    for outcomes in product(tuple(NeutralOutcome), repeat=len(components)):
        combined = NeutralOutcome.VIOLATION if NeutralOutcome.VIOLATION in outcomes else outcomes[0]
        rows.append(CombinationDecisionRowV3(outcomes, combined, ""))
    return CombinationRuleV3(
        "arm-combined",
        components,
        CombinationOperatorV3.DECLARATIVE_TABLE,
        tuple(rows),
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


def _configuration(
    arm_id: str = "arm-a",
    *,
    kind: ArmKindV3 = ArmKindV3.COMPONENT,
    combination_rule: CombinationRuleV3 | None = None,
) -> ArmConfigurationV3:
    key = _key(arm_id)
    return ArmConfigurationV3(
        arm_id=arm_id,
        kind=kind,
        exact_scopes=(key.scope,),
        denominator_policies=(_policy(key),),
        thresholds=_thresholds(key),
        sufficiency_rules=(_sufficiency(key),),
        judgment_vocabulary_digest=_digest("judgments"),
        analyzer_identity="joern-4.0+ousast-v3",
        fact_set_digest=_digest("facts"),
        configuration_digest=_digest("configuration"),
        registered_budget_digest=_digest("budget"),
        execution_identity="container@sha256:abc",
        outcome_mapping_digest=_digest("outcomes"),
        case_outcome_policy=(
            CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE
            if kind is ArmKindV3.COMBINED
            else CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE
        ),
        combination_rule=combination_rule,
        configuration_identity_digest="",
    )


def test_complete_component_and_combined_configurations_are_canonical() -> None:
    component = _configuration()
    combined = _configuration(
        "arm-combined",
        kind=ArmKindV3.COMBINED,
        combination_rule=_combination_rule(),
    )

    assert component.combination_rule is None
    assert combined.combination_rule is not None
    assert component.configuration_identity_digest == derive_arm_configuration_identity_digest(component)
    assert combined.configuration_identity_digest == derive_arm_configuration_identity_digest(combined)
    assert tuple(rule.metric_id for rule in component.denominator_policies[0].rules) == tuple(MetricId)


def test_every_arm_identity_input_changes_the_configuration_identity() -> None:
    value = _configuration()
    changed_key = _key("arm-a", "injection")
    combined = _configuration("arm-combined", kind=ArmKindV3.COMBINED, combination_rule=_combination_rule())
    assert combined.combination_rule is not None
    changed_rows = list(combined.combination_rule.decision_rows)
    changed_rows[0] = replace(changed_rows[0], combined_outcome=NeutralOutcome.INDETERMINATE, row_digest="")
    changed_rule = replace(combined.combination_rule, decision_rows=tuple(changed_rows), rule_digest="")
    mutations = (
        _configuration("arm-z"),
        replace(
            value,
            exact_scopes=(changed_key.scope,),
            denominator_policies=(_policy(changed_key),),
            thresholds=_thresholds(changed_key),
            sufficiency_rules=(_sufficiency(changed_key),),
            configuration_identity_digest="",
        ),
        replace(value, judgment_vocabulary_digest=_digest("judgments-2"), configuration_identity_digest=""),
        replace(value, analyzer_identity="analyzer-2", configuration_identity_digest=""),
        replace(value, fact_set_digest=_digest("facts-2"), configuration_identity_digest=""),
        replace(value, configuration_digest=_digest("configuration-2"), configuration_identity_digest=""),
        replace(value, registered_budget_digest=_digest("budget-2"), configuration_identity_digest=""),
        replace(value, execution_identity="execution-2", configuration_identity_digest=""),
        replace(value, outcome_mapping_digest=_digest("outcomes-2"), configuration_identity_digest=""),
        combined,
    )
    assert all(item.configuration_identity_digest != value.configuration_identity_digest for item in mutations)
    assert (
        replace(combined, combination_rule=changed_rule, configuration_identity_digest="").configuration_identity_digest
        != combined.configuration_identity_digest
    )


def test_configurations_refuse_cross_key_duplicate_unsorted_and_incomplete_values() -> None:
    value = _configuration()
    other_key = _key("arm-b")
    with pytest.raises(EvaluationMeasurementError, match="arm-scope key"):
        replace(value, thresholds=_thresholds(other_key), configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="canonical exact scopes"):
        replace(value, exact_scopes=(value.exact_scopes[0],) * 2, configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="exactly once"):
        replace(value, thresholds=value.thresholds[:-1], configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="canonical order"):
        replace(value, thresholds=tuple(reversed(value.thresholds)), configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="requires a combination rule"):
        _configuration("arm-combined", kind=ArmKindV3.COMBINED)
    with pytest.raises(EvaluationMeasurementError, match="must not carry"):
        _configuration(combination_rule=_combination_rule())


def test_threshold_sufficiency_and_result_contracts_are_exact() -> None:
    key = _key()
    rule = standard_scoped_metric_rules(key)[1]
    result = ScopedMetricResultV3.from_counts(key, rule.metric_id, numerator=8, denominator=10)
    assert result.sample_count == 10
    assert result.value == 0.8
    assert result.interval_lower is not None and result.interval_upper is not None

    with pytest.raises(EvaluationMeasurementError, match="fixed comparator"):
        replace(_thresholds(key)[0], comparator=Comparator.AT_MOST, threshold_digest="")
    with pytest.raises(EvaluationMeasurementError, match="finite"):
        replace(_thresholds(key)[0], target=float("nan"), threshold_digest="")
    with pytest.raises(EvaluationMeasurementError, match="sample count"):
        replace(result, sample_count=9)
    with pytest.raises(EvaluationMeasurementError, match="Wilson"):
        replace(result, interval_lower=0.0)


def test_aggregate_weights_are_reduced_canonical_and_sum_exactly_to_one() -> None:
    keys = (_key("arm-a"), _key("arm-b"))
    weights = (AggregateWeightV3(keys[0], 1, 3, ""), AggregateWeightV3(keys[1], 2, 3, ""))
    validate_aggregate_weights(keys, (10, 20), weights)

    with pytest.raises(EvaluationMeasurementError, match="reduced"):
        AggregateWeightV3(keys[0], 2, 6, "")
    with pytest.raises(EvaluationMeasurementError, match="sum exactly to one"):
        validate_aggregate_weights(keys, (10, 20), (AggregateWeightV3(keys[0], 1, 3, ""), AggregateWeightV3(keys[1], 1, 3, "")))
    with pytest.raises(EvaluationMeasurementError, match="one-to-one"):
        validate_aggregate_weights(keys, (10, 20), (AggregateWeightV3(keys[0], 1, 2, ""), AggregateWeightV3(keys[0], 1, 2, "")))
    with pytest.raises(EvaluationMeasurementError, match="sample counts"):
        validate_aggregate_weights(keys, (10,), weights)


def test_exact_types_refuse_subclasses_and_unknown_enum_like_values() -> None:
    class DerivedKey(ArmScopeKey):
        pass

    with pytest.raises(EvaluationMeasurementError, match="exact type"):
        DerivedKey("arm-a", ScopeKey("access_control", "python"))
    with pytest.raises(EvaluationMeasurementError, match="closed MetricId"):
        replace(standard_scoped_metric_rules(_key())[0], metric_id="paired_correctness", rule_digest="")  # type: ignore[arg-type]


def test_public_and_lower_configuration_modules_import_in_fresh_processes() -> None:
    for module in (
        "openultrasast.core.evaluation_measurement",
        "openultrasast.core._evaluation_arm_configuration",
    ):
        completed = subprocess.run(
            [sys.executable, "-c", f"import {module}; print({module}.__name__)"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == module


@pytest.mark.parametrize(
    ("field", "malformed"),
    (
        ("denominator_policies", None),
        ("denominator_policies", 1),
        ("denominator_policies", []),
        ("thresholds", None),
        ("thresholds", 1),
        ("thresholds", []),
        ("sufficiency_rules", None),
        ("sufficiency_rules", 1),
        ("sufficiency_rules", []),
    ),
)
def test_configuration_refuses_malformed_containers_with_contract_error(field: str, malformed: object) -> None:
    with pytest.raises(EvaluationMeasurementError):
        replace(_configuration(), **{field: malformed, "configuration_identity_digest": ""})


@pytest.mark.parametrize("sample_count", (True, 1.0))
def test_scoped_result_requires_an_exact_integer_sample_count(sample_count: object) -> None:
    result = ScopedMetricResultV3.from_counts(_key(), MetricId.VULNERABLE_RECALL, numerator=1, denominator=1)
    with pytest.raises(EvaluationMeasurementError, match="sample count"):
        replace(result, sample_count=sample_count)


def test_every_nested_arm_scope_key_is_revalidated() -> None:
    key = _key()
    rules = standard_scoped_metric_rules(key)
    policy = DenominatorPolicyV3(key, rules, IntervalMethod.WILSON_95, "")
    threshold = _thresholds(key)[0]
    sufficiency = _sufficiency(key)
    result = ScopedMetricResultV3.from_counts(key, MetricId.VULNERABLE_RECALL, numerator=1, denominator=1)
    weight = AggregateWeightV3(key, 1, 1, "")
    object.__setattr__(key.scope, "family_id", "")
    validators = (
        lambda: standard_scoped_metric_rules(key),
        rules[0].__post_init__,
        policy.__post_init__,
        threshold.__post_init__,
        sufficiency.__post_init__,
        result.__post_init__,
        weight.__post_init__,
        lambda: validate_aggregate_weights((key,), (1,), (weight,)),
    )
    for validate in validators:
        with pytest.raises(EvaluationMeasurementError, match="family_id"):
            validate()


@pytest.mark.parametrize("metric_id", tuple(MetricId))
@pytest.mark.parametrize("statistic", (Statistic.COUNT, Statistic.WILSON_LOWER, Statistic.WILSON_UPPER))
def test_count_and_wilson_statistics_are_allowed_for_every_metric(metric_id: MetricId, statistic: Statistic) -> None:
    key = _key()
    comparator = (
        Comparator.AT_MOST
        if metric_id
        in {
            MetricId.FIXED_FALSE_ALARM_RATE,
            MetricId.ORDINARY_FALSE_ALARMS_PER_100,
        }
        else Comparator.AT_LEAST
    )
    ScopedThresholdV3(key, metric_id, statistic, comparator, 1.0, "")


@pytest.mark.parametrize("metric_id", tuple(item for item in MetricId if item is not MetricId.ORDINARY_FALSE_ALARMS_PER_100))
def test_rate_is_allowed_only_for_nonordinary_metrics(metric_id: MetricId) -> None:
    key = _key()
    comparator = Comparator.AT_MOST if metric_id is MetricId.FIXED_FALSE_ALARM_RATE else Comparator.AT_LEAST
    ScopedThresholdV3(key, metric_id, Statistic.RATE, comparator, 0.5, "")
    with pytest.raises(EvaluationMeasurementError, match="PER_100"):
        ScopedThresholdV3(key, metric_id, Statistic.PER_100, comparator, 0.5, "")


def test_ordinary_metric_requires_per_100_or_statistic_independent_count_or_interval() -> None:
    key = _key()
    ScopedThresholdV3(
        key,
        MetricId.ORDINARY_FALSE_ALARMS_PER_100,
        Statistic.PER_100,
        Comparator.AT_MOST,
        5.0,
        "",
    )
    with pytest.raises(EvaluationMeasurementError, match="PER_100"):
        ScopedThresholdV3(
            key,
            MetricId.ORDINARY_FALSE_ALARMS_PER_100,
            Statistic.RATE,
            Comparator.AT_MOST,
            0.05,
            "",
        )


def test_policy_threshold_sufficiency_and_precision_mutations_are_independently_bound() -> None:
    value = _configuration()
    changed_threshold = replace(value.thresholds[0], target=0.6, threshold_digest="")
    threshold_configuration = replace(
        value,
        thresholds=(changed_threshold,) + value.thresholds[1:],
        configuration_identity_digest="",
    )
    changed_sufficiency = replace(value.sufficiency_rules[0], minimum_pairs=5, rule_digest="")
    sufficiency_configuration = replace(
        value,
        sufficiency_rules=(changed_sufficiency,),
        configuration_identity_digest="",
    )
    changed_precision = replace(
        value.sufficiency_rules[0].precision_rules[0],
        maximum_wilson_width=0.2,
        rule_digest="",
    )
    precision_sufficiency = replace(
        value.sufficiency_rules[0],
        precision_rules=(changed_precision,) + value.sufficiency_rules[0].precision_rules[1:],
        rule_digest="",
    )
    precision_configuration = replace(
        value,
        sufficiency_rules=(precision_sufficiency,),
        configuration_identity_digest="",
    )

    assert (
        len(
            {
                value.configuration_identity_digest,
                threshold_configuration.configuration_identity_digest,
                sufficiency_configuration.configuration_identity_digest,
                precision_configuration.configuration_identity_digest,
            }
        )
        == 4
    )
    with pytest.raises(EvaluationMeasurementError, match="canonical content"):
        replace(value.denominator_policies[0], policy_digest=_digest("substituted-policy"))


def test_cross_key_policy_sufficiency_and_result_are_refused() -> None:
    key = _key()
    other = _key("arm-b")
    value = _configuration()
    with pytest.raises(EvaluationMeasurementError, match="canonical arm-scope key"):
        replace(value, denominator_policies=(_policy(other),), configuration_identity_digest="")
    with pytest.raises(EvaluationMeasurementError, match="canonical arm-scope key"):
        replace(value, sufficiency_rules=(_sufficiency(other),), configuration_identity_digest="")
    result = ScopedMetricResultV3.from_counts(other, MetricId.VULNERABLE_RECALL, numerator=1, denominator=1)
    with pytest.raises(EvaluationMeasurementError, match="arm-scope key"):
        validate_scoped_metric_result(result, standard_scoped_metric_rules(key)[1])


@pytest.mark.parametrize(
    ("key", "metric_id", "numerator", "denominator"),
    (
        ("not-a-key", MetricId.VULNERABLE_RECALL, 1, 2),
        (_key(), "vulnerable_recall", 1, 2),
        (_key(), None, 1, 2),
        (_key(), MetricId.VULNERABLE_RECALL, "1", 2),
        (_key(), MetricId.VULNERABLE_RECALL, None, 2),
        (_key(), MetricId.VULNERABLE_RECALL, True, 2),
        (_key(), MetricId.VULNERABLE_RECALL, 1.0, 2),
        (_key(), MetricId.VULNERABLE_RECALL, -1, 2),
        (_key(), MetricId.VULNERABLE_RECALL, 1, "2"),
        (_key(), MetricId.VULNERABLE_RECALL, 1, None),
        (_key(), MetricId.VULNERABLE_RECALL, 1, True),
        (_key(), MetricId.VULNERABLE_RECALL, 1, 2.0),
        (_key(), MetricId.VULNERABLE_RECALL, 0, 0),
        (_key(), MetricId.VULNERABLE_RECALL, 0, -1),
        (_key(), MetricId.VULNERABLE_RECALL, 3, 2),
    ),
)
def test_scoped_result_factory_refuses_invalid_inputs_with_contract_error(
    key: object,
    metric_id: object,
    numerator: object,
    denominator: object,
) -> None:
    with pytest.raises(EvaluationMeasurementError):
        ScopedMetricResultV3.from_counts(  # type: ignore[arg-type]
            key,
            metric_id,
            numerator=numerator,
            denominator=denominator,
        )
