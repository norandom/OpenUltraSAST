"""Component and combined-arm configuration contracts for evaluation V3."""

from __future__ import annotations

from dataclasses import replace
from itertools import product

import pytest

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
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
    ScopedThresholdV3,
    ScopeKey,
    ScopeSufficiencyRuleV3,
    Statistic,
    standard_scoped_metric_rules,
)


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _rule(
    component_arm_ids: tuple[str, ...] = ("arm-a", "arm-b"),
    *,
    combined_arm_id: str = "arm-combined",
) -> CombinationRuleV3:
    rows = (
        tuple(
            CombinationDecisionRowV3(
                outcomes,
                NeutralOutcome.VIOLATION if NeutralOutcome.VIOLATION in outcomes else outcomes[0],
                "",
            )
            for outcomes in product(tuple(NeutralOutcome), repeat=len(component_arm_ids))
        )
        if component_arm_ids
        else ()
    )
    return CombinationRuleV3(
        combined_arm_id,
        component_arm_ids,
        CombinationOperatorV3.DECLARATIVE_TABLE,
        rows,
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


def _configuration(
    *,
    scope: ScopeKey | None = None,
    threshold_target: float = 0.5,
    minimum_pairs: int = 4,
    outcome_mapping: str = "outcomes",
    combination_rule: CombinationRuleV3 | None = None,
) -> ArmConfigurationV3:
    if scope is None:
        scope = ScopeKey("access_control", "python")
    arm_id = "arm-combined"
    key = ArmScopeKey(arm_id, scope)
    thresholds = tuple(
        ScopedThresholdV3(
            key,
            metric_id,
            (Statistic.PER_100 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else Statistic.RATE),
            (
                Comparator.AT_MOST
                if metric_id
                in {
                    MetricId.FIXED_FALSE_ALARM_RATE,
                    MetricId.ORDINARY_FALSE_ALARMS_PER_100,
                }
                else Comparator.AT_LEAST
            ),
            threshold_target,
            "",
        )
        for metric_id in MetricId
    )
    precision = tuple(IntervalPrecisionRuleV3(metric_id, 0.25, 4, "") for metric_id in MetricId)
    return ArmConfigurationV3(
        arm_id=arm_id,
        kind=ArmKindV3.COMBINED,
        exact_scopes=(scope,),
        denominator_policies=(DenominatorPolicyV3(key, standard_scoped_metric_rules(key), IntervalMethod.WILSON_95, ""),),
        thresholds=thresholds,
        sufficiency_rules=(ScopeSufficiencyRuleV3(key, minimum_pairs, 8, precision, ""),),
        judgment_vocabulary_digest=_digest("judgments"),
        analyzer_identity="joern-4.0+ousast-v3",
        fact_set_digest=_digest("facts"),
        configuration_digest=_digest("configuration"),
        registered_budget_digest=_digest("budget"),
        execution_identity="container@sha256:abc",
        outcome_mapping_digest=_digest(outcome_mapping),
        combination_rule=_rule() if combination_rule is None else combination_rule,
        configuration_identity_digest="",
    )


def test_combined_arm_requires_at_least_two_component_identities() -> None:
    with pytest.raises(EvaluationMeasurementError, match="at least two"):
        _rule(("arm-a",))


@pytest.mark.parametrize(
    "component_arm_ids",
    (
        (),
        ("arm-a", "arm-a"),
        ("arm-b", "arm-a"),
        ("arm-a", "arm-combined"),
    ),
)
def test_combined_arm_refuses_missing_duplicate_noncanonical_or_self_components(
    component_arm_ids: tuple[str, ...],
) -> None:
    with pytest.raises(EvaluationMeasurementError, match="component arm ids"):
        _rule(component_arm_ids)


def test_combination_rule_requires_the_complete_normalized_decision_table() -> None:
    rule = _rule()
    first, second = rule.decision_rows[:2]
    mutations = (
        rule.decision_rows[:-1],
        (first, first) + rule.decision_rows[2:],
        (second, first) + rule.decision_rows[2:],
        (replace(first, component_outcomes=(NeutralOutcome.VIOLATION,), row_digest=""),) + rule.decision_rows[1:],
    )
    for rows in mutations:
        with pytest.raises(EvaluationMeasurementError, match="canonical|every component outcome"):
            replace(rule, decision_rows=rows, rule_digest="")


def test_combination_rule_refuses_executable_or_nonclosed_behavior() -> None:
    rule = _rule()
    for field, value in (
        ("operator", lambda outcomes: outcomes[0]),
        ("candidate_policy", "identical_component_only"),
        ("decision_rows", lambda outcomes: outcomes[0]),
    ):
        with pytest.raises(EvaluationMeasurementError):
            replace(rule, **{field: value, "rule_digest": ""})


def test_each_combined_configuration_input_changes_its_identity() -> None:
    base = _configuration()
    base_rule = base.combination_rule
    assert base_rule is not None

    changed_components = _configuration(combination_rule=_rule(("arm-a", "arm-c")))
    changed_rows = list(base_rule.decision_rows)
    changed_rows[0] = replace(
        changed_rows[0],
        combined_outcome=NeutralOutcome.INDETERMINATE,
        row_digest="",
    )
    changed_rule_row = _configuration(
        combination_rule=replace(base_rule, decision_rows=tuple(changed_rows), rule_digest=""),
    )
    changed_scope_and_policy = _configuration(scope=ScopeKey("injection", "python"))
    changed_threshold = _configuration(threshold_target=0.6)
    changed_sufficiency = _configuration(minimum_pairs=5)
    changed_outcome_mapping = _configuration(outcome_mapping="outcomes-v2")

    identities = {
        item.configuration_identity_digest
        for item in (
            base,
            changed_components,
            changed_rule_row,
            changed_scope_and_policy,
            changed_threshold,
            changed_sufficiency,
            changed_outcome_mapping,
        )
    }
    assert len(identities) == 7


def test_identical_component_candidate_policy_is_the_only_proof_retention_policy() -> None:
    rule = _rule()
    assert rule.candidate_policy is ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY
    with pytest.raises(EvaluationMeasurementError, match="closed operator and candidate policy"):
        replace(rule, candidate_policy=object(), rule_digest="")
