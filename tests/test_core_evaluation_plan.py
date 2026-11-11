"""Non-circular label-blind evaluation-plan contracts."""

from __future__ import annotations

from dataclasses import fields, replace
from itertools import product

import pytest

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    CombinationDecisionRowV3,
    CombinationOperatorV3,
    CombinationRuleV3,
    Comparator,
    DenominatorPolicyV3,
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
from openultrasast.core.evaluation_plan import (
    EvaluationPlanDeclarationV3,
    EvaluationPlanError,
    ExpectedObservationSlotV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    derive_evaluation_input_set_digest,
    validate_evaluation_baselines,
)


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _slot_id(arm_id: str, input_digest: str) -> str:
    return canonical.content_digest(
        {
            "schema_version": "openultrasast.detection-core.evaluation-plan-value.v3",
            "kind": "expected_observation_slot_id",
            "payload": {"arm_id": arm_id, "input_identity_digest": input_digest},
        }
    )


def _combination_rule(combined_arm_id: str = "arm-combined", arm_ids: tuple[str, ...] = ("arm-a", "arm-b")) -> CombinationRuleV3:
    rows = tuple(
        CombinationDecisionRowV3(outcomes, NeutralOutcome.VIOLATION if NeutralOutcome.VIOLATION in outcomes else outcomes[0], "")
        for outcomes in product(tuple(NeutralOutcome), repeat=len(arm_ids))
    )
    return CombinationRuleV3(
        combined_arm_id,
        arm_ids,
        CombinationOperatorV3.DECLARATIVE_TABLE,
        rows,
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


def _configuration(arm_id: str, *, combined: bool = False, configuration: str = "configuration") -> ArmConfigurationV3:
    scope = ScopeKey("access_control", "python")
    key = ArmScopeKey(arm_id, scope)
    thresholds = tuple(
        ScopedThresholdV3(
            key,
            metric_id,
            Statistic.PER_100 if metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100 else Statistic.RATE,
            Comparator.AT_MOST
            if metric_id in {MetricId.FIXED_FALSE_ALARM_RATE, MetricId.ORDINARY_FALSE_ALARMS_PER_100}
            else Comparator.AT_LEAST,
            0.5,
            "",
        )
        for metric_id in MetricId
    )
    precision = tuple(IntervalPrecisionRuleV3(metric_id, 0.25, 4, "") for metric_id in MetricId)
    return ArmConfigurationV3(
        arm_id,
        ArmKindV3.COMBINED if combined else ArmKindV3.COMPONENT,
        (scope,),
        (DenominatorPolicyV3(key, standard_scoped_metric_rules(key), IntervalMethod.WILSON_95, ""),),
        thresholds,
        (ScopeSufficiencyRuleV3(key, 4, 8, precision, ""),),
        _digest("judgments"),
        "joern-v3",
        _digest("facts"),
        _digest(configuration),
        _digest("budget"),
        "container@sha256:abc",
        _digest("outcomes"),
        (CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE if combined else CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE),
        _combination_rule() if combined else None,
        "",
    )


def _declaration(*, configurations: tuple[ArmConfigurationV3, ...] | None = None) -> EvaluationPlanDeclarationV3:
    if configurations is None:
        configurations = (_configuration("arm-combined", combined=True), _configuration("arm-b"), _configuration("arm-a"))
    inputs = (_digest("input-b"), _digest("input-a"))
    return create_evaluation_plan_declaration(
        population_digest=_digest("population"),
        freeze_digest=_digest("freeze"),
        input_set_digest=derive_evaluation_input_set_digest(inputs),
        arm_configurations=configurations,
        input_identity_digests=inputs,
    )


def test_constructor_canonicalizes_plan_and_derives_complete_label_blind_slots() -> None:
    declaration = _declaration()
    assert tuple(row.arm_id for row in declaration.arm_configurations) == ("arm-a", "arm-b", "arm-combined")
    assert tuple((row.arm_id, row.input_identity_digest) for row in declaration.expected_observation_slots) == tuple(
        (arm_id, input_digest)
        for arm_id in ("arm-a", "arm-b", "arm-combined")
        for input_digest in sorted((_digest("input-a"), _digest("input-b")))
    )
    slot_fields = {field.name for field in fields(ExpectedObservationSlotV3)}
    assert slot_fields == {"slot_id", "arm_id", "input_identity_digest", "execution_identity", "slot_digest"}
    assert not {"label", "labels", "role", "ground_truth"} & slot_fields


def test_declaration_is_non_circular_and_baselines_are_derived_afterward() -> None:
    declaration = _declaration()
    declaration_fields = {field.name for field in fields(EvaluationPlanDeclarationV3)}
    assert "baselines" not in declaration_fields
    assert "baseline_digests" not in declaration_fields
    baselines = derive_evaluation_baselines(declaration)
    validate_evaluation_baselines(declaration, baselines)
    assert tuple(row.arm_id for row in baselines) == ("arm-a", "arm-b", "arm-combined")
    assert all(row.plan_declaration_digest == declaration.declaration_digest for row in baselines)
    assert not hasattr(declaration, "authorize")
    assert all(not hasattr(row, "authorize") for row in baselines)


def test_every_plan_identity_mutation_changes_declaration_and_affected_baselines() -> None:
    base = _declaration()
    mutations = (
        replace(base, population_digest=_digest("population-2"), declaration_digest=""),
        replace(base, freeze_digest=_digest("freeze-2"), declaration_digest=""),
        _declaration(
            configurations=(
                _configuration("arm-a", configuration="configuration-2"),
                _configuration("arm-b"),
                _configuration("arm-combined", combined=True),
            )
        ),
        create_evaluation_plan_declaration(
            population_digest=_digest("population"),
            freeze_digest=_digest("freeze"),
            input_set_digest=derive_evaluation_input_set_digest((_digest("input-a"), _digest("input-c"))),
            arm_configurations=base.arm_configurations,
            input_identity_digests=(_digest("input-a"), _digest("input-c")),
        ),
    )
    base_baselines = derive_evaluation_baselines(base)
    for changed in mutations:
        assert changed.declaration_digest != base.declaration_digest
        changed_baselines = derive_evaluation_baselines(changed)
        assert tuple(row.baseline_digest for row in changed_baselines) != tuple(row.baseline_digest for row in base_baselines)


def test_combined_arm_cannot_name_an_absent_component() -> None:
    with pytest.raises(EvaluationPlanError, match="absent component"):
        _declaration(configurations=(_configuration("arm-a"), _configuration("arm-combined", combined=True)))


def test_constructor_refuses_duplicate_arm_and_input_identities() -> None:
    component = _configuration("arm-a")
    with pytest.raises(EvaluationPlanError, match="unique arm identities"):
        _declaration(configurations=(component, component))
    with pytest.raises(EvaluationPlanError, match="input identities must be unique"):
        create_evaluation_plan_declaration(
            population_digest=_digest("population"),
            freeze_digest=_digest("freeze"),
            input_set_digest=derive_evaluation_input_set_digest((_digest("input-a"),)),
            arm_configurations=(component,),
            input_identity_digests=(_digest("input-a"), _digest("input-a")),
        )
    for invalid in ((), ("not-a-digest",), (None,)):
        with pytest.raises(EvaluationPlanError):
            derive_evaluation_input_set_digest(invalid)  # type: ignore[arg-type]


def test_input_set_identity_refuses_digest_mismatch_and_whole_column_omission() -> None:
    base = _declaration()
    with pytest.raises(EvaluationPlanError, match="input set digest"):
        replace(base, input_set_digest=_digest("wrong"), declaration_digest="")

    retained = tuple(slot for slot in base.expected_observation_slots if slot.input_identity_digest == _digest("input-a"))
    with pytest.raises(EvaluationPlanError, match="input set digest"):
        replace(base, expected_observation_slots=retained, declaration_digest="")


def test_combined_arm_cannot_use_another_combined_arm_as_a_component() -> None:
    base = _declaration()
    arm_a = base.arm_configurations[0]
    nested_rule = _combination_rule("arm-a", ("arm-b", "arm-combined"))
    nested = replace(
        arm_a,
        kind=ArmKindV3.COMBINED,
        case_outcome_policy=CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        combination_rule=nested_rule,
        configuration_identity_digest="",
    )
    with pytest.raises(EvaluationPlanError, match="component configuration"):
        _declaration(configurations=(nested, base.arm_configurations[1], base.arm_configurations[2]))


def test_direct_contract_refuses_missing_extra_duplicate_unsorted_and_cross_arm_slots() -> None:
    base = _declaration()
    slots = base.expected_observation_slots
    cross_arm = ExpectedObservationSlotV3(
        _slot_id("arm-z", slots[0].input_identity_digest),
        "arm-z",
        slots[0].input_identity_digest,
        slots[0].execution_identity,
        "",
    )
    mutations = (
        slots[:-1],
        slots + (slots[-1],),
        tuple(reversed(slots)),
        (cross_arm,) + slots[1:],
        (replace(slots[0], execution_identity="wrong", slot_digest=""),) + slots[1:],
    )
    for changed_slots in mutations:
        with pytest.raises(EvaluationPlanError):
            replace(base, expected_observation_slots=changed_slots, declaration_digest="")


def test_baseline_validation_refuses_missing_extra_reordered_and_rehashed_rows() -> None:
    declaration = _declaration()
    baselines = derive_evaluation_baselines(declaration)
    for changed in (
        baselines[:-1],
        baselines + (baselines[-1],),
        tuple(reversed(baselines)),
        (replace(baselines[0], arm_configuration_digest=_digest("wrong"), baseline_digest=""),) + baselines[1:],
    ):
        with pytest.raises(EvaluationPlanError):
            validate_evaluation_baselines(declaration, changed)


def test_exact_contracts_reject_subclasses_and_tampered_digests() -> None:
    declaration = _declaration()

    class DerivedDeclaration(EvaluationPlanDeclarationV3):
        pass

    with pytest.raises((EvaluationPlanError, TypeError, ValueError)):
        DerivedDeclaration(*tuple(getattr(declaration, field.name) for field in fields(EvaluationPlanDeclarationV3)))
    with pytest.raises(EvaluationPlanError, match="canonical content"):
        replace(declaration, declaration_digest=_digest("wrong"))
