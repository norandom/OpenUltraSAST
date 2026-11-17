"""Pure label-blind combination of complete component observation sets."""

from __future__ import annotations

from benchmarks.valid.arm_combination_contract import (
    CombinationPlannerError,
    CombinationRuleKindV1,
    CombinationRuleRegistrationV1,
    CombinedObservationV1,
    ComponentObservationV1,
    ProofContinuityAnchorV1,
    RegisteredCombinationPlanV1,
    combined_value,
)
from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1, validate_registered_evaluation_plan
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionPolicyV3, CaseOutcomeProjectionV3
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmKindV3,
    CombinationDecisionRowV3,
    CombinationRuleV3,
    NeutralOutcome,
)
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3
from openultrasast.core.factpack import ReviewIndependencePolicy


def register_combination_plan(
    plan: RegisteredEvaluationPlanV1,
    registrations: tuple[CombinationRuleRegistrationV1, ...],
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> RegisteredCombinationPlanV1:
    """Pre-register the closed meaning of every core combined-arm table."""
    validate_registered_evaluation_plan(
        plan,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    if type(registrations) is not tuple:
        raise CombinationPlannerError("rule registrations must be an exact tuple")
    ordered = tuple(sorted(registrations, key=lambda item: item.combined_arm_id))
    return RegisteredCombinationPlanV1(plan, ordered, "")


def _configuration(plan: RegisteredEvaluationPlanV1, arm_id: str) -> ArmConfigurationV3:
    matches = tuple(item for item in plan.declaration.arm_configurations if item.arm_id == arm_id)
    if len(matches) != 1:
        raise CombinationPlannerError("arm is absent or ambiguous in the registered plan")
    return matches[0]


def _validate_component(plan: RegisteredEvaluationPlanV1, component: ComponentObservationV1) -> None:
    component.__post_init__()
    observation = component.observation
    configuration = _configuration(plan, observation.arm_id)
    if configuration.kind is not ArmKindV3.COMPONENT:
        raise CombinationPlannerError("combined arms cannot be supplied as component observations")
    if (
        observation.configuration_digest != configuration.configuration_identity_digest
        or observation.registered_budget_digest != configuration.registered_budget_digest
        or observation.execution_identity != configuration.execution_identity
    ):
        raise CombinationPlannerError("component observation differs from its registered configuration")
    slots = tuple(
        item
        for item in plan.declaration.expected_observation_slots
        if item.arm_id == observation.arm_id and item.input_identity_digest == observation.input_identity_digest
    )
    if len(slots) != 1 or observation.slot_digest != slots[0].slot_digest:
        raise CombinationPlannerError("component observation differs from its exact planned slot")
    for anchor in component.proof_anchors:
        candidate = anchor.candidate
        if candidate.scope not in configuration.exact_scopes or candidate.family_id != candidate.scope.family_id:
            raise CombinationPlannerError("proof anchor family or scope differs from its component arm")


def _component_map(component: ComponentObservationV1) -> dict[tuple[str, str], ObservationCaseRefV3]:
    result = {(case.case_input_digest, case.underlying_push_digest): case for case in component.observation.cases}
    if not result or len(result) != len(component.observation.cases):
        raise CombinationPlannerError("component cases must be nonempty and unique by input and push")
    return result


def _decision(rule: CombinationRuleV3, outcomes: tuple[NeutralOutcome, ...]) -> CombinationDecisionRowV3:
    matches = tuple(row for row in rule.decision_rows if row.component_outcomes == outcomes)
    if len(matches) != 1:
        raise CombinationPlannerError("registered decision row is absent or ambiguous")
    return matches[0]


def _anchor_for_case(component: ComponentObservationV1, case: ObservationCaseRefV3) -> ProofContinuityAnchorV1 | None:
    if case.proof_candidate_digest is None:
        return None
    matches = tuple(anchor for anchor in component.proof_anchors if anchor.candidate.candidate_digest == case.proof_candidate_digest)
    if len(matches) > 1:
        raise CombinationPlannerError("component case has ambiguous proof continuity")
    return None if not matches else matches[0]


def _continuity_key(anchor: ProofContinuityAnchorV1) -> tuple[object, ...]:
    candidate = anchor.candidate
    return (
        candidate.family_id,
        candidate.scope,
        candidate.change_input_digest,
        anchor.packet_digest,
        candidate.finding_location_digest,
        anchor.proof_reference,
    )


def _retained_anchor(
    configuration: ArmConfigurationV3,
    components: tuple[ComponentObservationV1, ...],
    cases: tuple[ObservationCaseRefV3, ...],
) -> ProofContinuityAnchorV1 | None:
    anchors = tuple(anchor for component, case in zip(components, cases, strict=True) if (anchor := _anchor_for_case(component, case)))
    if len(anchors) != len(cases) or len({_continuity_key(anchor) for anchor in anchors}) != 1:
        return None
    retained = min(anchors, key=lambda item: (item.candidate.component_arm_id, item.anchor_digest))
    candidate = retained.candidate
    if candidate.scope not in configuration.exact_scopes or candidate.family_id != candidate.scope.family_id:
        return None
    return retained


def _case_sort(case: ObservationCaseRefV3) -> tuple[str, ...]:
    return (
        case.case_id_digest,
        case.case_input_digest,
        case.underlying_push_digest,
        case.result_digest,
        case.outcome_projection.projection_digest,
        case.proof_candidate_digest or "",
    )


def _combined_case(
    configuration: ArmConfigurationV3,
    components: tuple[ComponentObservationV1, ...],
    key: tuple[str, str],
    cases: tuple[ObservationCaseRefV3, ...],
) -> tuple[ObservationCaseRefV3, ProofContinuityAnchorV1 | None]:
    rule = configuration.combination_rule
    if type(rule) is not CombinationRuleV3:
        raise CombinationPlannerError("combined configuration has no exact core rule")
    outcomes = tuple(item.outcome_projection.normalized_outcome for item in cases)
    decision = _decision(rule, outcomes)
    projection = CaseOutcomeProjectionV3(
        key[0],
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        tuple(item.outcome_projection.projection_digest for item in cases),
        decision.combined_outcome,
        "",
    )
    anchor = _retained_anchor(configuration, components, cases)
    identity: dict[str, JsonValue] = {
        "combined_arm_id": configuration.arm_id,
        "case_input_digest": key[0],
        "underlying_push_digest": key[1],
        "component_case_ids": tuple(item.case_id_digest for item in cases),
    }
    result: JsonValue = {
        **identity,
        "component_result_digests": tuple(item.result_digest for item in cases),
        "outcome_projection_digest": projection.projection_digest,
        "retained_anchor_digest": None if anchor is None else anchor.anchor_digest,
    }
    combined = ObservationCaseRefV3(
        canonical.content_digest(identity),
        key[0],
        key[1],
        canonical.content_digest(result),
        projection,
        None if anchor is None else anchor.candidate.candidate_digest,
    )
    return combined, anchor


def _derive_cases(
    configuration: ArmConfigurationV3,
    components: tuple[ComponentObservationV1, ...],
) -> tuple[tuple[ObservationCaseRefV3, ...], tuple[ProofContinuityAnchorV1, ...]]:
    maps = tuple(_component_map(item) for item in components)
    keys = set(maps[0])
    if any(set(item) != keys for item in maps[1:]):
        raise CombinationPlannerError("component case sets are incomplete or mismatched")
    derived = tuple(_combined_case(configuration, components, key, tuple(item[key] for item in maps)) for key in sorted(keys))
    cases = tuple(sorted((item[0] for item in derived), key=_case_sort))
    anchors = tuple(sorted((item[1] for item in derived if item[1] is not None), key=lambda item: item.anchor_digest))
    return cases, anchors


def _derive_combined_observation(
    registered: RegisteredCombinationPlanV1,
    rule_registration: CombinationRuleRegistrationV1,
    components: tuple[ComponentObservationV1, ...],
) -> ArmObservationSetV3:
    configuration = _configuration(registered.plan, rule_registration.combined_arm_id)
    input_identity = components[0].observation.input_identity_digest
    slots = tuple(
        item
        for item in registered.plan.declaration.expected_observation_slots
        if item.arm_id == configuration.arm_id and item.input_identity_digest == input_identity
    )
    if len(slots) != 1:
        raise CombinationPlannerError("combined observation has no exact planned slot")
    cases, _ = _derive_cases(configuration, components)
    return ArmObservationSetV3(
        slots[0].slot_digest,
        configuration.arm_id,
        input_identity,
        configuration.execution_identity,
        configuration.registered_budget_digest,
        configuration.configuration_identity_digest,
        canonical.content_digest(tuple(item.observation.input_read_evidence_digest for item in components)),
        canonical.content_digest(tuple(item.observation.stage_execution_evidence_digest for item in components)),
        cases,
        "",
    )


def _derive_combination(
    registered: RegisteredCombinationPlanV1,
    combined_arm_id: str,
    components: tuple[ComponentObservationV1, ...],
) -> CombinedObservationV1:
    registrations = tuple(item for item in registered.rule_registrations if item.combined_arm_id == combined_arm_id)
    if len(registrations) != 1:
        raise CombinationPlannerError("combined arm has no unique registered rule")
    rule_registration = registrations[0]
    configuration = _configuration(registered.plan, combined_arm_id)
    rule = configuration.combination_rule
    if type(rule) is not CombinationRuleV3:
        raise CombinationPlannerError("combined arm has no exact core rule")
    if type(components) is not tuple or any(type(item) is not ComponentObservationV1 for item in components):
        raise CombinationPlannerError("components must use an exact tuple")
    ordered = tuple(sorted(components, key=lambda item: item.observation.arm_id))
    if tuple(item.observation.arm_id for item in ordered) != rule.component_arm_ids:
        raise CombinationPlannerError("component observations must cover every and only registered component")
    for item in ordered:
        _validate_component(registered.plan, item)
    if len({item.observation.input_identity_digest for item in ordered}) != 1:
        raise CombinationPlannerError("component observations belong to different planned inputs")
    combined = _derive_combined_observation(registered, rule_registration, ordered)
    cases, retained = _derive_cases(configuration, ordered)
    if combined.cases != cases:
        raise CombinationPlannerError("combined observation cases cannot be re-derived")
    return CombinedObservationV1(registered, rule_registration, ordered, combined, retained, "")


def combine_observations(
    registered: RegisteredCombinationPlanV1,
    combined_arm_id: str,
    components: tuple[ComponentObservationV1, ...],
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> CombinedObservationV1:
    """Purely derive one combined observation without invoking any arm."""
    if type(registered) is not RegisteredCombinationPlanV1:
        raise CombinationPlannerError("registered combination plan must use the exact contract")
    registered.__post_init__()
    validate_registered_evaluation_plan(
        registered.plan,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    return _derive_combination(registered, combined_arm_id, components)


def validate_combined_observation(
    value: CombinedObservationV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> None:
    if type(value) is not CombinedObservationV1:
        raise CombinationPlannerError("combined observation must use the exact contract")
    value.__post_init__()
    expected = combine_observations(
        value.registered_plan,
        value.rule_registration.combined_arm_id,
        value.component_observations,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    if value != expected:
        raise CombinationPlannerError("combined observation differs from deterministic re-derivation")


def combined_observation_bytes(
    value: CombinedObservationV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> bytes:
    validate_combined_observation(
        value,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    return canonical.canonical_bytes(combined_value(value, include_digest=True))


__all__ = [
    "CombinedObservationV1",
    "CombinationPlannerError",
    "CombinationRuleKindV1",
    "CombinationRuleRegistrationV1",
    "ComponentObservationV1",
    "ProofContinuityAnchorV1",
    "RegisteredCombinationPlanV1",
    "combine_observations",
    "combined_observation_bytes",
    "register_combination_plan",
    "validate_combined_observation",
]
