"""Factories for deterministic arm-combination contract tests."""

from __future__ import annotations

from dataclasses import replace
from itertools import product

from test_valid_benchmark_arm_registry import _configuration, _digest, _registration

from benchmarks.valid import arm_combination as combination
from benchmarks.valid import arm_contract as registry
from openultrasast.core import canonical
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionPolicyV3, CaseOutcomeProjectionV3
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmScopeKey,
    CombinationDecisionRowV3,
    CombinationOperatorV3,
    CombinationRuleV3,
    MetricId,
    NeutralOutcome,
    ProofCandidatePolicyV3,
    ScopeKey,
)
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3
from openultrasast.core.evaluation_plan import derive_evaluation_input_set_digest
from openultrasast.core.evaluation_release import ProofCandidateIdentityV3, derive_proof_candidate_identity_digest


def combined_outcome(kind: combination.CombinationRuleKindV1, outcomes: tuple[NeutralOutcome, ...]) -> NeutralOutcome:
    if kind is combination.CombinationRuleKindV1.UNION:
        if NeutralOutcome.VIOLATION in outcomes:
            return NeutralOutcome.VIOLATION
        if NeutralOutcome.INDETERMINATE in outcomes:
            return NeutralOutcome.INDETERMINATE
        return NeutralOutcome.SATISFIED
    if all(item is NeutralOutcome.VIOLATION for item in outcomes):
        return NeutralOutcome.VIOLATION
    if NeutralOutcome.SATISFIED in outcomes:
        return NeutralOutcome.SATISFIED
    return NeutralOutcome.INDETERMINATE


def rule(kind: combination.CombinationRuleKindV1) -> CombinationRuleV3:
    arm_ids = ("arm-experimental", "arm-shipped")
    rows = tuple(
        CombinationDecisionRowV3(outcomes, combined_outcome(kind, outcomes), "") for outcomes in product(tuple(NeutralOutcome), repeat=2)
    )
    return CombinationRuleV3(
        "arm-combined",
        arm_ids,
        CombinationOperatorV3.DECLARATIVE_TABLE,
        rows,
        ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY,
        "",
    )


def configuration_with_scopes(
    arm_id: str,
    scopes: tuple[ScopeKey, ...],
    *,
    configuration: str = "configuration",
) -> ArmConfigurationV3:
    base = _configuration(arm_id, configuration=configuration)
    scopes = tuple(sorted(scopes))
    keys = tuple(ArmScopeKey(arm_id, scope) for scope in scopes)
    policy = base.denominator_policies[0]
    sufficiency = base.sufficiency_rules[0]
    threshold_templates = {row.metric_id: row for row in base.thresholds}
    policies = tuple(
        replace(
            policy,
            key=key,
            rules=tuple(replace(metric_rule, key=key, rule_digest="") for metric_rule in policy.rules),
            policy_digest="",
        )
        for key in keys
    )
    thresholds = tuple(replace(threshold_templates[metric], key=key, threshold_digest="") for key in keys for metric in MetricId)
    sufficiency_rules = tuple(replace(sufficiency, key=key, rule_digest="") for key in keys)
    return replace(
        base,
        exact_scopes=scopes,
        denominator_policies=policies,
        thresholds=thresholds,
        sufficiency_rules=sufficiency_rules,
        configuration_identity_digest="",
    )


def plan(
    kind: combination.CombinationRuleKindV1 = combination.CombinationRuleKindV1.UNION,
    *,
    experimental_scopes: tuple[ScopeKey, ...] = (ScopeKey("injection", "python"),),
    shipped_scopes: tuple[ScopeKey, ...] = (ScopeKey("injection", "python"),),
    shipped_configuration: str = "configuration",
) -> registry.RegisteredEvaluationPlanV1:
    combined = replace(
        _configuration("arm-combined", combined=True),
        combination_rule=rule(kind),
        configuration_identity_digest="",
    )
    registrations = (
        _registration(registry.ArmRole.COMBINED, combined),
        _registration(
            registry.ArmRole.EXPERIMENTAL,
            configuration_with_scopes("arm-experimental", experimental_scopes),
        ),
        _registration(
            registry.ArmRole.SHIPPED,
            configuration_with_scopes("arm-shipped", shipped_scopes, configuration=shipped_configuration),
        ),
    )
    inputs = (_digest("input-a"),)
    return registry.register_evaluation_plan(
        registrations=registrations,
        population_digest=_digest("population"),
        freeze_digest=_digest("freeze"),
        input_set_digest=derive_evaluation_input_set_digest(inputs),
        input_identity_digests=inputs,
    )


def registered(
    kind: combination.CombinationRuleKindV1 = combination.CombinationRuleKindV1.UNION,
    *,
    experimental_scopes: tuple[ScopeKey, ...] = (ScopeKey("injection", "python"),),
    shipped_scopes: tuple[ScopeKey, ...] = (ScopeKey("injection", "python"),),
    shipped_configuration: str = "configuration",
) -> combination.RegisteredCombinationPlanV1:
    registered_plan = plan(
        kind,
        experimental_scopes=experimental_scopes,
        shipped_scopes=shipped_scopes,
        shipped_configuration=shipped_configuration,
    )
    registration = combination.CombinationRuleRegistrationV1("arm-combined", kind, rule(kind).rule_digest, "")
    return combination.register_combination_plan(registered_plan, (registration,))


def unchecked_registered(registered_plan: registry.RegisteredEvaluationPlanV1) -> combination.RegisteredCombinationPlanV1:
    registration = combination.CombinationRuleRegistrationV1(
        "arm-combined",
        combination.CombinationRuleKindV1.UNION,
        rule(combination.CombinationRuleKindV1.UNION).rule_digest,
        "",
    )
    value = object.__new__(combination.RegisteredCombinationPlanV1)
    object.__setattr__(value, "plan", registered_plan)
    object.__setattr__(value, "rule_registrations", (registration,))
    object.__setattr__(value, "combination_plan_digest", "")
    return value


def _content_ref(label: str) -> canonical.ContentRef:
    content = label.encode()
    return canonical.ContentRef(
        f"proof-{label}",
        canonical.bytes_digest(content),
        "application/json",
        len(content),
        _digest("proof-retention"),
        _digest(f"proof-receipt-{label}"),
    )


def _projection(case_input: str, outcome: NeutralOutcome, arm_id: str) -> CaseOutcomeProjectionV3:
    return CaseOutcomeProjectionV3(
        case_input,
        CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        (_digest(f"source-{arm_id}-{case_input}"),),
        outcome,
        "",
    )


def _candidate(
    arm_id: str,
    observation_digest: str,
    scope: ScopeKey,
    *,
    family: str,
    change: str,
    location: str,
) -> ProofCandidateIdentityV3:
    draft = ProofCandidateIdentityV3(
        arm_id,
        observation_digest,
        family,
        scope,
        _digest(location),
        _digest(change),
        "0" * 64,
    )
    return replace(draft, candidate_digest=derive_proof_candidate_identity_digest(draft))


def _observation_shell(
    registered_plan: combination.RegisteredCombinationPlanV1,
    arm_id: str,
) -> tuple[ArmConfigurationV3, ArmObservationSetV3]:
    plan_value = registered_plan.plan
    configuration = next(row.configuration for row in plan_value.registrations if row.arm_id == arm_id)
    slot = next(row for row in plan_value.declaration.expected_observation_slots if row.arm_id == arm_id)
    observation = ArmObservationSetV3(
        slot.slot_digest,
        arm_id,
        slot.input_identity_digest,
        configuration.execution_identity,
        configuration.registered_budget_digest,
        configuration.configuration_identity_digest,
        _digest(f"read-{arm_id}"),
        _digest(f"stage-{arm_id}"),
        (),
        "",
    )
    return configuration, observation


def _bind_proof(
    candidate: ProofCandidateIdentityV3,
    observation: ArmObservationSetV3,
    case: ObservationCaseRefV3,
    packet: str,
    proof_ref: str,
) -> tuple[ArmObservationSetV3, tuple[combination.ProofContinuityAnchorV1, ...]]:
    candidate = replace(candidate, observation_digest=observation.observation_digest)
    anchor = combination.ProofContinuityAnchorV1(candidate, _digest(packet), _content_ref(proof_ref), "")
    case = replace(case, proof_candidate_digest=candidate.candidate_digest)
    observation = replace(observation, cases=(case,), observation_digest="")
    candidate = replace(candidate, observation_digest=observation.observation_digest)
    return observation, (replace(anchor, candidate=candidate, anchor_digest=""),)


def component(
    registered_plan: combination.RegisteredCombinationPlanV1,
    arm_id: str,
    outcome: NeutralOutcome,
    *,
    proof: bool = False,
    family: str = "injection",
    ecosystem: str = "python",
    change: str = "change",
    packet: str = "packet",
    location: str = "location",
    proof_ref: str = "shared",
    case_input: str | None = None,
    push: str = "push",
) -> combination.ComponentObservationV1:
    configuration, provisional = _observation_shell(registered_plan, arm_id)
    case_input = _digest("case-input") if case_input is None else case_input
    candidate_scope = next(
        (scope for scope in configuration.exact_scopes if (scope.family_id, scope.ecosystem) == (family, ecosystem)),
        configuration.exact_scopes[0],
    )
    candidate = (
        _candidate(
            arm_id,
            provisional.observation_digest,
            candidate_scope,
            family=family,
            change=change,
            location=location,
        )
        if proof
        else None
    )
    case = ObservationCaseRefV3(
        _digest(f"case-{arm_id}"),
        case_input,
        _digest(push),
        _digest(f"result-{arm_id}-{outcome.value}"),
        _projection(case_input, outcome, arm_id),
        None if candidate is None else candidate.candidate_digest,
    )
    observation = replace(provisional, cases=(case,), observation_digest="")
    anchors: tuple[combination.ProofContinuityAnchorV1, ...] = ()
    if candidate is not None:
        observation, anchors = _bind_proof(candidate, observation, case, packet, proof_ref)
    return combination.ComponentObservationV1(observation, anchors, "")


def components(
    registered_plan: combination.RegisteredCombinationPlanV1,
    outcomes: tuple[NeutralOutcome, NeutralOutcome] = (NeutralOutcome.SATISFIED, NeutralOutcome.VIOLATION),
    *,
    proof: bool = False,
) -> tuple[combination.ComponentObservationV1, ...]:
    return (
        component(registered_plan, "arm-experimental", outcomes[0], proof=proof),
        component(registered_plan, "arm-shipped", outcomes[1], proof=proof),
    )
