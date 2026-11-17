"""Task 6.2 deterministic label-blind arm-combination tests."""

from __future__ import annotations

import sys
from dataclasses import fields, replace
from itertools import product
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from arm_combination_fixtures import (  # noqa: E402
    combined_outcome as _combined_outcome,
)
from arm_combination_fixtures import (
    component as _component,
)
from arm_combination_fixtures import (
    components as _components,
)
from arm_combination_fixtures import (
    plan as _plan,
)
from arm_combination_fixtures import (
    registered as _registered,
)
from arm_combination_fixtures import (
    rule as _rule,
)
from arm_combination_fixtures import (
    unchecked_registered as _unchecked_registered,
)
from test_valid_benchmark_arm_registry import _digest  # noqa: E402

from benchmarks.valid import arm_combination as combination
from openultrasast.core.evaluation_measurement import NeutralOutcome, ScopeKey


@pytest.mark.parametrize("kind", tuple(combination.CombinationRuleKindV1))
@pytest.mark.parametrize("outcomes", tuple(product(tuple(NeutralOutcome), repeat=2)))
def test_closed_rules_replay_every_outcome_deterministically(kind, outcomes) -> None:
    registered = _registered(kind)
    result = combination.combine_observations(registered, "arm-combined", _components(registered, outcomes))
    assert result.combined_observation.cases[0].outcome_projection.normalized_outcome is _combined_outcome(kind, outcomes)
    assert result.rule_registration.kind is kind


def test_component_order_is_normalized_and_every_result_is_preserved() -> None:
    registered = _registered()
    components = _components(registered)
    result = combination.combine_observations(registered, "arm-combined", tuple(reversed(components)))
    assert result.component_observations == components
    assert tuple(item.observation.observation_digest for item in result.component_observations) == tuple(
        item.observation.observation_digest for item in components
    )
    assert result.combined_observation.arm_id == "arm-combined"
    assert result.combined_observation not in tuple(item.observation for item in components)


@pytest.mark.parametrize(
    "mutation",
    ("missing", "duplicate", "extra", "cross_plan", "cross_observation_input", "cross_case_input", "cross_push"),
)
def test_missing_extra_duplicate_or_mismatched_components_are_refused(mutation: str) -> None:
    registered = _registered()
    components = _components(registered)
    if mutation == "missing":
        changed = components[:1]
    elif mutation == "duplicate":
        changed = (components[0], components[0], components[1])
    elif mutation == "extra":
        extra = replace(components[0].observation, arm_id="arm-extra", observation_digest="")
        changed = components + (combination.ComponentObservationV1(extra, (), ""),)
    elif mutation == "cross_plan":
        other = _registered(shipped_configuration="other-configuration")
        changed = (components[0], _component(other, "arm-shipped", NeutralOutcome.VIOLATION))
    elif mutation == "cross_observation_input":
        observation = replace(components[1].observation, input_identity_digest=_digest("other-input"), observation_digest="")
        changed = (components[0], combination.ComponentObservationV1(observation, (), ""))
    elif mutation == "cross_case_input":
        changed = (components[0], _component(registered, "arm-shipped", NeutralOutcome.VIOLATION, case_input=_digest("other")))
    else:
        changed = (components[0], _component(registered, "arm-shipped", NeutralOutcome.VIOLATION, push="other"))
    with pytest.raises(combination.CombinationPlannerError):
        combination.combine_observations(registered, "arm-combined", changed)


def test_unregistered_or_semantically_changed_rules_are_refused() -> None:
    plan = _plan(combination.CombinationRuleKindV1.UNION)
    wrong_kind = combination.CombinationRuleRegistrationV1(
        "arm-combined",
        combination.CombinationRuleKindV1.INTERSECTION,
        next(row.configuration.combination_rule for row in plan.registrations if row.arm_id == "arm-combined").rule_digest,
        "",
    )
    with pytest.raises(combination.CombinationPlannerError):
        combination.register_combination_plan(plan, (wrong_kind,))
    with pytest.raises(combination.CombinationPlannerError):
        combination.register_combination_plan(plan, ())


@pytest.mark.parametrize("missing_scope", (ScopeKey("other-family", "python"), ScopeKey("injection", "javascript")))
def test_registration_rejects_component_missing_combined_family_or_ecosystem(missing_scope: ScopeKey) -> None:
    plan = _plan(shipped_scopes=(missing_scope,))
    registration = combination.CombinationRuleRegistrationV1(
        "arm-combined", combination.CombinationRuleKindV1.UNION, _rule(combination.CombinationRuleKindV1.UNION).rule_digest, ""
    )
    with pytest.raises(combination.CombinationPlannerError):
        combination.register_combination_plan(plan, (registration,))


@pytest.mark.parametrize("missing_scope", (ScopeKey("other-family", "python"), ScopeKey("injection", "javascript")))
@pytest.mark.parametrize("proof", (False, True))
def test_constructor_bypass_cannot_combine_scope_incompatible_components(missing_scope: ScopeKey, proof: bool) -> None:
    registered = _unchecked_registered(_plan(shipped_scopes=(missing_scope,)))
    components = (
        _component(registered, "arm-experimental", NeutralOutcome.VIOLATION, proof=proof),
        _component(
            registered,
            "arm-shipped",
            NeutralOutcome.VIOLATION,
            proof=proof,
            family=missing_scope.family_id,
            ecosystem=missing_scope.ecosystem,
        ),
    )
    with pytest.raises(combination.CombinationPlannerError):
        combination.combine_observations(registered, "arm-combined", components)


def test_scope_configuration_is_bound_into_plan_identity() -> None:
    base = _registered()
    expanded = _registered(shipped_scopes=(ScopeKey("injection", "python"), ScopeKey("other-family", "python")))
    assert base.plan.plan_digest != expanded.plan.plan_digest
    assert base.combination_plan_digest != expanded.combination_plan_digest


def test_serializer_revalidates_scope_compatibility_after_constructor_bypass() -> None:
    registered = _registered()
    valid = combination.combine_observations(registered, "arm-combined", _components(registered))
    invalid_plan = _unchecked_registered(_plan(shipped_scopes=(ScopeKey("other-family", "python"),)))
    forged = object.__new__(combination.CombinedObservationV1)
    for field in fields(combination.CombinedObservationV1):
        value = invalid_plan if field.name == "registered_plan" else getattr(valid, field.name)
        object.__setattr__(forged, field.name, value)
    with pytest.raises(combination.CombinationPlannerError):
        combination.combined_observation_bytes(forged)


def test_exact_component_proof_continuity_is_retained_without_manufacture() -> None:
    registered = _registered()
    components = _components(registered, proof=True)
    result = combination.combine_observations(registered, "arm-combined", components)
    assert len(result.retained_proof_anchors) == 1
    retained = result.retained_proof_anchors[0]
    assert retained in tuple(anchor for component in components for anchor in component.proof_anchors)
    assert result.combined_observation.cases[0].proof_candidate_digest == retained.candidate.candidate_digest


@pytest.mark.parametrize("extra_scope", (ScopeKey("other-family", "python"), ScopeKey("injection", "javascript")))
def test_matching_component_only_scope_proof_is_not_retained(extra_scope: ScopeKey) -> None:
    scopes = tuple(sorted((ScopeKey("injection", "python"), extra_scope)))
    registered = _registered(experimental_scopes=scopes, shipped_scopes=scopes)
    components = (
        _component(
            registered,
            "arm-experimental",
            NeutralOutcome.VIOLATION,
            proof=True,
            family=extra_scope.family_id,
            ecosystem=extra_scope.ecosystem,
        ),
        _component(
            registered,
            "arm-shipped",
            NeutralOutcome.VIOLATION,
            proof=True,
            family=extra_scope.family_id,
            ecosystem=extra_scope.ecosystem,
        ),
    )

    result = combination.combine_observations(registered, "arm-combined", components)

    assert result.component_observations == components
    assert result.retained_proof_anchors == ()
    assert result.combined_observation.cases[0].proof_candidate_digest is None


@pytest.mark.parametrize("operation", (combination.validate_combined_observation, combination.combined_observation_bytes))
def test_forged_unrelated_retained_anchor_is_rejected_by_rederivation(operation) -> None:
    extra_scope = ScopeKey("other-family", "python")
    scopes = tuple(sorted((ScopeKey("injection", "python"), extra_scope)))
    registered = _registered(experimental_scopes=scopes, shipped_scopes=scopes)
    components = (
        _component(registered, "arm-experimental", NeutralOutcome.VIOLATION, proof=True, family=extra_scope.family_id),
        _component(registered, "arm-shipped", NeutralOutcome.VIOLATION, proof=True, family=extra_scope.family_id),
    )
    valid = combination.combine_observations(registered, "arm-combined", components)
    anchor = components[0].proof_anchors[0]
    case = replace(valid.combined_observation.cases[0], proof_candidate_digest=anchor.candidate.candidate_digest)
    observation = replace(valid.combined_observation, cases=(case,), observation_digest="")
    forged = combination.CombinedObservationV1(
        valid.registered_plan,
        valid.rule_registration,
        valid.component_observations,
        observation,
        (anchor,),
        "",
    )

    with pytest.raises(combination.CombinationPlannerError):
        operation(forged)


def test_missing_component_proof_blocks_combined_proof_continuity() -> None:
    registered = _registered()
    components = (
        _component(registered, "arm-experimental", NeutralOutcome.VIOLATION, proof=True),
        _component(registered, "arm-shipped", NeutralOutcome.VIOLATION),
    )
    result = combination.combine_observations(registered, "arm-combined", components)
    assert result.retained_proof_anchors == ()
    assert result.combined_observation.cases[0].proof_candidate_digest is None


@pytest.mark.parametrize("field", ("family", "change", "packet", "location", "proof_ref"))
def test_any_proof_continuity_mismatch_drops_combined_proof_authority(field: str) -> None:
    shipped_scopes = (ScopeKey("injection", "python"), ScopeKey("other-family", "python"))
    registered = _registered(shipped_scopes=shipped_scopes) if field == "family" else _registered()
    first = _component(registered, "arm-experimental", NeutralOutcome.VIOLATION, proof=True)
    kwargs = {field: f"other-{field}"}
    second = _component(registered, "arm-shipped", NeutralOutcome.VIOLATION, proof=True, **kwargs)
    result = combination.combine_observations(registered, "arm-combined", (first, second))
    assert result.retained_proof_anchors == ()
    assert result.combined_observation.cases[0].proof_candidate_digest is None


def test_no_proof_candidate_remains_not_demonstrated_and_confidence_cannot_enter() -> None:
    registered = _registered()
    result = combination.combine_observations(registered, "arm-combined", _components(registered))
    assert result.retained_proof_anchors == ()
    assert result.combined_observation.cases[0].proof_candidate_digest is None
    names = {item.name for item in fields(combination.CombinedObservationV1)}
    assert names.isdisjoint({"confidence", "agreement", "demonstrated", "label", "expected_outcome"})
    encoded = combination.combined_observation_bytes(result)
    assert all(token not in encoded for token in (b"confidence", b"agreement", b"demonstrated", b"label"))


def test_combined_identity_changes_with_component_result_and_api_has_no_runner_hook() -> None:
    registered = _registered()
    base = combination.combine_observations(registered, "arm-combined", _components(registered))
    changed = combination.combine_observations(
        registered, "arm-combined", _components(registered, (NeutralOutcome.SATISFIED, NeutralOutcome.SATISFIED))
    )
    assert base.combination_digest != changed.combination_digest
    assert {item.name for item in fields(combination.ComponentObservationV1)} == {"observation", "proof_anchors", "component_digest"}
