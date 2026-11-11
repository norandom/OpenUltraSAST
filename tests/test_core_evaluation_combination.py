"""Deterministic per-case combination replay for evaluation admission V3."""

from __future__ import annotations

from dataclasses import fields, replace
from itertools import product

import pytest
from test_core_evaluation_plan import _declaration, _digest

from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionPolicyV3,
    CaseOutcomeProjectionV3,
)
from openultrasast.core.evaluation_measurement import ArmScopeKey
from openultrasast.core.evaluation_release import ReleasedArmCaseBindingV3
from openultrasast.core.evidence import NeutralOutcome


def _projection(
    case_input: str,
    outcome: NeutralOutcome,
    *,
    sources: tuple[str, ...],
    combined: bool = False,
) -> CaseOutcomeProjectionV3:
    return CaseOutcomeProjectionV3(
        case_input,
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE
        if combined
        else CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        sources,
        outcome,
        "",
    )


def _binding(
    arm_id: str,
    case_input: str,
    projection: CaseOutcomeProjectionV3,
    *,
    candidate: str | None = None,
    case: str = "case-a",
) -> ReleasedArmCaseBindingV3:
    scope = _declaration().arm_configurations[0].exact_scopes[0]
    return ReleasedArmCaseBindingV3(
        ArmScopeKey(arm_id, scope),
        _digest(f"baseline-{arm_id}"),
        _digest(f"slot-{arm_id}-{case}"),
        _digest(f"observation-{arm_id}-{case}"),
        _digest(f"push-{case}"),
        _digest(f"{arm_id}-{case}"),
        case_input,
        projection,
        AdmissionCaseRole.ORDINARY,
        None,
        _digest(f"result-{arm_id}-{case}"),
        (_digest(f"evidence-{arm_id}-{case}"),),
        (_digest(f"change-{case}"),),
        _digest(f"manifest-{arm_id}-{case}"),
        candidate,
        "",
    )


def _valid_bindings(
    outcomes: tuple[NeutralOutcome, NeutralOutcome] = (NeutralOutcome.SATISFIED, NeutralOutcome.VIOLATION),
) -> tuple[ReleasedArmCaseBindingV3, ...]:
    declaration = _declaration()
    rule = next(item.combination_rule for item in declaration.arm_configurations if item.arm_id == "arm-combined")
    assert rule is not None
    case_input = _digest("shared-case-input")
    projection_a = _projection(case_input, outcomes[0], sources=(_digest("record-a"),))
    projection_b = _projection(case_input, outcomes[1], sources=(_digest("record-b"),))
    row = next(item for item in rule.decision_rows if item.component_outcomes == outcomes)
    combined = _projection(
        case_input,
        row.combined_outcome,
        sources=(projection_a.projection_digest, projection_b.projection_digest),
        combined=True,
    )
    candidate = _digest("candidate-a")
    return (
        _binding("arm-a", case_input, projection_a, candidate=candidate),
        _binding("arm-b", case_input, projection_b),
        _binding("arm-combined", case_input, combined, candidate=candidate),
    )


def test_combination_replay_joins_exact_cases_in_registered_component_order() -> None:
    from openultrasast.core.evaluation_combination import derive_combination_lineages_v3

    declaration = _declaration()
    bindings = _valid_bindings()
    (lineage,) = derive_combination_lineages_v3(declaration, bindings)
    combined = lineage.combined_cases[0]
    rule = next(item.combination_rule for item in declaration.arm_configurations if item.arm_id == "arm-combined")
    assert rule is not None
    expected_row = next(
        item
        for item in rule.decision_rows
        if item.component_outcomes == (NeutralOutcome.SATISFIED, NeutralOutcome.VIOLATION)
    )

    assert lineage.rule == rule
    assert lineage.component_observation_digests == tuple(item.observation_digest for item in bindings[:2])
    assert tuple(item.component_arm_id for item in combined.components) == rule.component_arm_ids
    assert tuple(item.normalized_outcome for item in combined.components) == expected_row.component_outcomes
    assert combined.components[0].proof_candidate_digest == bindings[0].proof_candidate_digest
    assert combined.components[1].proof_candidate_digest is None
    assert combined.key == bindings[2].key
    assert combined.case_id_digest == bindings[2].case_id_digest
    assert combined.observation_digest == bindings[2].observation_digest
    assert combined.decision_row_digest == expected_row.row_digest
    assert combined.normalized_outcome is expected_row.combined_outcome
    assert combined.combined_projection_digest == bindings[2].outcome_projection.projection_digest
    assert combined.retained_proof_candidate_digest == bindings[2].proof_candidate_digest


@pytest.mark.parametrize("outcomes", tuple(product(tuple(NeutralOutcome), repeat=2)))
def test_combination_replay_selects_every_registered_decision_row(
    outcomes: tuple[NeutralOutcome, NeutralOutcome],
) -> None:
    from openultrasast.core.evaluation_combination import derive_combination_lineages_v3

    declaration = _declaration()
    bindings = _valid_bindings(outcomes)
    combined = derive_combination_lineages_v3(declaration, bindings)[0].combined_cases[0]
    rule = next(item.combination_rule for item in declaration.arm_configurations if item.arm_id == "arm-combined")
    assert rule is not None
    expected = next(item for item in rule.decision_rows if item.component_outcomes == outcomes)
    assert (combined.decision_row_digest, combined.normalized_outcome) == (expected.row_digest, expected.combined_outcome)


@pytest.mark.parametrize(
    "mutation",
    ("missing_component", "missing_combined", "extra_combined", "reordered", "cross_input", "cross_scope"),
)
def test_combination_replay_refuses_incomplete_extra_reordered_or_cross_input_material(mutation: str) -> None:
    from openultrasast.core.evaluation_combination import CombinationValidationError, derive_combination_lineages_v3

    declaration = _declaration()
    bindings = _valid_bindings()
    if mutation == "missing_component":
        bindings = bindings[1:]
    elif mutation == "missing_combined":
        bindings = bindings[:2]
    elif mutation == "extra_combined":
        combined = bindings[2]
        extra_input = _digest("extra-case-input")
        extra_projection = replace(combined.outcome_projection, case_input_digest=extra_input, projection_digest="")
        bindings = bindings + (replace(combined, case_input_digest=extra_input, outcome_projection=extra_projection, binding_digest=""),)
    elif mutation == "reordered":
        bindings = (bindings[1], bindings[0], bindings[2])
    elif mutation == "cross_input":
        component = bindings[1]
        other_input = _digest("other-case-input")
        other_projection = replace(component.outcome_projection, case_input_digest=other_input, projection_digest="")
        changed = replace(
            component,
            case_input_digest=other_input,
            outcome_projection=other_projection,
            binding_digest="",
        )
        bindings = (bindings[0], changed, bindings[2])
    else:
        component = bindings[1]
        wrong_scope = replace(component.key.scope, ecosystem="javascript")
        changed = replace(component, key=ArmScopeKey(component.key.arm_id, wrong_scope), binding_digest="")
        bindings = (bindings[0], changed, bindings[2])
    with pytest.raises(CombinationValidationError):
        derive_combination_lineages_v3(declaration, bindings)


def test_combination_replay_refuses_wrong_component_policy_and_coordinated_combined_projection() -> None:
    from openultrasast.core.evaluation_combination import CombinationValidationError, derive_combination_lineages_v3

    declaration = _declaration()
    bindings = _valid_bindings()
    wrong_component_projection = _projection(
        bindings[0].case_input_digest,
        bindings[0].outcome_projection.normalized_outcome,
        sources=(bindings[0].outcome_projection.projection_digest,),
        combined=True,
    )
    wrong_component = replace(bindings[0], outcome_projection=wrong_component_projection, binding_digest="")
    with pytest.raises(CombinationValidationError, match="policy"):
        derive_combination_lineages_v3(declaration, (wrong_component, bindings[1], bindings[2]))

    wrong_combined_projection = _projection(
        bindings[2].case_input_digest,
        NeutralOutcome.SATISFIED,
        sources=(bindings[1].outcome_projection.projection_digest, bindings[0].outcome_projection.projection_digest),
        combined=True,
    )
    wrong_combined = replace(bindings[2], outcome_projection=wrong_combined_projection, binding_digest="")
    with pytest.raises(CombinationValidationError, match="projection"):
        derive_combination_lineages_v3(declaration, (bindings[0], bindings[1], wrong_combined))


def test_combination_lineage_contracts_are_exact_digest_bound_non_authorizing_values() -> None:
    from openultrasast.core.evaluation_combination import (
        CombinationLineageV3,
        CombinationValidationError,
        CombinedCaseOutcomeV3,
        ComponentCaseOutcomeV3,
        derive_combination_lineages_v3,
    )
    from openultrasast.core.evaluation_version import NonAuthorizingV3

    (lineage,) = derive_combination_lineages_v3(_declaration(), _valid_bindings())
    combined = lineage.combined_cases[0]
    component = combined.components[0]
    assert {item.name for item in fields(ComponentCaseOutcomeV3)} == {
        "component_arm_id",
        "scope",
        "case_input_digest",
        "case_id_digest",
        "observation_digest",
        "outcome_projection_digest",
        "normalized_outcome",
        "proof_candidate_digest",
        "component_digest",
    }
    assert {item.name for item in fields(CombinedCaseOutcomeV3)} == {
        "key",
        "case_id_digest",
        "case_input_digest",
        "observation_digest",
        "components",
        "decision_row_digest",
        "normalized_outcome",
        "retained_proof_candidate_digest",
        "combined_projection_digest",
    }
    assert {item.name for item in fields(CombinationLineageV3)} == {
        "rule",
        "component_observation_digests",
        "combined_cases",
        "lineage_digest",
    }
    assert all(isinstance(item, NonAuthorizingV3) for item in (component, combined, lineage))
    for value, field_name in ((component, "component_digest"), (lineage, "lineage_digest")):
        with pytest.raises((CombinationValidationError, ValueError)):
            replace(value, **{field_name: _digest("tampered")})
    changed_combined = replace(combined, combined_projection_digest=_digest("tampered"))
    with pytest.raises(CombinationValidationError, match="projection"):
        replace(lineage, combined_cases=(changed_combined,))


def test_combination_lineage_refuses_a_coordinated_wrong_table_result() -> None:
    from openultrasast.core.evaluation_combination import CombinationValidationError, derive_combination_lineages_v3

    (lineage,) = derive_combination_lineages_v3(_declaration(), _valid_bindings())
    combined = lineage.combined_cases[0]
    wrong_outcome = next(item for item in NeutralOutcome if item is not combined.normalized_outcome)
    wrong_row = next(item for item in lineage.rule.decision_rows if item.combined_outcome is wrong_outcome)
    changed = replace(
        combined,
        decision_row_digest=wrong_row.row_digest,
        normalized_outcome=wrong_outcome,
    )
    with pytest.raises(CombinationValidationError, match="outcome"):
        replace(lineage, combined_cases=(changed,), lineage_digest="")
