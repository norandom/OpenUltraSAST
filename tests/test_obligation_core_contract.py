"""Production access-control family contract conformance."""

from collections.abc import Callable
from dataclasses import replace

import pytest

from openultrasast.core import evidence, family, semantics
from openultrasast.semantic.obligations.core_contract import (
    ACCESS_CONTROL_CONTRACT_DIGEST,
    AccessControlContractError,
    production_access_control_contract,
    validate_access_control_contract,
)


def test_production_contract_pins_the_reviewed_access_control_vocabulary() -> None:
    contract = production_access_control_contract()

    assert contract.family_id == "access_control"
    assert contract.family_version == "2.0.0"
    assert contract.schema_version == evidence.EVIDENCE_PACKET_SCHEMA
    assert contract.ecosystems == ("express",)
    assert contract.security_object == family.ObjectSpec(
        "entry_operation_authorization",
        (
            family.FieldSpec("operation", semantics.FieldKind.TEXT, True),
            family.FieldSpec("boundary", semantics.FieldKind.TEXT, True),
        ),
        ("operation", "boundary"),
    )
    origin = family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT
    assert contract.roles == (
        family.RoleSpec("operation", (), (semantics.RelationKind.OPERATION_EFFECT,), origin),
        family.RoleSpec("constraint", (), (semantics.RelationKind.CONSTRAINT_EFFECT,), origin),
        family.RoleSpec("security_object", contract.security_object.fields, (), origin),
        family.RoleSpec("framework_factory", (), (semantics.RelationKind.REGISTRATION,), origin),
        family.RoleSpec("framework_instance", (), (semantics.RelationKind.REGISTRATION,), origin),
        family.RoleSpec("entry_handler", (), (semantics.RelationKind.INVOCATION,), origin),
        family.RoleSpec("entry_registration", (), (semantics.RelationKind.REGISTRATION,), origin),
    )
    required = ("operation", "constraint", "security_object")
    assert contract.decisions == (
        family.DecisionRule(
            "unguarded",
            evidence.NeutralOutcome.VIOLATION,
            required,
            (semantics.RelationStatus.COMPLETE,),
        ),
        family.DecisionRule(
            "discharged",
            evidence.NeutralOutcome.SATISFIED,
            required,
            (semantics.RelationStatus.COMPLETE,),
        ),
        family.DecisionRule(
            "indeterminate",
            evidence.NeutralOutcome.INDETERMINATE,
            ("constraint",),
            (semantics.RelationStatus.INCOMPLETE, semantics.RelationStatus.UNRESOLVED),
        ),
    )
    assert contract.residual_questions == (
        family.ResidualQuestion(
            "is_path_authorized",
            required,
            ("unguarded", "discharged", "indeterminate"),
        ),
    )
    assert contract.indeterminate_reasons == ("missing_constraint_relation", "ambiguous_constraint_relation")


def test_production_contract_has_one_deterministic_canonical_identity() -> None:
    first = production_access_control_contract()
    second = production_access_control_contract()

    family.validate_contract(first)
    validate_access_control_contract(first)
    assert first == second
    assert family.family_contract_digest(first) == ACCESS_CONTROL_CONTRACT_DIGEST
    assert family.family_contract_digest(second) == ACCESS_CONTROL_CONTRACT_DIGEST


def _add_role(contract: family.FamilyContract) -> family.FamilyContract:
    extra = family.RoleSpec(
        "undeclared",
        (),
        (semantics.RelationKind.CALL,),
        family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
    )
    return replace(contract, roles=(*contract.roles, extra))


def _alter_decision(contract: family.FamilyContract) -> family.FamilyContract:
    changed = replace(contract.decisions[0], required_roles=("constraint",))
    return replace(contract, decisions=(changed, *contract.decisions[1:]))


def _alter_field(contract: family.FamilyContract) -> family.FamilyContract:
    changed = replace(contract.security_object.fields[0], kind=semantics.FieldKind.INTEGER)
    security_object = replace(contract.security_object, fields=(changed, *contract.security_object.fields[1:]))
    return replace(contract, security_object=security_object)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda contract: replace(contract, ecosystems=("other",)),
        _add_role,
        _alter_decision,
        _alter_field,
        lambda contract: replace(contract, indeterminate_reasons=(*contract.indeterminate_reasons, "undeclared_reason")),
    ),
)
def test_exact_validator_rejects_altered_or_undeclared_contract_values(
    mutate: Callable[[family.FamilyContract], family.FamilyContract],
) -> None:
    contract = production_access_control_contract()

    with pytest.raises(AccessControlContractError, match="does not match the reviewed production contract"):
        validate_access_control_contract(mutate(contract))
