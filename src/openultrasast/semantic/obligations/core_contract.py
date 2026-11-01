"""Reviewed production access-control contract for detection-core v2."""

from __future__ import annotations

from openultrasast.core import evidence, family, semantics


class AccessControlContractError(family.FamilyContractError):
    """A contract does not equal the reviewed production access-control contract."""


_ORIGIN = family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT
_TEXT_FIELDS = (
    family.FieldSpec("operation", semantics.FieldKind.TEXT, True),
    family.FieldSpec("boundary", semantics.FieldKind.TEXT, True),
)


def _relation_role(role: str, kind: semantics.RelationKind) -> family.RoleSpec:
    return family.RoleSpec(role, (), (kind,), _ORIGIN)


def _build_contract() -> family.FamilyContract:
    required = ("operation", "constraint", "security_object")
    complete = (semantics.RelationStatus.COMPLETE,)
    return family.FamilyContract(
        family_id="access_control",
        family_version="2.0.0",
        schema_version=evidence.EVIDENCE_PACKET_SCHEMA,
        ecosystems=("express",),
        security_object=family.ObjectSpec("entry_operation_authorization", _TEXT_FIELDS, ("operation", "boundary")),
        roles=(
            _relation_role("operation", semantics.RelationKind.OPERATION_EFFECT),
            _relation_role("constraint", semantics.RelationKind.CONSTRAINT_EFFECT),
            family.RoleSpec("security_object", _TEXT_FIELDS, (), _ORIGIN),
            _relation_role("framework_factory", semantics.RelationKind.REGISTRATION),
            _relation_role("framework_instance", semantics.RelationKind.REGISTRATION),
            _relation_role("entry_handler", semantics.RelationKind.INVOCATION),
            _relation_role("entry_registration", semantics.RelationKind.REGISTRATION),
        ),
        decisions=(
            family.DecisionRule("unguarded", evidence.NeutralOutcome.VIOLATION, required, complete),
            family.DecisionRule("discharged", evidence.NeutralOutcome.SATISFIED, required, complete),
            family.DecisionRule(
                "indeterminate",
                evidence.NeutralOutcome.INDETERMINATE,
                ("constraint",),
                (semantics.RelationStatus.INCOMPLETE, semantics.RelationStatus.UNRESOLVED),
            ),
        ),
        residual_questions=(
            family.ResidualQuestion("is_path_authorized", required, ("unguarded", "discharged", "indeterminate")),
        ),
        indeterminate_reasons=("missing_constraint_relation", "ambiguous_constraint_relation"),
    )


_PRODUCTION_ACCESS_CONTROL_CONTRACT = _build_contract()
ACCESS_CONTROL_CONTRACT_DIGEST = family.family_contract_digest(_PRODUCTION_ACCESS_CONTROL_CONTRACT)


def production_access_control_contract() -> family.FamilyContract:
    """Return the immutable reviewed production access-control contract."""
    return _PRODUCTION_ACCESS_CONTROL_CONTRACT


def validate_access_control_contract(contract: family.FamilyContract) -> None:
    """Refuse any contract that differs from the reviewed production identity."""
    try:
        actual_digest = family.family_contract_digest(contract)
    except (family.FamilyContractError, TypeError) as exc:
        raise AccessControlContractError("contract does not match the reviewed production contract") from exc
    if actual_digest != ACCESS_CONTROL_CONTRACT_DIGEST:
        raise AccessControlContractError("contract does not match the reviewed production contract")


__all__ = [
    "ACCESS_CONTROL_CONTRACT_DIGEST",
    "AccessControlContractError",
    "production_access_control_contract",
    "validate_access_control_contract",
]
