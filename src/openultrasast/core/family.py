"""Closed vulnerability-family declarations and evidence conformance."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core.evidence import EvidenceRecord, NeutralOutcome
from openultrasast.core.semantics import (
    FieldKind,
    FieldValue,
    Observation,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticRelation,
)

MISSING_REVIEWED_DEPENDENCY = "missing_reviewed_dependency_relation"


class FamilyContractError(ValueError):
    """A family declaration or evidence record violates its closed contract."""


class UnsupportedFamilyScope(FamilyContractError):
    """Evidence names a family, schema, or ecosystem outside the declaration."""


class RelationOriginPolicy(Enum):
    PRODUCT_OR_REVIEWED_FACT = "product_or_reviewed_fact"
    EXCLUDED_DEPENDENCY_FACT_ONLY = "excluded_dependency_fact_only"


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise FamilyContractError(f"{field} must be nonempty text")


def _tuple(value: object, item_type: type[object], field: str, *, nonempty: bool = True) -> None:
    if not isinstance(value, tuple) or (nonempty and not value) or not all(isinstance(item, item_type) for item in value):
        raise FamilyContractError(f"{field} must be a{' nonempty' if nonempty else ''} tuple of {item_type.__name__}")


def _unique(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not all(isinstance(item, str) and item for item in values):
        raise FamilyContractError(f"{field} must contain nonempty text")
    if len(set(values)) != len(values):
        raise FamilyContractError(f"duplicate {field}")


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: FieldKind
    required: bool

    def __post_init__(self) -> None:
        _text(self.name, "field name")
        if not isinstance(self.kind, FieldKind):
            raise FamilyContractError("field kind must be a FieldKind")
        if not isinstance(self.required, bool):
            raise FamilyContractError("required must be boolean")


@dataclass(frozen=True)
class ObjectSpec:
    kind: str
    fields: tuple[FieldSpec, ...]
    identity_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.kind, "object kind")
        _field_specs(self.fields, "security-object fields", nonempty=True)
        _unique(self.identity_fields, "identity fields")
        if not self.identity_fields:
            raise FamilyContractError("identity fields must be nonempty")
        fields = {field.name: field for field in self.fields}
        if any(name not in fields or not fields[name].required for name in self.identity_fields):
            raise FamilyContractError("identity fields must name declared required fields")


@dataclass(frozen=True)
class RoleSpec:
    role: str
    fields: tuple[FieldSpec, ...]
    allowed_relation_kinds: tuple[RelationKind, ...]
    origin_policy: RelationOriginPolicy

    def __post_init__(self) -> None:
        _text(self.role, "role")
        _field_specs(self.fields, f"role {self.role} fields", nonempty=False)
        _tuple(self.allowed_relation_kinds, RelationKind, "allowed relation kinds", nonempty=False)
        _unique(tuple(item.value for item in self.allowed_relation_kinds), "allowed relation kinds")
        if not self.fields and not self.allowed_relation_kinds:
            raise FamilyContractError("a role must declare fields or allowed relation kinds")
        if not isinstance(self.origin_policy, RelationOriginPolicy):
            raise FamilyContractError("origin_policy must be a RelationOriginPolicy")


@dataclass(frozen=True)
class DecisionRule:
    family_code: str
    outcome: NeutralOutcome
    required_roles: tuple[str, ...]
    allowed_statuses: tuple[RelationStatus, ...]

    def __post_init__(self) -> None:
        _text(self.family_code, "family decision code")
        if not isinstance(self.outcome, NeutralOutcome):
            raise FamilyContractError("decision outcome must be a NeutralOutcome")
        _unique(self.required_roles, "required roles")
        _tuple(self.allowed_statuses, RelationStatus, "allowed statuses")
        _unique(tuple(item.value for item in self.allowed_statuses), "allowed statuses")
        if self.outcome is not NeutralOutcome.INDETERMINATE and self.allowed_statuses != (RelationStatus.COMPLETE,):
            raise FamilyContractError("determinate decisions may allow only complete evidence")
        if self.outcome is not NeutralOutcome.INDETERMINATE and not self.required_roles:
            raise FamilyContractError("determinate decisions require minimum evidence roles")


@dataclass(frozen=True)
class ResidualQuestion:
    question_id: str
    required_roles: tuple[str, ...]
    allowed_decisions: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.question_id, "question_id")
        _unique(self.required_roles, "required roles")
        _unique(self.allowed_decisions, "allowed decisions")
        if not self.required_roles or not self.allowed_decisions:
            raise FamilyContractError("residual questions require roles and allowed decisions")


@dataclass(frozen=True)
class FamilyContract:
    family_id: str
    family_version: str
    schema_version: str
    ecosystems: tuple[str, ...]
    security_object: ObjectSpec
    roles: tuple[RoleSpec, ...]
    decisions: tuple[DecisionRule, ...]
    residual_questions: tuple[ResidualQuestion, ...]
    indeterminate_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_contract(self)


def _field_specs(values: object, field: str, *, nonempty: bool) -> None:
    _tuple(values, FieldSpec, field, nonempty=nonempty)
    assert isinstance(values, tuple)
    _unique(tuple(item.name for item in values), field)


def validate_contract(contract: FamilyContract) -> None:
    if not isinstance(contract, FamilyContract):
        raise FamilyContractError("contract must be a FamilyContract")
    for value, field in (
        (contract.family_id, "family_id"),
        (contract.family_version, "family_version"),
        (contract.schema_version, "schema_version"),
    ):
        _text(value, field)
    _unique(contract.ecosystems, "ecosystems")
    if not contract.ecosystems:
        raise FamilyContractError("ecosystems must be nonempty")
    if not isinstance(contract.security_object, ObjectSpec):
        raise FamilyContractError("security_object must be an ObjectSpec")
    _tuple(contract.roles, RoleSpec, "roles")
    _tuple(contract.decisions, DecisionRule, "decisions")
    _tuple(contract.residual_questions, ResidualQuestion, "residual questions")
    _unique(tuple(item.role for item in contract.roles), "roles")
    _unique(tuple(item.family_code for item in contract.decisions), "decisions")
    _unique(tuple(item.question_id for item in contract.residual_questions), "residual questions")
    _unique(contract.indeterminate_reasons, "indeterminate reasons")
    if not contract.indeterminate_reasons:
        raise FamilyContractError("indeterminate reasons must be nonempty")
    _validate_contract_references(contract)


def _validate_contract_references(contract: FamilyContract) -> None:
    roles = {item.role for item in contract.roles}
    decisions = {item.family_code for item in contract.decisions}
    for rule in contract.decisions:
        if not set(rule.required_roles).issubset(roles):
            raise FamilyContractError("decision references an undeclared role")
    for question in contract.residual_questions:
        if not set(question.required_roles).issubset(roles):
            raise FamilyContractError("residual question references an undeclared role")
        if not set(question.allowed_decisions).issubset(decisions):
            raise FamilyContractError("residual question references an undeclared decision")


def _field_spec_value(value: FieldSpec) -> canonical.JsonValue:
    return {"name": value.name, "kind": value.kind.value, "required": value.required}


def _contract_value(contract: FamilyContract) -> canonical.JsonValue:
    return {
        "family_id": contract.family_id,
        "family_version": contract.family_version,
        "schema_version": contract.schema_version,
        "ecosystems": contract.ecosystems,
        "security_object": {
            "kind": contract.security_object.kind,
            "fields": tuple(_field_spec_value(item) for item in contract.security_object.fields),
            "identity_fields": contract.security_object.identity_fields,
        },
        "roles": tuple(
            {
                "role": role.role,
                "fields": tuple(_field_spec_value(item) for item in role.fields),
                "allowed_relation_kinds": tuple(item.value for item in role.allowed_relation_kinds),
                "origin_policy": role.origin_policy.value,
            }
            for role in contract.roles
        ),
        "decisions": tuple(
            {
                "family_code": rule.family_code,
                "outcome": rule.outcome.value,
                "required_roles": rule.required_roles,
                "allowed_statuses": tuple(item.value for item in rule.allowed_statuses),
            }
            for rule in contract.decisions
        ),
        "residual_questions": tuple(
            {
                "question_id": question.question_id,
                "required_roles": question.required_roles,
                "allowed_decisions": question.allowed_decisions,
            }
            for question in contract.residual_questions
        ),
        "indeterminate_reasons": contract.indeterminate_reasons,
    }


def family_contract_digest(contract: FamilyContract) -> str:
    validate_contract(contract)
    return canonical.content_digest(_contract_value(contract))


def _identity_field_value(value: FieldValue) -> canonical.JsonValue:
    return {"name": value.name, "kind": value.kind.value, "value": value.value}


def derive_security_object_id(spec: ObjectSpec, values: tuple[FieldValue, ...]) -> str:
    """Bind an object kind to its typed identity fields in declared order."""
    if not isinstance(spec, ObjectSpec):
        raise FamilyContractError("security object must be an ObjectSpec")
    _validate_fields(values, spec.fields, "security object")
    actual = {value.name: value for value in values}
    payload: canonical.JsonValue = {
        "kind": spec.kind,
        "identity_fields": tuple(_identity_field_value(actual[name]) for name in spec.identity_fields),
    }
    return canonical.content_digest(payload)


def _validate_fields(values: tuple[FieldValue, ...], specs: tuple[FieldSpec, ...], context: str) -> None:
    declared = {spec.name: spec for spec in specs}
    actual = {value.name: value for value in values}
    unknown = set(actual) - set(declared)
    if unknown:
        raise FamilyContractError(f"{context} contains an undeclared field: {sorted(unknown)[0]}")
    missing = {spec.name for spec in specs if spec.required} - set(actual)
    if missing:
        raise FamilyContractError(f"{context} is missing required field: {sorted(missing)[0]}")
    for name, value in actual.items():
        if value.kind is not declared[name].kind:
            raise FamilyContractError(f"{context} field {name} has the wrong kind")


def _role_map(contract: FamilyContract) -> dict[str, RoleSpec]:
    return {item.role: item for item in contract.roles}


def _validate_relation(relation: SemanticRelation, roles: dict[str, RoleSpec], packet_reasons: tuple[str, ...]) -> None:
    if relation.role not in roles:
        raise FamilyContractError(f"undeclared semantic role: {relation.role}")
    spec = roles[relation.role]
    if relation.kind not in spec.allowed_relation_kinds:
        raise FamilyContractError(f"relation kind {relation.kind.value} is not declared for role {relation.role}")
    _validate_origin(relation.status, relation.provenance.kind, spec, relation.reasons or packet_reasons)


def _validate_observation(observation: Observation, roles: dict[str, RoleSpec], packet_reasons: tuple[str, ...]) -> None:
    if observation.role not in roles:
        raise FamilyContractError(f"undeclared observation role: {observation.role}")
    spec = roles[observation.role]
    _validate_fields(observation.fields, spec.fields, f"observation role {observation.role}")
    _validate_origin(observation.status, observation.provenance.kind, spec, packet_reasons)


def _validate_origin(
    status: RelationStatus,
    provenance: ProvenanceKind,
    spec: RoleSpec,
    reasons: tuple[str, ...],
) -> None:
    if spec.origin_policy is not RelationOriginPolicy.EXCLUDED_DEPENDENCY_FACT_ONLY:
        return
    if status is RelationStatus.COMPLETE and provenance is not ProvenanceKind.SEMANTIC_FACT:
        raise FamilyContractError(f"role {spec.role} requires a reviewed semantic fact for complete evidence")
    if provenance is ProvenanceKind.PRODUCT_CODE and status is not RelationStatus.COMPLETE and MISSING_REVIEWED_DEPENDENCY not in reasons:
        raise FamilyContractError(f"role {spec.role} requires {MISSING_REVIEWED_DEPENDENCY}")


def _validate_scope(contract: FamilyContract, record: EvidenceRecord) -> None:
    packet = record.packet
    if packet.family_id != contract.family_id:
        raise UnsupportedFamilyScope("unsupported family scope; no cross-family fallback")
    if packet.schema_version != contract.schema_version:
        raise UnsupportedFamilyScope("unsupported schema scope; no fallback")
    if packet.ecosystem not in contract.ecosystems:
        raise UnsupportedFamilyScope("unsupported ecosystem scope; no fallback")
    expected = family_contract_digest(contract)
    if packet.family_contract_digest != expected:
        raise FamilyContractError("packet family contract digest does not match declaration")


def _validate_decision(contract: FamilyContract, record: EvidenceRecord) -> None:
    rules = {item.family_code: item for item in contract.decisions}
    if record.decision.family_code not in rules:
        raise FamilyContractError("decision code is not declared by the family")
    rule = rules[record.decision.family_code]
    if record.decision.outcome is not rule.outcome:
        raise FamilyContractError("family decision outcome does not match its declared outcome")
    if record.decision.outcome is NeutralOutcome.INDETERMINATE:
        unknown = set(record.decision.reasons) - set(contract.indeterminate_reasons)
        if unknown:
            raise FamilyContractError(f"indeterminate reason is not declared: {sorted(unknown)[0]}")
    statuses: dict[str, list[RelationStatus]] = {}
    for relation in record.packet.transitions:
        statuses.setdefault(relation.role, []).append(relation.status)
    for observation in record.packet.observations:
        statuses.setdefault(observation.role, []).append(observation.status)
    for role in rule.required_roles:
        if role not in statuses:
            raise FamilyContractError(f"required role is missing: {role}")
        if any(status not in rule.allowed_statuses for status in statuses[role]):
            raise FamilyContractError(f"required role has a status outside the decision rule: {role}")


def validate_record(contract: FamilyContract, record: EvidenceRecord) -> None:
    validate_contract(contract)
    if not isinstance(record, EvidenceRecord):
        raise FamilyContractError("record must be an EvidenceRecord")
    _validate_scope(contract, record)
    _validate_fields(record.packet.family_fields, contract.security_object.fields, "security object")
    expected_object_id = derive_security_object_id(contract.security_object, record.packet.family_fields)
    if record.packet.security_object_id != expected_object_id:
        raise FamilyContractError("security object identity does not match its declared identity fields")
    roles = _role_map(contract)
    for relation in record.packet.transitions:
        _validate_relation(relation, roles, record.packet.completeness_reasons)
    for observation in record.packet.observations:
        _validate_observation(observation, roles, record.packet.completeness_reasons)
    _validate_decision(contract, record)


__all__ = [
    "DecisionRule",
    "FamilyContract",
    "FamilyContractError",
    "FieldSpec",
    "MISSING_REVIEWED_DEPENDENCY",
    "ObjectSpec",
    "RelationOriginPolicy",
    "ResidualQuestion",
    "RoleSpec",
    "UnsupportedFamilyScope",
    "derive_security_object_id",
    "family_contract_digest",
    "validate_contract",
    "validate_record",
]
