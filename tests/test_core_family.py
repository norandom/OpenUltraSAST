"""Closed vulnerability-family declarations and record validation."""

from dataclasses import replace
from typing import cast

import pytest

import openultrasast.core.canonical as canonical
import openultrasast.core.evidence as evidence
import openultrasast.core.family as family
import openultrasast.core.provenance as provenance
import openultrasast.core.semantics as semantics


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _location(line: int = 10) -> semantics.SourceLocation:
    return semantics.SourceLocation("src/app.py", line, 2, "handle")


def _product() -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(semantics.ProvenanceKind.PRODUCT_CODE, _digest("source"), None, None, None)


def _fact() -> semantics.EvidenceProvenance:
    content = b"reviewed match"
    retention = _digest("retention")
    content_digest = canonical.bytes_digest(content)
    receipt_digest = canonical.derive_storage_receipt_digest(
        store_identity="reviewed-store",
        content_digest=content_digest,
        byte_length=len(content),
        retention_policy_digest=retention,
    )
    reference = canonical.ContentRef(
        "match",
        content_digest,
        "application/json",
        len(content),
        retention,
        receipt_digest,
    )
    return semantics.EvidenceProvenance(
        semantics.ProvenanceKind.SEMANTIC_FACT,
        _digest("source"),
        _digest("pack"),
        "fact.constraint",
        reference,
    )


def _relation(
    *,
    status: semantics.RelationStatus = semantics.RelationStatus.COMPLETE,
    origin: semantics.EvidenceProvenance | None = None,
    role: str = "constraint",
) -> semantics.SemanticRelation:
    return semantics.make_relation(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role=role,
        source=semantics.SemanticNode("operation", "operation", _location()),
        target=semantics.SemanticNode("policy", "policy", _location(11)),
        location=_location(12),
        status=status,
        conditions=("policy_applies",),
        reasons=() if status is semantics.RelationStatus.COMPLETE else ("missing_reviewed_dependency_relation",),
        provenance=_product() if origin is None else origin,
    )


def _observation(*, field_name: str = "resource", kind: semantics.FieldKind = semantics.FieldKind.TEXT) -> semantics.Observation:
    value: canonical.JsonValue = "document" if kind is semantics.FieldKind.TEXT else 7
    return semantics.make_observation(
        role="security_object",
        location=_location(13),
        fields=(semantics.FieldValue(field_name, kind, value),),
        status=semantics.RelationStatus.COMPLETE,
        provenance=_product(),
    )


def _contract(*, fact_only: bool = False) -> family.FamilyContract:
    origin = (
        family.RelationOriginPolicy.EXCLUDED_DEPENDENCY_FACT_ONLY if fact_only else family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT
    )
    return family.FamilyContract(
        family_id="obligation",
        family_version="1.0.0",
        schema_version=evidence.EVIDENCE_PACKET_SCHEMA,
        ecosystems=("python",),
        security_object=family.ObjectSpec(
            kind="operation",
            fields=(family.FieldSpec("operation", semantics.FieldKind.TEXT, True),),
            identity_fields=("operation",),
        ),
        roles=(
            family.RoleSpec(
                "constraint",
                (),
                (semantics.RelationKind.CONSTRAINT_EFFECT,),
                origin,
            ),
            family.RoleSpec(
                "security_object",
                (family.FieldSpec("resource", semantics.FieldKind.TEXT, True),),
                (),
                family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
            ),
        ),
        decisions=(
            family.DecisionRule(
                "blocked",
                evidence.NeutralOutcome.VIOLATION,
                ("constraint", "security_object"),
                (semantics.RelationStatus.COMPLETE,),
            ),
            family.DecisionRule(
                "safe",
                evidence.NeutralOutcome.SATISFIED,
                ("constraint", "security_object"),
                (semantics.RelationStatus.COMPLETE,),
            ),
            family.DecisionRule(
                "unknown",
                evidence.NeutralOutcome.INDETERMINATE,
                ("constraint",),
                (semantics.RelationStatus.INCOMPLETE, semantics.RelationStatus.UNRESOLVED),
            ),
        ),
        residual_questions=(family.ResidualQuestion("resolve_constraint", ("constraint",), ("blocked", "safe", "unknown")),),
        indeterminate_reasons=(
            "missing_reviewed_dependency_relation",
            "missing_required_role",
            "incomplete_required_role",
            "unsupported_scope",
        ),
    )


def _stamp(contract: family.FamilyContract) -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        _digest("analyzer"),
        family.family_contract_digest(contract),
        _digest("facts"),
        _digest("acquisition"),
        _digest("configuration"),
        _digest("population"),
        _digest("change"),
    )


def _packet(
    contract: family.FamilyContract,
    *,
    relation: semantics.SemanticRelation | None = None,
    observation: semantics.Observation | None = None,
    family_fields: tuple[semantics.FieldValue, ...] | None = None,
    ecosystem: str = "python",
) -> evidence.EvidencePacket:
    selected = _relation() if relation is None else relation
    reasons = selected.reasons if selected.status is not semantics.RelationStatus.COMPLETE else ()
    selected_fields = (semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),) if family_fields is None else family_fields
    scope = evidence.AnalyzedScope(
        "base",
        "head",
        _digest("change"),
        (evidence.SourceRegion("src/app.py", 1, 30),),
    )
    return evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        family.family_contract_digest(contract),
        family.derive_security_object_id(contract.security_object, selected_fields),
        ecosystem,
        scope,
        (selected,),
        (_observation() if observation is None else observation,),
        selected_fields,
        reasons,
        _stamp(contract),
    )


def _record(
    contract: family.FamilyContract,
    *,
    relation: semantics.SemanticRelation | None = None,
    observation: semantics.Observation | None = None,
    family_fields: tuple[semantics.FieldValue, ...] | None = None,
    ecosystem: str = "python",
    code: str = "blocked",
) -> evidence.EvidenceRecord:
    packet = _packet(
        contract,
        relation=relation,
        observation=observation,
        family_fields=family_fields,
        ecosystem=ecosystem,
    )
    indeterminate = relation is not None and relation.status is not semantics.RelationStatus.COMPLETE
    outcome = evidence.NeutralOutcome.INDETERMINATE if indeterminate else evidence.NeutralOutcome.VIOLATION
    decision = evidence.Decision(
        code,
        outcome,
        evidence.EvidenceBasis.DETERMINISTIC,
        packet.scope,
        packet.completeness_reasons,
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, decision, "")


def test_closed_family_contract_and_record_are_accepted() -> None:
    contract = _contract()
    family.validate_contract(contract)
    family.validate_record(contract, _record(contract))
    assert len(family.family_contract_digest(contract)) == 64


@pytest.mark.parametrize(
    "field",
    [
        "family_id",
        "family_version",
        "schema_version",
        "ecosystems",
        "roles",
        "decisions",
        "residual_questions",
        "indeterminate_reasons",
    ],
)
def test_contract_requires_every_declared_section(field: str) -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError):
        if field == "family_id":
            replace(contract, family_id="")
        elif field == "family_version":
            replace(contract, family_version="")
        elif field == "schema_version":
            replace(contract, schema_version="")
        elif field == "ecosystems":
            replace(contract, ecosystems=())
        elif field == "roles":
            replace(contract, roles=())
        elif field == "decisions":
            replace(contract, decisions=())
        elif field == "residual_questions":
            replace(contract, residual_questions=())
        else:
            replace(contract, indeterminate_reasons=())


def test_security_object_identity_fields_must_be_required_and_declared() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="identity"):
        replace(contract, security_object=replace(contract.security_object, identity_fields=("missing",)))
    optional = family.FieldSpec("operation", semantics.FieldKind.TEXT, False)
    with pytest.raises(family.FamilyContractError, match="identity"):
        replace(contract, security_object=replace(contract.security_object, fields=(optional,)))
    with pytest.raises(family.FamilyContractError, match="identity"):
        replace(contract, security_object=replace(contract.security_object, identity_fields=()))


def test_role_and_decision_declarations_are_closed_and_unique() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="duplicate"):
        replace(contract, roles=contract.roles + (contract.roles[0],))
    with pytest.raises(family.FamilyContractError, match="undeclared role"):
        replace(contract, decisions=(replace(contract.decisions[0], required_roles=("other",)),) + contract.decisions[1:])
    with pytest.raises(family.FamilyContractError, match="complete"):
        replace(
            contract,
            decisions=(replace(contract.decisions[0], allowed_statuses=(semantics.RelationStatus.INCOMPLETE,)),) + contract.decisions[1:],
        )
    with pytest.raises(family.FamilyContractError, match="minimum evidence"):
        replace(contract, decisions=(replace(contract.decisions[0], required_roles=()),) + contract.decisions[1:])


def test_residual_questions_reference_only_declared_roles_and_decisions() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="undeclared role"):
        replace(contract, residual_questions=(replace(contract.residual_questions[0], required_roles=("other",)),))
    with pytest.raises(family.FamilyContractError, match="undeclared decision"):
        replace(contract, residual_questions=(replace(contract.residual_questions[0], allowed_decisions=("other",)),))
    with pytest.raises(family.FamilyContractError, match="require roles"):
        replace(contract, residual_questions=(replace(contract.residual_questions[0], required_roles=()),))


def test_declaration_collections_require_immutable_tuples() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="ecosystems"):
        replace(contract, ecosystems=cast(tuple[str, ...], ["python"]))
    with pytest.raises(family.FamilyContractError, match="indeterminate reasons"):
        replace(contract, indeterminate_reasons=cast(tuple[str, ...], ["unsupported_scope"]))


def test_record_refuses_unsupported_family_ecosystem_and_schema_without_fallback() -> None:
    contract = _contract()
    record = _record(contract)
    with pytest.raises(family.UnsupportedFamilyScope, match="family"):
        family.validate_record(replace(contract, family_id="different"), record)
    with pytest.raises(family.UnsupportedFamilyScope, match="ecosystem"):
        family.validate_record(contract, _record(contract, ecosystem="javascript"))
    with pytest.raises(family.UnsupportedFamilyScope, match="schema"):
        family.validate_record(replace(contract, schema_version="other-schema"), record)


def test_record_refuses_unknown_and_mistyped_family_fields() -> None:
    contract = _contract()
    unknown = (semantics.FieldValue("other", semantics.FieldKind.TEXT, "read"),)
    wrong_type = (semantics.FieldValue("operation", semantics.FieldKind.INTEGER, 7),)
    with pytest.raises(family.FamilyContractError, match="field"):
        family.validate_record(contract, _record(contract, family_fields=unknown))
    with pytest.raises(family.FamilyContractError, match="kind"):
        family.validate_record(contract, _record(contract, family_fields=wrong_type))
    with pytest.raises(family.FamilyContractError, match="required"):
        family.validate_record(contract, _record(contract, family_fields=()))


def _record_with_packet(record: evidence.EvidenceRecord, packet: evidence.EvidencePacket) -> evidence.EvidenceRecord:
    decision = replace(record.decision, packet_digest=evidence.derive_packet_digest(packet))
    return evidence.EvidenceRecord(packet, decision, "")


def test_record_refuses_substituted_security_object_identity() -> None:
    contract = _contract()
    record = _record(contract)
    substituted = replace(record.packet, security_object_id=_digest("other-object"))
    with pytest.raises(family.FamilyContractError, match="security object identity"):
        family.validate_record(contract, _record_with_packet(record, substituted))


def test_identity_field_change_cannot_reuse_the_old_security_object_identity() -> None:
    contract = _contract()
    record = _record(contract)
    changed = replace(
        record.packet,
        family_fields=(semantics.FieldValue("operation", semantics.FieldKind.TEXT, "write"),),
    )
    with pytest.raises(family.FamilyContractError, match="security object identity"):
        family.validate_record(contract, _record_with_packet(record, changed))


def test_nonidentity_field_change_does_not_redirect_security_object_identity() -> None:
    contract = _contract()
    display = family.FieldSpec("display_name", semantics.FieldKind.TEXT, False)
    extended = replace(
        contract,
        security_object=replace(contract.security_object, fields=contract.security_object.fields + (display,)),
    )
    first = _record(
        extended,
        family_fields=(
            semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),
            semantics.FieldValue("display_name", semantics.FieldKind.TEXT, "first"),
        ),
    )
    second = _record(
        extended,
        family_fields=(
            semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),
            semantics.FieldValue("display_name", semantics.FieldKind.TEXT, "second"),
        ),
    )
    family.validate_record(extended, first)
    family.validate_record(extended, second)
    assert first.packet.security_object_id == second.packet.security_object_id


def test_security_object_identity_uses_declared_field_order_not_input_order() -> None:
    spec = family.ObjectSpec(
        "operation",
        (
            family.FieldSpec("operation", semantics.FieldKind.TEXT, True),
            family.FieldSpec("arity", semantics.FieldKind.INTEGER, True),
        ),
        ("operation", "arity"),
    )
    values = (
        semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),
        semantics.FieldValue("arity", semantics.FieldKind.INTEGER, 1),
    )
    assert family.derive_security_object_id(spec, values) == family.derive_security_object_id(spec, tuple(reversed(values)))
    reversed_spec = replace(spec, identity_fields=("arity", "operation"))
    assert family.derive_security_object_id(spec, values) != family.derive_security_object_id(reversed_spec, values)


def test_record_refuses_unknown_roles_relation_kinds_and_observation_fields() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="role"):
        family.validate_record(contract, _record(contract, relation=_relation(role="other")))
    wrong_kind = replace(_relation(), kind=semantics.RelationKind.CALL, relation_id="")
    with pytest.raises(family.FamilyContractError, match="kind"):
        family.validate_record(contract, _record(contract, relation=wrong_kind))
    with pytest.raises(family.FamilyContractError, match="field"):
        family.validate_record(contract, _record(contract, observation=_observation(field_name="other")))


def test_record_refuses_unknown_decision_and_outcome_mapping() -> None:
    contract = _contract()
    with pytest.raises(family.FamilyContractError, match="decision"):
        family.validate_record(contract, _record(contract, code="other"))
    record = _record(contract)
    wrong = replace(record, decision=replace(record.decision, outcome=evidence.NeutralOutcome.SATISFIED), record_id="")
    with pytest.raises(family.FamilyContractError, match="outcome"):
        family.validate_record(contract, wrong)


def test_indeterminate_reasons_must_be_declared() -> None:
    contract = _contract()
    relation = _relation(status=semantics.RelationStatus.INCOMPLETE)
    record = _record(contract, relation=relation, code="unknown")
    family.validate_record(contract, record)
    changed = replace(contract, indeterminate_reasons=("other",))
    with pytest.raises(family.FamilyContractError, match="reason"):
        family.validate_record(changed, _record(changed, relation=relation, code="unknown"))


def test_determinate_rule_requires_every_role_and_allowed_status() -> None:
    contract = _contract()
    missing = replace(_record(contract).packet, observations=())
    decision = replace(_record(contract).decision, packet_digest=evidence.derive_packet_digest(missing))
    record = evidence.EvidenceRecord(missing, decision, "")
    with pytest.raises(family.FamilyContractError, match="required role"):
        family.validate_record(contract, record)


def test_excluded_dependency_complete_relation_requires_reviewed_fact() -> None:
    contract = _contract(fact_only=True)
    with pytest.raises(family.FamilyContractError, match="reviewed semantic fact"):
        family.validate_record(contract, _record(contract))
    family.validate_record(contract, _record(contract, relation=_relation(origin=_fact())))


def test_missing_reviewed_dependency_is_named_incomplete_not_product_complete() -> None:
    contract = _contract(fact_only=True)
    relation = _relation(status=semantics.RelationStatus.INCOMPLETE)
    family.validate_record(contract, _record(contract, relation=relation, code="unknown"))
    wrong_reason = replace(relation, reasons=("different",), relation_id="")
    packet = replace(
        _packet(contract, relation=wrong_reason),
        completeness_reasons=("different",),
    )
    decision = evidence.Decision(
        "unknown",
        evidence.NeutralOutcome.INDETERMINATE,
        evidence.EvidenceBasis.DETERMINISTIC,
        packet.scope,
        packet.completeness_reasons,
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    with pytest.raises(family.FamilyContractError, match="missing_reviewed_dependency_relation"):
        family.validate_record(contract, evidence.EvidenceRecord(packet, decision, ""))


def test_contract_digest_changes_with_every_declaration_surface() -> None:
    contract = _contract()
    variants = (
        replace(contract, family_version="1.0.1"),
        replace(contract, ecosystems=("python", "java")),
        replace(contract, indeterminate_reasons=contract.indeterminate_reasons + ("new_reason",)),
    )
    assert len({family.family_contract_digest(contract), *(family.family_contract_digest(item) for item in variants)}) == 4
