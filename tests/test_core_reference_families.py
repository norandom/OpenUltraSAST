"""Two unlike family fixtures exercise the same neutral core validators."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import fields
from pathlib import Path
from typing import cast

import pytest

import openultrasast.core.canonical as canonical
import openultrasast.core.evidence as evidence
import openultrasast.core.family as family
import openultrasast.core.provenance as provenance
import openultrasast.core.semantics as semantics

FIXTURES = Path(__file__).parent / "fixtures" / "detection_core"


class ReferenceFixtureError(ValueError):
    """A reference case's claimed result contradicts its authored semantics."""


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _load(name: str) -> dict[str, object]:
    path = FIXTURES / name
    payload = path.read_bytes()
    assert len(payload) > 0, f"fixture instrument must read nonzero bytes: {path}"
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    return cast(dict[str, object], parsed)


def _field_spec(raw: object) -> family.FieldSpec:
    value = cast(dict[str, object], raw)
    return family.FieldSpec(str(value["name"]), semantics.FieldKind(str(value["kind"])), bool(value["required"]))


def _contract(raw: dict[str, object]) -> family.FamilyContract:
    security_object = cast(dict[str, object], raw["security_object"])
    roles = cast(list[dict[str, object]], raw["roles"])
    decisions = cast(list[dict[str, object]], raw["decisions"])
    questions = cast(list[dict[str, object]], raw["residual_questions"])
    return family.FamilyContract(
        family_id=str(raw["family_id"]),
        family_version=str(raw["family_version"]),
        schema_version=str(raw["schema_version"]),
        ecosystems=tuple(cast(list[str], raw["ecosystems"])),
        security_object=family.ObjectSpec(
            kind=str(security_object["kind"]),
            fields=tuple(_field_spec(item) for item in cast(list[object], security_object["fields"])),
            identity_fields=tuple(cast(list[str], security_object["identity_fields"])),
        ),
        roles=tuple(
            family.RoleSpec(
                role=str(role["role"]),
                fields=tuple(_field_spec(item) for item in cast(list[object], role["fields"])),
                allowed_relation_kinds=tuple(semantics.RelationKind(item) for item in cast(list[str], role["allowed_relation_kinds"])),
                origin_policy=family.RelationOriginPolicy(str(role["origin_policy"])),
            )
            for role in roles
        ),
        decisions=tuple(
            family.DecisionRule(
                family_code=str(rule["family_code"]),
                outcome=evidence.NeutralOutcome(str(rule["outcome"])),
                required_roles=tuple(cast(list[str], rule["required_roles"])),
                allowed_statuses=tuple(semantics.RelationStatus(item) for item in cast(list[str], rule["allowed_statuses"])),
            )
            for rule in decisions
        ),
        residual_questions=tuple(
            family.ResidualQuestion(
                question_id=str(question["question_id"]),
                required_roles=tuple(cast(list[str], question["required_roles"])),
                allowed_decisions=tuple(cast(list[str], question["allowed_decisions"])),
            )
            for question in questions
        ),
        indeterminate_reasons=tuple(cast(list[str], raw["indeterminate_reasons"])),
    )


def _location(path: str, line: int, symbol: str) -> semantics.SourceLocation:
    return semantics.SourceLocation(path, line, 0, symbol)


def _product(seed: str) -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(semantics.ProvenanceKind.PRODUCT_CODE, _digest(seed), None, None, None)


def _fields(raw: object) -> tuple[semantics.FieldValue, ...]:
    return tuple(
        semantics.FieldValue(str(item["name"]), semantics.FieldKind(str(item["kind"])), cast(canonical.JsonValue, item["value"]))
        for item in cast(list[dict[str, object]], raw)
    )


def _relation(raw: dict[str, object], path: str, offset: int) -> semantics.SemanticRelation:
    status = semantics.RelationStatus(str(raw["status"]))
    source = cast(dict[str, str], raw["source"])
    target = cast(dict[str, str], raw["target"])
    location = _location(path, offset, str(raw["role"]))
    return semantics.make_relation(
        kind=semantics.RelationKind(str(raw["kind"])),
        role=str(raw["role"]),
        source=semantics.SemanticNode(source["id"], source["role"], location),
        target=semantics.SemanticNode(target["id"], target["role"], _location(path, offset + 1, target["role"])),
        location=location,
        status=status,
        conditions=tuple(cast(list[str], raw["conditions"])),
        reasons=tuple(cast(list[str], raw["reasons"])),
        provenance=_product(f"relation:{path}:{offset}"),
    )


def _observation(raw: dict[str, object], path: str, offset: int) -> semantics.Observation:
    return semantics.make_observation(
        role=str(raw["role"]),
        location=_location(path, offset, str(raw["role"])),
        fields=_fields(raw["fields"]),
        status=semantics.RelationStatus(str(raw["status"])),
        provenance=_product(f"observation:{path}:{offset}"),
    )


def _stamp(contract: family.FamilyContract, case_id: str) -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        _digest("reference-analyzer"),
        family.family_contract_digest(contract),
        _digest("empty-fact-set"),
        _digest("authored-fixture-acquisition"),
        _digest("reference-configuration"),
        _digest("reference-population"),
        _digest(case_id),
    )


def _single_relation(transitions: tuple[semantics.SemanticRelation, ...], role: str) -> semantics.SemanticRelation:
    matches = tuple(item for item in transitions if item.role == role)
    if len(matches) != 1:
        raise ReferenceFixtureError(f"expected exactly one {role} relation")
    return matches[0]


def _single_observation(observations: tuple[semantics.Observation, ...], role: str) -> semantics.Observation:
    matches = tuple(item for item in observations if item.role == role)
    if len(matches) != 1:
        raise ReferenceFixtureError(f"expected exactly one {role} observation")
    return matches[0]


def _derive_obligation_claim(
    transitions: tuple[semantics.SemanticRelation, ...],
    observations: tuple[semantics.Observation, ...],
) -> tuple[str, evidence.NeutralOutcome]:
    if len(transitions) != 2:
        raise ReferenceFixtureError("obligation cases require operation and constraint relations")
    operation = _single_relation(transitions, "operation")
    constraint = _single_relation(transitions, "constraint")
    _single_observation(observations, "security_object")
    if operation.kind is not semantics.RelationKind.OPERATION_EFFECT:
        raise ReferenceFixtureError("operation relation has the wrong kind")
    if constraint.kind is not semantics.RelationKind.CONSTRAINT_EFFECT:
        raise ReferenceFixtureError("constraint relation has the wrong kind")
    if constraint.source.node_id != operation.target.node_id:
        raise ReferenceFixtureError("constraint does not apply to the authored operation")
    if any(item.status is not semantics.RelationStatus.COMPLETE for item in transitions):
        return "constraint_unknown", evidence.NeutralOutcome.INDETERMINATE
    if constraint.target.node_id == "unconstrained":
        return "constraint_exposed", evidence.NeutralOutcome.VIOLATION
    if constraint.target.node_id == "guarded":
        return "constraint_enforced", evidence.NeutralOutcome.SATISFIED
    raise ReferenceFixtureError("complete constraint has no recognized authored state")


def _transform_applied(observations: tuple[semantics.Observation, ...]) -> bool:
    transform = _single_observation(observations, "transform")
    if transform.status is not semantics.RelationStatus.COMPLETE or len(transform.fields) != 1:
        raise ReferenceFixtureError("transform observation must be complete and singular")
    field = transform.fields[0]
    if field.name != "applied" or field.kind is not semantics.FieldKind.BOOLEAN or not isinstance(field.value, bool):
        raise ReferenceFixtureError("transform observation must carry an applied boolean")
    return field.value


def _derive_taint_claim(
    transitions: tuple[semantics.SemanticRelation, ...],
    observations: tuple[semantics.Observation, ...],
) -> tuple[str, evidence.NeutralOutcome]:
    if len(transitions) != 2:
        raise ReferenceFixtureError("taint cases require exactly two ordered flow segments")
    first, second = transitions
    if any(item.role != "flow" or item.kind is not semantics.RelationKind.VALUE_TRANSFORMATION for item in transitions):
        raise ReferenceFixtureError("taint segments must be value transformations")
    if first.source.role != "source" or second.target.role != "sink":
        raise ReferenceFixtureError("taint segments are reversed or lack source/sink endpoints")
    if first.target.node_id != second.source.node_id:
        raise ReferenceFixtureError("taint segments are disconnected")
    _single_observation(observations, "source")
    _single_observation(observations, "sink")
    applied = _transform_applied(observations)
    if any(item.status is not semantics.RelationStatus.COMPLETE for item in transitions):
        return "flow_unknown", evidence.NeutralOutcome.INDETERMINATE
    if applied:
        return "flow_transformed", evidence.NeutralOutcome.SATISFIED
    return "flow_reaches_effect", evidence.NeutralOutcome.VIOLATION


def _derive_claim(
    contract: family.FamilyContract,
    transitions: tuple[semantics.SemanticRelation, ...],
    observations: tuple[semantics.Observation, ...],
) -> tuple[str, evidence.NeutralOutcome]:
    if contract.family_id == "operation-constraint":
        return _derive_obligation_claim(transitions, observations)
    if contract.family_id == "ordered-taint-flow":
        return _derive_taint_claim(transitions, observations)
    raise ReferenceFixtureError(f"no test oracle for family {contract.family_id}")


def _record(contract: family.FamilyContract, raw: dict[str, object]) -> evidence.EvidenceRecord:
    case_id = str(raw["case_id"])
    path = str(raw["path"])
    family_fields = _fields(raw["security_object"])
    transitions = tuple(_relation(item, path, 10 + index * 3) for index, item in enumerate(cast(list[dict[str, object]], raw["relations"])))
    observations = tuple(
        _observation(item, path, 50 + index) for index, item in enumerate(cast(list[dict[str, object]], raw["observations"]))
    )
    derived_decision, derived_outcome = _derive_claim(contract, transitions, observations)
    if (raw["decision"], raw["outcome"]) != (derived_decision, derived_outcome.value):
        raise ReferenceFixtureError("claimed decision/outcome contradicts authored semantics")
    reasons = tuple(cast(list[str], raw["completeness_reasons"]))
    scope = evidence.AnalyzedScope("reference-base", "reference-head", _digest(case_id), (evidence.SourceRegion(path, 1, 100),))
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        family.family_contract_digest(contract),
        family.derive_security_object_id(contract.security_object, family_fields),
        str(raw["ecosystem"]),
        scope,
        transitions,
        observations,
        family_fields,
        reasons,
        _stamp(contract, case_id),
    )
    decision = evidence.Decision(
        str(raw["decision"]),
        evidence.NeutralOutcome(str(raw["outcome"])),
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        reasons,
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, decision, "")


@pytest.mark.parametrize(
    ("family_file", "cases_file"),
    [("obligation_family.json", "obligation_cases.json"), ("taint_family.json", "taint_cases.json")],
)
def test_reference_family_triplet_uses_shared_validators(family_file: str, cases_file: str) -> None:
    contract = _contract(_load(family_file))
    cases = cast(list[dict[str, object]], _load(cases_file)["cases"])
    family.validate_contract(contract)
    records = tuple(_record(contract, case) for case in cases)
    for record in records:
        family.validate_record(contract, record)
        encoded = evidence.evidence_record_bytes(record)
        assert len(encoded) > 0
        assert json.loads(encoded)["packet"]["family_id"] == contract.family_id
    assert tuple(record.decision.outcome for record in records) == (
        evidence.NeutralOutcome.VIOLATION,
        evidence.NeutralOutcome.SATISFIED,
        evidence.NeutralOutcome.INDETERMINATE,
    )


def test_reference_families_have_materially_different_semantic_shapes() -> None:
    obligation = _contract(_load("obligation_family.json"))
    taint = _contract(_load("taint_family.json"))
    obligation_kinds = {kind for role in obligation.roles for kind in role.allowed_relation_kinds}
    taint_kinds = {kind for role in taint.roles for kind in role.allowed_relation_kinds}
    assert obligation.security_object.kind == "operation_constraint"
    assert taint.security_object.kind == "ordered_flow"
    assert obligation_kinds == {semantics.RelationKind.OPERATION_EFFECT, semantics.RelationKind.CONSTRAINT_EFFECT}
    assert taint_kinds == {semantics.RelationKind.VALUE_TRANSFORMATION}
    assert obligation_kinds.isdisjoint(taint_kinds)


def test_taint_cases_preserve_source_to_sink_transition_order() -> None:
    contract = _contract(_load("taint_family.json"))
    cases = cast(list[dict[str, object]], _load("taint_cases.json")["cases"])
    for case in cases:
        record = _record(contract, case)
        node_ids = tuple((relation.source.node_id, relation.target.node_id) for relation in record.packet.transitions)
        assert node_ids[0] == ("input", "transform")
        assert node_ids[1] == ("transform", "effect")


def test_reference_fixtures_do_not_add_family_specific_core_fields() -> None:
    assert tuple(field.name for field in fields(evidence.EvidencePacket)) == (
        "schema_version",
        "family_id",
        "family_contract_digest",
        "security_object_id",
        "ecosystem",
        "scope",
        "transitions",
        "observations",
        "family_fields",
        "completeness_reasons",
        "provenance",
    )
    fixture_text = "".join((FIXTURES / name).read_text() for name in ("obligation_family.json", "taint_family.json"))
    for forbidden in ("authorization", "access_control", "resource_authority", "target_framework"):
        assert forbidden not in fixture_text


def _mutable_case(name: str, index: int) -> dict[str, object]:
    cases = cast(list[dict[str, object]], _load(name)["cases"])
    return deepcopy(cases[index])


def test_contradictory_claimed_outcome_is_rejected_before_core_validation() -> None:
    contract = _contract(_load("obligation_family.json"))
    case = _mutable_case("obligation_cases.json", 0)
    case["outcome"] = "satisfied"
    with pytest.raises(ReferenceFixtureError):
        _record(contract, case)


def test_enforced_obligation_cannot_claim_violation() -> None:
    contract = _contract(_load("obligation_family.json"))
    case = _mutable_case("obligation_cases.json", 1)
    case["decision"] = "constraint_exposed"
    case["outcome"] = "violation"
    with pytest.raises(ReferenceFixtureError):
        _record(contract, case)


def test_applied_transform_cannot_claim_violation() -> None:
    contract = _contract(_load("taint_family.json"))
    case = _mutable_case("taint_cases.json", 1)
    case["decision"] = "flow_reaches_effect"
    case["outcome"] = "violation"
    with pytest.raises(ReferenceFixtureError):
        _record(contract, case)


def test_disconnected_flow_segment_is_rejected() -> None:
    contract = _contract(_load("taint_family.json"))
    case = _mutable_case("taint_cases.json", 0)
    relations = cast(list[dict[str, object]], case["relations"])
    cast(dict[str, str], relations[1]["source"])["id"] = "disconnected"
    with pytest.raises(ReferenceFixtureError):
        _record(contract, case)


def test_reversed_flow_segments_are_rejected() -> None:
    contract = _contract(_load("taint_family.json"))
    case = _mutable_case("taint_cases.json", 0)
    relations = cast(list[dict[str, object]], case["relations"])
    relations.reverse()
    with pytest.raises(ReferenceFixtureError):
        _record(contract, case)
