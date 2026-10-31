"""Immutable evidence packet and neutral decision contracts."""

from __future__ import annotations

import json
from dataclasses import fields, replace
from enum import Enum
from typing import cast

import pytest

import openultrasast.core.canonical as canonical
import openultrasast.core.evidence as evidence
import openultrasast.core.provenance as provenance
import openultrasast.core.semantics as semantics


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _location(line: int = 7) -> semantics.SourceLocation:
    return semantics.SourceLocation("src/app.py", line, 2, "handle")


def _product_provenance() -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(
        semantics.ProvenanceKind.PRODUCT_CODE,
        _digest("source"),
        None,
        None,
        None,
    )


def _relation(status: semantics.RelationStatus = semantics.RelationStatus.COMPLETE) -> semantics.SemanticRelation:
    source = semantics.SemanticNode("request", "request", _location())
    target = semantics.SemanticNode("resource", "resource", _location(8))
    reasons = () if status is semantics.RelationStatus.COMPLETE else (f"relation:{status.value}",)
    return semantics.make_relation(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role="authorization_constraint",
        source=source,
        target=target,
        location=_location(9),
        status=status,
        conditions=("authenticated",),
        reasons=reasons,
        provenance=_product_provenance(),
    )


def _observation(status: semantics.RelationStatus = semantics.RelationStatus.COMPLETE) -> semantics.Observation:
    return semantics.make_observation(
        role="security_object",
        location=_location(10),
        fields=(semantics.FieldValue("kind", semantics.FieldKind.TEXT, "resource"),),
        status=status,
        provenance=_product_provenance(),
    )


def _scope(*regions: evidence.SourceRegion) -> evidence.AnalyzedScope:
    selected = regions or (evidence.SourceRegion("src/app.py", 1, 20),)
    return evidence.AnalyzedScope("base", "head", _digest("change"), selected)


def _stamp() -> provenance.ProvenanceStamp:
    return provenance.ProvenanceStamp(
        *(
            _digest(name)
            for name in (
                "analyzer",
                "family-contract",
                "facts",
                "acquisition",
                "configuration",
                "population",
                "change-input",
            )
        )
    )


def _packet(
    *,
    status: semantics.RelationStatus = semantics.RelationStatus.COMPLETE,
    completeness: tuple[str, ...] | None = None,
    transitions: tuple[semantics.SemanticRelation, ...] | None = None,
) -> evidence.EvidencePacket:
    relation = _relation(status)
    reasons = () if status is semantics.RelationStatus.COMPLETE else relation.reasons
    return evidence.EvidencePacket(
        schema_version=evidence.EVIDENCE_PACKET_SCHEMA,
        family_id="access-control",
        family_contract_digest=_digest("family-contract"),
        security_object_id="resource:42",
        ecosystem="python",
        scope=_scope(),
        transitions=(relation,) if transitions is None else transitions,
        observations=(_observation(),),
        family_fields=(semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),),
        completeness_reasons=reasons if completeness is None else completeness,
        provenance=_stamp(),
    )


def _empty_decision_provenance() -> provenance.DecisionProvenance:
    return provenance.DecisionProvenance(None, None, None, None, None, None)


def _decision(
    packet: evidence.EvidencePacket,
    *,
    outcome: evidence.NeutralOutcome = evidence.NeutralOutcome.VIOLATION,
    basis: evidence.EvidenceBasis = evidence.EvidenceBasis.DETERMINISTIC,
    reasons: tuple[str, ...] = (),
    bounded_scope: evidence.AnalyzedScope | None = None,
    decision_provenance: provenance.DecisionProvenance | None = None,
) -> evidence.Decision:
    return evidence.Decision(
        family_code="unauthorized_access",
        outcome=outcome,
        basis=basis,
        bounded_scope=packet.scope if bounded_scope is None else bounded_scope,
        reasons=reasons,
        packet_digest=evidence.derive_packet_digest(packet),
        provenance=_empty_decision_provenance() if decision_provenance is None else decision_provenance,
    )


def _record(
    *,
    packet: evidence.EvidencePacket | None = None,
    outcome: evidence.NeutralOutcome = evidence.NeutralOutcome.VIOLATION,
    basis: evidence.EvidenceBasis = evidence.EvidenceBasis.DETERMINISTIC,
    reasons: tuple[str, ...] = (),
    bounded_scope: evidence.AnalyzedScope | None = None,
    decision_provenance: provenance.DecisionProvenance | None = None,
) -> evidence.EvidenceRecord:
    selected = _packet() if packet is None else packet
    decision = _decision(
        selected,
        outcome=outcome,
        basis=basis,
        reasons=reasons,
        bounded_scope=bounded_scope,
        decision_provenance=decision_provenance,
    )
    return evidence.EvidenceRecord(selected, decision, "")


@pytest.mark.parametrize("outcome", [evidence.NeutralOutcome.VIOLATION, evidence.NeutralOutcome.SATISFIED])
def test_determinate_records_round_trip_canonically(outcome: evidence.NeutralOutcome) -> None:
    record = _record(outcome=outcome)
    content = evidence.evidence_record_bytes(record)
    parsed = json.loads(content)

    assert len(content) > 0
    assert json.dumps(parsed, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode() == content
    assert record.record_id == canonical.bytes_digest(content)
    assert parsed["decision"]["family_code"] == "unauthorized_access"
    assert parsed["decision"]["outcome"] == outcome.value
    assert parsed["packet"]["family_id"] == "access-control"


def test_incomplete_record_round_trips_as_named_indeterminate() -> None:
    packet = _packet(status=semantics.RelationStatus.INCOMPLETE)
    record = _record(
        packet=packet,
        outcome=evidence.NeutralOutcome.INDETERMINATE,
        reasons=packet.completeness_reasons,
    )
    parsed = json.loads(evidence.evidence_record_bytes(record))

    assert parsed["decision"]["outcome"] == "indeterminate"
    assert parsed["decision"]["reasons"] == ["relation:incomplete"]


def test_packet_preserves_ordered_semantics_and_family_fields() -> None:
    first = _relation()
    second = replace(first, location=_location(11), relation_id="")
    forward = _packet(transitions=(first, second))
    reverse = _packet(transitions=(second, first))

    assert forward.transitions == (first, second)
    assert evidence.derive_packet_digest(forward) != evidence.derive_packet_digest(reverse)
    assert forward.family_fields[0].name == "operation"


@pytest.mark.parametrize("status", [semantics.RelationStatus.INCOMPLETE, semantics.RelationStatus.UNRESOLVED])
@pytest.mark.parametrize("outcome", [evidence.NeutralOutcome.VIOLATION, evidence.NeutralOutcome.SATISFIED])
def test_noncomplete_semantics_cannot_produce_determinate_outcome(
    status: semantics.RelationStatus,
    outcome: evidence.NeutralOutcome,
) -> None:
    packet = _packet(status=status)
    with pytest.raises(evidence.EvidenceValidationError, match="non-complete|completeness"):
        _record(packet=packet, outcome=outcome)


def test_packet_requires_every_noncomplete_reason_to_be_named() -> None:
    with pytest.raises(evidence.EvidenceValidationError, match="completeness"):
        _packet(status=semantics.RelationStatus.INCOMPLETE, completeness=())


def test_noncomplete_observation_also_forces_indeterminate_outcome() -> None:
    packet = replace(
        _packet(),
        observations=(_observation(semantics.RelationStatus.UNRESOLVED),),
        completeness_reasons=("observation:unresolved",),
    )
    with pytest.raises(evidence.EvidenceValidationError, match="non-complete"):
        _record(packet=packet, outcome=evidence.NeutralOutcome.VIOLATION)


def test_indeterminate_requires_reasons_and_carries_every_packet_reason() -> None:
    packet = _packet(status=semantics.RelationStatus.INCOMPLETE)
    with pytest.raises(evidence.EvidenceValidationError, match="reason"):
        _record(packet=packet, outcome=evidence.NeutralOutcome.INDETERMINATE)
    with pytest.raises(evidence.EvidenceValidationError, match="completeness"):
        _record(packet=packet, outcome=evidence.NeutralOutcome.INDETERMINATE, reasons=("different",))


def test_satisfaction_requires_nonempty_bounded_scope_within_packet_scope() -> None:
    packet = _packet()
    with pytest.raises(evidence.EvidenceValidationError, match="bounded scope"):
        _record(
            packet=packet,
            outcome=evidence.NeutralOutcome.SATISFIED,
            bounded_scope=_scope(evidence.SourceRegion("src/other.py", 1, 2)),
        )
    outside = evidence.AnalyzedScope("base", "head", _digest("other-change"), packet.scope.regions)
    with pytest.raises(evidence.EvidenceValidationError, match="bounded scope"):
        _record(packet=packet, outcome=evidence.NeutralOutcome.SATISFIED, bounded_scope=outside)


def test_satisfaction_accepts_an_exact_nonempty_subset_scope() -> None:
    packet = replace(
        _packet(),
        scope=_scope(evidence.SourceRegion("src/app.py", 1, 10), evidence.SourceRegion("src/app.py", 20, 30)),
    )
    bounded = _scope(evidence.SourceRegion("src/app.py", 1, 10))
    record = _record(packet=packet, outcome=evidence.NeutralOutcome.SATISFIED, bounded_scope=bounded)
    assert record.decision.bounded_scope == bounded


def _model_provenance() -> provenance.DecisionProvenance:
    identity = provenance.ModelCallIdentity(
        provider="provider",
        model="model",
        program_digest=_digest("program"),
        prompt_digest=_digest("prompt"),
        configuration_digest=_digest("model-configuration"),
        adapter_revision="adapter-v1",
    )
    return provenance.DecisionProvenance(
        identity,
        _digest("model-result"),
        _digest("model-declaration"),
        None,
        None,
        _digest("lineage"),
    )


def _proof_provenance() -> provenance.DecisionProvenance:
    return provenance.DecisionProvenance(None, None, None, _digest("proof"), _digest("producer"), None)


@pytest.mark.parametrize(
    ("basis", "decision_provenance"),
    [
        (evidence.EvidenceBasis.DETERMINISTIC, _empty_decision_provenance()),
        (evidence.EvidenceBasis.MODEL_CORROBORATED, _model_provenance()),
        (evidence.EvidenceBasis.EXECUTION_BACKED, _proof_provenance()),
    ],
)
def test_every_closed_evidence_basis_accepts_only_its_complete_provenance(
    basis: evidence.EvidenceBasis,
    decision_provenance: provenance.DecisionProvenance,
) -> None:
    record = _record(basis=basis, decision_provenance=decision_provenance)
    assert record.decision.basis is basis


@pytest.mark.parametrize(
    ("basis", "decision_provenance"),
    [
        (evidence.EvidenceBasis.DETERMINISTIC, _model_provenance()),
        (evidence.EvidenceBasis.DETERMINISTIC, _proof_provenance()),
        (evidence.EvidenceBasis.MODEL_CORROBORATED, _empty_decision_provenance()),
        (evidence.EvidenceBasis.MODEL_CORROBORATED, replace(_model_provenance(), model_result_digest=None)),
        (evidence.EvidenceBasis.EXECUTION_BACKED, _empty_decision_provenance()),
        (evidence.EvidenceBasis.EXECUTION_BACKED, replace(_proof_provenance(), proof_producer_digest=None)),
        (evidence.EvidenceBasis.EXECUTION_BACKED, _model_provenance()),
    ],
)
def test_basis_provenance_is_a_closed_union(
    basis: evidence.EvidenceBasis,
    decision_provenance: provenance.DecisionProvenance,
) -> None:
    with pytest.raises(evidence.EvidenceValidationError, match="basis|provenance"):
        _record(basis=basis, decision_provenance=decision_provenance)


def test_packet_has_no_model_or_proof_fields() -> None:
    names = {item.name for item in fields(evidence.EvidencePacket)}
    assert not any("model" in name or "proof" in name for name in names)
    assert {"model_identity", "proof_record_digest"} <= {item.name for item in fields(provenance.DecisionProvenance)}


def test_decision_is_bound_to_exact_packet_digest_and_record_identity() -> None:
    record = _record()
    with pytest.raises(evidence.EvidenceValidationError, match="packet digest"):
        replace(record, decision=replace(record.decision, packet_digest=_digest("other")), record_id="")
    with pytest.raises(evidence.EvidenceValidationError, match="record_id"):
        replace(record, record_id="0" * 64)


def test_packet_rejects_duplicate_logical_identities() -> None:
    relation = _relation()
    with pytest.raises(evidence.EvidenceValidationError, match="duplicate"):
        _packet(transitions=(relation, relation))
    packet = _packet()
    with pytest.raises(evidence.EvidenceValidationError, match="duplicate"):
        replace(packet, family_fields=(packet.family_fields[0], packet.family_fields[0]))


def test_scope_and_text_contracts_are_runtime_checked() -> None:
    with pytest.raises(evidence.EvidenceValidationError, match="line"):
        evidence.SourceRegion("src/app.py", 9, 8)
    with pytest.raises(evidence.EvidenceValidationError, match="region"):
        evidence.AnalyzedScope("base", "head", _digest("change"), ())
    packet = _packet()
    with pytest.raises(evidence.EvidenceValidationError, match="family_id"):
        replace(packet, family_id=cast(str, 7))


def test_unknown_runtime_enums_and_schema_are_refused() -> None:
    packet = _packet()
    with pytest.raises(evidence.EvidenceValidationError, match="schema"):
        replace(packet, schema_version="unknown")

    class ForeignOutcome(Enum):
        VIOLATION = "violation"

    with pytest.raises(evidence.EvidenceValidationError, match="NeutralOutcome"):
        replace(_decision(packet), outcome=cast(evidence.NeutralOutcome, ForeignOutcome.VIOLATION))
