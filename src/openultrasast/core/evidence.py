"""Immutable family-neutral evidence packets and neutral decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core.provenance import DecisionProvenance, ModelCallIdentity, ProvenanceStamp
from openultrasast.core.semantics import (
    EvidenceProvenance,
    FieldValue,
    Observation,
    RelationStatus,
    SemanticNode,
    SemanticRelation,
    SourceLocation,
)

EVIDENCE_PACKET_SCHEMA = "openultrasast.detection-core.evidence-packet.v2"
EVIDENCE_RECORD_SCHEMA = "openultrasast.detection-core.evidence-record.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class EvidenceValidationError(ValueError):
    """An evidence packet or decision violates the neutral core contract."""


class NeutralOutcome(Enum):
    VIOLATION = "violation"
    SATISFIED = "satisfied"
    INDETERMINATE = "indeterminate"


class EvidenceBasis(Enum):
    DETERMINISTIC = "deterministic"
    MODEL_CORROBORATED = "model_corroborated"
    EXECUTION_BACKED = "execution_backed"


def _require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise EvidenceValidationError(f"{field} must be nonempty text")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EvidenceValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _require_text_tuple(value: object, field: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, str) and item for item in value):
        raise EvidenceValidationError(f"{field} must be a tuple of nonempty text")
    try:
        canonical.require_unique_identities(value, kind=field)
    except canonical.DuplicateIdentityError as exc:
        raise EvidenceValidationError(str(exc)) from exc


@dataclass(frozen=True)
class SourceRegion:
    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        _require_text(self.path, "path")
        for value, field in ((self.start_line, "start_line"), (self.end_line, "end_line")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise EvidenceValidationError(f"{field} must be a positive line number")
        if self.end_line < self.start_line:
            raise EvidenceValidationError("end_line must not precede start_line")


@dataclass(frozen=True)
class AnalyzedScope:
    base_revision: str
    head_revision: str
    change_digest: str
    regions: tuple[SourceRegion, ...]

    def __post_init__(self) -> None:
        _require_text(self.base_revision, "base_revision")
        _require_text(self.head_revision, "head_revision")
        _require_digest(self.change_digest, "change_digest")
        if not isinstance(self.regions, tuple) or not self.regions:
            raise EvidenceValidationError("regions must be a nonempty tuple")
        if not all(isinstance(region, SourceRegion) for region in self.regions):
            raise EvidenceValidationError("every region must be a SourceRegion")
        identities = tuple(f"{region.path}:{region.start_line}:{region.end_line}" for region in self.regions)
        try:
            canonical.require_unique_identities(identities, kind="region")
        except canonical.DuplicateIdentityError as exc:
            raise EvidenceValidationError(str(exc)) from exc


def _location_value(location: SourceLocation) -> canonical.JsonValue:
    return {"path": location.path, "line": location.line, "column": location.column, "symbol": location.symbol}


def _node_value(node: SemanticNode) -> canonical.JsonValue:
    return {"node_id": node.node_id, "role": node.role, "location": _location_value(node.location)}


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _semantic_provenance_value(value: EvidenceProvenance) -> canonical.JsonValue:
    fact_match: canonical.JsonValue = None if value.fact_match is None else _content_ref_value(value.fact_match)
    return {
        "kind": value.kind.value,
        "source_content_digest": value.source_content_digest,
        "semantic_pack_digest": value.semantic_pack_digest,
        "semantic_fact_id": value.semantic_fact_id,
        "fact_match": fact_match,
    }


def _field_value(value: FieldValue) -> canonical.JsonValue:
    return {"name": value.name, "kind": value.kind.value, "value": value.value}


def _relation_value(value: SemanticRelation) -> canonical.JsonValue:
    return {
        "relation_id": value.relation_id,
        "kind": value.kind.value,
        "role": value.role,
        "source": _node_value(value.source),
        "target": _node_value(value.target),
        "location": _location_value(value.location),
        "status": value.status.value,
        "conditions": value.conditions,
        "reasons": value.reasons,
        "provenance": _semantic_provenance_value(value.provenance),
    }


def _observation_value(value: Observation) -> canonical.JsonValue:
    return {
        "observation_id": value.observation_id,
        "role": value.role,
        "location": _location_value(value.location),
        "fields": tuple(_field_value(field) for field in value.fields),
        "status": value.status.value,
        "provenance": _semantic_provenance_value(value.provenance),
    }


def _scope_value(value: AnalyzedScope) -> canonical.JsonValue:
    return {
        "base_revision": value.base_revision,
        "head_revision": value.head_revision,
        "change_digest": value.change_digest,
        "regions": tuple({"path": region.path, "start_line": region.start_line, "end_line": region.end_line} for region in value.regions),
    }


def _stamp_value(value: ProvenanceStamp) -> canonical.JsonValue:
    return {
        "analyzer_revision": value.analyzer_revision,
        "family_contract_digest": value.family_contract_digest,
        "fact_set_digest": value.fact_set_digest,
        "acquisition_record_digest": value.acquisition_record_digest,
        "configuration_digest": value.configuration_digest,
        "population_digest": value.population_digest,
        "change_input_digest": value.change_input_digest,
    }


@dataclass(frozen=True)
class EvidencePacket:
    schema_version: str
    family_id: str
    family_contract_digest: str
    security_object_id: str
    ecosystem: str
    scope: AnalyzedScope
    transitions: tuple[SemanticRelation, ...]
    observations: tuple[Observation, ...]
    family_fields: tuple[FieldValue, ...]
    completeness_reasons: tuple[str, ...]
    provenance: ProvenanceStamp

    def __post_init__(self) -> None:
        _validate_packet(self)


def _validate_packet(packet: EvidencePacket) -> None:
    if packet.schema_version != EVIDENCE_PACKET_SCHEMA:
        raise EvidenceValidationError(f"unknown evidence packet schema: {packet.schema_version!r}")
    for value, field in (
        (packet.family_id, "family_id"),
        (packet.security_object_id, "security_object_id"),
        (packet.ecosystem, "ecosystem"),
    ):
        _require_text(value, field)
    _require_digest(packet.family_contract_digest, "family_contract_digest")
    if not isinstance(packet.scope, AnalyzedScope):
        raise EvidenceValidationError("scope must be an AnalyzedScope")
    _validate_packet_members(packet)
    _validate_completeness(packet)
    if not isinstance(packet.provenance, ProvenanceStamp):
        raise EvidenceValidationError("provenance must be a ProvenanceStamp")
    if packet.provenance.family_contract_digest != packet.family_contract_digest:
        raise EvidenceValidationError("packet family contract digest does not match provenance")


def _validate_packet_members(packet: EvidencePacket) -> None:
    members = (
        (packet.transitions, SemanticRelation, "relation", "relation_id"),
        (packet.observations, Observation, "observation", "observation_id"),
        (packet.family_fields, FieldValue, "family field", "name"),
    )
    for values, expected_type, kind, identity_field in members:
        if not isinstance(values, tuple) or not all(isinstance(value, expected_type) for value in values):
            raise EvidenceValidationError(f"{kind} values must be a tuple of {expected_type.__name__}")
        try:
            canonical.require_unique_identities(tuple(getattr(value, identity_field) for value in values), kind=kind)
        except canonical.DuplicateIdentityError as exc:
            raise EvidenceValidationError(str(exc)) from exc


def _validate_completeness(packet: EvidencePacket) -> None:
    _require_text_tuple(packet.completeness_reasons, "completeness reason")
    relations_incomplete = any(item.status is not RelationStatus.COMPLETE for item in packet.transitions)
    observations_incomplete = any(item.status is not RelationStatus.COMPLETE for item in packet.observations)
    if (relations_incomplete or observations_incomplete) and not packet.completeness_reasons:
        raise EvidenceValidationError("non-complete semantics require named completeness reasons")
    relation_reasons = {reason for relation in packet.transitions for reason in relation.reasons}
    if not relation_reasons.issubset(packet.completeness_reasons):
        raise EvidenceValidationError("every non-complete relation reason must be named in packet completeness")


def _packet_value(packet: EvidencePacket) -> canonical.JsonValue:
    return {
        "schema_version": packet.schema_version,
        "family_id": packet.family_id,
        "family_contract_digest": packet.family_contract_digest,
        "security_object_id": packet.security_object_id,
        "ecosystem": packet.ecosystem,
        "scope": _scope_value(packet.scope),
        "transitions": tuple(_relation_value(item) for item in packet.transitions),
        "observations": tuple(_observation_value(item) for item in packet.observations),
        "family_fields": tuple(_field_value(item) for item in packet.family_fields),
        "completeness_reasons": packet.completeness_reasons,
        "provenance": _stamp_value(packet.provenance),
    }


def derive_packet_digest(packet: EvidencePacket) -> str:
    if not isinstance(packet, EvidencePacket):
        raise EvidenceValidationError("packet must be an EvidencePacket")
    return canonical.content_digest(_packet_value(packet))


def _model_identity_value(value: ModelCallIdentity) -> canonical.JsonValue:
    return {
        "provider": value.provider,
        "model": value.model,
        "program_digest": value.program_digest,
        "prompt_digest": value.prompt_digest,
        "configuration_digest": value.configuration_digest,
        "adapter_revision": value.adapter_revision,
    }


def _decision_provenance_value(value: DecisionProvenance) -> canonical.JsonValue:
    model: canonical.JsonValue = None if value.model_identity is None else _model_identity_value(value.model_identity)
    return {
        "model_identity": model,
        "model_result_digest": value.model_result_digest,
        "model_declaration_digest": value.model_declaration_digest,
        "proof_record_digest": value.proof_record_digest,
        "proof_producer_digest": value.proof_producer_digest,
        "lineage_manifest_digest": value.lineage_manifest_digest,
    }


@dataclass(frozen=True)
class Decision:
    family_code: str
    outcome: NeutralOutcome
    basis: EvidenceBasis
    bounded_scope: AnalyzedScope
    reasons: tuple[str, ...]
    packet_digest: str
    provenance: DecisionProvenance

    def __post_init__(self) -> None:
        _require_text(self.family_code, "family_code")
        if not isinstance(self.outcome, NeutralOutcome):
            raise EvidenceValidationError("outcome must be a NeutralOutcome")
        if not isinstance(self.basis, EvidenceBasis):
            raise EvidenceValidationError("basis must be an EvidenceBasis")
        if not isinstance(self.bounded_scope, AnalyzedScope):
            raise EvidenceValidationError("bounded_scope must be an AnalyzedScope")
        _require_text_tuple(self.reasons, "decision reason")
        _require_digest(self.packet_digest, "packet_digest")
        if not isinstance(self.provenance, DecisionProvenance):
            raise EvidenceValidationError("provenance must be DecisionProvenance")
        _validate_basis(self.basis, self.provenance)


def _validate_basis(basis: EvidenceBasis, value: DecisionProvenance) -> None:
    model = (value.model_identity, value.model_result_digest, value.model_declaration_digest, value.lineage_manifest_digest)
    proof = (value.proof_record_digest, value.proof_producer_digest)
    if basis is EvidenceBasis.DETERMINISTIC and any(item is not None for item in (*model, *proof)):
        raise EvidenceValidationError("deterministic basis forbids model, proof, and lineage provenance")
    if basis is EvidenceBasis.MODEL_CORROBORATED and (any(item is None for item in model) or any(item is not None for item in proof)):
        raise EvidenceValidationError("model-corroborated basis requires complete model provenance and forbids proof provenance")
    if basis is EvidenceBasis.EXECUTION_BACKED and (any(item is None for item in proof) or any(item is not None for item in model)):
        raise EvidenceValidationError("execution-backed basis requires complete proof provenance and forbids model provenance")


def _decision_value(decision: Decision) -> canonical.JsonValue:
    return {
        "family_code": decision.family_code,
        "outcome": decision.outcome.value,
        "basis": decision.basis.value,
        "bounded_scope": _scope_value(decision.bounded_scope),
        "reasons": decision.reasons,
        "packet_digest": decision.packet_digest,
        "provenance": _decision_provenance_value(decision.provenance),
    }


def _scope_within(bounded: AnalyzedScope, analyzed: AnalyzedScope) -> bool:
    if (bounded.base_revision, bounded.head_revision, bounded.change_digest) != (
        analyzed.base_revision,
        analyzed.head_revision,
        analyzed.change_digest,
    ):
        return False
    return all(region in analyzed.regions for region in bounded.regions)


@dataclass(frozen=True)
class EvidenceRecord:
    packet: EvidencePacket
    decision: Decision
    record_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.packet, EvidencePacket) or not isinstance(self.decision, Decision):
            raise EvidenceValidationError("record requires an EvidencePacket and Decision")
        _validate_record_pair(self.packet, self.decision)
        expected = derive_record_id(self.packet, self.decision)
        if not self.record_id:
            object.__setattr__(self, "record_id", expected)
        elif self.record_id != expected:
            raise EvidenceValidationError("record_id does not match canonical record fields")


def _validate_record_pair(packet: EvidencePacket, decision: Decision) -> None:
    if decision.packet_digest != derive_packet_digest(packet):
        raise EvidenceValidationError("decision packet digest does not match packet")
    if not _scope_within(decision.bounded_scope, packet.scope):
        raise EvidenceValidationError("decision bounded scope is outside analyzed packet scope")
    noncomplete = any(item.status is not RelationStatus.COMPLETE for item in packet.transitions) or any(
        item.status is not RelationStatus.COMPLETE for item in packet.observations
    )
    if decision.outcome is not NeutralOutcome.INDETERMINATE and (packet.completeness_reasons or noncomplete):
        raise EvidenceValidationError("non-complete semantics or completeness reasons forbid a determinate outcome")
    if decision.outcome is NeutralOutcome.INDETERMINATE:
        if not decision.reasons:
            raise EvidenceValidationError("indeterminate outcome requires a named reason")
        if not set(packet.completeness_reasons).issubset(decision.reasons):
            raise EvidenceValidationError("indeterminate reasons must include every packet completeness reason")
    elif decision.reasons:
        raise EvidenceValidationError("determinate outcomes must not carry indeterminate reasons")


def _record_value(packet: EvidencePacket, decision: Decision) -> canonical.JsonValue:
    return {
        "schema_version": EVIDENCE_RECORD_SCHEMA,
        "packet": _packet_value(packet),
        "decision": _decision_value(decision),
    }


def derive_record_id(packet: EvidencePacket, decision: Decision) -> str:
    return canonical.content_digest(_record_value(packet, decision))


def evidence_record_bytes(record: EvidenceRecord) -> bytes:
    if not isinstance(record, EvidenceRecord):
        raise EvidenceValidationError("record must be an EvidenceRecord")
    return canonical.canonical_bytes(_record_value(record.packet, record.decision))


__all__ = [
    "AnalyzedScope",
    "Decision",
    "EVIDENCE_PACKET_SCHEMA",
    "EVIDENCE_RECORD_SCHEMA",
    "EvidenceBasis",
    "EvidencePacket",
    "EvidenceRecord",
    "EvidenceValidationError",
    "NeutralOutcome",
    "SourceRegion",
    "derive_packet_digest",
    "derive_record_id",
    "evidence_record_bytes",
]
