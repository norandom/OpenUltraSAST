"""Family-neutral evidence-record decoder for conformance replay."""

from __future__ import annotations

from entry_fact_core_wire import location, obj, reference, seq

from openultrasast.core import evidence, provenance, semantics


def node(value: object) -> semantics.SemanticNode:
    row = obj(value)
    return semantics.SemanticNode(row["node_id"], row["role"], location(row["location"]))


def semantic_provenance(value: object) -> semantics.EvidenceProvenance:
    row = obj(value)
    fact_match = None if row["fact_match"] is None else reference(row["fact_match"])
    return semantics.EvidenceProvenance(
        semantics.ProvenanceKind(row["kind"]),
        row["source_content_digest"],
        row["semantic_pack_digest"],
        row["semantic_fact_id"],
        fact_match,
    )


def relation(value: object) -> semantics.SemanticRelation:
    row = obj(value)
    return semantics.SemanticRelation(
        row["relation_id"],
        semantics.RelationKind(row["kind"]),
        row["role"],
        node(row["source"]),
        node(row["target"]),
        location(row["location"]),
        semantics.RelationStatus(row["status"]),
        tuple(seq(row["conditions"])),
        tuple(seq(row["reasons"])),
        semantic_provenance(row["provenance"]),
    )


def field(value: object) -> semantics.FieldValue:
    row = obj(value)
    return semantics.FieldValue(row["name"], semantics.FieldKind(row["kind"]), row["value"])


def observation(value: object) -> semantics.Observation:
    row = obj(value)
    return semantics.Observation(
        row["observation_id"],
        row["role"],
        location(row["location"]),
        tuple(field(item) for item in seq(row["fields"])),
        semantics.RelationStatus(row["status"]),
        semantic_provenance(row["provenance"]),
    )


def scope(value: object) -> evidence.AnalyzedScope:
    row = obj(value)
    return evidence.AnalyzedScope(
        row["base_revision"],
        row["head_revision"],
        row["change_digest"],
        tuple(
            evidence.SourceRegion(item["path"], item["start_line"], item["end_line"]) for raw in seq(row["regions"]) for item in (obj(raw),)
        ),
    )


def stamp(value: object) -> provenance.ProvenanceStamp:
    row = obj(value)
    return provenance.ProvenanceStamp(
        row["analyzer_revision"],
        row["family_contract_digest"],
        row["fact_set_digest"],
        row["acquisition_record_digest"],
        row["configuration_digest"],
        row["population_digest"],
        row["change_input_digest"],
    )


def packet(value: object) -> evidence.EvidencePacket:
    row = obj(value)
    return evidence.EvidencePacket(
        row["schema_version"],
        row["family_id"],
        row["family_contract_digest"],
        row["security_object_id"],
        row["ecosystem"],
        scope(row["scope"]),
        tuple(relation(item) for item in seq(row["transitions"])),
        tuple(observation(item) for item in seq(row["observations"])),
        tuple(field(item) for item in seq(row["family_fields"])),
        tuple(seq(row["completeness_reasons"])),
        stamp(row["provenance"]),
    )


def decision_provenance(value: object) -> provenance.DecisionProvenance:
    row = obj(value)
    assert row["model_identity"] is None
    return provenance.DecisionProvenance(
        None,
        row["model_result_digest"],
        row["model_declaration_digest"],
        row["proof_record_digest"],
        row["proof_producer_digest"],
        row["lineage_manifest_digest"],
    )


def decision(value: object) -> evidence.Decision:
    row = obj(value)
    return evidence.Decision(
        row["family_code"],
        evidence.NeutralOutcome(row["outcome"]),
        evidence.EvidenceBasis(row["basis"]),
        scope(row["bounded_scope"]),
        tuple(seq(row["reasons"])),
        row["packet_digest"],
        decision_provenance(row["provenance"]),
    )


def record(value: object) -> evidence.EvidenceRecord:
    row = obj(value)
    return evidence.EvidenceRecord(packet(row["packet"]), decision(row["decision"]), row["record_id"])
