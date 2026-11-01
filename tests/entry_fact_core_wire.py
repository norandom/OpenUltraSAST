"""Family-neutral decoders for the checked-in fact conformance envelope."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from openultrasast.core import canonical, custody, evidence, family, lineage, semantics
from openultrasast.core.factmatch import FactMatchEvidence, StructuralObservation
from openultrasast.core.factpack import (
    FactPack,
    IndependenceAttestation,
    KnowledgeEvidence,
    KnowledgeEvidenceKind,
    RelationEffect,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
)

REPLAY_SCHEMA = "openultrasast.access-control.entry-fact-core-replay.v1"


def obj(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def seq(value: object) -> tuple[Any, ...]:
    assert isinstance(value, list)
    return tuple(value)


def location(value: object) -> semantics.SourceLocation:
    row = obj(value)
    return semantics.SourceLocation(row["path"], row["line"], row["column"], row["symbol"])


def reference(value: object) -> canonical.ContentRef:
    row = obj(value)
    return canonical.ContentRef(
        row["artifact_id"],
        row["content_digest"],
        row["media_type"],
        row["byte_length"],
        row["retention_policy_digest"],
        row["storage_receipt_digest"],
    )


def field_spec(value: object) -> family.FieldSpec:
    row = obj(value)
    return family.FieldSpec(row["name"], semantics.FieldKind(row["kind"]), row["required"])


def contract(value: object) -> family.FamilyContract:
    row = obj(value)
    security = obj(row["security_object"])
    return family.FamilyContract(
        row["family_id"],
        row["family_version"],
        row["schema_version"],
        tuple(seq(row["ecosystems"])),
        family.ObjectSpec(
            security["kind"],
            tuple(field_spec(item) for item in seq(security["fields"])),
            tuple(seq(security["identity_fields"])),
        ),
        tuple(
            family.RoleSpec(
                item["role"],
                tuple(field_spec(field) for field in seq(item["fields"])),
                tuple(semantics.RelationKind(kind) for kind in seq(item["allowed_relation_kinds"])),
                family.RelationOriginPolicy(item["origin_policy"]),
            )
            for raw in seq(row["roles"])
            for item in (obj(raw),)
        ),
        tuple(
            family.DecisionRule(
                item["family_code"],
                evidence.NeutralOutcome(item["outcome"]),
                tuple(seq(item["required_roles"])),
                tuple(semantics.RelationStatus(status) for status in seq(item["allowed_statuses"])),
            )
            for raw in seq(row["decisions"])
            for item in (obj(raw),)
        ),
        tuple(
            family.ResidualQuestion(item["question_id"], tuple(seq(item["required_roles"])), tuple(seq(item["allowed_decisions"])))
            for raw in seq(row["residual_questions"])
            for item in (obj(raw),)
        ),
        tuple(seq(row["indeterminate_reasons"])),
    )


def attestation(value: object) -> IndependenceAttestation:
    row = obj(value)
    return IndependenceAttestation(
        row["subject_digest"],
        row["producer_identity"],
        row["reviewer_identity"],
        reference(row["conflict_disclosure"]),
        row["attestation_digest"],
    )


def knowledge(value: object) -> KnowledgeEvidence:
    row = obj(value)
    return KnowledgeEvidence(
        KnowledgeEvidenceKind(row["kind"]),
        reference(row["content"]),
        row["producer_identity"],
        row["reviewer_identity"],
        attestation(row["independence"]),
        row["lineage_manifest_digest"],
    )


def fact_pack(value: object) -> FactPack:
    row = obj(value)
    facts = tuple(
        SemanticFact(
            item["fact_id"],
            item["role"],
            tuple(
                StructuralRequirement(req["requirement_id"], StructuralRequirementKind(req["kind"]), req["field"], req["expected"])
                for raw_req in seq(item["structural_requirements"])
                for req in (obj(raw_req),)
            ),
            tuple(
                RelationEffect(
                    semantics.RelationKind(effect["kind"]),
                    effect["role"],
                    effect["source_role"],
                    effect["target_role"],
                    tuple(seq(effect["conditions"])),
                )
                for raw_effect in seq(item["relation_effects"])
                for effect in (obj(raw_effect),)
            ),
        )
        for raw in seq(row["facts"])
        for item in (obj(raw),)
    )
    return FactPack(
        row["schema_version"],
        row["family_contract_digest"],
        row["family_id"],
        row["ecosystem"],
        row["language"],
        facts,
        row["normalized_content_digest"],
        row["review_identity"],
        tuple(knowledge(item) for item in seq(row["review_evidence"])),
        row["review_evidence_digest"],
        row["review_policy_digest"],
    )


def observation(value: object) -> StructuralObservation:
    row = obj(value)
    return StructuralObservation(row["requirement_id"], location(row["location"]), row["observed"], reference(row["evidence"]))


def fact_match(value: object) -> FactMatchEvidence:
    row = obj(value)
    return FactMatchEvidence(
        row["pack_digest"],
        row["fact_id"],
        location(row["product_location"]),
        tuple(observation(item) for item in seq(row["observations"])),
        row["matcher_revision"],
        row["matcher_behavior_digest"],
        row["matcher_lineage_manifest_digest"],
        row["match_digest"],
    )


def lineage_use(value: object) -> lineage.LineageUse:
    row = obj(value)
    return lineage.LineageUse(
        custody.LineagePurpose(row["purpose"]),
        row["source_population_digest"],
        row["labels_accessed"],
        row["influenced_artifact_digest"],
        row["population_use_receipt_digest"],
    )


def lineage_manifest(value: object) -> lineage.LineageManifest:
    row = obj(value)
    return lineage.LineageManifest(
        row["arm_id"],
        row["subject_digest"],
        tuple(lineage_use(item) for item in seq(row["uses"])),
        row["manifest_digest"],
    )


def use_request(value: object) -> custody.PopulationUseRequest:
    row = obj(value)
    return custody.PopulationUseRequest(
        row["population_digest"],
        row["arm_id"],
        custody.LineagePurpose(row["purpose"]),
        row["labels_accessed"],
        row["influenced_artifact_digest"],
        row["expected_log_digest"],
    )


def use_receipt(value: object) -> custody.PopulationUseReceipt:
    row = obj(value)
    return custody.PopulationUseReceipt(
        use_request(row["request"]),
        row["request_digest"],
        row["population_digest"],
        row["custodian_identity"],
        row["sequence"],
        row["predecessor_digest"],
        custody.PopulationStatus(row["prior_status"]),
        custody.PopulationStatus(row["status"]),
        tuple(seq(row["reasons"])),
        row["receipt_digest"],
    )


def custody_log(value: object) -> custody.PopulationCustodyLog:
    row = obj(value)
    return custody.PopulationCustodyLog(
        row["population_digest"],
        row["custodian_identity"],
        tuple(use_receipt(item) for item in seq(row["receipts"])),
        row["receipt_count"],
        row["head_receipt_digest"],
        custody.PopulationStatus(row["status"]),
        row["log_digest"],
    )


@dataclass
class MemoryCustody:
    logs: dict[str, custody.PopulationCustodyLog]

    def current_log(self, population_digest: str) -> custody.PopulationCustodyLog:
        return self.logs[population_digest]


@dataclass
class FileResolver:
    root: Path
    entries: dict[str, tuple[canonical.ContentRef, str, str]]
    substitution: tuple[str, str] | None = None

    def resolve(self, value: canonical.ContentRef) -> canonical.ResolvedContent:
        expected, path, store = self.entries[value.content_digest]
        assert expected == value
        if self.substitution is not None and value.content_digest == self.substitution[0]:
            path = self.substitution[1]
        content = (self.root / path).read_bytes()
        receipt = canonical.StorageReceipt(
            store,
            value.content_digest,
            value.byte_length,
            value.retention_policy_digest,
            value.storage_receipt_digest,
        )
        return canonical.ResolvedContent(content, receipt)


def load_envelope(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    assert len(content) > 0
    row = obj(json.loads(content))
    assert row["schema_version"] == REPLAY_SCHEMA
    payload = {key: value for key, value in row.items() if key != "envelope_digest"}
    assert canonical.content_digest(_freeze(payload)) == row["envelope_digest"]
    return row


def _freeze(value: object) -> canonical.JsonValue:
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, dict):
        return {key: _freeze(item) for key, item in value.items()}
    return cast(canonical.JsonValue, value)
