"""Canonical value projections for v2 fact-pack identities."""

from __future__ import annotations

from typing import TYPE_CHECKING

from openultrasast.core import canonical

if TYPE_CHECKING:
    from openultrasast.core.factpack import (
        FactPack,
        IndependenceAttestation,
        KnowledgeEvidence,
        RelationEffect,
        SemanticFact,
        StructuralRequirement,
    )

ATTESTATION_SCHEMA = "openultrasast.detection-core.independence-attestation.v2"
REVIEW_POLICY_SCHEMA = "openultrasast.detection-core.fact-review-policy.v2"
REVIEW_EVIDENCE_SCHEMA = "openultrasast.detection-core.fact-review-evidence.v2"


def _ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def attestation_digest(attestation: IndependenceAttestation) -> str:
    return canonical.content_digest(
        {
            "schema_version": ATTESTATION_SCHEMA,
            "subject_digest": attestation.subject_digest,
            "producer_identity": attestation.producer_identity,
            "reviewer_identity": attestation.reviewer_identity,
            "conflict_disclosure": _ref_value(attestation.conflict_disclosure),
        }
    )


def review_policy_digest(
    reviewed_reviewer_digests: tuple[str, ...],
    forbidden_identity_pairs: tuple[tuple[str, str], ...],
    trusted_store_identities: tuple[str, ...],
    maximum_evidence_bytes: int,
) -> str:
    return canonical.content_digest(
        {
            "schema_version": REVIEW_POLICY_SCHEMA,
            "reviewed_reviewer_digests": tuple(sorted(reviewed_reviewer_digests)),
            "forbidden_identity_pairs": tuple(sorted(forbidden_identity_pairs)),
            "trusted_store_identities": tuple(sorted(trusted_store_identities)),
            "maximum_evidence_bytes": maximum_evidence_bytes,
        }
    )


def _attestation_value(attestation: IndependenceAttestation) -> canonical.JsonValue:
    return {
        "subject_digest": attestation.subject_digest,
        "producer_identity": attestation.producer_identity,
        "reviewer_identity": attestation.reviewer_identity,
        "conflict_disclosure": _ref_value(attestation.conflict_disclosure),
        "attestation_digest": attestation.attestation_digest,
    }


def _evidence_value(evidence: KnowledgeEvidence, *, include_lineage: bool) -> canonical.JsonValue:
    """Project evidence; lineage is omitted only from the digest it names as subject."""
    value: dict[str, canonical.JsonValue] = {
        "kind": evidence.kind.value,
        "content": _ref_value(evidence.content),
        "producer_identity": evidence.producer_identity,
        "reviewer_identity": evidence.reviewer_identity,
        "independence": _attestation_value(evidence.independence),
    }
    if include_lineage:
        value["lineage_manifest_digest"] = evidence.lineage_manifest_digest
    return value


def _requirement_value(requirement: StructuralRequirement) -> canonical.JsonValue:
    return {
        "requirement_id": requirement.requirement_id,
        "kind": requirement.kind.value,
        "field": requirement.field,
        "expected": requirement.expected,
    }


def _effect_value(effect: RelationEffect) -> canonical.JsonValue:
    return {
        "kind": effect.kind.value,
        "role": effect.role,
        "source_role": effect.source_role,
        "target_role": effect.target_role,
        "conditions": effect.conditions,
    }


def _fact_value(fact: SemanticFact) -> canonical.JsonValue:
    return {
        "fact_id": fact.fact_id,
        "role": fact.role,
        "structural_requirements": tuple(_requirement_value(item) for item in fact.structural_requirements),
        "relation_effects": tuple(_effect_value(item) for item in fact.relation_effects),
    }


def pack_content_digest(pack: FactPack) -> str:
    return canonical.content_digest(
        {
            "schema_version": pack.schema_version,
            "family_contract_digest": pack.family_contract_digest,
            "family_id": pack.family_id,
            "ecosystem": pack.ecosystem,
            "language": pack.language,
            "facts": tuple(_fact_value(fact) for fact in pack.facts),
            "review_identity": pack.review_identity,
            "review_evidence": tuple(_evidence_value(item, include_lineage=False) for item in pack.review_evidence),
            "review_policy_digest": pack.review_policy_digest,
        }
    )


def evidence_digest(review_evidence: tuple[KnowledgeEvidence, ...]) -> str:
    return canonical.content_digest(
        {
            "schema_version": REVIEW_EVIDENCE_SCHEMA,
            "review_evidence": tuple(_evidence_value(item, include_lineage=True) for item in review_evidence),
        }
    )
