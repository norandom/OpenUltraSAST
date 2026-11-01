"""Nested value codecs for the installed fact-authority wire boundary."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import TypeVar, cast

from openultrasast.core import canonical, provenance, semantics
from openultrasast.core.factpack import (
    IndependenceAttestation,
    KnowledgeEvidence,
    KnowledgeEvidenceKind,
    RelationEffect,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
)

_T = TypeVar("_T")
_REF_FIELDS = ("artifact_id", "content_digest", "media_type", "byte_length", "retention_policy_digest", "storage_receipt_digest")
_ATTESTATION_FIELDS = ("subject_digest", "producer_identity", "reviewer_identity", "conflict_disclosure", "attestation_digest")


class InstalledAuthorityWireError(ValueError):
    """Installed authority bytes do not satisfy the closed wire contract."""


def wire_value(value: object) -> canonical.JsonValue:
    """Project dataclasses, enums, and parsed JSON into canonical values."""
    if isinstance(value, Enum):
        return cast(canonical.JsonValue, value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: wire_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise InstalledAuthorityWireError("JSON object keys must be text")
        return {cast(str, key): wire_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return tuple(wire_value(item) for item in value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise InstalledAuthorityWireError(f"unsupported wire value: {type(value).__name__}")


def closed_object(value: object, expected: tuple[str, ...], label: str) -> dict[str, object]:
    """Require a JSON object with exactly the declared field set."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InstalledAuthorityWireError(f"{label} must be an object")
    record = cast(dict[str, object], value)
    missing = set(expected) - set(record)
    unknown = set(record) - set(expected)
    if missing or unknown:
        details = [f"missing {item}" for item in sorted(missing)]
        details.extend(f"unknown {item}" for item in sorted(unknown))
        raise InstalledAuthorityWireError(f"{label} has {', '.join(details)}")
    return record


def items(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise InstalledAuthorityWireError(f"{label} must be an array")
    return tuple(value)


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InstalledAuthorityWireError(f"{label} must be nonempty text")
    return value


def integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InstalledAuthorityWireError(f"{label} must be an integer")
    return value


def boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise InstalledAuthorityWireError(f"{label} must be boolean")
    return value


def strings(value: object, label: str) -> tuple[str, ...]:
    return tuple(text(item, label) for item in items(value, label))


def pairs(value: object, label: str) -> tuple[tuple[str, str], ...]:
    decoded: list[tuple[str, str]] = []
    for item in items(value, label):
        pair = items(item, label)
        if len(pair) != 2:
            raise InstalledAuthorityWireError(f"{label} entries must be pairs")
        decoded.append((text(pair[0], label), text(pair[1], label)))
    return tuple(decoded)


def parse_record(content: bytes, schema: str, expected: tuple[str, ...], label: str) -> dict[str, object]:
    """Parse canonical JSON and enforce its top-level schema and fields."""
    if not isinstance(content, bytes):
        raise InstalledAuthorityWireError(f"{label} content must be bytes")
    try:
        raw: object = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstalledAuthorityWireError(f"{label} is not valid JSON") from exc
    record = closed_object(raw, expected, label)
    if record["schema_version"] != schema:
        raise InstalledAuthorityWireError(f"unknown {label} schema")
    if canonical.canonical_bytes(wire_value(record)) != content:
        raise InstalledAuthorityWireError(f"{label} bytes are not canonical")
    return record


def decode_value(label: str, build: Callable[[], _T]) -> _T:
    """Normalize typed construction failures to the wire error boundary."""
    try:
        return build()
    except InstalledAuthorityWireError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise InstalledAuthorityWireError(f"invalid {label}: {exc}") from exc


def content_ref(value: object) -> canonical.ContentRef:
    row = closed_object(value, _REF_FIELDS, "content reference")
    return canonical.ContentRef(
        text(row["artifact_id"], "artifact_id"),
        text(row["content_digest"], "content_digest"),
        text(row["media_type"], "media_type"),
        integer(row["byte_length"], "byte_length"),
        text(row["retention_policy_digest"], "retention_policy_digest"),
        text(row["storage_receipt_digest"], "storage_receipt_digest"),
    )


def attestation(value: object) -> IndependenceAttestation:
    row = closed_object(value, _ATTESTATION_FIELDS, "attestation")
    return IndependenceAttestation(
        text(row["subject_digest"], "subject_digest"),
        text(row["producer_identity"], "producer_identity"),
        text(row["reviewer_identity"], "reviewer_identity"),
        content_ref(row["conflict_disclosure"]),
        text(row["attestation_digest"], "attestation_digest"),
    )


def evidence(value: object) -> KnowledgeEvidence:
    expected = ("kind", "content", "producer_identity", "reviewer_identity", "independence", "lineage_manifest_digest")
    row = closed_object(value, expected, "knowledge evidence")
    return KnowledgeEvidence(
        KnowledgeEvidenceKind(text(row["kind"], "evidence kind")),
        content_ref(row["content"]),
        text(row["producer_identity"], "producer_identity"),
        text(row["reviewer_identity"], "reviewer_identity"),
        attestation(row["independence"]),
        text(row["lineage_manifest_digest"], "lineage_manifest_digest"),
    )


def requirement(value: object) -> StructuralRequirement:
    row = closed_object(value, ("requirement_id", "kind", "field", "expected"), "structural requirement")
    return StructuralRequirement(
        text(row["requirement_id"], "requirement_id"),
        StructuralRequirementKind(text(row["kind"], "requirement kind")),
        text(row["field"], "requirement field"),
        wire_value(row["expected"]),
    )


def effect(value: object) -> RelationEffect:
    row = closed_object(value, ("kind", "role", "source_role", "target_role", "conditions"), "relation effect")
    return RelationEffect(
        semantics.RelationKind(text(row["kind"], "relation kind")),
        text(row["role"], "effect role"),
        text(row["source_role"], "source role"),
        text(row["target_role"], "target role"),
        strings(row["conditions"], "conditions"),
    )


def fact(value: object) -> SemanticFact:
    row = closed_object(value, ("fact_id", "role", "structural_requirements", "relation_effects"), "semantic fact")
    requirements = items(row["structural_requirements"], "structural_requirements")
    effects = items(row["relation_effects"], "relation_effects")
    return SemanticFact(
        text(row["fact_id"], "fact_id"),
        text(row["role"], "fact role"),
        tuple(requirement(item) for item in requirements),
        tuple(effect(item) for item in effects),
    )


def lineage(value: object) -> provenance.LineageManifest:
    row = closed_object(value, ("arm_id", "subject_digest", "uses", "manifest_digest"), "lineage")
    expected = (
        "purpose",
        "source_population_digest",
        "labels_accessed",
        "influenced_artifact_digest",
        "population_use_receipt_digest",
    )
    uses = tuple(_lineage_use(item, expected) for item in items(row["uses"], "lineage uses"))
    return provenance.LineageManifest(
        text(row["arm_id"], "arm_id"),
        text(row["subject_digest"], "subject_digest"),
        uses,
        text(row["manifest_digest"], "manifest_digest"),
    )


def _lineage_use(value: object, expected: tuple[str, ...]) -> provenance.LineageUse:
    row = closed_object(value, expected, "lineage use")
    return provenance.LineageUse(
        provenance.LineagePurpose(text(row["purpose"], "lineage purpose")),
        text(row["source_population_digest"], "source population"),
        boolean(row["labels_accessed"], "labels_accessed"),
        text(row["influenced_artifact_digest"], "influenced artifact"),
        text(row["population_use_receipt_digest"], "population receipt"),
    )


def custody_policy(value: object) -> provenance.PopulationCustodyPolicy:
    row = closed_object(value, ("reviewed_custodian_digests", "policy_digest"), "custody policy")
    return provenance.PopulationCustodyPolicy(
        strings(row["reviewed_custodian_digests"], "custodian digests"),
        text(row["policy_digest"], "custody policy digest"),
    )


def review_policy(value: object) -> ReviewIndependencePolicy:
    expected = (
        "reviewed_reviewer_digests",
        "forbidden_identity_pairs",
        "trusted_store_identities",
        "maximum_evidence_bytes",
        "policy_digest",
    )
    row = closed_object(value, expected, "review policy")
    return ReviewIndependencePolicy(
        strings(row["reviewed_reviewer_digests"], "reviewer digests"),
        pairs(row["forbidden_identity_pairs"], "forbidden pairs"),
        strings(row["trusted_store_identities"], "store identities"),
        integer(row["maximum_evidence_bytes"], "maximum evidence bytes"),
        text(row["policy_digest"], "review policy digest"),
    )
