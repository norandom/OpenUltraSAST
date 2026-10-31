"""Replay validation for fact-derived relations and dependency boundaries."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

from openultrasast.core import canonical
from openultrasast.core.custody import PopulationCustodyPolicy, PopulationCustodyPort
from openultrasast.core.evidence import EvidenceRecord
from openultrasast.core.factapply import apply_fact
from openultrasast.core.factmatch import FACT_MATCH_SCHEMA, FactMatchEvidence, StructuralObservation
from openultrasast.core.factpack import FactPack, ReviewIndependencePolicy
from openultrasast.core.family import FamilyContract, validate_record
from openultrasast.core.lineage import LineageManifest
from openultrasast.core.semantics import ProvenanceKind, SemanticRelation, SourceLocation


class FactRelationValidationError(ValueError):
    """A fact-derived relation cannot be reproduced from its named inputs."""


def _mapping(value: object, keys: set[str], field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value) or set(value) != keys:
        raise FactRelationValidationError(f"{field} must be an exact canonical object")
    return cast(Mapping[str, object], value)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FactRelationValidationError(f"{field} must be nonempty text")
    return value


def _integer(value: object, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise FactRelationValidationError(f"{field} must be an integer of at least {minimum}")
    return value


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field)


def _optional_integer(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _integer(value, field, minimum=0)


def _json_value(value: object) -> canonical.JsonValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        canonical.canonical_bytes(value)
        return value
    if isinstance(value, list):
        return tuple(_json_value(item) for item in value)
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {cast(str, key): _json_value(item) for key, item in value.items()}
    raise FactRelationValidationError("match artifact contains a value outside the canonical JSON profile")


def _location(value: object, field: str) -> SourceLocation:
    item = _mapping(value, {"path", "line", "column", "symbol"}, field)
    return SourceLocation(
        _text(item["path"], f"{field}.path"),
        _integer(item["line"], f"{field}.line", minimum=1),
        _optional_integer(item["column"], f"{field}.column"),
        _optional_text(item["symbol"], f"{field}.symbol"),
    )


def _reference(value: object, field: str) -> canonical.ContentRef:
    item = _mapping(
        value,
        {"artifact_id", "content_digest", "media_type", "byte_length", "retention_policy_digest", "storage_receipt_digest"},
        field,
    )
    return canonical.ContentRef(
        _text(item["artifact_id"], f"{field}.artifact_id"),
        _text(item["content_digest"], f"{field}.content_digest"),
        _text(item["media_type"], f"{field}.media_type"),
        _integer(item["byte_length"], f"{field}.byte_length", minimum=0),
        _text(item["retention_policy_digest"], f"{field}.retention_policy_digest"),
        _text(item["storage_receipt_digest"], f"{field}.storage_receipt_digest"),
    )


def _observation(value: object, index: int) -> StructuralObservation:
    field = f"observations[{index}]"
    item = _mapping(value, {"requirement_id", "location", "observed", "evidence"}, field)
    return StructuralObservation(
        _text(item["requirement_id"], f"{field}.requirement_id"),
        _location(item["location"], f"{field}.location"),
        _json_value(item["observed"]),
        _reference(item["evidence"], f"{field}.evidence"),
    )


def _match_from_bytes(content: bytes) -> FactMatchEvidence:
    try:
        parsed = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FactRelationValidationError(f"match artifact is not canonical JSON: {exc}") from exc
    normalized = _json_value(parsed)
    if canonical.canonical_bytes(normalized) != content:
        raise FactRelationValidationError("match artifact bytes are not canonical")
    item = _mapping(
        parsed,
        {
            "schema_version",
            "pack_digest",
            "fact_id",
            "product_location",
            "observations",
            "matcher_revision",
            "matcher_behavior_digest",
            "matcher_lineage_manifest_digest",
        },
        "match artifact",
    )
    if item["schema_version"] != FACT_MATCH_SCHEMA:
        raise FactRelationValidationError("match artifact has an unknown schema version")
    observations = item["observations"]
    if not isinstance(observations, list):
        raise FactRelationValidationError("match observations must be an array")
    return FactMatchEvidence(
        _text(item["pack_digest"], "match.pack_digest"),
        _text(item["fact_id"], "match.fact_id"),
        _location(item["product_location"], "match.product_location"),
        tuple(_observation(value, index) for index, value in enumerate(observations)),
        _text(item["matcher_revision"], "match.matcher_revision"),
        _text(item["matcher_behavior_digest"], "match.matcher_behavior_digest"),
        _text(item["matcher_lineage_manifest_digest"], "match.matcher_lineage_manifest_digest"),
        canonical.bytes_digest(content),
    )


def _pack_for(relation: SemanticRelation, packs: Sequence[FactPack]) -> FactPack:
    digest = relation.provenance.semantic_pack_digest
    matches = tuple(pack for pack in packs if pack.normalized_content_digest == digest)
    if len(matches) != 1:
        raise FactRelationValidationError("semantic pack identity is missing or ambiguous")
    return matches[0]


def _replay_relation(
    relation: SemanticRelation,
    record: EvidenceRecord,
    contract: FamilyContract,
    packs: Sequence[FactPack],
    population_digest: str,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    pack = _pack_for(relation, packs)
    if (pack.family_id, pack.family_contract_digest, pack.ecosystem) != (
        record.packet.family_id,
        record.packet.family_contract_digest,
        record.packet.ecosystem,
    ):
        raise FactRelationValidationError("semantic pack scope does not match the evidence record")
    reference = relation.provenance.fact_match
    if reference is None or relation.provenance.semantic_fact_id is None:
        raise FactRelationValidationError("semantic fact provenance is incomplete")
    content = canonical.resolve_content(
        reference,
        resolver,
        trusted_store_identities=review_policy.trusted_store_identities,
        maximum_bytes=review_policy.maximum_evidence_bytes,
    )
    match = _match_from_bytes(content)
    replayed = apply_fact(
        pack,
        relation.provenance.semantic_fact_id,
        match,
        reference,
        contract,
        population_digest,
        lineages,
        custody,
        custody_policy,
        review_policy,
        resolver,
    )
    if relation not in replayed:
        raise FactRelationValidationError("fact-derived relation does not equal replayed declared effect")


def validate_fact_relations(
    record: EvidenceRecord,
    contract: FamilyContract,
    packs: Sequence[FactPack],
    evaluation_population_digest: str,
    lineages: Sequence[LineageManifest],
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    """Re-open and replay every fact-derived relation in an evidence record."""
    try:
        validate_record(contract, record)
        if record.packet.provenance.population_digest != evaluation_population_digest:
            raise FactRelationValidationError("record has an invalid evaluation population scope")
        if not isinstance(packs, Sequence) or not all(isinstance(pack, FactPack) for pack in packs):
            raise FactRelationValidationError("packs must be a sequence of FactPack values")
        for relation in record.packet.transitions:
            if relation.provenance.kind is ProvenanceKind.SEMANTIC_FACT:
                _replay_relation(
                    relation,
                    record,
                    contract,
                    packs,
                    evaluation_population_digest,
                    lineages,
                    custody,
                    custody_policy,
                    review_policy,
                    resolver,
                )
    except FactRelationValidationError:
        raise
    except (LookupError, TypeError, ValueError) as exc:
        raise FactRelationValidationError(f"fact relation replay failed: {exc}") from exc


__all__ = ["FactRelationValidationError", "validate_fact_relations"]
