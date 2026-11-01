"""Externally bootstrapped authority for access-control entry facts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from openultrasast.core import canonical, family, provenance
from openultrasast.core.factpack import (
    FactPack,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_fact_pack_content_digest,
    derive_independence_attestation_digest,
    derive_review_evidence_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.semantic.obligations.core_contract import validate_access_control_contract

ENTRY_FACT_AUTHORITY_SCHEMA = "openultrasast.access-control.entry-fact-authority.v2"
ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA = "openultrasast.access-control.entry-authority-bootstrap.v2"
AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA = "openultrasast.access-control.authority-conflict-disclosure.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class EntryFactAuthorityError(ValueError):
    """Installed entry-fact authority cannot be authenticated externally."""


def _require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise EntryFactAuthorityError(f"{field} must be nonempty text")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EntryFactAuthorityError(f"{field} must be a full lowercase SHA-256 digest")


def _require_digest_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise EntryFactAuthorityError(f"{field} must be a nonempty tuple")
    for value in values:
        _require_digest(value, field)
    if len(set(values)) != len(values):
        raise EntryFactAuthorityError(f"duplicate {field}")


def _require_forbidden_pairs(values: object) -> None:
    if not isinstance(values, tuple):
        raise EntryFactAuthorityError("forbidden identity pairs must be a tuple")
    for pair in values:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise EntryFactAuthorityError("forbidden identity pairs must contain pairs")
        _require_digest(pair[0], "forbidden producer")
        _require_digest(pair[1], "forbidden reviewer")
    if len(set(values)) != len(values):
        raise EntryFactAuthorityError("duplicate forbidden identity pair")


def _require_store_identities(values: object) -> None:
    if not isinstance(values, tuple) or not values:
        raise EntryFactAuthorityError("trusted store identities must be a nonempty tuple")
    for value in values:
        _require_text(value, "trusted store identity")
    if len(set(values)) != len(values):
        raise EntryFactAuthorityError("duplicate trusted store identity")


@dataclass(frozen=True)
class EntryAuthorityBootstrapPolicy:
    reviewed_bundle_reviewer_digests: tuple[str, ...]
    forbidden_identity_pairs: tuple[tuple[str, str], ...]
    trusted_store_identities: tuple[str, ...]
    maximum_bundle_bytes: int
    policy_digest: str

    def __post_init__(self) -> None:
        _require_digest_tuple(self.reviewed_bundle_reviewer_digests, "reviewed bundle reviewer")
        _require_forbidden_pairs(self.forbidden_identity_pairs)
        _require_store_identities(self.trusted_store_identities)
        if isinstance(self.maximum_bundle_bytes, bool) or not isinstance(self.maximum_bundle_bytes, int):
            raise EntryFactAuthorityError("maximum bundle bytes must be a positive integer")
        if self.maximum_bundle_bytes <= 0:
            raise EntryFactAuthorityError("maximum bundle bytes must be a positive integer")
        _require_digest(self.policy_digest, "bootstrap policy digest")


@dataclass(frozen=True)
class EntryFactAuthorityBundle:
    contract: family.FamilyContract
    packs: tuple[FactPack, ...]
    recognition_projection: canonical.ContentRef
    lineages: tuple[provenance.LineageManifest, ...]
    custody_policy: provenance.PopulationCustodyPolicy
    review_policy: ReviewIndependencePolicy
    matcher_revision: str
    matcher_behavior_digest: str
    matcher_lineage_manifest_digest: str
    authority_review: IndependenceAttestation
    bundle_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.contract, family.FamilyContract):
            raise EntryFactAuthorityError("contract must be a FamilyContract")
        if not isinstance(self.packs, tuple) or not all(isinstance(pack, FactPack) for pack in self.packs):
            raise EntryFactAuthorityError("packs must be a tuple of FactPack values")
        if not isinstance(self.recognition_projection, canonical.ContentRef):
            raise EntryFactAuthorityError("recognition projection must be a ContentRef")
        if not isinstance(self.lineages, tuple) or not all(isinstance(item, provenance.LineageManifest) for item in self.lineages):
            raise EntryFactAuthorityError("lineages must be a tuple of LineageManifest values")
        if not isinstance(self.custody_policy, provenance.PopulationCustodyPolicy):
            raise EntryFactAuthorityError("custody policy must be a PopulationCustodyPolicy")
        if not isinstance(self.review_policy, ReviewIndependencePolicy):
            raise EntryFactAuthorityError("review policy must be a ReviewIndependencePolicy")
        _require_text(self.matcher_revision, "matcher revision")
        _require_digest(self.matcher_behavior_digest, "matcher behavior digest")
        _require_digest(self.matcher_lineage_manifest_digest, "matcher lineage manifest digest")
        if not isinstance(self.authority_review, IndependenceAttestation):
            raise EntryFactAuthorityError("authority review must be an IndependenceAttestation")
        _require_digest(self.bundle_digest, "bundle digest")


@dataclass(frozen=True)
class EntryFactAuthorityContext:
    bundle: EntryFactAuthorityBundle
    custody: provenance.PopulationCustodyPort
    resolver: canonical.ContentResolver


def derive_entry_authority_bootstrap_policy_digest(
    reviewed_bundle_reviewer_digests: tuple[str, ...],
    forbidden_identity_pairs: tuple[tuple[str, str], ...],
    trusted_store_identities: tuple[str, ...],
    maximum_bundle_bytes: int,
) -> str:
    """Derive the external bootstrap identity without consulting a bundle."""
    return canonical.content_digest(
        {
            "schema_version": ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA,
            "reviewed_bundle_reviewer_digests": tuple(sorted(reviewed_bundle_reviewer_digests)),
            "forbidden_identity_pairs": tuple(sorted(forbidden_identity_pairs)),
            "trusted_store_identities": tuple(sorted(trusted_store_identities)),
            "maximum_bundle_bytes": maximum_bundle_bytes,
        }
    )


def _reference_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _pack_identity(pack: FactPack) -> Mapping[str, canonical.JsonValue]:
    return {
        "family_contract_digest": pack.family_contract_digest,
        "family_id": pack.family_id,
        "ecosystem": pack.ecosystem,
        "language": pack.language,
        "normalized_content_digest": pack.normalized_content_digest,
        "review_evidence_digest": pack.review_evidence_digest,
        "review_policy_digest": pack.review_policy_digest,
    }


def derive_entry_fact_authority_bundle_digest(bundle: EntryFactAuthorityBundle) -> str:
    """Derive the authority review subject, excluding the review and digest fields."""
    ordered_packs = sorted(bundle.packs, key=lambda pack: (pack.ecosystem, pack.language, pack.normalized_content_digest))
    pack_identities = tuple(_pack_identity(pack) for pack in ordered_packs)
    return canonical.content_digest(
        {
            "schema_version": ENTRY_FACT_AUTHORITY_SCHEMA,
            "family_contract_digest": family.family_contract_digest(bundle.contract),
            "packs": pack_identities,
            "recognition_projection": _reference_value(bundle.recognition_projection),
            "lineage_manifest_digests": tuple(sorted(item.manifest_digest for item in bundle.lineages)),
            "custody_policy_digest": bundle.custody_policy.policy_digest,
            "review_policy_digest": bundle.review_policy.policy_digest,
            "matcher_revision": bundle.matcher_revision,
            "matcher_behavior_digest": bundle.matcher_behavior_digest,
            "matcher_lineage_manifest_digest": bundle.matcher_lineage_manifest_digest,
        }
    )


def _validate_bootstrap(policy: EntryAuthorityBootstrapPolicy) -> None:
    policy.__post_init__()
    expected = derive_entry_authority_bootstrap_policy_digest(
        policy.reviewed_bundle_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_bundle_bytes,
    )
    if policy.policy_digest != expected:
        raise EntryFactAuthorityError("bootstrap policy digest cannot be re-derived")


def _validate_ports(custody: object, resolver: object) -> None:
    if not callable(getattr(custody, "current_log", None)):
        raise EntryFactAuthorityError("population custody port is missing")
    if not callable(getattr(resolver, "resolve", None)):
        raise EntryFactAuthorityError("content resolver is missing")


def _validate_policies(bundle: EntryFactAuthorityBundle) -> None:
    custody_expected = provenance.derive_population_custody_policy_digest(bundle.custody_policy.reviewed_custodian_digests)
    if bundle.custody_policy.policy_digest != custody_expected:
        raise EntryFactAuthorityError("custody policy digest cannot be re-derived")
    review_expected = derive_review_independence_policy_digest(
        bundle.review_policy.reviewed_reviewer_digests,
        bundle.review_policy.forbidden_identity_pairs,
        bundle.review_policy.trusted_store_identities,
        bundle.review_policy.maximum_evidence_bytes,
    )
    if bundle.review_policy.policy_digest != review_expected:
        raise EntryFactAuthorityError("review policy digest cannot be re-derived")


def _validate_lineages(bundle: EntryFactAuthorityBundle) -> dict[str, provenance.LineageManifest]:
    indexed: dict[str, provenance.LineageManifest] = {}
    for lineage in bundle.lineages:
        lineage.__post_init__()
        expected = provenance.derive_lineage_manifest_digest(lineage.arm_id, lineage.subject_digest, lineage.uses)
        if lineage.manifest_digest != expected:
            raise EntryFactAuthorityError("lineage manifest digest cannot be re-derived")
        if lineage.manifest_digest in indexed:
            raise EntryFactAuthorityError("duplicate lineage manifest identity")
        indexed[lineage.manifest_digest] = lineage
    matcher = indexed.get(bundle.matcher_lineage_manifest_digest)
    if matcher is None or matcher.subject_digest != bundle.matcher_behavior_digest:
        raise EntryFactAuthorityError("matcher lineage is missing or names another behavior")
    if not any(use.purpose is provenance.LineagePurpose.MATCHING_BEHAVIOR for use in matcher.uses):
        raise EntryFactAuthorityError("matcher lineage lacks matching-behavior provenance")
    return indexed


def _validate_packs(bundle: EntryFactAuthorityBundle, lineages: dict[str, provenance.LineageManifest]) -> None:
    if not bundle.packs:
        raise EntryFactAuthorityError("authority bundle requires reviewed packs")
    identities = tuple((pack.ecosystem, pack.language) for pack in bundle.packs)
    if len(set(identities)) != len(identities):
        raise EntryFactAuthorityError("duplicate language-scoped pack identity")
    contract_digest = family.family_contract_digest(bundle.contract)
    for pack in bundle.packs:
        pack.__post_init__()
        if pack.family_contract_digest != contract_digest or pack.family_id != bundle.contract.family_id:
            raise EntryFactAuthorityError("pack does not name the production family contract")
        if pack.ecosystem not in bundle.contract.ecosystems:
            raise EntryFactAuthorityError("pack ecosystem is outside the production contract")
        if pack.review_policy_digest != bundle.review_policy.policy_digest:
            raise EntryFactAuthorityError("pack review policy differs from authority")
        if pack.normalized_content_digest != derive_fact_pack_content_digest(pack):
            raise EntryFactAuthorityError("pack content digest cannot be re-derived")
        if pack.review_evidence_digest != derive_review_evidence_digest(pack.review_evidence):
            raise EntryFactAuthorityError("pack review evidence digest cannot be re-derived")
        if not pack.review_evidence or pack.review_identity not in bundle.review_policy.reviewed_reviewer_digests:
            raise EntryFactAuthorityError("pack lacks an independently reviewed identity")
        _validate_pack_lineages(pack, lineages)


def _validate_pack_lineages(pack: FactPack, lineages: dict[str, provenance.LineageManifest]) -> None:
    for evidence in pack.review_evidence:
        lineage = lineages.get(evidence.lineage_manifest_digest)
        if lineage is None or lineage.subject_digest != pack.normalized_content_digest:
            raise EntryFactAuthorityError("semantic-fact lineage is missing or names another pack")
        if not any(use.purpose is provenance.LineagePurpose.SEMANTIC_FACT for use in lineage.uses):
            raise EntryFactAuthorityError("pack lineage lacks semantic-fact provenance")


def _validate_review(bundle: EntryFactAuthorityBundle, bootstrap: EntryAuthorityBootstrapPolicy) -> None:
    review = bundle.authority_review
    review.__post_init__()
    if bundle.bundle_digest != derive_entry_fact_authority_bundle_digest(bundle):
        raise EntryFactAuthorityError("authority bundle digest cannot be re-derived")
    if review.subject_digest != bundle.bundle_digest:
        raise EntryFactAuthorityError("authority review subject does not name the bundle")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise EntryFactAuthorityError("authority attestation digest cannot be re-derived")
    if review.producer_identity == review.reviewer_identity:
        raise EntryFactAuthorityError("authority producer and reviewer must be independent")
    if review.reviewer_identity not in bootstrap.reviewed_bundle_reviewer_digests:
        raise EntryFactAuthorityError("authority reviewer is not trusted by bootstrap")
    if (review.producer_identity, review.reviewer_identity) in bootstrap.forbidden_identity_pairs:
        raise EntryFactAuthorityError("authority producer/reviewer pair is forbidden")


def _resolve(reference: canonical.ContentRef, bootstrap: EntryAuthorityBootstrapPolicy, resolver: canonical.ContentResolver) -> bytes:
    try:
        return canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=bootstrap.trusted_store_identities,
            maximum_bytes=bootstrap.maximum_bundle_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError, ValueError, TypeError) as exc:
        raise EntryFactAuthorityError("authority artifact cannot be resolved under bootstrap") from exc


def _validate_disclosure(content: bytes) -> None:
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EntryFactAuthorityError("authority conflict disclosure is not canonical JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "conflicts", "resolved"}:
        raise EntryFactAuthorityError("authority conflict disclosure has unknown fields")
    conflicts = raw["conflicts"]
    if raw["schema_version"] != AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA:
        raise EntryFactAuthorityError("authority conflict disclosure schema is unknown")
    if not isinstance(conflicts, list) or not all(isinstance(item, str) and item for item in conflicts):
        raise EntryFactAuthorityError("authority conflicts must be a list of nonempty text")
    if raw["resolved"] is not True:
        raise EntryFactAuthorityError("authority conflict disclosure is unresolved")
    canonical_value: Mapping[str, canonical.JsonValue] = {
        "schema_version": AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,
        "conflicts": tuple(conflicts),
        "resolved": True,
    }
    expected = canonical.canonical_record_bytes(
        canonical_value, known_schema_versions=(AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA,)
    )
    if content != expected:
        raise EntryFactAuthorityError("authority conflict disclosure bytes are not canonical")


def authenticate_entry_fact_authority(
    bundle: EntryFactAuthorityBundle,
    bootstrap: EntryAuthorityBootstrapPolicy,
    custody: provenance.PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EntryFactAuthorityContext:
    """Authenticate installed authority without interpreting packs or reading custody state."""
    if not isinstance(bundle, EntryFactAuthorityBundle) or not isinstance(bootstrap, EntryAuthorityBootstrapPolicy):
        raise EntryFactAuthorityError("authority and bootstrap must use the typed contracts")
    _validate_ports(custody, resolver)
    bundle.__post_init__()
    _validate_bootstrap(bootstrap)
    _validate_review(bundle, bootstrap)
    disclosure = _resolve(bundle.authority_review.conflict_disclosure, bootstrap, resolver)
    _validate_disclosure(disclosure)
    validate_access_control_contract(bundle.contract)
    _validate_policies(bundle)
    lineages = _validate_lineages(bundle)
    _validate_packs(bundle, lineages)
    projection = _resolve(bundle.recognition_projection, bootstrap, resolver)
    if not projection:
        raise EntryFactAuthorityError("recognition projection must be nonempty")
    return EntryFactAuthorityContext(bundle, custody, resolver)


__all__ = [
    "AUTHORITY_CONFLICT_DISCLOSURE_SCHEMA",
    "ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA",
    "ENTRY_FACT_AUTHORITY_SCHEMA",
    "EntryAuthorityBootstrapPolicy",
    "EntryFactAuthorityBundle",
    "EntryFactAuthorityContext",
    "EntryFactAuthorityError",
    "authenticate_entry_fact_authority",
    "derive_entry_authority_bootstrap_policy_digest",
    "derive_entry_fact_authority_bundle_digest",
]
