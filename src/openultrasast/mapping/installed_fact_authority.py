"""Closed canonical wire format for installed entry-fact authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from openultrasast.core import canonical
from openultrasast.core.factpack import FACT_PACK_SCHEMA, FactPack
from openultrasast.core.family import FamilyContract
from openultrasast.mapping._installed_fact_authority_codec import (
    InstalledAuthorityWireError,
    attestation,
    content_ref,
    custody_policy,
    decode_value,
    evidence,
    fact,
    integer,
    items,
    lineage,
    pairs,
    parse_record,
    review_policy,
    strings,
    text,
    wire_value,
)
from openultrasast.mapping.fact_authority import (
    ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA,
    EntryAuthorityBootstrapPolicy,
    EntryFactAuthorityBundle,
)

INSTALLED_AUTHORITY_SCHEMA = "openultrasast.access-control.installed-entry-authority.v1"
PACK_FILES = ("express.javascript.v2.json", "express.typescript.v2.json")
_PACK_LANGUAGES = ("javascript", "typescript")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_PACK_FIELDS = (
    "schema_version",
    "family_contract_digest",
    "family_id",
    "ecosystem",
    "language",
    "facts",
    "normalized_content_digest",
    "review_identity",
    "review_evidence",
    "review_evidence_digest",
    "review_policy_digest",
)
_BOOTSTRAP_FIELDS = (
    "schema_version",
    "reviewed_bundle_reviewer_digests",
    "forbidden_identity_pairs",
    "trusted_store_identities",
    "maximum_bundle_bytes",
    "policy_digest",
)
_AUTHORITY_FIELDS = (
    "schema_version",
    "pack_files",
    "recognition_projection",
    "lineages",
    "custody_policy",
    "review_policy",
    "matcher_revision",
    "matcher_behavior_digest",
    "matcher_lineage_manifest_digest",
    "authority_review",
    "bundle_digest",
)


def _record_bytes(value: object, schema: str) -> bytes:
    record = cast(Mapping[str, canonical.JsonValue], wire_value(value))
    return canonical.canonical_record_bytes(record, known_schema_versions=(schema,))


def fact_pack_bytes(value: FactPack) -> bytes:
    """Encode every public fact-pack field as canonical JSON."""
    return _record_bytes(value, FACT_PACK_SCHEMA)


def decode_fact_pack_bytes(content: bytes) -> FactPack:
    """Decode only the closed v2 fact-pack representation."""

    def build() -> FactPack:
        row = parse_record(content, FACT_PACK_SCHEMA, _PACK_FIELDS, "fact pack")
        value = FactPack(
            FACT_PACK_SCHEMA,
            text(row["family_contract_digest"], "family_contract_digest"),
            text(row["family_id"], "family_id"),
            text(row["ecosystem"], "ecosystem"),
            text(row["language"], "language"),
            tuple(fact(item) for item in items(row["facts"], "facts")),
            text(row["normalized_content_digest"], "normalized_content_digest"),
            text(row["review_identity"], "review_identity"),
            tuple(evidence(item) for item in items(row["review_evidence"], "review_evidence")),
            text(row["review_evidence_digest"], "review_evidence_digest"),
            text(row["review_policy_digest"], "review_policy_digest"),
        )
        if fact_pack_bytes(value) != content:
            raise InstalledAuthorityWireError("fact pack does not round-trip canonically")
        return value

    return decode_value("fact pack", build)


def bootstrap_bytes(value: EntryAuthorityBootstrapPolicy) -> bytes:
    """Encode the external bootstrap policy without authority data."""
    row = cast(dict[str, canonical.JsonValue], wire_value(value))
    return canonical.canonical_record_bytes(
        {"schema_version": ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA, **row},
        known_schema_versions=(ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA,),
    )


def decode_bootstrap_bytes(content: bytes) -> EntryAuthorityBootstrapPolicy:
    """Decode a closed external bootstrap policy."""

    def build() -> EntryAuthorityBootstrapPolicy:
        row = parse_record(content, ENTRY_AUTHORITY_BOOTSTRAP_SCHEMA, _BOOTSTRAP_FIELDS, "bootstrap")
        value = EntryAuthorityBootstrapPolicy(
            strings(row["reviewed_bundle_reviewer_digests"], "bundle reviewers"),
            pairs(row["forbidden_identity_pairs"], "forbidden pairs"),
            strings(row["trusted_store_identities"], "store identities"),
            integer(row["maximum_bundle_bytes"], "maximum bundle bytes"),
            text(row["policy_digest"], "policy digest"),
        )
        if bootstrap_bytes(value) != content:
            raise InstalledAuthorityWireError("bootstrap does not round-trip canonically")
        return value

    return decode_value("bootstrap", build)


def _authority_record(value: EntryFactAuthorityBundle) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": INSTALLED_AUTHORITY_SCHEMA,
        "pack_files": PACK_FILES,
        "recognition_projection": wire_value(value.recognition_projection),
        "lineages": wire_value(value.lineages),
        "custody_policy": wire_value(value.custody_policy),
        "review_policy": wire_value(value.review_policy),
        "matcher_revision": value.matcher_revision,
        "matcher_behavior_digest": value.matcher_behavior_digest,
        "matcher_lineage_manifest_digest": value.matcher_lineage_manifest_digest,
        "authority_review": wire_value(value.authority_review),
        "bundle_digest": value.bundle_digest,
    }


def installed_authority_bytes(value: EntryFactAuthorityBundle) -> bytes:
    """Encode installed authority while leaving bootstrap trust external."""
    return canonical.canonical_record_bytes(
        _authority_record(value),
        known_schema_versions=(INSTALLED_AUTHORITY_SCHEMA,),
    )


def decode_installed_authority_bytes(
    content: bytes,
    packs: tuple[FactPack, ...],
    contract: FamilyContract,
) -> EntryFactAuthorityBundle:
    """Decode closed installed authority and attach separately decoded packs."""

    def build() -> EntryFactAuthorityBundle:
        row = parse_record(content, INSTALLED_AUTHORITY_SCHEMA, _AUTHORITY_FIELDS, "installed authority")
        if strings(row["pack_files"], "pack_files") != PACK_FILES:
            raise InstalledAuthorityWireError("pack_files must use the fixed order")
        if tuple(pack.language for pack in packs) != _PACK_LANGUAGES:
            raise InstalledAuthorityWireError("packs must use the fixed language order")
        value = EntryFactAuthorityBundle(
            contract,
            packs,
            content_ref(row["recognition_projection"]),
            tuple(lineage(item) for item in items(row["lineages"], "lineages")),
            custody_policy(row["custody_policy"]),
            review_policy(row["review_policy"]),
            text(row["matcher_revision"], "matcher_revision"),
            text(row["matcher_behavior_digest"], "matcher_behavior_digest"),
            text(row["matcher_lineage_manifest_digest"], "matcher_lineage_manifest_digest"),
            attestation(row["authority_review"]),
            text(row["bundle_digest"], "bundle_digest"),
        )
        if installed_authority_bytes(value) != content:
            raise InstalledAuthorityWireError("installed authority does not round-trip canonically")
        return value

    return decode_value("installed authority", build)


@dataclass(frozen=True)
class DigestDirectoryResolver:
    """Read immutable artifacts by validated content digest only."""

    root: Path
    store_identity: str

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        if _DIGEST.fullmatch(reference.content_digest) is None:
            raise canonical.ArtifactResolutionError("content digest is not lowercase SHA-256")
        path = self.root / "artifacts" / "sha256" / reference.content_digest
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise canonical.ArtifactResolutionError("digest-addressed artifact is unavailable") from exc
        if len(content) != reference.byte_length or canonical.bytes_digest(content) != reference.content_digest:
            raise canonical.ArtifactResolutionError("digest-addressed artifact bytes do not match reference")
        receipt_digest = canonical.derive_storage_receipt_digest(
            store_identity=self.store_identity,
            content_digest=reference.content_digest,
            byte_length=reference.byte_length,
            retention_policy_digest=reference.retention_policy_digest,
        )
        receipt = canonical.StorageReceipt(
            self.store_identity,
            reference.content_digest,
            reference.byte_length,
            reference.retention_policy_digest,
            receipt_digest,
        )
        return canonical.ResolvedContent(content, receipt)


__all__ = [
    "DigestDirectoryResolver",
    "INSTALLED_AUTHORITY_SCHEMA",
    "InstalledAuthorityWireError",
    "PACK_FILES",
    "bootstrap_bytes",
    "decode_bootstrap_bytes",
    "decode_fact_pack_bytes",
    "decode_installed_authority_bytes",
    "fact_pack_bytes",
    "installed_authority_bytes",
]
