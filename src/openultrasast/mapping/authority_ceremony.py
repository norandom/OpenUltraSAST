"""Approved repo-local review ceremony for installed entry authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from openultrasast.core import canonical
from openultrasast.mapping._installed_fact_authority_codec import parse_record, text
from openultrasast.mapping.fact_authority import (
    EntryAuthorityBootstrapPolicy,
    EntryFactAuthorityBundle,
    derive_entry_authority_bootstrap_policy_digest,
)
from openultrasast.mapping.installed_fact_authority import decode_bootstrap_bytes

AUTHORITY_IDENTITY_SCHEMA = "openultrasast.access-control.authority-identity.v1"
INSTALLED_ARTIFACT_STORE_IDENTITY = "openultrasast-installed-entry-artifacts-v1"
_IDENTITY_FIELDS = ("schema_version", "role", "name", "approval_basis")
_MAXIMUM_BUNDLE_BYTES = 1_048_576


class AuthorityCeremonyError(ValueError):
    """Installed authority identities do not match the approved ceremony."""


@dataclass(frozen=True)
class AuthorityIdentityManifest:
    """Closed canonical identity whose digest is used at authority boundaries."""

    schema_version: str
    role: str
    name: str
    approval_basis: str

    @property
    def identity_digest(self) -> str:
        return canonical.bytes_digest(identity_manifest_bytes(self))


APPROVED_IDENTITY_MANIFESTS = (
    AuthorityIdentityManifest(
        AUTHORITY_IDENTITY_SCHEMA,
        "producer",
        "openultrasast-entry-pack-generator-v1",
        "generated-from-reviewed-entry-data",
    ),
    AuthorityIdentityManifest(
        AUTHORITY_IDENTITY_SCHEMA,
        "reviewer",
        "openultrasast-maintainer",
        "maintainer-session-approval:2026-11-01",
    ),
    AuthorityIdentityManifest(
        AUTHORITY_IDENTITY_SCHEMA,
        "custodian",
        "openultrasast-installed-entry-custodian-v1",
        "checked-in-artifact-custody",
    ),
)


@dataclass(frozen=True)
class InstalledAuthorityCeremony:
    """Approved identities and the external host bootstrap policy."""

    producer: AuthorityIdentityManifest
    reviewer: AuthorityIdentityManifest
    custodian: AuthorityIdentityManifest
    bootstrap: EntryAuthorityBootstrapPolicy


def identity_manifest_bytes(value: AuthorityIdentityManifest) -> bytes:
    """Encode an identity manifest using the closed canonical schema."""
    if not isinstance(value, AuthorityIdentityManifest):
        raise AuthorityCeremonyError("identity manifest must use the typed contract")
    record: dict[str, canonical.JsonValue] = {
        "schema_version": value.schema_version,
        "role": value.role,
        "name": value.name,
        "approval_basis": value.approval_basis,
    }
    try:
        return canonical.canonical_record_bytes(record, known_schema_versions=(AUTHORITY_IDENTITY_SCHEMA,))
    except (TypeError, ValueError) as exc:
        raise AuthorityCeremonyError(f"invalid identity manifest: {exc}") from exc


def decode_identity_manifest_bytes(content: bytes) -> AuthorityIdentityManifest:
    """Decode only canonical bytes with the exact identity field set."""
    try:
        row = parse_record(content, AUTHORITY_IDENTITY_SCHEMA, _IDENTITY_FIELDS, "authority identity")
        value = AuthorityIdentityManifest(
            text(row["schema_version"], "schema_version"),
            text(row["role"], "role"),
            text(row["name"], "name"),
            text(row["approval_basis"], "approval_basis"),
        )
        if identity_manifest_bytes(value) != content:
            raise AuthorityCeremonyError("identity manifest does not round-trip canonically")
        return value
    except AuthorityCeremonyError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityCeremonyError(f"invalid authority identity: {exc}") from exc


def _approved_bootstrap(reviewer_digest: str) -> EntryAuthorityBootstrapPolicy:
    reviewers = (reviewer_digest,)
    forbidden: tuple[tuple[str, str], ...] = ()
    stores = (INSTALLED_ARTIFACT_STORE_IDENTITY,)
    digest = derive_entry_authority_bootstrap_policy_digest(
        reviewers,
        forbidden,
        stores,
        _MAXIMUM_BUNDLE_BYTES,
    )
    return EntryAuthorityBootstrapPolicy(reviewers, forbidden, stores, _MAXIMUM_BUNDLE_BYTES, digest)


def load_installed_authority_ceremony(entries_root: Path) -> InstalledAuthorityCeremony:
    """Load and pin the checked-in manifests plus external bootstrap policy."""
    identity_root = entries_root / "identities"
    filenames = ("generator.json", "maintainer-reviewer.json", "custodian.json")
    try:
        manifests = tuple(decode_identity_manifest_bytes((identity_root / name).read_bytes()) for name in filenames)
        bootstrap = decode_bootstrap_bytes((entries_root / "bootstrap.json").read_bytes())
    except OSError as exc:
        raise AuthorityCeremonyError("installed ceremony record is unavailable") from exc
    except ValueError as exc:
        raise AuthorityCeremonyError(f"installed ceremony record is invalid: {exc}") from exc
    if manifests != APPROVED_IDENTITY_MANIFESTS:
        raise AuthorityCeremonyError("installed identity fields differ from the approved ceremony")
    expected_bootstrap = _approved_bootstrap(manifests[1].identity_digest)
    if bootstrap != expected_bootstrap:
        raise AuthorityCeremonyError("installed bootstrap differs from the approved ceremony")
    return InstalledAuthorityCeremony(*manifests, bootstrap)


def _require_binding(condition: bool, label: str) -> None:
    if not condition:
        raise AuthorityCeremonyError(f"{label} identity binding does not match the approved ceremony")


def _validate_pack_bindings(
    bundle: EntryFactAuthorityBundle,
    producer_digest: str,
    reviewer_digest: str,
) -> None:
    for pack in bundle.packs:
        _require_binding(pack.review_identity == reviewer_digest, "pack review")
        for evidence in pack.review_evidence:
            _require_binding(evidence.producer_identity == producer_digest, "pack producer")
            _require_binding(evidence.reviewer_identity == reviewer_digest, "pack reviewer")
            _require_binding(evidence.independence.producer_identity == producer_digest, "pack attestation producer")
            _require_binding(evidence.independence.reviewer_identity == reviewer_digest, "pack attestation reviewer")


def validate_authority_ceremony_bindings(
    ceremony: InstalledAuthorityCeremony,
    bundle: EntryFactAuthorityBundle,
) -> None:
    """Require every authority and pack identity to use the manifest digests."""
    producer = ceremony.producer.identity_digest
    reviewer = ceremony.reviewer.identity_digest
    custodian = ceremony.custodian.identity_digest
    bootstrap = ceremony.bootstrap
    _require_binding(bootstrap.reviewed_bundle_reviewer_digests == (reviewer,), "bootstrap reviewer admission")
    _require_binding(bootstrap.trusted_store_identities == (INSTALLED_ARTIFACT_STORE_IDENTITY,), "bootstrap store admission")
    expected_policy = derive_entry_authority_bootstrap_policy_digest(
        bootstrap.reviewed_bundle_reviewer_digests,
        bootstrap.forbidden_identity_pairs,
        bootstrap.trusted_store_identities,
        bootstrap.maximum_bundle_bytes,
    )
    _require_binding(bootstrap.policy_digest == expected_policy, "bootstrap policy")
    _require_binding(producer != reviewer, "producer/reviewer separation")
    _require_binding((producer, reviewer) not in bootstrap.forbidden_identity_pairs, "forbidden pair")
    _require_binding(bundle.review_policy.reviewed_reviewer_digests == (reviewer,), "review policy reviewer admission")
    _require_binding(
        bundle.review_policy.trusted_store_identities == bootstrap.trusted_store_identities,
        "review policy store admission",
    )
    _require_binding(bundle.custody_policy.reviewed_custodian_digests == (custodian,), "custody")
    _require_binding(bundle.authority_review.producer_identity == producer, "authority producer")
    _require_binding(bundle.authority_review.reviewer_identity == reviewer, "authority reviewer")
    _validate_pack_bindings(bundle, producer, reviewer)


__all__ = [
    "APPROVED_IDENTITY_MANIFESTS",
    "AUTHORITY_IDENTITY_SCHEMA",
    "INSTALLED_ARTIFACT_STORE_IDENTITY",
    "AuthorityCeremonyError",
    "AuthorityIdentityManifest",
    "InstalledAuthorityCeremony",
    "decode_identity_manifest_bytes",
    "identity_manifest_bytes",
    "load_installed_authority_ceremony",
    "validate_authority_ceremony_bindings",
]
