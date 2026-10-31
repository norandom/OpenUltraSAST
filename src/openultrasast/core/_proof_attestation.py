"""Canonical proof-attestation bytes and bounded artifact resolution."""

from __future__ import annotations

from collections.abc import Collection

from openultrasast.core import canonical

PROOF_ATTESTATION_SCHEMA = "openultrasast.detection-core.proof-attestation.v2"


def proof_attestation_bytes(
    producer_identity_digest: str,
    proof_record_digest: str,
    affected_result_digest: str,
    safe_result_digest: str,
    witness_content_digest: str,
) -> bytes:
    payload: dict[str, canonical.JsonValue] = {
        "schema_version": PROOF_ATTESTATION_SCHEMA,
        "producer_identity_digest": producer_identity_digest,
        "proof_record_digest": proof_record_digest,
        "affected_result_digest": affected_result_digest,
        "safe_result_digest": safe_result_digest,
        "witness_content_digest": witness_content_digest,
    }
    return canonical.canonical_record_bytes(payload, known_schema_versions=(PROOF_ATTESTATION_SCHEMA,))


def validate_proof_artifacts(
    control: canonical.ContentRef,
    witness: canonical.ContentRef,
    attestation: canonical.ContentRef,
    expected_attestation: bytes,
    resolver: canonical.ContentResolver,
    trusted_stores: Collection[str],
    maximum_bytes: int,
) -> None:
    for reference in (control, witness):
        canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=trusted_stores,
            maximum_bytes=maximum_bytes,
        )
    resolved = canonical.resolve_content(
        attestation,
        resolver,
        trusted_store_identities=trusted_stores,
        maximum_bytes=maximum_bytes,
    )
    if resolved != expected_attestation:
        raise canonical.ArtifactValidationError("proof attestation does not bind the exact verification identities")


__all__ = ["PROOF_ATTESTATION_SCHEMA", "proof_attestation_bytes", "validate_proof_artifacts"]
