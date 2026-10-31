"""Canonical differential-proof validation for execution-backed evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core.semantics import SourceLocation
from openultrasast.core.verdict_v2 import DefectClaim

DIFFERENTIAL_PROOF_SCHEMA = "openultrasast.detection-core.differential-proof.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ProofValidationError(ValueError):
    """A proof attachment cannot reproduce execution-backed evidence."""


class ProofOutcome(Enum):
    DEMONSTRATED = "demonstrated"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProofValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ProofValidationError(f"{field} must be nonempty text")


def _positive(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProofValidationError(f"{field} must be a positive integer")


def _ref_value(value: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "media_type": value.media_type,
        "byte_length": value.byte_length,
        "retention_policy_digest": value.retention_policy_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
    }


def _location_value(value: SourceLocation) -> canonical.JsonValue:
    return {"path": value.path, "line": value.line, "column": value.column, "symbol": value.symbol}


@dataclass(frozen=True)
class ProofProducerIdentity:
    producer_id: str
    verifier_revision: str
    sandbox_profile_digest: str
    oracle_contract_digest: str
    review_digest: str

    def __post_init__(self) -> None:
        _text(self.producer_id, "producer_id")
        _text(self.verifier_revision, "verifier_revision")
        for value, field in (
            (self.sandbox_profile_digest, "sandbox_profile_digest"),
            (self.oracle_contract_digest, "oracle_contract_digest"),
            (self.review_digest, "review_digest"),
        ):
            _digest(value, field)


def _producer_value(value: ProofProducerIdentity) -> canonical.JsonValue:
    return {
        "producer_id": value.producer_id,
        "verifier_revision": value.verifier_revision,
        "sandbox_profile_digest": value.sandbox_profile_digest,
        "oracle_contract_digest": value.oracle_contract_digest,
        "review_digest": value.review_digest,
    }


def derive_producer_identity_digest(value: ProofProducerIdentity) -> str:
    value.__post_init__()
    return canonical.content_digest(_producer_value(value))


@dataclass(frozen=True)
class ProofSideResult:
    input_digest: str
    observed: bool
    observation_digest: str
    run_count: int
    result_digest: str

    def __post_init__(self) -> None:
        _digest(self.input_digest, "proof side input_digest")
        if not isinstance(self.observed, bool):
            raise ProofValidationError("proof side observed must be boolean")
        _digest(self.observation_digest, "proof side observation_digest")
        _positive(self.run_count, "proof side run_count")
        expected = derive_proof_side_result_digest(self)
        if not self.result_digest:
            object.__setattr__(self, "result_digest", expected)
        elif self.result_digest != expected:
            raise ProofValidationError("proof side result digest cannot be re-derived")


def _side_value(value: ProofSideResult) -> dict[str, canonical.JsonValue]:
    return {
        "input_digest": value.input_digest,
        "observed": value.observed,
        "observation_digest": value.observation_digest,
        "run_count": value.run_count,
    }


def derive_proof_side_result_digest(value: ProofSideResult) -> str:
    return canonical.content_digest(_side_value(value))


@dataclass(frozen=True)
class ControlBinding:
    affected_change_input_digest: str
    safe_input_digest: str
    control_manifest: canonical.ContentRef
    reviewer_identity: str
    binding_digest: str

    def __post_init__(self) -> None:
        _digest(self.affected_change_input_digest, "affected_change_input_digest")
        _digest(self.safe_input_digest, "safe_input_digest")
        if not isinstance(self.control_manifest, canonical.ContentRef):
            raise ProofValidationError("control_manifest must be a ContentRef")
        _digest(self.reviewer_identity, "control reviewer_identity")
        expected = derive_control_binding_digest(self)
        if not self.binding_digest:
            object.__setattr__(self, "binding_digest", expected)
        elif self.binding_digest != expected:
            raise ProofValidationError("control binding digest cannot be re-derived")


def _control_value(value: ControlBinding) -> dict[str, canonical.JsonValue]:
    return {
        "affected_change_input_digest": value.affected_change_input_digest,
        "safe_input_digest": value.safe_input_digest,
        "control_manifest": _ref_value(value.control_manifest),
        "reviewer_identity": value.reviewer_identity,
    }


def derive_control_binding_digest(value: ControlBinding) -> str:
    return canonical.content_digest(_control_value(value))


@dataclass(frozen=True)
class DifferentialProofRecord:
    schema_version: str
    producer: ProofProducerIdentity
    affected: ProofSideResult
    safe: ProofSideResult
    control: ControlBinding
    witness: canonical.ContentRef
    outcome: ProofOutcome
    record_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != DIFFERENTIAL_PROOF_SCHEMA:
            raise ProofValidationError("unknown differential proof schema")
        if not isinstance(self.producer, ProofProducerIdentity):
            raise ProofValidationError("producer must use ProofProducerIdentity")
        if not isinstance(self.affected, ProofSideResult) or not isinstance(self.safe, ProofSideResult):
            raise ProofValidationError("proof sides must use ProofSideResult")
        if not isinstance(self.control, ControlBinding) or not isinstance(self.witness, canonical.ContentRef):
            raise ProofValidationError("proof control and witness have invalid types")
        if not isinstance(self.outcome, ProofOutcome):
            raise ProofValidationError("proof outcome is invalid")
        expected = derive_differential_proof_record_digest(self)
        if not self.record_digest:
            object.__setattr__(self, "record_digest", expected)
        elif self.record_digest != expected:
            raise ProofValidationError("differential proof digest cannot be re-derived")


def _proof_value(value: DifferentialProofRecord) -> canonical.JsonValue:
    return {
        "schema_version": value.schema_version,
        "producer": _producer_value(value.producer),
        "affected": {**_side_value(value.affected), "result_digest": value.affected.result_digest},
        "safe": {**_side_value(value.safe), "result_digest": value.safe.result_digest},
        "control": {**_control_value(value.control), "binding_digest": value.control.binding_digest},
        "witness": _ref_value(value.witness),
        "outcome": value.outcome.value,
    }


def derive_differential_proof_record_digest(value: DifferentialProofRecord) -> str:
    return canonical.content_digest(_proof_value(value))


@dataclass(frozen=True)
class ProofVerificationReceipt:
    producer_identity_digest: str
    proof_record_digest: str
    affected_result_digest: str
    safe_result_digest: str
    witness_content_digest: str
    attestation: canonical.ContentRef
    receipt_digest: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.producer_identity_digest, "producer_identity_digest"),
            (self.proof_record_digest, "proof_record_digest"),
            (self.affected_result_digest, "affected_result_digest"),
            (self.safe_result_digest, "safe_result_digest"),
            (self.witness_content_digest, "witness_content_digest"),
        ):
            _digest(value, field)
        if not isinstance(self.attestation, canonical.ContentRef):
            raise ProofValidationError("attestation must be a ContentRef")
        expected = derive_proof_verification_receipt_digest(self)
        if not self.receipt_digest:
            object.__setattr__(self, "receipt_digest", expected)
        elif self.receipt_digest != expected:
            raise ProofValidationError("proof verification receipt digest cannot be re-derived")


def _verification_value(value: ProofVerificationReceipt) -> canonical.JsonValue:
    return {
        "producer_identity_digest": value.producer_identity_digest,
        "proof_record_digest": value.proof_record_digest,
        "affected_result_digest": value.affected_result_digest,
        "safe_result_digest": value.safe_result_digest,
        "witness_content_digest": value.witness_content_digest,
        "attestation": _ref_value(value.attestation),
    }


def derive_proof_verification_receipt_digest(value: ProofVerificationReceipt) -> str:
    return canonical.content_digest(_verification_value(value))


@dataclass(frozen=True)
class ProofTrustPolicy:
    reviewed_producer_digests: tuple[str, ...]
    reviewed_control_reviewer_digests: tuple[str, ...]
    trusted_store_identities: tuple[str, ...]
    maximum_artifact_bytes: int
    policy_digest: str

    def __post_init__(self) -> None:
        for values, field in (
            (self.reviewed_producer_digests, "reviewed producer"),
            (self.reviewed_control_reviewer_digests, "reviewed control reviewer"),
        ):
            if not values:
                raise ProofValidationError(f"{field} identities must be nonempty")
            for value in values:
                _digest(value, field)
            canonical.require_unique_identities(values, kind=field)
        if not self.trusted_store_identities or not all(isinstance(value, str) and value for value in self.trusted_store_identities):
            raise ProofValidationError("trusted store identities must be nonempty text")
        canonical.require_unique_identities(self.trusted_store_identities, kind="trusted store")
        _positive(self.maximum_artifact_bytes, "maximum_artifact_bytes")
        expected = derive_proof_trust_policy_digest(self)
        if not self.policy_digest:
            object.__setattr__(self, "policy_digest", expected)
        elif self.policy_digest != expected:
            raise ProofValidationError("proof trust policy digest cannot be re-derived")


def derive_proof_trust_policy_digest(value: ProofTrustPolicy) -> str:
    payload: canonical.JsonValue = {
        "reviewed_producer_digests": tuple(sorted(value.reviewed_producer_digests)),
        "reviewed_control_reviewer_digests": tuple(sorted(value.reviewed_control_reviewer_digests)),
        "trusted_store_identities": tuple(sorted(value.trusted_store_identities)),
        "maximum_artifact_bytes": value.maximum_artifact_bytes,
    }
    return canonical.content_digest(payload)


@dataclass(frozen=True)
class ProofAttachment:
    proof_id: str
    family_id: str
    packet_digest: str
    location: SourceLocation
    proof: DifferentialProofRecord
    verification: ProofVerificationReceipt

    def __post_init__(self) -> None:
        _text(self.family_id, "proof family_id")
        _digest(self.packet_digest, "proof packet_digest")
        if not isinstance(self.location, SourceLocation):
            raise ProofValidationError("proof location must be a SourceLocation")
        if not isinstance(self.proof, DifferentialProofRecord) or not isinstance(self.verification, ProofVerificationReceipt):
            raise ProofValidationError("proof attachment has invalid proof or verification")
        expected = derive_proof_attachment_id(self)
        if not self.proof_id:
            object.__setattr__(self, "proof_id", expected)
        elif self.proof_id != expected:
            raise ProofValidationError("proof attachment identity cannot be re-derived")


def derive_proof_attachment_id(value: ProofAttachment) -> str:
    payload: canonical.JsonValue = {
        "family_id": value.family_id,
        "packet_digest": value.packet_digest,
        "location": _location_value(value.location),
        "proof_record_digest": value.proof.record_digest,
        "verification_receipt_digest": value.verification.receipt_digest,
    }
    return canonical.content_digest(payload)


def attach_differential_proof(
    claim: DefectClaim,
    attachment: ProofAttachment,
    policy: ProofTrustPolicy,
    resolver: canonical.ContentResolver,
) -> DefectClaim:
    """Validate and attach affected-only proof without granting rollout permission."""
    from openultrasast.core._proof_apply import attach_differential_proof as apply_proof

    return apply_proof(claim, attachment, policy, resolver)


__all__ = [
    "ControlBinding",
    "DIFFERENTIAL_PROOF_SCHEMA",
    "DifferentialProofRecord",
    "ProofAttachment",
    "ProofOutcome",
    "ProofProducerIdentity",
    "ProofSideResult",
    "ProofTrustPolicy",
    "ProofValidationError",
    "ProofVerificationReceipt",
    "attach_differential_proof",
    "derive_producer_identity_digest",
]
