"""Differential-proof application against one exact defect claim."""

from __future__ import annotations

from dataclasses import replace

from openultrasast.core import canonical, provenance
from openultrasast.core._proof_attestation import proof_attestation_bytes, validate_proof_artifacts
from openultrasast.core.evidence import EvidenceBasis, EvidenceRecord, derive_packet_digest
from openultrasast.core.proof import (
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofTrustPolicy,
    ProofValidationError,
    ProofVerificationReceipt,
    derive_producer_identity_digest,
)
from openultrasast.core.verdict_v2 import DefectClaim


def _validate_claim_binding(claim: DefectClaim, attachment: ProofAttachment) -> None:
    try:
        claim.__post_init__()
        attachment.__post_init__()
        attachment.proof.__post_init__()
        attachment.proof.producer.__post_init__()
        attachment.proof.affected.__post_init__()
        attachment.proof.safe.__post_init__()
        attachment.proof.control.__post_init__()
        attachment.verification.__post_init__()
    except (TypeError, ValueError) as exc:
        raise ProofValidationError(f"proof attachment identity validation failed: {exc}") from exc
    record = claim.record
    if record.decision.basis is EvidenceBasis.EXECUTION_BACKED:
        raise ProofValidationError("an execution-backed claim cannot replace its proof attachment")
    if attachment.family_id != record.packet.family_id or attachment.packet_digest != derive_packet_digest(record.packet):
        raise ProofValidationError("proof family or packet does not match the defect claim")
    if attachment.location != claim.location:
        raise ProofValidationError("proof attachment does not match the exact claim location")


def _validate_change_and_outcome(record: EvidenceRecord, proof: DifferentialProofRecord) -> None:
    change = record.packet.provenance.change_input_digest
    if proof.affected.input_digest != change or proof.control.affected_change_input_digest != change:
        raise ProofValidationError("affected proof input does not match the evidence change input")
    if proof.safe.input_digest != proof.control.safe_input_digest:
        raise ProofValidationError("safe proof input does not match the reviewed control")
    if proof.affected.input_digest == proof.safe.input_digest:
        raise ProofValidationError("affected and safe proof inputs must be distinct")
    if proof.outcome is not ProofOutcome.DEMONSTRATED or not proof.affected.observed or proof.safe.observed:
        raise ProofValidationError("only demonstrated affected-only behavior can upgrade evidence basis")


def _validate_trust(
    proof: DifferentialProofRecord,
    verification: ProofVerificationReceipt,
    policy: ProofTrustPolicy,
) -> str:
    try:
        policy.__post_init__()
    except (TypeError, ValueError) as exc:
        raise ProofValidationError(f"proof policy validation failed: {exc}") from exc
    producer_digest = derive_producer_identity_digest(proof.producer)
    if producer_digest not in policy.reviewed_producer_digests:
        raise ProofValidationError("proof producer is not independently reviewed")
    reviewer = proof.control.reviewer_identity
    if reviewer not in policy.reviewed_control_reviewer_digests:
        raise ProofValidationError("control reviewer is not admitted by the proof policy")
    producer_ids = (proof.producer.producer_id, canonical.content_digest(proof.producer.producer_id), producer_digest)
    if reviewer in producer_ids:
        raise ProofValidationError("proof producer cannot supply a self-asserted safe control")
    expected = (
        producer_digest,
        proof.record_digest,
        proof.affected.result_digest,
        proof.safe.result_digest,
        proof.witness.content_digest,
    )
    actual = (
        verification.producer_identity_digest,
        verification.proof_record_digest,
        verification.affected_result_digest,
        verification.safe_result_digest,
        verification.witness_content_digest,
    )
    if actual != expected:
        raise ProofValidationError("proof verification identities do not match the proof record")
    return producer_digest


def _resolve_artifacts(
    proof: DifferentialProofRecord,
    verification: ProofVerificationReceipt,
    policy: ProofTrustPolicy,
    resolver: canonical.ContentResolver,
) -> None:
    try:
        expected = proof_attestation_bytes(
            verification.producer_identity_digest,
            verification.proof_record_digest,
            verification.affected_result_digest,
            verification.safe_result_digest,
            verification.witness_content_digest,
        )
        validate_proof_artifacts(
            proof.control.control_manifest,
            proof.witness,
            verification.attestation,
            expected,
            resolver,
            policy.trusted_store_identities,
            policy.maximum_artifact_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError, ValueError) as exc:
        raise ProofValidationError(f"proof artifact validation failed: {exc}") from exc


def attach_differential_proof(
    claim: DefectClaim,
    attachment: ProofAttachment,
    policy: ProofTrustPolicy,
    resolver: canonical.ContentResolver,
) -> DefectClaim:
    if not isinstance(claim, DefectClaim) or not isinstance(attachment, ProofAttachment):
        raise ProofValidationError("proof application requires a DefectClaim and ProofAttachment")
    if not isinstance(policy, ProofTrustPolicy):
        raise ProofValidationError("proof application requires a ProofTrustPolicy")
    _validate_claim_binding(claim, attachment)
    _validate_change_and_outcome(claim.record, attachment.proof)
    producer_digest = _validate_trust(attachment.proof, attachment.verification, policy)
    _resolve_artifacts(attachment.proof, attachment.verification, policy, resolver)
    decision = replace(
        claim.record.decision,
        basis=EvidenceBasis.EXECUTION_BACKED,
        provenance=provenance.DecisionProvenance(None, None, None, attachment.proof.record_digest, producer_digest, None),
    )
    record = EvidenceRecord(claim.record.packet, decision, "")
    return DefectClaim(record, EvidenceBasis.EXECUTION_BACKED, claim.location, claim.change_anchor)


__all__ = ["attach_differential_proof"]
