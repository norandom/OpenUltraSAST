"""Translate verifier-owned differential results into core proof contracts.

This adapter hashes verifier observations and copies immutable identities. It never
executes a sandbox, an oracle, or a demonstration.
"""

from __future__ import annotations

import math

from openultrasast.core import canonical
from openultrasast.core.proof import (
    DIFFERENTIAL_PROOF_SCHEMA,
    ControlBinding,
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofVerificationReceipt,
    derive_producer_identity_digest,
)
from openultrasast.core.semantics import SourceLocation
from openultrasast.search.verify import RunObservation, SideRecord, VerificationRecord


class ProofAdapterError(ValueError):
    """Search verification evidence cannot form a core proof attachment."""


def _duration(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ProofAdapterError(f"{field} must be a finite non-negative duration")
    return float(value)


def _run_value(value: RunObservation) -> canonical.JsonValue:
    if type(value) is not RunObservation or not isinstance(value.observed, bool) or not isinstance(value.evidence, str):
        raise ProofAdapterError("verification runs must use typed observations")
    return {
        "observed": value.observed,
        "evidence_digest": canonical.bytes_digest(value.evidence.encode()),
        "elapsed_seconds": _duration(value.elapsed_seconds, "run elapsed_seconds"),
    }


def _side_value(value: SideRecord) -> canonical.JsonValue:
    if type(value) is not SideRecord or not isinstance(value.outcome, str) or not isinstance(value.reason, str):
        raise ProofAdapterError("verification sides must use typed records")
    if type(value.runs) is not tuple:
        raise ProofAdapterError("verification side runs must be an exact tuple")
    if isinstance(value.scratch_peak_bytes, bool) or not isinstance(value.scratch_peak_bytes, int) or value.scratch_peak_bytes < 0:
        raise ProofAdapterError("scratch_peak_bytes must be a non-negative integer")
    if value.exit_code is not None and (isinstance(value.exit_code, bool) or not isinstance(value.exit_code, int)):
        raise ProofAdapterError("verification exit_code must be an integer or null")
    text = (value.isolation_mode, value.phase, value.stderr, value.stdout)
    if not all(isinstance(item, str) for item in text):
        raise ProofAdapterError("verification side metadata must be text")
    if not isinstance(value.chromium_no_sandbox, bool) or value.control_observed not in (None, True, False):
        raise ProofAdapterError("verification side flags are invalid")
    return {
        "outcome": value.outcome,
        "runs": tuple(_run_value(item) for item in value.runs),
        "elapsed_seconds": _duration(value.elapsed_seconds, "side elapsed_seconds"),
        "reason_digest": canonical.bytes_digest(value.reason.encode()),
        "build_seconds": _duration(value.build_seconds, "build_seconds"),
        "ready_seconds": _duration(value.ready_seconds, "ready_seconds"),
        "run_seconds": _duration(value.run_seconds, "run_seconds"),
        "scratch_peak_bytes": value.scratch_peak_bytes,
        "isolation_mode": value.isolation_mode,
        "chromium_no_sandbox": value.chromium_no_sandbox,
        "phase": value.phase,
        "exit_code": value.exit_code,
        "stderr_digest": canonical.bytes_digest(value.stderr.encode()),
        "stdout_digest": canonical.bytes_digest(value.stdout.encode()),
        "control_observed": value.control_observed,
    }


def _verification_value(value: VerificationRecord) -> canonical.JsonValue:
    if not isinstance(value.reason, str) or not isinstance(value.isolation_mode, str):
        raise ProofAdapterError("verification metadata must be text")
    if not isinstance(value.chromium_no_sandbox, bool):
        raise ProofAdapterError("verification chromium flag must be boolean")
    return {
        "outcome": value.outcome,
        "elapsed_seconds": _duration(value.elapsed_seconds, "verification elapsed_seconds"),
        "reason_digest": canonical.bytes_digest(value.reason.encode()),
        "isolation_mode": value.isolation_mode,
        "chromium_no_sandbox": value.chromium_no_sandbox,
    }


def _observation_digest(side: SideRecord, verification: VerificationRecord) -> str:
    return canonical.content_digest({"side": _side_value(side), "verification": _verification_value(verification)})


def _validate_side_records(value: VerificationRecord, affected: SideRecord, safe: SideRecord) -> None:
    if any(type(item) is not SideRecord or item.outcome != "observed" for item in value.sides):
        raise ProofAdapterError("both proof sides must have observed outcomes")
    if any(type(item.runs) is not tuple or not all(type(run) is RunObservation for run in item.runs) for item in value.sides):
        raise ProofAdapterError("both proof sides require typed run tuples")
    if any(len(item.runs) != 3 for item in value.sides):
        raise ProofAdapterError("both proof sides require exactly three runs")
    if not all(item.observed for item in affected.runs):
        raise ProofAdapterError("affected proof side must be observed in every run")
    if any(item.observed for item in safe.runs):
        raise ProofAdapterError("safe proof side must be unobserved in every run")


def _validated_sides(value: VerificationRecord) -> tuple[SideRecord, SideRecord]:
    if type(value) is not VerificationRecord:
        raise ProofAdapterError("verification must be an exact VerificationRecord")
    if value.outcome != "demonstrated":
        raise ProofAdapterError("only a demonstrated verification can form proof")
    if type(value.sides) is not tuple or len(value.sides) != 2:
        raise ProofAdapterError("demonstrated verification requires exactly two sides")
    affected, safe = value.sides
    _validate_side_records(value, affected, safe)
    if any(item.isolation_mode != value.isolation_mode for item in value.sides):
        raise ProofAdapterError("proof side isolation does not match verification")
    if any(item.chromium_no_sandbox != value.chromium_no_sandbox for item in value.sides):
        raise ProofAdapterError("proof side chromium flag does not match verification")
    _verification_value(value)
    return affected, safe


def map_verification_record(
    verification: VerificationRecord,
    *,
    producer: ProofProducerIdentity,
    affected_input_digest: str,
    safe_input_digest: str,
    control_manifest: canonical.ContentRef,
    control_reviewer_identity: str,
    witness: canonical.ContentRef,
) -> DifferentialProofRecord:
    """Map a completed affected/safe record without running verifier code."""
    affected_record, safe_record = _validated_sides(verification)
    try:
        affected = ProofSideResult(
            affected_input_digest, True, _observation_digest(affected_record, verification), len(affected_record.runs), ""
        )
        safe = ProofSideResult(safe_input_digest, False, _observation_digest(safe_record, verification), len(safe_record.runs), "")
        control = ControlBinding(affected_input_digest, safe_input_digest, control_manifest, control_reviewer_identity, "")
        return DifferentialProofRecord(DIFFERENTIAL_PROOF_SCHEMA, producer, affected, safe, control, witness, ProofOutcome.DEMONSTRATED, "")
    except (TypeError, ValueError) as exc:
        raise ProofAdapterError(f"proof identities are invalid: {exc}") from exc


def make_proof_attachment(
    proof: DifferentialProofRecord,
    *,
    family_id: str,
    packet_digest: str,
    location: SourceLocation,
    attestation: canonical.ContentRef,
) -> ProofAttachment:
    """Bind a mapped proof to its externally stored verification attestation."""
    if type(proof) is not DifferentialProofRecord:
        raise ProofAdapterError("proof must be an exact DifferentialProofRecord")
    try:
        receipt = ProofVerificationReceipt(
            derive_producer_identity_digest(proof.producer),
            proof.record_digest,
            proof.affected.result_digest,
            proof.safe.result_digest,
            proof.witness.content_digest,
            attestation,
            "",
        )
        return ProofAttachment("", family_id, packet_digest, location, proof, receipt)
    except (TypeError, ValueError) as exc:
        raise ProofAdapterError(f"proof attachment identities are invalid: {exc}") from exc


__all__ = ["ProofAdapterError", "make_proof_attachment", "map_verification_record"]
