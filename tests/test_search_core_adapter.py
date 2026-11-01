"""Search verification records cross a conservative core proof boundary."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_proof import _case, _claim

from openultrasast.core._proof_attestation import proof_attestation_bytes
from openultrasast.core.evidence import EvidenceBasis
from openultrasast.core.proof import (
    ProofValidationError,
    attach_differential_proof,
    derive_producer_identity_digest,
)
from openultrasast.search.core_adapter import ProofAdapterError, make_proof_attachment, map_verification_record
from openultrasast.search.verify import RunObservation, SideRecord, VerificationRecord


def _verification(*, outcome: str = "demonstrated", affected: bool = True, safe: bool = False) -> VerificationRecord:
    def side(observed: bool, name: str) -> SideRecord:
        runs = tuple(RunObservation(observed, f"{name}:{index}", 0.01) for index in range(3))
        return SideRecord("observed", runs, 0.03, "complete", isolation_mode="task-boundary")

    return VerificationRecord(
        outcome,
        (side(affected, "affected"), side(safe, "safe")),
        0.06,
        "owned differential",
        isolation_mode="task-boundary",
    )


def _mapped(record: VerificationRecord):
    case = _case()
    proof = map_verification_record(
        record,
        producer=case.attachment.proof.producer,
        affected_input_digest=case.attachment.proof.affected.input_digest,
        safe_input_digest=case.attachment.proof.safe.input_digest,
        control_manifest=case.attachment.proof.control.control_manifest,
        control_reviewer_identity=case.attachment.proof.control.reviewer_identity,
        witness=case.attachment.proof.witness,
    )
    return case, proof


def test_demonstrated_verification_maps_and_attaches_without_execution_ownership() -> None:
    case, proof = _mapped(_verification())
    attestation, resolver = stored_artifact(
        proof_attestation_bytes(
            derive_producer_identity_digest(proof.producer),
            proof.record_digest,
            proof.affected.result_digest,
            proof.safe.result_digest,
            proof.witness.content_digest,
        ),
        artifact_id="search-verification-attestation",
    )
    attachment = make_proof_attachment(
        proof,
        family_id=case.attachment.family_id,
        packet_digest=case.attachment.packet_digest,
        location=case.attachment.location,
        attestation=attestation,
    )
    merged = InMemoryContentResolver({**case.resolver.artifacts, **resolver.artifacts})

    derived = attach_differential_proof(_claim(case.record), attachment, case.policy, merged)

    assert derived.basis is EvidenceBasis.EXECUTION_BACKED
    assert derived.record.decision.provenance.proof_record_digest == proof.record_digest


def test_complete_verification_metadata_is_bound_into_proof_identity() -> None:
    record = _verification()
    _, proof = _mapped(record)

    _, changed_reason = _mapped(replace(record, reason="different verifier reason"))
    changed_run = replace(record.sides[0].runs[0], evidence="different observation")
    changed_side = replace(record.sides[0], runs=(changed_run, *record.sides[0].runs[1:]))
    _, changed_evidence = _mapped(replace(record, sides=(changed_side, record.sides[1])))

    assert changed_reason.record_digest != proof.record_digest
    assert changed_evidence.record_digest != proof.record_digest


@pytest.mark.parametrize(
    ("record", "reason"),
    (
        (_verification(outcome="inconclusive"), "demonstrated"),
        (_verification(affected=False), "affected"),
        (_verification(safe=True), "safe"),
        (replace(_verification(), sides=_verification().sides[:1]), "two sides"),
    ),
)
def test_inconclusive_or_non_differential_verification_is_refused(record: VerificationRecord, reason: str) -> None:
    with pytest.raises(ProofAdapterError, match=reason):
        _mapped(record)


def test_mismatched_fixture_remains_at_prior_basis() -> None:
    case, proof = _mapped(_verification())
    affected = replace(
        proof.affected,
        input_digest=case.attachment.proof.safe.input_digest,
        result_digest="",
    )
    wrong = replace(proof, affected=affected, record_digest="")
    attestation, resolver = stored_artifact(
        proof_attestation_bytes(
            derive_producer_identity_digest(wrong.producer),
            wrong.record_digest,
            wrong.affected.result_digest,
            wrong.safe.result_digest,
            wrong.witness.content_digest,
        ),
        artifact_id="mismatched-search-attestation",
    )
    attachment = make_proof_attachment(
        wrong,
        family_id=case.attachment.family_id,
        packet_digest=case.attachment.packet_digest,
        location=case.attachment.location,
        attestation=attestation,
    )
    merged = InMemoryContentResolver({**case.resolver.artifacts, **resolver.artifacts})
    claim = _claim(case.record)

    with pytest.raises(ProofValidationError, match="affected proof input"):
        attach_differential_proof(claim, attachment, case.policy, merged)
    assert claim.basis is EvidenceBasis.DETERMINISTIC
