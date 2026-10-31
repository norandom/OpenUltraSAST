"""Differential proof attachment and execution-backed basis tests."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical, provenance
from openultrasast.core._proof_attestation import proof_attestation_bytes
from openultrasast.core.evidence import (
    EVIDENCE_PACKET_SCHEMA,
    AnalyzedScope,
    Decision,
    EvidenceBasis,
    EvidencePacket,
    EvidenceRecord,
    NeutralOutcome,
    SourceRegion,
    derive_packet_digest,
)
from openultrasast.core.proof import (
    DIFFERENTIAL_PROOF_SCHEMA,
    ControlBinding,
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofTrustPolicy,
    ProofValidationError,
    ProofVerificationReceipt,
    attach_differential_proof,
    derive_producer_identity_digest,
)
from openultrasast.core.semantics import (
    EvidenceProvenance,
    FieldKind,
    FieldValue,
    ProvenanceKind,
    RelationKind,
    RelationStatus,
    SemanticNode,
    SourceLocation,
    make_observation,
    make_relation,
)
from openultrasast.core.verdict_v2 import DefectClaim


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _record() -> EvidenceRecord:
    location = SourceLocation("src/app.py", 12, 4, "call")
    relation = make_relation(
        kind=RelationKind.CALL,
        role="flow",
        source=SemanticNode("source", "source", SourceLocation("src/app.py", 10, 2, "source")),
        target=SemanticNode("target", "target", SourceLocation("src/app.py", 11, 2, "target")),
        location=location,
        status=RelationStatus.COMPLETE,
        conditions=(),
        reasons=(),
        provenance=EvidenceProvenance(ProvenanceKind.PRODUCT_CODE, _digest("source"), None, None, None),
    )
    scope = AnalyzedScope("base", "head", _digest("change"), (SourceRegion("src/app.py", 1, 20),))
    stamp = provenance.ProvenanceStamp(
        _digest("analyzer"),
        _digest("family-contract"),
        _digest("facts"),
        _digest("acquisition"),
        _digest("configuration"),
        _digest("population"),
        _digest("change-input"),
    )
    packet = EvidencePacket(
        EVIDENCE_PACKET_SCHEMA,
        "reference-flow",
        stamp.family_contract_digest,
        _digest("object"),
        "python",
        scope,
        (relation,),
        (),
        (FieldValue("name", FieldKind.TEXT, "read"),),
        (),
        stamp,
    )
    decision = Decision(
        "bad",
        NeutralOutcome.VIOLATION,
        EvidenceBasis.DETERMINISTIC,
        scope,
        (),
        derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return EvidenceRecord(packet, decision, "")


def _claim(record: EvidenceRecord) -> DefectClaim:
    return DefectClaim(record, record.decision.basis, record.packet.transitions[0].location, record.packet.scope.regions[0])


@dataclass(frozen=True)
class ProofCase:
    record: EvidenceRecord
    attachment: ProofAttachment
    policy: ProofTrustPolicy
    resolver: InMemoryContentResolver


def _case() -> ProofCase:
    record = _record()
    reviewer = _digest("control-reviewer")
    control_ref, control_resolver = stored_artifact(b'{"control":"safe"}', artifact_id="control")
    witness_ref, witness_resolver = stored_artifact(b'{"affected":true,"safe":false}', artifact_id="witness")
    producer = ProofProducerIdentity(
        "search-with-proof",
        "verifier-v4",
        _digest("sandbox-profile"),
        _digest("oracle-contract"),
        _digest("producer-review"),
    )
    affected = ProofSideResult(record.packet.provenance.change_input_digest, True, _digest("affected-observation"), 2, "")
    safe_input = _digest("safe-control-input")
    safe = ProofSideResult(safe_input, False, _digest("safe-observation"), 2, "")
    control = ControlBinding(affected.input_digest, safe_input, control_ref, reviewer, "")
    proof = DifferentialProofRecord(
        DIFFERENTIAL_PROOF_SCHEMA,
        producer,
        affected,
        safe,
        control,
        witness_ref,
        ProofOutcome.DEMONSTRATED,
        "",
    )
    attestation_ref, attestation_resolver = stored_artifact(
        proof_attestation_bytes(
            derive_producer_identity_digest(producer),
            proof.record_digest,
            affected.result_digest,
            safe.result_digest,
            witness_ref.content_digest,
        ),
        artifact_id="attestation",
    )
    verification = ProofVerificationReceipt(
        derive_producer_identity_digest(producer),
        proof.record_digest,
        affected.result_digest,
        safe.result_digest,
        witness_ref.content_digest,
        attestation_ref,
        "",
    )
    attachment = ProofAttachment(
        "",
        record.packet.family_id,
        derive_packet_digest(record.packet),
        record.packet.transitions[0].location,
        proof,
        verification,
    )
    policy = ProofTrustPolicy(
        (derive_producer_identity_digest(producer),),
        (reviewer,),
        ("trusted-store",),
        4096,
        "",
    )
    artifacts = {
        **control_resolver.artifacts,
        **witness_resolver.artifacts,
        **attestation_resolver.artifacts,
    }
    return ProofCase(record, attachment, policy, InMemoryContentResolver(artifacts))


def test_demonstrated_affected_only_proof_upgrades_basis_without_rollout_authority() -> None:
    case = _case()
    claim = _claim(case.record)
    derived = attach_differential_proof(claim, case.attachment, case.policy, case.resolver)
    assert derived is not claim and derived.record.packet is case.record.packet
    assert derived.location == claim.location and derived.change_anchor == claim.change_anchor
    assert derived.record.decision.outcome is NeutralOutcome.VIOLATION
    assert derived.record.decision.family_code == claim.record.decision.family_code
    assert derived.record.decision.bounded_scope is claim.record.decision.bounded_scope
    assert derived.record.decision.reasons == claim.record.decision.reasons
    assert derived.record.decision.basis is EvidenceBasis.EXECUTION_BACKED
    assert derived.record.decision.provenance.proof_record_digest == case.attachment.proof.record_digest
    assert derived.record.decision.provenance.proof_producer_digest == derive_producer_identity_digest(case.attachment.proof.producer)
    assert not hasattr(derived, "rollout_authorized")


@pytest.mark.parametrize(
    ("outcome", "affected", "safe"),
    (
        (ProofOutcome.INCONCLUSIVE, True, False),
        (ProofOutcome.FAILED, True, False),
        (ProofOutcome.DEMONSTRATED, True, True),
        (ProofOutcome.DEMONSTRATED, False, False),
    ),
)
def test_only_demonstrated_affected_only_behavior_is_eligible(outcome: ProofOutcome, affected: bool, safe: bool) -> None:
    case = _case()
    affected_side = replace(case.attachment.proof.affected, observed=affected, result_digest="")
    safe_side = replace(case.attachment.proof.safe, observed=safe, result_digest="")
    proof = replace(case.attachment.proof, affected=affected_side, safe=safe_side, outcome=outcome, record_digest="")
    verification = replace(
        case.attachment.verification,
        proof_record_digest=proof.record_digest,
        affected_result_digest=affected_side.result_digest,
        safe_result_digest=safe_side.result_digest,
        receipt_digest="",
    )
    attachment = replace(case.attachment, proof=proof, verification=verification, proof_id="")
    with pytest.raises(ProofValidationError, match="affected-only"):
        attach_differential_proof(_claim(case.record), attachment, case.policy, case.resolver)


@pytest.mark.parametrize("field", ("family", "packet", "location", "affected", "safe"))
def test_attachment_must_match_family_packet_location_and_change_control(field: str) -> None:
    case = _case()
    attachment = case.attachment
    if field == "family":
        attachment = replace(attachment, family_id="other-family", proof_id="")
    elif field == "packet":
        attachment = replace(attachment, packet_digest=_digest("other-packet"), proof_id="")
    elif field == "location":
        attachment = replace(attachment, location=SourceLocation("src/other.py", 1, None, None), proof_id="")
    elif field == "affected":
        side = replace(attachment.proof.affected, input_digest=_digest("other-change"), result_digest="")
        proof = replace(attachment.proof, affected=side, record_digest="")
        receipt = replace(
            attachment.verification,
            proof_record_digest=proof.record_digest,
            affected_result_digest=side.result_digest,
            receipt_digest="",
        )
        attachment = replace(attachment, proof=proof, verification=receipt, proof_id="")
    else:
        control = replace(attachment.proof.control, safe_input_digest=_digest("other-safe"), binding_digest="")
        proof = replace(attachment.proof, control=control, record_digest="")
        receipt = replace(attachment.verification, proof_record_digest=proof.record_digest, receipt_digest="")
        attachment = replace(attachment, proof=proof, verification=receipt, proof_id="")
    with pytest.raises(ProofValidationError):
        attach_differential_proof(_claim(case.record), attachment, case.policy, case.resolver)


def test_unreviewed_or_self_asserted_producer_and_control_are_refused() -> None:
    case = _case()
    with pytest.raises(ProofValidationError, match="producer"):
        attach_differential_proof(
            _claim(case.record),
            case.attachment,
            replace(case.policy, reviewed_producer_digests=(_digest("unknown-producer"),), policy_digest=""),
            case.resolver,
        )
    self_asserted = replace(
        case.attachment.proof.control,
        reviewer_identity=derive_producer_identity_digest(case.attachment.proof.producer),
        binding_digest="",
    )
    proof = replace(case.attachment.proof, control=self_asserted, record_digest="")
    receipt = replace(case.attachment.verification, proof_record_digest=proof.record_digest, receipt_digest="")
    attachment = replace(case.attachment, proof=proof, verification=receipt, proof_id="")
    policy = replace(
        case.policy,
        reviewed_control_reviewer_digests=(self_asserted.reviewer_identity,),
        policy_digest="",
    )
    with pytest.raises(ProofValidationError, match="self-asserted"):
        attach_differential_proof(_claim(case.record), attachment, policy, case.resolver)


def test_all_artifacts_must_resolve_under_store_and_byte_policy() -> None:
    case = _case()
    untrusted = replace(case.policy, trusted_store_identities=("other-store",), policy_digest="")
    with pytest.raises(ProofValidationError, match="artifact"):
        attach_differential_proof(_claim(case.record), case.attachment, untrusted, case.resolver)
    too_small = replace(case.policy, maximum_artifact_bytes=1, policy_digest="")
    with pytest.raises(ProofValidationError, match="artifact"):
        attach_differential_proof(_claim(case.record), case.attachment, too_small, case.resolver)


def test_verification_identity_substitution_is_refused() -> None:
    case = _case()
    object.__setattr__(case.attachment.verification, "witness_content_digest", _digest("substituted-witness"))
    with pytest.raises(ProofValidationError, match="verification"):
        attach_differential_proof(_claim(case.record), case.attachment, case.policy, case.resolver)


def test_rehashed_proof_cannot_reuse_a_trusted_attestation() -> None:
    case = _case()
    affected = replace(
        case.attachment.proof.affected,
        observation_digest=_digest("substituted-observation"),
        run_count=case.attachment.proof.affected.run_count + 1,
        result_digest="",
    )
    proof = replace(case.attachment.proof, affected=affected, record_digest="")
    verification = replace(
        case.attachment.verification,
        proof_record_digest=proof.record_digest,
        affected_result_digest=affected.result_digest,
        receipt_digest="",
    )
    attachment = replace(case.attachment, proof=proof, verification=verification, proof_id="")
    with pytest.raises(ProofValidationError, match="attestation"):
        attach_differential_proof(_claim(case.record), attachment, case.policy, case.resolver)


def test_proof_at_another_complete_packet_location_cannot_upgrade_claim() -> None:
    case = _case()
    location_b = SourceLocation("src/app.py", 18, 4, "other")
    observation = make_observation(
        role="context",
        location=location_b,
        fields=(),
        status=RelationStatus.COMPLETE,
        provenance=EvidenceProvenance(ProvenanceKind.PRODUCT_CODE, _digest("other-source"), None, None, None),
    )
    packet = replace(case.record.packet, observations=(observation,))
    decision = replace(case.record.decision, packet_digest=derive_packet_digest(packet))
    record = EvidenceRecord(packet, decision, "")
    claim = DefectClaim(record, record.decision.basis, record.packet.transitions[0].location, record.packet.scope.regions[0])
    attachment = replace(
        case.attachment,
        packet_digest=derive_packet_digest(packet),
        location=location_b,
        proof_id="",
    )
    with pytest.raises(ProofValidationError, match="claim location"):
        attach_differential_proof(claim, attachment, case.policy, case.resolver)


def test_raw_non_claim_record_cannot_gain_execution_backed_basis() -> None:
    case = _case()
    decision = replace(
        case.record.decision,
        family_code="good",
        outcome=NeutralOutcome.SATISFIED,
    )
    record = EvidenceRecord(case.record.packet, decision, "")
    with pytest.raises(ProofValidationError, match="DefectClaim"):
        attach_differential_proof(record, case.attachment, case.policy, case.resolver)  # type: ignore[arg-type]
