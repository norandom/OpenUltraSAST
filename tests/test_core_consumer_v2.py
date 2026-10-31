"""Closed v2 consumer integration for validation, proof, scope, and budget."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, InMemoryPopulationCustody, custody_contract, stored_artifact
from test_core_budget_v2 import _hardware, _reference_workload
from test_core_family import _contract as family_contract
from test_core_family import _record as family_record
from test_core_family import _relation as family_relation
from test_core_validation_v2 import (
    _catalog,
    _deterministic_case,
    _named_inputs,
    _review_policy,
    _trust_policy,
    _with_fact_set,
)

import openultrasast.core.consumer_v2 as consumer_v2
from openultrasast.core import budget, canonical, evidence, validation
from openultrasast.core._proof_attestation import proof_attestation_bytes
from openultrasast.core.consumer_v2 import ConsumerContractError, PushRequest, consume_records, make_push_request
from openultrasast.core.family import FamilyContract
from openultrasast.core.proof import (
    DIFFERENTIAL_PROOF_SCHEMA,
    ControlBinding,
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofProducerIdentity,
    ProofSideResult,
    ProofTrustPolicy,
    ProofVerificationReceipt,
    derive_producer_identity_digest,
)
from openultrasast.core.semantics import RelationStatus


def _measurement(changed_bytes: int = 120) -> tuple[canonical.ContentRef, InMemoryContentResolver]:
    content = canonical.canonical_bytes({"schema_version": budget.CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": changed_bytes})
    return stored_artifact(content, artifact_id="consumer-changed-bytes")


def _resolver(*values: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for value in values:
        artifacts.update(value.artifacts)
    return InMemoryContentResolver(artifacts)


def _request(
    value: validation.EvidenceValidationInput,
    resolver: InMemoryContentResolver,
    *,
    scope: evidence.AnalyzedScope | None = None,
    budget_ms: int = 1_000,
    transition_count: int | None = None,
) -> tuple[PushRequest, InMemoryContentResolver]:
    selected_scope = value.record.packet.scope if scope is None else scope
    measurement, measurement_resolver = _measurement()
    complexity = budget.ChangeComplexity(
        selected_scope.change_digest,
        "small",
        len(selected_scope.regions),
        len(value.record.packet.transitions) if transition_count is None else transition_count,
        120,
        measurement,
    )
    derivation = budget.BudgetDerivation("small", 5, 0.8, _reference_workload(), _hardware(), budget_ms, "")
    request = make_push_request(scope=selected_scope, workload_class="small", complexity=complexity, budget=derivation)
    return request, _resolver(resolver, measurement_resolver)


def _incomplete_case() -> tuple[
    validation.EvidenceValidationInput,
    validation.EvidenceValidationContext,
    InMemoryPopulationCustody,
    InMemoryContentResolver,
]:
    contract = family_contract()
    record = family_record(contract, relation=family_relation(status=RelationStatus.INCOMPLETE), code="unknown")
    return _record_case(record, contract)


def _record_case(
    record: evidence.EvidenceRecord,
    contract: FamilyContract,
) -> tuple[
    validation.EvidenceValidationInput,
    validation.EvidenceValidationContext,
    InMemoryPopulationCustody,
    InMemoryContentResolver,
]:
    record = _with_fact_set(record, ())
    named, resolver = _named_inputs(record, contract, ())
    initial, custody_policy, _ = custody_contract()
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(contract),
        fact_packs=(),
        model_programs=(),
        lineages=(),
        fact_review_policy=_review_policy(),
        provenance_trust_policy=_trust_policy(),
        custody_policy=custody_policy,
    )
    value = validation.make_evidence_validation_input(record=record, named_inputs=named)
    return value, context, InMemoryPopulationCustody(initial, custody_policy), resolver


def _proof(
    record: evidence.EvidenceRecord,
) -> tuple[ProofAttachment, ProofTrustPolicy, InMemoryContentResolver]:
    reviewer = canonical.content_digest("consumer-control-reviewer")
    control_ref, control_resolver = stored_artifact(b'{"control":"safe"}', artifact_id="consumer-control")
    witness_ref, witness_resolver = stored_artifact(b'{"affected":true,"safe":false}', artifact_id="consumer-witness")
    producer = ProofProducerIdentity(
        "consumer-search-proof",
        "verifier-v1",
        canonical.content_digest("consumer-sandbox"),
        canonical.content_digest("consumer-oracle"),
        canonical.content_digest("consumer-producer-review"),
    )
    affected = ProofSideResult(
        record.packet.provenance.change_input_digest,
        True,
        canonical.content_digest("consumer-affected"),
        2,
        "",
    )
    safe = ProofSideResult(
        canonical.content_digest("consumer-safe-input"),
        False,
        canonical.content_digest("consumer-safe"),
        2,
        "",
    )
    control = ControlBinding(affected.input_digest, safe.input_digest, control_ref, reviewer, "")
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
    producer_digest = derive_producer_identity_digest(producer)
    attestation_ref, attestation_resolver = stored_artifact(
        proof_attestation_bytes(
            producer_digest,
            proof.record_digest,
            affected.result_digest,
            safe.result_digest,
            witness_ref.content_digest,
        ),
        artifact_id="consumer-attestation",
    )
    verification = ProofVerificationReceipt(
        producer_digest,
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
        evidence.derive_packet_digest(record.packet),
        record.packet.transitions[0].location,
        proof,
        verification,
    )
    policy = ProofTrustPolicy((producer_digest,), (reviewer,), ("trusted-store",), 4096, "")
    return attachment, policy, _resolver(control_resolver, witness_resolver, attestation_resolver)


def test_synthetic_push_returns_bounded_defect_and_input_budget_identities() -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)

    result = consume_records(request, (value,), context, custody, 100, combined)

    assert result.request_digest == request.request_id
    assert len(result.defects) == 1 and result.satisfactions == () and result.silence == ()
    assert result.input_record_digests == (value.record.record_id,)
    assert result.complexity is request.complexity
    assert result.total_reply_ms >= 100
    assert result.budget_derivation_digest == request.budget.derivation_digest


def test_incomplete_push_preserves_exact_named_silence_reasons() -> None:
    value, context, custody, resolver = _incomplete_case()
    request, combined = _request(value, resolver)

    result = consume_records(request, (value,), context, custody, 100, combined)

    assert result.defects == () and result.satisfactions == ()
    assert len(result.silence) == 1
    assert result.silence[0].reasons == ("missing_reviewed_dependency_relation",)
    assert result.silence[0].evidence_record_digests == (value.record.record_id,)


def test_satisfied_push_returns_completed_questions_and_exact_record_scope() -> None:
    contract = family_contract()
    base = family_record(contract)
    decision = replace(base.decision, family_code="safe", outcome=evidence.NeutralOutcome.SATISFIED)
    value, context, custody, resolver = _record_case(evidence.EvidenceRecord(base.packet, decision, ""), contract)
    request, combined = _request(value, resolver)

    result = consume_records(request, (value,), context, custody, 100, combined)

    assert result.defects == () and result.silence == ()
    assert result.satisfactions[0].question_ids == ("resolve_constraint",)
    assert result.satisfactions[0].scope == value.record.decision.bounded_scope


def test_push_request_identity_is_rederived_before_record_validation() -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)

    with pytest.raises(ConsumerContractError, match="request identity"):
        consume_records(replace(request, request_id="0" * 64), (value,), context, custody, 100, combined)


def test_raw_forged_input_is_revalidated_before_any_output() -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)
    forged = replace(value, input_digest="0" * 64)

    with pytest.raises(ConsumerContractError, match="validation.*input digest"):
        consume_records(request, (forged,), context, custody, 100, combined)


def test_request_scope_and_complexity_must_match_validated_records() -> None:
    value, context, custody, resolver = _deterministic_case()
    narrow = evidence.AnalyzedScope(
        value.record.packet.scope.base_revision,
        value.record.packet.scope.head_revision,
        value.record.packet.scope.change_digest,
        (evidence.SourceRegion("src/app.py", 1, 5),),
    )
    request, combined = _request(value, resolver, scope=narrow)
    with pytest.raises(ConsumerContractError, match="scope"):
        consume_records(request, (value,), context, custody, 100, combined)

    wrong_count, combined = _request(value, resolver, transition_count=2)
    with pytest.raises(ConsumerContractError, match="transition count"):
        consume_records(wrong_count, (value,), context, custody, 100, combined)


def test_optional_proof_is_applied_through_trust_validator() -> None:
    value, context, custody, resolver = _deterministic_case()
    attachment, trust, proof_resolver = _proof(value.record)
    request, combined = _request(value, _resolver(resolver, proof_resolver))
    combined = _resolver(combined, proof_resolver)

    result = consume_records(
        request,
        (value,),
        context,
        custody,
        100,
        combined,
        attachments=(attachment,),
        proof_trust=trust,
    )

    assert result.defects[0].basis is evidence.EvidenceBasis.EXECUTION_BACKED
    assert result.defects[0].record.decision.provenance.proof_record_digest == attachment.proof.record_digest
    with pytest.raises(ConsumerContractError, match="proof trust"):
        consume_records(request, (value,), context, custody, 100, combined, attachments=(attachment,))


def test_measured_deadline_is_checked_after_processing() -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver, budget_ms=10)

    with pytest.raises(ConsumerContractError, match=r"budget:.*ms>10ms"):
        consume_records(request, (value,), context, custody, 11, combined)


def test_measured_deadline_adds_actual_core_processing_time(monkeypatch: pytest.MonkeyPatch) -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver, budget_ms=10)
    ticks = iter((1_000_000, 12_000_001))
    monkeypatch.setattr(consumer_v2, "_monotonic_ns", lambda: next(ticks), raising=False)

    with pytest.raises(ConsumerContractError, match=r"budget:.*13ms>10ms"):
        consume_records(request, (value,), context, custody, 1, combined)


def test_verdict_reports_elapsed_before_entry_plus_measured_core_time(monkeypatch: pytest.MonkeyPatch) -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)
    ticks = iter((1_000_000, 3_500_001))
    monkeypatch.setattr(consumer_v2, "_monotonic_ns", lambda: next(ticks))

    result = consume_records(request, (value,), context, custody, 5, combined)

    assert result.total_reply_ms == 8


def test_budget_measurement_resolution_is_inside_measured_core_time(monkeypatch: pytest.MonkeyPatch) -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver, budget_ms=10)
    clock = [0]

    class DelayedMeasurementResolver:
        def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
            if reference.artifact_id == request.complexity.measurement.artifact_id:
                clock[0] += 20_000_000
            return combined.resolve(reference)

    monkeypatch.setattr(consumer_v2, "_monotonic_ns", lambda: clock[0])

    with pytest.raises(ConsumerContractError, match=r"budget:.*21ms>10ms"):
        consume_records(request, (value,), context, custody, 1, DelayedMeasurementResolver())


@pytest.mark.parametrize(
    ("elapsed_before", "started", "finished", "message"),
    (
        (0, 0, 0, "strictly positive"),
        (1, 2, 1, "monotonic"),
        (1, True, 1, "monotonic"),
        (1, -1, 0, "monotonic"),
        (1, 0, True, "monotonic"),
        (1, 0, -1, "monotonic"),
    ),
)
def test_elapsed_measurement_refuses_invalid_clock_matrix(
    monkeypatch: pytest.MonkeyPatch,
    elapsed_before: int,
    started: int,
    finished: int,
    message: str,
) -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)
    ticks = iter((started, finished))
    monkeypatch.setattr(consumer_v2, "_monotonic_ns", lambda: next(ticks))

    with pytest.raises(ConsumerContractError, match=message):
        consume_records(request, (value,), context, custody, elapsed_before, combined)


@pytest.mark.parametrize(
    ("elapsed_before", "started", "finished", "expected"),
    (
        (0, 5, 6, 1),
        (2, 5, 5, 2),
    ),
)
def test_elapsed_measurement_rounds_nanoseconds_and_allows_preentry_time(
    monkeypatch: pytest.MonkeyPatch,
    elapsed_before: int,
    started: int,
    finished: int,
    expected: int,
) -> None:
    value, context, custody, resolver = _deterministic_case()
    request, combined = _request(value, resolver)
    ticks = iter((started, finished))
    monkeypatch.setattr(consumer_v2, "_monotonic_ns", lambda: next(ticks))

    result = consume_records(request, (value,), context, custody, elapsed_before, combined)

    assert result.total_reply_ms == expected
