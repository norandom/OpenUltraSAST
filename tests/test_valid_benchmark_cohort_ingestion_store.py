"""Durable persistence and replay for the bounded Python cohort batch."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    ECOSYSTEM_POLICY,
    GROUND_TRUTH_POLICY,
    PYTHON_COUNT,
    READ_POLICY,
    FakeReader,
    _Client,
    _read_authority,
    _settings,
    authority,
    candidates_for,
    python_cohort_state,
    python_entries,
    request_for,
    resolver,
    reviewed_record,
)

from benchmarks.valid import cohort_ingestion_store  # noqa: E402
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    CohortBatchStatus,
    CohortInsufficientReason,
    cohort_batch_bytes,
    ingest_python_cohort_batch,
)
from benchmarks.valid.replacement_artifact_contract import ArtifactAccessClass, ArtifactKind, validate_artifact  # noqa: E402
from benchmarks.valid.sourcing_queue import SourcingQueueReason, sourcing_queue_policy  # noqa: E402
from benchmarks.valid.sourcing_queue_build import InsufficientFamiliesRefusal, build_sourcing_queue  # noqa: E402


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network or SZZ was invoked")

    import socket

    from benchmarks.unseen import extract

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(extract, "introducing", forbidden)
    monkeypatch.setattr(extract.Git, "blame", forbidden)


def _ingest(records, state, candidates):
    return ingest_python_cohort_batch(
        records,
        state=state,
        candidates_by_digest=candidates,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def _prepared():
    state, resolved = python_cohort_state()
    requests = [request_for(f"py-{index:02d}") for index in range(PYTHON_COUNT)] + [request_for("js-00")]
    return state, candidates_for(requests, resolved)


def _records(state, candidates):
    return [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in python_entries(state)]


def test_accepted_batch_persists_resumes_and_replays_from_durable_evidence():
    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    state, candidates = _prepared()
    records = _records(state, candidates)
    outcome = _ingest(records, state, candidates)
    assert outcome.status is CohortBatchStatus.ACCEPTED

    record_references = cohort_ingestion_store.publish_external_review_records(store, records)
    reference = cohort_ingestion_store.persist_cohort_batch(store, outcome)
    assert cohort_ingestion_store.persist_cohort_batch(store, outcome) == reference
    accepted = store.get(
        reference, expected_kind=ArtifactKind.REVIEW, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    validate_artifact(accepted.content, reference=reference)
    assert reference.access_class is ArtifactAccessClass.OPERATOR_SAFE

    restarted = S3ArtifactRepository(_settings(), client)
    resumed = cohort_ingestion_store.resume_cohort_batch(
        restarted, reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == outcome
    assert cohort_batch_bytes(resumed) == cohort_batch_bytes(outcome)

    reread = cohort_ingestion_store.read_external_review_records(
        restarted, record_references, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    replayed = _ingest(reread, state, candidates)
    assert replayed == outcome
    assert replayed.batch_digest == outcome.batch_digest


def test_refused_batches_durably_persist_their_exclusions():
    store = S3ArtifactRepository(_settings(), _Client())
    state, candidates = _prepared()
    entries = python_entries(state)
    weak = [
        reviewed_record(entries[0], candidates[entries[0].candidate_digest], gt_changes={"defect_present": None}),
        reviewed_record(entries[1], candidates[entries[1].candidate_digest], gt_changes={"conflict_disclosed": False}),
    ]
    good = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries[2:5]]
    outcome = _ingest([weak[0][0], weak[1][0], *good], state, candidates)

    assert outcome.status is CohortBatchStatus.INSUFFICIENT
    assert outcome.insufficient_reason is CohortInsufficientReason.INSUFFICIENT_ACCEPTED_POSITIVES
    reference = cohort_ingestion_store.persist_cohort_batch(store, outcome)

    resumed = cohort_ingestion_store.resume_cohort_batch(
        store, reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == outcome
    reasons = {item.reason for item in resumed.record_outcomes if item.reason is not None}
    assert reasons == {"missing_human_judgment", "conflict_disclosure_missing"}
    assert len(resumed.accepted_positives) == 3
    assert len(resumed.pending_entries) == len(entries) - 5


def test_insufficient_families_refusal_persists_its_exclusions_durably():
    store = S3ArtifactRepository(_settings(), _Client())
    resolved = resolver()
    requests = [request_for("py-00"), request_for("py-00"), request_for("py-02")]
    with pytest.raises(InsufficientFamiliesRefusal) as error:
        build_sourcing_queue(
            requests,
            reader=FakeReader(),
            resolver=resolved,
            authority=authority(resolved),
            policy=sourcing_queue_policy(per_ecosystem_cap=20, required_families=2),
            enumeration_actor="sourcing-operator@example.invalid",
            enumeration_reviewer="enumeration-reviewer@example.invalid",
        )
    attempt = error.value.attempt_exclusions
    assert len(attempt) == 1

    reference = cohort_ingestion_store.persist_refused_queue_exclusions(
        store, attempt, policy_digest=sourcing_queue_policy(per_ecosystem_cap=20).policy_digest
    )
    accepted = store.get(
        reference, expected_kind=ArtifactKind.POPULATION, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    payload = accepted.artifact.payload
    assert payload["exclusions"]
    persisted = payload["exclusions"][0]
    assert persisted["reason"] == SourcingQueueReason.DUPLICATE_CANDIDATE.value
    assert persisted["exclusion_digest"] == attempt[0].exclusion_digest


def test_batch_outcome_decode_refuses_hostile_and_tampered_bytes():
    state, candidates = _prepared()
    outcome = _ingest(_records(state, candidates), state, candidates)
    content = cohort_batch_bytes(outcome)
    decode = cohort_ingestion_store.decode_cohort_batch

    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(b"")
    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(b"not json at all")
    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(b'{"schema_version":"openultrasast.valid-detection-benchmark.python-cohort-batch.v1","x":NaN}')
    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}")
    assert decode(content) == outcome

    import json

    tampered = json.loads(content)
    tampered["batch_digest"] = "0" * 64
    tampered_bytes = json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(tampered_bytes)

    truncated = json.loads(content)
    truncated["accepted_positives"] = truncated["accepted_positives"][:1]
    truncated_bytes = json.dumps(truncated, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(cohort_ingestion_store.CohortStateError):
        decode(truncated_bytes)


def test_batch_outcome_decode_closes_bogus_insufficient_reason_as_state_mismatch():
    state, candidates = _prepared()
    entries = python_entries(state)
    weak = [
        reviewed_record(entries[0], candidates[entries[0].candidate_digest], gt_changes={"defect_present": None}),
        reviewed_record(entries[1], candidates[entries[1].candidate_digest], gt_changes={"conflict_disclosed": False}),
    ]
    good = [reviewed_record(entry, candidates[entry.candidate_digest])[0] for entry in entries[2:5]]
    outcome = _ingest([weak[0][0], weak[1][0], *good], state, candidates)
    assert outcome.status is CohortBatchStatus.INSUFFICIENT

    import json

    tampered = json.loads(cohort_batch_bytes(outcome))
    tampered["insufficient_reason"] = "bogus_reason"
    tampered_bytes = json.dumps(tampered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with pytest.raises(cohort_ingestion_store.CohortStateError) as error:
        cohort_ingestion_store.decode_cohort_batch(tampered_bytes)
    assert error.value.reason is cohort_ingestion_store.CohortStateReason.STATE_MISMATCH
