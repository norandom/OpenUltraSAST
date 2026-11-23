"""Combined closure of the replacement positive set over durable accepted ledgers."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cohort_ingestion_fixtures import (  # noqa: E402
    COMBINED_PYTHON_NAMES,
    FOURTH_PYTHON_NAMES,
    READ_POLICY,
    SINGLE_FAMILY_PYTHON_NAMES,
    THIRD_PYTHON_NAMES,
    _Client,
    _read_authority,
    _settings,
    ingested_replacement_ledger,
    replacement_cohort_state,
)

from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.cohort_ingestion import (  # noqa: E402
    CohortBatchStatus,
    cohort_batch,
    ingest_python_cohort_batch,
)
from benchmarks.valid.cohort_ingestion_store import (  # noqa: E402
    persist_cohort_batch,
    resume_cohort_batch,
)
from benchmarks.valid.positive_set_closure import (  # noqa: E402
    COMBINED_POSITIVE_FLOOR,
    PositiveSetClosureReason,
    PositiveSetClosureStateError,
    PositiveSetClosureStateReason,
    PositiveSetClosureStatus,
    positive_set_closure,
    positive_set_closure_bytes,
    project_positive_set_closure,
)
from benchmarks.valid.positive_set_closure_store import (  # noqa: E402
    decode_positive_set_closure,
    persist_positive_set_closure,
    resume_positive_set_closure,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    validate_artifact,
)


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


def _python_rounds(rounds):
    names = tuple(name for round_names in rounds for name in round_names)
    state, resolved = replacement_cohort_state(python_names=names, javascript_names=())
    ledger = ()
    for round_names in rounds:
        ledger = (*ledger, *ingested_replacement_ledger(state, resolved, python_names=round_names, javascript_names=()))
    return state, resolved, ledger


def _py_only_batches():
    return _python_rounds((COMBINED_PYTHON_NAMES, THIRD_PYTHON_NAMES, FOURTH_PYTHON_NAMES, SINGLE_FAMILY_PYTHON_NAMES))[2]


def test_closure_is_deterministic_across_ledger_permutations():
    batches = _py_only_batches()
    assert len(batches) == 4

    closure = project_positive_set_closure(batches)
    permuted = project_positive_set_closure(tuple(reversed(batches)))

    assert closure == permuted
    assert closure.closure_digest == permuted.closure_digest
    assert closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert closure.reason is PositiveSetClosureReason.MISSING_ECOSYSTEM
    assert closure.total_accepted_positives == 48 >= COMBINED_POSITIVE_FLOOR
    assert dict(closure.positives_by_ecosystem) == {"javascript": 0, "python": 48}
    assert closure.batch_digests == tuple(sorted(batch.batch_digest for batch in batches))
    assert closure.accepted_batch_digests == closure.batch_digests
    assert len(closure.accepted_families) >= 2
    assert decode_positive_set_closure(positive_set_closure_bytes(closure)) == closure


def test_closure_refuses_closed_below_the_floor():
    batches = _python_rounds((COMBINED_PYTHON_NAMES, THIRD_PYTHON_NAMES, FOURTH_PYTHON_NAMES))[2]
    assert len(batches) == 3

    closure = project_positive_set_closure(batches)

    assert closure.status is PositiveSetClosureStatus.INSUFFICIENT
    assert closure.reason is PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES
    assert closure.total_accepted_positives == 36 < COMBINED_POSITIVE_FLOOR
    assert len(closure.accepted_batch_digests) == 3


def test_closure_reports_no_accepted_batches_and_fails_closed_on_malformed_ledgers():
    empty = project_positive_set_closure(())
    assert empty.status is PositiveSetClosureStatus.INSUFFICIENT
    assert empty.reason is PositiveSetClosureReason.NO_ACCEPTED_BATCHES
    assert empty.total_accepted_positives == 0
    assert empty.accepted_batch_digests == () and empty.batch_digests == ()
    assert decode_positive_set_closure(positive_set_closure_bytes(empty)) == empty

    state, resolved = replacement_cohort_state(python_names=COMBINED_PYTHON_NAMES, javascript_names=())
    pending_only = ingest_python_cohort_batch(
        [],
        state=state,
        candidates_by_digest={},
        expected_ecosystem_policy_digest="a" * 64,
        expected_ground_truth_policy_digest="b" * 64,
    )
    assert pending_only.status is CohortBatchStatus.INSUFFICIENT
    unanswered = project_positive_set_closure((pending_only,))
    assert unanswered.status is PositiveSetClosureStatus.INSUFFICIENT
    assert unanswered.reason is PositiveSetClosureReason.NO_ACCEPTED_BATCHES
    assert unanswered.total_accepted_positives == 0

    batches = _py_only_batches()
    first = batches[0]
    second = batches[1]
    conflicted = cohort_batch(
        ecosystem=second.ecosystem,
        queue_digest=second.queue_digest,
        census_digest=second.census_digest,
        ecosystem_policy_digest=second.ecosystem_policy_digest,
        ground_truth_policy_digest=second.ground_truth_policy_digest,
        record_outcomes=second.record_outcomes,
        pending_entries=second.pending_entries,
        accepted_positives=(
            replace(second.accepted_positives[0], change_identity_digest=first.accepted_positives[0].change_identity_digest),
            *second.accepted_positives[1:],
        ),
        status=second.status,
        insufficient_reason=second.insufficient_reason,
    )
    for bad in (
        None,
        {"ecosystem": "python"},
        replace(first, ecosystem="typescript"),
        replace(first, batch_digest="z" * 64),
        replace(first, accepted_positives=()),
        replace(first, accepted_positives=(replace(first.accepted_positives[0], ground_truth_review_digest="y" * 64),)),
        replace(first, accepted_positives=(replace(first.accepted_positives[0], verified_scopes=()),)),
        (first, conflicted),
    ):
        with pytest.raises(PositiveSetClosureStateError) as error:
            project_positive_set_closure(bad if isinstance(bad, tuple) else (bad,))
        assert error.value.reason is PositiveSetClosureStateReason.STATE_MISMATCH


def test_closure_assembler_fails_closed_on_impossible_combinations():
    based = {
        "batch_digests": ("a" * 64, "b" * 64),
        "accepted_batch_digests": ("a" * 64,),
        "total_accepted_positives": 45,
        "positives_by_ecosystem": {"javascript": 21, "python": 24},
        "accepted_families": ("injection", "path_traversal"),
        "status": PositiveSetClosureStatus.CLOSED,
        "reason": PositiveSetClosureReason.ALL_GAPS_CLOSED,
    }
    valid = positive_set_closure(**based)
    assert valid.status is PositiveSetClosureStatus.CLOSED
    assert positive_set_closure_bytes(valid)

    short = positive_set_closure(
        **{
            **based,
            "total_accepted_positives": 39,
            "positives_by_ecosystem": {"javascript": 21, "python": 18},
            "status": PositiveSetClosureStatus.INSUFFICIENT,
            "reason": PositiveSetClosureReason.INSUFFICIENT_TOTAL_POSITIVES,
        }
    )
    assert short.total_accepted_positives == 39

    mutations = (
        {"total_accepted_positives": 39},
        {"positives_by_ecosystem": {"python": 45}},
        {"accepted_families": ("injection",)},
        {"accepted_batch_digests": ()},
        {"total_accepted_positives": 44, "positives_by_ecosystem": {"javascript": 21, "python": 24}},
        {"status": PositiveSetClosureStatus.INSUFFICIENT, "reason": PositiveSetClosureReason.MISSING_ECOSYSTEM},
    )
    for changes in mutations:
        with pytest.raises(PositiveSetClosureStateError) as error:
            positive_set_closure(**{**based, **changes})
        assert error.value.reason is PositiveSetClosureStateReason.STATE_MISMATCH

    with pytest.raises(PositiveSetClosureStateError) as error:
        positive_set_closure(
            **{**based, "status": PositiveSetClosureStatus.INSUFFICIENT, "reason": PositiveSetClosureReason.NO_ACCEPTED_BATCHES}
        )
    assert error.value.reason is PositiveSetClosureStateReason.STATE_MISMATCH


def test_closure_decodes_hostile_bytes_and_persists_durably():
    batches = _py_only_batches()
    closure = project_positive_set_closure(batches)
    content = positive_set_closure_bytes(closure)
    assert content and decode_positive_set_closure(content) == closure

    good = json.loads(content)
    spaced = json.dumps(good, sort_keys=True, indent=1).encode("utf-8")
    wrong_schema = json.dumps({**good, "schema_version": "other.v1"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered = json.dumps({**good, "reason": "insufficient_families"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    for bad in (
        b"",
        b"not json at all",
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"k":' + b"[" * 20000 + b"]" * 20000 + b"}",
        spaced,
        wrong_schema,
        tampered,
    ):
        with pytest.raises(PositiveSetClosureStateError):
            decode_positive_set_closure(bad)

    client = _Client()
    store = S3ArtifactRepository(_settings(), client)
    reference = persist_positive_set_closure(store, closure)
    assert persist_positive_set_closure(store, closure) == reference
    accepted = store.get(
        reference, expected_kind=ArtifactKind.POPULATION, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    validate_artifact(accepted.content, reference=reference)
    assert reference.access_class is ArtifactAccessClass.OPERATOR_SAFE

    batch_references = [persist_cohort_batch(store, batch) for batch in batches]
    resumed_batches = [
        resume_cohort_batch(
            S3ArtifactRepository(_settings(), client), item, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
        )
        for item in batch_references
    ]
    assert project_positive_set_closure(tuple(resumed_batches)) == closure

    resumed = resume_positive_set_closure(
        S3ArtifactRepository(_settings(), client), reference, authority=_read_authority(), expected_access_policy_digest=READ_POLICY
    )
    assert resumed == closure
    assert positive_set_closure_bytes(resumed) == content
