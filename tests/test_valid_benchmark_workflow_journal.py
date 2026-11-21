"""Task 7.2 causal workflow journal, lease-protected CAS head, stalled projection."""

from __future__ import annotations

import io
import json
import re
import sys
import threading
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import workflow_journal  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    canonical_json_bytes,
)
from benchmarks.valid.store_configuration import StorePurpose, StoreSettings  # noqa: E402
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core import canonical  # noqa: E402

_HEX64 = re.compile(r"[0-9a-f]{64}")


class _ProviderError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code, "Message": "provider password=/private/path"}}
        super().__init__("provider secret")


class _Version:
    def __init__(self, version_id: str, body: bytes, etag: str) -> None:
        self.version_id = version_id
        self.body = body
        self.etag = etag


class _Client:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.versions: dict[str, list[_Version]] = {}
        self.next_version = 1
        self.force_head_conflict = False
        self.provider_failure = False
        self.corrupt_reads = False
        self.head_write_barrier: threading.Barrier | None = None

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        barrier = self.head_write_barrier
        if barrier is not None and key.endswith("head.json") and "IfMatch" in kwargs:
            barrier.wait(timeout=5)
        with self.lock:
            if self.provider_failure:
                raise _ProviderError("InternalError")
            versions = self.versions.setdefault(key, [])
            current = versions[-1] if versions else None
            if self.force_head_conflict and key.endswith("head.json"):
                raise _ProviderError("PreconditionFailed")
            if kwargs.get("IfNoneMatch") == "*" and current is not None:
                raise _ProviderError("PreconditionFailed")
            expected = kwargs.get("IfMatch")
            if expected is not None and (current is None or current.etag != expected):
                raise _ProviderError("PreconditionFailed")
            body = kwargs["Body"]
            assert isinstance(body, bytes) and body
            version_id = f"version-{self.next_version}"
            self.next_version += 1
            etag = sha256(body + version_id.encode()).hexdigest()
            versions.append(_Version(version_id, body, etag))
            return {"ETag": etag, "VersionId": version_id}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        with self.lock:
            if self.provider_failure:
                raise _ProviderError("InternalError")
            key = str(kwargs["Key"])
            requested = kwargs.get("VersionId")
            matching = [item for item in self.versions.get(key, []) if requested is None or item.version_id == requested]
            if not matching:
                raise _ProviderError("NoSuchKey")
            version = matching[-1]
            body = b"corrupt" if self.corrupt_reads else version.body
            return {
                "Body": io.BytesIO(body),
                "ContentLength": len(body),
                "VersionId": version.version_id,
                "ETag": version.etag,
            }

    def drop(self, key: str) -> None:
        with self.lock:
            self.versions.pop(key, None)

    def raw_put(self, key: str, body: bytes) -> None:
        with self.lock:
            version_id = f"version-{self.next_version}"
            self.next_version += 1
            self.versions.setdefault(key, []).append(_Version(version_id, body, sha256(body + version_id.encode()).hexdigest()))


def _digest(seed: str) -> str:
    return canonical.content_digest({"seed": seed})


def _settings(purpose: StorePurpose = StorePurpose.TRANSIENT) -> StoreSettings:
    return StoreSettings(
        purpose,
        f"https://{purpose.value}.invalid:9000",
        f"valid-{purpose.value}",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _journal(client: _Client) -> workflow_journal.S3WorkflowJournal:
    return workflow_journal.S3WorkflowJournal(_settings(), client)


def _authority(
    seed: str = "authority",
    kind: ArtifactKind = ArtifactKind.WORKFLOW,
    access: ArtifactAccessClass = ArtifactAccessClass.CUSTODIAN_SEALED,
) -> ArtifactReference:
    content = _digest(seed)
    return ArtifactReference(kind, content, 256, _digest(f"{seed}-provenance"), access)


def _at(minute: int) -> str:
    hour, minute = divmod(minute, 60)
    return f"2026-11-20T{9 + hour:02d}:{minute:02d}:00Z"


def _entry(**overrides: object) -> workflow_journal.WorkflowJournalEntryV1:
    value: dict[str, object] = {
        "workflow_digest": _digest("workflow"),
        "sequence": 1,
        "previous_entry_digest": _digest("entry-0"),
        "attempt_id": "attempt-1",
        "lease_owner_id": "owner-a",
        "phase": WorkflowPhase.ARM_EXECUTION,
        "heartbeat_at": _at(1),
        "lease_expires_at": _at(31),
        "counts": WorkflowCounts(2, 1, 12, 5, 0),
        "entry_digest": "",
    }
    value.update(overrides)
    return workflow_journal.WorkflowJournalEntryV1(**value)  # type: ignore[arg-type]


def _initial_entry() -> workflow_journal.WorkflowJournalEntryV1:
    return _entry(
        sequence=0,
        previous_entry_digest=None,
        phase=WorkflowPhase.PREFLIGHT,
        counts=WorkflowCounts(2, 0, 12, 0, 0),
    )


def _started(
    client: _Client, authority: ArtifactReference | None = None
) -> tuple[workflow_journal.S3WorkflowJournal, workflow_journal.WorkflowHeadV1]:
    journal = _journal(client)
    selected = authority if authority is not None else _authority()
    head = journal.initialize(_initial_entry(), selected, selected.content_digest)
    assert head is not None
    return journal, head


def _successor(
    head: workflow_journal.WorkflowHeadV1, sequence: int, **overrides: object
) -> tuple[workflow_journal.WorkflowJournalEntryV1, workflow_journal.WorkflowHeadV1]:
    fields: dict[str, object] = {
        "heartbeat_at": _at(sequence),
        "lease_expires_at": _at(sequence + 30),
    }
    fields.update(overrides)
    entry = _entry(sequence=sequence, previous_entry_digest=head.entry_digest, **fields)
    return entry, workflow_journal.successor_head(head, entry)


def _appended(
    journal: workflow_journal.S3WorkflowJournal,
    head: workflow_journal.WorkflowHeadV1,
    sequence: int,
    **overrides: object,
) -> workflow_journal.WorkflowHeadV1:
    entry, successor = _successor(head, sequence, **overrides)
    assert journal.append_and_swap(head.head_digest, entry, successor) is True
    return successor


def _run_threads(action: Callable[[], object], count: int = 2) -> list[object]:
    results: list[object] = []
    lock = threading.Lock()

    def target() -> None:
        outcome = action()
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=target) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    return results


def _reserialized(content: bytes, mutate: Callable[[dict[str, object]], None]) -> bytes:
    value = json.loads(content)
    assert isinstance(value, dict)
    mutate(value)
    return canonical_json_bytes(value)


def test_entry_binds_exact_causal_fields_with_byte_identical_digest() -> None:
    first = _entry()
    second = _entry()
    assert first == second
    assert workflow_journal.journal_entry_bytes(first) == workflow_journal.journal_entry_bytes(second)
    assert _HEX64.fullmatch(first.entry_digest)
    changed = _entry(counts=WorkflowCounts(2, 2, 12, 6, 0))
    assert changed.entry_digest != first.entry_digest
    decoded = workflow_journal.decode_workflow_journal_entry(workflow_journal.journal_entry_bytes(first))
    assert decoded == first


def test_entry_rejects_free_form_or_noncanonical_content() -> None:
    cases: list[dict[str, object]] = [
        {"workflow_digest": "not-a-digest"},
        {"sequence": -1},
        {"sequence": "1"},
        {"previous_entry_digest": "not-a-digest"},
        {"attempt_id": "attempt;/rm -rf"},
        {"attempt_id": ""},
        {"lease_owner_id": "owner with spaces"},
        {"phase": "tuning"},
        {"heartbeat_at": "2026-11-20 09:00:00"},
        {"heartbeat_at": "2026-13-20T09:00:00Z"},
        {"lease_expires_at": _at(1)},
        {"counts": (2, 1, 12, 5, 0)},
    ]
    for overrides in cases:
        with pytest.raises(workflow_journal.WorkflowJournalError) as report:
            _entry(**overrides)
        assert report.value.reason is workflow_journal.WorkflowJournalReason.INVALID_REQUEST


def test_head_round_trip_and_noncanonical_bytes_are_refused() -> None:
    authority = _authority()
    entry = _initial_entry()
    head = workflow_journal.WorkflowHeadV1(
        entry.workflow_digest,
        0,
        entry.entry_digest,
        entry.lease_owner_id,
        entry.lease_expires_at,
        authority,
        authority.content_digest,
        "",
    )
    content = workflow_journal.journal_head_bytes(head)
    assert workflow_journal.decode_workflow_head(content) == head
    assert b"password" not in content and b"/private" not in content

    def drop_field(value: dict[str, object]) -> None:
        value.pop("head_digest")

    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        workflow_journal.decode_workflow_head(_reserialized(content, drop_field))
    assert report.value.reason is workflow_journal.WorkflowJournalReason.MALFORMED_CONTENT
    with pytest.raises(workflow_journal.WorkflowJournalError):
        workflow_journal.decode_workflow_head(b'{"schema_version": "x"} ')
    with pytest.raises(workflow_journal.WorkflowJournalError):
        workflow_journal.decode_workflow_journal_entry(b"")


def test_initial_head_selects_exact_sealed_authority_before_first_execution() -> None:
    client = _Client()
    _, head = _started(client)
    authority = head.retry_authority_ref
    assert authority.artifact_kind is ArtifactKind.WORKFLOW
    assert authority.access_class is ArtifactAccessClass.CUSTODIAN_SEALED
    assert head.retry_authority_digest == authority.content_digest
    assert head.sequence == 0
    assert (head.workflow_digest, head.lease_owner_id) == (_digest("workflow"), "owner-a")
    assert head.entry_digest == _initial_entry().entry_digest


def test_initial_head_refuses_unsealed_foreign_or_mismatched_authority() -> None:
    client = _Client()
    journal = _journal(client)
    unsealed = _authority(access=ArtifactAccessClass.PRIVATE)
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.initialize(_initial_entry(), unsealed, unsealed.content_digest)
    assert report.value.reason is workflow_journal.WorkflowJournalReason.INVALID_REQUEST
    foreign = _authority(kind=ArtifactKind.OBSERVATION)
    with pytest.raises(workflow_journal.WorkflowJournalError):
        journal.initialize(_initial_entry(), foreign, foreign.content_digest)
    sealed = _authority()
    with pytest.raises(workflow_journal.WorkflowJournalError):
        journal.initialize(_initial_entry(), sealed, _digest("other-authority"))
    with pytest.raises(workflow_journal.WorkflowJournalError) as initial:
        journal.initialize(_entry(), sealed, sealed.content_digest)
    assert initial.value.reason is workflow_journal.WorkflowJournalReason.INVALID_ENTRY
    durable = None
    with pytest.raises(workflow_journal.WorkflowJournalError):
        durable = workflow_journal.S3WorkflowJournal(_settings(StorePurpose.DURABLE), _Client())
        durable.initialize(_initial_entry(), sealed, sealed.content_digest)
    assert durable is None


def test_initialize_has_exactly_one_winner_and_preserves_first_head() -> None:
    client = _Client()
    journal, head = _started(client)
    other = _authority("other")
    assert journal.initialize(_initial_entry(), other, other.content_digest) is None
    assert journal.current_head(_digest("workflow")) == head


def test_successor_heads_preserve_the_selected_authority_unchanged() -> None:
    client = _Client()
    journal, head = _started(client)
    first = _appended(journal, head, 1, counts=WorkflowCounts(2, 1, 12, 5, 0))
    second = _appended(journal, first, 2, counts=WorkflowCounts(2, 1, 12, 6, 0))
    authority = head.retry_authority_ref
    for successor in (first, second):
        assert successor.retry_authority_ref == authority
        assert successor.retry_authority_digest == head.retry_authority_digest
    assert second.entry_digest != first.entry_digest
    assert journal.current_head(_digest("workflow")) == second


def test_substituted_authority_cannot_replace_the_selection() -> None:
    client = _Client()
    journal, head = _started(client)
    entry = _entry(previous_entry_digest=head.entry_digest)
    substituted = workflow_journal.WorkflowHeadV1(
        entry.workflow_digest,
        1,
        entry.entry_digest,
        entry.lease_owner_id,
        entry.lease_expires_at,
        _authority("substituted"),
        _digest("substituted"),
        "",
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.append_and_swap(head.head_digest, entry, substituted)
    assert report.value.reason is workflow_journal.WorkflowJournalReason.AUTHORITY_SUBSTITUTED
    assert journal.current_head(_digest("workflow")) == head
    with pytest.raises(workflow_journal.WorkflowJournalError) as guard:
        workflow_journal.require_selected_authority(head, _authority("substituted"), _digest("s"))
    assert guard.value.reason is workflow_journal.WorkflowJournalReason.AUTHORITY_SUBSTITUTED
    assert workflow_journal.require_selected_authority(head, head.retry_authority_ref, head.retry_authority_digest)


def test_missing_predecessor_or_forked_entries_fail() -> None:
    client = _Client()
    journal, head = _started(client)
    fork = _entry(sequence=1, previous_entry_digest=_digest("orphan-entry"))
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.append_and_swap(head.head_digest, fork, workflow_journal.successor_head(head, fork))
    assert report.value.reason is workflow_journal.WorkflowJournalReason.INVALID_SUCCESSOR
    collision = _entry(sequence=0, previous_entry_digest=None)
    with pytest.raises(workflow_journal.WorkflowJournalError):
        journal.append_and_swap(head.head_digest, collision, workflow_journal.successor_head(head, collision))
    skip = _entry(sequence=2, previous_entry_digest=head.entry_digest)
    with pytest.raises(workflow_journal.WorkflowJournalError):
        journal.append_and_swap(head.head_digest, skip, workflow_journal.successor_head(head, skip))
    assert journal.current_head(_digest("workflow")) == head


def test_stale_expected_head_digest_or_provider_conflict_returns_false() -> None:
    client = _Client()
    journal, head = _started(client)
    first = _appended(journal, head, 1)
    entry, successor = _successor(head, 1)
    assert journal.append_and_swap(head.head_digest, entry, successor) is False
    client.force_head_conflict = True
    entry2, successor2 = _successor(first, 2)
    assert journal.append_and_swap(first.head_digest, entry2, successor2) is False
    client.force_head_conflict = False
    assert journal.current_head(_digest("workflow")) == first


def test_concurrent_append_has_exactly_one_winner() -> None:
    client = _Client()
    journal, head = _started(client)
    client.head_write_barrier = threading.Barrier(2)
    entry, successor = _successor(head, 1)

    results = _run_threads(lambda: journal.append_and_swap(head.head_digest, entry, successor))
    client.head_write_barrier = None
    assert sorted(str(result) for result in results) == ["False", "True"]
    assert journal.current_head(_digest("workflow")) == successor


def test_stale_owner_append_and_renewal_are_refused() -> None:
    client = _Client()
    journal, head = _started(client)
    foreign, foreign_head = _successor(head, 1, lease_owner_id="owner-b")
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.append_and_swap(head.head_digest, foreign, foreign_head)
    assert report.value.reason is workflow_journal.WorkflowJournalReason.LEASE_OWNER_MISMATCH
    assert journal.current_head(_digest("workflow")) == head


def test_expired_lease_blocks_owner_append_and_renewal() -> None:
    client = _Client()
    journal, head = _started(client)
    late, late_head = _successor(head, 1, heartbeat_at=_at(31), lease_expires_at=_at(61))
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.append_and_swap(head.head_digest, late, late_head)
    assert report.value.reason is workflow_journal.WorkflowJournalReason.LEASE_EXPIRED
    assert journal.current_head(_digest("workflow")) == head


def test_acquisition_requires_an_expired_validated_head() -> None:
    client = _Client()
    journal, head = _started(client)
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.acquire_expired_lease(
            _digest("workflow"),
            head.head_digest,
            "attempt-2",
            "owner-b",
            phase=WorkflowPhase.ARM_EXECUTION,
            counts=WorkflowCounts(2, 0, 12, 0, 0),
            heartbeat_at=_at(1),
            lease_expires_at=_at(31),
        )
    assert report.value.reason is workflow_journal.WorkflowJournalReason.LEASE_NOT_EXPIRED
    with pytest.raises(workflow_journal.WorkflowJournalError) as missing:
        journal.acquire_expired_lease(
            _digest("unknown-workflow"),
            _digest("unknown-head"),
            "attempt-2",
            "owner-b",
            phase=WorkflowPhase.ARM_EXECUTION,
            counts=WorkflowCounts(2, 0, 12, 0, 0),
            heartbeat_at=_at(31),
            lease_expires_at=_at(61),
        )
    assert missing.value.reason is workflow_journal.WorkflowJournalReason.NOT_FOUND


def test_concurrent_resume_has_exactly_one_winner() -> None:
    client = _Client()
    journal, head = _started(client)
    client.head_write_barrier = threading.Barrier(2)

    def acquire() -> object:
        return journal.acquire_expired_lease(
            _digest("workflow"),
            head.head_digest,
            "attempt-2",
            "owner-b",
            phase=WorkflowPhase.ARM_EXECUTION,
            counts=WorkflowCounts(2, 0, 12, 0, 0),
            heartbeat_at=_at(31),
            lease_expires_at=_at(61),
        )

    winners = [result for result in _run_threads(acquire) if result is not None]
    client.head_write_barrier = None
    assert len(winners) == 1
    resumed = winners[0]
    assert isinstance(resumed, workflow_journal.WorkflowHeadV1)
    assert (resumed.lease_owner_id, resumed.sequence) == ("owner-b", 1)
    assert resumed.retry_authority_ref == head.retry_authority_ref
    assert resumed.retry_authority_digest == head.retry_authority_digest
    assert (
        journal.acquire_expired_lease(
            _digest("workflow"),
            head.head_digest,
            "attempt-3",
            "owner-c",
            phase=WorkflowPhase.SCORING,
            counts=WorkflowCounts(2, 0, 12, 0, 0),
            heartbeat_at=_at(32),
            lease_expires_at=_at(62),
        )
        is None
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as live:
        journal.acquire_expired_lease(
            _digest("workflow"),
            resumed.head_digest,
            "attempt-3",
            "owner-c",
            phase=WorkflowPhase.SCORING,
            counts=WorkflowCounts(2, 0, 12, 0, 0),
            heartbeat_at=_at(32),
            lease_expires_at=_at(62),
        )
    assert live.value.reason is workflow_journal.WorkflowJournalReason.LEASE_NOT_EXPIRED
    current = _appended(
        journal,
        resumed,
        2,
        attempt_id="attempt-2",
        lease_owner_id="owner-b",
        heartbeat_at=_at(45),
        lease_expires_at=_at(75),
    )
    stale = _entry(
        sequence=3,
        previous_entry_digest=current.entry_digest,
        attempt_id="attempt-1",
        lease_owner_id="owner-a",
        heartbeat_at=_at(46),
        lease_expires_at=_at(76),
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as old:
        journal.append_and_swap(current.head_digest, stale, workflow_journal.successor_head(current, stale))
    assert old.value.reason is workflow_journal.WorkflowJournalReason.LEASE_OWNER_MISMATCH


def test_scratch_loss_recovery_resolves_the_same_selected_authority() -> None:
    client = _Client()
    journal, head = _started(client)
    _appended(journal, head, 1, counts=WorkflowCounts(2, 1, 12, 5, 0))
    recovered = _journal(client)
    current = recovered.current_head(_digest("workflow"))
    assert current.retry_authority_ref == head.retry_authority_ref
    assert current.retry_authority_digest == head.retry_authority_digest
    status = recovered.rebuild_status(_digest("workflow"), _at(2))
    assert status.chain_length == 2
    assert status.phase is WorkflowPhase.ARM_EXECUTION
    assert status.counts == WorkflowCounts(2, 1, 12, 5, 0)


def test_rebuild_ignores_orphan_and_stale_entries() -> None:
    client = _Client()
    journal, head = _started(client)
    _appended(journal, head, 1, counts=WorkflowCounts(2, 1, 12, 5, 0))
    second = _appended(
        journal,
        journal.current_head(_digest("workflow")),
        2,
        counts=WorkflowCounts(2, 2, 12, 8, 0),
    )
    orphan = _entry(attempt_id="attempt-9", sequence=9)
    client.raw_put(
        workflow_journal.workflow_entry_key(_digest("workflow"), orphan.entry_digest),
        workflow_journal.journal_entry_bytes(orphan),
    )
    status = journal.rebuild_status(_digest("workflow"), _at(3))
    assert status.chain_length == 3
    assert status.counts == WorkflowCounts(2, 2, 12, 8, 0)
    assert status.phase is WorkflowPhase.ARM_EXECUTION
    assert status.head == second


def test_missing_predecessor_in_rebuilt_chain_fails_closed() -> None:
    client = _Client()
    journal, head = _started(client)
    _appended(journal, head, 1)
    client.drop(workflow_journal.workflow_entry_key(_digest("workflow"), _initial_entry().entry_digest))
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.rebuild_status(_digest("workflow"), _at(2))
    assert report.value.reason is workflow_journal.WorkflowJournalReason.CHAIN_BROKEN


def test_expired_authoritative_head_projects_impaired_stalled_only() -> None:
    client = _Client()
    journal, head = _started(client)
    _appended(
        journal,
        head,
        1,
        heartbeat_at=_at(1),
        lease_expires_at=_at(6),
        counts=WorkflowCounts(2, 1, 12, 5, 0),
    )
    moving = journal.rebuild_status(_digest("workflow"), _at(5))
    assert moving.lease_expired is False
    assert moving.projected_status is None
    assert moving.projected_reason is None
    expired = journal.rebuild_status(_digest("workflow"), _at(6))
    assert expired.lease_expired is True
    assert expired.projected_status is WorkflowStatus.IMPAIRED
    assert expired.projected_reason is WorkflowReasonCode.STALLED
    assert expired.projected_reason is not WorkflowReasonCode.INSTRUMENT_FAILURE
    assert expired.counts == WorkflowCounts(2, 1, 12, 5, 0)


def test_orphan_or_corrupt_store_state_fails_closed() -> None:
    client = _Client()
    journal = _journal(client)
    with pytest.raises(workflow_journal.WorkflowJournalError) as report:
        journal.current_head(_digest("workflow"))
    assert report.value.reason is workflow_journal.WorkflowJournalReason.NOT_FOUND
    with pytest.raises(workflow_journal.WorkflowJournalError):
        journal.current_head("not-a-digest")
    _started(client)
    client.corrupt_reads = True
    with pytest.raises(workflow_journal.WorkflowJournalError) as corrupt:
        journal.current_head(_digest("workflow"))
    assert corrupt.value.reason is workflow_journal.WorkflowJournalReason.MALFORMED_CONTENT
    client.corrupt_reads = False
    client.provider_failure = True
    with pytest.raises(workflow_journal.WorkflowJournalError) as failed:
        journal.current_head(_digest("workflow"))
    assert failed.value.reason is workflow_journal.WorkflowJournalReason.STORE_FAILURE
