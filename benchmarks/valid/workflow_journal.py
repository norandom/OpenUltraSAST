"""Task 7.2 causal workflow journal with a lease-protected compare-and-swap head.

The journal is the transient causal record of one benchmark workflow run. Every
entry names its exact sequence, predecessor, attempt, lease owner, phase,
counts, and deadlines; the single CAS-protected head selects the exact
custodian-sealed automatic-retry authority before first execution and preserves
that selection through every successor. All serialized fields are closed
vocabularies, bounded integers, or full digests, so exception text, paths,
labels, payloads, secrets, and customer content have no entry point.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, TypeVar, cast

from benchmarks.valid.custody_probe_io import valid_version_id
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    canonical_json_bytes,
)
from benchmarks.valid.store_configuration import StorePurpose, StoreSettings
from benchmarks.valid.workflow_outcome import (
    WORKFLOW_COUNT_FIELDS,
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue

WORKFLOW_JOURNAL_SCHEMA = "openultrasast.valid-detection-benchmark.workflow-journal.v1"
WORKFLOW_HEAD_SCHEMA = "openultrasast.valid-detection-benchmark.workflow-journal-head.v1"
WORKFLOW_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.workflow-journal-authority.v1"
WORKFLOW_ENTRY_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_digest",
        "sequence",
        "previous_entry_digest",
        "attempt_id",
        "lease_owner_id",
        "phase",
        "heartbeat_at",
        "lease_expires_at",
        "counts",
        "entry_digest",
    }
)
WORKFLOW_HEAD_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_digest",
        "sequence",
        "entry_digest",
        "lease_owner_id",
        "lease_expires_at",
        "retry_authority_ref",
        "retry_authority_digest",
        "head_digest",
    }
)
WORKFLOW_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "access_class",
        "provenance_digest",
        "content_digest",
        "byte_length",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_CONFLICT_CODES = frozenset({"409", "412", "ConditionalRequestConflict", "PreconditionFailed"})
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound", "NoSuchVersion"})
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class WorkflowJournalReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    MALFORMED_CONTENT = "malformed_content"
    INVALID_ENTRY = "invalid_entry"
    INVALID_HEAD = "invalid_head"
    INVALID_SUCCESSOR = "invalid_successor"
    AUTHORITY_SUBSTITUTED = "authority_substituted"
    LEASE_OWNER_MISMATCH = "lease_owner_mismatch"
    LEASE_NOT_EXPIRED = "lease_not_expired"
    LEASE_EXPIRED = "lease_expired"
    CHAIN_BROKEN = "chain_broken"
    DIGEST_MISMATCH = "digest_mismatch"
    READBACK_MISMATCH = "readback_mismatch"
    UNREADABLE_RESPONSE = "unreadable_response"
    STORE_FAILURE = "store_failure"


class WorkflowJournalError(RuntimeError):
    """Refuse unsafe journal content or state with a closed reason."""

    def __init__(self, reason: WorkflowJournalReason) -> None:
        self.reason = reason
        super().__init__(f"workflow_journal_{reason.value}")


def _is_digest(value: object, *, optional: bool = False) -> bool:
    if optional and value == "":
        return True
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _is_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _is_timestamp(value: object) -> bool:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def _is_sequence(value: object) -> bool:
    return type(value) is int and 0 <= value <= 1 << 31


def _require_digest(value: object) -> str:
    if not _is_digest(value):
        raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)
    return cast(str, value)


@dataclass(frozen=True)
class WorkflowJournalEntryV1:
    """One causal progress or heartbeat record with its exact lease context."""

    workflow_digest: str
    sequence: int
    previous_entry_digest: str | None
    attempt_id: str
    lease_owner_id: str
    phase: WorkflowPhase
    heartbeat_at: str
    lease_expires_at: str
    counts: WorkflowCounts
    entry_digest: str

    def __post_init__(self) -> None:
        _validate_entry(self)
        expected = canonical.content_digest(_entry_value(self, include_digest=False))
        _bind_record_digest(self, "entry_digest", self.entry_digest, expected)


@dataclass(frozen=True)
class WorkflowHeadV1:
    """CAS-protected head binding the immutable selected retry authority."""

    workflow_digest: str
    sequence: int
    entry_digest: str
    lease_owner_id: str
    lease_expires_at: str
    retry_authority_ref: ArtifactReference
    retry_authority_digest: str
    head_digest: str

    def __post_init__(self) -> None:
        _validate_head(self)
        expected = canonical.content_digest(_head_value(self, include_digest=False))
        _bind_record_digest(self, "head_digest", self.head_digest, expected)


def _bind_record_digest(record: object, field: str, current: str, expected: str) -> None:
    if current and current != expected:
        raise WorkflowJournalError(WorkflowJournalReason.DIGEST_MISMATCH)
    if not current:
        object.__setattr__(record, field, expected)


def _validate_entry(value: WorkflowJournalEntryV1) -> None:
    if (
        type(value) is not WorkflowJournalEntryV1
        or type(value.phase) is not WorkflowPhase
        or type(value.counts) is not WorkflowCounts
        or not _is_digest(value.workflow_digest)
        or not _is_sequence(value.sequence)
        or (value.previous_entry_digest is not None and not _is_digest(value.previous_entry_digest))
        or not _is_identifier(value.attempt_id)
        or not _is_identifier(value.lease_owner_id)
        or not _is_timestamp(value.heartbeat_at)
        or not _is_timestamp(value.lease_expires_at)
        or value.lease_expires_at <= value.heartbeat_at
        or not _is_digest(value.entry_digest, optional=True)
    ):
        raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)


def _validate_head(value: WorkflowHeadV1) -> None:
    reference = value.retry_authority_ref
    if (
        type(value) is not WorkflowHeadV1
        or type(reference) is not ArtifactReference
        or not _is_digest(value.workflow_digest)
        or not _is_sequence(value.sequence)
        or not _is_digest(value.entry_digest)
        or not _is_identifier(value.lease_owner_id)
        or not _is_timestamp(value.lease_expires_at)
        or not _is_digest(value.retry_authority_digest)
        or not _is_digest(value.head_digest, optional=True)
        or reference.artifact_kind is not ArtifactKind.WORKFLOW
        or reference.access_class is not ArtifactAccessClass.CUSTODIAN_SEALED
        or value.retry_authority_digest != reference.content_digest
    ):
        raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)


def _validate_head_entry(head: WorkflowHeadV1, entry: WorkflowJournalEntryV1) -> None:
    if (
        type(head) is not WorkflowHeadV1
        or type(entry) is not WorkflowJournalEntryV1
        or head.workflow_digest != entry.workflow_digest
        or head.sequence != entry.sequence
        or head.entry_digest != entry.entry_digest
        or head.lease_owner_id != entry.lease_owner_id
        or head.lease_expires_at != entry.lease_expires_at
    ):
        raise WorkflowJournalError(WorkflowJournalReason.INVALID_HEAD)


def successor_head(prior: WorkflowHeadV1, entry: WorkflowJournalEntryV1) -> WorkflowHeadV1:
    """Build the successor head while preserving the selected authority exactly."""
    return WorkflowHeadV1(
        prior.workflow_digest,
        entry.sequence,
        entry.entry_digest,
        entry.lease_owner_id,
        entry.lease_expires_at,
        prior.retry_authority_ref,
        prior.retry_authority_digest,
        "",
    )


def require_selected_authority(
    head: WorkflowHeadV1, candidate: ArtifactReference, authority_digest: str
) -> ArtifactReference:
    """Accept a retry authority only when the CAS head selected exactly it."""
    if candidate != head.retry_authority_ref or authority_digest != head.retry_authority_digest:
        raise WorkflowJournalError(WorkflowJournalReason.AUTHORITY_SUBSTITUTED)
    return candidate


def _projection(lease_expired: bool) -> tuple[WorkflowStatus | None, WorkflowReasonCode | None]:
    if lease_expired:
        return (WorkflowStatus.IMPAIRED, WorkflowReasonCode.STALLED)
    return (None, None)


@dataclass(frozen=True)
class WorkflowJournalStatus:
    """Status rebuilt from the complete validated chain to the head."""

    workflow_digest: str
    head: WorkflowHeadV1
    head_entry: WorkflowJournalEntryV1
    chain_length: int
    phase: WorkflowPhase
    counts: WorkflowCounts
    lease_expired: bool
    projected_status: WorkflowStatus | None
    projected_reason: WorkflowReasonCode | None

    def __post_init__(self) -> None:
        if (
            type(self.lease_expired) is not bool
            or type(self.chain_length) is not int
            or self.phase != self.head_entry.phase
            or self.counts != self.head_entry.counts
            or self.chain_length != self.head_entry.sequence + 1
            or (self.projected_status, self.projected_reason) != _projection(self.lease_expired)
        ):
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)


def _counts_value(counts: WorkflowCounts) -> dict[str, JsonValue]:
    return {
        "planned_arms": counts.planned_arms,
        "completed_arms": counts.completed_arms,
        "planned_inputs": counts.planned_inputs,
        "completed_inputs": counts.completed_inputs,
        "deferred_inputs": counts.deferred_inputs,
    }


def _authority_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    return {
        "schema_version": WORKFLOW_AUTHORITY_SCHEMA,
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "provenance_digest": reference.provenance_digest,
        "content_digest": reference.content_digest,
        "byte_length": reference.byte_length,
    }


def _entry_value(value: WorkflowJournalEntryV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": WORKFLOW_JOURNAL_SCHEMA,
        "workflow_digest": value.workflow_digest,
        "sequence": value.sequence,
        "previous_entry_digest": value.previous_entry_digest,
        "attempt_id": value.attempt_id,
        "lease_owner_id": value.lease_owner_id,
        "phase": value.phase.value,
        "heartbeat_at": value.heartbeat_at,
        "lease_expires_at": value.lease_expires_at,
        "counts": _counts_value(value.counts),
    }
    if include_digest:
        result["entry_digest"] = value.entry_digest
    return result


def _head_value(value: WorkflowHeadV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": WORKFLOW_HEAD_SCHEMA,
        "workflow_digest": value.workflow_digest,
        "sequence": value.sequence,
        "entry_digest": value.entry_digest,
        "lease_owner_id": value.lease_owner_id,
        "lease_expires_at": value.lease_expires_at,
        "retry_authority_ref": _authority_value(value.retry_authority_ref),
        "retry_authority_digest": value.retry_authority_digest,
    }
    if include_digest:
        result["head_digest"] = value.head_digest
    return result


def journal_entry_bytes(value: WorkflowJournalEntryV1) -> bytes:
    """Encode a revalidated journal entry as deterministic canonical JSON."""
    value.__post_init__()
    return canonical.canonical_bytes(_entry_value(value, include_digest=True))


def journal_head_bytes(value: WorkflowHeadV1) -> bytes:
    """Encode a revalidated journal head as deterministic canonical JSON."""
    value.__post_init__()
    return canonical.canonical_bytes(_head_value(value, include_digest=True))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
        value[key] = item
    return value


def _journal_reject_constant(name: str) -> None:
    raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from ValueError(f"non-canonical JSON constant: {name}")


def _journal_finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from ValueError(f"non-finite JSON number: {text}")
    return value


def _decode_canonical(content: bytes) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    try:
        decoded = json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=_journal_reject_constant,
            parse_float=_journal_finite_float,
        )
    except WorkflowJournalError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from None
    if type(decoded) is not dict or canonical_json_bytes(decoded) != content:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    return decoded


def _decode_enum(value: object, enum_type: type[_EnumT]) -> _EnumT:
    if type(value) is not str:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    try:
        return enum_type(value)
    except ValueError:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from None


def _decode_counts(value: object) -> WorkflowCounts:
    if type(value) is not dict or set(value) != WORKFLOW_COUNT_FIELDS:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    try:
        return WorkflowCounts(
            cast(int, value["planned_arms"]),
            cast(int, value["completed_arms"]),
            cast(int, value["planned_inputs"]),
            cast(int, value["completed_inputs"]),
            cast(int, value["deferred_inputs"]),
        )
    except (KeyError, ValueError):
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from None


def _decode_authority(value: object) -> ArtifactReference:
    if (
        type(value) is not dict
        or set(value) != WORKFLOW_AUTHORITY_FIELDS
        or value.get("schema_version") != WORKFLOW_AUTHORITY_SCHEMA
        or type(value.get("byte_length")) is not int
    ):
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    try:
        return ArtifactReference(
            ArtifactKind(cast(str, value["artifact_kind"])),
            cast(str, value["content_digest"]),
            cast(int, value["byte_length"]),
            cast(str, value["provenance_digest"]),
            ArtifactAccessClass(cast(str, value["access_class"])),
        )
    except (KeyError, ValueError):
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT) from None


def decode_workflow_journal_entry(content: bytes) -> WorkflowJournalEntryV1:
    """Decode only canonical journal-entry bytes under the closed schema."""
    value = _decode_canonical(content)
    if set(value) != WORKFLOW_ENTRY_FIELDS or value.get("schema_version") != WORKFLOW_JOURNAL_SCHEMA:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    previous = value["previous_entry_digest"]
    return WorkflowJournalEntryV1(
        cast(str, value["workflow_digest"]),
        cast(int, value["sequence"]),
        None if previous is None else cast(str, previous),
        cast(str, value["attempt_id"]),
        cast(str, value["lease_owner_id"]),
        _decode_enum(value["phase"], WorkflowPhase),
        cast(str, value["heartbeat_at"]),
        cast(str, value["lease_expires_at"]),
        _decode_counts(value["counts"]),
        cast(str, value["entry_digest"]),
    )


def decode_workflow_head(content: bytes) -> WorkflowHeadV1:
    """Decode only canonical journal-head bytes under the closed schema."""
    value = _decode_canonical(content)
    if set(value) != WORKFLOW_HEAD_FIELDS or value.get("schema_version") != WORKFLOW_HEAD_SCHEMA:
        raise WorkflowJournalError(WorkflowJournalReason.MALFORMED_CONTENT)
    return WorkflowHeadV1(
        cast(str, value["workflow_digest"]),
        cast(int, value["sequence"]),
        cast(str, value["entry_digest"]),
        cast(str, value["lease_owner_id"]),
        cast(str, value["lease_expires_at"]),
        _decode_authority(value["retry_authority_ref"]),
        cast(str, value["retry_authority_digest"]),
        cast(str, value["head_digest"]),
    )


class S3WorkflowJournalClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class _Receipt:
    version_id: str
    storage_token: str


def workflow_head_key(workflow_digest: str) -> str:
    return f"workflow/{workflow_digest}/head.json"


def workflow_entry_key(workflow_digest: str, entry_digest: str) -> str:
    return f"workflow/{workflow_digest}/entries/{entry_digest}.json"


def _provider_code(error: Exception) -> str:
    try:
        response = getattr(error, "response", None)
        details = response.get("Error") if isinstance(response, Mapping) else None
        code = details.get("Code", "") if isinstance(details, Mapping) else getattr(error, "code", "")
    except Exception:
        return ""
    return code if isinstance(code, str) else ""


class S3WorkflowJournal:
    """Append-only causal journal with one lease-protected compare-and-swap head."""

    def __init__(self, settings: StoreSettings, client: S3WorkflowJournalClient) -> None:
        if not isinstance(settings, StoreSettings) or settings.purpose is not StorePurpose.TRANSIENT:
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)
        self._bucket, self._client = settings.bucket, client

    def initialize(
        self,
        entry: WorkflowJournalEntryV1,
        retry_authority_ref: ArtifactReference,
        retry_authority_digest: str,
    ) -> WorkflowHeadV1 | None:
        """Select the sealed retry authority in the first head before execution."""
        if (
            type(entry) is not WorkflowJournalEntryV1
            or entry.sequence != 0
            or entry.previous_entry_digest is not None
        ):
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_ENTRY)
        head = WorkflowHeadV1(
            entry.workflow_digest,
            0,
            entry.entry_digest,
            entry.lease_owner_id,
            entry.lease_expires_at,
            retry_authority_ref,
            retry_authority_digest,
            "",
        )
        _validate_head_entry(head, entry)
        self._persist_entry(entry.workflow_digest, entry.entry_digest, journal_entry_bytes(entry))
        receipt, conflicted = self._write(
            workflow_head_key(entry.workflow_digest), journal_head_bytes(head), absent=True
        )
        if conflicted:
            return None
        self._verify_head(head, journal_head_bytes(head), self._require_receipt(receipt))
        return head

    def current_head(self, workflow_digest: str) -> WorkflowHeadV1:
        """Read and validate the durable head after scratch loss or restart."""
        head, _, _ = self._validated_head(_require_digest(workflow_digest))
        return head

    def append_and_swap(
        self,
        expected_head_digest: str,
        entry: WorkflowJournalEntryV1,
        head: WorkflowHeadV1,
    ) -> bool:
        """Append one entry and swap the head only when the exact head is current."""
        _require_digest(expected_head_digest)
        _validate_head_entry(head, entry)
        prior, _, receipt = self._validated_head(_require_digest(entry.workflow_digest))
        if prior.head_digest != expected_head_digest:
            return False
        self._validate_successor(prior, entry, head)
        self._persist_entry(entry.workflow_digest, entry.entry_digest, journal_entry_bytes(entry))
        return self._swap_head(prior, receipt, head)

    def acquire_expired_lease(
        self,
        workflow_digest: str,
        expected_head_digest: str,
        attempt_id: str,
        lease_owner_id: str,
        *,
        phase: WorkflowPhase,
        counts: WorkflowCounts,
        heartbeat_at: str,
        lease_expires_at: str,
    ) -> WorkflowHeadV1 | None:
        """Grant one resume owner only over an expired validated head."""
        if (
            not _is_digest(workflow_digest)
            or not _is_digest(expected_head_digest)
            or not _is_identifier(attempt_id)
            or not _is_identifier(lease_owner_id)
            or type(phase) is not WorkflowPhase
            or type(counts) is not WorkflowCounts
            or not _is_timestamp(heartbeat_at)
            or not _is_timestamp(lease_expires_at)
        ):
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)
        prior, _, receipt = self._validated_head(workflow_digest)
        if prior.head_digest != expected_head_digest:
            return None
        if heartbeat_at < prior.lease_expires_at:
            raise WorkflowJournalError(WorkflowJournalReason.LEASE_NOT_EXPIRED)
        entry = WorkflowJournalEntryV1(
            workflow_digest,
            prior.sequence + 1,
            prior.entry_digest,
            attempt_id,
            lease_owner_id,
            phase,
            heartbeat_at,
            lease_expires_at,
            counts,
            "",
        )
        head = successor_head(prior, entry)
        self._persist_entry(head.workflow_digest, entry.entry_digest, journal_entry_bytes(entry))
        return head if self._swap_head(prior, receipt, head) else None

    def rebuild_status(self, workflow_digest: str, now: str) -> WorkflowJournalStatus:
        """Rebuild status from the complete chain to the head, ignoring orphans."""
        digest = _require_digest(workflow_digest)
        if not _is_timestamp(now):
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_REQUEST)
        head, entry, _ = self._validated_head(digest)
        chain_length = self._validate_chain(digest, entry)
        lease_expired = now >= head.lease_expires_at
        status, reason = _projection(lease_expired)
        return WorkflowJournalStatus(
            digest, head, entry, chain_length, entry.phase, entry.counts, lease_expired, status, reason
        )

    def _validated_head(self, digest: str) -> tuple[WorkflowHeadV1, WorkflowJournalEntryV1, _Receipt]:
        read = self._read(workflow_head_key(digest))
        if read is None:
            raise WorkflowJournalError(WorkflowJournalReason.NOT_FOUND)
        body, receipt = read
        head = decode_workflow_head(body)
        if head.workflow_digest != digest:
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_HEAD)
        entry = self._read_entry(digest, head.entry_digest)
        _validate_head_entry(head, entry)
        return head, entry, receipt

    def _validate_chain(self, digest: str, head_entry: WorkflowJournalEntryV1) -> int:
        entry = head_entry
        length = 1
        while entry.sequence > 0:
            previous = entry.previous_entry_digest
            if type(previous) is not str:
                raise WorkflowJournalError(WorkflowJournalReason.CHAIN_BROKEN)
            prior = self._read_entry(digest, previous)
            if prior.sequence != entry.sequence - 1:
                raise WorkflowJournalError(WorkflowJournalReason.CHAIN_BROKEN)
            entry = prior
            length += 1
        return length

    def _read_entry(self, digest: str, entry_digest: str) -> WorkflowJournalEntryV1:
        read = self._read(workflow_entry_key(digest, entry_digest))
        if read is None:
            raise WorkflowJournalError(WorkflowJournalReason.CHAIN_BROKEN)
        entry = decode_workflow_journal_entry(read[0])
        if entry.entry_digest != entry_digest or entry.workflow_digest != digest:
            raise WorkflowJournalError(WorkflowJournalReason.CHAIN_BROKEN)
        return entry

    def _validate_successor(
        self, prior: WorkflowHeadV1, entry: WorkflowJournalEntryV1, head: WorkflowHeadV1
    ) -> None:
        if (
            entry.workflow_digest != prior.workflow_digest
            or entry.sequence != prior.sequence + 1
            or entry.previous_entry_digest != prior.entry_digest
        ):
            raise WorkflowJournalError(WorkflowJournalReason.INVALID_SUCCESSOR)
        if (
            head.retry_authority_ref != prior.retry_authority_ref
            or head.retry_authority_digest != prior.retry_authority_digest
        ):
            raise WorkflowJournalError(WorkflowJournalReason.AUTHORITY_SUBSTITUTED)
        if entry.lease_owner_id != prior.lease_owner_id:
            raise WorkflowJournalError(WorkflowJournalReason.LEASE_OWNER_MISMATCH)
        if entry.heartbeat_at >= prior.lease_expires_at:
            raise WorkflowJournalError(WorkflowJournalReason.LEASE_EXPIRED)

    def _swap_head(self, prior: WorkflowHeadV1, receipt: _Receipt, head: WorkflowHeadV1) -> bool:
        head_body = journal_head_bytes(head)
        committed, conflicted = self._write(
            workflow_head_key(head.workflow_digest), head_body, token=receipt.storage_token
        )
        if conflicted:
            return False
        replacement = self._require_receipt(committed)
        if (
            replacement.version_id == receipt.version_id
            or replacement.storage_token == receipt.storage_token
        ):
            raise WorkflowJournalError(WorkflowJournalReason.UNREADABLE_RESPONSE)
        self._verify_head(head, head_body, replacement)
        return True

    def _persist_entry(self, digest: str, entry_digest: str, body: bytes) -> None:
        key = workflow_entry_key(digest, entry_digest)
        receipt, conflicted = self._write(key, body, absent=True)
        if conflicted:
            read = self._read(key)
            if read is None or read[0] != body:
                raise WorkflowJournalError(WorkflowJournalReason.READBACK_MISMATCH)
            return
        self._require_receipt(receipt)

    def _verify_head(self, head: WorkflowHeadV1, body: bytes, receipt: _Receipt) -> None:
        read = self._read(workflow_head_key(head.workflow_digest), receipt.version_id)
        if read is None:
            raise WorkflowJournalError(WorkflowJournalReason.READBACK_MISMATCH)
        current_body, current_receipt = read
        if current_body != body or current_receipt != receipt or decode_workflow_head(current_body) != head:
            raise WorkflowJournalError(WorkflowJournalReason.READBACK_MISMATCH)

    def _write(
        self, key: str, body: bytes, *, absent: bool = False, token: str | None = None
    ) -> tuple[_Receipt | None, bool]:
        request: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": body,
            **({"IfNoneMatch": "*"} if absent else {}),
            **({"IfMatch": token} if token is not None else {}),
        }
        code = ""
        try:
            response = self._client.put_object(**request)
        except Exception as error:
            code, response = _provider_code(error), None
        if response is None:
            return (None, code in _CONFLICT_CODES)
        if (
            not isinstance(response, Mapping)
            or not valid_version_id(response.get("VersionId"))
            or type(response.get("ETag")) is not str
            or not response.get("ETag")
        ):
            raise WorkflowJournalError(WorkflowJournalReason.UNREADABLE_RESPONSE)
        return (_Receipt(cast(str, response.get("VersionId")), cast(str, response.get("ETag"))), False)

    def _read(self, key: str, version_id: str | None = None) -> tuple[bytes, _Receipt] | None:
        request: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            **({"VersionId": version_id} if version_id is not None else {}),
        }
        code = ""
        try:
            response = self._client.get_object(**request)
        except Exception as error:
            code, response = _provider_code(error), None
        if response is None:
            if code in _NOT_FOUND_CODES:
                return None
            raise WorkflowJournalError(WorkflowJournalReason.STORE_FAILURE)
        return self._decode_read(response)

    @staticmethod
    def _decode_read(response: Mapping[str, object]) -> tuple[bytes, _Receipt]:
        source = response.get("Body")
        try:
            body = source.read() if hasattr(source, "read") else source
        except Exception:
            body = None
        version_id, token, length = response.get("VersionId"), response.get("ETag"), response.get("ContentLength")
        if (
            type(body) is not bytes
            or not body
            or type(version_id) is not str
            or type(length) is not int
            or length != len(body)
            or not valid_version_id(version_id)
            or type(token) is not str
            or not token
        ):
            raise WorkflowJournalError(WorkflowJournalReason.UNREADABLE_RESPONSE)
        return body, _Receipt(version_id, token)

    @staticmethod
    def _require_receipt(receipt: _Receipt | None) -> _Receipt:
        if receipt is None:
            raise WorkflowJournalError(WorkflowJournalReason.STORE_FAILURE)
        return receipt


__all__ = [
    "S3WorkflowJournal",
    "S3WorkflowJournalClient",
    "WorkflowHeadV1",
    "WorkflowJournalEntryV1",
    "WorkflowJournalError",
    "WorkflowJournalReason",
    "WorkflowJournalStatus",
    "WORKFLOW_AUTHORITY_FIELDS",
    "WORKFLOW_AUTHORITY_SCHEMA",
    "WORKFLOW_ENTRY_FIELDS",
    "WORKFLOW_HEAD_FIELDS",
    "WORKFLOW_HEAD_SCHEMA",
    "WORKFLOW_JOURNAL_SCHEMA",
    "decode_workflow_head",
    "decode_workflow_journal_entry",
    "journal_entry_bytes",
    "journal_head_bytes",
    "require_selected_authority",
    "successor_head",
    "workflow_entry_key",
    "workflow_head_key",
]
