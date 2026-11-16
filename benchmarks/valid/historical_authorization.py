"""Exact-file authority for withdrawn valid-benchmark history.

The pinned inventory is evidence, not authority. Only an independently supplied,
validated review record can turn the withdrawal candidate into audit authority.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from openultrasast.core.canonical import JsonValue, content_digest

HISTORICAL_INVENTORY_SCHEMA = "openultrasast.valid-detection-benchmark.historical-inventory.v1"
HISTORICAL_WITHDRAWAL_SCHEMA = "openultrasast.valid-detection-benchmark.historical-withdrawal.v1"
HISTORICAL_REVIEW_SCHEMA = "openultrasast.valid-detection-benchmark.historical-review.v1"
PILOT_DATE = "2026-10-12"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_GLOB_MARKERS = frozenset("*?[")

PINNED_HISTORICAL_DIGESTS: Mapping[str, str] = MappingProxyType(
    {
        "benchmarks/valid/pilot/freeze-valid.json": "fc6c97a034a6e2828bc003d72a2ab03445a18a3f64387310f26c7cd3ae9bf6ba",
        "benchmarks/valid/pilot/pool-valid.toml": "48765c7703c6465f0f7fc00df81c07618b52065ed637cf97c112fdea98896c3f",
        "tests/fixtures/detection_core/admission_v2/go_replay.json": "16dfa63087ac7ef11404196df1766961c16a3f0f148e743251df191a8070f7be",
        "tests/fixtures/detection_core/admission_v2/go_report.json": "bf5d839c9c29f22db4a54ce2bbfff986315bf910248ea1a28ac64de0660ac59f",
        "tests/fixtures/detection_core/admission_v2/manifest.json": "c470ccd0d27eaf98de1ac50846c2281d2ec777a96def4211e92051b158317b2b",
        "tests/fixtures/detection_core/admission_v2/no_go_replay.json": "a385eee59970fba07d615172524c90038997911f3bd302e56bb23be029e50e6e",
        "tests/fixtures/detection_core/admission_v2/no_go_report.json": "3c0d8698bb72157de384fa1ad63c4c1b5bafbd1001235e416aaeced9cb5da8b7",
        "tests/fixtures/detection_core/admission_v2/validation_failures.json": (
            "c80a1214c59c26e25db0978c85ce07ced9642baf9dc57ef0a5f0f1504f11c49f"
        ),
        "tests/fixtures/detection_core/admission_v2/zero_model_replay.json": (
            "c17ab6fc00c5aea7e981a07dbb28aaa9b3da399429948029aaeb1f67eebecfd9"
        ),
        "tests/fixtures/detection_core/admission_v2/zero_model_report.json": (
            "336f07de37ec15eeaffb6711ce398762c6091d49b7993fd7a38f7cdebf33f85c"
        ),
    }
)


class HistoricalAuthorizationError(ValueError):
    """Historical bytes or review evidence do not match exact authority."""


class HistoricalPathReason(StrEnum):
    WITHDRAWN_PILOT = "withdrawn_pilot"
    FROZEN_V2_COMPATIBILITY = "frozen_v2_compatibility"


class HistoricalStatus(StrEnum):
    WITHDRAWN_NON_ADMISSIBLE = "withdrawn_non_admissible"


class ReplacementStatus(StrEnum):
    PENDING = "replacement_pending"


class WithdrawalReason(StrEnum):
    PERMANENT_RESERVATION_OVERLAP = "permanent_reservation_overlap"


@dataclass(frozen=True)
class HistoricalInventoryEntryV1:
    path: str
    byte_length: int
    content_digest: str
    reason: HistoricalPathReason


@dataclass(frozen=True)
class HistoricalInventoryV1:
    entries: tuple[HistoricalInventoryEntryV1, ...]
    inventory_digest: str


@dataclass(frozen=True)
class HistoricalWithdrawalCandidateV1:
    entries: tuple[HistoricalInventoryEntryV1, ...]
    inventory_digest: str
    pilot_date: str
    status: HistoricalStatus
    replacement_status: ReplacementStatus
    reason: WithdrawalReason
    candidate_digest: str


@dataclass(frozen=True)
class HistoricalReviewEvidenceV1:
    subject_digest: str
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    review_digest: str


@dataclass(frozen=True)
class HistoricalWithdrawalV1:
    candidate: HistoricalWithdrawalCandidateV1
    review: HistoricalReviewEvidenceV1
    withdrawal_digest: str

    @property
    def pilot_date(self) -> str:
        return self.candidate.pilot_date

    @property
    def status(self) -> HistoricalStatus:
        return self.candidate.status

    @property
    def replacement_status(self) -> ReplacementStatus:
        return self.candidate.replacement_status

    @property
    def reason(self) -> WithdrawalReason:
        return self.candidate.reason

    @property
    def inventory_digest(self) -> str:
        return self.candidate.inventory_digest


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise HistoricalAuthorizationError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HistoricalAuthorizationError(f"{field} must be nonempty text")
    return value.strip()


def _canonical_path(value: object) -> str:
    text = _require_text(value, "historical path")
    path = PurePosixPath(text)
    invalid = path.is_absolute() or text != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts)
    if invalid or any(marker in text for marker in _GLOB_MARKERS):
        raise HistoricalAuthorizationError("historical path must be exact canonical repository-relative POSIX")
    return text


def _entry_value(entry: HistoricalInventoryEntryV1) -> JsonValue:
    return {
        "path": entry.path,
        "byte_length": entry.byte_length,
        "content_digest": entry.content_digest,
        "withdrawal_reason": entry.reason.value,
    }


def _validate_entry(entry: HistoricalInventoryEntryV1) -> None:
    _canonical_path(entry.path)
    if isinstance(entry.byte_length, bool) or not isinstance(entry.byte_length, int) or entry.byte_length <= 0:
        raise HistoricalAuthorizationError("historical inventory byte length must be positive")
    _require_digest(entry.content_digest, "historical content digest")
    if not isinstance(entry.reason, HistoricalPathReason):
        raise HistoricalAuthorizationError("historical withdrawal reason is unsupported")


def _inventory_value(inventory: HistoricalInventoryV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": HISTORICAL_INVENTORY_SCHEMA,
        "entries": tuple(_entry_value(entry) for entry in inventory.entries),
    }
    if include_digest:
        value["inventory_digest"] = inventory.inventory_digest
    return value


def inventory_bytes(inventory: HistoricalInventoryV1) -> bytes:
    paths = tuple(entry.path for entry in inventory.entries)
    if not inventory.entries or paths != tuple(sorted(set(paths))):
        raise HistoricalAuthorizationError("historical inventory paths are not canonical")
    for entry in inventory.entries:
        _validate_entry(entry)
    expected = content_digest(_inventory_value(inventory, include_digest=False))
    if inventory.inventory_digest != expected:
        raise HistoricalAuthorizationError("historical inventory digest does not match")
    return canonical_json_bytes(_inventory_value(inventory, include_digest=True))


def _pinned_reason(path: str) -> HistoricalPathReason:
    if path.startswith("benchmarks/valid/pilot/"):
        return HistoricalPathReason.WITHDRAWN_PILOT
    return HistoricalPathReason.FROZEN_V2_COMPATIBILITY


def _read_exact_file(root: Path, relative: str) -> bytes:
    root_resolved = root.resolve()
    target = root / relative
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root_resolved):
        raise HistoricalAuthorizationError("historical path must resolve to a regular file")
    content = target.read_bytes()
    if not content:
        raise HistoricalAuthorizationError("historical path read zero bytes")
    return content


def pinned_historical_inventory(root: Path) -> HistoricalInventoryV1:
    entries: list[HistoricalInventoryEntryV1] = []
    for relative, expected_digest in sorted(PINNED_HISTORICAL_DIGESTS.items()):
        path = _canonical_path(relative)
        content = _read_exact_file(root, path)
        actual_digest = sha256(content).hexdigest()
        if actual_digest != expected_digest:
            raise HistoricalAuthorizationError(f"historical content digest changed: {path}")
        entries.append(HistoricalInventoryEntryV1(path, len(content), actual_digest, _pinned_reason(path)))
    draft = HistoricalInventoryV1(tuple(entries), "")
    return HistoricalInventoryV1(draft.entries, content_digest(_inventory_value(draft, include_digest=False)))


def _candidate_value(candidate: HistoricalWithdrawalCandidateV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": HISTORICAL_WITHDRAWAL_SCHEMA,
        "pilot_date": candidate.pilot_date,
        "status": candidate.status.value,
        "replacement_status": candidate.replacement_status.value,
        "withdrawal_reason": candidate.reason.value,
        "inventory_digest": candidate.inventory_digest,
        "entries": tuple(_entry_value(entry) for entry in candidate.entries),
    }
    if include_digest:
        value["candidate_digest"] = candidate.candidate_digest
    return value


def _validate_candidate(candidate: HistoricalWithdrawalCandidateV1) -> None:
    inventory_bytes(HistoricalInventoryV1(candidate.entries, candidate.inventory_digest))
    fixed = (
        candidate.pilot_date == PILOT_DATE
        and candidate.status is HistoricalStatus.WITHDRAWN_NON_ADMISSIBLE
        and candidate.replacement_status is ReplacementStatus.PENDING
        and candidate.reason is WithdrawalReason.PERMANENT_RESERVATION_OVERLAP
    )
    if not fixed:
        raise HistoricalAuthorizationError("historical withdrawal candidate has unsupported lifecycle values")
    expected = content_digest(_candidate_value(candidate, include_digest=False))
    if candidate.candidate_digest != expected:
        raise HistoricalAuthorizationError("historical withdrawal candidate digest does not match")


def build_withdrawal_candidate(inventory: HistoricalInventoryV1) -> HistoricalWithdrawalCandidateV1:
    inventory_bytes(inventory)
    draft = HistoricalWithdrawalCandidateV1(
        inventory.entries,
        inventory.inventory_digest,
        PILOT_DATE,
        HistoricalStatus.WITHDRAWN_NON_ADMISSIBLE,
        ReplacementStatus.PENDING,
        WithdrawalReason.PERMANENT_RESERVATION_OVERLAP,
        "",
    )
    return HistoricalWithdrawalCandidateV1(
        draft.entries,
        draft.inventory_digest,
        draft.pilot_date,
        draft.status,
        draft.replacement_status,
        draft.reason,
        content_digest(_candidate_value(draft, include_digest=False)),
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise HistoricalAuthorizationError(f"duplicate canonical JSON key: {key}")
        value[key] = item
    return value


def _decode_review(content: bytes) -> dict[str, object]:
    if not isinstance(content, bytes) or not content:
        raise HistoricalAuthorizationError("historical review bytes must be nonempty")
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except HistoricalAuthorizationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HistoricalAuthorizationError("historical review bytes are unreadable") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != content:
        raise HistoricalAuthorizationError("historical review bytes are not canonical")
    return value


def _review_value(review: HistoricalReviewEvidenceV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": review.subject_digest,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosed": review.conflict_disclosed,
        "policy_digest": review.policy_digest,
    }
    if include_digest:
        value["review_digest"] = review.review_digest
    return value


def _review_fields() -> frozenset[str]:
    return frozenset(
        {
            "schema_version",
            "subject_digest",
            "decision",
            "producer_identity",
            "reviewer_identity",
            "conflict_disclosed",
            "policy_digest",
            "review_digest",
        }
    )


def _validate_review_evidence(review: HistoricalReviewEvidenceV1) -> None:
    _require_digest(review.subject_digest, "review subject digest")
    producer = _require_text(review.producer_identity, "producer identity")
    reviewer = _require_text(review.reviewer_identity, "reviewer identity")
    if producer == reviewer:
        raise HistoricalAuthorizationError("historical review must be independent")
    if review.conflict_disclosed is not True:
        raise HistoricalAuthorizationError("historical review conflict disclosure is required")
    _require_digest(review.policy_digest, "review policy digest")
    expected = content_digest(_review_value(review, include_digest=False))
    if review.review_digest != expected:
        raise HistoricalAuthorizationError("historical review digest does not match")


def _review_evidence(content: bytes) -> HistoricalReviewEvidenceV1:
    value = _decode_review(content)
    if set(value) != _review_fields() or value.get("schema_version") != HISTORICAL_REVIEW_SCHEMA:
        raise HistoricalAuthorizationError("historical review fields or schema are unsupported")
    if value.get("decision") != "authorize_exact_historical_audit":
        raise HistoricalAuthorizationError("historical review decision is unsupported")
    producer = _require_text(value.get("producer_identity"), "producer identity")
    reviewer = _require_text(value.get("reviewer_identity"), "reviewer identity")
    if producer == reviewer:
        raise HistoricalAuthorizationError("historical review must be independent")
    if value.get("conflict_disclosed") is not True:
        raise HistoricalAuthorizationError("historical review conflict disclosure is required")
    review = HistoricalReviewEvidenceV1(
        _require_digest(value.get("subject_digest"), "review subject digest"),
        producer,
        reviewer,
        True,
        _require_digest(value.get("policy_digest"), "review policy digest"),
        _require_digest(value.get("review_digest"), "review digest"),
    )
    _validate_review_evidence(review)
    return review


def _withdrawal_value(withdrawal: HistoricalWithdrawalV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "candidate": _candidate_value(withdrawal.candidate, include_digest=True),
        "review": _review_value(withdrawal.review, include_digest=True),
    }
    if include_digest:
        value["withdrawal_digest"] = withdrawal.withdrawal_digest
    return value


def withdrawal_bytes(withdrawal: HistoricalWithdrawalV1) -> bytes:
    _validate_candidate(withdrawal.candidate)
    _validate_review_evidence(withdrawal.review)
    if withdrawal.review.subject_digest != withdrawal.candidate.candidate_digest:
        raise HistoricalAuthorizationError("historical review subject does not match withdrawal candidate")
    expected = content_digest(_withdrawal_value(withdrawal, include_digest=False))
    if withdrawal.withdrawal_digest != expected:
        raise HistoricalAuthorizationError("historical withdrawal digest does not match")
    return canonical_json_bytes(_withdrawal_value(withdrawal, include_digest=True))


def accept_reviewed_withdrawal(candidate: HistoricalWithdrawalCandidateV1, review_content: bytes) -> HistoricalWithdrawalV1:
    _validate_candidate(candidate)
    review = _review_evidence(review_content)
    if review.subject_digest != candidate.candidate_digest:
        raise HistoricalAuthorizationError("historical review subject does not match withdrawal candidate")
    draft = HistoricalWithdrawalV1(candidate, review, "")
    return HistoricalWithdrawalV1(candidate, review, content_digest(_withdrawal_value(draft, include_digest=False)))


def require_current_qualification(withdrawal: HistoricalWithdrawalV1) -> None:
    withdrawal_bytes(withdrawal)
    raise HistoricalAuthorizationError("withdrawn historical pilot is non-admissible for current qualification")


def authorize_historical_path(root: Path, relative_path: str, expected_digest: str, withdrawal: HistoricalWithdrawalV1) -> bytes:
    withdrawal_bytes(withdrawal)
    path = _canonical_path(relative_path)
    digest = _require_digest(expected_digest, "historical requested digest")
    entries_by_path = {entry.path: entry for entry in withdrawal.candidate.entries}
    entry = entries_by_path.get(path)
    if entry is None or entry.content_digest != digest:
        raise HistoricalAuthorizationError("historical path and digest are not exactly authorized")
    content = _read_exact_file(root, path)
    if len(content) != entry.byte_length or sha256(content).hexdigest() != entry.content_digest:
        raise HistoricalAuthorizationError("historical byte length or digest changed")
    return content


__all__ = [
    "HISTORICAL_REVIEW_SCHEMA",
    "PINNED_HISTORICAL_DIGESTS",
    "HistoricalAuthorizationError",
    "HistoricalInventoryEntryV1",
    "HistoricalInventoryV1",
    "HistoricalPathReason",
    "HistoricalReviewEvidenceV1",
    "HistoricalStatus",
    "HistoricalWithdrawalCandidateV1",
    "HistoricalWithdrawalV1",
    "ReplacementStatus",
    "WithdrawalReason",
    "accept_reviewed_withdrawal",
    "authorize_historical_path",
    "build_withdrawal_candidate",
    "inventory_bytes",
    "pinned_historical_inventory",
    "require_current_qualification",
    "withdrawal_bytes",
]
