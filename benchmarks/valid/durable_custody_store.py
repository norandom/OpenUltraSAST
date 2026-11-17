"""Monotonic S3 compare-and-swap for population custody logs."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from benchmarks.valid.custody_probe_contract import (
    CustodyCapabilityReport,
    RealPopulationAdmissionDisabled,
    require_real_population_admission,
)
from benchmarks.valid.custody_probe_io import valid_version_id
from benchmarks.valid.store_configuration import RetentionProfile, StorePurpose, StoreSettings, store_namespace_identity
from openultrasast.core import canonical
from openultrasast.core.custody import (
    CUSTODY_LOG_SCHEMA,
    LineagePurpose,
    PopulationCustodyError,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationStatus,
    PopulationUseReceipt,
    PopulationUseRequest,
    validate_population_custody_log,
)

_CONFLICT_CODES = frozenset({"409", "412", "ConditionalRequestConflict", "PreconditionFailed"})
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound", "NoSuchVersion"})
_DIGEST = re.compile(r"[0-9a-f]{64}")


class DurableCustodyReason(StrEnum):
    CAPABILITY_DISABLED = "capability_disabled"
    INVALID_INPUT = "invalid_input"
    NOT_FOUND = "not_found"
    INVALID_LOG = "invalid_log"
    INVALID_SUCCESSOR = "invalid_successor"
    UNREADABLE_RESPONSE = "unreadable_response"
    READBACK_MISMATCH = "readback_mismatch"
    STORE_FAILURE = "store_failure"


class DurableCustodyStoreError(RuntimeError):
    def __init__(self, reason: DurableCustodyReason) -> None:
        self.reason = reason
        super().__init__(f"durable_custody_{reason.value}")


class S3DurableCustodyClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class _StorageReceipt:
    version_id: str
    storage_token: str


@dataclass(frozen=True)
class _WriteAttempt:
    receipt: _StorageReceipt | None
    is_conflict: bool
    reason: DurableCustodyReason | None


@dataclass(frozen=True)
class _StoredLog:
    log: PopulationCustodyLog
    body: bytes
    receipt: _StorageReceipt


@dataclass(frozen=True)
class _ReadAttempt:
    stored: _StoredLog | None
    is_absent: bool
    reason: DurableCustodyReason | None


def _provider_code(error: Exception) -> str:
    try:
        response = getattr(error, "response", None)
        details = response.get("Error") if isinstance(response, Mapping) else None
        code = details.get("Code", "") if isinstance(details, Mapping) else getattr(error, "code", "")
    except Exception:
        return ""
    return code if isinstance(code, str) else str(code) if type(code) is int else ""


def _request_value(request: PopulationUseRequest) -> canonical.JsonValue:
    return {
        "population_digest": request.population_digest,
        "arm_id": request.arm_id,
        "purpose": request.purpose.value,
        "labels_accessed": request.labels_accessed,
        "influenced_artifact_digest": request.influenced_artifact_digest,
        "expected_log_digest": request.expected_log_digest,
    }


def _receipt_value(receipt: PopulationUseReceipt) -> canonical.JsonValue:
    return {
        "request": _request_value(receipt.request),
        "request_digest": receipt.request_digest,
        "population_digest": receipt.population_digest,
        "custodian_identity": receipt.custodian_identity,
        "sequence": receipt.sequence,
        "predecessor_digest": receipt.predecessor_digest,
        "prior_status": receipt.prior_status.value,
        "status": receipt.status.value,
        "reasons": receipt.reasons,
        "receipt_digest": receipt.receipt_digest,
    }


def canonical_population_custody_log_bytes(log: PopulationCustodyLog) -> bytes:
    value: canonical.JsonValue = {
        "schema_version": CUSTODY_LOG_SCHEMA,
        "population_digest": log.population_digest,
        "custodian_identity": log.custodian_identity,
        "receipts": tuple(_receipt_value(receipt) for receipt in log.receipts),
        "receipt_count": log.receipt_count,
        "head_receipt_digest": log.head_receipt_digest,
        "status": log.status.value,
        "log_digest": log.log_digest,
    }
    return canonical.canonical_bytes(value)


def _request_from(value: object) -> PopulationUseRequest | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return PopulationUseRequest(
            cast(str, value["population_digest"]),
            cast(str, value["arm_id"]),
            LineagePurpose(value["purpose"]),
            cast(bool, value["labels_accessed"]),
            cast(str | None, value["influenced_artifact_digest"]),
            cast(str, value["expected_log_digest"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _receipt_from(value: object) -> PopulationUseReceipt | None:
    if not isinstance(value, Mapping):
        return None
    request = _request_from(value.get("request"))
    if request is None:
        return None
    try:
        reasons = value["reasons"]
        if not isinstance(reasons, list):
            return None
        return PopulationUseReceipt(
            request,
            cast(str, value["request_digest"]),
            cast(str, value["population_digest"]),
            cast(str, value["custodian_identity"]),
            cast(int, value["sequence"]),
            cast(str | None, value["predecessor_digest"]),
            PopulationStatus(value["prior_status"]),
            PopulationStatus(value["status"]),
            tuple(cast(list[str], reasons)),
            cast(str, value["receipt_digest"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _decode_log(body: bytes) -> PopulationCustodyLog | None:
    try:
        value = json.loads(body)
        if not isinstance(value, Mapping) or value.get("schema_version") != CUSTODY_LOG_SCHEMA:
            return None
        raw_receipts = value["receipts"]
        if not isinstance(raw_receipts, list):
            return None
        receipts = tuple(_receipt_from(item) for item in raw_receipts)
        if any(item is None for item in receipts):
            return None
        log = PopulationCustodyLog(
            cast(str, value["population_digest"]),
            cast(str, value["custodian_identity"]),
            cast(tuple[PopulationUseReceipt, ...], receipts),
            cast(int, value["receipt_count"]),
            cast(str | None, value["head_receipt_digest"]),
            PopulationStatus(value["status"]),
            cast(str, value["log_digest"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        return None
    return log if canonical_population_custody_log_bytes(log) == body else None


class S3DurableCustodyStore:
    """Capability-gated durable head and content-addressed custody events."""

    def __init__(
        self,
        settings: StoreSettings,
        client: S3DurableCustodyClient,
        policy: PopulationCustodyPolicy,
        capability_report: CustodyCapabilityReport,
        transient_store_identity: str,
        transient_profile: RetentionProfile,
    ) -> None:
        valid = type(settings) is StoreSettings and settings.purpose is StorePurpose.DURABLE
        if not valid or type(policy) is not PopulationCustodyPolicy:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_INPUT)
        disabled = False
        try:
            require_real_population_admission(
                capability_report,
                store_namespace_identity(settings),
                transient_store_identity,
                transient_profile,
            )
        except RealPopulationAdmissionDisabled:
            disabled = True
        if disabled:
            raise DurableCustodyStoreError(DurableCustodyReason.CAPABILITY_DISABLED)
        self._settings = settings
        self._client = client
        self._policy = policy

    def initialize(self, initial: PopulationCustodyLog) -> bool:
        self._validate_initial(initial)
        body = canonical_population_custody_log_bytes(initial)
        self._persist_event(initial, body)
        write = self._write(self._head_key(initial.population_digest), body, absent=True)
        if write.is_conflict:
            return False
        receipt = self._require_write(write)
        self._verify_committed(initial, body, receipt)
        return True

    def current_log(self, population_digest: str) -> PopulationCustodyLog:
        if not isinstance(population_digest, str) or _DIGEST.fullmatch(population_digest) is None:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_INPUT)
        read = self._read(self._head_key(population_digest))
        if read.is_absent:
            raise DurableCustodyStoreError(DurableCustodyReason.NOT_FOUND)
        stored = self._require_read(read)
        if stored.log.population_digest != population_digest:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_LOG)
        self._validate_log(stored.log)
        return stored.log

    def compare_and_swap(self, expected_log_digest: str, replacement: PopulationCustodyLog) -> bool:
        if not isinstance(expected_log_digest, str) or _DIGEST.fullmatch(expected_log_digest) is None:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_INPUT)
        self._validate_log(replacement)
        current = self._read(self._head_key(replacement.population_digest))
        stored = self._require_read(current)
        if stored.log.log_digest != expected_log_digest:
            return False
        self._validate_successor(stored.log, replacement)
        body = canonical_population_custody_log_bytes(replacement)
        self._persist_event(replacement, body)
        write = self._write(
            self._head_key(replacement.population_digest),
            body,
            token=stored.receipt.storage_token,
        )
        if write.is_conflict:
            return False
        receipt = self._require_write(write)
        if receipt.version_id == stored.receipt.version_id or receipt.storage_token == stored.receipt.storage_token:
            raise DurableCustodyStoreError(DurableCustodyReason.UNREADABLE_RESPONSE)
        self._verify_committed(replacement, body, receipt)
        return True

    def _validate_log(self, log: PopulationCustodyLog) -> None:
        invalid = False
        try:
            validate_population_custody_log(log, self._policy)
        except (PopulationCustodyError, TypeError, ValueError):
            invalid = True
        if invalid:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_LOG)

    def _validate_initial(self, log: PopulationCustodyLog) -> None:
        self._validate_log(log)
        if log.status is not PopulationStatus.AVAILABLE or log.receipt_count != 0 or log.receipts:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_LOG)

    def _validate_successor(self, prior: PopulationCustodyLog, replacement: PopulationCustodyLog) -> None:
        direct = (
            prior.status is PopulationStatus.AVAILABLE
            and replacement.status is PopulationStatus.SPENT
            and prior.population_digest == replacement.population_digest
            and prior.custodian_identity == replacement.custodian_identity
            and replacement.receipt_count == prior.receipt_count + 1
            and replacement.receipts[:-1] == prior.receipts
            and replacement.receipts[-1].request.expected_log_digest == prior.log_digest
        )
        if not direct:
            raise DurableCustodyStoreError(DurableCustodyReason.INVALID_SUCCESSOR)

    def _persist_event(self, log: PopulationCustodyLog, body: bytes) -> None:
        key = self._event_key(log.population_digest, log.log_digest)
        write = self._write(key, body, absent=True)
        if write.is_conflict:
            existing = self._require_read(self._read(key))
            if existing.body != body or existing.log != log:
                raise DurableCustodyStoreError(DurableCustodyReason.READBACK_MISMATCH)
            return
        receipt = self._require_write(write)
        self._verify_exact(key, log, body, receipt)

    def _verify_committed(self, log: PopulationCustodyLog, body: bytes, receipt: _StorageReceipt) -> None:
        self._verify_exact(self._head_key(log.population_digest), log, body, receipt)

    def _verify_exact(self, key: str, log: PopulationCustodyLog, body: bytes, receipt: _StorageReceipt) -> None:
        read = self._require_read(self._read(key, receipt.version_id))
        if read.log != log or read.body != body or read.receipt != receipt:
            raise DurableCustodyStoreError(DurableCustodyReason.READBACK_MISMATCH)
        self._validate_log(read.log)

    def _write(
        self,
        key: str,
        body: bytes,
        *,
        absent: bool = False,
        token: str | None = None,
    ) -> _WriteAttempt:
        request: dict[str, object] = {"Bucket": self._settings.bucket, "Key": key, "Body": body}
        if absent:
            request["IfNoneMatch"] = "*"
        if token is not None:
            request["IfMatch"] = token
        code = ""
        try:
            response = self._client.put_object(**request)
        except Exception as error:
            code = _provider_code(error)
            response = None
        if response is None:
            return _WriteAttempt(None, code in _CONFLICT_CODES, DurableCustodyReason.STORE_FAILURE)
        if not isinstance(response, Mapping):
            return _WriteAttempt(None, False, DurableCustodyReason.UNREADABLE_RESPONSE)
        version_id, token_value = response.get("VersionId"), response.get("ETag")
        if not valid_version_id(version_id) or not isinstance(token_value, str) or not token_value:
            return _WriteAttempt(None, False, DurableCustodyReason.UNREADABLE_RESPONSE)
        return _WriteAttempt(_StorageReceipt(cast(str, version_id), token_value), False, None)

    def _read(self, key: str, version_id: str | None = None) -> _ReadAttempt:
        request: dict[str, object] = {"Bucket": self._settings.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        code = ""
        try:
            response = self._client.get_object(**request)
        except Exception as error:
            code = _provider_code(error)
            response = None
        if response is None:
            absent = code in _NOT_FOUND_CODES
            reason = None if absent else DurableCustodyReason.STORE_FAILURE
            return _ReadAttempt(None, absent, reason)
        return self._decode_read(response)

    @staticmethod
    def _decode_read(response: Mapping[str, object]) -> _ReadAttempt:
        source = response.get("Body")
        try:
            body = source.read() if hasattr(source, "read") else source
        except Exception:
            body = None
        version_id, token, length = response.get("VersionId"), response.get("ETag"), response.get("ContentLength")
        valid = (
            isinstance(body, bytes)
            and bool(body)
            and type(length) is int
            and length == len(body)
            and valid_version_id(version_id)
            and isinstance(token, str)
            and bool(token)
        )
        if not valid:
            return _ReadAttempt(None, False, DurableCustodyReason.UNREADABLE_RESPONSE)
        log = _decode_log(cast(bytes, body))
        if log is None:
            return _ReadAttempt(None, False, DurableCustodyReason.INVALID_LOG)
        receipt = _StorageReceipt(cast(str, version_id), cast(str, token))
        return _ReadAttempt(_StoredLog(log, cast(bytes, body), receipt), False, None)

    @staticmethod
    def _require_write(write: _WriteAttempt) -> _StorageReceipt:
        if write.receipt is None:
            raise DurableCustodyStoreError(write.reason or DurableCustodyReason.STORE_FAILURE)
        return write.receipt

    @staticmethod
    def _require_read(read: _ReadAttempt) -> _StoredLog:
        if read.stored is None:
            reason = DurableCustodyReason.NOT_FOUND if read.is_absent else read.reason
            raise DurableCustodyStoreError(reason or DurableCustodyReason.STORE_FAILURE)
        return read.stored

    @staticmethod
    def _head_key(population_digest: str) -> str:
        return f"custody/{population_digest}/head.json"

    @staticmethod
    def _event_key(population_digest: str, log_digest: str) -> str:
        return f"custody/{population_digest}/events/{log_digest}.json"


__all__ = [
    "DurableCustodyReason",
    "DurableCustodyStoreError",
    "S3DurableCustodyClient",
    "S3DurableCustodyStore",
    "canonical_population_custody_log_bytes",
]
