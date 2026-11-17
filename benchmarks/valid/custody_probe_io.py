"""Strict S3 data-plane I/O for custody capability probes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from benchmarks.valid.custody_probe_contract import (
    CustodyCapabilityError,
    CustodyProbeErrorReason,
    ProbeResultReason,
)
from benchmarks.valid.store_configuration import StoreSettings
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes

_PRECONDITION_CODES = frozenset({"409", "412", "ConditionalRequestConflict", "PreconditionFailed"})
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound", "NoSuchVersion"})


class S3CustodyProbeClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_object_versions(self, **kwargs: object) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class WriteReceipt:
    version_id: str
    storage_token: str


@dataclass(frozen=True)
class WriteAttempt:
    receipt: WriteReceipt | None
    is_conflict: bool
    reason: ProbeResultReason


@dataclass(frozen=True)
class ReadAttempt:
    body: bytes | None
    receipt: WriteReceipt | None
    is_absent: bool
    reason: ProbeResultReason


def _provider_code(error: Exception) -> str:
    try:
        response = getattr(error, "response", None)
        details = response.get("Error") if isinstance(response, Mapping) else None
        code = details.get("Code", "") if isinstance(details, Mapping) else getattr(error, "code", "")
    except Exception:
        return ""
    return code if isinstance(code, str) else str(code) if type(code) is int else ""


def valid_epoch(value: object) -> bool:
    return type(value) is int and value > 0


def valid_version_id(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value != "null"


def probe_input(value: bytes) -> tuple[str, int]:
    if type(value) is not bytes or not value:
        raise CustodyCapabilityError(CustodyProbeErrorReason.INVALID_INPUT)
    return bytes_digest(value), len(value)


def probe_body(kind: str, input_digest: str, sequence: int) -> bytes:
    value: JsonValue = {"input_digest": input_digest, "kind": kind, "sequence": sequence}
    return canonical_bytes(value)


class ProbeIO:
    def __init__(self, settings: StoreSettings, client: S3CustodyProbeClient) -> None:
        self.settings = settings
        self.client = client

    def write(self, key: str, body: bytes, *, absent: bool = False, token: str | None = None) -> WriteAttempt:
        request: dict[str, object] = {"Bucket": self.settings.bucket, "Key": key, "Body": body}
        if absent:
            request["IfNoneMatch"] = "*"
        if token is not None:
            request["IfMatch"] = token
        provider_code = ""
        try:
            response = self.client.put_object(**request)
        except Exception as error:
            provider_code = _provider_code(error)
            response = None
        if response is None:
            return WriteAttempt(None, provider_code in _PRECONDITION_CODES, ProbeResultReason.STORE_FAILURE)
        if not isinstance(response, Mapping):
            return WriteAttempt(None, False, ProbeResultReason.UNREADABLE_RESPONSE)
        version_id, storage_token = response.get("VersionId"), response.get("ETag")
        if not valid_version_id(version_id) or not isinstance(storage_token, str) or not storage_token:
            return WriteAttempt(None, False, ProbeResultReason.UNREADABLE_RESPONSE)
        return WriteAttempt(WriteReceipt(cast(str, version_id), storage_token), False, ProbeResultReason.NONE)

    def read(self, key: str, version_id: str | None = None) -> ReadAttempt:
        request: dict[str, object] = {"Bucket": self.settings.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        provider_code = ""
        try:
            response = self.client.get_object(**request)
        except Exception as error:
            provider_code = _provider_code(error)
            response = None
        if response is None:
            is_absent = provider_code in _NOT_FOUND_CODES
            reason = ProbeResultReason.NONE if is_absent else ProbeResultReason.STORE_FAILURE
            return ReadAttempt(None, None, is_absent, reason)
        return self._decode_read(response)

    @staticmethod
    def _decode_read(response: Mapping[str, object]) -> ReadAttempt:
        body_source = response.get("Body")
        try:
            body = body_source.read() if hasattr(body_source, "read") else body_source
        except Exception:
            body = None
        version_id, storage_token, length = response.get("VersionId"), response.get("ETag"), response.get("ContentLength")
        valid = (
            isinstance(body, bytes)
            and bool(body)
            and type(length) is int
            and length == len(body)
            and valid_version_id(version_id)
            and isinstance(storage_token, str)
            and bool(storage_token)
        )
        if not valid:
            return ReadAttempt(None, None, False, ProbeResultReason.UNREADABLE_RESPONSE)
        receipt = WriteReceipt(cast(str, version_id), cast(str, storage_token))
        return ReadAttempt(cast(bytes, body), receipt, False, ProbeResultReason.NONE)

    def version_ids(self, key: str) -> tuple[tuple[str, ...] | None, ProbeResultReason]:
        try:
            response = self.client.list_object_versions(Bucket=self.settings.bucket, Prefix=key)
        except Exception:
            return None, ProbeResultReason.STORE_FAILURE
        if not isinstance(response, Mapping) or response.get("IsTruncated") is not False:
            return None, ProbeResultReason.UNREADABLE_RESPONSE
        versions = response.get("Versions", [])
        markers = response.get("DeleteMarkers", [])
        if not isinstance(versions, list) or not isinstance(markers, list) or markers:
            return None, ProbeResultReason.UNREADABLE_RESPONSE
        version_ids: list[str] = []
        for item in versions:
            if not isinstance(item, Mapping) or item.get("Key") != key:
                return None, ProbeResultReason.UNREADABLE_RESPONSE
            version_id = item.get("VersionId")
            if not valid_version_id(version_id):
                return None, ProbeResultReason.UNREADABLE_RESPONSE
            version_ids.append(cast(str, version_id))
        return tuple(version_ids), ProbeResultReason.NONE
