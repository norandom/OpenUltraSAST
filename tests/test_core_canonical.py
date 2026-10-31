"""Strict canonical codec and resolver-backed artifact boundary (Req 1.4, 10.4)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import MutableMapping
from dataclasses import replace
from enum import Enum
from typing import cast

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical


class _UnknownEnum(Enum):
    VALUE = "value"


def test_canonical_bytes_are_deterministic_utf8_and_compact() -> None:
    left: canonical.JsonValue = {"schema_version": canonical.DETECTION_CORE_SCHEMA, "z": "café", "a": (2, 1)}
    right: canonical.JsonValue = {"a": (2, 1), "z": "café", "schema_version": canonical.DETECTION_CORE_SCHEMA}
    expected = b'{"a":[2,1],"schema_version":"openultrasast.detection-core.v2","z":"caf\xc3\xa9"}'

    assert canonical.canonical_bytes(left) == expected
    assert canonical.canonical_bytes(right) == expected


def test_sequence_order_is_retained() -> None:
    assert canonical.canonical_bytes(("second", "first")) == b'["second","first"]'
    assert canonical.canonical_bytes(("first", "second")) != canonical.canonical_bytes(("second", "first"))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_numbers_are_refused_before_hashing(value: float) -> None:
    with pytest.raises(canonical.CanonicalizationError, match="finite"):
        canonical.content_digest({"schema_version": canonical.DETECTION_CORE_SCHEMA, "value": value})


@pytest.mark.parametrize("value", [[1], {1}, b"bytes", _UnknownEnum.VALUE, {1: "not-string"}])
def test_unsupported_values_are_refused(value: object) -> None:
    with pytest.raises(canonical.CanonicalizationError):
        canonical.canonical_bytes(value)  # type: ignore[arg-type]


def test_record_schema_is_explicit_and_closed() -> None:
    record = {"schema_version": canonical.DETECTION_CORE_SCHEMA, "value": "ok"}
    assert canonical.canonical_record_bytes(record) == canonical.canonical_bytes(record)
    with pytest.raises(canonical.SchemaVersionError, match="schema_version"):
        canonical.canonical_record_bytes({"value": "missing"})
    with pytest.raises(canonical.SchemaVersionError, match="unknown"):
        canonical.canonical_record_bytes({"schema_version": "openultrasast.unknown.v9"})


def test_sha256_identities_are_full_lowercase_hex() -> None:
    payload = {"schema_version": canonical.DETECTION_CORE_SCHEMA, "value": "ok"}
    digest = canonical.content_digest(payload)
    assert digest == hashlib.sha256(canonical.canonical_bytes(payload)).hexdigest()
    assert len(digest) == 64
    assert digest == digest.lower()


def test_duplicate_logical_identities_are_refused() -> None:
    canonical.require_unique_identities(("relation-1", "relation-2"), kind="relation")
    with pytest.raises(canonical.DuplicateIdentityError, match="relation-1"):
        canonical.require_unique_identities(("relation-1", "relation-1"), kind="relation")


@pytest.mark.parametrize("field", ["content_digest", "retention_policy_digest", "storage_receipt_digest"])
def test_content_reference_refuses_malformed_digests(field: str) -> None:
    reference, _ = stored_artifact(b"{}")
    with pytest.raises(canonical.DigestFormatError, match=field):
        _replace_reference_digest(reference, field, "ABC123")
    with pytest.raises(canonical.DigestFormatError, match=field):
        _replace_reference_digest(reference, field, cast(str, None))


@pytest.mark.parametrize("value", ["", 7, None])
def test_content_reference_requires_nonempty_text_identities(value: object) -> None:
    reference, _ = stored_artifact(b"{}")
    with pytest.raises(ValueError, match="artifact_id"):
        replace(reference, artifact_id=cast(str, value))
    with pytest.raises(ValueError, match="media_type"):
        replace(reference, media_type=cast(str, value))


@pytest.mark.parametrize("value", ["", 7, None])
def test_storage_receipt_requires_nonempty_text_identity(value: object) -> None:
    reference, resolver = stored_artifact(b"{}")
    receipt = resolver.artifacts[reference.artifact_id].receipt
    with pytest.raises(ValueError, match="store_identity"):
        replace(receipt, store_identity=cast(str, value))


def _replace_reference_digest(reference: canonical.ContentRef, field: str, value: str) -> canonical.ContentRef:
    if field == "content_digest":
        return replace(reference, content_digest=value)
    if field == "retention_policy_digest":
        return replace(reference, retention_policy_digest=value)
    if field == "storage_receipt_digest":
        return replace(reference, storage_receipt_digest=value)
    raise AssertionError(f"unknown test field: {field}")


def test_resolver_validates_content_and_receipt_before_returning_bytes() -> None:
    content = b'{"schema_version":"openultrasast.detection-core.v2"}'
    reference, resolver = stored_artifact(content)
    assert (
        canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=("trusted-store",),
            maximum_bytes=1024,
        )
        == content
    )


def test_missing_artifact_is_an_instrument_failure_not_empty_content() -> None:
    reference, _ = stored_artifact(b"nonempty")
    resolver = InMemoryContentResolver({})
    with pytest.raises(canonical.ArtifactResolutionError, match="not found"):
        canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=("trusted-store",),
            maximum_bytes=1024,
        )


def test_in_memory_resolver_defensively_copies_caller_mapping() -> None:
    reference, original = stored_artifact(b"original")
    _, replacement = stored_artifact(b"replacement")
    caller_mapping = {reference.artifact_id: original.artifacts[reference.artifact_id]}
    resolver = InMemoryContentResolver(caller_mapping)

    caller_mapping[reference.artifact_id] = replacement.artifacts[reference.artifact_id]

    assert resolver.resolve(reference).content == b"original"


def test_in_memory_resolver_exposes_read_only_state() -> None:
    reference, resolver = stored_artifact(b"original")
    _, replacement = stored_artifact(b"replacement")
    exposed = cast(MutableMapping[str, canonical.ResolvedContent], resolver.artifacts)

    with pytest.raises(TypeError):
        exposed[reference.artifact_id] = replacement.artifacts[reference.artifact_id]
    assert resolver.resolve(reference).content == b"original"


def _resolve(
    reference: canonical.ContentRef,
    resolver: InMemoryContentResolver,
    *,
    trusted_store_identities: tuple[str, ...] = ("trusted-store",),
    maximum_bytes: int = 1024,
) -> bytes:
    return canonical.resolve_content(
        reference,
        resolver,
        trusted_store_identities=trusted_store_identities,
        maximum_bytes=maximum_bytes,
    )


def test_content_digest_mismatch_precedes_parsing() -> None:
    reference, resolver = stored_artifact(b"not json")
    bad_reference = replace(reference, content_digest="0" * 64)
    with pytest.raises(canonical.ArtifactValidationError, match="content digest"):
        _resolve(bad_reference, resolver)


def test_resolved_byte_length_mismatch_is_refused() -> None:
    reference, resolver = stored_artifact(b"content")
    bad_reference = replace(reference, byte_length=reference.byte_length + 1)
    with pytest.raises(canonical.ArtifactValidationError, match="byte length"):
        _resolve(bad_reference, resolver)


@pytest.mark.parametrize(
    ("receipt_field", "value", "message"),
    [
        ("content_digest", "0" * 64, "receipt content digest"),
        ("byte_length", 99, "receipt byte length"),
        ("retention_policy_digest", "1" * 64, "retention policy"),
        ("receipt_digest", "2" * 64, "receipt digest"),
    ],
)
def test_storage_receipt_mismatches_are_refused(receipt_field: str, value: object, message: str) -> None:
    reference, resolver = stored_artifact(b"content")
    resolved = resolver.artifacts[reference.artifact_id]
    bad_receipt = _replace_receipt_field(resolved.receipt, receipt_field, value)
    bad_resolver = InMemoryContentResolver({reference.artifact_id: replace(resolved, receipt=bad_receipt)})
    with pytest.raises(canonical.ArtifactValidationError, match=message):
        _resolve(reference, bad_resolver)


def _replace_receipt_field(receipt: canonical.StorageReceipt, field: str, value: object) -> canonical.StorageReceipt:
    if field == "byte_length":
        if not isinstance(value, int):
            raise AssertionError("byte_length test value must be an integer")
        return replace(receipt, byte_length=value)
    if not isinstance(value, str):
        raise AssertionError(f"{field} test value must be text")
    if field == "content_digest":
        return replace(receipt, content_digest=value)
    if field == "retention_policy_digest":
        return replace(receipt, retention_policy_digest=value)
    if field == "receipt_digest":
        return replace(receipt, receipt_digest=value)
    raise AssertionError(f"unknown test field: {field}")


def test_untrusted_store_and_configured_size_limit_are_refused() -> None:
    reference, resolver = stored_artifact(b"content")
    with pytest.raises(canonical.ArtifactValidationError, match="trusted"):
        _resolve(reference, resolver, trusted_store_identities=("other-store",))
    with pytest.raises(canonical.ArtifactValidationError, match="maximum"):
        _resolve(reference, resolver, maximum_bytes=3)


def test_receipt_identity_is_rederived_not_merely_compared() -> None:
    reference, resolver = stored_artifact(b"content")
    resolved = resolver.artifacts[reference.artifact_id]
    forged = replace(resolved.receipt, store_identity="other-store")
    forged_reference = replace(reference, storage_receipt_digest=forged.receipt_digest)
    forged_resolver = InMemoryContentResolver({reference.artifact_id: replace(resolved, receipt=forged)})
    with pytest.raises(canonical.ArtifactValidationError, match="receipt digest"):
        _resolve(forged_reference, forged_resolver, trusted_store_identities=("other-store",))


def test_resolved_content_is_valid_json_only_after_boundary_validation() -> None:
    payload = {"schema_version": canonical.DETECTION_CORE_SCHEMA, "value": "read"}
    reference, resolver = stored_artifact(canonical.canonical_bytes(payload))
    validated = _resolve(reference, resolver)
    assert json.loads(validated) == payload
