"""Create-only S3 artifact repository and access-boundary tests."""

from __future__ import annotations

import io
import sys
import traceback
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import artifact_repository as repository  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.store_configuration import StorePurpose, StoreSettings  # noqa: E402
from openultrasast.core.canonical import bytes_digest  # noqa: E402


def _digest(name: str) -> str:
    return bytes_digest(name.encode())


class _ProviderError(Exception):
    def __init__(self, code: str, secret: str = "provider-secret") -> None:
        self.response = {"Error": {"Code": code, "Message": secret}}
        super().__init__(secret)


class _ExplodingBody:
    def read(self) -> bytes:
        raise _ProviderError("InternalError", "body endpoint password=/home/body-private")


class _Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.put_calls: list[dict[str, object]] = []
        self.get_calls: list[dict[str, object]] = []
        self.put_error: Exception | None = None
        self.get_error: Exception | None = None
        self.read_override: bytes | None = None
        self.length_override: int | None = None
        self.put_response: dict[str, object] = {"ETag": "opaque-storage-token"}
        self.body_error = False

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.put_calls.append(kwargs)
        if self.put_error is not None:
            raise self.put_error
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if kwargs.get("IfNoneMatch") != "*":
            raise AssertionError("conditional create was not requested")
        if key in self.objects:
            raise _ProviderError("PreconditionFailed")
        body = kwargs["Body"]
        assert isinstance(body, bytes)
        self.objects[key] = body
        return self.put_response

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.get_calls.append(kwargs)
        if self.get_error is not None:
            raise self.get_error
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if key not in self.objects:
            raise _ProviderError("NoSuchKey")
        content = self.objects[key] if self.read_override is None else self.read_override
        length = len(content) if self.length_override is None else self.length_override
        body: object = _ExplodingBody() if self.body_error else io.BytesIO(content)
        return {"Body": body, "ContentLength": length}


def _settings() -> StoreSettings:
    return StoreSettings(
        StorePurpose.DURABLE,
        "https://store.internal.invalid:9000",
        "valid-benchmark-durable",
        "ACCESS-SECRET",
        "SECRET-SECRET",
        "eu-test-1",
        "SESSION-SECRET",
    )


def _artifact(
    kind: ArtifactKind = ArtifactKind.POPULATION,
    access: ArtifactAccessClass = ArtifactAccessClass.PUBLIC,
) -> tuple[bytes, ArtifactReference]:
    content = canonical_artifact_bytes(
        kind,
        {"count": 1, "authority_digest": _digest("authority")},
        access_class=access,
        provenance_digest=_digest("provenance"),
    )
    return content, artifact_reference(content)


def _authority(
    role: repository.ArtifactActorRole,
    permissions: tuple[repository.ArtifactReadPermission, ...] = (),
) -> repository.ArtifactReadAuthority:
    return repository.artifact_read_authority(
        role,
        permissions,
        _digest("read-policy"),
        expected_access_policy_digest=_digest("read-policy"),
    )


def _repo(client: _Client) -> repository.S3ArtifactRepository:
    return repository.S3ArtifactRepository(_settings(), client)


def _assert_closed_exception(error: BaseException) -> None:
    rendered = "".join(traceback.format_exception(error))
    for forbidden in (
        "provider-secret",
        "endpoint password",
        "/home/get-private",
        "/home/put-private",
        "/home/body-private",
        "raw-private-payload",
    ):
        assert forbidden not in rendered
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                pending.append(linked)
    assert len(seen) == 1


@pytest.mark.parametrize("kind", tuple(ArtifactKind))
def test_all_closed_artifact_kinds_round_trip_byte_identically(kind: ArtifactKind) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact(kind)

    assert content
    assert service.put_if_absent(content, reference=reference) == reference
    accepted = service.get(
        reference,
        expected_kind=kind,
        authority=_authority(repository.ArtifactActorRole.DETECTOR),
        expected_access_policy_digest=_digest("read-policy"),
    )
    assert accepted.content == content
    assert accepted.reference == reference
    assert client.put_calls[0]["IfNoneMatch"] == "*"


def test_purpose_key_is_closed_deterministic_and_contains_only_digest_metadata() -> None:
    content, reference = _artifact()
    first = repository.artifact_object_location(_settings(), reference)
    second = repository.artifact_object_location(_settings(), reference)

    assert content
    assert first == second
    assert first.purpose is StorePurpose.DURABLE
    assert first.bucket == "valid-benchmark-durable"
    assert first.key == f"populations/public/{reference.content_digest}.json"
    for forbidden in ("store.internal", "ACCESS-SECRET", "SECRET-SECRET", "/home/", "password"):
        assert forbidden not in first.key


def test_equal_existing_bytes_are_idempotent_and_different_bytes_conflict_without_overwrite() -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    location = repository.artifact_object_location(_settings(), reference)
    client.objects[(location.bucket, location.key)] = content

    assert service.put_if_absent(content, reference=reference) == reference
    assert client.objects[(location.bucket, location.key)] == content

    client.objects[(location.bucket, location.key)] = b"different-existing-bytes"
    with pytest.raises(repository.ArtifactRepositoryConflict) as caught:
        service.put_if_absent(content, reference=reference)
    assert caught.value.reason is repository.ArtifactRepositoryReason.IDENTITY_CONFLICT
    assert client.objects[(location.bucket, location.key)] == b"different-existing-bytes"
    assert "different" not in str(caught.value)


@pytest.mark.parametrize(
    ("access", "allowed_role", "permission"),
    (
        (ArtifactAccessClass.PUBLIC, repository.ArtifactActorRole.DETECTOR, None),
        (ArtifactAccessClass.PRIVATE, repository.ArtifactActorRole.CUSTODIAN, repository.ArtifactReadPermission.PRIVATE),
        (
            ArtifactAccessClass.CUSTODIAN_SEALED,
            repository.ArtifactActorRole.CUSTODIAN,
            repository.ArtifactReadPermission.CUSTODIAN_SEALED,
        ),
        (ArtifactAccessClass.OPERATOR_SAFE, repository.ArtifactActorRole.OPERATOR, None),
        (ArtifactAccessClass.OPERATOR_SAFE, repository.ArtifactActorRole.PRESENTER, None),
    ),
)
def test_access_classes_require_exact_roles_and_permissions(
    access: ArtifactAccessClass,
    allowed_role: repository.ArtifactActorRole,
    permission: repository.ArtifactReadPermission | None,
) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact(access=access)
    service.put_if_absent(content, reference=reference)
    permissions = () if permission is None else (permission,)

    accepted = service.get(
        reference,
        expected_kind=reference.artifact_kind,
        authority=_authority(allowed_role, permissions),
        expected_access_policy_digest=_digest("read-policy"),
    )
    assert accepted.content == content


@pytest.mark.parametrize(
    ("access", "role", "permissions"),
    (
        (ArtifactAccessClass.PRIVATE, repository.ArtifactActorRole.DETECTOR, ()),
        (ArtifactAccessClass.PRIVATE, repository.ArtifactActorRole.CUSTODIAN, ()),
        (ArtifactAccessClass.CUSTODIAN_SEALED, repository.ArtifactActorRole.OPERATOR, ()),
        (ArtifactAccessClass.CUSTODIAN_SEALED, repository.ArtifactActorRole.CUSTODIAN, ()),
        (ArtifactAccessClass.OPERATOR_SAFE, repository.ArtifactActorRole.DETECTOR, ()),
    ),
)
def test_unauthorized_reads_fail_before_fetch_without_raw_content(
    access: ArtifactAccessClass,
    role: repository.ArtifactActorRole,
    permissions: tuple[repository.ArtifactReadPermission, ...],
) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact(access=access)
    service.put_if_absent(content, reference=reference)
    client.get_calls.clear()

    with pytest.raises(repository.ArtifactRepositoryError) as caught:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(role, permissions),
            expected_access_policy_digest=_digest("read-policy"),
        )
    assert caught.value.reason is repository.ArtifactRepositoryReason.NOT_AUTHORIZED
    assert client.get_calls == []
    assert content.decode() not in str(caught.value)


def test_policy_mismatch_and_tampered_authority_fail_before_fetch() -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    service.put_if_absent(content, reference=reference)
    authority = _authority(repository.ArtifactActorRole.DETECTOR)
    client.get_calls.clear()

    for invalid in (authority, replace(authority, actor_role=repository.ArtifactActorRole.OPERATOR)):
        with pytest.raises(repository.ArtifactRepositoryError):
            service.get(
                reference,
                expected_kind=reference.artifact_kind,
                authority=invalid,
                expected_access_policy_digest=_digest("wrong-policy") if invalid is authority else _digest("read-policy"),
            )
    assert client.get_calls == []

    malformed_permissions = replace(
        authority,
        permissions=cast(tuple[repository.ArtifactReadPermission, ...], ("private",)),
    )
    with pytest.raises(repository.ArtifactRepositoryError):
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=malformed_permissions,
            expected_access_policy_digest=_digest("read-policy"),
        )

    with pytest.raises(repository.ArtifactRepositoryError):
        repository.artifact_read_authority(
            repository.ArtifactActorRole.DETECTOR,
            (repository.ArtifactReadPermission.PRIVATE,),
            _digest("read-policy"),
            expected_access_policy_digest=_digest("read-policy"),
        )
    with pytest.raises(repository.ArtifactRepositoryError):
        repository.artifact_read_authority(
            repository.ArtifactActorRole.DETECTOR,
            (),
            "not-a-digest",
            expected_access_policy_digest="not-a-digest",
        )


@pytest.mark.parametrize("mutation", ("kind", "digest", "length", "provenance", "access"))
def test_strict_reads_reject_every_reference_or_kind_mismatch(mutation: str) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    service.put_if_absent(content, reference=reference)
    expected_kind = reference.artifact_kind
    changed = reference
    if mutation == "kind":
        expected_kind = ArtifactKind.REPORT
    elif mutation == "digest":
        changed = replace(reference, content_digest=_digest("wrong"))
    elif mutation == "length":
        changed = replace(reference, byte_length=reference.byte_length + 1)
    elif mutation == "provenance":
        changed = replace(reference, provenance_digest=_digest("wrong"))
    else:
        changed = replace(reference, access_class=ArtifactAccessClass.PRIVATE)

    with pytest.raises(repository.ArtifactRepositoryError):
        service.get(
            changed,
            expected_kind=expected_kind,
            authority=_authority(repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_digest("read-policy"),
        )


@pytest.mark.parametrize(
    ("mode", "reason"),
    (
        ("missing", repository.ArtifactRepositoryReason.NOT_FOUND),
        ("empty", repository.ArtifactRepositoryReason.EMPTY_OBJECT),
        ("malformed", repository.ArtifactRepositoryReason.INVALID_OBJECT),
        ("length", repository.ArtifactRepositoryReason.STORE_FAILURE),
        ("transport", repository.ArtifactRepositoryReason.STORE_FAILURE),
    ),
)
def test_missing_empty_malformed_and_transport_reads_are_closed_failures(
    mode: str,
    reason: repository.ArtifactRepositoryReason,
) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    location = repository.artifact_object_location(_settings(), reference)
    if mode != "missing":
        client.objects[(location.bucket, location.key)] = content
    if mode == "empty":
        client.read_override = b""
    elif mode == "malformed":
        client.read_override = b"not-json"
    elif mode == "length":
        client.length_override = len(content) + 1
    elif mode == "transport":
        client.get_error = _ProviderError("InternalError", "endpoint password=/home/private")

    with pytest.raises(repository.ArtifactRepositoryError) as caught:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_digest("read-policy"),
        )
    assert caught.value.reason is reason
    assert "password" not in str(caught.value)
    assert "/home/" not in str(caught.value)


def test_successful_create_requires_exact_nonempty_readback() -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    client.read_override = b""

    with pytest.raises(repository.ArtifactRepositoryError) as caught:
        service.put_if_absent(content, reference=reference)
    assert caught.value.reason is repository.ArtifactRepositoryReason.EMPTY_OBJECT

    wrong_reference = replace(reference, byte_length=reference.byte_length + 1)
    with pytest.raises(repository.ArtifactRepositoryError) as invalid:
        _repo(_Client()).put_if_absent(content, reference=wrong_reference)
    assert invalid.value.reason is repository.ArtifactRepositoryReason.INVALID_OBJECT

    ambiguous_client = _Client()
    ambiguous_client.put_response = {}
    with pytest.raises(repository.ArtifactRepositoryError) as ambiguous:
        _repo(ambiguous_client).put_if_absent(content, reference=reference)
    assert ambiguous.value.reason is repository.ArtifactRepositoryReason.STORE_FAILURE


def test_configured_client_is_lazy_path_style_sigv4_and_does_not_administer_store(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def client_factory(*args: object, **kwargs: object) -> _Client:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _Client()

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=client_factory))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: kwargs))
    service = repository.open_s3_artifact_repository(_settings())

    assert isinstance(service, repository.S3ArtifactRepository)
    assert captured["args"] == ("s3",)
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["endpoint_url"] == _settings().endpoint
    assert kwargs["aws_access_key_id"] == _settings().access_key_id
    assert kwargs["aws_secret_access_key"] == _settings().secret_access_key
    config = kwargs["config"]
    assert isinstance(config, dict)
    assert config["signature_version"] == "s3v4"
    assert config["s3"] == {"addressing_style": "path"}
    assert not any(name in captured for name in ("create_bucket", "put_bucket_lifecycle", "put_bucket_versioning"))


@pytest.mark.parametrize(
    "failure",
    ("get", "put", "body", "precondition_missing", "precondition_transport", "precondition_malformed"),
)
def test_provider_failures_discard_exception_chains_and_sensitive_messages(failure: str) -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    location = repository.artifact_object_location(_settings(), reference)
    client.objects[(location.bucket, location.key)] = content
    if failure == "get":
        client.get_error = _ProviderError("InternalError", "endpoint password=/home/get-private")
    elif failure == "put":
        client.objects.clear()
        client.put_error = _ProviderError("InternalError", "endpoint password=/home/put-private")
    elif failure == "body":
        client.body_error = True
    elif failure == "precondition_missing":
        client.get_error = _ProviderError("NoSuchKey", "endpoint password=/home/missing-private")
    elif failure == "precondition_transport":
        client.get_error = _ProviderError("InternalError", "endpoint password=/home/reread-private")
    else:
        client.read_override = b"raw-private-payload"

    with pytest.raises(repository.ArtifactRepositoryError) as caught:
        if failure in {"get", "body"}:
            service.get(
                reference,
                expected_kind=reference.artifact_kind,
                authority=_authority(repository.ArtifactActorRole.DETECTOR),
                expected_access_policy_digest=_digest("read-policy"),
            )
        else:
            service.put_if_absent(content, reference=reference)
    _assert_closed_exception(caught.value)


def test_invalid_raw_artifact_failure_has_no_payload_bearing_exception_chain() -> None:
    client = _Client()
    service = _repo(client)
    content, reference = _artifact()
    location = repository.artifact_object_location(_settings(), reference)
    client.objects[(location.bucket, location.key)] = b"raw-private-payload"

    with pytest.raises(repository.ArtifactRepositoryError) as caught:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_digest("read-policy"),
        )
    _assert_closed_exception(caught.value)
