"""Exact durable projection recovery after local scratch loss."""

from __future__ import annotations

import io
import shutil
import sys
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import artifact_recovery as recovery  # noqa: E402
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
    def __init__(self, code: str, detail: str = "provider private-label pass_word=/home/private") -> None:
        rendered = detail.replace("pass_", "pass")
        self.response = {"Error": {"Code": code, "Message": rendered}}
        super().__init__(rendered)


class _Client:
    def __init__(self, objects: dict[tuple[str, str], bytes] | None = None) -> None:
        self.objects = {} if objects is None else objects
        self.read_count = 0

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if key in self.objects:
            raise _ProviderError("PreconditionFailed")
        body = kwargs["Body"]
        assert isinstance(body, bytes)
        self.objects[key] = body
        return {"ETag": "opaque"}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.read_count += 1
        key = (str(kwargs["Bucket"]), str(kwargs["Key"]))
        if key not in self.objects:
            raise _ProviderError("NoSuchKey")
        content = self.objects[key]
        return {"Body": io.BytesIO(content), "ContentLength": len(content)}


def _settings() -> StoreSettings:
    return StoreSettings(
        StorePurpose.DURABLE,
        "https://durable.invalid:9000",
        "valid-benchmark-durable",
        "access",
        "secret",
        "eu-test-1",
        None,
    )


def _repo(client: _Client) -> repository.S3ArtifactRepository:
    return repository.S3ArtifactRepository(_settings(), client)


def _authority(access: ArtifactAccessClass) -> repository.ArtifactReadAuthority:
    if access is ArtifactAccessClass.CUSTODIAN_SEALED:
        return repository.artifact_read_authority(
            repository.ArtifactActorRole.CUSTODIAN,
            (repository.ArtifactReadPermission.CUSTODIAN_SEALED,),
            _digest("read-policy"),
            expected_access_policy_digest=_digest("read-policy"),
        )
    if access is ArtifactAccessClass.PRIVATE:
        return repository.artifact_read_authority(
            repository.ArtifactActorRole.CUSTODIAN,
            (repository.ArtifactReadPermission.PRIVATE,),
            _digest("read-policy"),
            expected_access_policy_digest=_digest("read-policy"),
        )
    return repository.artifact_read_authority(
        repository.ArtifactActorRole.OPERATOR,
        (),
        _digest("read-policy"),
        expected_access_policy_digest=_digest("read-policy"),
    )


def _member(family: recovery.ProjectionFamily, index: int) -> tuple[bytes, ArtifactReference]:
    content = canonical_artifact_bytes(
        recovery.projection_kind(family),
        {"decision": f"accepted_{index}", "sequence": index},
        access_class=recovery.projection_access(family),
        provenance_digest=_digest(f"member-provenance-{family.value}"),
    )
    return content, artifact_reference(content)


def _member_with_access(
    family: recovery.ProjectionFamily,
    index: int,
    access: ArtifactAccessClass,
) -> tuple[bytes, ArtifactReference]:
    content = canonical_artifact_bytes(
        recovery.projection_kind(family),
        {"decision": f"accepted_{index}", "sequence": index},
        access_class=access,
        provenance_digest=_digest(f"member-provenance-{family.value}-{access.value}"),
    )
    return content, artifact_reference(content)


def _stored_projection(
    family: recovery.ProjectionFamily,
    client: _Client,
) -> tuple[repository.S3ArtifactRepository, recovery.DurableProjectionRootV1, ArtifactReference]:
    repo = _repo(client)
    members = tuple(_member(family, index) for index in range(2))
    for content, reference in members:
        repo.put_if_absent(content, reference=reference)
    root, content, reference = recovery.build_durable_projection_root(
        family,
        tuple(reference for _, reference in members),
        authority_digest=_digest(f"authority-{family.value}"),
        expires_at_epoch=2_000_000_000,
    )
    repo.put_if_absent(content, reference=reference)
    return repo, root, reference


def _stored_mixed_population(
    client: _Client,
) -> tuple[repository.S3ArtifactRepository, recovery.DurableProjectionRootV1, ArtifactReference]:
    repo = _repo(client)
    accesses = (
        ArtifactAccessClass.PUBLIC,
        ArtifactAccessClass.PRIVATE,
        ArtifactAccessClass.CUSTODIAN_SEALED,
    )
    members = tuple(_member_with_access(recovery.ProjectionFamily.POPULATION, index, access) for index, access in enumerate(accesses))
    for content, reference in members:
        repo.put_if_absent(content, reference=reference)
    root, content, reference = recovery.build_durable_projection_root(
        recovery.ProjectionFamily.POPULATION,
        tuple(member_reference for _, member_reference in members),
        authority_digest=_digest("mixed-population-authority"),
        expires_at_epoch=2_000_000_000,
    )
    repo.put_if_absent(content, reference=reference)
    return repo, root, reference


def _mixed_population_authority() -> repository.ArtifactReadAuthority:
    return repository.artifact_read_authority(
        repository.ArtifactActorRole.CUSTODIAN,
        (
            repository.ArtifactReadPermission.PRIVATE,
            repository.ArtifactReadPermission.CUSTODIAN_SEALED,
        ),
        _digest("read-policy"),
        expected_access_policy_digest=_digest("read-policy"),
    )


def _unprivileged_authority(role: repository.ArtifactActorRole) -> repository.ArtifactReadAuthority:
    return repository.artifact_read_authority(
        role,
        (),
        _digest("read-policy"),
        expected_access_policy_digest=_digest("read-policy"),
    )


def _unchecked_root_artifact(
    root: recovery.DurableProjectionRootV1,
    *,
    envelope_family: recovery.ProjectionFamily,
    envelope_kind: ArtifactKind | None = None,
    envelope_access: ArtifactAccessClass | None = None,
    envelope_provenance: str | None = None,
) -> tuple[bytes, ArtifactReference]:
    payload = {
        "schema_version": root.schema_version,
        "family": root.family.value,
        "authority_digest": root.authority_digest,
        "expires_at_epoch": root.expires_at_epoch,
        "member_count": root.member_count,
        "member_references": tuple(
            {
                "artifact_kind": item.artifact_kind.value,
                "access_class": item.access_class.value,
                "provenance_digest": item.provenance_digest,
                "content_digest": item.content_digest,
                "byte_length": item.byte_length,
            }
            for item in root.member_references
        ),
        "ordered_member_digest": root.ordered_member_digest,
    }
    content = canonical_artifact_bytes(
        recovery.projection_kind(envelope_family) if envelope_kind is None else envelope_kind,
        payload,
        access_class=recovery.projection_access(envelope_family) if envelope_access is None else envelope_access,
        provenance_digest=root.authority_digest if envelope_provenance is None else envelope_provenance,
    )
    return content, artifact_reference(content)


def test_genuine_canonical_root_round_trips_exact_bytes_and_reference() -> None:
    client = _Client()
    repo, root, stored_reference = _stored_projection(recovery.ProjectionFamily.RESERVATION, client)
    content, reference = recovery.canonical_projection_root_artifact(root)

    assert reference == stored_reference
    accepted = repo.get(
        reference,
        expected_kind=recovery.projection_kind(root.family),
        authority=_authority(recovery.projection_access(root.family)),
        expected_access_policy_digest=_digest("read-policy"),
    )
    assert accepted.content == content
    assert accepted.reference == reference


def test_mixed_access_population_projection_survives_scratch_loss(tmp_path: Path) -> None:
    client = _Client()
    _, root, reference = _stored_mixed_population(client)
    scratch = tmp_path / "population-materialized"
    scratch.mkdir()
    (scratch / "projection.json").write_text("replaceable")
    shutil.rmtree(scratch)

    result = recovery.recover_durable_projection(
        _repo(_Client(client.objects)),
        expected_family=root.family,
        root_reference=reference,
        authority=_mixed_population_authority(),
        expected_access_policy_digest=_digest("read-policy"),
        expected_authority_digest=root.authority_digest,
        current_epoch=1_900_000_000,
    )

    assert tuple(item.reference.access_class for item in result.members) == (
        ArtifactAccessClass.PUBLIC,
        ArtifactAccessClass.PRIVATE,
        ArtifactAccessClass.CUSTODIAN_SEALED,
    )
    assert tuple(item.reference for item in result.members) == root.member_references


@pytest.mark.parametrize(
    "role",
    (
        repository.ArtifactActorRole.DETECTOR,
        repository.ArtifactActorRole.PRESENTER,
        repository.ArtifactActorRole.OPERATOR,
    ),
)
def test_unprivileged_roles_cannot_recover_mixed_population_members(role: repository.ArtifactActorRole) -> None:
    client = _Client()
    repo, root, reference = _stored_mixed_population(client)
    authority = _unprivileged_authority(role)

    for member_reference in root.member_references:
        if member_reference.access_class is ArtifactAccessClass.PUBLIC:
            continue
        with pytest.raises(repository.ArtifactRepositoryError, match="not_authorized"):
            repo.get(
                member_reference,
                expected_kind=ArtifactKind.POPULATION,
                authority=authority,
                expected_access_policy_digest=_digest("read-policy"),
            )

    with pytest.raises(recovery.ArtifactRecoveryError):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=reference,
            authority=authority,
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


def test_private_only_custodian_cannot_read_sealed_population_member() -> None:
    client = _Client()
    repo, root, reference = _stored_mixed_population(client)

    with pytest.raises(recovery.ArtifactRecoveryError, match="invalid_member"):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=reference,
            authority=_authority(ArtifactAccessClass.PRIVATE),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


@pytest.mark.parametrize(
    "family",
    (
        recovery.ProjectionFamily.WORKFLOW,
        recovery.ProjectionFamily.REPLAY,
        recovery.ProjectionFamily.REPORT,
    ),
)
def test_nonexpiring_terminal_projection_recovers_at_arbitrarily_late_time(family: recovery.ProjectionFamily) -> None:
    client = _Client()
    repo = _repo(client)
    member_content, member_reference = _member(family, 0)
    repo.put_if_absent(member_content, reference=member_reference)
    root, root_content, root_reference = recovery.build_durable_projection_root(
        family,
        (member_reference,),
        authority_digest=_digest(f"nonexpiring-{family.value}"),
        expires_at_epoch=None,
    )
    repo.put_if_absent(root_content, reference=root_reference)

    result = recovery.recover_durable_projection(
        repo,
        expected_family=family,
        root_reference=root_reference,
        authority=_authority(recovery.projection_access(family)),
        expected_access_policy_digest=_digest("read-policy"),
        expected_authority_digest=root.authority_digest,
        current_epoch=10**30,
    )

    assert result.root.expires_at_epoch is None
    assert result.root_reference == root_reference


@pytest.mark.parametrize("mutation", ("kind", "access", "payload"))
def test_rehashed_noncanonical_root_envelope_is_refused(mutation: str) -> None:
    client = _Client()
    repo, root, _ = _stored_projection(recovery.ProjectionFamily.POPULATION, client)
    payload_root = replace(root, schema_version="wrong") if mutation == "payload" else root
    content, forged_reference = _unchecked_root_artifact(
        payload_root,
        envelope_family=root.family,
        envelope_kind=ArtifactKind.REPLAY if mutation == "kind" else None,
        envelope_access=ArtifactAccessClass.PUBLIC if mutation == "access" else None,
    )
    repo.put_if_absent(content, reference=forged_reference)

    with pytest.raises(recovery.ArtifactRecoveryError):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=forged_reference,
            authority=_authority(recovery.projection_access(root.family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


def test_payload_authority_a_cannot_be_rewrapped_with_envelope_provenance_b() -> None:
    client = _Client()
    repo, root, _ = _stored_projection(recovery.ProjectionFamily.POPULATION, client)
    content, forged_reference = _unchecked_root_artifact(
        root,
        envelope_family=root.family,
        envelope_provenance=_digest("authority-b"),
    )
    repo.put_if_absent(content, reference=forged_reference)

    with pytest.raises(recovery.ArtifactRecoveryError, match="invalid_root"):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=forged_reference,
            authority=_authority(recovery.projection_access(root.family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


@pytest.mark.parametrize("family", tuple(recovery.ProjectionFamily))
def test_restart_recovers_every_projection_from_durable_objects_only(
    family: recovery.ProjectionFamily,
    tmp_path: Path,
) -> None:
    client = _Client()
    _, root, reference = _stored_projection(family, client)
    scratch = tmp_path / family.value
    scratch.mkdir()
    (scratch / "plausible-latest.json").write_text("stale local cache")
    shutil.rmtree(scratch)

    restarted_client = _Client(client.objects)
    restarted = _repo(restarted_client)
    result = recovery.recover_durable_projection(
        restarted,
        expected_family=family,
        root_reference=reference,
        authority=_authority(recovery.projection_access(family)),
        expected_access_policy_digest=_digest("read-policy"),
        expected_authority_digest=root.authority_digest,
        current_epoch=1_900_000_000,
    )

    assert result.root == root
    assert result.root_reference == reference
    assert tuple(item.reference for item in result.members) == root.member_references
    assert tuple(item.content for item in result.members) == tuple(_member(family, index)[0] for index in range(2))
    assert result.decision_digest == recovery.projection_decision_digest(root, result.members)
    assert restarted_client.read_count == root.member_count + 1
    assert (
        recovery.list_durable_projection(
            restarted,
            expected_family=family,
            root_reference=reference,
            authority=_authority(recovery.projection_access(family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )
        == root.member_references
    )


def test_recovery_preserves_member_order_and_never_selects_a_plausible_root() -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.LIFECYCLE, client)
    other_root, other_content, other_reference = recovery.build_durable_projection_root(
        recovery.ProjectionFamily.LIFECYCLE,
        tuple(reversed(root.member_references)),
        authority_digest=root.authority_digest,
        expires_at_epoch=2_000_000_000,
    )
    repo.put_if_absent(other_content, reference=other_reference)

    result = recovery.recover_durable_projection(
        repo,
        expected_family=recovery.ProjectionFamily.LIFECYCLE,
        root_reference=reference,
        authority=_authority(recovery.projection_access(recovery.ProjectionFamily.LIFECYCLE)),
        expected_access_policy_digest=_digest("read-policy"),
        expected_authority_digest=root.authority_digest,
        current_epoch=1_900_000_000,
    )
    assert result.root != other_root
    assert result.root_reference == reference
    assert tuple(item.reference for item in result.members) == root.member_references


@pytest.mark.parametrize("field", ("artifact_kind", "access_class"))
def test_root_reference_must_match_the_exact_expected_family_contract(field: str) -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.REPORT, client)
    changed = (
        replace(reference, artifact_kind=ArtifactKind.REPLAY)
        if field == "artifact_kind"
        else replace(reference, access_class=ArtifactAccessClass.PRIVATE)
    )

    with pytest.raises(recovery.ArtifactRecoveryError, match="invalid_root"):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=changed,
            authority=_authority(recovery.projection_access(root.family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


@pytest.mark.parametrize("failure", ("wrong_role", "wrong_policy"))
def test_sealed_observation_recovery_requires_exact_read_authority(failure: str) -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.OBSERVATION, client)
    authority = (
        _authority(ArtifactAccessClass.OPERATOR_SAFE) if failure == "wrong_role" else _authority(ArtifactAccessClass.CUSTODIAN_SEALED)
    )
    policy = _digest("read-policy") if failure == "wrong_role" else _digest("different-policy")

    with pytest.raises(recovery.ArtifactRecoveryError, match="invalid_root"):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=reference,
            authority=authority,
            expected_access_policy_digest=policy,
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


@pytest.mark.parametrize(
    "mutation",
    ("schema", "family", "authority", "expiry", "count", "order_digest", "duplicate", "member_kind", "member_access"),
)
def test_wrong_expired_or_conflicting_root_metadata_is_refused(mutation: str) -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.POPULATION, client)
    if mutation == "expiry":
        assert root.expires_at_epoch is not None
        with pytest.raises(recovery.ArtifactRecoveryError, match="expired_authority"):
            recovery.recover_durable_projection(
                repo,
                expected_family=root.family,
                root_reference=reference,
                authority=_authority(recovery.projection_access(root.family)),
                expected_access_policy_digest=_digest("read-policy"),
                expected_authority_digest=root.authority_digest,
                current_epoch=root.expires_at_epoch,
            )
        return

    changed = root
    if mutation == "schema":
        changed = replace(root, schema_version="wrong")
    elif mutation == "family":
        changed = replace(root, family=recovery.ProjectionFamily.REPORT)
    elif mutation == "authority":
        changed = replace(root, authority_digest=_digest("other-authority"))
    elif mutation == "count":
        changed = replace(root, member_count=root.member_count + 1)
    elif mutation == "order_digest":
        changed = replace(root, ordered_member_digest=_digest("wrong-order"))
    elif mutation == "duplicate":
        changed = replace(root, member_references=(root.member_references[0], root.member_references[0]))
    elif mutation == "member_kind":
        changed_ref = replace(root.member_references[0], artifact_kind=ArtifactKind.REPORT)
        changed = replace(root, member_references=(changed_ref, *root.member_references[1:]))
    elif mutation == "member_access":
        changed_ref = replace(root.member_references[0], access_class=ArtifactAccessClass.OPERATOR_SAFE)
        changed = replace(root, member_references=(changed_ref, *root.member_references[1:]))
    content, changed_ref = _unchecked_root_artifact(
        changed,
        envelope_family=recovery.ProjectionFamily.POPULATION,
    )
    repo.put_if_absent(content, reference=changed_ref)
    with pytest.raises(recovery.ArtifactRecoveryError):
        recovery.recover_durable_projection(
            repo,
            expected_family=recovery.ProjectionFamily.POPULATION,
            root_reference=changed_ref,
            authority=_authority(recovery.projection_access(recovery.ProjectionFamily.POPULATION)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


@pytest.mark.parametrize("failure", ("missing_root", "missing_member", "changed_member"))
def test_missing_or_changed_durable_bytes_fail_closed(failure: str) -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.REPORT, client)
    if failure == "missing_root":
        target = repository.artifact_object_location(_settings(), reference)
    else:
        target = repository.artifact_object_location(_settings(), root.member_references[0])
    key = (target.bucket, target.key)
    if failure == "changed_member":
        client.objects[key] = b"changed-private-payload"
    else:
        del client.objects[key]

    with pytest.raises(recovery.ArtifactRecoveryError):
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=reference,
            authority=_authority(recovery.projection_access(root.family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )


def test_recovery_errors_do_not_retain_private_payload_or_provider_diagnostics() -> None:
    client = _Client()
    repo, root, reference = _stored_projection(recovery.ProjectionFamily.OBSERVATION, client)
    target = repository.artifact_object_location(_settings(), root.member_references[0])
    del client.objects[(target.bucket, target.key)]

    with pytest.raises(recovery.ArtifactRecoveryError) as caught:
        recovery.recover_durable_projection(
            repo,
            expected_family=root.family,
            root_reference=reference,
            authority=_authority(recovery.projection_access(root.family)),
            expected_access_policy_digest=_digest("read-policy"),
            expected_authority_digest=root.authority_digest,
            current_epoch=1_900_000_000,
        )
    rendered = "".join(traceback.format_exception(caught.value))
    assert "private-label" not in rendered
    assert "password" not in rendered
    assert "/home/private" not in rendered
    assert "NoSuchKey" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
