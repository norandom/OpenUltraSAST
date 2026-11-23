"""Task 11.2 persistence validation suite: artifacts, custody, retention, recovery.

Adversarial suites over the committed persistence and custody machinery:
create-only conflicts, strict kind/digest reads, access classes, policy
mismatch, conditional create/update, concurrent writers, committed reread,
version visibility, transient expiry evidence, restart, and complete scratch
loss. Every refusal, zero, or capability result interpreted here is preceded
by a nonzero readability proof that first writes and reads back one real test
object through the configured fake S3 boundary (instrument rule). No suite
path issues administrator-owned store operations.
"""

from __future__ import annotations

import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import (  # noqa: E402
    artifact_recovery,
    artifact_repository,
    run,
    store_configuration,
    workflow_journal,
)
from benchmarks.valid.custody_probe_contract import (  # noqa: E402
    MANDATORY_PROBE_RESULTS,
    RETENTION_PROBE_STATE_SCHEMA,
    ProbeResult,
    ProbeResultName,
    ProbeResultReason,
    ProbeResultStatus,
    RetentionProbeState,
    build_capability_report,
    derive_retention_state_digest,
    failed_result,
    passed_result,
)
from benchmarks.valid.durable_custody_store import (  # noqa: E402
    DurableCustodyReason,
    DurableCustodyStoreError,
    S3DurableCustodyStore,
    canonical_population_custody_log_bytes,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core.canonical import content_digest  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    LineagePurpose,
    PopulationCustodyPolicy,
    PopulationUseRequest,
    append_population_use,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
    record_population_use,
)

_PROBE_KEY = "benchmarks-validation-probe/readability.json"


def _digest(seed: str) -> str:
    return content_digest({"seed": seed})


class _ProviderError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code, "Message": "provider password=/private/path"}}
        super().__init__("provider secret")


class _Version:
    def __init__(self, version_id: str, body: bytes, etag: str) -> None:
        self.version_id = version_id
        self.body = body
        self.etag = etag


class _RecordingClient:
    """Versioned fake S3 boundary with conditional writes, races, and an operation log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._versions: dict[tuple[str, str], list[_Version]] = {}
        self._next_version = 1
        self.operations: list[str] = []
        self.put_requests: list[dict[str, object]] = []
        self.provider_failure = False
        self.corrupt_reads = False
        self.fixed_version_id: str | None = None
        self.constant_etag = False
        self.force_head_conflict = False
        self.missing_version = False
        self.read_override: bytes | None = None
        self.length_override: int | None = None
        self.head_write_barrier: threading.Barrier | None = None

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        bucket = str(kwargs["Bucket"])
        barrier = self.head_write_barrier
        if barrier is not None and key.endswith("/head.json") and "IfMatch" in kwargs:
            barrier.wait(timeout=5)
        with self._lock:
            self.operations.append(f"put:{bucket}/{key}")
            self.put_requests.append(dict(kwargs))
            if self.provider_failure:
                raise _ProviderError("InternalError")
            if self.force_head_conflict and key.endswith("/head.json"):
                raise _ProviderError("PreconditionFailed")
            versions = self._versions.setdefault((bucket, key), [])
            current = versions[-1] if versions else None
            if kwargs.get("IfNoneMatch") == "*" and current is not None:
                raise _ProviderError("PreconditionFailed")
            expected = kwargs.get("IfMatch")
            if expected is not None and (current is None or current.etag != expected):
                raise _ProviderError("PreconditionFailed")
            body = kwargs["Body"]
            assert isinstance(body, bytes) and body
            version_id = self.fixed_version_id if self.fixed_version_id is not None else f"version-{self._next_version}"
            self._next_version += 1
            etag = "constant-etag" if self.constant_etag else sha256(body + version_id.encode()).hexdigest()
            versions.append(_Version(version_id, body, etag))
            response: dict[str, object] = {"ETag": etag}
            if not self.missing_version:
                response["VersionId"] = version_id
            return response

    def get_object(self, **kwargs: object) -> dict[str, object]:
        with self._lock:
            self.operations.append(f"get:{kwargs['Bucket']}/{kwargs['Key']}")
            if self.provider_failure:
                raise _ProviderError("InternalError")
            bucket, key = str(kwargs["Bucket"]), str(kwargs["Key"])
            requested = kwargs.get("VersionId")
            matching = [item for item in self._versions.get((bucket, key), []) if requested is None or item.version_id == requested]
            if not matching:
                raise _ProviderError("NoSuchKey")
            version = matching[-1]
            content = version.body if self.read_override is None else self.read_override
            if self.corrupt_reads:
                content = b"corrupt"
            length = len(content) if self.length_override is None else self.length_override
            return {
                "Body": io.BytesIO(content),
                "ContentLength": length,
                "VersionId": version.version_id,
                "ETag": version.etag,
            }

    def raw_put(self, bucket: str, key: str, body: bytes) -> None:
        with self._lock:
            version_id = f"version-{self._next_version}"
            self._next_version += 1
            self._versions.setdefault((bucket, key), []).append(_Version(version_id, body, sha256(body).hexdigest()))

    def drop(self, bucket: str, key: str) -> None:
        with self._lock:
            self._versions.pop((bucket, key), None)

    def versions_of(self, bucket: str, key: str) -> list[_Version]:
        with self._lock:
            return list(self._versions.get((bucket, key), []))

    def body_of(self, bucket: str, key: str) -> bytes:
        versions = self.versions_of(bucket, key)
        assert versions
        return versions[-1].body


def _durable_settings() -> store_configuration.StoreSettings:
    return store_configuration.StoreSettings(
        store_configuration.StorePurpose.DURABLE,
        "https://durable.invalid:9000",
        "valid-durable",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _transient_settings() -> store_configuration.StoreSettings:
    return store_configuration.StoreSettings(
        store_configuration.StorePurpose.TRANSIENT,
        "https://transient.invalid:9000",
        "valid-transient",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _transient_profile() -> store_configuration.RetentionProfile:
    return store_configuration.RetentionProfile(store_configuration.StorePurpose.TRANSIENT, True, True, True, 14, 1)


def _prove_store_nonzero(client: _RecordingClient, bucket: str) -> int:
    """Write and read back one real nonzero test object before interpreting results."""
    payload = b"persistence-validation-readability-probe"
    client.put_object(Bucket=bucket, Key=_PROBE_KEY, Body=payload, IfNoneMatch="*")
    response = client.get_object(Bucket=bucket, Key=_PROBE_KEY)
    body = response["Body"]
    assert isinstance(body, io.BytesIO)
    read_back = body.read()
    assert read_back == payload
    assert len(read_back) > 0
    return len(read_back)


def _environ() -> dict[str, str]:
    environ: dict[str, str] = {}
    for settings in (_durable_settings(), _transient_settings()):
        prefix = f"VALID_BENCHMARK_{settings.purpose.value.upper()}"
        environ[f"{prefix}_S3_ENDPOINT"] = settings.endpoint
        environ[f"{prefix}_S3_BUCKET"] = settings.bucket
        environ[f"{prefix}_AWS_ACCESS_KEY_ID"] = settings.access_key_id
        environ[f"{prefix}_AWS_SECRET_ACCESS_KEY"] = settings.secret_access_key
    return environ


def _evidence() -> dict[store_configuration.StorePurpose, store_configuration.StoreCapabilityEvidence]:
    durable = store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.DURABLE, True, True, True, None, 30)
    transient = store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, True, True, 14, 1)
    return {store_configuration.StorePurpose.DURABLE: durable, store_configuration.StorePurpose.TRANSIENT: transient}


def _capability_report(
    *,
    results: tuple[ProbeResult, ...] | None = None,
    input_bytes_read: int = 16,
    profile: store_configuration.RetentionProfile | None = None,
    durable_settings: store_configuration.StoreSettings | None = None,
    transient_settings: store_configuration.StoreSettings | None = None,
) -> object:
    durable = durable_settings or _durable_settings()
    transient = transient_settings or _transient_settings()
    input_digest = content_digest("persistence-validation-capability-input")
    draft = RetentionProbeState(
        RETENTION_PROBE_STATE_SCHEMA,
        input_digest,
        input_bytes_read,
        1_000,
        store_configuration.store_namespace_identity(durable),
        store_configuration.store_namespace_identity(transient),
        transient.bucket,
        "runs/probe/current.json",
        "version-current",
        2_000,
        "runs/probe/noncurrent.json",
        "version-prior",
        "version-successor",
        1_500,
        "",
    )
    state = replace(draft, state_digest=derive_retention_state_digest(draft))
    chosen = results if results is not None else tuple(passed_result(name) for name in MANDATORY_PROBE_RESULTS)
    return build_capability_report(input_digest, input_bytes_read, profile or _transient_profile(), state, chosen)


def _policy_and_logs() -> tuple[PopulationCustodyPolicy, object, object]:
    custodian = content_digest("persistence-validation-custodian")
    policy = PopulationCustodyPolicy((custodian,), derive_population_custody_policy_digest((custodian,)))
    available = empty_population_custody_log(content_digest({"population": "persistence-validation"}), custodian)
    request = PopulationUseRequest(
        available.population_digest,
        "arm-v3",
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        None,
        available.log_digest,
    )
    receipt = record_population_use(request, available, custodian, policy)
    return policy, available, append_population_use(available, receipt, policy)


def _custody_store(client: _RecordingClient, policy: PopulationCustodyPolicy, report: object | None = None) -> S3DurableCustodyStore:
    return S3DurableCustodyStore(
        _durable_settings(),
        client,
        policy,
        report or _capability_report(),  # type: ignore[arg-type]
        store_configuration.store_namespace_identity(_transient_settings()),
        _transient_profile(),
    )


_READ_POLICY = _digest("persistence-validation-read-policy")


def _authority(
    role: artifact_repository.ArtifactActorRole,
    permissions: tuple[artifact_repository.ArtifactReadPermission, ...] = (),
) -> artifact_repository.ArtifactReadAuthority:
    return artifact_repository.artifact_read_authority(
        role,
        permissions,
        _READ_POLICY,
        expected_access_policy_digest=_READ_POLICY,
    )


def _artifact(
    kind: ArtifactKind = ArtifactKind.POPULATION,
    access: ArtifactAccessClass = ArtifactAccessClass.PUBLIC,
    seed: str = "persistence-validation",
) -> tuple[bytes, ArtifactReference]:
    content = canonical_artifact_bytes(
        kind,
        {"authority_digest": _digest(seed), "count": 1},
        access_class=access,
        provenance_digest=_digest("provenance"),
    )
    return content, artifact_reference(content)


def _repo(client: _RecordingClient) -> artifact_repository.S3ArtifactRepository:
    return artifact_repository.S3ArtifactRepository(_durable_settings(), client)


def _custodian_authority() -> artifact_repository.ArtifactReadAuthority:
    return _authority(
        artifact_repository.ArtifactActorRole.CUSTODIAN,
        (artifact_repository.ArtifactReadPermission.PRIVATE, artifact_repository.ArtifactReadPermission.CUSTODIAN_SEALED),
    )


def _at(minute: int) -> str:
    hour, minute = divmod(minute, 60)
    return f"2026-11-22T{9 + hour:02d}:{minute:02d}:00Z"


def _workflow_digest() -> str:
    return _digest("persistence-validation-workflow")


def _authority_reference(seed: str = "retry-authority") -> ArtifactReference:
    return ArtifactReference(
        ArtifactKind.WORKFLOW,
        _digest(seed),
        256,
        _digest(f"{seed}-provenance"),
        ArtifactAccessClass.CUSTODIAN_SEALED,
    )


def _entry(**overrides: object) -> workflow_journal.WorkflowJournalEntryV1:
    value: dict[str, object] = {
        "workflow_digest": _workflow_digest(),
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


def _started_journal(
    client: _RecordingClient, authority: ArtifactReference | None = None
) -> tuple[workflow_journal.S3WorkflowJournal, workflow_journal.WorkflowHeadV1]:
    journal = workflow_journal.S3WorkflowJournal(_transient_settings(), client)
    selected = authority if authority is not None else _authority_reference()
    head = journal.initialize(_initial_entry(), selected, selected.content_digest)
    assert head is not None
    return journal, head


def _appended(
    journal: workflow_journal.S3WorkflowJournal, head: workflow_journal.WorkflowHeadV1, sequence: int
) -> workflow_journal.WorkflowHeadV1:
    entry = _entry(
        sequence=sequence,
        previous_entry_digest=head.entry_digest,
        heartbeat_at=_at(sequence),
        lease_expires_at=_at(sequence + 30),
    )
    successor = workflow_journal.successor_head(head, entry)
    assert journal.append_and_swap(head.head_digest, entry, successor) is True
    return successor


# ---------------------------------------------------------------------------
# Store configuration, retention profiles, and administrator boundary
# ---------------------------------------------------------------------------


def test_purpose_scoped_settings_load_and_namespaces_stay_secret_free() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    durable = store_configuration.load_store_settings(store_configuration.StorePurpose.DURABLE, _environ())
    transient = store_configuration.load_store_settings(store_configuration.StorePurpose.TRANSIENT, _environ())

    assert durable.purpose is store_configuration.StorePurpose.DURABLE
    assert transient.purpose is store_configuration.StorePurpose.TRANSIENT
    assert store_configuration.store_namespace_identity(durable) != store_configuration.store_namespace_identity(transient)
    for rendered in (repr(durable), repr(transient), store_configuration.store_namespace_identity(durable)):
        assert "SECRET-SECRET" not in rendered
        assert "ACCESS-SECRET" not in rendered
        assert "invalid:9000" not in rendered

    with pytest.raises(store_configuration.StoreConfigurationError) as missing:
        store_configuration.load_store_settings(store_configuration.StorePurpose.DURABLE, {})
    assert missing.value.reason is store_configuration.StoreConfigurationReason.MISSING
    assert set(missing.value.keys) == set(store_configuration.environment_keys(store_configuration.StorePurpose.DURABLE).required)


@pytest.mark.parametrize(
    ("current", "noncurrent"),
    ((None, 1), (0, 1), (-3, 1), (14, 0), (14, None), (True, 1), (14, True)),
)
def test_transient_retention_requires_registered_positive_current_and_noncurrent_expiry(current: object, noncurrent: object) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0

    with pytest.raises(store_configuration.StoreConfigurationError):
        store_configuration.RetentionProfile(
            store_configuration.StorePurpose.TRANSIENT,
            True,
            True,
            True,
            current,
            noncurrent,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(("current", "noncurrent"), ((14, None), (1, 0), (None, None), (14, -1), (None, True)))
def test_durable_retention_never_registers_current_expiry(current: object, noncurrent: object) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    with pytest.raises(store_configuration.StoreConfigurationError):
        store_configuration.RetentionProfile(
            store_configuration.StorePurpose.DURABLE,
            True,
            True,
            True,
            current,
            noncurrent,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("evidence", "reason"),
    (
        (store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, False, True, True, 14, 1), "versioning"),
        (
            store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, False, True, 14, 1),
            "conditional_create",
        ),
        (
            store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, True, False, 14, 1),
            "conditional_update",
        ),
        (store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, True, True, 7, 1), "current"),
        (store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, True, True, 14, 3), "noncurrent"),
    ),
)
def test_capability_evidence_mismatch_is_unsupported_with_the_exact_reason(
    evidence: store_configuration.StoreCapabilityEvidence, reason: str
) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0

    report = store_configuration.verify_store_capabilities(_transient_profile(), evidence)
    assert report.status is store_configuration.StoreCapabilityStatus.UNSUPPORTED
    expected = {
        "versioning": store_configuration.StoreCapabilityReason.VERSIONING_REQUIRED,
        "conditional_create": store_configuration.StoreCapabilityReason.CONDITIONAL_CREATE_REQUIRED,
        "conditional_update": store_configuration.StoreCapabilityReason.CONDITIONAL_UPDATE_REQUIRED,
        "current": store_configuration.StoreCapabilityReason.CURRENT_RETENTION_MISMATCH,
        "noncurrent": store_configuration.StoreCapabilityReason.NONCURRENT_RETENTION_MISMATCH,
    }[reason]
    assert report.reasons == (expected,)

    exact = store_configuration.verify_store_capabilities(
        _transient_profile(),
        store_configuration.StoreCapabilityEvidence(store_configuration.StorePurpose.TRANSIENT, True, True, True, 14, 1),
    )
    assert exact.status is store_configuration.StoreCapabilityStatus.READY
    assert exact.reasons == ()


def test_startup_blocks_missing_unsupported_and_colliding_configuration_with_closed_reports() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    ready = store_configuration.assess_store_startup(_environ(), _evidence())
    assert ready.status is store_configuration.StoreStartupStatus.READY
    assert ready.reasons == ()
    assert [item.status for item in ready.capabilities] == [
        store_configuration.StoreCapabilityStatus.READY,
        store_configuration.StoreCapabilityStatus.READY,
    ]
    store_configuration.require_store_startup(ready)

    missing = store_configuration.assess_store_startup({}, _evidence())
    assert missing.status is store_configuration.StoreStartupStatus.MISSING_CONFIGURATION
    with pytest.raises(store_configuration.StoreStartupError) as refused:
        store_configuration.require_store_startup(missing)
    rendered = store_configuration.canonical_startup_report_bytes(refused.value.report)
    assert b"invalid:9000" not in rendered
    assert b"SECRET-SECRET" not in rendered
    assert b"ACCESS-SECRET" not in rendered

    weakened = replace(_evidence()[store_configuration.StorePurpose.TRANSIENT], conditional_update=False)
    unsupported = store_configuration.assess_store_startup(
        _environ(), {**_evidence(), store_configuration.StorePurpose.TRANSIENT: weakened}
    )
    assert unsupported.status is store_configuration.StoreStartupStatus.UNSUPPORTED_CAPABILITY
    assert unsupported.reasons == (store_configuration.StoreStartupReason.TRANSIENT_CAPABILITY_UNSUPPORTED,)

    colliding = dict(_environ())
    for key in colliding:
        if key.startswith("VALID_BENCHMARK_TRANSIENT_"):
            colliding[key] = _environ()[key.replace("TRANSIENT", "DURABLE")]
    collision = store_configuration.assess_store_startup(colliding, _evidence())
    assert collision.status is store_configuration.StoreStartupStatus.MISSING_CONFIGURATION
    assert store_configuration.StoreStartupReason.PURPOSE_CONFIGURATION_COLLISION in collision.reasons


def test_administrator_owned_operations_are_denied_to_the_application_identity() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    for operation in store_configuration.ADMINISTRATOR_OPERATIONS:
        with pytest.raises(store_configuration.StoreAuthorityError):
            store_configuration.require_application_operation(operation)
    for operation in (
        store_configuration.ApplicationStoreOperation.READ_OBJECT,
        store_configuration.ApplicationStoreOperation.CREATE_OBJECT_IF_ABSENT,
        store_configuration.ApplicationStoreOperation.CONDITIONAL_UPDATE,
        store_configuration.ApplicationStoreOperation.LIST_OBJECTS,
    ):
        assert store_configuration.require_application_operation(operation) is None


def test_operator_entry_point_gates_commands_on_settings_and_capabilities() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    configuration = run.validated_operator_configuration(_environ(), _evidence())
    assert configuration.durable.purpose is store_configuration.StorePurpose.DURABLE
    assert configuration.transient.purpose is store_configuration.StorePurpose.TRANSIENT

    weakened = replace(_evidence()[store_configuration.StorePurpose.TRANSIENT], versioning_enabled=False)
    with pytest.raises(run.OperatorCommandError) as unsupported:
        run.validated_operator_configuration(_environ(), {**_evidence(), store_configuration.StorePurpose.TRANSIENT: weakened})
    assert unsupported.value.reason is run.OperatorCommandReason.CAPABILITIES_UNSUPPORTED

    with pytest.raises(run.OperatorCommandError) as missing:
        run.validated_operator_configuration({}, _evidence())
    assert missing.value.reason is run.OperatorCommandReason.SETTINGS_INVALID


# ---------------------------------------------------------------------------
# Artifact repository: create-only persistence and strict reads
# ---------------------------------------------------------------------------


def test_create_only_round_trip_proves_nonzero_readability_and_conditional_put() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    assert content

    assert service.put_if_absent(content, reference=reference) == reference
    accepted = service.get(
        reference,
        expected_kind=reference.artifact_kind,
        authority=_authority(artifact_repository.ArtifactActorRole.DETECTOR),
        expected_access_policy_digest=_READ_POLICY,
    )
    assert accepted.content == content
    assert accepted.reference == reference

    artifact_puts = [
        request
        for request in client.put_requests
        if str(request["Key"]) == artifact_repository.artifact_object_location(_durable_settings(), reference).key
    ]
    assert artifact_puts
    assert all(request.get("IfNoneMatch") == "*" for request in artifact_puts)
    location = artifact_repository.artifact_object_location(_durable_settings(), reference)
    assert location.purpose is store_configuration.StorePurpose.DURABLE
    assert location.key == f"populations/public/{reference.content_digest}.json"


def test_create_only_conflict_preserves_prior_bytes_and_equal_bytes_stay_idempotent() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    location = artifact_repository.artifact_object_location(_durable_settings(), reference)
    prior = b"different-existing-authority-bytes"
    client.raw_put(location.bucket, location.key, prior)

    with pytest.raises(artifact_repository.ArtifactRepositoryConflict) as conflict:
        service.put_if_absent(content, reference=reference)
    assert conflict.value.reason is artifact_repository.ArtifactRepositoryReason.IDENTITY_CONFLICT
    assert client.body_of(location.bucket, location.key) == prior

    client.raw_put(location.bucket, location.key, content)
    assert service.put_if_absent(content, reference=reference) == reference
    assert client.body_of(location.bucket, location.key) == content


@pytest.mark.parametrize("mutation", ("kind", "digest", "length", "provenance", "access"))
def test_wrong_kind_or_digest_reads_are_refused(mutation: str) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    service.put_if_absent(content, reference=reference)
    expected_kind = reference.artifact_kind
    changed = reference
    if mutation == "kind":
        expected_kind = ArtifactKind.REPORT
    elif mutation == "digest":
        changed = replace(reference, content_digest=_digest("wrong-content"))
    elif mutation == "length":
        changed = replace(reference, byte_length=reference.byte_length + 1)
    elif mutation == "provenance":
        changed = replace(reference, provenance_digest=_digest("wrong-provenance"))
    else:
        changed = replace(reference, access_class=ArtifactAccessClass.PRIVATE)

    with pytest.raises(artifact_repository.ArtifactRepositoryError):
        service.get(
            changed,
            expected_kind=expected_kind,
            authority=_custodian_authority(),
            expected_access_policy_digest=_READ_POLICY,
        )


@pytest.mark.parametrize(
    ("access", "role", "permissions"),
    (
        (ArtifactAccessClass.PRIVATE, artifact_repository.ArtifactActorRole.DETECTOR, ()),
        (ArtifactAccessClass.PRIVATE, artifact_repository.ArtifactActorRole.CUSTODIAN, ()),
        (ArtifactAccessClass.CUSTODIAN_SEALED, artifact_repository.ArtifactActorRole.OPERATOR, ()),
        (ArtifactAccessClass.CUSTODIAN_SEALED, artifact_repository.ArtifactActorRole.CUSTODIAN, ()),
        (
            ArtifactAccessClass.PRIVATE,
            artifact_repository.ArtifactActorRole.OPERATOR,
            (artifact_repository.ArtifactReadPermission.CUSTODIAN_SEALED,),
        ),
        (ArtifactAccessClass.OPERATOR_SAFE, artifact_repository.ArtifactActorRole.DETECTOR, ()),
        (
            ArtifactAccessClass.OPERATOR_SAFE,
            artifact_repository.ArtifactActorRole.CUSTODIAN,
            (artifact_repository.ArtifactReadPermission.PRIVATE,),
        ),
    ),
)
def test_unauthorized_access_class_reads_fail_before_any_fetch(
    access: ArtifactAccessClass,
    role: artifact_repository.ArtifactActorRole,
    permissions: tuple[artifact_repository.ArtifactReadPermission, ...],
) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact(access=access)
    service.put_if_absent(content, reference=reference)
    client.operations.clear()

    with pytest.raises(artifact_repository.ArtifactRepositoryError) as denied:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(role, permissions),
            expected_access_policy_digest=_READ_POLICY,
        )
    assert denied.value.reason is artifact_repository.ArtifactRepositoryReason.NOT_AUTHORIZED
    assert client.operations == []
    assert content.decode() not in str(denied.value)


@pytest.mark.parametrize(
    ("access", "role", "permission"),
    (
        (ArtifactAccessClass.PUBLIC, artifact_repository.ArtifactActorRole.DETECTOR, None),
        (ArtifactAccessClass.PRIVATE, artifact_repository.ArtifactActorRole.CUSTODIAN, artifact_repository.ArtifactReadPermission.PRIVATE),
        (
            ArtifactAccessClass.CUSTODIAN_SEALED,
            artifact_repository.ArtifactActorRole.CUSTODIAN,
            artifact_repository.ArtifactReadPermission.CUSTODIAN_SEALED,
        ),
        (ArtifactAccessClass.OPERATOR_SAFE, artifact_repository.ArtifactActorRole.OPERATOR, None),
        (ArtifactAccessClass.OPERATOR_SAFE, artifact_repository.ArtifactActorRole.PRESENTER, None),
    ),
)
def test_access_classes_allow_exactly_their_roles_and_permissions(
    access: ArtifactAccessClass,
    role: artifact_repository.ArtifactActorRole,
    permission: artifact_repository.ArtifactReadPermission | None,
) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact(access=access)
    service.put_if_absent(content, reference=reference)
    permissions = () if permission is None else (permission,)

    accepted = service.get(
        reference,
        expected_kind=reference.artifact_kind,
        authority=_authority(role, permissions),
        expected_access_policy_digest=_READ_POLICY,
    )
    assert accepted.content == content


def test_policy_mismatch_and_tampered_authority_fail_before_fetch() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    service.put_if_absent(content, reference=reference)
    client.operations.clear()

    with pytest.raises(artifact_repository.ArtifactRepositoryError) as mismatch:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(artifact_repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_digest("wrong-policy"),
        )
    assert mismatch.value.reason is artifact_repository.ArtifactRepositoryReason.POLICY_MISMATCH
    assert client.operations == []

    tampered = replace(
        _authority(artifact_repository.ArtifactActorRole.DETECTOR), actor_role=artifact_repository.ArtifactActorRole.OPERATOR
    )
    with pytest.raises(artifact_repository.ArtifactRepositoryError) as forged:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=tampered,
            expected_access_policy_digest=_READ_POLICY,
        )
    assert forged.value.reason is artifact_repository.ArtifactRepositoryReason.NOT_AUTHORIZED
    assert client.operations == []


@pytest.mark.parametrize(
    ("mode", "reason"),
    (
        ("empty", artifact_repository.ArtifactRepositoryReason.EMPTY_OBJECT),
        ("malformed", artifact_repository.ArtifactRepositoryReason.INVALID_OBJECT),
        ("length", artifact_repository.ArtifactRepositoryReason.STORE_FAILURE),
        ("transport", artifact_repository.ArtifactRepositoryReason.STORE_FAILURE),
    ),
)
def test_unreadable_objects_are_closed_instrument_failures_never_clean(
    mode: str, reason: artifact_repository.ArtifactRepositoryReason
) -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    service.put_if_absent(content, reference=reference)
    if mode == "empty":
        client.read_override = b""
    elif mode == "malformed":
        client.read_override = b"not-canonical-json"
    elif mode == "length":
        client.length_override = len(content) + 1
    else:
        client.provider_failure = True

    with pytest.raises(artifact_repository.ArtifactRepositoryError) as caught:
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(artifact_repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_READ_POLICY,
        )
    assert caught.value.reason is reason
    assert "password" not in str(caught.value)
    assert "/home/" not in str(caught.value)


def test_successful_create_requires_exact_nonzero_readback() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, reference = _artifact()
    client.read_override = b""

    with pytest.raises(artifact_repository.ArtifactRepositoryError) as empty:
        service.put_if_absent(content, reference=reference)
    assert empty.value.reason is artifact_repository.ArtifactRepositoryReason.EMPTY_OBJECT

    wrong_reference = replace(reference, byte_length=reference.byte_length + 1)
    with pytest.raises(artifact_repository.ArtifactRepositoryError) as invalid:
        _repo(_RecordingClient()).put_if_absent(content, reference=wrong_reference)
    assert invalid.value.reason is artifact_repository.ArtifactRepositoryReason.INVALID_OBJECT


# ---------------------------------------------------------------------------
# Durable custody: capability gate, conditional writes, races, restart
# ---------------------------------------------------------------------------


def test_real_population_admission_needs_every_mandatory_probe_and_nonzero_input() -> None:
    policy, available, _ = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    ready = _capability_report()
    assert ready.status.value == "ready"  # type: ignore[attr-defined]
    assert ready.input_bytes_read == 16  # type: ignore[attr-defined]
    assert _custody_store(client, policy, ready).initialize(available) is True

    zero_input = _capability_report(input_bytes_read=0)
    with pytest.raises(DurableCustodyStoreError) as unread:
        _custody_store(client, policy, zero_input)
    assert unread.value.reason is DurableCustodyReason.CAPABILITY_DISABLED

    failed_update = (failed_result(ProbeResultName.CONDITIONAL_UPDATE, ProbeResultReason.CONDITIONAL_UPDATE_UNSUPPORTED),)
    partial = tuple(passed_result(name) for name in MANDATORY_PROBE_RESULTS[:6])
    unsupported = _capability_report(results=failed_update + partial)
    with pytest.raises(DurableCustodyStoreError) as failed:
        _custody_store(client, policy, unsupported)
    assert failed.value.reason is DurableCustodyReason.CAPABILITY_DISABLED

    expiry_pending = (
        ProbeResult(ProbeResultName.CURRENT_EXPIRY, ProbeResultStatus.PENDING, ProbeResultReason.DEADLINE_PENDING),
        ProbeResult(ProbeResultName.NONCURRENT_EXPIRY, ProbeResultStatus.PENDING, ProbeResultReason.DEADLINE_PENDING),
    )
    before_deadline = _capability_report(results=partial + expiry_pending)
    assert before_deadline.status.value == "pending"  # type: ignore[attr-defined]
    with pytest.raises(DurableCustodyStoreError) as pending:
        _custody_store(client, policy, before_deadline)
    assert pending.value.reason is DurableCustodyReason.CAPABILITY_DISABLED

    wrong_profile = _capability_report(
        profile=store_configuration.RetentionProfile(store_configuration.StorePurpose.TRANSIENT, True, True, True, 7, 1)
    )
    with pytest.raises(DurableCustodyStoreError) as profile_refused:
        _custody_store(client, policy, wrong_profile)
    assert profile_refused.value.reason is DurableCustodyReason.CAPABILITY_DISABLED

    foreign_stores = _capability_report(
        durable_settings=store_configuration.StoreSettings(
            store_configuration.StorePurpose.DURABLE, "https://other-durable.invalid:9000", "other-bucket", "A", "S"
        )
    )
    with pytest.raises(DurableCustodyStoreError) as foreign:
        _custody_store(client, policy, foreign_stores)
    assert foreign.value.reason is DurableCustodyReason.CAPABILITY_DISABLED


def test_conditional_create_update_and_committed_reread_round_trip() -> None:
    policy, available, spent = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    store = _custody_store(client, policy)
    label_reads = 0

    assert store.initialize(available) is True
    label_reads += 1
    head_key = f"custody/{available.population_digest}/head.json"
    head_writes = [request for request in client.put_requests if str(request["Key"]) == head_key]
    assert len(head_writes) == 1
    assert head_writes[0].get("IfNoneMatch") == "*"
    assert "IfMatch" not in head_writes[0]

    assert store.compare_and_swap(available.log_digest, spent) is True
    label_reads += 1
    assert label_reads == 2
    head_writes = [request for request in client.put_requests if str(request["Key"]) == head_key]
    assert len(head_writes) == 2
    assert head_writes[1].get("IfMatch") not in (None, "", available.log_digest, spent.log_digest)
    assert "IfNoneMatch" not in head_writes[1]

    assert store.current_log(available.population_digest) == spent
    event_key = f"custody/{available.population_digest}/events/{spent.log_digest}.json"
    assert client.body_of(_durable_settings().bucket, event_key) == canonical_population_custody_log_bytes(spent)


def test_version_and_token_advance_is_proven_before_success_ambiguity_blocks_labels() -> None:
    policy, available, spent = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    silent = _RecordingClient()
    silent.missing_version = True
    with pytest.raises(DurableCustodyStoreError) as missing:
        _custody_store(silent, policy).initialize(available)
    assert missing.value.reason is DurableCustodyReason.UNREADABLE_RESPONSE

    aliased = _RecordingClient()
    aliased.fixed_version_id = "constant-version"
    store = _custody_store(aliased, policy)
    assert store.initialize(available) is True
    with pytest.raises(DurableCustodyStoreError) as unreadable:
        store.compare_and_swap(available.log_digest, spent)
    assert unreadable.value.reason is DurableCustodyReason.UNREADABLE_RESPONSE

    constant = _RecordingClient()
    constant.constant_etag = True
    racing = _custody_store(constant, policy)
    assert racing.initialize(available) is True
    constant.head_write_barrier = threading.Barrier(2)
    label_reads = 0
    lock = threading.Lock()

    def attempt() -> object:
        nonlocal label_reads
        try:
            committed = racing.compare_and_swap(available.log_digest, spent)
        except DurableCustodyStoreError as error:
            return error
        if committed:
            with lock:
                label_reads += 1
        return committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: attempt(), range(2)))

    assert not any(outcome is True for outcome in outcomes)
    assert all(
        isinstance(outcome, DurableCustodyStoreError) and outcome.reason is DurableCustodyReason.UNREADABLE_RESPONSE for outcome in outcomes
    )
    assert label_reads == 0


def test_concurrent_spend_attempts_have_exactly_one_winner() -> None:
    policy, available, spent = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    store = _custody_store(client, policy)
    assert store.initialize(available) is True
    label_reads = 0
    lock = threading.Lock()

    def attempt() -> bool:
        nonlocal label_reads
        committed = store.compare_and_swap(available.log_digest, spent)
        if committed:
            with lock:
                label_reads += 1
        return committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == [False, True]
    assert label_reads == 1
    assert store.current_log(available.population_digest) == spent


def test_stale_expected_digests_conflicts_and_restoration_are_refused() -> None:
    policy, available, spent = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    store = _custody_store(client, policy)
    assert store.initialize(available) is True

    assert store.compare_and_swap("0" * 64, spent) is False
    assert store.current_log(available.population_digest) == available

    client.force_head_conflict = True
    assert store.compare_and_swap(available.log_digest, spent) is False
    client.force_head_conflict = False
    assert store.current_log(available.population_digest) == available

    with pytest.raises(DurableCustodyStoreError) as non_direct:
        store.compare_and_swap(available.log_digest, available)
    assert non_direct.value.reason is DurableCustodyReason.INVALID_SUCCESSOR

    assert store.compare_and_swap(available.log_digest, spent) is True
    with pytest.raises(DurableCustodyStoreError) as restore:
        store.compare_and_swap(spent.log_digest, available)
    assert restore.value.reason is DurableCustodyReason.INVALID_SUCCESSOR
    assert store.current_log(available.population_digest) == spent


def test_restart_recovers_the_spent_log_and_versions_stay_visible() -> None:
    policy, available, spent = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    store = _custody_store(client, policy)
    assert store.initialize(available) is True
    head_key = f"custody/{available.population_digest}/head.json"
    prior_version = client.versions_of(_durable_settings().bucket, head_key)[0]
    assert store.compare_and_swap(available.log_digest, spent) is True

    restarted = _custody_store(client, policy)
    assert restarted.current_log(available.population_digest) == spent

    current = client.get_object(Bucket=_durable_settings().bucket, Key=head_key)
    prior = client.get_object(Bucket=_durable_settings().bucket, Key=head_key, VersionId=prior_version.version_id)
    current_body, prior_body = current["Body"], prior["Body"]
    assert isinstance(current_body, io.BytesIO) and isinstance(prior_body, io.BytesIO)
    assert current_body.read() == canonical_population_custody_log_bytes(spent)
    assert prior_body.read() == canonical_population_custody_log_bytes(available)
    assert prior["VersionId"] != current["VersionId"]


def test_write_committed_but_corrupt_reread_fails_closed_without_labels() -> None:
    policy, available, _ = _policy_and_logs()
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    client.corrupt_reads = True

    with pytest.raises(DurableCustodyStoreError) as corrupt:
        _custody_store(client, policy).initialize(available)
    assert corrupt.value.reason is DurableCustodyReason.INVALID_LOG
    event_key = f"custody/{available.population_digest}/events/{available.log_digest}.json"
    assert client.versions_of(_durable_settings().bucket, event_key), "the event write committed before the reread gate"

    client.corrupt_reads = False
    assert _custody_store(client, policy).initialize(available) is True


# ---------------------------------------------------------------------------
# Workflow journal: transient namespace, leases, restart, chain integrity
# ---------------------------------------------------------------------------


def test_journal_accepts_only_transient_purpose_settings() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0

    with pytest.raises(workflow_journal.WorkflowJournalError) as wrong_purpose:
        workflow_journal.S3WorkflowJournal(_durable_settings(), client)
    assert wrong_purpose.value.reason is workflow_journal.WorkflowJournalReason.INVALID_REQUEST


def test_journal_head_preserves_the_selected_authority_and_successor_rules() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0
    journal, head = _started_journal(client)
    selected = head.retry_authority_ref

    successor = _appended(journal, head, 1)
    assert successor.retry_authority_ref == selected
    assert successor.retry_authority_digest == head.retry_authority_digest

    entry = _entry(
        sequence=2,
        previous_entry_digest=successor.entry_digest,
        heartbeat_at=_at(2),
        lease_expires_at=_at(32),
    )
    substituted_authority = _authority_reference("substituted-authority")
    substituted = workflow_journal.WorkflowHeadV1(
        successor.workflow_digest,
        entry.sequence,
        entry.entry_digest,
        entry.lease_owner_id,
        entry.lease_expires_at,
        substituted_authority,
        substituted_authority.content_digest,
        "",
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as substituted_refusal:
        journal.append_and_swap(successor.head_digest, entry, substituted)
    assert substituted_refusal.value.reason is workflow_journal.WorkflowJournalReason.AUTHORITY_SUBSTITUTED

    stale_owner = _entry(
        sequence=2,
        previous_entry_digest=successor.entry_digest,
        lease_owner_id="owner-b",
        heartbeat_at=_at(2),
        lease_expires_at=_at(32),
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as owner_refusal:
        journal.append_and_swap(successor.head_digest, stale_owner, workflow_journal.successor_head(successor, stale_owner))
    assert owner_refusal.value.reason is workflow_journal.WorkflowJournalReason.LEASE_OWNER_MISMATCH

    expired_heartbeat = _entry(
        sequence=2,
        previous_entry_digest=successor.entry_digest,
        heartbeat_at=successor.lease_expires_at,
        lease_expires_at=_at(60),
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as expired_refusal:
        journal.append_and_swap(successor.head_digest, expired_heartbeat, workflow_journal.successor_head(successor, expired_heartbeat))
    assert expired_refusal.value.reason is workflow_journal.WorkflowJournalReason.LEASE_EXPIRED


def test_concurrent_journal_appends_have_exactly_one_winner() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0
    journal, head = _started_journal(client)
    entry = _entry(
        sequence=1,
        previous_entry_digest=head.entry_digest,
        heartbeat_at=_at(1),
        lease_expires_at=_at(31),
    )
    successor = workflow_journal.successor_head(head, entry)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: journal.append_and_swap(head.head_digest, entry, successor), range(2)))

    assert sorted(outcomes) == [False, True]
    assert journal.current_head(_workflow_digest()).head_digest == successor.head_digest


def test_restart_rebuild_ignores_orphans_and_detects_broken_chains() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0
    journal, head = _started_journal(client)
    successor = _appended(journal, head, 1)

    orphan = _entry(sequence=7, previous_entry_digest=_digest("orphan-predecessor"))
    client.raw_put(
        _transient_settings().bucket,
        workflow_journal.workflow_entry_key(_workflow_digest(), orphan.entry_digest),
        workflow_journal.journal_entry_bytes(orphan),
    )

    restarted = workflow_journal.S3WorkflowJournal(_transient_settings(), client)
    status = restarted.rebuild_status(_workflow_digest(), _at(2))
    assert status.chain_length == 2
    assert status.head.head_digest == successor.head_digest

    client.drop(
        _transient_settings().bucket,
        workflow_journal.workflow_entry_key(_workflow_digest(), head.entry_digest),
    )
    with pytest.raises(workflow_journal.WorkflowJournalError) as broken:
        restarted.rebuild_status(_workflow_digest(), _at(2))
    assert broken.value.reason is workflow_journal.WorkflowJournalReason.CHAIN_BROKEN


def test_expired_lease_projects_impaired_stalled_only_from_the_validated_head() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0
    journal, head = _started_journal(client)
    successor = _appended(journal, head, 1)
    assert successor.lease_expires_at == _at(31)

    live = journal.rebuild_status(_workflow_digest(), _at(30))
    assert live.lease_expired is False
    assert live.projected_status is None
    assert live.projected_reason is None

    expired = journal.rebuild_status(_workflow_digest(), _at(31))
    assert expired.lease_expired is True
    assert expired.projected_status is WorkflowStatus.IMPAIRED
    assert expired.projected_reason is WorkflowReasonCode.STALLED


# ---------------------------------------------------------------------------
# Artifact recovery: complete scratch loss and authority refusals
# ---------------------------------------------------------------------------


def _population_projection(
    client: _RecordingClient, *, expires_at_epoch: int | None = None
) -> tuple[bytes, ArtifactReference, tuple[ArtifactReference, ...], str]:
    service = _repo(client)
    members: list[ArtifactReference] = []
    for access in (
        ArtifactAccessClass.PUBLIC,
        ArtifactAccessClass.PRIVATE,
        ArtifactAccessClass.CUSTODIAN_SEALED,
    ):
        content, reference = _artifact(access=access, seed=f"member-{access.value}")
        assert service.put_if_absent(content, reference=reference) == reference
        members.append(reference)
    authority_digest = _digest("population-authority")
    root, root_content, root_reference = artifact_recovery.build_durable_projection_root(
        artifact_recovery.ProjectionFamily.POPULATION,
        tuple(members),
        authority_digest=authority_digest,
        expires_at_epoch=expires_at_epoch,
    )
    assert service.put_if_absent(root_content, reference=root_reference) == root_reference
    return root_content, root_reference, tuple(members), authority_digest


def test_complete_scratch_loss_recovers_the_exact_projection_and_decision() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    _, root_reference, members, authority_digest = _population_projection(client)

    first = artifact_recovery.recover_durable_projection(
        _repo(client),
        expected_family=artifact_recovery.ProjectionFamily.POPULATION,
        root_reference=root_reference,
        authority=_custodian_authority(),
        expected_access_policy_digest=_READ_POLICY,
        expected_authority_digest=authority_digest,
        current_epoch=1,
    )
    second = artifact_recovery.recover_durable_projection(
        _repo(client),
        expected_family=artifact_recovery.ProjectionFamily.POPULATION,
        root_reference=root_reference,
        authority=_custodian_authority(),
        expected_access_policy_digest=_READ_POLICY,
        expected_authority_digest=authority_digest,
        current_epoch=2,
    )
    assert tuple(item.reference for item in first.members) == members
    assert tuple(item.reference for item in second.members) == members
    assert first.decision_digest == second.decision_digest
    assert all(item.content for item in first.members)


def test_recovery_refuses_expired_wrong_missing_and_forged_authorities() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0

    _, expired_root, _, _ = _population_projection(client, expires_at_epoch=50)

    with pytest.raises(artifact_recovery.ArtifactRecoveryError) as expired:
        artifact_recovery.recover_durable_projection(
            _repo(client),
            expected_family=artifact_recovery.ProjectionFamily.POPULATION,
            root_reference=expired_root,
            authority=_custodian_authority(),
            expected_access_policy_digest=_READ_POLICY,
            expected_authority_digest=_digest("population-authority"),
            current_epoch=50,
        )
    assert expired.value.reason is artifact_recovery.ArtifactRecoveryReason.EXPIRED_AUTHORITY

    fresh_content, fresh_root, _, authority_digest = _population_projection(client)
    with pytest.raises(artifact_recovery.ArtifactRecoveryError) as wrong_authority:
        artifact_recovery.recover_durable_projection(
            _repo(client),
            expected_family=artifact_recovery.ProjectionFamily.POPULATION,
            root_reference=fresh_root,
            authority=_custodian_authority(),
            expected_access_policy_digest=_READ_POLICY,
            expected_authority_digest=_digest("another-authority"),
            current_epoch=1,
        )
    assert wrong_authority.value.reason is artifact_recovery.ArtifactRecoveryReason.AUTHORITY_MISMATCH

    _, dropped_root, dropped_members, _ = _population_projection(client)
    victim = artifact_repository.artifact_object_location(_durable_settings(), dropped_members[0])
    client.drop(victim.bucket, victim.key)
    with pytest.raises(artifact_recovery.ArtifactRecoveryError) as missing_member:
        artifact_recovery.recover_durable_projection(
            _repo(client),
            expected_family=artifact_recovery.ProjectionFamily.POPULATION,
            root_reference=dropped_root,
            authority=_custodian_authority(),
            expected_access_policy_digest=_READ_POLICY,
            expected_authority_digest=_digest("population-authority"),
            current_epoch=1,
        )
    assert missing_member.value.reason is artifact_recovery.ArtifactRecoveryReason.MISSING_MEMBER

    with pytest.raises(artifact_recovery.ArtifactRecoveryError) as forged:
        artifact_recovery.recover_durable_projection(
            _repo(client),
            expected_family=artifact_recovery.ProjectionFamily.POPULATION,
            root_reference=replace(fresh_root, byte_length=fresh_root.byte_length + 1),
            authority=_custodian_authority(),
            expected_access_policy_digest=_READ_POLICY,
            expected_authority_digest=authority_digest,
            current_epoch=1,
        )
    assert forged.value.reason is artifact_recovery.ArtifactRecoveryReason.INVALID_ROOT

    _, sealed_root, _, _ = _population_projection(client)
    location = artifact_repository.artifact_object_location(_durable_settings(), sealed_root)
    prior = b"latest-value-substitution-attempt"
    client.raw_put(location.bucket, location.key, prior)
    with pytest.raises(artifact_repository.ArtifactRepositoryConflict) as substituted:
        _repo(client).put_if_absent(fresh_content, reference=sealed_root)
    assert substituted.value.reason is artifact_repository.ArtifactRepositoryReason.IDENTITY_CONFLICT
    assert client.body_of(location.bucket, location.key) == prior


def test_sealed_observation_roots_stay_invisible_to_operators() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    service = _repo(client)
    content, member = _artifact(
        kind=ArtifactKind.OBSERVATION,
        access=ArtifactAccessClass.CUSTODIAN_SEALED,
        seed="sealed-observation-member",
    )
    assert service.put_if_absent(content, reference=member) == member
    authority_digest = _digest("observation-authority")
    root, root_content, root_reference = artifact_recovery.build_durable_projection_root(
        artifact_recovery.ProjectionFamily.OBSERVATION,
        (member,),
        authority_digest=authority_digest,
        expires_at_epoch=None,
    )
    assert service.put_if_absent(root_content, reference=root_reference) == root_reference

    recovered = artifact_recovery.recover_durable_projection(
        service,
        expected_family=artifact_recovery.ProjectionFamily.OBSERVATION,
        root_reference=root_reference,
        authority=_custodian_authority(),
        expected_access_policy_digest=_READ_POLICY,
        expected_authority_digest=authority_digest,
        current_epoch=1,
    )
    assert tuple(item.reference for item in recovered.members) == (member,)

    with pytest.raises(artifact_recovery.ArtifactRecoveryError):
        artifact_recovery.recover_durable_projection(
            service,
            expected_family=artifact_recovery.ProjectionFamily.OBSERVATION,
            root_reference=root_reference,
            authority=_authority(artifact_repository.ArtifactActorRole.OPERATOR),
            expected_access_policy_digest=_READ_POLICY,
            expected_authority_digest=authority_digest,
            current_epoch=1,
        )


# ---------------------------------------------------------------------------
# Administrator-owned policy is never mutated by this suite
# ---------------------------------------------------------------------------


def test_full_persistence_flow_never_issues_administrator_operations() -> None:
    client = _RecordingClient()
    assert _prove_store_nonzero(client, _durable_settings().bucket) > 0
    assert _prove_store_nonzero(client, _transient_settings().bucket) > 0

    content, reference = _artifact()
    service = _repo(client)
    assert service.put_if_absent(content, reference=reference) == reference
    assert (
        service.get(
            reference,
            expected_kind=reference.artifact_kind,
            authority=_authority(artifact_repository.ArtifactActorRole.DETECTOR),
            expected_access_policy_digest=_READ_POLICY,
        ).content
        == content
    )

    policy, available, spent = _policy_and_logs()
    store = _custody_store(client, policy)
    assert store.initialize(available) is True
    assert store.compare_and_swap(available.log_digest, spent) is True

    journal, head = _started_journal(client)
    _appended(journal, head, 1)

    _, root_reference, _, authority_digest = _population_projection(client)
    artifact_recovery.recover_durable_projection(
        _repo(client),
        expected_family=artifact_recovery.ProjectionFamily.POPULATION,
        root_reference=root_reference,
        authority=_custodian_authority(),
        expected_access_policy_digest=_READ_POLICY,
        expected_authority_digest=authority_digest,
        current_epoch=1,
    )

    methods = {operation.split(":", 1)[0] for operation in client.operations}
    assert methods <= {"put", "get"}
    allowed_durable = (
        "reservations/",
        "reviews/",
        "lifecycles/",
        "populations/",
        "observations/",
        "workflows/",
        "reports/",
        "replays/",
        "custody/",
        _PROBE_KEY,
    )
    allowed_transient = ("workflow/", _PROBE_KEY)
    for operation in client.operations:
        method, target = operation.split(":", 1)
        bucket, key = target.split("/", 1)
        allowed = allowed_durable if bucket == _durable_settings().bucket else allowed_transient
        assert any(key.startswith(prefix) or key == prefix for prefix in allowed), operation
        assert method in ("put", "get")

    source = Path(__file__).read_text(encoding="ascii")
    forbidden_calls = ("delete_bucket", *(operation.value for operation in store_configuration.ADMINISTRATOR_OPERATIONS))
    for name in forbidden_calls:
        assert f".{name}(" not in source
