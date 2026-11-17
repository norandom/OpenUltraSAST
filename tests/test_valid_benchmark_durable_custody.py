"""Production durable custody compare-and-swap tests."""

from __future__ import annotations

import inspect
import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid.custody_probe_contract import (
    CUSTODY_CAPABILITY_REPORT_SCHEMA,
    MANDATORY_PROBE_RESULTS,
    RETENTION_PROBE_STATE_SCHEMA,
    CustodyCapabilityReport,
    CustodyCapabilityStatus,
    ProbeResult,
    ProbeResultReason,
    ProbeResultStatus,
    RetentionProbeState,
    build_capability_report,
    derive_retention_state_digest,
    passed_result,
)
from benchmarks.valid.durable_custody_store import (
    DurableCustodyReason,
    DurableCustodyStoreError,
    S3DurableCustodyStore,
)
from benchmarks.valid.store_configuration import RetentionProfile, StorePurpose, StoreSettings, store_namespace_identity
from openultrasast.core.canonical import content_digest
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationUseRequest,
    append_population_use,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
    record_population_use,
)


class _ProviderError(Exception):
    def __init__(self, code: str, secret: str = "provider password=/private/path") -> None:
        self.response = {"Error": {"Code": code, "Message": secret}}
        super().__init__(secret)


class _Version:
    def __init__(self, version_id: str, body: bytes, etag: str) -> None:
        self.version_id = version_id
        self.body = body
        self.etag = etag


class _Client:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.values: dict[tuple[str, str], list[_Version]] = {}
        self.requests: list[dict[str, object]] = []
        self.next_version = 1
        self.force_conflict = False
        self.force_head_conflict = False
        self.provider_failure = False
        self.missing_version = False
        self.fixed_version_id: str | None = None
        self.constant_etag = False
        self.head_update_barrier: threading.Barrier | None = None
        self.corrupt_reads = False

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        if self.head_update_barrier is not None and key.endswith("/head.json") and "IfMatch" in kwargs:
            self.head_update_barrier.wait(timeout=5)
        with self.lock:
            self.requests.append(dict(kwargs))
            if self.provider_failure:
                raise _ProviderError("InternalError")
            bucket = str(kwargs["Bucket"])
            versions = self.values.setdefault((bucket, key), [])
            current = versions[-1] if versions else None
            if self.force_conflict or (self.force_head_conflict and key.endswith("/head.json")):
                raise _ProviderError("PreconditionFailed")
            if kwargs.get("IfNoneMatch") == "*" and current is not None:
                raise _ProviderError("PreconditionFailed")
            expected = kwargs.get("IfMatch")
            if expected is not None and (current is None or current.etag != expected):
                raise _ProviderError("PreconditionFailed")
            body = kwargs["Body"]
            assert isinstance(body, bytes) and body
            version_id = self.fixed_version_id if self.fixed_version_id is not None else f"version-{self.next_version}"
            self.next_version += 1
            etag = "constant-etag" if self.constant_etag else sha256(body + version_id.encode()).hexdigest()
            versions.append(_Version(version_id, body, etag))
            response: dict[str, object] = {"ETag": etag}
            if not self.missing_version:
                response["VersionId"] = version_id
            return response

    def get_object(self, **kwargs: object) -> dict[str, object]:
        with self.lock:
            if self.provider_failure:
                raise _ProviderError("InternalError")
            bucket, key = str(kwargs["Bucket"]), str(kwargs["Key"])
            versions = self.values.get((bucket, key), [])
            requested = kwargs.get("VersionId")
            matching = [item for item in versions if requested is None or item.version_id == requested]
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


def _settings(purpose: StorePurpose) -> StoreSettings:
    return StoreSettings(
        purpose,
        f"https://{purpose.value}.invalid:9000",
        f"valid-{purpose.value}",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _profile() -> RetentionProfile:
    return RetentionProfile(StorePurpose.TRANSIENT, True, True, True, 2, 1)


def _report() -> CustodyCapabilityReport:
    durable_identity = store_namespace_identity(_settings(StorePurpose.DURABLE))
    transient_identity = store_namespace_identity(_settings(StorePurpose.TRANSIENT))
    input_digest = content_digest("capability-input")
    draft = RetentionProbeState(
        RETENTION_PROBE_STATE_SCHEMA,
        input_digest,
        16,
        1_000,
        durable_identity,
        transient_identity,
        _settings(StorePurpose.TRANSIENT).bucket,
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
    results = tuple(passed_result(name) for name in MANDATORY_PROBE_RESULTS)
    return build_capability_report(input_digest, 16, _profile(), state, results)


def _policy_and_logs() -> tuple[PopulationCustodyPolicy, PopulationCustodyLog, PopulationCustodyLog]:
    custodian = content_digest("reviewed-custodian")
    policy = PopulationCustodyPolicy((custodian,), derive_population_custody_policy_digest((custodian,)))
    available = empty_population_custody_log(content_digest("population"), custodian)
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


def _store(client: _Client, policy: PopulationCustodyPolicy, report: CustodyCapabilityReport | None = None) -> S3DurableCustodyStore:
    return S3DurableCustodyStore(
        _settings(StorePurpose.DURABLE),
        client,
        policy,
        report or _report(),
        store_namespace_identity(_settings(StorePurpose.TRANSIENT)),
        _profile(),
    )


def test_initial_head_and_spent_successor_round_trip_after_restart() -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    store = _store(client, policy)

    assert store.initialize(available) is True
    assert store.compare_and_swap(available.log_digest, spent) is True
    restarted = _store(client, policy)

    assert restarted.current_log(available.population_digest) == spent
    head_updates = [request for request in client.requests if str(request["Key"]).endswith("/head.json")]
    assert head_updates[0]["IfNoneMatch"] == "*"
    assert head_updates[1]["IfMatch"] != available.log_digest
    assert any("IfMatch" in request for request in client.requests)


def test_concurrent_spend_has_exactly_one_winner() -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    store = _store(client, policy)
    assert store.initialize(available)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: store.compare_and_swap(available.log_digest, spent), range(2)))

    assert sorted(outcomes) == [False, True]
    assert store.current_log(available.population_digest) == spent


def test_constant_storage_token_cannot_authorize_two_callers_or_labels() -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    client.constant_etag = True
    store = _store(client, policy)
    assert store.initialize(available)
    client.head_update_barrier = threading.Barrier(2)
    label_reads = 0
    read_lock = threading.Lock()

    def attempt() -> bool | DurableCustodyStoreError:
        nonlocal label_reads
        try:
            committed = store.compare_and_swap(available.log_digest, spent)
        except DurableCustodyStoreError as error:
            return error
        if committed:
            with read_lock:
                label_reads += 1
        return committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: attempt(), range(2)))

    assert not any(outcome is True for outcome in outcomes)
    assert all(
        isinstance(outcome, DurableCustodyStoreError) and outcome.reason is DurableCustodyReason.UNREADABLE_RESPONSE for outcome in outcomes
    )
    assert label_reads == 0
    assert store.current_log(available.population_digest) == spent


def test_stale_or_provider_conflicted_cas_fails_without_changing_head() -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    store = _store(client, policy)
    assert store.initialize(available)
    assert store.compare_and_swap("0" * 64, spent) is False
    client.force_head_conflict = True
    assert store.compare_and_swap(available.log_digest, spent) is False
    client.force_head_conflict = False
    assert store.current_log(available.population_digest) == available


@pytest.mark.parametrize("operation", ("read", "cas"))
def test_malformed_domain_digest_is_refused_before_store_access(operation: str) -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    store = _store(client, policy)
    with pytest.raises(DurableCustodyStoreError) as invalid:
        if operation == "read":
            store.current_log("../not-a-digest")
        else:
            store.compare_and_swap("not-a-digest", spent)
    assert invalid.value.reason is DurableCustodyReason.INVALID_INPUT
    assert client.requests == []


def test_missing_head_and_missing_write_version_fail_closed() -> None:
    policy, available, _ = _policy_and_logs()
    client = _Client()
    store = _store(client, policy)
    with pytest.raises(DurableCustodyStoreError) as missing:
        store.current_log(available.population_digest)
    assert missing.value.reason is DurableCustodyReason.NOT_FOUND

    client.missing_version = True
    with pytest.raises(DurableCustodyStoreError) as unreadable:
        store.initialize(available)
    assert unreadable.value.reason is DurableCustodyReason.UNREADABLE_RESPONSE


@pytest.mark.parametrize("version_id", ("", "null"))
def test_null_or_empty_write_version_fails_closed(version_id: str) -> None:
    policy, available, _ = _policy_and_logs()
    client = _Client()
    client.fixed_version_id = version_id

    with pytest.raises(DurableCustodyStoreError) as unreadable:
        _store(client, policy).initialize(available)

    assert unreadable.value.reason is DurableCustodyReason.UNREADABLE_RESPONSE


def test_aliased_same_key_successor_version_fails_closed() -> None:
    policy, available, spent = _policy_and_logs()
    client = _Client()
    client.fixed_version_id = "constant-version"
    store = _store(client, policy)
    assert store.initialize(available)

    with pytest.raises(DurableCustodyStoreError) as unreadable:
        store.compare_and_swap(available.log_digest, spent)

    assert unreadable.value.reason is DurableCustodyReason.UNREADABLE_RESPONSE


def test_invalid_non_direct_or_restoring_successors_are_rejected() -> None:
    policy, available, spent = _policy_and_logs()
    store = _store(_Client(), policy)
    assert store.initialize(available)
    with pytest.raises(DurableCustodyStoreError) as non_direct:
        store.compare_and_swap(available.log_digest, available)
    assert non_direct.value.reason is DurableCustodyReason.INVALID_SUCCESSOR
    assert store.compare_and_swap(available.log_digest, spent)
    with pytest.raises(DurableCustodyStoreError) as restore:
        store.compare_and_swap(spent.log_digest, available)
    assert restore.value.reason is DurableCustodyReason.INVALID_SUCCESSOR


def test_ambiguous_readback_and_provider_diagnostics_fail_closed() -> None:
    policy, available, _ = _policy_and_logs()
    client = _Client()
    client.corrupt_reads = True
    with pytest.raises(DurableCustodyStoreError) as mismatch:
        _store(client, policy).initialize(available)
    assert mismatch.value.reason is DurableCustodyReason.INVALID_LOG

    failed = _Client()
    failed.provider_failure = True
    with pytest.raises(DurableCustodyStoreError) as provider:
        _store(failed, policy).initialize(available)
    assert provider.value.reason is DurableCustodyReason.STORE_FAILURE
    assert "password" not in str(provider.value)
    assert "private" not in str(provider.value)
    assert provider.value.__cause__ is None
    assert provider.value.__context__ is None


def test_exact_ready_capability_report_is_required() -> None:
    policy, available, _ = _policy_and_logs()
    changed_result = ProbeResult(
        MANDATORY_PROBE_RESULTS[0],
        ProbeResultStatus.FAILED,
        ProbeResultReason.CONDITIONAL_CREATE_UNSUPPORTED,
    )
    invalid = replace(
        _report(),
        status=CustodyCapabilityStatus.UNSUPPORTED,
        results=(changed_result, *_report().results[1:]),
    )
    with pytest.raises(DurableCustodyStoreError) as disabled:
        _store(_Client(), policy, invalid).initialize(available)
    assert disabled.value.reason is DurableCustodyReason.CAPABILITY_DISABLED


def test_cas_api_cannot_receive_or_read_label_material() -> None:
    parameters = tuple(inspect.signature(S3DurableCustodyStore.compare_and_swap).parameters)
    assert parameters == ("self", "expected_log_digest", "replacement")
    assert "label" not in inspect.getsource(S3DurableCustodyStore.compare_and_swap).lower()


def test_capability_report_fixture_is_canonical_ready() -> None:
    report = _report()
    assert report.schema_version == CUSTODY_CAPABILITY_REPORT_SCHEMA
    assert report.status is CustodyCapabilityStatus.READY
