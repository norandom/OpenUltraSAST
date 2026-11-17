"""Durable custody capability and retention probe tests."""

from __future__ import annotations

import io
import json
import sys
import threading
import traceback
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import custody_probe_contract as contract  # noqa: E402
from benchmarks.valid import custody_store as custody  # noqa: E402
from benchmarks.valid.custody_probe_io import ProbeIO  # noqa: E402
from benchmarks.valid.store_configuration import (  # noqa: E402
    RetentionProfile,
    StorePurpose,
    StoreSettings,
    store_namespace_identity,
)


class _ProviderError(Exception):
    def __init__(self, code: str, secret: str = "provider password=/home/private") -> None:
        self.response = {"Error": {"Code": code, "Message": secret}}
        super().__init__(secret)


class _Version:
    def __init__(self, version_id: str, body: bytes, etag: str) -> None:
        self.version_id = version_id
        self.body = body
        self.etag = etag


class _Client:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_version = 1
        self.versions: dict[tuple[str, str], list[_Version]] = {}
        self.hidden_current: set[tuple[str, str]] = set()
        self.calls: list[str] = []
        self.allow_two_winners = False
        self.ignore_if_none_match = False
        self.invalid_read = False
        self.provider_failure = False
        self.fixed_version_id: str | None = None
        self.exact_delete_marker_version_id: str | None = None
        self.version_listing_overrides: dict[str, object] = {}

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("put_object")
        if self.provider_failure:
            raise _ProviderError("InternalError")
        bucket, key = str(kwargs["Bucket"]), str(kwargs["Key"])
        body = kwargs["Body"]
        assert isinstance(body, bytes)
        with self._lock:
            versions = self.versions.setdefault((bucket, key), [])
            current = versions[-1] if versions and (bucket, key) not in self.hidden_current else None
            if kwargs.get("IfNoneMatch") == "*" and current is not None and not self.ignore_if_none_match:
                raise _ProviderError("PreconditionFailed")
            expected = kwargs.get("IfMatch")
            if expected is not None and not self.allow_two_winners:
                if current is None or current.etag != expected:
                    raise _ProviderError("PreconditionFailed")
            version_id = self.fixed_version_id or f"version-{self._next_version}"
            self._next_version += 1
            etag = sha256(body + version_id.encode()).hexdigest()
            versions.append(_Version(version_id, body, etag))
            self.hidden_current.discard((bucket, key))
            return {"VersionId": version_id, "ETag": etag}

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("get_object")
        if self.provider_failure:
            raise _ProviderError("InternalError")
        bucket, key = str(kwargs["Bucket"]), str(kwargs["Key"])
        if (bucket, key) in self.hidden_current:
            raise _ProviderError("NoSuchKey")
        versions = self.versions.get((bucket, key), [])
        requested = kwargs.get("VersionId")
        matching = [item for item in versions if requested is None or item.version_id == requested]
        if not matching:
            raise _ProviderError("NoSuchKey")
        version = matching[-1]
        if self.invalid_read:
            return {"Body": io.BytesIO(b""), "ContentLength": 0}
        return {
            "Body": io.BytesIO(version.body),
            "ContentLength": len(version.body),
            "VersionId": version.version_id,
            "ETag": version.etag,
        }

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("list_object_versions")
        bucket, key = str(kwargs["Bucket"]), str(kwargs["Prefix"])
        versions = self.versions.get((bucket, key), [])
        values = [
            {
                "Key": key,
                "VersionId": item.version_id,
                "ETag": item.etag,
                "Size": len(item.body),
                "IsLatest": index == len(versions) - 1 and (bucket, key) not in self.hidden_current,
            }
            for index, item in enumerate(versions)
        ]
        markers: list[object] = []
        if self.exact_delete_marker_version_id is not None:
            markers.append({"Key": key, "VersionId": self.exact_delete_marker_version_id})
        response: dict[str, object] = {"Versions": values, "DeleteMarkers": markers, "IsTruncated": False}
        response.update(self.version_listing_overrides)
        return response

    def expire_current(self, bucket: str, key: str) -> None:
        self.hidden_current.add((bucket, key))

    def expire_version(self, bucket: str, key: str, version_id: str) -> None:
        versions = self.versions[(bucket, key)]
        self.versions[(bucket, key)] = [item for item in versions if item.version_id != version_id]


def _settings(purpose: StorePurpose) -> StoreSettings:
    suffix = purpose.value
    return StoreSettings(
        purpose,
        f"https://{suffix}.invalid:9000",
        f"valid-benchmark-{suffix}",
        "ACCESS-SECRET",
        "SECRET-SECRET",
    )


def _profile() -> RetentionProfile:
    return RetentionProfile(
        StorePurpose.TRANSIENT,
        versioning_required=True,
        conditional_create_required=True,
        conditional_update_required=True,
        current_version_expiry_days=2,
        noncurrent_version_expiry_days=1,
    )


def _service(durable: _Client, transient: _Client) -> custody.S3CustodyCapabilityProbe:
    return custody.S3CustodyCapabilityProbe(
        _settings(StorePurpose.DURABLE),
        durable,
        _settings(StorePurpose.TRANSIENT),
        transient,
        _profile(),
    )


def _finish_retention(client: _Client, state: contract.RetentionProbeState) -> None:
    client.expire_current(state.transient_bucket, state.current_key)
    client.expire_version(state.transient_bucket, state.noncurrent_key, state.noncurrent_version_id)


def _expected_store_identities() -> tuple[str, str]:
    return (
        store_namespace_identity(_settings(StorePurpose.DURABLE)),
        store_namespace_identity(_settings(StorePurpose.TRANSIENT)),
    )


def test_store_identity_binds_namespace_without_credentials() -> None:
    durable = _settings(StorePurpose.DURABLE)
    rotated = StoreSettings(
        StorePurpose.DURABLE,
        durable.endpoint,
        durable.bucket,
        "ROTATED-ACCESS",
        "ROTATED-SECRET",
    )

    assert store_namespace_identity(durable) == store_namespace_identity(rotated)
    assert durable.access_key_id not in store_namespace_identity(durable)
    assert durable.secret_access_key not in store_namespace_identity(durable)


def test_probe_passes_every_mandatory_result_after_recorded_expiry() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"nonzero-custody-capability-input"
    state = service.prepare_retention_probe(probe_input, current_epoch=1_000)
    pending = service.probe(probe_input, state, current_epoch=1_001)
    _finish_retention(transient, state)

    report = service.probe(
        probe_input,
        state,
        current_epoch=state.current_deadline_epoch,
        prior_report=pending,
    )

    assert report.status is contract.CustodyCapabilityStatus.READY
    assert report.input_bytes_read == len(probe_input)
    assert tuple(result.name for result in report.results) == tuple(contract.MANDATORY_PROBE_RESULTS)
    assert all(result.status is contract.ProbeResultStatus.PASSED for result in report.results)
    assert report.may_admit_real_population is True
    contract.require_real_population_admission(report, *_expected_store_identities(), _profile())
    encoded = contract.canonical_custody_capability_report_bytes(report)
    payload = json.loads(encoded)
    assert payload["schema_version"] == contract.CUSTODY_CAPABILITY_REPORT_SCHEMA
    assert payload["input_bytes_read"] == len(probe_input)
    assert payload["report_digest"] == report.report_digest
    assert set(durable.calls + transient.calls) <= {"put_object", "get_object", "list_object_versions"}


def test_before_deadlines_is_pending_and_cannot_authorize_admission() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"pending-retention-input"
    state = service.prepare_retention_probe(probe_input, current_epoch=2_000)

    report = service.probe(probe_input, state, current_epoch=2_001)

    assert report.status is contract.CustodyCapabilityStatus.PENDING
    retention = {result.name: result for result in report.results}
    assert retention[contract.ProbeResultName.CURRENT_EXPIRY].status is contract.ProbeResultStatus.PENDING
    assert retention[contract.ProbeResultName.NONCURRENT_EXPIRY].status is contract.ProbeResultStatus.PENDING
    assert report.may_admit_real_population is False
    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(report, *_expected_store_identities(), _profile())


@pytest.mark.parametrize("expired", ("current", "noncurrent"))
def test_premature_retention_is_a_failed_measurement(expired: str) -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = f"premature-{expired}".encode()
    state = service.prepare_retention_probe(probe_input, current_epoch=3_000)
    if expired == "current":
        transient.expire_current(state.transient_bucket, state.current_key)
    else:
        transient.expire_version(state.transient_bucket, state.noncurrent_key, state.noncurrent_version_id)

    report = service.probe(probe_input, state, current_epoch=3_001)

    assert report.status is contract.CustodyCapabilityStatus.UNSUPPORTED
    result = next(item for item in report.results if item.name.value == f"{expired}_expiry")
    assert result.reason is contract.ProbeResultReason.PREMATURE_EXPIRY
    assert report.may_admit_real_population is False


def test_expiry_deadline_miss_is_failed_not_pending() -> None:
    service = _service(_Client(), _Client())
    probe_input = b"deadline-miss"
    state = service.prepare_retention_probe(probe_input, current_epoch=4_000)
    pending = service.probe(probe_input, state, current_epoch=4_001)

    report = service.probe(probe_input, state, state.current_deadline_epoch, prior_report=pending)

    assert report.status is contract.CustodyCapabilityStatus.UNSUPPORTED
    reasons = {item.reason for item in report.results}
    assert contract.ProbeResultReason.EXPIRY_DEADLINE_MISSED in reasons


def test_two_writer_ambiguity_disables_admission() -> None:
    durable, transient = _Client(), _Client()
    durable.allow_two_winners = True
    service = _service(durable, transient)
    probe_input = b"two-writer-ambiguity"
    state = service.prepare_retention_probe(probe_input, current_epoch=5_000)
    _finish_retention(transient, state)

    report = service.probe(probe_input, state, current_epoch=state.current_deadline_epoch)

    result = next(item for item in report.results if item.name is contract.ProbeResultName.CONCURRENT_SINGLE_WINNER)
    assert result.status is contract.ProbeResultStatus.FAILED
    assert result.reason is contract.ProbeResultReason.CONFLICT_NOT_ENFORCED
    assert report.status is contract.CustodyCapabilityStatus.UNSUPPORTED


def test_ignored_conditional_create_is_detected_and_cannot_authorize() -> None:
    durable, transient = _Client(), _Client()
    durable.ignore_if_none_match = True
    service = _service(durable, transient)
    probe_input = b"ignored-if-none-match"
    state = service.prepare_retention_probe(probe_input, current_epoch=5_500)

    report = service.probe(probe_input, state, current_epoch=5_501)

    result = next(item for item in report.results if item.name is contract.ProbeResultName.CONDITIONAL_CREATE)
    assert result.status is contract.ProbeResultStatus.FAILED
    assert result.reason is contract.ProbeResultReason.CONDITIONAL_CREATE_UNSUPPORTED
    assert report.may_admit_real_population is False


def test_constant_durable_version_id_fails_visibility_and_admission() -> None:
    durable, transient = _Client(), _Client()
    durable.fixed_version_id = "constant-version"
    service = _service(durable, transient)
    probe_input = b"constant-durable-version"
    state = service.prepare_retention_probe(probe_input, current_epoch=5_600)

    report = service.probe(probe_input, state, current_epoch=5_601)

    visibility = next(item for item in report.results if item.name is contract.ProbeResultName.VERSION_VISIBILITY)
    assert visibility.status is contract.ProbeResultStatus.FAILED
    assert report.may_admit_real_population is False


@pytest.mark.parametrize("version_id", ("constant-version", "null"))
def test_transient_version_id_without_real_succession_fails_preparation(version_id: str) -> None:
    transient = _Client()
    transient.fixed_version_id = version_id

    with pytest.raises(contract.CustodyCapabilityError) as caught:
        _service(_Client(), transient).prepare_retention_probe(b"invalid-transient-version", current_epoch=5_650)

    assert caught.value.reason is contract.CustodyProbeErrorReason.UNREADABLE_RESPONSE


def test_final_retention_without_bound_predeadline_presence_cannot_be_ready() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"missing-presence-evidence"
    state = service.prepare_retention_probe(probe_input, current_epoch=5_700)
    _finish_retention(transient, state)

    report = service.probe(probe_input, state, current_epoch=state.current_deadline_epoch)

    assert report.status is contract.CustodyCapabilityStatus.UNSUPPORTED
    retention = report.results[-2:]
    assert all(item.reason is contract.ProbeResultReason.PRESENCE_EVIDENCE_MISSING for item in retention)


@pytest.mark.parametrize(
    "delete_markers",
    (
        [{"Key": "probe-key", "VersionId": "null"}],
        [{"Key": "probe-key", "VersionId": "marker-1"}],
        [{"Key": "wrong-key", "VersionId": "marker-1"}],
        ["malformed-marker"],
    ),
)
def test_version_listing_rejects_every_delete_marker(delete_markers: list[object]) -> None:
    client = _Client()
    client.version_listing_overrides["DeleteMarkers"] = delete_markers

    version_ids, reason = ProbeIO(_settings(StorePurpose.DURABLE), client).version_ids("probe-key")

    assert version_ids is None
    assert reason is contract.ProbeResultReason.UNREADABLE_RESPONSE


@pytest.mark.parametrize(
    "listing_overrides",
    (
        {"IsTruncated": True},
        {"Versions": [{"Key": "wrong-key", "VersionId": "version-1"}]},
        {"Versions": [{"Key": "probe-key", "VersionId": "null"}]},
        {"Versions": ["malformed-version"]},
    ),
)
def test_version_listing_rejects_ambiguous_or_malformed_versions(listing_overrides: dict[str, object]) -> None:
    client = _Client()
    client.version_listing_overrides.update(listing_overrides)

    version_ids, reason = ProbeIO(_settings(StorePurpose.DURABLE), client).version_ids("probe-key")

    assert version_ids is None
    assert reason is contract.ProbeResultReason.UNREADABLE_RESPONSE


def test_null_delete_marker_is_instrument_failure_and_cannot_authorize() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"null-delete-marker"
    state = service.prepare_retention_probe(probe_input, current_epoch=5_800)
    durable.exact_delete_marker_version_id = "null"

    report = service.probe(probe_input, state, current_epoch=5_801)

    assert report.status is contract.CustodyCapabilityStatus.INSTRUMENT_FAILURE
    assert report.may_admit_real_population is False
    assert contract.ProbeResultReason.UNREADABLE_RESPONSE in {item.reason for item in report.results}
    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(report, *_expected_store_identities(), _profile())


def test_unreadable_response_is_instrument_failure_and_diagnostics_are_closed() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"unreadable-response"
    state = service.prepare_retention_probe(probe_input, current_epoch=6_000)
    _finish_retention(transient, state)
    durable.invalid_read = True

    report = service.probe(probe_input, state, current_epoch=state.current_deadline_epoch)

    assert report.status is contract.CustodyCapabilityStatus.INSTRUMENT_FAILURE
    assert contract.ProbeResultReason.UNREADABLE_RESPONSE in {item.reason for item in report.results}
    rendered = repr(report) + str(report)
    assert "password" not in rendered
    assert "/home/private" not in rendered


def test_provider_exceptions_do_not_escape_in_report_or_exception_chain() -> None:
    durable, transient = _Client(), _Client()
    transient.provider_failure = True

    with pytest.raises(contract.CustodyCapabilityError) as caught:
        _service(durable, transient).prepare_retention_probe(b"provider-failure", current_epoch=7_000)

    rendered = "".join(traceback.format_exception(caught.value))
    assert caught.value.reason is contract.CustodyProbeErrorReason.STORE_FAILURE
    assert "password" not in rendered
    assert "/home/private" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("probe_input", (b"", bytearray(b"not-bytes")))
def test_empty_or_invalid_probe_input_fails_before_store_access(probe_input: object) -> None:
    durable, transient = _Client(), _Client()

    with pytest.raises(contract.CustodyCapabilityError) as caught:
        _service(durable, transient).prepare_retention_probe(probe_input, current_epoch=8_000)  # type: ignore[arg-type]

    assert caught.value.reason is contract.CustodyProbeErrorReason.INVALID_INPUT
    assert durable.calls == transient.calls == []


def test_tampered_or_mismatched_retention_state_is_refused() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    state = service.prepare_retention_probe(b"state-binding", current_epoch=9_000)

    with pytest.raises(contract.CustodyCapabilityError) as mismatched:
        service.probe(b"different-input", state, current_epoch=9_001)
    assert mismatched.value.reason is contract.CustodyProbeErrorReason.STATE_MISMATCH

    state.__dict__["current_key"] = "runs/forged/current.json"
    with pytest.raises(contract.CustodyCapabilityError) as tampered:
        service.probe(b"state-binding", state, current_epoch=9_001)
    assert tampered.value.reason is contract.CustodyProbeErrorReason.STATE_MISMATCH


@pytest.mark.parametrize("invalid_versions", ("null", "aliased"))
def test_rehashed_invalid_retention_version_state_is_refused(invalid_versions: str) -> None:
    service = _service(_Client(), _Client())
    probe_input = b"invalid-version-state"
    state = service.prepare_retention_probe(probe_input, current_epoch=9_500)
    if invalid_versions == "null":
        forged = replace(state, noncurrent_version_id="null", state_digest="")
    else:
        forged = replace(state, successor_version_id=state.noncurrent_version_id, state_digest="")
    forged = replace(forged, state_digest=contract.derive_retention_state_digest(forged))

    with pytest.raises(contract.CustodyCapabilityError) as caught:
        service.probe(probe_input, forged, current_epoch=9_501)

    assert caught.value.reason is contract.CustodyProbeErrorReason.STATE_MISMATCH


def test_report_validation_rejects_missing_result_or_forged_digest() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"report-validation"
    state = service.prepare_retention_probe(probe_input, current_epoch=10_000)
    pending = service.probe(probe_input, state, current_epoch=10_001)
    _finish_retention(transient, state)
    report = service.probe(probe_input, state, state.current_deadline_epoch, prior_report=pending)

    report.__dict__["results"] = report.results[:-1]
    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(report, *_expected_store_identities(), _profile())

    clean_report = service.probe(b"second-report-input", service.prepare_retention_probe(b"second-report-input", 20_000), 20_001)
    clean_report.__dict__["report_digest"] = "0" * 64
    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(clean_report, *_expected_store_identities(), _profile())


def test_report_cannot_be_substituted_across_store_namespaces() -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"namespace-binding"
    state = service.prepare_retention_probe(probe_input, current_epoch=30_000)
    pending = service.probe(probe_input, state, current_epoch=30_001)
    _finish_retention(transient, state)
    report = service.probe(probe_input, state, state.current_deadline_epoch, prior_report=pending)
    alternate = StoreSettings(
        StorePurpose.DURABLE,
        "https://other-durable.invalid:9000",
        "other-valid-benchmark-durable",
        "OTHER-ACCESS",
        "OTHER-SECRET",
    )

    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(
            report,
            store_namespace_identity(alternate),
            _expected_store_identities()[1],
            _profile(),
        )


@pytest.mark.parametrize(
    "mismatched_profile",
    (
        replace(_profile(), current_version_expiry_days=3),
        replace(_profile(), noncurrent_version_expiry_days=2),
    ),
)
def test_ready_report_requires_exact_typed_retention_profile(mismatched_profile: RetentionProfile) -> None:
    durable, transient = _Client(), _Client()
    service = _service(durable, transient)
    probe_input = b"retention-policy-binding"
    state = service.prepare_retention_probe(probe_input, current_epoch=40_000)
    pending = service.probe(probe_input, state, current_epoch=40_001)
    _finish_retention(transient, state)
    report = service.probe(probe_input, state, state.current_deadline_epoch, prior_report=pending)

    with pytest.raises(contract.RealPopulationAdmissionDisabled):
        contract.require_real_population_admission(
            report,
            *_expected_store_identities(),
            mismatched_profile,
        )
    contract.require_real_population_admission(report, *_expected_store_identities(), _profile())
