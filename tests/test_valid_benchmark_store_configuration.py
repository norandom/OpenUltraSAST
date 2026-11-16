"""Store settings, retention, capability, and application-authority contracts."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import store_configuration as store  # noqa: E402


def _environment() -> dict[str, str]:
    return {
        "VALID_BENCHMARK_DURABLE_S3_ENDPOINT": "https://durable.invalid:9000",
        "VALID_BENCHMARK_DURABLE_S3_BUCKET": "valid-benchmark-durable",
        "VALID_BENCHMARK_DURABLE_AWS_ACCESS_KEY_ID": "durable-key",
        "VALID_BENCHMARK_DURABLE_AWS_SECRET_ACCESS_KEY": "durable-secret",
        "VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT": "https://transient.invalid:9000",
        "VALID_BENCHMARK_TRANSIENT_S3_BUCKET": "valid-benchmark-runs",
        "VALID_BENCHMARK_TRANSIENT_AWS_ACCESS_KEY_ID": "transient-key",
        "VALID_BENCHMARK_TRANSIENT_AWS_SECRET_ACCESS_KEY": "transient-secret",
    }


def _evidence(
    purpose: store.StorePurpose,
    *,
    versioning: bool = True,
    conditional_create: bool = True,
    conditional_update: bool = True,
) -> store.StoreCapabilityEvidence:
    current = None if purpose is store.StorePurpose.DURABLE else 14
    noncurrent = 30 if purpose is store.StorePurpose.DURABLE else 1
    return store.StoreCapabilityEvidence(
        purpose=purpose,
        versioning_enabled=versioning,
        conditional_create=conditional_create,
        conditional_update=conditional_update,
        current_version_expiry_days=current,
        noncurrent_version_expiry_days=noncurrent,
    )


def _all_evidence() -> dict[store.StorePurpose, store.StoreCapabilityEvidence]:
    return {purpose: _evidence(purpose) for purpose in store.StorePurpose}


def test_loads_separate_runtime_settings_without_repr_disclosure() -> None:
    environment = {
        **_environment(),
        "VALID_BENCHMARK_DURABLE_S3_REGION": "eu-test-1",
        "VALID_BENCHMARK_DURABLE_AWS_SESSION_TOKEN": "durable-token",
    }

    configuration = store.load_store_configuration(environment)

    assert configuration.durable.bucket == "valid-benchmark-durable"
    assert configuration.durable.region == "eu-test-1"
    assert configuration.durable.session_token == "durable-token"
    assert configuration.transient.bucket == "valid-benchmark-runs"
    displayed = repr(configuration)
    for private_value in (
        "https://durable.invalid:9000",
        "durable-key",
        "durable-secret",
        "durable-token",
        "https://transient.invalid:9000",
        "transient-key",
        "transient-secret",
    ):
        assert private_value not in displayed


def test_direct_load_rejects_a_shared_purpose_namespace_without_disclosure() -> None:
    environment = _environment()
    environment["VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT"] = environment["VALID_BENCHMARK_DURABLE_S3_ENDPOINT"]
    environment["VALID_BENCHMARK_TRANSIENT_S3_BUCKET"] = environment["VALID_BENCHMARK_DURABLE_S3_BUCKET"]

    with pytest.raises(store.StoreConfigurationError) as caught:
        store.load_store_configuration(environment)

    assert caught.value.reason is store.StoreConfigurationReason.INVALID
    assert "purpose_namespace_collision" in str(caught.value)
    for private_value in environment.values():
        assert private_value not in str(caught.value)


@pytest.mark.parametrize(
    "durable_endpoint,transient_endpoint",
    (
        ("HTTPS://STORE.INVALID:9000", "https://store.invalid:9000"),
        ("https://store.invalid", "https://store.invalid:443"),
        ("http://store.invalid", "http://store.invalid:80/"),
        ("https://store.invalid/base", "https://store.invalid/base/"),
        ("https://BÜCHER.invalid", "https://xn--bcher-kva.invalid:443/"),
        ("https://[2001:db8::1]", "https://[2001:0DB8:0:0:0:0:0:1]:443/"),
    ),
)
def test_equivalent_endpoint_spellings_cannot_bypass_purpose_isolation(
    durable_endpoint: str,
    transient_endpoint: str,
) -> None:
    environment = _environment()
    environment["VALID_BENCHMARK_DURABLE_S3_ENDPOINT"] = durable_endpoint
    environment["VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT"] = transient_endpoint
    environment["VALID_BENCHMARK_TRANSIENT_S3_BUCKET"] = environment["VALID_BENCHMARK_DURABLE_S3_BUCKET"]

    with pytest.raises(store.StoreConfigurationError, match="purpose_namespace_collision") as caught:
        store.load_store_configuration(environment)
    report = store.assess_store_startup(environment, _all_evidence())

    assert report.status is store.StoreStartupStatus.MISSING_CONFIGURATION
    assert store.StoreStartupReason.PURPOSE_CONFIGURATION_COLLISION in report.reasons
    encoded = store.canonical_startup_report_bytes(report)
    for private_value in environment.values():
        assert private_value not in str(caught.value)
        assert private_value.encode() not in encoded


@pytest.mark.parametrize(
    "durable_endpoint,transient_endpoint",
    (
        ("https://store.invalid/base", "https://store.invalid/Base"),
        ("https://store.invalid/one/", "https://store.invalid/two/"),
    ),
)
def test_distinct_case_sensitive_endpoint_prefixes_remain_separate(
    durable_endpoint: str,
    transient_endpoint: str,
) -> None:
    environment = _environment()
    environment["VALID_BENCHMARK_DURABLE_S3_ENDPOINT"] = durable_endpoint
    environment["VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT"] = transient_endpoint
    environment["VALID_BENCHMARK_TRANSIENT_S3_BUCKET"] = environment["VALID_BENCHMARK_DURABLE_S3_BUCKET"]

    configuration = store.load_store_configuration(environment)

    assert configuration.durable.endpoint == durable_endpoint
    assert configuration.transient.endpoint == transient_endpoint


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://user@store.invalid",
        "https://store.invalid/base?query=1",
        "https://store.invalid/base#fragment",
        "https://store.invalid:99999",
        "https://host name.invalid",
        "https://[not-an-ipv6-address]",
    ),
)
def test_endpoint_namespace_rejects_ambiguous_or_malformed_urls_without_disclosure(endpoint: str) -> None:
    environment = _environment()
    environment["VALID_BENCHMARK_DURABLE_S3_ENDPOINT"] = endpoint

    with pytest.raises(store.StoreConfigurationError) as caught:
        store.load_store_settings(store.StorePurpose.DURABLE, environment)

    assert caught.value.reason is store.StoreConfigurationReason.INVALID
    assert endpoint not in str(caught.value)


@pytest.mark.parametrize("purpose", tuple(store.StorePurpose))
def test_missing_and_invalid_configuration_name_only_environment_keys(
    purpose: store.StorePurpose,
) -> None:
    environment = _environment()
    missing_key = store.environment_keys(purpose).secret_access_key
    secret = environment.pop(missing_key)

    with pytest.raises(store.StoreConfigurationError) as caught:
        store.load_store_settings(purpose, environment)

    assert caught.value.reason is store.StoreConfigurationReason.MISSING
    assert missing_key in str(caught.value)
    assert secret not in str(caught.value)

    environment[missing_key] = secret
    environment[store.environment_keys(purpose).endpoint] = "host-without-scheme"
    with pytest.raises(store.StoreConfigurationError) as invalid:
        store.load_store_settings(purpose, environment)
    assert invalid.value.reason is store.StoreConfigurationReason.INVALID
    assert "host-without-scheme" not in str(invalid.value)


def test_default_profiles_separate_durable_and_transient_retention() -> None:
    profiles = store.default_retention_profiles(current_expiry_days=14, noncurrent_expiry_days=1)

    durable = profiles[store.StorePurpose.DURABLE]
    transient = profiles[store.StorePurpose.TRANSIENT]
    assert durable.current_version_expiry_days is None
    assert durable.noncurrent_version_expiry_days == 30
    assert transient.current_version_expiry_days == 14
    assert transient.noncurrent_version_expiry_days == 1
    assert all(
        (profile.versioning_required, profile.conditional_create_required, profile.conditional_update_required) == (True, True, True)
        for profile in profiles.values()
    )


@pytest.mark.parametrize(
    "purpose,current,noncurrent",
    (
        ("durable", 1, None),
        ("durable", None, None),
        ("durable", None, 0),
        ("transient", None, 1),
        ("transient", 14, 0),
        ("transient", True, 1),
    ),
)
def test_invalid_retention_profiles_are_refused(
    purpose: str,
    current: int | None,
    noncurrent: int | None,
) -> None:
    with pytest.raises(store.StoreConfigurationError):
        store.RetentionProfile(
            purpose=store.StorePurpose(purpose),
            versioning_required=True,
            conditional_create_required=True,
            conditional_update_required=True,
            current_version_expiry_days=current,
            noncurrent_version_expiry_days=noncurrent,
        )


def test_capability_evidence_requires_closed_boolean_values() -> None:
    with pytest.raises(store.StoreConfigurationError):
        store.StoreCapabilityEvidence(
            purpose=store.StorePurpose.DURABLE,
            versioning_enabled=1,  # type: ignore[arg-type]
            conditional_create=True,
            conditional_update=True,
            current_version_expiry_days=None,
            noncurrent_version_expiry_days=None,
        )


@pytest.mark.parametrize(
    "mutation,reason",
    (
        ({"versioning_enabled": False}, "versioning_required"),
        ({"conditional_create": False}, "conditional_create_required"),
        ({"conditional_update": False}, "conditional_update_required"),
        ({"current_version_expiry_days": 15}, "current_retention_mismatch"),
        ({"noncurrent_version_expiry_days": 2}, "noncurrent_retention_mismatch"),
    ),
)
def test_capability_report_uses_closed_unsupported_reasons(
    mutation: dict[str, object],
    reason: str,
) -> None:
    profiles = store.default_retention_profiles(current_expiry_days=14, noncurrent_expiry_days=1)
    evidence = replace(_evidence(store.StorePurpose.TRANSIENT), **mutation)

    report = store.verify_store_capabilities(profiles[store.StorePurpose.TRANSIENT], evidence)

    assert report.status is store.StoreCapabilityStatus.UNSUPPORTED
    assert store.StoreCapabilityReason(reason) in report.reasons


@pytest.mark.parametrize("noncurrent", (None, 31))
def test_durable_noncurrent_expiry_is_required_and_exact(noncurrent: int | None) -> None:
    profiles = store.default_retention_profiles(current_expiry_days=14, noncurrent_expiry_days=1)
    evidence = replace(
        _evidence(store.StorePurpose.DURABLE),
        noncurrent_version_expiry_days=noncurrent,
    )

    report = store.verify_store_capabilities(profiles[store.StorePurpose.DURABLE], evidence)

    assert report.status is store.StoreCapabilityStatus.UNSUPPORTED
    assert store.StoreCapabilityReason.NONCURRENT_RETENTION_MISMATCH in report.reasons


def test_startup_distinguishes_missing_and_unsupported_from_ready() -> None:
    missing_environment = _environment()
    missing_environment.pop("VALID_BENCHMARK_DURABLE_S3_BUCKET")
    missing = store.assess_store_startup(missing_environment, _all_evidence())
    assert missing.status is store.StoreStartupStatus.MISSING_CONFIGURATION
    assert store.StoreStartupReason.DURABLE_CONFIGURATION_MISSING in missing.reasons

    unsupported_evidence = _all_evidence()
    unsupported_evidence[store.StorePurpose.TRANSIENT] = _evidence(
        store.StorePurpose.TRANSIENT,
        conditional_update=False,
    )
    unsupported = store.assess_store_startup(_environment(), unsupported_evidence)
    assert unsupported.status is store.StoreStartupStatus.UNSUPPORTED_CAPABILITY
    assert store.StoreStartupReason.TRANSIENT_CAPABILITY_UNSUPPORTED in unsupported.reasons

    ready = store.assess_store_startup(_environment(), _all_evidence())
    assert ready.status is store.StoreStartupStatus.READY
    assert ready.reasons == ()


def test_startup_rejects_a_shared_purpose_namespace_with_closed_redacted_reason() -> None:
    environment = _environment()
    environment["VALID_BENCHMARK_TRANSIENT_S3_ENDPOINT"] = environment["VALID_BENCHMARK_DURABLE_S3_ENDPOINT"]
    environment["VALID_BENCHMARK_TRANSIENT_S3_BUCKET"] = environment["VALID_BENCHMARK_DURABLE_S3_BUCKET"]

    report = store.assess_store_startup(environment, _all_evidence())

    assert report.status is store.StoreStartupStatus.MISSING_CONFIGURATION
    assert store.StoreStartupReason.PURPOSE_CONFIGURATION_COLLISION in report.reasons
    encoded = store.canonical_startup_report_bytes(report)
    for private_value in environment.values():
        assert private_value.encode() not in encoded


def test_missing_probe_evidence_is_an_unsupported_prerequisite() -> None:
    evidence = _all_evidence()
    evidence.pop(store.StorePurpose.DURABLE)

    report = store.assess_store_startup(_environment(), evidence)

    assert report.status is store.StoreStartupStatus.UNSUPPORTED_CAPABILITY
    assert store.StoreStartupReason.DURABLE_CAPABILITY_EVIDENCE_MISSING in report.reasons


def test_startup_refusal_carries_only_closed_status_and_reasons() -> None:
    evidence = _all_evidence()
    evidence[store.StorePurpose.DURABLE] = _evidence(store.StorePurpose.DURABLE, versioning=False)
    report = store.assess_store_startup(_environment(), evidence)

    with pytest.raises(store.StoreStartupError) as caught:
        store.require_store_startup(report)

    assert caught.value.report == report
    assert "clean" not in str(caught.value).lower()
    assert "versioning" not in str(caught.value).lower()


def test_safe_startup_artifact_excludes_settings_and_is_deterministic() -> None:
    report = store.assess_store_startup(_environment(), _all_evidence())

    first = store.canonical_startup_report_bytes(report)
    second = store.canonical_startup_report_bytes(report)
    decoded = json.loads(first)

    assert first == second
    assert decoded["status"] == "ready"
    assert tuple(item["purpose"] for item in decoded["capabilities"]) == ("durable", "transient")
    for private_value in _environment().values():
        assert private_value.encode() not in first


def test_application_authority_denies_every_administrator_operation() -> None:
    for operation in store.ApplicationStoreOperation:
        if operation in store.ADMINISTRATOR_OPERATIONS:
            with pytest.raises(store.StoreAuthorityError, match="administrator_owned_operation"):
                store.require_application_operation(operation)
        else:
            store.require_application_operation(operation)


def test_environment_example_lists_names_with_blank_values() -> None:
    example = Path(".env.example").read_text()
    for purpose in store.StorePurpose:
        keys = store.environment_keys(purpose)
        for key in keys.required + keys.optional:
            assert f"{key}=" in example
            assert not next(line for line in example.splitlines() if line.startswith(f"{key}="))[len(key) + 1 :]
