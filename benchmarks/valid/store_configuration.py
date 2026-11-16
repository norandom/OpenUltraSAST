"""Fail-closed store configuration for the replacement valid benchmark.

Runtime endpoints and credentials stay in this module's non-serializable settings
objects. Shared artifacts receive only closed capability status and policy digests.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from urllib.parse import urlsplit

from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes

STORE_STARTUP_REPORT_SCHEMA = "openultrasast.valid-detection-benchmark.store-startup.v1"
DEFAULT_DURABLE_NONCURRENT_EXPIRY_DAYS = 30
_BUCKET_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


class StorePurpose(StrEnum):
    """Purpose-specific stores with independent retention policy."""

    DURABLE = "durable"
    TRANSIENT = "transient"


class StoreConfigurationReason(StrEnum):
    MISSING = "missing"
    INVALID = "invalid"


class StoreCapabilityStatus(StrEnum):
    READY = "ready"
    UNSUPPORTED = "unsupported"


class StoreCapabilityReason(StrEnum):
    VERSIONING_REQUIRED = "versioning_required"
    CONDITIONAL_CREATE_REQUIRED = "conditional_create_required"
    CONDITIONAL_UPDATE_REQUIRED = "conditional_update_required"
    CURRENT_RETENTION_MISMATCH = "current_retention_mismatch"
    NONCURRENT_RETENTION_MISMATCH = "noncurrent_retention_mismatch"


class StoreStartupStatus(StrEnum):
    READY = "ready"
    MISSING_CONFIGURATION = "missing_configuration"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"


class StoreStartupReason(StrEnum):
    DURABLE_CONFIGURATION_MISSING = "durable_configuration_missing"
    DURABLE_CONFIGURATION_INVALID = "durable_configuration_invalid"
    TRANSIENT_CONFIGURATION_MISSING = "transient_configuration_missing"
    TRANSIENT_CONFIGURATION_INVALID = "transient_configuration_invalid"
    PURPOSE_CONFIGURATION_COLLISION = "purpose_configuration_collision"
    DURABLE_CAPABILITY_EVIDENCE_MISSING = "durable_capability_evidence_missing"
    TRANSIENT_CAPABILITY_EVIDENCE_MISSING = "transient_capability_evidence_missing"
    DURABLE_CAPABILITY_UNSUPPORTED = "durable_capability_unsupported"
    TRANSIENT_CAPABILITY_UNSUPPORTED = "transient_capability_unsupported"


class ApplicationStoreOperation(StrEnum):
    READ_OBJECT = "read_object"
    CREATE_OBJECT_IF_ABSENT = "create_object_if_absent"
    CONDITIONAL_UPDATE = "conditional_update"
    LIST_OBJECTS = "list_objects"
    READ_VERSIONING = "read_versioning"
    READ_LIFECYCLE = "read_lifecycle"
    CREATE_BUCKET = "create_bucket"
    SET_BUCKET_VERSIONING = "set_bucket_versioning"
    PUT_LIFECYCLE_POLICY = "put_lifecycle_policy"
    PROVISION_CREDENTIALS = "provision_credentials"
    PROBE_CLUSTER_HEALTH = "probe_cluster_health"


ADMINISTRATOR_OPERATIONS = frozenset(
    {
        ApplicationStoreOperation.CREATE_BUCKET,
        ApplicationStoreOperation.SET_BUCKET_VERSIONING,
        ApplicationStoreOperation.PUT_LIFECYCLE_POLICY,
        ApplicationStoreOperation.PROVISION_CREDENTIALS,
        ApplicationStoreOperation.PROBE_CLUSTER_HEALTH,
    }
)


class StoreConfigurationError(ValueError):
    """Configuration is absent or invalid without disclosing its values."""

    def __init__(self, purpose: StorePurpose, reason: StoreConfigurationReason, keys: tuple[str, ...]) -> None:
        self.purpose = purpose
        self.reason = reason
        self.keys = keys
        super().__init__(f"{purpose.value}_store_configuration_{reason.value}: {','.join(keys)}")


class StoreAuthorityError(PermissionError):
    """An application identity requested an administrator-owned operation."""


class StoreStartupError(RuntimeError):
    """Startup prerequisites failed before benchmark execution."""

    def __init__(self, report: StoreStartupReport) -> None:
        self.report = report
        reasons = ",".join(reason.value for reason in report.reasons)
        super().__init__(f"benchmark_store_startup_refused:{report.status.value}:{reasons}")


@dataclass(frozen=True)
class StoreEnvironmentKeys:
    endpoint: str
    bucket: str
    access_key_id: str
    secret_access_key: str
    region: str
    session_token: str

    @property
    def required(self) -> tuple[str, ...]:
        return (self.endpoint, self.bucket, self.access_key_id, self.secret_access_key)

    @property
    def optional(self) -> tuple[str, ...]:
        return (self.region, self.session_token)


@dataclass(frozen=True)
class StoreSettings:
    purpose: StorePurpose
    endpoint: str = field(repr=False)
    bucket: str
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    region: str | None = field(default=None, repr=False)
    session_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class StoreConfiguration:
    durable: StoreSettings
    transient: StoreSettings


@dataclass(frozen=True)
class RetentionProfile:
    purpose: StorePurpose
    versioning_required: bool
    conditional_create_required: bool
    conditional_update_required: bool
    current_version_expiry_days: int | None
    noncurrent_version_expiry_days: int | None

    def __post_init__(self) -> None:
        requirements = (
            self.versioning_required,
            self.conditional_create_required,
            self.conditional_update_required,
        )
        if any(type(value) is not bool or not value for value in requirements):
            raise StoreConfigurationError(self.purpose, StoreConfigurationReason.INVALID, ("capability_profile",))
        _validate_retention(self.purpose, self.current_version_expiry_days, self.noncurrent_version_expiry_days)


@dataclass(frozen=True)
class StoreCapabilityEvidence:
    purpose: StorePurpose
    versioning_enabled: bool
    conditional_create: bool
    conditional_update: bool
    current_version_expiry_days: int | None
    noncurrent_version_expiry_days: int | None

    def __post_init__(self) -> None:
        capability_flags = (self.versioning_enabled, self.conditional_create, self.conditional_update)
        if any(type(value) is not bool for value in capability_flags):
            raise StoreConfigurationError(self.purpose, StoreConfigurationReason.INVALID, ("capability_evidence",))
        _validate_optional_days(self.current_version_expiry_days, self.purpose)
        _validate_optional_days(self.noncurrent_version_expiry_days, self.purpose)


@dataclass(frozen=True)
class StoreCapabilityReport:
    purpose: StorePurpose
    status: StoreCapabilityStatus
    reasons: tuple[StoreCapabilityReason, ...]
    profile_digest: str


@dataclass(frozen=True)
class StoreStartupReport:
    status: StoreStartupStatus
    reasons: tuple[StoreStartupReason, ...]
    capabilities: tuple[StoreCapabilityReport, ...]


_ENVIRONMENT_KEYS = {
    purpose: StoreEnvironmentKeys(
        *(
            f"VALID_BENCHMARK_{purpose.value.upper()}_{suffix}"
            for suffix in (
                "S3_ENDPOINT",
                "S3_BUCKET",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "S3_REGION",
                "AWS_SESSION_TOKEN",
            )
        )
    )
    for purpose in StorePurpose
}


def environment_keys(purpose: StorePurpose) -> StoreEnvironmentKeys:
    return _ENVIRONMENT_KEYS[StorePurpose(purpose)]


def _hostname_namespace(hostname: str) -> str:
    try:
        return ip_address(hostname).compressed.lower()
    except ValueError:
        pass
    if any(character.isspace() for character in hostname):
        raise ValueError("endpoint hostname is malformed")
    try:
        canonical = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("endpoint hostname is malformed") from error
    labels = canonical.split(".")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    if not labels or any(label_pattern.fullmatch(label) is None for label in labels):
        raise ValueError("endpoint hostname is malformed")
    return canonical


def _endpoint_namespace(value: str) -> tuple[str, str, int, str]:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("endpoint URL is malformed") from error
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or hostname is None:
        raise ValueError("endpoint URL is malformed")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("endpoint URL is ambiguous")
    authority = parsed.netloc.rsplit("@", 1)[-1]
    if authority.endswith(":"):
        raise ValueError("endpoint port is malformed")
    effective_port = port if port is not None else {"http": 80, "https": 443}[scheme]
    path = "" if parsed.path in {"", "/"} else parsed.path.removesuffix("/")
    return (scheme, _hostname_namespace(hostname), effective_port, path)


def load_store_settings(purpose: StorePurpose, environ: Mapping[str, str]) -> StoreSettings:
    """Load one purpose without placing runtime values in an artifact."""
    purpose = StorePurpose(purpose)
    keys = environment_keys(purpose)
    missing = tuple(key for key in keys.required if not environ.get(key, "").strip())
    if missing:
        raise StoreConfigurationError(purpose, StoreConfigurationReason.MISSING, missing)
    endpoint = environ[keys.endpoint].strip()
    bucket = environ[keys.bucket].strip()
    try:
        _endpoint_namespace(endpoint)
        endpoint_is_valid = True
    except ValueError:
        endpoint_is_valid = False
    checks = ((keys.endpoint, endpoint_is_valid), (keys.bucket, bool(_BUCKET_NAME.fullmatch(bucket))))
    invalid = tuple(key for key, is_valid in checks if not is_valid)
    if invalid:
        raise StoreConfigurationError(purpose, StoreConfigurationReason.INVALID, invalid)
    return StoreSettings(
        purpose=purpose,
        endpoint=endpoint,
        bucket=bucket,
        access_key_id=environ[keys.access_key_id].strip(),
        secret_access_key=environ[keys.secret_access_key].strip(),
        region=environ.get(keys.region, "").strip() or None,
        session_token=environ.get(keys.session_token, "").strip() or None,
    )


def load_store_configuration(environ: Mapping[str, str]) -> StoreConfiguration:
    durable = load_store_settings(StorePurpose.DURABLE, environ)
    transient = load_store_settings(StorePurpose.TRANSIENT, environ)
    if _same_namespace(durable, transient):
        raise StoreConfigurationError(
            StorePurpose.TRANSIENT,
            StoreConfigurationReason.INVALID,
            ("purpose_namespace_collision",),
        )
    return StoreConfiguration(durable=durable, transient=transient)


def _same_namespace(durable: StoreSettings, transient: StoreSettings) -> bool:
    return _endpoint_namespace(durable.endpoint) == _endpoint_namespace(transient.endpoint) and durable.bucket == transient.bucket


def _positive_days(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _validate_optional_days(value: int | None, purpose: StorePurpose) -> None:
    if value is not None and not _positive_days(value):
        raise StoreConfigurationError(purpose, StoreConfigurationReason.INVALID, ("retention_days",))


def _validate_retention(purpose: StorePurpose, current: int | None, noncurrent: int | None) -> None:
    if purpose is StorePurpose.DURABLE:
        if current is not None or not _positive_days(noncurrent):
            raise StoreConfigurationError(purpose, StoreConfigurationReason.INVALID, ("durable_retention",))
        return
    if not _positive_days(current) or not _positive_days(noncurrent):
        raise StoreConfigurationError(purpose, StoreConfigurationReason.INVALID, ("transient_retention",))


def default_retention_profiles(
    *,
    current_expiry_days: int,
    noncurrent_expiry_days: int,
    durable_noncurrent_expiry_days: int = DEFAULT_DURABLE_NONCURRENT_EXPIRY_DAYS,
) -> dict[StorePurpose, RetentionProfile]:
    common = {"versioning_required": True, "conditional_create_required": True, "conditional_update_required": True}
    return {
        StorePurpose.DURABLE: RetentionProfile(
            StorePurpose.DURABLE,
            **common,
            current_version_expiry_days=None,
            noncurrent_version_expiry_days=durable_noncurrent_expiry_days,
        ),
        StorePurpose.TRANSIENT: RetentionProfile(
            StorePurpose.TRANSIENT,
            **common,
            current_version_expiry_days=current_expiry_days,
            noncurrent_version_expiry_days=noncurrent_expiry_days,
        ),
    }


def _profile_digest(profile: RetentionProfile) -> str:
    value: JsonValue = {
        "purpose": profile.purpose.value,
        "versioning_required": profile.versioning_required,
        "conditional_create_required": profile.conditional_create_required,
        "conditional_update_required": profile.conditional_update_required,
        "current_version_expiry_days": profile.current_version_expiry_days,
        "noncurrent_version_expiry_days": profile.noncurrent_version_expiry_days,
    }
    return bytes_digest(canonical_bytes(value))


def verify_store_capabilities(profile: RetentionProfile, evidence: StoreCapabilityEvidence) -> StoreCapabilityReport:
    if profile.purpose is not evidence.purpose:
        raise StoreConfigurationError(profile.purpose, StoreConfigurationReason.INVALID, ("capability_purpose",))
    comparisons = (
        (not evidence.versioning_enabled, StoreCapabilityReason.VERSIONING_REQUIRED),
        (not evidence.conditional_create, StoreCapabilityReason.CONDITIONAL_CREATE_REQUIRED),
        (not evidence.conditional_update, StoreCapabilityReason.CONDITIONAL_UPDATE_REQUIRED),
        (
            evidence.current_version_expiry_days != profile.current_version_expiry_days,
            StoreCapabilityReason.CURRENT_RETENTION_MISMATCH,
        ),
        (
            evidence.noncurrent_version_expiry_days != profile.noncurrent_version_expiry_days,
            StoreCapabilityReason.NONCURRENT_RETENTION_MISMATCH,
        ),
    )
    reasons = tuple(reason for failed, reason in comparisons if failed)
    status = StoreCapabilityStatus.UNSUPPORTED if reasons else StoreCapabilityStatus.READY
    return StoreCapabilityReport(profile.purpose, status, reasons, _profile_digest(profile))


def _configuration_reason(purpose: StorePurpose, reason: StoreConfigurationReason) -> StoreStartupReason:
    return StoreStartupReason(f"{purpose.value}_configuration_{reason.value}")


def _evidence_missing_reason(purpose: StorePurpose) -> StoreStartupReason:
    return StoreStartupReason(f"{purpose.value}_capability_evidence_missing")


def _unsupported_reason(purpose: StorePurpose) -> StoreStartupReason:
    return StoreStartupReason(f"{purpose.value}_capability_unsupported")


def assess_store_startup(
    environ: Mapping[str, str],
    evidence_by_purpose: Mapping[StorePurpose, StoreCapabilityEvidence],
    *,
    current_expiry_days: int = 14,
    noncurrent_expiry_days: int = 1,
) -> StoreStartupReport:
    profiles = default_retention_profiles(
        current_expiry_days=current_expiry_days,
        noncurrent_expiry_days=noncurrent_expiry_days,
    )
    startup_reasons: list[StoreStartupReason] = []
    reports: list[StoreCapabilityReport] = []
    settings_by_purpose: dict[StorePurpose, StoreSettings] = {}
    for purpose in StorePurpose:
        try:
            settings_by_purpose[purpose] = load_store_settings(purpose, environ)
        except StoreConfigurationError as error:
            startup_reasons.append(_configuration_reason(purpose, error.reason))
            continue
        evidence = evidence_by_purpose.get(purpose)
        if evidence is None:
            startup_reasons.append(_evidence_missing_reason(purpose))
            continue
        report = verify_store_capabilities(profiles[purpose], evidence)
        reports.append(report)
        if report.status is StoreCapabilityStatus.UNSUPPORTED:
            startup_reasons.append(_unsupported_reason(purpose))
    if len(settings_by_purpose) == len(StorePurpose) and _same_namespace(
        settings_by_purpose[StorePurpose.DURABLE],
        settings_by_purpose[StorePurpose.TRANSIENT],
    ):
        startup_reasons.append(StoreStartupReason.PURPOSE_CONFIGURATION_COLLISION)
    if any("configuration" in reason.value for reason in startup_reasons):
        status = StoreStartupStatus.MISSING_CONFIGURATION
    elif startup_reasons:
        status = StoreStartupStatus.UNSUPPORTED_CAPABILITY
    else:
        status = StoreStartupStatus.READY
    return StoreStartupReport(status, tuple(startup_reasons), tuple(reports))


def require_store_startup(report: StoreStartupReport) -> None:
    if report.status is not StoreStartupStatus.READY:
        raise StoreStartupError(report)


def canonical_startup_report_bytes(report: StoreStartupReport) -> bytes:
    """Serialize only safe closed status, reasons, and policy identities."""
    capabilities: tuple[JsonValue, ...] = tuple(
        {
            "purpose": item.purpose.value,
            "status": item.status.value,
            "reasons": tuple(reason.value for reason in item.reasons),
            "profile_digest": item.profile_digest,
        }
        for item in report.capabilities
    )
    value: JsonValue = {
        "schema_version": STORE_STARTUP_REPORT_SCHEMA,
        "status": report.status.value,
        "reasons": tuple(reason.value for reason in report.reasons),
        "capabilities": capabilities,
    }
    return canonical_bytes(value)


def require_application_operation(operation: ApplicationStoreOperation) -> None:
    operation = ApplicationStoreOperation(operation)
    if operation in ADMINISTRATOR_OPERATIONS:
        raise StoreAuthorityError(f"administrator_owned_operation:{operation.value}")
