"""Canonical capability report and retention-state contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum

from benchmarks.valid.store_configuration import RetentionProfile
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes

CUSTODY_CAPABILITY_REPORT_SCHEMA = "openultrasast.valid-detection-benchmark.custody-capability.v1"
RETENTION_PROBE_STATE_SCHEMA = "openultrasast.valid-detection-benchmark.retention-probe-state.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ProbeResultName(StrEnum):
    CONDITIONAL_CREATE = "conditional_create"
    CONDITIONAL_UPDATE = "conditional_update"
    CONCURRENT_SINGLE_WINNER = "concurrent_single_winner"
    VERSION_VISIBILITY = "version_visibility"
    COMMITTED_SUCCESSOR_REREAD = "committed_successor_reread"
    RESTART_RECOVERY = "restart_recovery"
    CURRENT_EXPIRY = "current_expiry"
    NONCURRENT_EXPIRY = "noncurrent_expiry"


MANDATORY_PROBE_RESULTS = tuple(ProbeResultName)


class ProbeResultStatus(StrEnum):
    PASSED = "passed"
    PENDING = "pending"
    FAILED = "failed"


class ProbeResultReason(StrEnum):
    NONE = "none"
    DEADLINE_PENDING = "deadline_pending"
    CONDITIONAL_CREATE_UNSUPPORTED = "conditional_create_unsupported"
    CONDITIONAL_UPDATE_UNSUPPORTED = "conditional_update_unsupported"
    CONFLICT_NOT_ENFORCED = "conflict_not_enforced"
    VERSION_NOT_VISIBLE = "version_not_visible"
    READBACK_MISMATCH = "readback_mismatch"
    RESTART_MISMATCH = "restart_mismatch"
    PREMATURE_EXPIRY = "premature_expiry"
    EXPIRY_DEADLINE_MISSED = "expiry_deadline_missed"
    UNREADABLE_RESPONSE = "unreadable_response"
    STORE_FAILURE = "store_failure"
    DEPENDENCY_FAILED = "dependency_failed"
    PRESENCE_EVIDENCE_MISSING = "presence_evidence_missing"


class CustodyCapabilityStatus(StrEnum):
    READY = "ready"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    INSTRUMENT_FAILURE = "instrument_failure"


class CustodyProbeErrorReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    STATE_MISMATCH = "state_mismatch"
    STORE_FAILURE = "store_failure"
    UNREADABLE_RESPONSE = "unreadable_response"


class CustodyCapabilityError(RuntimeError):
    def __init__(self, reason: CustodyProbeErrorReason) -> None:
        self.reason = reason
        super().__init__(f"custody_capability_{reason.value}")


class RealPopulationAdmissionDisabled(RuntimeError):
    """A closed capability report cannot authorize a real population."""


@dataclass(frozen=True)
class RetentionProbeState:
    schema_version: str
    input_digest: str
    input_bytes_read: int
    started_at_epoch: int
    durable_store_identity: str
    transient_store_identity: str
    transient_bucket: str
    current_key: str
    current_version_id: str
    current_deadline_epoch: int
    noncurrent_key: str
    noncurrent_version_id: str
    successor_version_id: str
    noncurrent_deadline_epoch: int
    state_digest: str


@dataclass(frozen=True)
class ProbeResult:
    name: ProbeResultName
    status: ProbeResultStatus
    reason: ProbeResultReason


@dataclass(frozen=True)
class CustodyCapabilityReport:
    schema_version: str
    status: CustodyCapabilityStatus
    input_digest: str
    input_bytes_read: int
    durable_store_identity: str
    transient_store_identity: str
    retention_profile_digest: str
    retention_state_digest: str
    results: tuple[ProbeResult, ...]
    report_digest: str

    @property
    def may_admit_real_population(self) -> bool:
        return self.status is CustodyCapabilityStatus.READY and all(result.status is ProbeResultStatus.PASSED for result in self.results)


def passed_result(name: ProbeResultName) -> ProbeResult:
    return ProbeResult(name, ProbeResultStatus.PASSED, ProbeResultReason.NONE)


def failed_result(name: ProbeResultName, reason: ProbeResultReason) -> ProbeResult:
    return ProbeResult(name, ProbeResultStatus.FAILED, reason)


def retention_state_value(state: RetentionProbeState) -> dict[str, JsonValue]:
    return {
        "schema_version": state.schema_version,
        "input_digest": state.input_digest,
        "input_bytes_read": state.input_bytes_read,
        "started_at_epoch": state.started_at_epoch,
        "durable_store_identity": state.durable_store_identity,
        "transient_store_identity": state.transient_store_identity,
        "transient_bucket": state.transient_bucket,
        "current_key": state.current_key,
        "current_version_id": state.current_version_id,
        "current_deadline_epoch": state.current_deadline_epoch,
        "noncurrent_key": state.noncurrent_key,
        "noncurrent_version_id": state.noncurrent_version_id,
        "successor_version_id": state.successor_version_id,
        "noncurrent_deadline_epoch": state.noncurrent_deadline_epoch,
    }


def derive_retention_state_digest(state: RetentionProbeState) -> str:
    return bytes_digest(canonical_bytes(retention_state_value(state)))


def retention_profile_digest(profile: RetentionProfile) -> str:
    value: JsonValue = {
        "purpose": profile.purpose.value,
        "versioning_required": profile.versioning_required,
        "conditional_create_required": profile.conditional_create_required,
        "conditional_update_required": profile.conditional_update_required,
        "current_version_expiry_days": profile.current_version_expiry_days,
        "noncurrent_version_expiry_days": profile.noncurrent_version_expiry_days,
    }
    return bytes_digest(canonical_bytes(value))


def _result_value(result: ProbeResult) -> dict[str, JsonValue]:
    return {"name": result.name.value, "status": result.status.value, "reason": result.reason.value}


def _report_value(report: CustodyCapabilityReport) -> dict[str, JsonValue]:
    return {
        "schema_version": report.schema_version,
        "status": report.status.value,
        "input_digest": report.input_digest,
        "input_bytes_read": report.input_bytes_read,
        "durable_store_identity": report.durable_store_identity,
        "transient_store_identity": report.transient_store_identity,
        "retention_profile_digest": report.retention_profile_digest,
        "retention_state_digest": report.retention_state_digest,
        "results": tuple(_result_value(result) for result in report.results),
    }


def _status_for_results(results: tuple[ProbeResult, ...]) -> CustodyCapabilityStatus:
    instrument_reasons = {ProbeResultReason.STORE_FAILURE, ProbeResultReason.UNREADABLE_RESPONSE}
    if any(result.reason in instrument_reasons for result in results):
        return CustodyCapabilityStatus.INSTRUMENT_FAILURE
    if any(result.status is ProbeResultStatus.FAILED for result in results):
        return CustodyCapabilityStatus.UNSUPPORTED
    if any(result.status is ProbeResultStatus.PENDING for result in results):
        return CustodyCapabilityStatus.PENDING
    return CustodyCapabilityStatus.READY


def build_capability_report(
    input_digest: str,
    input_bytes_read: int,
    profile: RetentionProfile,
    state: RetentionProbeState,
    results: tuple[ProbeResult, ...],
) -> CustodyCapabilityReport:
    draft = CustodyCapabilityReport(
        CUSTODY_CAPABILITY_REPORT_SCHEMA,
        _status_for_results(results),
        input_digest,
        input_bytes_read,
        state.durable_store_identity,
        state.transient_store_identity,
        retention_profile_digest(profile),
        state.state_digest,
        results,
        "",
    )
    return replace(draft, report_digest=bytes_digest(canonical_bytes(_report_value(draft))))


def _valid_result(result: ProbeResult) -> bool:
    if type(result.name) is not ProbeResultName:
        return False
    if type(result.status) is not ProbeResultStatus or type(result.reason) is not ProbeResultReason:
        return False
    if result.status is ProbeResultStatus.PASSED:
        return result.reason is ProbeResultReason.NONE
    if result.status is ProbeResultStatus.PENDING:
        return result.name in {ProbeResultName.CURRENT_EXPIRY, ProbeResultName.NONCURRENT_EXPIRY} and (
            result.reason is ProbeResultReason.DEADLINE_PENDING
        )
    return result.reason not in {ProbeResultReason.NONE, ProbeResultReason.DEADLINE_PENDING}


def _valid_report(report: CustodyCapabilityReport) -> bool:
    valid_types = type(report) is CustodyCapabilityReport and all(type(item) is ProbeResult for item in report.results)
    if not valid_types:
        return False
    return (
        report.schema_version == CUSTODY_CAPABILITY_REPORT_SCHEMA
        and type(report.input_bytes_read) is int
        and report.input_bytes_read > 0
        and _DIGEST.fullmatch(report.input_digest) is not None
        and _DIGEST.fullmatch(report.durable_store_identity) is not None
        and _DIGEST.fullmatch(report.transient_store_identity) is not None
        and _DIGEST.fullmatch(report.retention_profile_digest) is not None
        and _DIGEST.fullmatch(report.retention_state_digest) is not None
        and _DIGEST.fullmatch(report.report_digest) is not None
        and tuple(item.name for item in report.results) == MANDATORY_PROBE_RESULTS
        and all(_valid_result(item) for item in report.results)
        and report.status is _status_for_results(report.results)
        and report.report_digest == bytes_digest(canonical_bytes(_report_value(report)))
    )


def canonical_custody_capability_report_bytes(report: CustodyCapabilityReport) -> bytes:
    if not _valid_report(report):
        raise CustodyCapabilityError(CustodyProbeErrorReason.STATE_MISMATCH)
    return canonical_bytes({**_report_value(report), "report_digest": report.report_digest})


def prior_presence_results(
    report: CustodyCapabilityReport,
    *,
    input_digest: str,
    input_bytes_read: int,
    state: RetentionProbeState,
    profile_digest: str,
) -> tuple[ProbeResult, ...] | None:
    if not _valid_report(report) or report.status is not CustodyCapabilityStatus.PENDING:
        return None
    identities_match = (
        report.input_digest == input_digest
        and report.input_bytes_read == input_bytes_read
        and report.durable_store_identity == state.durable_store_identity
        and report.transient_store_identity == state.transient_store_identity
        and report.retention_profile_digest == profile_digest
        and report.retention_state_digest == state.state_digest
    )
    durable_passed = all(item.status is ProbeResultStatus.PASSED for item in report.results[:6])
    retention_pending = all(item.status is ProbeResultStatus.PENDING for item in report.results[6:])
    return report.results[:6] if identities_match and durable_passed and retention_pending else None


def require_real_population_admission(
    report: CustodyCapabilityReport,
    expected_durable_store_identity: str,
    expected_transient_store_identity: str,
    expected_retention_profile: RetentionProfile,
) -> None:
    if type(report) is not CustodyCapabilityReport:
        raise RealPopulationAdmissionDisabled("real_population_admission_disabled")
    stores_match = (
        report.durable_store_identity == expected_durable_store_identity
        and report.transient_store_identity == expected_transient_store_identity
    )
    profile_matches = type(expected_retention_profile) is RetentionProfile and (
        report.retention_profile_digest == retention_profile_digest(expected_retention_profile)
    )
    if not _valid_report(report) or not stores_match or not profile_matches or not report.may_admit_real_population:
        raise RealPopulationAdmissionDisabled("real_population_admission_disabled")
