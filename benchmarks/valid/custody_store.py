"""Runtime capability probe for durable benchmark custody storage."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import cast

from benchmarks.valid.custody_probe_contract import (
    RETENTION_PROBE_STATE_SCHEMA,
    CustodyCapabilityError,
    CustodyCapabilityReport,
    CustodyProbeErrorReason,
    ProbeResult,
    ProbeResultName,
    ProbeResultReason,
    ProbeResultStatus,
    RetentionProbeState,
    build_capability_report,
    derive_retention_state_digest,
    failed_result,
    passed_result,
    prior_presence_results,
    retention_profile_digest,
)
from benchmarks.valid.custody_probe_io import (
    ProbeIO,
    ReadAttempt,
    S3CustodyProbeClient,
    WriteAttempt,
    WriteReceipt,
    probe_body,
    probe_input,
    valid_epoch,
    valid_version_id,
)
from benchmarks.valid.store_configuration import RetentionProfile, StorePurpose, StoreSettings, store_namespace_identity
from openultrasast.core.canonical import bytes_digest, canonical_bytes

_DAY_SECONDS = 86_400


class S3CustodyCapabilityProbe:
    """Probe data-plane guarantees without changing store configuration."""

    def __init__(
        self,
        durable_settings: StoreSettings,
        durable_client: S3CustodyProbeClient,
        transient_settings: StoreSettings,
        transient_client: S3CustodyProbeClient,
        transient_profile: RetentionProfile,
    ) -> None:
        valid = (
            type(durable_settings) is StoreSettings
            and durable_settings.purpose is StorePurpose.DURABLE
            and type(transient_settings) is StoreSettings
            and transient_settings.purpose is StorePurpose.TRANSIENT
            and type(transient_profile) is RetentionProfile
            and transient_profile.purpose is StorePurpose.TRANSIENT
        )
        if not valid:
            raise CustodyCapabilityError(CustodyProbeErrorReason.INVALID_INPUT)
        self._durable = ProbeIO(durable_settings, durable_client)
        self._transient = ProbeIO(transient_settings, transient_client)
        self._durable_client = durable_client
        self._profile = transient_profile
        self._durable_identity = store_namespace_identity(durable_settings)
        self._transient_identity = store_namespace_identity(transient_settings)
        if self._durable_identity == self._transient_identity:
            raise CustodyCapabilityError(CustodyProbeErrorReason.INVALID_INPUT)

    def prepare_retention_probe(self, input_bytes: bytes, current_epoch: int) -> RetentionProbeState:
        input_digest, input_bytes_read = probe_input(input_bytes)
        if not valid_epoch(current_epoch):
            raise CustodyCapabilityError(CustodyProbeErrorReason.INVALID_INPUT)
        base = f"runs/capability-probes/{bytes_digest(canonical_bytes((input_digest, current_epoch)))}"
        current_key, noncurrent_key = f"{base}/current.json", f"{base}/noncurrent.json"
        current_body = probe_body("retention-current", input_digest, 0)
        successor_body = probe_body("retention-successor", input_digest, 1)
        current = self._transient.write(current_key, current_body, absent=True)
        prior = self._transient.write(noncurrent_key, probe_body("retention-noncurrent", input_digest, 0), absent=True)
        if current.receipt is None or prior.receipt is None:
            self._raise_prepare_failure(current, prior)
        current_receipt, prior_receipt = cast(WriteReceipt, current.receipt), cast(WriteReceipt, prior.receipt)
        successor = self._transient.write(
            noncurrent_key,
            successor_body,
            token=prior_receipt.storage_token,
        )
        if successor.receipt is None:
            self._raise_prepare_failure(successor)
        successor_receipt = cast(WriteReceipt, successor.receipt)
        self._validate_retention_seed(
            current_key,
            current_body,
            current_receipt,
            noncurrent_key,
            successor_body,
            successor_receipt,
            prior_receipt.version_id,
        )
        return self._retention_state(
            input_digest,
            input_bytes_read,
            current_epoch,
            current_key,
            current_receipt,
            noncurrent_key,
            prior_receipt,
            successor_receipt,
        )

    def _retention_state(
        self,
        input_digest: str,
        input_bytes_read: int,
        current_epoch: int,
        current_key: str,
        current: WriteReceipt,
        noncurrent_key: str,
        prior: WriteReceipt,
        successor: WriteReceipt,
    ) -> RetentionProbeState:
        current_days = self._profile.current_version_expiry_days
        noncurrent_days = self._profile.noncurrent_version_expiry_days
        assert current_days is not None and noncurrent_days is not None
        draft = RetentionProbeState(
            RETENTION_PROBE_STATE_SCHEMA,
            input_digest,
            input_bytes_read,
            current_epoch,
            self._durable_identity,
            self._transient_identity,
            self._transient.settings.bucket,
            current_key,
            current.version_id,
            current_epoch + current_days * _DAY_SECONDS,
            noncurrent_key,
            prior.version_id,
            successor.version_id,
            current_epoch + noncurrent_days * _DAY_SECONDS,
            "",
        )
        return replace(draft, state_digest=derive_retention_state_digest(draft))

    def _validate_retention_seed(
        self,
        current_key: str,
        current_body: bytes,
        current: WriteReceipt,
        noncurrent_key: str,
        successor_body: bytes,
        successor: WriteReceipt,
        prior_version_id: str,
    ) -> None:
        current_read = self._transient.read(current_key)
        successor_read = self._transient.read(noncurrent_key)
        versions, reason = self._transient.version_ids(noncurrent_key)
        reads_match = (
            current_read.body == current_body
            and current_read.receipt == current
            and successor_read.body == successor_body
            and successor_read.receipt == successor
        )
        expected_versions = (prior_version_id, successor.version_id)
        versions_match = versions is not None and self._has_exact_versions(versions, expected_versions)
        if reads_match and versions_match:
            return
        if reason is ProbeResultReason.STORE_FAILURE:
            raise CustodyCapabilityError(CustodyProbeErrorReason.STORE_FAILURE)
        raise CustodyCapabilityError(CustodyProbeErrorReason.UNREADABLE_RESPONSE)

    @staticmethod
    def _raise_prepare_failure(*attempts: WriteAttempt) -> None:
        reason = CustodyProbeErrorReason.STORE_FAILURE
        if any(item.reason is ProbeResultReason.UNREADABLE_RESPONSE for item in attempts):
            reason = CustodyProbeErrorReason.UNREADABLE_RESPONSE
        raise CustodyCapabilityError(reason)

    def probe(
        self,
        input_bytes: bytes,
        state: RetentionProbeState,
        current_epoch: int,
        *,
        prior_report: CustodyCapabilityReport | None = None,
    ) -> CustodyCapabilityReport:
        input_digest, input_bytes_read = probe_input(input_bytes)
        self._validate_state(state, input_digest, input_bytes_read)
        if not valid_epoch(current_epoch):
            raise CustodyCapabilityError(CustodyProbeErrorReason.INVALID_INPUT)
        durable_results = self._durable_results(input_digest, input_bytes_read, state, prior_report)
        retention_results = self._probe_retention(state, current_epoch)
        if prior_report is None and current_epoch >= min(state.current_deadline_epoch, state.noncurrent_deadline_epoch):
            retention_results = [
                item
                if item.reason in {ProbeResultReason.STORE_FAILURE, ProbeResultReason.UNREADABLE_RESPONSE}
                else failed_result(item.name, ProbeResultReason.PRESENCE_EVIDENCE_MISSING)
                for item in retention_results
            ]
        results = [*durable_results, *retention_results]
        return build_capability_report(input_digest, input_bytes_read, self._profile, state, tuple(results))

    def _durable_results(
        self,
        input_digest: str,
        input_bytes_read: int,
        state: RetentionProbeState,
        prior_report: CustodyCapabilityReport | None,
    ) -> list[ProbeResult]:
        if prior_report is None:
            return self._probe_durable(input_digest, state.state_digest)
        results = prior_presence_results(
            prior_report,
            input_digest=input_digest,
            input_bytes_read=input_bytes_read,
            state=state,
            profile_digest=retention_profile_digest(self._profile),
        )
        if results is None:
            raise CustodyCapabilityError(CustodyProbeErrorReason.STATE_MISMATCH)
        return list(results)

    def _validate_state(self, state: RetentionProbeState, input_digest: str, input_bytes_read: int) -> None:
        if type(state) is not RetentionProbeState or not valid_epoch(state.started_at_epoch):
            raise CustodyCapabilityError(CustodyProbeErrorReason.STATE_MISMATCH)
        current_days = self._profile.current_version_expiry_days
        noncurrent_days = self._profile.noncurrent_version_expiry_days
        expected_base = f"runs/capability-probes/{bytes_digest(canonical_bytes((input_digest, state.started_at_epoch)))}"
        valid = (
            state.schema_version == RETENTION_PROBE_STATE_SCHEMA
            and state.input_digest == input_digest
            and state.input_bytes_read == input_bytes_read
            and state.durable_store_identity == self._durable_identity
            and state.transient_store_identity == self._transient_identity
            and state.transient_bucket == self._transient.settings.bucket
            and state.state_digest == derive_retention_state_digest(state)
            and state.current_key == f"{expected_base}/current.json"
            and state.noncurrent_key == f"{expected_base}/noncurrent.json"
            and valid_version_id(state.current_version_id)
            and valid_version_id(state.noncurrent_version_id)
            and valid_version_id(state.successor_version_id)
            and state.noncurrent_version_id != state.successor_version_id
            and current_days is not None
            and noncurrent_days is not None
            and state.current_deadline_epoch == state.started_at_epoch + current_days * _DAY_SECONDS
            and state.noncurrent_deadline_epoch == state.started_at_epoch + noncurrent_days * _DAY_SECONDS
        )
        if not valid:
            raise CustodyCapabilityError(CustodyProbeErrorReason.STATE_MISMATCH)

    def _probe_durable(self, input_digest: str, state_digest: str) -> list[ProbeResult]:
        key = f"custody/capability-probes/{bytes_digest(canonical_bytes((input_digest, state_digest)))}/head.json"
        first_body = probe_body("durable-head", input_digest, 0)
        first = self._durable.write(key, first_body, absent=True)
        if first.receipt is None:
            reason = self._write_reason(first, ProbeResultReason.CONDITIONAL_CREATE_UNSUPPORTED)
            return [failed_result(ProbeResultName.CONDITIONAL_CREATE, reason), *self._dependent_results()]
        duplicate = self._durable.write(key, probe_body("durable-duplicate", input_digest, 0), absent=True)
        original = self._durable.read(key)
        original_matches = original.body == first_body and original.receipt == first.receipt
        if not duplicate.is_conflict or not original_matches:
            reason = self._write_reason(duplicate, ProbeResultReason.CONDITIONAL_CREATE_UNSUPPORTED)
            if original.reason is not ProbeResultReason.NONE:
                reason = original.reason
            elif duplicate.is_conflict and not original_matches:
                reason = ProbeResultReason.READBACK_MISMATCH
            return [failed_result(ProbeResultName.CONDITIONAL_CREATE, reason), *self._dependent_results()]
        results = [passed_result(ProbeResultName.CONDITIONAL_CREATE)]
        second_body = probe_body("durable-head", input_digest, 1)
        second = self._durable.write(key, second_body, token=first.receipt.storage_token)
        if second.receipt is None:
            reason = self._write_reason(second, ProbeResultReason.CONDITIONAL_UPDATE_UNSUPPORTED)
            return [*results, failed_result(ProbeResultName.CONDITIONAL_UPDATE, reason), *self._dependent_results(skip=1)]
        results.append(passed_result(ProbeResultName.CONDITIONAL_UPDATE))
        race = self._race(key, input_digest, second.receipt.storage_token)
        results.append(race[0])
        if race[1] is None:
            return [*results, *self._dependent_results(skip=2)]
        winner, winner_body = race[1]
        versions, reason = self._durable.version_ids(key)
        expected_versions = (first.receipt.version_id, second.receipt.version_id, winner.version_id)
        if versions is None:
            results.append(failed_result(ProbeResultName.VERSION_VISIBILITY, reason))
        elif not self._has_exact_versions(versions, expected_versions):
            results.append(failed_result(ProbeResultName.VERSION_VISIBILITY, ProbeResultReason.VERSION_NOT_VISIBLE))
        else:
            results.append(passed_result(ProbeResultName.VERSION_VISIBILITY))
        readback = self._durable.read(key)
        results.append(self._read_result(ProbeResultName.COMMITTED_SUCCESSOR_REREAD, readback, winner, winner_body))
        restarted = ProbeIO(self._durable.settings, self._durable_client).read(key)
        restart = self._read_result(ProbeResultName.RESTART_RECOVERY, restarted, winner, winner_body)
        if restart.reason is ProbeResultReason.READBACK_MISMATCH:
            restart = failed_result(ProbeResultName.RESTART_RECOVERY, ProbeResultReason.RESTART_MISMATCH)
        results.append(restart)
        return results

    @staticmethod
    def _has_exact_versions(versions: tuple[str, ...], expected: tuple[str, ...]) -> bool:
        return len(expected) == len(set(expected)) and len(versions) == len(expected) and set(versions) == set(expected)

    @staticmethod
    def _write_reason(attempt: WriteAttempt, unsupported: ProbeResultReason) -> ProbeResultReason:
        if attempt.is_conflict:
            return unsupported
        if attempt.reason in {ProbeResultReason.STORE_FAILURE, ProbeResultReason.UNREADABLE_RESPONSE}:
            return attempt.reason
        return unsupported

    @staticmethod
    def _dependent_results(skip: int = 0) -> list[ProbeResult]:
        names = tuple(ProbeResultName)[2 + skip : 6]
        return [failed_result(name, ProbeResultReason.DEPENDENCY_FAILED) for name in names]

    def _race(self, key: str, input_digest: str, token: str) -> tuple[ProbeResult, tuple[WriteReceipt, bytes] | None]:
        bodies = (probe_body("durable-race-a", input_digest, 2), probe_body("durable-race-b", input_digest, 2))
        with ThreadPoolExecutor(max_workers=2) as executor:
            attempts = tuple(executor.map(lambda body: self._durable.write(key, body, token=token), bodies))
        winners = tuple((item.receipt, body) for item, body in zip(attempts, bodies, strict=True) if item.receipt is not None)
        conflicts = sum(item.is_conflict for item in attempts)
        if len(winners) == 1 and conflicts == 1:
            return passed_result(ProbeResultName.CONCURRENT_SINGLE_WINNER), winners[0]
        if any(item.reason is ProbeResultReason.UNREADABLE_RESPONSE for item in attempts):
            reason = ProbeResultReason.UNREADABLE_RESPONSE
        elif any(item.reason is ProbeResultReason.STORE_FAILURE and not item.is_conflict for item in attempts):
            reason = ProbeResultReason.STORE_FAILURE
        else:
            reason = ProbeResultReason.CONFLICT_NOT_ENFORCED
        return failed_result(ProbeResultName.CONCURRENT_SINGLE_WINNER, reason), None

    @staticmethod
    def _read_result(name: ProbeResultName, read: ReadAttempt, receipt: WriteReceipt, body: bytes) -> ProbeResult:
        if read.reason is not ProbeResultReason.NONE:
            return failed_result(name, read.reason)
        if read.is_absent or read.body != body or read.receipt != receipt:
            return failed_result(name, ProbeResultReason.READBACK_MISMATCH)
        return passed_result(name)

    def _probe_retention(self, state: RetentionProbeState, current_epoch: int) -> list[ProbeResult]:
        expected = probe_body("retention-current", state.input_digest, 0)
        current = self._transient.read(state.current_key)
        if current_epoch < state.current_deadline_epoch:
            current_result = self._before_current_deadline(current, state, expected)
        else:
            current_result = self._after_current_deadline(current)
        versions, reason = self._transient.version_ids(state.noncurrent_key)
        noncurrent_result = self._noncurrent_result(versions, reason, state, current_epoch)
        return [current_result, noncurrent_result]

    @staticmethod
    def _before_current_deadline(read: ReadAttempt, state: RetentionProbeState, expected: bytes) -> ProbeResult:
        if read.reason is not ProbeResultReason.NONE:
            return failed_result(ProbeResultName.CURRENT_EXPIRY, read.reason)
        if read.is_absent:
            return failed_result(ProbeResultName.CURRENT_EXPIRY, ProbeResultReason.PREMATURE_EXPIRY)
        if read.body != expected or read.receipt is None or read.receipt.version_id != state.current_version_id:
            return failed_result(ProbeResultName.CURRENT_EXPIRY, ProbeResultReason.READBACK_MISMATCH)
        return ProbeResult(ProbeResultName.CURRENT_EXPIRY, ProbeResultStatus.PENDING, ProbeResultReason.DEADLINE_PENDING)

    @staticmethod
    def _after_current_deadline(read: ReadAttempt) -> ProbeResult:
        if read.reason is not ProbeResultReason.NONE:
            return failed_result(ProbeResultName.CURRENT_EXPIRY, read.reason)
        if read.is_absent:
            return passed_result(ProbeResultName.CURRENT_EXPIRY)
        return failed_result(ProbeResultName.CURRENT_EXPIRY, ProbeResultReason.EXPIRY_DEADLINE_MISSED)

    @staticmethod
    def _noncurrent_result(
        versions: tuple[str, ...] | None,
        reason: ProbeResultReason,
        state: RetentionProbeState,
        current_epoch: int,
    ) -> ProbeResult:
        if versions is None:
            return failed_result(ProbeResultName.NONCURRENT_EXPIRY, reason)
        is_visible = state.noncurrent_version_id in versions
        if current_epoch < state.noncurrent_deadline_epoch:
            if not is_visible:
                return failed_result(ProbeResultName.NONCURRENT_EXPIRY, ProbeResultReason.PREMATURE_EXPIRY)
            return ProbeResult(
                ProbeResultName.NONCURRENT_EXPIRY,
                ProbeResultStatus.PENDING,
                ProbeResultReason.DEADLINE_PENDING,
            )
        if is_visible:
            return failed_result(ProbeResultName.NONCURRENT_EXPIRY, ProbeResultReason.EXPIRY_DEADLINE_MISSED)
        return passed_result(ProbeResultName.NONCURRENT_EXPIRY)
