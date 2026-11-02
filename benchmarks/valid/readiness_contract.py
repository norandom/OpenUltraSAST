"""Benchmark-owned adapter for detection-core v2 readiness records.

Core owns immutable contracts and pure validation. Benchmark workflows retain
sequencing, persistence, and population work; this module only constructs the
canonical values and enforces the readiness gate before that work starts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from openultrasast.core.canonical import JsonValue, content_digest
from openultrasast.core.coverage import InputManifest, InputReadReceipt, derive_input_manifest_digest, validate_instrument
from openultrasast.core.readiness import (
    AnalysisIdentity,
    FixtureResult,
    ReadinessEvidenceUse,
    ReadinessResult,
    ReadinessStage,
    ReadinessValidationError,
    StageAuthorization,
    StageResult,
    authorize_stage,
    derive_readiness_result_digest,
    required_evidence_use,
    validate_readiness_result,
)


class ReadinessBlocked(RuntimeError):
    """Population work is not authorized by current readiness evidence."""

    def __init__(
        self,
        failing_stage: ReadinessStage | None,
        reasons: tuple[str, ...],
        correction_lever: str | None,
    ) -> None:
        self.failing_stage = failing_stage
        self.reasons = reasons
        self.correction_lever = correction_lever
        layer = "readiness contract" if failing_stage is None else failing_stage.value
        correction = "" if correction_lever is None else f"; correction: {correction_lever}"
        super().__init__(f"{layer}: {'; '.join(reasons)}{correction}")


def _read_input(input_id: str, path: Path) -> InputReadReceipt:
    try:
        payload = path.read_bytes()
    except OSError:
        return InputReadReceipt(input_id, str(path), False, 0, None)
    return InputReadReceipt(input_id, str(path), True, len(payload), hashlib.sha256(payload).hexdigest())


def read_tracked_inputs(
    inputs: tuple[tuple[str, Path], ...],
) -> tuple[InputManifest, tuple[InputReadReceipt, ...]]:
    """Open tracked inputs and emit receipts; validation later refuses bad reads."""
    input_ids = tuple(input_id for input_id, _path in inputs)
    manifest = InputManifest(input_ids, derive_input_manifest_digest(input_ids))
    receipts = tuple(_read_input(input_id, path) for input_id, path in inputs)
    return manifest, receipts


def _read_receipt_value(receipt: InputReadReceipt) -> JsonValue:
    return {
        "input_id": receipt.input_id,
        "path": receipt.path,
        "opened": receipt.opened,
        "byte_count": receipt.byte_count,
        "content_digest": receipt.content_digest,
    }


def _instrument_value(manifest: InputManifest, receipts: tuple[InputReadReceipt, ...]) -> JsonValue:
    return {
        "tracked_input_ids": manifest.tracked_input_ids,
        "manifest_digest": manifest.manifest_digest,
        "receipts": tuple(_read_receipt_value(item) for item in receipts),
    }


def derive_development_measurement_digest(
    manifest: InputManifest,
    receipts: tuple[InputReadReceipt, ...],
) -> str:
    """Bind a development measurement to the exact verified instrument reads."""
    validate_instrument(manifest, receipts)
    return content_digest(_instrument_value(manifest, receipts))


def build_readiness_result(
    *,
    arm_id: str,
    family_id: str,
    ecosystem: str,
    stage: ReadinessStage,
    result: StageResult,
    identity: AnalysisIdentity,
    predecessor_digests: tuple[str, ...],
    fixture_results: tuple[FixtureResult, ...],
    measurement_digest: str,
    correction_lever: str | None,
    population_digest: str | None,
    population_freeze_digest: str | None,
    population_use_receipt_digests: tuple[str, ...],
) -> ReadinessResult:
    evidence_use = required_evidence_use(stage)
    digest = derive_readiness_result_digest(
        arm_id=arm_id,
        family_id=family_id,
        ecosystem=ecosystem,
        stage=stage,
        evidence_use=evidence_use,
        population_digest=population_digest,
        population_freeze_digest=population_freeze_digest,
        population_use_receipt_digests=population_use_receipt_digests,
        result=result,
        identity=identity,
        predecessor_digests=predecessor_digests,
        fixture_results=fixture_results,
        measurement_digest=measurement_digest,
        correction_lever=correction_lever,
    )
    return ReadinessResult(
        arm_id,
        family_id,
        ecosystem,
        stage,
        evidence_use,
        population_digest,
        population_freeze_digest,
        population_use_receipt_digests,
        result,
        identity,
        predecessor_digests,
        fixture_results,
        measurement_digest,
        correction_lever,
        digest,
    )


@dataclass(frozen=True)
class DevelopmentObservation:
    """A v2 development result plus the instrument evidence that produced it."""

    readiness_result: ReadinessResult
    input_manifest: InputManifest
    input_read_receipts: tuple[InputReadReceipt, ...]
    observation_digest: str

    def __post_init__(self) -> None:
        validate_development_observation(self)


def _observation_value(value: DevelopmentObservation) -> JsonValue:
    return {
        "readiness_result_digest": value.readiness_result.result_digest,
        "instrument": _instrument_value(value.input_manifest, value.input_read_receipts),
    }


def validate_development_observation(value: DevelopmentObservation) -> None:
    """Revalidate the readiness result, instrument, and their exact binding."""
    validate_readiness_result(value.readiness_result)
    if value.readiness_result.stage is not ReadinessStage.DEVELOPMENT:
        raise ReadinessValidationError("development observation must use the development stage")
    if value.readiness_result.evidence_use is not ReadinessEvidenceUse.DEVELOPMENT_POPULATION:
        raise ReadinessValidationError("development observation must use development population evidence")
    expected_measurement = derive_development_measurement_digest(value.input_manifest, value.input_read_receipts)
    if value.readiness_result.measurement_digest != expected_measurement:
        raise ReadinessValidationError("development measurement does not match instrument receipts")
    if value.observation_digest != content_digest(_observation_value(value)):
        raise ReadinessValidationError("development observation digest does not match content")


def build_development_observation(
    *,
    arm_id: str,
    family_id: str,
    ecosystem: str,
    identity: AnalysisIdentity,
    population_digest: str,
    population_freeze_digest: str,
    population_use_receipt_digests: tuple[str, ...],
    predecessor_digests: tuple[str, ...],
    fixture_results: tuple[FixtureResult, ...],
    input_manifest: InputManifest,
    input_read_receipts: tuple[InputReadReceipt, ...],
    result: StageResult = StageResult.PASSED,
    correction_lever: str | None = None,
) -> DevelopmentObservation:
    """Create a development observation only from verified nonzero input reads."""
    measurement = derive_development_measurement_digest(input_manifest, input_read_receipts)
    readiness_result = build_readiness_result(
        arm_id=arm_id,
        family_id=family_id,
        ecosystem=ecosystem,
        stage=ReadinessStage.DEVELOPMENT,
        result=result,
        identity=identity,
        predecessor_digests=predecessor_digests,
        fixture_results=fixture_results,
        measurement_digest=measurement,
        correction_lever=correction_lever,
        population_digest=population_digest,
        population_freeze_digest=population_freeze_digest,
        population_use_receipt_digests=population_use_receipt_digests,
    )
    probe = object.__new__(DevelopmentObservation)
    object.__setattr__(probe, "readiness_result", readiness_result)
    object.__setattr__(probe, "input_manifest", input_manifest)
    object.__setattr__(probe, "input_read_receipts", input_read_receipts)
    object.__setattr__(probe, "observation_digest", "")
    digest = content_digest(_observation_value(probe))
    return DevelopmentObservation(readiness_result, input_manifest, input_read_receipts, digest)


def require_stage_authorized(
    target: ReadinessStage,
    receipts: tuple[ReadinessResult, ...],
    current_identity: AnalysisIdentity,
) -> StageAuthorization:
    """Refuse population work on missing, failed, stale, or malformed readiness."""
    try:
        authorization = authorize_stage(target, receipts, current_identity)
    except ReadinessValidationError as exc:
        raise ReadinessBlocked(None, (str(exc),), None) from exc
    if not authorization.authorized:
        raise ReadinessBlocked(authorization.failing_stage, authorization.reasons, authorization.correction_lever)
    return authorization


__all__ = [
    "DevelopmentObservation",
    "ReadinessBlocked",
    "build_development_observation",
    "build_readiness_result",
    "derive_development_measurement_digest",
    "read_tracked_inputs",
    "require_stage_authorized",
    "validate_development_observation",
]
