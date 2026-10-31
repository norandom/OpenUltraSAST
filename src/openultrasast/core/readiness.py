"""Ordered, immutable detection-readiness evidence contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical

READINESS_RESULT_SCHEMA = "openultrasast.detection-core.readiness-result.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ReadinessValidationError(ValueError):
    """Readiness evidence violates the closed stage contract."""


class ReadinessStage(Enum):
    INSTRUMENT = "instrument"
    RECOGNITION = "recognition"
    TRANSITIONS = "transitions"
    CONSTRAINTS = "constraints"
    PAIRS = "pairs"
    DEVELOPMENT = "development"
    ADMISSION = "admission"
    INTEGRATION = "integration"


class StageResult(Enum):
    PASSED = "passed"
    FAILED = "failed"


class FixtureRole(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    AMBIGUITY = "ambiguity"


class ReadinessEvidenceUse(Enum):
    REGRESSION_FIXTURE = "regression_fixture"
    DEVELOPMENT_POPULATION = "development_population"
    REPOSITORY_HOLDOUT = "repository_holdout"
    FRESH_ADMISSION = "fresh_admission"
    CONSUMER_INTEGRATION = "consumer_integration"


_STAGE_EVIDENCE_USE = {
    ReadinessStage.INSTRUMENT: ReadinessEvidenceUse.REGRESSION_FIXTURE,
    ReadinessStage.RECOGNITION: ReadinessEvidenceUse.REGRESSION_FIXTURE,
    ReadinessStage.TRANSITIONS: ReadinessEvidenceUse.REGRESSION_FIXTURE,
    ReadinessStage.CONSTRAINTS: ReadinessEvidenceUse.REGRESSION_FIXTURE,
    ReadinessStage.PAIRS: ReadinessEvidenceUse.REGRESSION_FIXTURE,
    ReadinessStage.DEVELOPMENT: ReadinessEvidenceUse.DEVELOPMENT_POPULATION,
    ReadinessStage.ADMISSION: ReadinessEvidenceUse.FRESH_ADMISSION,
    ReadinessStage.INTEGRATION: ReadinessEvidenceUse.CONSUMER_INTEGRATION,
}
_POPULATION_USES = {
    ReadinessEvidenceUse.DEVELOPMENT_POPULATION,
    ReadinessEvidenceUse.REPOSITORY_HOLDOUT,
    ReadinessEvidenceUse.FRESH_ADMISSION,
}


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ReadinessValidationError(f"{field} must be nonempty text")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReadinessValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _optional_digest(value: object, field: str) -> None:
    if value is not None:
        _digest(value, field)


def _text_tuple(value: object, field: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, str) and item for item in value):
        raise ReadinessValidationError(f"{field} must be a tuple of nonempty text")
    if len(set(value)) != len(value):
        raise ReadinessValidationError(f"{field} must not contain duplicates")


def _digest_tuple(value: object, field: str, *, allow_empty: bool = True) -> None:
    if not isinstance(value, tuple):
        raise ReadinessValidationError(f"{field} must be a tuple")
    if not allow_empty and not value:
        raise ReadinessValidationError(f"{field} must not be empty")
    item_name = field.replace("_", " ").removesuffix("s")
    for item in value:
        _digest(item, item_name)
    if len(set(value)) != len(value):
        raise ReadinessValidationError(f"duplicate {item_name}")


@dataclass(frozen=True)
class FixtureResult:
    role: FixtureRole
    fixture_digest: str
    passed: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_fixture_result(self)


def validate_fixture_result(value: FixtureResult) -> None:
    if not isinstance(value, FixtureResult):
        raise ReadinessValidationError("fixture result must be a FixtureResult")
    if not isinstance(value.role, FixtureRole):
        raise ReadinessValidationError("fixture role must be a FixtureRole")
    _digest(value.fixture_digest, "fixture digest")
    if not isinstance(value.passed, bool):
        raise ReadinessValidationError("fixture passed must be boolean")
    _text_tuple(value.reasons, "fixture reasons")
    if value.passed and value.reasons:
        raise ReadinessValidationError("passed fixture must not carry failure reasons")
    if not value.passed and not value.reasons:
        raise ReadinessValidationError("failed fixture must carry reasons")


@dataclass(frozen=True)
class AnalysisIdentity:
    core_schema_version: str
    semantic_vocabulary_digest: str
    analyzer_revision: str
    family_contract_digest: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    model_program_digest: str | None
    outcome_mapping_digest: str

    def __post_init__(self) -> None:
        validate_analysis_identity(self)


def validate_analysis_identity(value: AnalysisIdentity) -> None:
    if not isinstance(value, AnalysisIdentity):
        raise ReadinessValidationError("identity must be an AnalysisIdentity")
    _text(value.core_schema_version, "core schema version")
    _text(value.analyzer_revision, "analyzer revision")
    for item, field in (
        (value.semantic_vocabulary_digest, "semantic vocabulary digest"),
        (value.family_contract_digest, "family contract digest"),
        (value.fact_set_digest, "fact set digest"),
        (value.acquisition_record_digest, "acquisition record digest"),
        (value.configuration_digest, "configuration digest"),
        (value.outcome_mapping_digest, "outcome mapping digest"),
    ):
        _digest(item, field)
    _optional_digest(value.model_program_digest, "model program digest")


def required_evidence_use(stage: ReadinessStage) -> ReadinessEvidenceUse:
    if not isinstance(stage, ReadinessStage):
        raise ReadinessValidationError("stage must be a ReadinessStage")
    return _STAGE_EVIDENCE_USE[stage]


@dataclass(frozen=True)
class ReadinessResult:
    arm_id: str
    family_id: str
    ecosystem: str
    stage: ReadinessStage
    evidence_use: ReadinessEvidenceUse
    population_digest: str | None
    population_freeze_digest: str | None
    population_use_receipt_digests: tuple[str, ...]
    result: StageResult
    identity: AnalysisIdentity
    predecessor_digests: tuple[str, ...]
    fixture_results: tuple[FixtureResult, ...]
    measurement_digest: str
    correction_lever: str | None
    result_digest: str

    def __post_init__(self) -> None:
        validate_readiness_result(self)


def _identity_value(value: AnalysisIdentity) -> canonical.JsonValue:
    return {
        "core_schema_version": value.core_schema_version,
        "semantic_vocabulary_digest": value.semantic_vocabulary_digest,
        "analyzer_revision": value.analyzer_revision,
        "family_contract_digest": value.family_contract_digest,
        "fact_set_digest": value.fact_set_digest,
        "acquisition_record_digest": value.acquisition_record_digest,
        "configuration_digest": value.configuration_digest,
        "model_program_digest": value.model_program_digest,
        "outcome_mapping_digest": value.outcome_mapping_digest,
    }


def _fixture_value(value: FixtureResult) -> canonical.JsonValue:
    return {
        "role": value.role.value,
        "fixture_digest": value.fixture_digest,
        "passed": value.passed,
        "reasons": value.reasons,
    }


def _validate_fixtures(values: object, result: StageResult) -> None:
    if not isinstance(values, tuple) or not all(isinstance(item, FixtureResult) for item in values):
        raise ReadinessValidationError("fixture_results must be a tuple of FixtureResult values")
    for item in values:
        validate_fixture_result(item)
    if tuple(item.role for item in values) != tuple(FixtureRole):
        raise ReadinessValidationError("fixture roles must be the exact positive, negative, ambiguity triplet")
    failures = tuple(item for item in values if not item.passed)
    if result is StageResult.PASSED and failures:
        raise ReadinessValidationError("passed stage requires every fixture to pass")
    if result is StageResult.FAILED and not failures:
        raise ReadinessValidationError("failed stage requires at least one failed fixture")


def _validate_population(value: ReadinessResult) -> None:
    if value.evidence_use in _POPULATION_USES:
        _digest(value.population_digest, "population digest")
        _digest(value.population_freeze_digest, "population freeze digest")
        _digest_tuple(value.population_use_receipt_digests, "population_use_receipt_digests", allow_empty=False)
        return
    if value.population_digest is not None or value.population_freeze_digest is not None or value.population_use_receipt_digests != ():
        raise ReadinessValidationError("this evidence use must not name a population")


def _validate_result_fields(value: ReadinessResult) -> None:
    for item, field in ((value.arm_id, "arm_id"), (value.family_id, "family_id"), (value.ecosystem, "ecosystem")):
        _text(item, field)
    if not isinstance(value.stage, ReadinessStage):
        raise ReadinessValidationError("stage must be a ReadinessStage")
    if not isinstance(value.evidence_use, ReadinessEvidenceUse):
        raise ReadinessValidationError("evidence use must be a ReadinessEvidenceUse")
    if value.evidence_use is not required_evidence_use(value.stage):
        raise ReadinessValidationError(f"wrong evidence use for {value.stage.value} stage")
    if not isinstance(value.result, StageResult):
        raise ReadinessValidationError("result must be a StageResult")
    validate_analysis_identity(value.identity)
    _validate_population(value)
    _digest_tuple(value.predecessor_digests, "predecessor_digests")
    if value.stage is ReadinessStage.INSTRUMENT and value.predecessor_digests:
        raise ReadinessValidationError("instrument stage must not name a predecessor")
    if value.stage is not ReadinessStage.INSTRUMENT and not value.predecessor_digests:
        raise ReadinessValidationError("later stage must name at least one predecessor")
    _validate_fixtures(value.fixture_results, value.result)
    _digest(value.measurement_digest, "measurement digest")
    if value.result is StageResult.PASSED and value.correction_lever is not None:
        raise ReadinessValidationError("passed stage must not name a correction lever")
    if value.result is StageResult.FAILED:
        _text(value.correction_lever, "correction lever")


def _result_value(value: ReadinessResult) -> canonical.JsonValue:
    return {
        "schema_version": READINESS_RESULT_SCHEMA,
        "arm_id": value.arm_id,
        "family_id": value.family_id,
        "ecosystem": value.ecosystem,
        "stage": value.stage.value,
        "evidence_use": value.evidence_use.value,
        "population_digest": value.population_digest,
        "population_freeze_digest": value.population_freeze_digest,
        "population_use_receipt_digests": value.population_use_receipt_digests,
        "result": value.result.value,
        "identity": _identity_value(value.identity),
        "predecessor_digests": value.predecessor_digests,
        "fixture_results": tuple(_fixture_value(item) for item in value.fixture_results),
        "measurement_digest": value.measurement_digest,
        "correction_lever": value.correction_lever,
    }


def derive_readiness_result_digest(
    *,
    arm_id: str,
    family_id: str,
    ecosystem: str,
    stage: ReadinessStage,
    evidence_use: ReadinessEvidenceUse,
    population_digest: str | None,
    population_freeze_digest: str | None,
    population_use_receipt_digests: tuple[str, ...],
    result: StageResult,
    identity: AnalysisIdentity,
    predecessor_digests: tuple[str, ...],
    fixture_results: tuple[FixtureResult, ...],
    measurement_digest: str,
    correction_lever: str | None,
) -> str:
    probe = object.__new__(ReadinessResult)
    fields = {
        "arm_id": arm_id,
        "family_id": family_id,
        "ecosystem": ecosystem,
        "stage": stage,
        "evidence_use": evidence_use,
        "population_digest": population_digest,
        "population_freeze_digest": population_freeze_digest,
        "population_use_receipt_digests": population_use_receipt_digests,
        "result": result,
        "identity": identity,
        "predecessor_digests": predecessor_digests,
        "fixture_results": fixture_results,
        "measurement_digest": measurement_digest,
        "correction_lever": correction_lever,
    }
    for field, item in fields.items():
        object.__setattr__(probe, field, item)
    object.__setattr__(probe, "result_digest", "0" * 64)
    _validate_result_fields(probe)
    return canonical.content_digest(_result_value(probe))


def validate_readiness_result(value: ReadinessResult) -> None:
    if not isinstance(value, ReadinessResult):
        raise ReadinessValidationError("readiness result must be a ReadinessResult")
    _validate_result_fields(value)
    _digest(value.result_digest, "result digest")
    if value.result_digest != canonical.content_digest(_result_value(value)):
        raise ReadinessValidationError("result digest does not match readiness content")


__all__ = [
    "READINESS_RESULT_SCHEMA",
    "AnalysisIdentity",
    "FixtureResult",
    "FixtureRole",
    "ReadinessEvidenceUse",
    "ReadinessResult",
    "ReadinessStage",
    "ReadinessValidationError",
    "StageResult",
    "derive_readiness_result_digest",
    "required_evidence_use",
    "validate_analysis_identity",
    "validate_fixture_result",
    "validate_readiness_result",
]
