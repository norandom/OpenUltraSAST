"""Complete reviewed pre-spend authority validation for evaluation admission V3."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.custody import PopulationCustodyLog, PopulationCustodyPort, PopulationStatus, validate_population_custody_log
from openultrasast.core.evaluation_attempt import AttemptHistoryV3, validate_evaluation_attempt_history
from openultrasast.core.evaluation_feasibility import (
    EvaluationFeasibilityV3,
    validate_evaluation_feasibility,
)
from openultrasast.core.evaluation_observation import SealedObservationRefV3, validate_evaluation_observations
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.readiness import ReadinessResult, validate_readiness_result

_DIGEST = re.compile(r"[0-9a-f]{64}")
_MANIFEST_PAYLOAD_SCHEMA = "openultrasast.detection-core.evaluation-admission-manifest-payload.v3"
_MANIFEST_SCHEMA = "openultrasast.detection-core.evaluation-admission-manifest.v3"
_OBSERVATION_SET_SCHEMA = "openultrasast.detection-core.evaluation-observation-set.v3"
_READINESS_SET_SCHEMA = "openultrasast.detection-core.evaluation-readiness-set.v3"
_AUTHORITY_SCHEMA = "openultrasast.detection-core.evaluation-admission-authority.v3"


class EvaluationAuthorityError(ValueError):
    """The complete reviewed V3 admission graph cannot produce pre-spend authority."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationAuthorityError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _digest_tuple(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationAuthorityError(f"{field} must be a nonempty canonical tuple")
    for item in value:
        _digest(item, field)
    if value != tuple(sorted(set(value))):
        raise EvaluationAuthorityError(f"{field} must be unique and canonical")
    return value


def _ordered_digest_tuple(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationAuthorityError(f"{field} must be a nonempty exact tuple")
    for item in value:
        _digest(item, field)
    if len(set(value)) != len(value):
        raise EvaluationAuthorityError(f"{field} must not contain duplicates")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationAuthorityError(f"{field} does not match canonical content")


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _review_value(review: IndependenceAttestation) -> canonical.JsonValue:
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": _content_ref_value(review.conflict_disclosure),
        "attestation_digest": review.attestation_digest,
    }


@dataclass(frozen=True)
class EvaluationAdmissionManifestV3(EvaluationV3Contract, NonAuthorizingV3):
    """Externally produced complete label-blind graph plus independent review."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    plan_manifest: EvaluationPlanManifestV3
    feasibility_digest: str
    observations: tuple[SealedObservationRefV3, ...]
    readiness_digests: tuple[str, ...]
    custody_log_digest: str
    attempt_history: AttemptHistoryV3
    payload_digest: str
    review: IndependenceAttestation
    manifest_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationAdmissionManifestV3, field="evaluation admission manifest")
        if type(self.plan_manifest) is not EvaluationPlanManifestV3:
            raise EvaluationAuthorityError("admission plan manifest must use exact EvaluationPlanManifestV3")
        self.plan_manifest.__post_init__()
        _digest(self.feasibility_digest, "admission feasibility digest")
        if type(self.observations) is not tuple or not self.observations:
            raise EvaluationAuthorityError("admission observations must be a nonempty exact tuple")
        if any(type(item) is not SealedObservationRefV3 for item in self.observations):
            raise EvaluationAuthorityError("admission observations must use exact sealed references")
        for item in self.observations:
            item.__post_init__()
        _digest_tuple(self.readiness_digests, "admission readiness digest")
        _digest(self.custody_log_digest, "admission custody log digest")
        if type(self.attempt_history) is not AttemptHistoryV3:
            raise EvaluationAuthorityError("admission attempt history must use exact AttemptHistoryV3")
        self.attempt_history.__post_init__()
        _digest(self.payload_digest, "admission payload digest")
        if type(self.review) is not IndependenceAttestation:
            raise EvaluationAuthorityError("admission review must use exact IndependenceAttestation")
        self.review.__post_init__()
        if type(self.review.conflict_disclosure) is not canonical.ContentRef:
            raise EvaluationAuthorityError("admission review disclosure must use exact ContentRef")
        self.review.conflict_disclosure.__post_init__()
        _digest(self.manifest_digest, "admission manifest digest")


def _manifest_payload_value(manifest: EvaluationAdmissionManifestV3) -> canonical.JsonValue:
    return {
        "schema_version": _MANIFEST_PAYLOAD_SCHEMA,
        "plan_manifest_digest": manifest.plan_manifest.manifest_digest,
        "feasibility_digest": manifest.feasibility_digest,
        "observation_ref_digests": tuple(item.ref_digest for item in manifest.observations),
        "readiness_digests": manifest.readiness_digests,
        "custody_log_digest": manifest.custody_log_digest,
        "attempt_history_digest": manifest.attempt_history.history_digest,
        "attempt_history_head_digest": manifest.attempt_history.head_event_digest,
    }


def derive_evaluation_admission_manifest_payload_digest(manifest: EvaluationAdmissionManifestV3) -> str:
    if type(manifest) is not EvaluationAdmissionManifestV3:
        raise EvaluationAuthorityError("admission manifest must use exact EvaluationAdmissionManifestV3")
    manifest.__post_init__()
    return canonical.content_digest(_manifest_payload_value(manifest))


def derive_evaluation_admission_manifest_digest(manifest: EvaluationAdmissionManifestV3) -> str:
    if type(manifest) is not EvaluationAdmissionManifestV3:
        raise EvaluationAuthorityError("admission manifest must use exact EvaluationAdmissionManifestV3")
    manifest.__post_init__()
    return canonical.content_digest(
        {
            "schema_version": _MANIFEST_SCHEMA,
            "payload_digest": manifest.payload_digest,
            "review": _review_value(manifest.review),
        }
    )


def derive_evaluation_observation_set_digest(observations: tuple[SealedObservationRefV3, ...]) -> str:
    if type(observations) is not tuple or not observations or any(type(item) is not SealedObservationRefV3 for item in observations):
        raise EvaluationAuthorityError("observation set must be a nonempty tuple of exact sealed references")
    for item in observations:
        item.__post_init__()
    return canonical.content_digest(
        {"schema_version": _OBSERVATION_SET_SCHEMA, "observation_ref_digests": tuple(item.ref_digest for item in observations)}
    )


def derive_evaluation_readiness_set_digest(readiness_digests: tuple[str, ...]) -> str:
    values = _digest_tuple(readiness_digests, "readiness digest")
    return canonical.content_digest({"schema_version": _READINESS_SET_SCHEMA, "readiness_digests": values})


def _authority_value(authority: EvaluationAdmissionAuthorityV3) -> canonical.JsonValue:
    return {
        "schema_version": _AUTHORITY_SCHEMA,
        "admission_manifest_digest": authority.admission_manifest_digest,
        "plan_manifest_digest": authority.plan_manifest_digest,
        "baseline_digests": authority.baseline_digests,
        "feasibility_digest": authority.feasibility_digest,
        "observation_set_digest": authority.observation_set_digest,
        "readiness_set_digest": authority.readiness_set_digest,
        "validation_context_digest": authority.validation_context_digest,
        "custody_log_digest": authority.custody_log_digest,
        "attempt_history_head_digest": authority.attempt_history_head_digest,
        "admission_review_digest": authority.admission_review_digest,
    }


@dataclass(frozen=True)
class EvaluationAdmissionAuthorityV3(EvaluationV3Contract, NonAuthorizingV3):
    """Validated projection that may feed preparation but never consumer use."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    admission_manifest_digest: str
    plan_manifest_digest: str
    baseline_digests: tuple[str, ...]
    feasibility_digest: str
    observation_set_digest: str
    readiness_set_digest: str
    validation_context_digest: str
    custody_log_digest: str
    attempt_history_head_digest: str
    admission_review_digest: str
    authority_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationAdmissionAuthorityV3, field="evaluation admission authority")
        for field in (
            "admission_manifest_digest",
            "plan_manifest_digest",
            "feasibility_digest",
            "observation_set_digest",
            "readiness_set_digest",
            "validation_context_digest",
            "custody_log_digest",
            "attempt_history_head_digest",
            "admission_review_digest",
        ):
            _digest(getattr(self, field), field)
        _ordered_digest_tuple(self.baseline_digests, "authority baseline digest")
        _bind(self, "authority_digest", canonical.content_digest(_authority_value(self)))


def _validate_manifest_review(
    manifest: EvaluationAdmissionManifestV3,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> None:
    from openultrasast.core._evaluation_plan_review import _validate_policy, _validate_review

    policy = _validate_policy(context.admission_review_policy)
    expected_payload = derive_evaluation_admission_manifest_payload_digest(manifest)
    if manifest.payload_digest != expected_payload:
        raise EvaluationAuthorityError("admission payload digest cannot be re-derived")
    _validate_review(manifest.review, expected_payload, policy, resolver)
    if manifest.manifest_digest != derive_evaluation_admission_manifest_digest(manifest):
        raise EvaluationAuthorityError("admission manifest digest cannot be re-derived")


def _validate_readiness(
    manifest: EvaluationAdmissionManifestV3,
    readiness: Sequence[ReadinessResult],
) -> None:
    if type(readiness) is not tuple or any(type(item) is not ReadinessResult for item in readiness):
        raise EvaluationAuthorityError("current readiness must be an exact tuple of ReadinessResult values")
    for item in readiness:
        validate_readiness_result(item)
    digests = tuple(sorted(item.result_digest for item in readiness))
    if len(set(digests)) != len(digests) or digests != manifest.readiness_digests:
        raise EvaluationAuthorityError("current readiness set does not match the reviewed admission manifest")
    if digests != manifest.plan_manifest.readiness_digests:
        raise EvaluationAuthorityError("current readiness set does not match the reviewed plan")


def _current_custody(
    manifest: EvaluationAdmissionManifestV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> PopulationCustodyLog:
    population = manifest.plan_manifest.declaration.population_digest
    current = custody.current_log(population)
    validate_population_custody_log(current, context.evidence.custody_policy, current=custody)
    if current.population_digest != population:
        raise EvaluationAuthorityError("current custody population does not match the reviewed plan")
    expected = manifest.custody_log_digest
    if manifest.plan_manifest.custody_log_digest != expected or current.log_digest != expected:
        raise EvaluationAuthorityError("admission custody head is stale or differs from the reviewed plan")
    if current.status is not PopulationStatus.AVAILABLE:
        raise EvaluationAuthorityError("admission population is not currently available")
    return current


def _make_authority(
    manifest: EvaluationAdmissionManifestV3,
    context: AdmissionValidationContext,
) -> EvaluationAdmissionAuthorityV3:
    plan = manifest.plan_manifest
    return EvaluationAdmissionAuthorityV3(
        manifest.manifest_digest,
        plan.manifest_digest,
        tuple(item.baseline_digest for item in plan.baselines),
        manifest.feasibility_digest,
        derive_evaluation_observation_set_digest(manifest.observations),
        derive_evaluation_readiness_set_digest(manifest.readiness_digests),
        context.context_digest,
        manifest.custody_log_digest,
        manifest.attempt_history.head_event_digest,
        manifest.review.attestation_digest,
        "",
    )


def authorize_evaluation_admission(
    manifest: EvaluationAdmissionManifestV3,
    feasibility: EvaluationFeasibilityV3,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> EvaluationAdmissionAuthorityV3:
    """Revalidate the complete current label-blind graph and derive one exact authority."""
    try:
        if type(manifest) is not EvaluationAdmissionManifestV3:
            raise EvaluationAuthorityError("admission manifest must use exact EvaluationAdmissionManifestV3")
        manifest.__post_init__()
        if type(context) is not AdmissionValidationContext:
            raise EvaluationAuthorityError("validation context must use exact AdmissionValidationContext")
        _validate_context(context)
        _validate_manifest_review(manifest, context, resolver)
        policy = context.admission_review_policy
        validate_evaluation_feasibility(manifest.plan_manifest, feasibility, policy, resolver)
        if not feasibility.may_spend or feasibility.feasibility_digest != manifest.feasibility_digest:
            raise EvaluationAuthorityError("reviewed feasibility is insufficient or differs from the admission manifest")
        validate_evaluation_observations(
            manifest.plan_manifest.declaration,
            manifest.observations,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
        validate_evaluation_attempt_history(manifest.plan_manifest, manifest.attempt_history, policy, resolver)
        _validate_readiness(manifest, readiness)
        current = _current_custody(manifest, context, custody)
        authority = _make_authority(manifest, context)
        latest = custody.current_log(current.population_digest)
        if latest.log_digest != current.log_digest or latest.status is not PopulationStatus.AVAILABLE:
            raise EvaluationAuthorityError("admission custody changed during authority derivation")
        return authority
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except EvaluationAuthorityError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationAuthorityError(f"evaluation admission authority refused: {exc}") from exc


__all__ = [
    "EvaluationAdmissionAuthorityV3",
    "EvaluationAdmissionManifestV3",
    "EvaluationAuthorityError",
    "authorize_evaluation_admission",
    "derive_evaluation_admission_manifest_digest",
    "derive_evaluation_admission_manifest_payload_digest",
    "derive_evaluation_observation_set_digest",
    "derive_evaluation_readiness_set_digest",
]
