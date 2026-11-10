"""Pure all-arm preparation and shared-spend binding for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyLog,
    PopulationCustodyPort,
    PopulationStatus,
    PopulationUseReceipt,
    PopulationUseRequest,
    derive_population_use_request_digest,
    validate_population_custody_log,
)
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionAuthorityV3,
    EvaluationAdmissionManifestV3,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
    derive_evaluation_observation_set_digest,
    derive_evaluation_readiness_set_digest,
)
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_PREPARATION_SCHEMA = "openultrasast.detection-core.evaluation-preparation.v3"
_SPEND_BINDING_SCHEMA = "openultrasast.detection-core.evaluation-spend-binding.v3"


class EvaluationSharedSpendError(ValueError):
    """A V3 preparation or all-arm shared-spend binding is invalid."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationSharedSpendError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _ordered_digests(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationSharedSpendError(f"{field} must be a nonempty exact tuple")
    for item in value:
        _digest(item, field)
    if len(set(value)) != len(value):
        raise EvaluationSharedSpendError(f"{field} must not contain duplicates")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationSharedSpendError(f"{field} does not match canonical content")


def _preparation_value(value: EvaluationPreparationV3) -> canonical.JsonValue:
    return {
        "schema_version": _PREPARATION_SCHEMA,
        "authority_digest": value.authority.authority_digest,
        "label_release_request_digest": derive_population_use_request_digest(value.label_release_request),
        "planned_baseline_digests": value.planned_baseline_digests,
    }


@dataclass(frozen=True)
class EvaluationPreparationV3(EvaluationV3Contract, NonAuthorizingV3):
    """Pure head-bound request covering every baseline in one authority."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    authority: EvaluationAdmissionAuthorityV3
    label_release_request: PopulationUseRequest
    planned_baseline_digests: tuple[str, ...]
    preparation_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationPreparationV3, field="evaluation preparation")
        if type(self.authority) is not EvaluationAdmissionAuthorityV3:
            raise EvaluationSharedSpendError("preparation authority must use exact EvaluationAdmissionAuthorityV3")
        self.authority.__post_init__()
        if type(self.label_release_request) is not PopulationUseRequest:
            raise EvaluationSharedSpendError("label-release request must use exact PopulationUseRequest")
        self.label_release_request.__post_init__()
        baselines = _ordered_digests(self.planned_baseline_digests, "planned baseline digest")
        if baselines != self.authority.baseline_digests:
            raise EvaluationSharedSpendError("planned baseline set must equal the exact authority baseline set")
        request = self.label_release_request
        expected = (
            self.authority.plan_manifest_digest,
            LineagePurpose.ADMISSION_LABEL_OPEN,
            True,
            self.authority.authority_digest,
            self.authority.custody_log_digest,
        )
        actual = (
            request.arm_id,
            request.purpose,
            request.labels_accessed,
            request.influenced_artifact_digest,
            request.expected_log_digest,
        )
        if actual != expected:
            raise EvaluationSharedSpendError("label-release request does not match the exact authority")
        _bind(self, "preparation_digest", canonical.content_digest(_preparation_value(self)))


def derive_evaluation_preparation_digest(value: EvaluationPreparationV3) -> str:
    if type(value) is not EvaluationPreparationV3:
        raise EvaluationSharedSpendError("preparation must use exact EvaluationPreparationV3")
    value.__post_init__()
    return canonical.content_digest(_preparation_value(value))


def _binding_value(value: EvaluationSpendBindingV3) -> canonical.JsonValue:
    return {
        "schema_version": _SPEND_BINDING_SCHEMA,
        "preparation_digest": value.preparation_digest,
        "receipt_digest": value.receipt_digest,
        "planned_baseline_digests": value.planned_baseline_digests,
    }


@dataclass(frozen=True)
class EvaluationSpendBindingV3(EvaluationV3Contract, NonAuthorizingV3):
    """Exact current spend receipt bound to the complete planned baseline set."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    preparation_digest: str
    receipt_digest: str
    planned_baseline_digests: tuple[str, ...]
    binding_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationSpendBindingV3, field="evaluation spend binding")
        _digest(self.preparation_digest, "spend preparation digest")
        _digest(self.receipt_digest, "spend receipt digest")
        _ordered_digests(self.planned_baseline_digests, "spend planned baseline digest")
        _bind(self, "binding_digest", canonical.content_digest(_binding_value(self)))


def derive_evaluation_spend_binding_digest(value: EvaluationSpendBindingV3) -> str:
    if type(value) is not EvaluationSpendBindingV3:
        raise EvaluationSharedSpendError("spend binding must use exact EvaluationSpendBindingV3")
    value.__post_init__()
    return canonical.content_digest(_binding_value(value))


def _validate_authority_binding(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    context: AdmissionValidationContext,
) -> None:
    manifest.__post_init__()
    authority.__post_init__()
    if manifest.payload_digest != derive_evaluation_admission_manifest_payload_digest(manifest):
        raise EvaluationSharedSpendError("admission manifest payload is not canonical")
    if manifest.manifest_digest != derive_evaluation_admission_manifest_digest(manifest):
        raise EvaluationSharedSpendError("admission manifest digest is not canonical")
    plan = manifest.plan_manifest
    expected = (
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
    )
    actual = (
        authority.admission_manifest_digest,
        authority.plan_manifest_digest,
        authority.baseline_digests,
        authority.feasibility_digest,
        authority.observation_set_digest,
        authority.readiness_set_digest,
        authority.validation_context_digest,
        authority.custody_log_digest,
        authority.attempt_history_head_digest,
        authority.admission_review_digest,
    )
    if actual != expected:
        raise EvaluationSharedSpendError("authority does not match the complete reviewed admission graph")


def _validate_preparation_graph(
    manifest: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    context: AdmissionValidationContext,
) -> str:
    if type(manifest) is not EvaluationAdmissionManifestV3 or type(preparation) is not EvaluationPreparationV3:
        raise EvaluationSharedSpendError("manifest and preparation must use exact V3 contract types")
    if type(context) is not AdmissionValidationContext:
        raise EvaluationSharedSpendError("validation context must use exact AdmissionValidationContext")
    _validate_context(context)
    preparation.__post_init__()
    _validate_authority_binding(manifest, preparation.authority, context)
    population = manifest.plan_manifest.declaration.population_digest
    if preparation.label_release_request.population_digest != population:
        raise EvaluationSharedSpendError("label-release request population differs from the reviewed plan")
    return population


def validate_evaluation_preparation(
    manifest: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> None:
    """Validate the exact graph and current available head before an external CAS."""
    try:
        population = _validate_preparation_graph(manifest, preparation, context)
        current = custody.current_log(population)
        validate_population_custody_log(current, context.evidence.custody_policy, current=custody)
        if current.log_digest != preparation.authority.custody_log_digest or current.status is not PopulationStatus.AVAILABLE:
            raise EvaluationSharedSpendError("preparation custody head is stale or unavailable")
        latest = custody.current_log(population)
        if latest.log_digest != current.log_digest or latest.status is not PopulationStatus.AVAILABLE:
            raise EvaluationSharedSpendError("custody changed during evaluation preparation validation")
    except EvaluationSharedSpendError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationSharedSpendError(f"evaluation preparation validation refused: {exc}") from exc


def prepare_evaluation_spend(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> EvaluationPreparationV3:
    """Build a pure all-arm request against the exact current available head."""
    try:
        if type(manifest) is not EvaluationAdmissionManifestV3 or type(authority) is not EvaluationAdmissionAuthorityV3:
            raise EvaluationSharedSpendError("manifest and authority must use exact V3 contract types")
        if type(context) is not AdmissionValidationContext:
            raise EvaluationSharedSpendError("validation context must use exact AdmissionValidationContext")
        _validate_context(context)
        _validate_authority_binding(manifest, authority, context)
        population = manifest.plan_manifest.declaration.population_digest
        current = custody.current_log(population)
        validate_population_custody_log(current, context.evidence.custody_policy, current=custody)
        if current.log_digest != authority.custody_log_digest or current.status is not PopulationStatus.AVAILABLE:
            raise EvaluationSharedSpendError("preparation custody head is stale or unavailable")
        request = PopulationUseRequest(
            population,
            authority.plan_manifest_digest,
            LineagePurpose.ADMISSION_LABEL_OPEN,
            True,
            authority.authority_digest,
            authority.custody_log_digest,
        )
        preparation = EvaluationPreparationV3(authority, request, authority.baseline_digests, "")
        validate_evaluation_preparation(manifest, preparation, context, custody)
        return preparation
    except EvaluationSharedSpendError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationSharedSpendError(f"evaluation preparation refused: {exc}") from exc


def _exact_successor_receipt(
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt | None,
) -> PopulationUseReceipt:
    if receipt is None:
        raise EvaluationSharedSpendError("shared-spend receipt is missing")
    if type(receipt) is not PopulationUseReceipt:
        raise EvaluationSharedSpendError("shared-spend receipt must use exact PopulationUseReceipt")
    if receipt.prior_status is not PopulationStatus.AVAILABLE or receipt.status is not PopulationStatus.SPENT:
        raise EvaluationSharedSpendError("shared-spend receipt must change available to spent")
    if receipt.request != preparation.label_release_request:
        raise EvaluationSharedSpendError("shared-spend receipt does not match the preparation")
    return receipt


def _current_spent_successor(
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> PopulationCustodyLog:
    population = preparation.label_release_request.population_digest
    current = custody.current_log(population)
    validate_population_custody_log(current, context.evidence.custody_policy, current=custody)
    is_head = bool(current.receipts) and current.receipts[-1] == receipt
    if not is_head or current.receipt_count != receipt.sequence or current.status is not PopulationStatus.SPENT:
        raise EvaluationSharedSpendError("shared-spend receipt is not the current-chain direct successor")
    return current


def bind_evaluation_spend(
    manifest: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt | None,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> EvaluationSpendBindingV3:
    """Bind only the exact current AVAILABLE-to-SPENT successor for all arms."""
    try:
        population = _validate_preparation_graph(manifest, preparation, context)
        exact_receipt = _exact_successor_receipt(preparation, receipt)
        current = _current_spent_successor(preparation, exact_receipt, context, custody)
        binding = EvaluationSpendBindingV3(
            preparation.preparation_digest,
            exact_receipt.receipt_digest,
            preparation.planned_baseline_digests,
            "",
        )
        latest = custody.current_log(population)
        if latest.log_digest != current.log_digest or latest.status is not PopulationStatus.SPENT:
            raise EvaluationSharedSpendError("shared-spend receipt is no longer the current-chain direct successor")
        return binding
    except EvaluationSharedSpendError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationSharedSpendError(f"evaluation shared spend refused: {exc}") from exc


__all__ = [
    "EvaluationPreparationV3",
    "EvaluationSharedSpendError",
    "EvaluationSpendBindingV3",
    "bind_evaluation_spend",
    "derive_evaluation_preparation_digest",
    "derive_evaluation_spend_binding_digest",
    "prepare_evaluation_spend",
    "validate_evaluation_preparation",
]
