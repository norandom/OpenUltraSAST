"""Pure spend-before-label authorization for admission scoring."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._closed_graph import exact_dataclass_problem
from openultrasast.core.admission_context import AdmissionValidationContext, validate_admission_context
from openultrasast.core.admission_feasibility import evaluate_threshold_feasibility
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationStatus,
    PopulationUseReceipt,
    PopulationUseRequest,
    append_population_use,
    derive_population_use_request_digest,
    empty_population_custody_log,
    validate_population_custody_log,
)
from openultrasast.core.measurement import DenominatorPolicy
from openultrasast.core.readiness import ReadinessResult

ADMISSION_AUTHORIZATION_SCHEMA = "openultrasast.detection-core.admission-authorization.v2"
ADMISSION_PREPARATION_SCHEMA = "openultrasast.detection-core.admission-preparation.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class AdmissionSpendError(ValueError):
    """The pre-label population spend cannot authorize scoring."""


@dataclass(frozen=True)
class AdmissionAuthorization:
    manifest_digest: str
    validation_context_digest: str
    readiness_digests: tuple[str, ...]
    custody_log_digest: str
    feasibility_digest: str
    authorization_digest: str


@dataclass(frozen=True)
class AdmissionPreparation:
    authorization: AdmissionAuthorization
    label_release_request: PopulationUseRequest
    preparation_digest: str


@dataclass(frozen=True)
class _HistoricalCustody:
    current: PopulationCustodyPort
    population_digest: str
    historical_log: PopulationCustodyLog

    def current_log(self, population_digest: str) -> PopulationCustodyLog:
        if population_digest == self.population_digest:
            return self.historical_log
        return self.current.current_log(population_digest)


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionSpendError(f"{field} must be a full lowercase SHA-256 digest")


def _authorization_value(authorization: AdmissionAuthorization) -> canonical.JsonValue:
    return {
        "schema_version": ADMISSION_AUTHORIZATION_SCHEMA,
        "manifest_digest": authorization.manifest_digest,
        "validation_context_digest": authorization.validation_context_digest,
        "readiness_digests": authorization.readiness_digests,
        "custody_log_digest": authorization.custody_log_digest,
        "feasibility_digest": authorization.feasibility_digest,
    }


def derive_admission_authorization_digest(authorization: AdmissionAuthorization) -> str:
    return canonical.content_digest(_authorization_value(authorization))


def _preparation_value(preparation: AdmissionPreparation) -> canonical.JsonValue:
    return {
        "schema_version": ADMISSION_PREPARATION_SCHEMA,
        "authorization": _authorization_value(preparation.authorization),
        "authorization_digest": preparation.authorization.authorization_digest,
        "label_release_request_digest": derive_population_use_request_digest(preparation.label_release_request),
    }


def derive_admission_preparation_digest(preparation: AdmissionPreparation) -> str:
    return canonical.content_digest(_preparation_value(preparation))


def _validate_authorization(authorization: AdmissionAuthorization) -> None:
    problem = exact_dataclass_problem(authorization, AdmissionAuthorization, "admission authorization")
    if problem is not None:
        raise AdmissionSpendError(f"closed admission authorization violation: {problem}")
    for field in (
        "manifest_digest",
        "validation_context_digest",
        "custody_log_digest",
        "feasibility_digest",
        "authorization_digest",
    ):
        _require_digest(getattr(authorization, field), field)
    if type(authorization.readiness_digests) is not tuple:
        raise AdmissionSpendError("readiness digests must be an exact tuple")
    for digest in authorization.readiness_digests:
        _require_digest(digest, "readiness digest")
    if authorization.readiness_digests != tuple(sorted(set(authorization.readiness_digests))):
        raise AdmissionSpendError("readiness digests must be unique and canonical")
    if authorization.authorization_digest != derive_admission_authorization_digest(authorization):
        raise AdmissionSpendError("admission authorization digest cannot be re-derived")


def _validate_preparation(preparation: AdmissionPreparation) -> None:
    problem = exact_dataclass_problem(preparation, AdmissionPreparation, "admission preparation")
    if problem is not None:
        raise AdmissionSpendError(f"closed admission preparation violation: {problem}")
    _validate_authorization(preparation.authorization)
    request = preparation.label_release_request
    if type(request) is not PopulationUseRequest:
        raise AdmissionSpendError("label-release request must be exact")
    authorization = preparation.authorization
    expected = (
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        authorization.authorization_digest,
        authorization.custody_log_digest,
    )
    actual = (request.purpose, request.labels_accessed, request.influenced_artifact_digest, request.expected_log_digest)
    if actual != expected:
        raise AdmissionSpendError("label-release request does not match exact authorization")
    _require_digest(preparation.preparation_digest, "preparation_digest")
    if preparation.preparation_digest != derive_admission_preparation_digest(preparation):
        raise AdmissionSpendError("admission preparation digest cannot be re-derived")


def _make_authorization(
    manifest: AdmissionManifestV2,
    context: AdmissionValidationContext,
    custody_log_digest: str,
    feasibility_digest: str,
) -> AdmissionAuthorization:
    provisional = AdmissionAuthorization(
        manifest.manifest_digest,
        context.context_digest,
        manifest.readiness_digests,
        custody_log_digest,
        feasibility_digest,
        "0" * 64,
    )
    return AdmissionAuthorization(
        provisional.manifest_digest,
        provisional.validation_context_digest,
        provisional.readiness_digests,
        provisional.custody_log_digest,
        provisional.feasibility_digest,
        derive_admission_authorization_digest(provisional),
    )


def _make_preparation(manifest: AdmissionManifestV2, authorization: AdmissionAuthorization) -> AdmissionPreparation:
    request = PopulationUseRequest(
        manifest.identity.population_digest,
        manifest.identity.arm_id,
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        authorization.authorization_digest,
        authorization.custody_log_digest,
    )
    provisional = AdmissionPreparation(authorization, request, "0" * 64)
    return AdmissionPreparation(authorization, request, derive_admission_preparation_digest(provisional))


def authorize_admission(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionPreparation:
    """Revalidate label-blind inputs and return a pure head-bound release request."""
    try:
        validate_admission_context(manifest, denominator, readiness, context, custody, resolver)
        feasibility = evaluate_threshold_feasibility(manifest, denominator, context.admission_review_policy, resolver)
        current = custody.current_log(manifest.identity.population_digest)
        validate_population_custody_log(current, context.evidence.custody_policy, current=custody)
        if current.log_digest != manifest.custody_log_digest or current.status is not PopulationStatus.AVAILABLE:
            raise AdmissionSpendError("authorization custody head is stale or unavailable")
        authorization = _make_authorization(manifest, context, current.log_digest, feasibility.feasibility_digest)
        preparation = _make_preparation(manifest, authorization)
        _validate_preparation(preparation)
        return preparation
    except AdmissionSpendError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionSpendError(f"admission authorization refused: {exc}") from exc


def _historical_log(
    current: PopulationCustodyLog,
    expected_digest: str,
    policy: PopulationCustodyPolicy,
) -> PopulationCustodyLog:
    historical = empty_population_custody_log(current.population_digest, current.custodian_identity)
    if historical.log_digest == expected_digest:
        return historical
    for receipt in current.receipts:
        historical = append_population_use(historical, receipt, policy)
        if historical.log_digest == expected_digest:
            return historical
    raise AdmissionSpendError("authorization custody head is not in the current complete chain")


def _canonical_preparation(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[AdmissionPreparation, PopulationCustodyLog]:
    population = manifest.identity.population_digest
    current = custody.current_log(population)
    policy = context.evidence.custody_policy
    validate_population_custody_log(current, policy, current=custody)
    historical = _historical_log(current, manifest.custody_log_digest, policy)
    view = _HistoricalCustody(custody, population, historical)
    expected = authorize_admission(manifest, denominator, readiness, context, view, resolver)
    return expected, current


def validate_pre_label_spend(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt | None,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionAuthorization:
    """Authorize scoring only for the exact current AVAILABLE-to-SPENT successor."""
    try:
        _validate_preparation(preparation)
        expected, current = _canonical_preparation(manifest, denominator, readiness, context, custody, resolver)
        if preparation != expected:
            raise AdmissionSpendError("supplied value is not the canonical preparation")
        if receipt is None:
            raise AdmissionSpendError("label-release spend receipt is missing")
        if type(receipt) is not PopulationUseReceipt:
            raise AdmissionSpendError("label-release spend receipt must be exact")
        if receipt.prior_status is not PopulationStatus.AVAILABLE or receipt.status is not PopulationStatus.SPENT:
            raise AdmissionSpendError("label-release receipt must change available to spent")
        if receipt.request != preparation.label_release_request:
            raise AdmissionSpendError("label-release receipt does not match preparation")
        is_head = bool(current.receipts) and current.receipts[-1] == receipt
        if not is_head or current.receipt_count != receipt.sequence or current.status is not PopulationStatus.SPENT:
            raise AdmissionSpendError("label-release receipt is not the current-chain direct successor")
        if custody.current_log(current.population_digest).log_digest != current.log_digest:
            raise AdmissionSpendError("label-release receipt is no longer the current-chain direct successor")
        return preparation.authorization
    except AdmissionSpendError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionSpendError(f"label-release spend refused: {exc}") from exc


__all__ = [
    "ADMISSION_AUTHORIZATION_SCHEMA",
    "ADMISSION_PREPARATION_SCHEMA",
    "AdmissionAuthorization",
    "AdmissionPreparation",
    "AdmissionSpendError",
    "authorize_admission",
    "derive_admission_authorization_digest",
    "derive_admission_preparation_digest",
    "validate_pre_label_spend",
]
