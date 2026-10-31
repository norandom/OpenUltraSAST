"""Pure append-only population custody contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from openultrasast.core import canonical

CUSTODY_LOG_SCHEMA = "openultrasast.detection-core.population-custody-log.v2"
CUSTODY_POLICY_SCHEMA = "openultrasast.detection-core.population-custody-policy.v2"
CUSTODY_REQUEST_SCHEMA = "openultrasast.detection-core.population-use-request.v2"
CUSTODY_RECEIPT_SCHEMA = "openultrasast.detection-core.population-use-receipt.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _require_digest(value: object, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise canonical.DigestFormatError(f"{field_name} must be a full lowercase SHA-256 digest")


def _require_text(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be nonempty text")


class PopulationCustodyError(ValueError):
    """A population custody chain or compare-and-swap request is invalid."""


class LineagePurpose(Enum):
    PROMPT = "prompt"
    EXAMPLE = "example"
    THRESHOLD = "threshold"
    FITTED_MODEL = "fitted_model"
    SEMANTIC_FACT = "semantic_fact"
    MATCHING_BEHAVIOR = "matching_behavior"
    DECISION_MAPPING = "decision_mapping"
    PROMOTION = "promotion"
    ADMISSION_LABEL_OPEN = "admission_label_open"


class PopulationStatus(Enum):
    AVAILABLE = "available"
    SPENT = "spent"


@dataclass(frozen=True)
class PopulationUseRequest:
    population_digest: str
    arm_id: str
    purpose: LineagePurpose
    labels_accessed: bool
    influenced_artifact_digest: str | None
    expected_log_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.population_digest, "population_digest")
        _require_text(self.arm_id, "arm_id")
        if not isinstance(self.purpose, LineagePurpose):
            raise TypeError("purpose must be a LineagePurpose")
        if not isinstance(self.labels_accessed, bool):
            raise TypeError("labels_accessed must be boolean")
        if self.influenced_artifact_digest is not None:
            _require_digest(self.influenced_artifact_digest, "influenced_artifact_digest")
        _require_digest(self.expected_log_digest, "expected_log_digest")


@dataclass(frozen=True)
class PopulationUseReceipt:
    request: PopulationUseRequest
    request_digest: str
    population_digest: str
    custodian_identity: str
    sequence: int
    predecessor_digest: str | None
    prior_status: PopulationStatus
    status: PopulationStatus
    reasons: tuple[str, ...]
    receipt_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, PopulationUseRequest):
            raise TypeError("request must be a PopulationUseRequest")
        for name in ("request_digest", "population_digest", "custodian_identity", "receipt_digest"):
            _require_digest(getattr(self, name), name)
        if self.predecessor_digest is not None:
            _require_digest(self.predecessor_digest, "predecessor_digest")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence <= 0:
            raise ValueError("sequence must be a positive integer")
        if not isinstance(self.prior_status, PopulationStatus) or not isinstance(self.status, PopulationStatus):
            raise TypeError("receipt status must be a PopulationStatus")
        if not isinstance(self.reasons, tuple) or not all(isinstance(reason, str) and reason for reason in self.reasons):
            raise TypeError("reasons must be a tuple of nonempty text")


@dataclass(frozen=True)
class PopulationCustodyPolicy:
    reviewed_custodian_digests: tuple[str, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.reviewed_custodian_digests, tuple) or not self.reviewed_custodian_digests:
            raise ValueError("reviewed_custodian_digests must be a nonempty tuple")
        for digest in self.reviewed_custodian_digests:
            _require_digest(digest, "reviewed_custodian_digest")
        if len(set(self.reviewed_custodian_digests)) != len(self.reviewed_custodian_digests):
            raise ValueError("reviewed_custodian_digests must be unique")
        _require_digest(self.policy_digest, "policy_digest")


@dataclass(frozen=True)
class PopulationCustodyLog:
    population_digest: str
    custodian_identity: str
    receipts: tuple[PopulationUseReceipt, ...]
    receipt_count: int
    head_receipt_digest: str | None
    status: PopulationStatus
    log_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.population_digest, "population_digest")
        _require_digest(self.custodian_identity, "custodian_identity")
        if not isinstance(self.receipts, tuple) or not all(isinstance(item, PopulationUseReceipt) for item in self.receipts):
            raise TypeError("receipts must be a tuple of PopulationUseReceipt values")
        if isinstance(self.receipt_count, bool) or not isinstance(self.receipt_count, int) or self.receipt_count < 0:
            raise ValueError("receipt_count must be a nonnegative integer")
        if self.head_receipt_digest is not None:
            _require_digest(self.head_receipt_digest, "head_receipt_digest")
        if not isinstance(self.status, PopulationStatus):
            raise TypeError("status must be a PopulationStatus")
        _require_digest(self.log_digest, "log_digest")


class PopulationCustodyPort(Protocol):
    def current_log(self, population_digest: str) -> PopulationCustodyLog: ...


def _request_value(request: PopulationUseRequest) -> canonical.JsonValue:
    return {
        "schema_version": CUSTODY_REQUEST_SCHEMA,
        "population_digest": request.population_digest,
        "arm_id": request.arm_id,
        "purpose": request.purpose.value,
        "labels_accessed": request.labels_accessed,
        "influenced_artifact_digest": request.influenced_artifact_digest,
        "expected_log_digest": request.expected_log_digest,
    }


def derive_population_use_request_digest(request: PopulationUseRequest) -> str:
    return canonical.content_digest(_request_value(request))


def _receipt_value(receipt: PopulationUseReceipt) -> canonical.JsonValue:
    return {
        "schema_version": CUSTODY_RECEIPT_SCHEMA,
        "request": _request_value(receipt.request),
        "request_digest": receipt.request_digest,
        "population_digest": receipt.population_digest,
        "custodian_identity": receipt.custodian_identity,
        "sequence": receipt.sequence,
        "predecessor_digest": receipt.predecessor_digest,
        "prior_status": receipt.prior_status.value,
        "status": receipt.status.value,
        "reasons": receipt.reasons,
    }


def derive_population_use_receipt_digest(receipt: PopulationUseReceipt) -> str:
    return canonical.content_digest(_receipt_value(receipt))


def derive_population_custody_policy_digest(reviewed_custodian_digests: tuple[str, ...]) -> str:
    return canonical.content_digest(
        {"schema_version": CUSTODY_POLICY_SCHEMA, "reviewed_custodian_digests": tuple(sorted(reviewed_custodian_digests))}
    )


def _log_digest(population: str, custodian: str, receipts: tuple[PopulationUseReceipt, ...], status: PopulationStatus) -> str:
    return canonical.content_digest(
        {
            "schema_version": CUSTODY_LOG_SCHEMA,
            "population_digest": population,
            "custodian_identity": custodian,
            "receipt_digests": tuple(receipt.receipt_digest for receipt in receipts),
            "receipt_count": len(receipts),
            "head_receipt_digest": receipts[-1].receipt_digest if receipts else None,
            "status": status.value,
        }
    )


def empty_population_custody_log(population_digest: str, custodian_identity: str) -> PopulationCustodyLog:
    return PopulationCustodyLog(
        population_digest,
        custodian_identity,
        (),
        0,
        None,
        PopulationStatus.AVAILABLE,
        _log_digest(population_digest, custodian_identity, (), PopulationStatus.AVAILABLE),
    )


def _validate_custody_policy(policy: PopulationCustodyPolicy) -> None:
    expected = derive_population_custody_policy_digest(policy.reviewed_custodian_digests)
    if policy.policy_digest != expected:
        raise PopulationCustodyError("population custody policy digest cannot be re-derived")


def _validate_receipt_link(
    log: PopulationCustodyLog,
    receipt: PopulationUseReceipt,
    sequence: int,
    prefix: tuple[PopulationUseReceipt, ...],
    status: PopulationStatus,
) -> None:
    predecessor = prefix[-1].receipt_digest if prefix else None
    if receipt.sequence != sequence:
        raise PopulationCustodyError("receipt sequence is not contiguous")
    if receipt.predecessor_digest != predecessor:
        raise PopulationCustodyError("receipt predecessor does not match complete chain")
    if receipt.population_digest != log.population_digest or receipt.request.population_digest != log.population_digest:
        raise PopulationCustodyError("receipt population does not match log")
    if receipt.custodian_identity != log.custodian_identity:
        raise PopulationCustodyError("receipt custodian does not match log")
    expected = _log_digest(log.population_digest, log.custodian_identity, prefix, status)
    if receipt.request.expected_log_digest != expected:
        raise PopulationCustodyError("receipt expected log does not match prefix")


def _validate_receipt_identity(receipt: PopulationUseReceipt, status: PopulationStatus) -> PopulationStatus:
    expected_status = PopulationStatus.SPENT if status is PopulationStatus.SPENT or receipt.request.labels_accessed else status
    if receipt.prior_status is not status or receipt.status is not expected_status:
        raise PopulationCustodyError("receipt status is not monotonic")
    expected_reasons = ("labels_accessed",) if receipt.request.labels_accessed else ()
    if status is PopulationStatus.SPENT and not receipt.request.labels_accessed:
        expected_reasons = ("population_already_spent",)
    if receipt.reasons != expected_reasons:
        raise PopulationCustodyError("receipt reasons do not match status transition")
    if receipt.request_digest != derive_population_use_request_digest(receipt.request):
        raise PopulationCustodyError("request digest cannot be re-derived")
    if receipt.receipt_digest != derive_population_use_receipt_digest(receipt):
        raise PopulationCustodyError("receipt digest cannot be re-derived")
    return expected_status


def _validate_log_metadata(log: PopulationCustodyLog, status: PopulationStatus) -> None:
    if log.receipt_count != len(log.receipts):
        raise PopulationCustodyError("receipt count does not match complete chain")
    head = log.receipts[-1].receipt_digest if log.receipts else None
    if log.head_receipt_digest != head:
        raise PopulationCustodyError("head receipt does not match complete chain")
    if log.status is not status:
        raise PopulationCustodyError("log status does not match receipt chain")
    if log.log_digest != _log_digest(log.population_digest, log.custodian_identity, log.receipts, status):
        raise PopulationCustodyError("log digest cannot be re-derived")


def validate_population_custody_log(
    log: PopulationCustodyLog,
    policy: PopulationCustodyPolicy,
    *,
    current: PopulationCustodyPort | None = None,
) -> None:
    _validate_custody_policy(policy)
    if log.custodian_identity not in policy.reviewed_custodian_digests:
        raise PopulationCustodyError("population custodian is not reviewed")
    status = PopulationStatus.AVAILABLE
    prefix: tuple[PopulationUseReceipt, ...] = ()
    for sequence, receipt in enumerate(log.receipts, 1):
        _validate_receipt_link(log, receipt, sequence, prefix, status)
        status = _validate_receipt_identity(receipt, status)
        prefix = (*prefix, receipt)
    _validate_log_metadata(log, status)
    if current is not None:
        current_log = current.current_log(log.population_digest)
        validate_population_custody_log(current_log, policy)
        if current_log.log_digest != log.log_digest:
            raise PopulationCustodyError("candidate is not the current complete log")


def record_population_use(
    request: PopulationUseRequest,
    prior: PopulationCustodyLog,
    custodian_identity: str,
    policy: PopulationCustodyPolicy,
) -> PopulationUseReceipt:
    validate_population_custody_log(prior, policy)
    if custodian_identity not in policy.reviewed_custodian_digests:
        raise PopulationCustodyError("population custodian is not reviewed")
    if custodian_identity != prior.custodian_identity:
        raise PopulationCustodyError("population custodian does not match log")
    if request.population_digest != prior.population_digest:
        raise PopulationCustodyError("request population does not match log")
    if request.expected_log_digest != prior.log_digest:
        raise PopulationCustodyError("request expected log does not match current head")
    status = PopulationStatus.SPENT if prior.status is PopulationStatus.SPENT or request.labels_accessed else prior.status
    reasons: tuple[str, ...]
    if request.labels_accessed:
        reasons = ("labels_accessed",)
    else:
        reasons = ("population_already_spent",) if prior.status is PopulationStatus.SPENT else ()
    provisional = PopulationUseReceipt(
        request,
        derive_population_use_request_digest(request),
        prior.population_digest,
        custodian_identity,
        prior.receipt_count + 1,
        prior.head_receipt_digest,
        prior.status,
        status,
        reasons,
        "0" * 64,
    )
    return replace(provisional, receipt_digest=derive_population_use_receipt_digest(provisional))


def append_population_use(
    prior: PopulationCustodyLog, receipt: PopulationUseReceipt, policy: PopulationCustodyPolicy
) -> PopulationCustodyLog:
    validate_population_custody_log(prior, policy)
    if receipt.request.expected_log_digest != prior.log_digest:
        raise PopulationCustodyError("receipt expected log does not match prior log")
    receipts = (*prior.receipts, receipt)
    provisional = PopulationCustodyLog(
        prior.population_digest,
        prior.custodian_identity,
        receipts,
        len(receipts),
        receipt.receipt_digest,
        receipt.status,
        "0" * 64,
    )
    result = replace(
        provisional,
        log_digest=_log_digest(provisional.population_digest, provisional.custodian_identity, receipts, provisional.status),
    )
    validate_population_custody_log(result, policy)
    return result


__all__ = [
    "LineagePurpose",
    "PopulationCustodyError",
    "PopulationCustodyLog",
    "PopulationCustodyPolicy",
    "PopulationCustodyPort",
    "PopulationStatus",
    "PopulationUseReceipt",
    "PopulationUseRequest",
    "append_population_use",
    "derive_population_custody_policy_digest",
    "derive_population_use_receipt_digest",
    "derive_population_use_request_digest",
    "empty_population_custody_log",
    "record_population_use",
    "validate_population_custody_log",
]
