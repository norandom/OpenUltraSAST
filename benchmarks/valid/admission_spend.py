"""Task 8.3 admission spend: commit custody before any label byte opens.

The spend phase conditionally appends the exact available-to-spent custody
successor, rereads it as the committed head, and only then opens nonzero
sealed-label bytes inside the custodian boundary. It joins the opened ground
truth to the frozen custodian-sealed observations without exposing labels to
arms, binds every released case to its exact scope, role, pair, result,
evidence, change inputs, observation, and reviewed admission manifest, and
requires one independent post-spend release review before the closed release
bound to the committed receipt may reach scoring.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from benchmarks.valid.admission_execution import AdmissionExecutionV1
from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadAuthority,
    ArtifactReadPermission,
    ArtifactRepositoryError,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.durable_custody_store import DurableCustodyStoreError
from benchmarks.valid.population_material_contract import SEALED_LABEL_SCHEMA
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
    canonical_json_bytes,
)
from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.canonical import JsonValue
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyError,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationStatus,
    PopulationUseReceipt,
    PopulationUseRequest,
    append_population_use,
    record_population_use,
    validate_population_custody_log,
)
from openultrasast.core.evaluation_authority import EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_observation import (
    SealedObservationRefV3,
    decode_arm_observation_set,
)
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

CASE_RELEASE_DOCUMENT_SCHEMA = "openultrasast.valid-detection-benchmark.case-release.v1"
GROUND_TRUTH_LABEL_SCHEMA = "openultrasast.valid-detection-benchmark.ground-truth-label.v1"
SEALED_LABEL_OBJECT_SCHEMA = SEALED_LABEL_SCHEMA
LABEL_OPEN_ARM_ID = "valid-detection-benchmark.admission-spend"
_SEALED = ArtifactAccessClass.CUSTODIAN_SEALED
_ZERO = "0" * 64
_DIGEST = re.compile(r"[0-9a-f]{64}")
_RECORD_FIELDS = frozenset({"change_digest", "label_digest", "judgment_digest", "label_base64", "judgment_base64"})
_LABEL_FIELDS = frozenset({"role", "pair_id_digest", "family_id", "ecosystem"})
_TRUTH_ROLES = frozenset({AdmissionCaseRole.VULNERABLE.value, AdmissionCaseRole.FIXED.value})


class AdmissionSpendReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    AUTHORIZATION_REFUSED = "authorization_refused"
    CUSTODY_HEAD_UNAVAILABLE = "custody_head_unavailable"
    CUSTODY_CONFLICT = "custody_conflict"
    CUSTODY_UNREADABLE = "custody_unreadable"
    LABELS_UNREADABLE = "labels_unreadable"
    OBSERVATIONS_UNREADABLE = "observations_unreadable"
    JOIN_INCOMPLETE = "join_incomplete"
    REVIEW_REQUIRED = "review_required"
    PERSISTENCE_FAILED = "persistence_failed"


class AdmissionSpendError(RuntimeError):
    """Refuse a spend or release step with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionSpendReason) -> None:
        self.reason = reason
        super().__init__(f"admission_spend_{reason.value}")


def _refused(reason: AdmissionSpendReason) -> AdmissionSpendError:
    return AdmissionSpendError(reason)


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refused(AdmissionSpendReason.INVALID_REQUEST)
    return value


class CustodyCompareAndSwap(PopulationCustodyPort, Protocol):
    """Durable custody seam owning the monotonic head transitions."""

    def compare_and_swap(self, expected_log_digest: str, replacement: PopulationCustodyLog) -> bool: ...


@dataclass(frozen=True)
class GroundTruthLabelV1:
    """One decoded sealed-label row; custodian boundary only."""

    change_digest: str
    role: AdmissionCaseRole
    pair_id_digest: str
    family_id: str
    ecosystem: str
    label_digest: str
    judgment_digest: str

    def __post_init__(self) -> None:
        for field in ("change_digest", "pair_id_digest", "label_digest", "judgment_digest"):
            _digest(getattr(self, field))
        if type(self.role) is not AdmissionCaseRole or self.role.value not in _TRUTH_ROLES:
            raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
        for field in ("family_id", "ecosystem"):
            if type(getattr(self, field)) is not str or not getattr(self, field) or len(getattr(self, field)) > 128:
                raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)


@dataclass(frozen=True)
class ReleasedCaseV1:
    """Closed digest-bound post-spend case binding; the sole scoring input."""

    arm_id: str
    input_identity_digest: str
    case_id_digest: str
    case_input_digest: str
    underlying_push_digest: str
    result_digest: str
    read_receipt_digest: str
    role: AdmissionCaseRole
    pair_id_digest: str | None
    family_id: str
    ecosystem: str
    label_digest: str
    judgment_digest: str
    observation_slot_digest: str
    observation_digest: str
    manifest_digest: str
    case_digest: str

    def __post_init__(self) -> None:
        for field in (
            "input_identity_digest",
            "case_id_digest",
            "case_input_digest",
            "underlying_push_digest",
            "result_digest",
            "read_receipt_digest",
            "label_digest",
            "judgment_digest",
            "observation_slot_digest",
            "observation_digest",
            "manifest_digest",
        ):
            _digest(getattr(self, field))
        if type(self.arm_id) is not str or not self.arm_id or len(self.arm_id) > 128:
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        if type(self.role) is not AdmissionCaseRole:
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        labeled = self.role is not AdmissionCaseRole.ORDINARY
        if labeled:
            _digest(self.pair_id_digest)
            if not self.family_id or not self.ecosystem or _ZERO in (self.label_digest, self.judgment_digest):
                raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        elif (
            self.pair_id_digest is not None
            or self.family_id != ""
            or self.ecosystem != ""
            or _ZERO not in (self.label_digest, self.judgment_digest)
        ):
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        expected = canonical.content_digest(_case_value(self))
        if self.case_digest == "":
            object.__setattr__(self, "case_digest", expected)
        elif _digest(self.case_digest) != expected:
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)


def _case_value(row: ReleasedCaseV1) -> dict[str, JsonValue]:
    return {
        "arm_id": row.arm_id,
        "input_identity_digest": row.input_identity_digest,
        "case_id_digest": row.case_id_digest,
        "case_input_digest": row.case_input_digest,
        "underlying_push_digest": row.underlying_push_digest,
        "result_digest": row.result_digest,
        "read_receipt_digest": row.read_receipt_digest,
        "role": row.role.value,
        "pair_id_digest": row.pair_id_digest,
        "family_id": row.family_id,
        "ecosystem": row.ecosystem,
        "label_digest": row.label_digest,
        "judgment_digest": row.judgment_digest,
        "observation_slot_digest": row.observation_slot_digest,
        "observation_digest": row.observation_digest,
        "manifest_digest": row.manifest_digest,
    }


@dataclass(frozen=True)
class AdmissionSpendRequestV1:
    """Every custodian authority the spend phase needs after execution."""

    execution: AdmissionExecutionV1
    custody: CustodyCompareAndSwap
    repository: S3ArtifactRepository
    custodian_access_policy_digest: str
    custody_policy: PopulationCustodyPolicy
    custodian_identity: str
    population_digest: str
    positive_change_digests: tuple[str, ...]
    scope_census: tuple[tuple[str, str, int], ...]
    load_labels: Callable[[], bytes]
    review: IndependenceAttestation | None
    review_policy: ReviewIndependencePolicy
    resolver: canonical.ContentResolver


@dataclass(frozen=True)
class AdmissionSpendReleaseV1:
    """Closed spend product; only a reviewed release bound to the receipt scores."""

    refusal_reason: AdmissionSpendReason | None
    custody_receipt_digest: str
    labels_spent: bool
    label_bytes_read: int
    label_bytes_digest: str
    released_cases: tuple[ReleasedCaseV1, ...]
    review_reference: ArtifactReference | None
    release_digest: str

    def __post_init__(self) -> None:
        if type(self.label_bytes_read) is not int or self.label_bytes_read < 0:
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        if self.refusal_reason is None:
            if (
                not self.labels_spent
                or self.label_bytes_read == 0
                or not self.released_cases
                or self.review_reference is None
                or not self.release_digest
            ):
                raise _refused(AdmissionSpendReason.INVALID_REQUEST)
            _digest(self.custody_receipt_digest)
            _digest(self.label_bytes_digest)
        elif self.labels_spent:
            _digest(self.custody_receipt_digest)
            if self.label_bytes_read and not self.label_bytes_digest:
                raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        elif (
            self.custody_receipt_digest
            or self.label_bytes_read
            or self.label_bytes_digest
            or self.released_cases
            or self.review_reference is not None
            or self.release_digest
        ):
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)


def _validated_request(request: AdmissionSpendRequestV1) -> None:
    if (
        type(request) is not AdmissionSpendRequestV1
        or type(request.execution) is not AdmissionExecutionV1
        or type(request.repository) is not S3ArtifactRepository
        or type(request.custody_policy) is not PopulationCustodyPolicy
        or type(request.positive_change_digests) is not tuple
        or not request.positive_change_digests
        or type(request.scope_census) is not tuple
        or not request.scope_census
        or not callable(request.load_labels)
        or not callable(getattr(request.custody, "current_log", None))
        or not callable(getattr(request.custody, "compare_and_swap", None))
        or not callable(getattr(request.resolver, "resolve", None))
        or (request.review is not None and type(request.review) is not IndependenceAttestation)
        or type(request.review_policy) is not ReviewIndependencePolicy
    ):
        raise _refused(AdmissionSpendReason.INVALID_REQUEST)
    for digest in (
        request.custodian_access_policy_digest,
        request.custodian_identity,
        request.population_digest,
        *request.positive_change_digests,
    ):
        _digest(digest)
    seen: set[tuple[str, str]] = set()
    for family, ecosystem, count in request.scope_census:
        if (
            type(family) is not str
            or not family
            or len(family) > 128
            or type(ecosystem) is not str
            or not ecosystem
            or len(ecosystem) > 128
            or type(count) is not int
            or count <= 0
            or (family, ecosystem) in seen
        ):
            raise _refused(AdmissionSpendReason.INVALID_REQUEST)
        seen.add((family, ecosystem))


def label_open_request(
    population_digest: str, admission_manifest_digest: str, custody_log_digest: str
) -> PopulationUseRequest:
    """Build the deterministic label-open request the exact successor appends."""
    return PopulationUseRequest(
        _digest(population_digest),
        LABEL_OPEN_ARM_ID,
        LineagePurpose.ADMISSION_LABEL_OPEN,
        True,
        _digest(admission_manifest_digest),
        _digest(custody_log_digest),
    )


def _decode_label_record(item: object) -> GroundTruthLabelV1:
    if type(item) is not dict or frozenset(item) != _RECORD_FIELDS:
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    try:
        label = base64.b64decode(item["label_base64"], validate=True)
        judgment = base64.b64decode(item["judgment_base64"], validate=True)
        truth = json.loads(label.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float)
        exact_truth = (
            type(truth) is dict
            and frozenset(truth) == _LABEL_FIELDS | {"schema_version"}
            and canonical_json_bytes(truth) == label
        )
    except (AttributeError, TypeError, ValueError, RecursionError):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE) from None
    if (
        not exact_truth
        or truth.get("schema_version") != GROUND_TRUTH_LABEL_SCHEMA
        or not judgment
        or canonical.bytes_digest(label) != item["label_digest"]
        or canonical.bytes_digest(judgment) != item["judgment_digest"]
    ):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    try:
        role = AdmissionCaseRole(truth["role"])
    except (TypeError, ValueError):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE) from None
    return GroundTruthLabelV1(
        _digest(item["change_digest"]),
        role,
        _digest(truth["pair_id_digest"]),
        truth["family_id"] if type(truth["family_id"]) is str else "",
        truth["ecosystem"] if type(truth["ecosystem"]) is str else "",
        _digest(item["label_digest"]),
        _digest(item["judgment_digest"]),
    )


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(text)
    return value


def decode_sealed_labels(raw: bytes) -> tuple[GroundTruthLabelV1, ...]:
    """Decode only the exact canonical custodian-sealed label object."""
    if type(raw) is not bytes or not raw:
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    try:
        document = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE) from None
    if (
        type(document) is not dict
        or document.get("schema_version") != SEALED_LABEL_OBJECT_SCHEMA
        or type(document.get("records")) is not list
        or not document["records"]
    ):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    rows = tuple(_decode_label_record(item) for item in document["records"])
    if len({row.change_digest for row in rows}) != len(rows):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    try:
        canonical_document = canonical_json_bytes(document) == raw
    except (TypeError, ValueError, RecursionError):
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE) from None
    if tuple(sorted(rows, key=lambda row: row.change_digest)) != rows or not canonical_document:
        raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
    return rows


def _custodian_authority(policy_digest: str) -> ArtifactReadAuthority:
    return artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.CUSTODIAN_SEALED,),
        policy_digest,
        expected_access_policy_digest=policy_digest,
    )


def _sealed_observation_document(
    repository: S3ArtifactRepository, policy: str, sealed: SealedObservationRefV3
) -> bytes:
    reference = ArtifactReference(
        ArtifactKind.OBSERVATION,
        sealed.observation.content_digest,
        sealed.observation.byte_length,
        sealed.observation_digest,
        _SEALED,
    )
    try:
        accepted = repository.get(
            reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=_custodian_authority(policy),
            expected_access_policy_digest=policy,
        )
    except ArtifactRepositoryError:
        raise _refused(AdmissionSpendReason.OBSERVATIONS_UNREADABLE) from None
    payload = accepted.artifact.payload
    if payload.get("observation_digest") != sealed.observation_digest:
        raise _refused(AdmissionSpendReason.OBSERVATIONS_UNREADABLE)
    try:
        document = payload.get("observation")
        if type(document) is not str or not document:
            raise _refused(AdmissionSpendReason.OBSERVATIONS_UNREADABLE)
        return document.encode("utf-8")
    except (TypeError, ValueError):
        raise _refused(AdmissionSpendReason.OBSERVATIONS_UNREADABLE) from None


def _validate_census(
    labels: tuple[GroundTruthLabelV1, ...], scope_census: tuple[tuple[str, str, int], ...]
) -> None:
    counts: dict[tuple[str, str], int] = {}
    for label in labels:
        key = (label.family_id, label.ecosystem)
        counts[key] = counts.get(key, 0) + 1
    if counts != {(family, ecosystem): count for family, ecosystem, count in scope_census}:
        raise _refused(AdmissionSpendReason.JOIN_INCOMPLETE)


def join_released_cases(
    execution: AdmissionExecutionV1,
    repository: S3ArtifactRepository,
    custodian_access_policy_digest: str,
    labels: tuple[GroundTruthLabelV1, ...],
    positive_change_digests: tuple[str, ...],
    scope_census: tuple[tuple[str, str, int], ...],
) -> tuple[ReleasedCaseV1, ...]:
    """Join opened ground truth to the frozen sealed observations, label-blind."""
    manifest = _authorized_manifest(execution)
    if type(labels) is not tuple or any(type(row) is not GroundTruthLabelV1 for row in labels):
        raise _refused(AdmissionSpendReason.INVALID_REQUEST)
    _validate_census(labels, scope_census)
    positives = frozenset(positive_change_digests)
    index: dict[str, GroundTruthLabelV1] = {}
    for label in labels:
        if label.change_digest in index or label.change_digest not in positives:
            raise _refused(AdmissionSpendReason.JOIN_INCOMPLETE)
        index[label.change_digest] = label
    cases: list[ReleasedCaseV1] = []
    seen: set[str] = set()
    for sealed in execution.sealed_observations:
        document = _sealed_observation_document(repository, custodian_access_policy_digest, sealed)
        try:
            observation = decode_arm_observation_set(document)
        except (ValueError, RecursionError):
            raise _refused(AdmissionSpendReason.OBSERVATIONS_UNREADABLE) from None
        for case in observation.cases:
            matched: GroundTruthLabelV1 | None = index.get(case.case_input_digest)
            if case.case_input_digest in positives and matched is None:
                raise _refused(AdmissionSpendReason.JOIN_INCOMPLETE)
            seen.add(case.case_input_digest)
            cases.append(
                ReleasedCaseV1(
                    sealed.arm_id,
                    sealed.input_identity_digest,
                    case.case_id_digest,
                    case.case_input_digest,
                    case.underlying_push_digest,
                    case.result_digest,
                    sealed.read_receipt_digest,
                    matched.role if matched is not None else AdmissionCaseRole.ORDINARY,
                    matched.pair_id_digest if matched is not None else None,
                    matched.family_id if matched is not None else "",
                    matched.ecosystem if matched is not None else "",
                    matched.label_digest if matched is not None else _ZERO,
                    matched.judgment_digest if matched is not None else _ZERO,
                    sealed.slot_digest,
                    sealed.observation_digest,
                    manifest.manifest_digest,
                    "",
                )
            )
    if not seen & positives or not cases:
        raise _refused(AdmissionSpendReason.JOIN_INCOMPLETE)
    return tuple(sorted(cases, key=lambda row: row.case_digest))


def _authorized_manifest(execution: AdmissionExecutionV1) -> EvaluationAdmissionManifestV3:
    authorization = execution.spend_authorization
    if (
        execution.refusal_reason is not None
        or execution.admission_manifest is None
        or authorization is None
        or authorization.may_spend is not True
    ):
        raise _refused(AdmissionSpendReason.AUTHORIZATION_REFUSED)
    return execution.admission_manifest


def _spend_custody(
    request: AdmissionSpendRequestV1, manifest: EvaluationAdmissionManifestV3
) -> PopulationUseReceipt:
    try:
        prior = request.custody.current_log(request.population_digest)
    except DurableCustodyStoreError:
        raise _refused(AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE) from None
    if (
        prior.population_digest != request.population_digest
        or prior.status is not PopulationStatus.AVAILABLE
        or prior.log_digest != manifest.custody_log_digest
    ):
        raise _refused(AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE)
    try:
        receipt = record_population_use(
            label_open_request(request.population_digest, manifest.manifest_digest, prior.log_digest),
            prior,
            request.custodian_identity,
            request.custody_policy,
        )
        successor = append_population_use(prior, receipt, request.custody_policy)
    except (PopulationCustodyError, TypeError, ValueError):
        raise _refused(AdmissionSpendReason.CUSTODY_HEAD_UNAVAILABLE) from None
    try:
        committed = request.custody.compare_and_swap(prior.log_digest, successor)
    except DurableCustodyStoreError:
        raise _refused(AdmissionSpendReason.CUSTODY_UNREADABLE) from None
    if committed is not True:
        raise _refused(AdmissionSpendReason.CUSTODY_CONFLICT)
    _reread_committed_successor(request, successor, receipt)
    return receipt


def _reread_committed_successor(
    request: AdmissionSpendRequestV1, successor: PopulationCustodyLog, receipt: PopulationUseReceipt
) -> None:
    try:
        head = request.custody.current_log(receipt.population_digest)
        validate_population_custody_log(head, request.custody_policy, current=request.custody)
    except (DurableCustodyStoreError, PopulationCustodyError, TypeError, ValueError):
        raise _refused(AdmissionSpendReason.CUSTODY_UNREADABLE) from None
    if (
        head.status is not PopulationStatus.SPENT
        or head.log_digest != successor.log_digest
        or head.receipt_count != receipt.sequence
        or not head.receipts
        or head.receipts[-1] != receipt
    ):
        raise _refused(AdmissionSpendReason.CUSTODY_UNREADABLE)


def _release_value(
    manifest_digest: str, receipt_digest: str, label_digest: str, label_read: int, case_digests: tuple[str, ...]
) -> dict[str, JsonValue]:
    return {
        "schema_version": CASE_RELEASE_DOCUMENT_SCHEMA,
        "admission_manifest_digest": manifest_digest,
        "custody_receipt_digest": receipt_digest,
        "label_bytes_digest": label_digest,
        "label_bytes_read": label_read,
        "case_digests": case_digests,
    }


def release_review_subject(
    admission_manifest_digest: str,
    custody_receipt_digest: str,
    released_cases: tuple[ReleasedCaseV1, ...],
    label_bytes: bytes,
) -> str:
    """Derive the deterministic subject an external post-spend review signs."""
    if type(label_bytes) is not bytes:
        raise _refused(AdmissionSpendReason.INVALID_REQUEST)
    return canonical.content_digest(
        _release_value(
            _digest(admission_manifest_digest),
            _digest(custody_receipt_digest),
            canonical.bytes_digest(label_bytes),
            len(label_bytes),
            tuple(row.case_digest for row in released_cases),
        )
    )


def _review_value(review: IndependenceAttestation) -> dict[str, JsonValue]:
    reference = review.conflict_disclosure
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": {
            "artifact_id": reference.artifact_id,
            "content_digest": reference.content_digest,
            "media_type": reference.media_type,
            "byte_length": reference.byte_length,
            "retention_policy_digest": reference.retention_policy_digest,
            "storage_receipt_digest": reference.storage_receipt_digest,
        },
        "attestation_digest": review.attestation_digest,
    }


def _validate_release_review(
    review: IndependenceAttestation | None,
    subject: str,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> IndependenceAttestation:
    if type(review) is not IndependenceAttestation or review.subject_digest != subject:
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED)
    if review.producer_identity == review.reviewer_identity:
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED)
    try:
        review.__post_init__()
        policy.__post_init__()
    except (FactPackValidationError, TypeError, ValueError):
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED) from None
    if (
        policy.policy_digest
        != derive_review_independence_policy_digest(
            policy.reviewed_reviewer_digests,
            policy.forbidden_identity_pairs,
            policy.trusted_store_identities,
            policy.maximum_evidence_bytes,
        )
        or review.reviewer_identity not in policy.reviewed_reviewer_digests
        or (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs
        or review.attestation_digest != derive_independence_attestation_digest(review)
    ):
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED)
    try:
        disclosure = canonical.resolve_content(
            review.conflict_disclosure,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED) from None
    if not disclosure:
        raise _refused(AdmissionSpendReason.REVIEW_REQUIRED)
    return review


def _persist_release(
    repository: S3ArtifactRepository,
    policy: str,
    payload: Mapping[str, JsonValue],
    subject: str,
) -> ArtifactReference:
    try:
        content = canonical_artifact_bytes(
            ArtifactKind.WORKFLOW, dict(payload), access_class=_SEALED, provenance_digest=subject
        )
        reference = artifact_reference(content)
        repository.put_if_absent(content, reference=reference)
        accepted = repository.get(
            reference,
            expected_kind=ArtifactKind.WORKFLOW,
            authority=_custodian_authority(policy),
            expected_access_policy_digest=policy,
        )
    except (ArtifactRepositoryError, TypeError, ValueError):
        raise _refused(AdmissionSpendReason.PERSISTENCE_FAILED) from None
    if accepted.content != content:
        raise _refused(AdmissionSpendReason.PERSISTENCE_FAILED)
    return reference


def _refusal(
    reason: AdmissionSpendReason,
    receipt_digest: str,
    label_read: int,
    label_digest: str,
    committed: bool,
) -> AdmissionSpendReleaseV1:
    return AdmissionSpendReleaseV1(
        reason,
        receipt_digest if committed else "",
        committed,
        label_read,
        label_digest if label_read else "",
        (),
        None,
        "",
    )


def commit_spend_and_release(request: AdmissionSpendRequestV1) -> AdmissionSpendReleaseV1:
    """Commit custody, open labels, join ground truth, and review the release."""
    _validated_request(request)
    try:
        manifest = _authorized_manifest(request.execution)
        receipt = _spend_custody(request, manifest)
    except AdmissionSpendError as error:
        return _refusal(error.reason, "", 0, "", False)
    return _release_after_spend(request, manifest, receipt)


def _release_after_spend(
    request: AdmissionSpendRequestV1,
    manifest: EvaluationAdmissionManifestV3,
    receipt: PopulationUseReceipt,
) -> AdmissionSpendReleaseV1:
    label_read = 0
    label_digest = ""
    try:
        try:
            raw = request.load_labels()
        except Exception:
            raise _refused(AdmissionSpendReason.LABELS_UNREADABLE) from None
        if type(raw) is not bytes or not raw:
            raise _refused(AdmissionSpendReason.LABELS_UNREADABLE)
        label_read = len(raw)
        label_digest = canonical.bytes_digest(raw)
        labels = decode_sealed_labels(raw)
        cases = join_released_cases(
            request.execution,
            request.repository,
            request.custodian_access_policy_digest,
            labels,
            request.positive_change_digests,
            request.scope_census,
        )
        subject = release_review_subject(manifest.manifest_digest, receipt.receipt_digest, cases, raw)
        review = _validate_release_review(request.review, subject, request.review_policy, request.resolver)
        value = _release_value(
            manifest.manifest_digest,
            receipt.receipt_digest,
            label_digest,
            label_read,
            tuple(row.case_digest for row in cases),
        )
        review_value = _review_value(review)
        release_digest = canonical.content_digest({**value, "review": review_value})
        payload: dict[str, JsonValue] = {
            **value,
            "review": review_value,
            "release_digest": release_digest,
            "cases": tuple(_case_value(row) for row in cases),
        }
        reference = _persist_release(request.repository, request.custodian_access_policy_digest, payload, subject)
    except AdmissionSpendError as error:
        return _refusal(error.reason, receipt.receipt_digest, label_read, label_digest, True)
    return AdmissionSpendReleaseV1(
        None, receipt.receipt_digest, True, label_read, label_digest, cases, reference, release_digest
    )


__all__ = [
    "CASE_RELEASE_DOCUMENT_SCHEMA",
    "GROUND_TRUTH_LABEL_SCHEMA",
    "SEALED_LABEL_OBJECT_SCHEMA",
    "AdmissionSpendError",
    "AdmissionSpendReason",
    "AdmissionSpendReleaseV1",
    "AdmissionSpendRequestV1",
    "CustodyCompareAndSwap",
    "GroundTruthLabelV1",
    "ReleasedCaseV1",
    "commit_spend_and_release",
    "decode_sealed_labels",
    "join_released_cases",
    "label_open_request",
    "release_review_subject",
]
