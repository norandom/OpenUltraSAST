"""Task 8.4 exact-scope case projection and matching differential-proof promotion."""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.admission_execution import AdmissionExecutionV1
from benchmarks.valid.admission_spend import (
    AdmissionSpendError,
    AdmissionSpendReleaseV1,
    ReleasedCaseV1,
    decode_sealed_labels,
)
from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ordinary_change_contract import (
    OrdinaryPushV1,
    OrdinarySelectionError,
    OrdinarySelectionV1,
    ordinary_selection_bytes,
)
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from openultrasast.core import canonical
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_authority import EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_measurement import ScopeKey
from openultrasast.core.evaluation_plan import PopulationCensusV3
from openultrasast.core.proof import (
    DifferentialProofRecord,
    ProofAttachment,
    ProofOutcome,
    ProofTrustPolicy,
    ProofValidationError,
    ProofVerificationReceipt,
    derive_producer_identity_digest,
)
from openultrasast.core.semantics import SourceLocation

EXACT_SCOPE_PROJECTION_SCHEMA = "openultrasast.valid-detection-benchmark.exact-scope-projection.v1"
GROUND_TRUTH_JUDGMENT_SCHEMA = "openultrasast.valid-detection-benchmark.ground-truth-judgment.v1"
PROOF_PROMOTION_SCHEMA = "openultrasast.valid-detection-benchmark.proof-promotion.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_JUDGMENT_FIELDS = frozenset({"schema_version", "path", "line", "column", "symbol"})
_VULNERABLE = AdmissionCaseRole.VULNERABLE
_FIXED = AdmissionCaseRole.FIXED
_ORDINARY = AdmissionCaseRole.ORDINARY


class AdmissionProjectionReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    RELEASE_UNBOUND = "release_unbound"
    SCOPE_UNVERIFIED = "scope_unverified"
    CENSUS_MISMATCH = "census_mismatch"
    ECOSYSTEM_CROSSED = "ecosystem_crossed"
    PROOF_MISMATCH = "proof_mismatch"
    PROOF_UNTRUSTED = "proof_untrusted"
    JUDGMENT_UNREADABLE = "judgment_unreadable"


class AdmissionProjectionError(RuntimeError):
    """Refuse a projection or promotion step with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionProjectionReason) -> None:
        self.reason = reason
        super().__init__(f"admission_projection_{reason.value}")


class ProofDisposition(StrEnum):
    """Closed demonstration outcomes for one flagged positive."""

    DEMONSTRATED = "demonstrated"
    NOT_DEMONSTRATED = "not_demonstrated"


class VerificationBasis(StrEnum):
    """Closed evidence bases a proof candidate may claim."""

    EXECUTION_DIFFERENTIAL = "execution_differential"
    SCANNER_VERIFICATION = "scanner_verification"
    MODEL_AGREEMENT = "model_agreement"


def _refused(reason: AdmissionProjectionReason) -> AdmissionProjectionError:
    return AdmissionProjectionError(reason)


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
    return value


def _text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 128:
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
        return
    if _digest(actual) != expected:
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(text)
    return value


@dataclass(frozen=True)
class ScopedDenominatorV1:
    arm_id: str
    family_id: str
    ecosystem: str
    vulnerable_case_digests: tuple[str, ...]
    fixed_case_digests: tuple[str, ...]
    ordinary_case_digests: tuple[str, ...]
    vulnerable_count: int
    fixed_count: int
    ordinary_push_count: int
    scope_digest: str

    def __post_init__(self) -> None:
        for field in ("arm_id", "family_id", "ecosystem"):
            _text(getattr(self, field))
        for field in ("vulnerable_case_digests", "fixed_case_digests", "ordinary_case_digests"):
            digests = getattr(self, field)
            if type(digests) is not tuple or digests != tuple(sorted(set(digests))):
                raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
            for digest in digests:
                _digest(digest)
        if (self.vulnerable_count, self.fixed_count, self.ordinary_push_count) != tuple(
            len(getattr(self, field)) for field in ("vulnerable_case_digests", "fixed_case_digests", "ordinary_case_digests")
        ):
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        _bind(self, "scope_digest", canonical.content_digest(_scope_value(self)))


def _scope_value(row: ScopedDenominatorV1) -> dict[str, JsonValue]:
    return {
        "arm_id": row.arm_id,
        "family_id": row.family_id,
        "ecosystem": row.ecosystem,
        "vulnerable_case_digests": row.vulnerable_case_digests,
        "fixed_case_digests": row.fixed_case_digests,
        "ordinary_case_digests": row.ordinary_case_digests,
    }


@dataclass(frozen=True)
class WholeCoverageV1:
    change_input_digests: tuple[str, ...]
    change_input_count: int
    coverage_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.change_input_digests) is not tuple
            or not self.change_input_digests
            or self.change_input_digests != tuple(sorted(set(self.change_input_digests)))
            or type(self.change_input_count) is not int
            or self.change_input_count != len(self.change_input_digests)
        ):
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        for digest in self.change_input_digests:
            _digest(digest)
        _bind(self, "coverage_digest", canonical.content_digest({"change_input_digests": self.change_input_digests}))


@dataclass(frozen=True)
class ExactScopeProjectionV1:
    """Closed exact-scope projection bound to the reviewed manifest and release."""

    manifest_digest: str
    release_digest: str
    scopes: tuple[ScopedDenominatorV1, ...]
    whole_coverage: WholeCoverageV1
    projection_digest: str

    def __post_init__(self) -> None:
        _digest(self.manifest_digest)
        _digest(self.release_digest)
        if type(self.scopes) is not tuple or not self.scopes or any(type(row) is not ScopedDenominatorV1 for row in self.scopes):
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        for row in self.scopes:
            row.__post_init__()
        keys = [(row.arm_id, row.family_id, row.ecosystem) for row in self.scopes]
        if keys != sorted(set(keys)) or type(self.whole_coverage) is not WholeCoverageV1:
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        self.whole_coverage.__post_init__()
        _bind(
            self,
            "projection_digest",
            canonical.content_digest(
                {
                    "schema_version": EXACT_SCOPE_PROJECTION_SCHEMA,
                    "manifest_digest": self.manifest_digest,
                    "release_digest": self.release_digest,
                    "scope_digests": tuple(row.scope_digest for row in self.scopes),
                    "whole_coverage_digest": self.whole_coverage.coverage_digest,
                }
            ),
        )


@dataclass(frozen=True)
class ProjectionRequestV1:
    release: AdmissionSpendReleaseV1
    execution: AdmissionExecutionV1
    selection: OrdinarySelectionV1


@dataclass(frozen=True)
class LabelBlindProofCandidateV1:
    """Label-blind flagged candidate; no label fact may enter its identity."""

    arm_id: str
    family_claim: str
    ecosystem_claim: str
    packet_digest: str
    anchor: SourceLocation
    flagged_input_digest: str
    control_input_digest: str
    record_digest: str
    receipt_digest: str
    candidate_digest: str

    def __post_init__(self) -> None:
        for field in ("arm_id", "family_claim", "ecosystem_claim"):
            _text(getattr(self, field))
        for field in ("packet_digest", "flagged_input_digest", "control_input_digest", "record_digest", "receipt_digest"):
            _digest(getattr(self, field))
        if type(self.anchor) is not SourceLocation:
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        try:
            self.anchor.__post_init__()
        except (TypeError, ValueError):
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST) from None
        _bind(self, "candidate_digest", canonical.content_digest(_candidate_value(self)))


def _candidate_value(candidate: LabelBlindProofCandidateV1) -> JsonValue:
    anchor = candidate.anchor
    return {
        "arm_id": candidate.arm_id,
        "family_claim": candidate.family_claim,
        "ecosystem_claim": candidate.ecosystem_claim,
        "packet_digest": candidate.packet_digest,
        "anchor": {
            "path": anchor.path,
            "line": anchor.line,
            "column": anchor.column,
            "symbol": anchor.symbol,
        },
        "flagged_input_digest": candidate.flagged_input_digest,
        "control_input_digest": candidate.control_input_digest,
        "record_digest": candidate.record_digest,
        "receipt_digest": candidate.receipt_digest,
    }


@dataclass(frozen=True)
class ProofPromotionRequestV1:
    release: AdmissionSpendReleaseV1
    execution: AdmissionExecutionV1
    selection: OrdinarySelectionV1
    label_bytes: bytes
    candidate: LabelBlindProofCandidateV1 | None
    record: DifferentialProofRecord | None
    verification: ProofVerificationReceipt | None
    basis: VerificationBasis
    trust: ProofTrustPolicy


@dataclass(frozen=True)
class ProofPromotionV1:
    """Closed promotion outcome; absent or inconclusive proof stays not demonstrated."""

    disposition: ProofDisposition
    candidate_digest: str
    attachment: ProofAttachment | None
    promotion_digest: str

    def __post_init__(self) -> None:
        if type(self.disposition) is not ProofDisposition or type(self.candidate_digest) is not str:
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        if self.candidate_digest:
            _digest(self.candidate_digest)
        demonstrated = self.disposition is ProofDisposition.DEMONSTRATED
        if demonstrated != (self.attachment is not None) or (demonstrated and not self.candidate_digest):
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        payload: JsonValue = {
            "schema_version": PROOF_PROMOTION_SCHEMA,
            "disposition": self.disposition.value,
            "candidate_digest": self.candidate_digest,
            "attachment_proof_id": self.attachment.proof_id if self.attachment is not None else None,
        }
        _bind(self, "promotion_digest", canonical.content_digest(payload))


def _reviewed_manifest(execution: AdmissionExecutionV1) -> EvaluationAdmissionManifestV3:
    manifest = execution.admission_manifest
    if (
        execution.refusal_reason is not None
        or manifest is None
        or execution.spend_authorization is None
        or execution.spend_authorization.may_spend is not True
    ):
        raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    return manifest


def _validated_request(request: ProjectionRequestV1) -> None:
    if (
        type(request) is not ProjectionRequestV1
        or type(request.release) is not AdmissionSpendReleaseV1
        or type(request.execution) is not AdmissionExecutionV1
        or type(request.selection) is not OrdinarySelectionV1
    ):
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)


def _push_ecosystem(push: OrdinaryPushV1) -> str:
    try:
        return CanonicalEcosystem(push.ecosystem).value
    except ValueError:
        raise _refused(AdmissionProjectionReason.ECOSYSTEM_CROSSED) from None


def _validated_selection(selection: OrdinarySelectionV1) -> dict[str, OrdinaryPushV1]:
    try:
        ordinary_selection_bytes(selection)
    except (OrdinarySelectionError, TypeError, ValueError):
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST) from None
    pushes: dict[str, OrdinaryPushV1] = {}
    for push in selection.pushes:
        _push_ecosystem(push)
        pushes[push.push_digest] = push
    if not pushes:
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
    return pushes


def _planned_arm_scopes(manifest: EvaluationAdmissionManifestV3) -> dict[str, tuple[ScopeKey, ...]]:
    planned: dict[str, tuple[ScopeKey, ...]] = {}
    for configuration in manifest.plan_manifest.declaration.arm_configurations:
        if _text(configuration.arm_id) in planned:
            raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
        planned[configuration.arm_id] = tuple(sorted(set(configuration.exact_scopes)))
    if not planned:
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)
    return planned


def _released_index(
    release: AdmissionSpendReleaseV1, manifest: EvaluationAdmissionManifestV3, planned: dict[str, tuple[ScopeKey, ...]]
) -> tuple[dict[str, list[ReleasedCaseV1]], dict[str, tuple[AdmissionCaseRole, str, str, str]]]:
    if release.refusal_reason is not None or not release.released_cases:
        raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    by_arm: dict[str, list[ReleasedCaseV1]] = {arm_id: [] for arm_id in planned}
    labeled: dict[str, tuple[AdmissionCaseRole, str, str, str]] = {}
    for row in release.released_cases:
        row.__post_init__()
        if row.manifest_digest != manifest.manifest_digest:
            raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
        if row.arm_id not in by_arm:
            raise _refused(AdmissionProjectionReason.SCOPE_UNVERIFIED)
        by_arm[row.arm_id].append(row)
        if row.role is not _ORDINARY:
            fact = (row.role, row.family_id, row.ecosystem, row.pair_id_digest or "")
            if labeled.setdefault(row.case_input_digest, fact) != fact:
                raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    if any(not rows for rows in by_arm.values()):
        raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    sets = [{row.case_input_digest for row in rows} for rows in by_arm.values()]
    if any(len(rows) != len(item) for rows, item in zip(by_arm.values(), sets, strict=True)):
        raise _refused(AdmissionProjectionReason.CENSUS_MISMATCH)
    if any(item != sets[0] for item in sets[1:]):
        raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    return by_arm, labeled


def _rebound_census(
    labeled: dict[str, tuple[AdmissionCaseRole, str, str, str]],
    pushes: dict[str, OrdinaryPushV1],
    census: PopulationCensusV3,
    planned: dict[str, tuple[ScopeKey, ...]],
) -> None:
    scope_totals = Counter((family, ecosystem) for _role, family, ecosystem, _pair in labeled.values())
    ecosystems = {scope.ecosystem for claimed in planned.values() for scope in claimed}
    ordinary_rows = {row.ecosystem: row.ordinary_push_count for row in census.ordinary_rows}
    if not {_push_ecosystem(push) for push in pushes.values()} <= ecosystems or set(ordinary_rows) != ecosystems:
        raise _refused(AdmissionProjectionReason.ECOSYSTEM_CROSSED)
    if census.whole_underlying_push_count != len(labeled) + len(pushes):
        raise _refused(AdmissionProjectionReason.CENSUS_MISMATCH)
    for row in census.scope_rows:
        if scope_totals.get((row.scope.family_id, row.scope.ecosystem), 0) != row.pair_count:
            raise _refused(AdmissionProjectionReason.CENSUS_MISMATCH)
    counts = Counter(_push_ecosystem(push) for push in pushes.values())
    if counts != ordinary_rows:
        raise _refused(AdmissionProjectionReason.CENSUS_MISMATCH)


def _rebound_ordinary(by_arm: dict[str, list[ReleasedCaseV1]], pushes: dict[str, OrdinaryPushV1]) -> None:
    push_set = set(pushes)
    for rows in by_arm.values():
        if {row.case_input_digest for row in rows if row.role is _ORDINARY} != push_set or any(
            row.role is not _ORDINARY and row.case_input_digest in push_set for row in rows
        ):
            raise _refused(AdmissionProjectionReason.CENSUS_MISMATCH)


def _scoped_rows(
    by_arm: dict[str, list[ReleasedCaseV1]],
    planned: dict[str, tuple[ScopeKey, ...]],
    pushes: dict[str, OrdinaryPushV1],
) -> tuple[ScopedDenominatorV1, ...]:
    rows = []
    for arm_id in sorted(planned):
        arm_rows = by_arm[arm_id]
        for scope in planned[arm_id]:
            key = (scope.family_id, scope.ecosystem)
            vulnerable = tuple(
                sorted(row.case_digest for row in arm_rows if row.role is _VULNERABLE and (row.family_id, row.ecosystem) == key)
            )
            fixed = tuple(sorted(row.case_digest for row in arm_rows if row.role is _FIXED and (row.family_id, row.ecosystem) == key))
            ordinary = tuple(
                sorted(
                    row.case_digest
                    for row in arm_rows
                    if row.role is _ORDINARY and _push_ecosystem(pushes[row.case_input_digest]) == scope.ecosystem
                )
            )
            rows.append(
                ScopedDenominatorV1(
                    arm_id,
                    scope.family_id,
                    scope.ecosystem,
                    vulnerable,
                    fixed,
                    ordinary,
                    len(vulnerable),
                    len(fixed),
                    len(ordinary),
                    "",
                )
            )
    return tuple(rows)


def project_exact_scopes(request: ProjectionRequestV1) -> ExactScopeProjectionV1:
    """Project released cases into exact scopes without rerunning any arm."""
    _validated_request(request)
    manifest = _reviewed_manifest(request.execution)
    pushes = _validated_selection(request.selection)
    planned = _planned_arm_scopes(manifest)
    by_arm, labeled = _released_index(request.release, manifest, planned)
    census = manifest.plan_manifest.census
    _rebound_census(labeled, pushes, census, planned)
    _rebound_ordinary(by_arm, pushes)
    rows = _scoped_rows(by_arm, planned, pushes)
    inputs = tuple(sorted({row.case_input_digest for rows in by_arm.values() for row in rows}))
    whole = WholeCoverageV1(inputs, len(inputs), "")
    return ExactScopeProjectionV1(manifest.manifest_digest, request.release.release_digest, rows, whole, "")


def exact_scope_projection_bytes(projection: ExactScopeProjectionV1) -> bytes:
    """Canonical replay bytes for the exact closed projection product."""
    projection.__post_init__()
    value: JsonValue = {
        "schema_version": EXACT_SCOPE_PROJECTION_SCHEMA,
        "manifest_digest": projection.manifest_digest,
        "release_digest": projection.release_digest,
        "scopes": tuple({**_scope_value(row), "scope_digest": row.scope_digest} for row in projection.scopes),
        "whole_coverage": {
            "change_input_digests": projection.whole_coverage.change_input_digests,
            "coverage_digest": projection.whole_coverage.coverage_digest,
        },
        "projection_digest": projection.projection_digest,
    }
    return canonical_json_bytes(value)


def _validated_promotion_request(request: ProofPromotionRequestV1) -> None:
    if (
        type(request) is not ProofPromotionRequestV1
        or type(request.release) is not AdmissionSpendReleaseV1
        or type(request.execution) is not AdmissionExecutionV1
        or type(request.selection) is not OrdinarySelectionV1
        or type(request.label_bytes) is not bytes
        or not request.label_bytes
        or type(request.trust) is not ProofTrustPolicy
        or type(request.basis) is not VerificationBasis
        or not (request.candidate is None or type(request.candidate) is LabelBlindProofCandidateV1)
        or not (request.record is None or type(request.record) is DifferentialProofRecord)
        or not (request.verification is None or type(request.verification) is ProofVerificationReceipt)
    ):
        raise _refused(AdmissionProjectionReason.INVALID_REQUEST)


def _release_judgments(raw: bytes, release: AdmissionSpendReleaseV1) -> dict[str, bytes]:
    if release.refusal_reason is not None or canonical.bytes_digest(raw) != release.label_bytes_digest:
        raise _refused(AdmissionProjectionReason.RELEASE_UNBOUND)
    try:
        decode_sealed_labels(raw)
        document = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float)
        judgments = {item["change_digest"]: base64.b64decode(item["judgment_base64"], validate=True) for item in document["records"]}
    except (AdmissionSpendError, AttributeError, TypeError, ValueError, RecursionError):
        raise _refused(AdmissionProjectionReason.JUDGMENT_UNREADABLE) from None
    return judgments


def _judgment_anchor(judgments: dict[str, bytes], change: str) -> SourceLocation:
    judgment = judgments.get(change)
    if type(judgment) is not bytes or not judgment:
        raise _refused(AdmissionProjectionReason.JUDGMENT_UNREADABLE)
    try:
        document = json.loads(judgment.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float)
        canonical_form = type(document) is dict and canonical_json_bytes(document) == judgment
    except (UnicodeDecodeError, TypeError, ValueError, RecursionError):
        raise _refused(AdmissionProjectionReason.JUDGMENT_UNREADABLE) from None
    if not canonical_form or frozenset(document) != _JUDGMENT_FIELDS or document.get("schema_version") != GROUND_TRUTH_JUDGMENT_SCHEMA:
        raise _refused(AdmissionProjectionReason.JUDGMENT_UNREADABLE)
    try:
        return SourceLocation(document["path"], document["line"], document["column"], document["symbol"])
    except (TypeError, ValueError):
        raise _refused(AdmissionProjectionReason.JUDGMENT_UNREADABLE) from None


def _trusted_record(
    candidate: LabelBlindProofCandidateV1,
    record: DifferentialProofRecord,
    verification: ProofVerificationReceipt,
    trust: ProofTrustPolicy,
    basis: VerificationBasis,
) -> None:
    if basis is not VerificationBasis.EXECUTION_DIFFERENTIAL:
        raise _refused(AdmissionProjectionReason.PROOF_UNTRUSTED)
    try:
        trust.__post_init__()
        record.__post_init__()
        verification.__post_init__()
    except (ProofValidationError, TypeError, ValueError):
        raise _refused(AdmissionProjectionReason.PROOF_UNTRUSTED) from None
    if candidate.record_digest != record.record_digest or candidate.receipt_digest != verification.receipt_digest:
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    producer = derive_producer_identity_digest(record.producer)
    reviewer = record.control.reviewer_identity
    if (
        producer not in trust.reviewed_producer_digests
        or reviewer not in trust.reviewed_control_reviewer_digests
        or reviewer in (record.producer.producer_id, canonical.content_digest(record.producer.producer_id), producer)
    ):
        raise _refused(AdmissionProjectionReason.PROOF_UNTRUSTED)
    if (
        producer,
        record.record_digest,
        record.affected.result_digest,
        record.safe.result_digest,
        record.witness.content_digest,
    ) != (
        verification.producer_identity_digest,
        verification.proof_record_digest,
        verification.affected_result_digest,
        verification.safe_result_digest,
        verification.witness_content_digest,
    ):
        raise _refused(AdmissionProjectionReason.PROOF_UNTRUSTED)


def _released_pair(
    release: AdmissionSpendReleaseV1,
    manifest: EvaluationAdmissionManifestV3,
    candidate: LabelBlindProofCandidateV1,
) -> tuple[ReleasedCaseV1, ReleasedCaseV1]:
    planned = _planned_arm_scopes(manifest)
    if candidate.arm_id not in planned:
        raise _refused(AdmissionProjectionReason.SCOPE_UNVERIFIED)
    claim = (candidate.family_claim, candidate.ecosystem_claim)
    claimed = any((scope.family_id, scope.ecosystem) == claim for scope in planned[candidate.arm_id])
    censused = any((row.scope.family_id, row.scope.ecosystem) == claim for row in manifest.plan_manifest.census.scope_rows)
    if not claimed or not censused:
        raise _refused(AdmissionProjectionReason.SCOPE_UNVERIFIED)
    index = {row.case_input_digest: row for row in release.released_cases if row.arm_id == candidate.arm_id}
    flagged, control = index.get(candidate.flagged_input_digest), index.get(candidate.control_input_digest)
    if flagged is None or control is None or flagged is control:
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    if (flagged.role, control.role) != (_VULNERABLE, _FIXED):
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    if flagged.pair_id_digest != control.pair_id_digest or not flagged.pair_id_digest:
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    if (flagged.family_id, flagged.ecosystem) != claim or (control.family_id, control.ecosystem) != claim:
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    return flagged, control


def _bound_record(record: DifferentialProofRecord, flagged: ReleasedCaseV1, control: ReleasedCaseV1) -> None:
    flagged_input, control_input = flagged.case_input_digest, control.case_input_digest
    if (record.affected.input_digest, record.control.affected_change_input_digest) != (flagged_input, flagged_input):
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    if (record.safe.input_digest, record.control.safe_input_digest) != (control_input, control_input):
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)


def _demonstrated(record: DifferentialProofRecord) -> bool:
    return record.outcome is ProofOutcome.DEMONSTRATED and record.affected.observed and not record.safe.observed


def promote_proof_candidate(request: ProofPromotionRequestV1) -> ProofPromotionV1:
    """Promote only a fully matching label-blind differential-proof candidate."""
    _validated_promotion_request(request)
    manifest = _reviewed_manifest(request.execution)
    judgments = _release_judgments(request.label_bytes, request.release)
    if request.candidate is None or request.record is None or request.verification is None:
        return ProofPromotionV1(ProofDisposition.NOT_DEMONSTRATED, "", None, "")
    candidate, record, verification = request.candidate, request.record, request.verification
    _trusted_record(candidate, record, verification, request.trust, request.basis)
    flagged, control = _released_pair(request.release, manifest, candidate)
    _bound_record(record, flagged, control)
    anchor = _judgment_anchor(judgments, flagged.case_input_digest)
    if candidate.anchor != anchor:
        raise _refused(AdmissionProjectionReason.PROOF_MISMATCH)
    if not _demonstrated(record):
        return ProofPromotionV1(ProofDisposition.NOT_DEMONSTRATED, candidate.candidate_digest, None, "")
    attachment = ProofAttachment("", candidate.family_claim, candidate.packet_digest, anchor, record, verification)
    return ProofPromotionV1(ProofDisposition.DEMONSTRATED, candidate.candidate_digest, attachment, "")


def proof_promotion_bytes(product: ProofPromotionV1) -> bytes:
    """Canonical replay bytes for the exact closed promotion product."""
    product.__post_init__()
    payload: JsonValue = {
        "schema_version": PROOF_PROMOTION_SCHEMA,
        "disposition": product.disposition.value,
        "candidate_digest": product.candidate_digest,
        "attachment_proof_id": product.attachment.proof_id if product.attachment is not None else None,
    }
    return canonical_json_bytes(payload)


__all__ = [
    "EXACT_SCOPE_PROJECTION_SCHEMA",
    "GROUND_TRUTH_JUDGMENT_SCHEMA",
    "PROOF_PROMOTION_SCHEMA",
    "AdmissionProjectionError",
    "AdmissionProjectionReason",
    "ExactScopeProjectionV1",
    "LabelBlindProofCandidateV1",
    "ProjectionRequestV1",
    "ProofDisposition",
    "ProofPromotionRequestV1",
    "ProofPromotionV1",
    "ScopedDenominatorV1",
    "VerificationBasis",
    "WholeCoverageV1",
    "exact_scope_projection_bytes",
    "project_exact_scopes",
    "proof_promotion_bytes",
    "promote_proof_candidate",
]
