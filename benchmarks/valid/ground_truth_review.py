"""Independent reviewed ground truth for replacement benchmark positives."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.ecosystem_review import (
    CanonicalEcosystem,
    EcosystemReviewError,
    EcosystemReviewStatus,
    RepositoryEcosystemReviewV1,
    project_accepted_ecosystems,
    repository_ecosystem_review_bytes,
)
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1, fix_site_candidate_bytes
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

GROUND_TRUTH_REVIEW_SCHEMA = "openultrasast.valid-detection-benchmark.ground-truth-review.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")


class GroundTruthStatus(StrEnum):
    ACCEPTED = "accepted"
    EXCLUDED = "excluded"


class GroundTruthExclusionReason(StrEnum):
    MISSING_HUMAN_JUDGMENT = "missing_human_judgment"
    JUDGMENT_REJECTED = "judgment_rejected"
    SELF_REVIEW = "self_review"
    CONFLICT_DISCLOSURE_MISSING = "conflict_disclosure_missing"
    POLICY_UNSATISFIED = "policy_unsatisfied"
    MISSING_SCOPE = "missing_scope"
    SCOPE_SUBSTITUTION = "scope_substitution"
    ECOSYSTEM_NOT_ACCEPTED = "ecosystem_not_accepted"


class GroundTruthReviewError(ValueError):
    """Ground-truth review is stale, inconsistent, or non-authoritative."""


@dataclass(frozen=True, order=True)
class VerifiedScope:
    vulnerability_family: str
    ecosystem: CanonicalEcosystem

    def __post_init__(self) -> None:
        family = _family_name(self.vulnerability_family)
        try:
            ecosystem = CanonicalEcosystem(self.ecosystem)
        except (TypeError, ValueError) as error:
            raise GroundTruthReviewError("verified scope ecosystem is unsupported") from error
        object.__setattr__(self, "vulnerability_family", family)
        object.__setattr__(self, "ecosystem", ecosystem)


@dataclass(frozen=True)
class GroundTruthAttestationV1:
    candidate_digest: str
    ecosystem_review_digest: str
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    policy_satisfied: bool
    defect_present: bool | None
    fix_addresses: bool | None
    in_repository_reachable: bool | None
    verified_scopes: tuple[VerifiedScope, ...]
    model_assistance_digest: str | None = None


@dataclass(frozen=True)
class GroundTruthReviewV1:
    canonical_repository: str
    network_identity_digest: str
    candidate_digest: str
    ecosystem_review_digest: str
    change_identity_digest: str
    vulnerable_revision: str
    fixed_revision: str
    path: str
    function: str
    defect_present: bool | None
    fix_addresses: bool | None
    in_repository_reachable: bool | None
    reviewed_scopes: tuple[VerifiedScope, ...]
    verified_scopes: tuple[VerifiedScope, ...]
    model_assistance_digest: str | None
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    policy_satisfied: bool
    status: GroundTruthStatus
    exclusion_reason: GroundTruthExclusionReason | None
    review_digest: str


@dataclass(frozen=True)
class AcceptedGroundTruthV1:
    change_identity_digest: str
    candidate_digest: str
    ecosystem_review_digest: str
    ground_truth_review_digest: str
    verified_scopes: tuple[VerifiedScope, ...]


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GroundTruthReviewError(f"{field} must be nonempty text")
    return value.strip()


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise GroundTruthReviewError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _family_name(value: object) -> str:
    family = _text(value, "vulnerability family").lower()
    if _FAMILY.fullmatch(family) is None:
        raise GroundTruthReviewError("vulnerability family must be a canonical evidence label")
    return family


def _judgment(value: object, field: str) -> bool | None:
    if value is not None and type(value) is not bool:
        raise GroundTruthReviewError(f"{field} judgment must be boolean or absent")
    return value


def _scopes(values: Iterable[VerifiedScope]) -> tuple[VerifiedScope, ...]:
    try:
        scopes = tuple(VerifiedScope(item.vulnerability_family, item.ecosystem) for item in values)
    except (AttributeError, TypeError) as error:
        raise GroundTruthReviewError("verified scopes are malformed") from error
    return tuple(sorted(set(scopes)))


def _scope_value(scope: VerifiedScope) -> dict[str, JsonValue]:
    return {"vulnerability_family": scope.vulnerability_family, "ecosystem": scope.ecosystem.value}


def _change_identity(candidate: FixSiteCandidateV1) -> str:
    value: JsonValue = {
        "canonical_repository": candidate.canonical_repository,
        "network_identity_digest": candidate.network_identity_digest,
        "vulnerable_revision": candidate.vulnerable.revision,
        "fixed_revision": candidate.fixed.revision,
        "path": candidate.fixed.path,
        "function": candidate.fixed.function,
        "change_inputs_digest": candidate.change_inputs_digest,
    }
    return content_digest(value)


def _review_value(review: GroundTruthReviewV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": GROUND_TRUTH_REVIEW_SCHEMA,
        "canonical_repository": review.canonical_repository,
        "network_identity_digest": review.network_identity_digest,
        "candidate_digest": review.candidate_digest,
        "ecosystem_review_digest": review.ecosystem_review_digest,
        "change_identity_digest": review.change_identity_digest,
        "vulnerable_revision": review.vulnerable_revision,
        "fixed_revision": review.fixed_revision,
        "path": review.path,
        "function": review.function,
        "defect_present": review.defect_present,
        "fix_addresses": review.fix_addresses,
        "in_repository_reachable": review.in_repository_reachable,
        "reviewed_scopes": tuple(_scope_value(scope) for scope in review.reviewed_scopes),
        "verified_scopes": tuple(_scope_value(scope) for scope in review.verified_scopes),
        "model_assistance_digest": review.model_assistance_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosed": review.conflict_disclosed,
        "policy_digest": review.policy_digest,
        "policy_satisfied": review.policy_satisfied,
        "status": review.status.value,
        "exclusion_reason": review.exclusion_reason.value if review.exclusion_reason is not None else None,
    }
    if include_digest:
        value["review_digest"] = review.review_digest
    return value


def _validate_ecosystem_authority(
    candidate: FixSiteCandidateV1,
    ecosystem_review: RepositoryEcosystemReviewV1,
    expected_policy_digest: str,
) -> CanonicalEcosystem | None:
    try:
        repository_ecosystem_review_bytes(
            ecosystem_review,
            candidate=candidate,
            expected_policy_digest=expected_policy_digest,
        )
    except EcosystemReviewError as error:
        raise GroundTruthReviewError("ecosystem review authority is invalid") from error
    if ecosystem_review.status is EcosystemReviewStatus.ACCEPTED:
        assert ecosystem_review.ecosystem is not None
        return ecosystem_review.ecosystem
    return None


def _validate_attestation(
    candidate: FixSiteCandidateV1,
    ecosystem_review: RepositoryEcosystemReviewV1,
    attestation: GroundTruthAttestationV1,
    expected_ground_truth_policy_digest: str,
) -> None:
    fix_site_candidate_bytes(candidate)
    if _digest(attestation.candidate_digest, "candidate digest") != candidate.candidate_digest:
        raise GroundTruthReviewError("ground-truth candidate digest is stale")
    if _digest(attestation.ecosystem_review_digest, "ecosystem review digest") != ecosystem_review.review_digest:
        raise GroundTruthReviewError("ground-truth ecosystem review digest is stale")
    policy = _digest(attestation.policy_digest, "ground-truth review policy digest")
    if policy != _digest(expected_ground_truth_policy_digest, "expected ground-truth policy digest"):
        raise GroundTruthReviewError("ground-truth review policy digest is stale")
    _text(attestation.producer_identity, "producer identity")
    _text(attestation.reviewer_identity, "reviewer identity")
    if type(attestation.conflict_disclosed) is not bool or type(attestation.policy_satisfied) is not bool:
        raise GroundTruthReviewError("ground-truth review policy values must be boolean")
    for value, field in (
        (attestation.defect_present, "defect-present"),
        (attestation.fix_addresses, "fix-addresses"),
        (attestation.in_repository_reachable, "in-repository-reachable"),
    ):
        _judgment(value, field)
    if attestation.model_assistance_digest is not None:
        _digest(attestation.model_assistance_digest, "model assistance digest")


def _classify(
    ecosystem: CanonicalEcosystem | None,
    attestation: GroundTruthAttestationV1,
    scopes: tuple[VerifiedScope, ...],
) -> GroundTruthExclusionReason | None:
    if attestation.producer_identity == attestation.reviewer_identity:
        return GroundTruthExclusionReason.SELF_REVIEW
    if not attestation.conflict_disclosed:
        return GroundTruthExclusionReason.CONFLICT_DISCLOSURE_MISSING
    if not attestation.policy_satisfied:
        return GroundTruthExclusionReason.POLICY_UNSATISFIED
    judgments = (attestation.defect_present, attestation.fix_addresses, attestation.in_repository_reachable)
    if any(value is None for value in judgments):
        return GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT
    if not all(judgments):
        return GroundTruthExclusionReason.JUDGMENT_REJECTED
    if ecosystem is None:
        return GroundTruthExclusionReason.ECOSYSTEM_NOT_ACCEPTED
    if not scopes:
        return GroundTruthExclusionReason.MISSING_SCOPE
    if any(scope.ecosystem is not ecosystem for scope in scopes):
        return GroundTruthExclusionReason.SCOPE_SUBSTITUTION
    return None


def _attestation_from_review(review: GroundTruthReviewV1) -> GroundTruthAttestationV1:
    return GroundTruthAttestationV1(
        review.candidate_digest,
        review.ecosystem_review_digest,
        review.producer_identity,
        review.reviewer_identity,
        review.conflict_disclosed,
        review.policy_digest,
        review.policy_satisfied,
        review.defect_present,
        review.fix_addresses,
        review.in_repository_reachable,
        review.reviewed_scopes,
        review.model_assistance_digest,
    )


def review_ground_truth(
    candidate: FixSiteCandidateV1,
    ecosystem_review: RepositoryEcosystemReviewV1,
    attestation: GroundTruthAttestationV1,
    *,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> GroundTruthReviewV1:
    """Validate externally governed judgments without inventing a label."""
    ecosystem = _validate_ecosystem_authority(candidate, ecosystem_review, expected_ecosystem_policy_digest)
    _validate_attestation(candidate, ecosystem_review, attestation, expected_ground_truth_policy_digest)
    scopes = _scopes(attestation.verified_scopes)
    reason = _classify(ecosystem, attestation, scopes)
    verified = scopes if reason is None else ()
    status = GroundTruthStatus.ACCEPTED if reason is None else GroundTruthStatus.EXCLUDED
    draft = GroundTruthReviewV1(
        candidate.canonical_repository,
        candidate.network_identity_digest,
        candidate.candidate_digest,
        ecosystem_review.review_digest,
        _change_identity(candidate),
        candidate.vulnerable.revision,
        candidate.fixed.revision,
        candidate.fixed.path,
        candidate.fixed.function,
        attestation.defect_present,
        attestation.fix_addresses,
        attestation.in_repository_reachable,
        scopes,
        verified,
        attestation.model_assistance_digest,
        _text(attestation.producer_identity, "producer identity"),
        _text(attestation.reviewer_identity, "reviewer identity"),
        attestation.conflict_disclosed,
        attestation.policy_digest,
        attestation.policy_satisfied,
        status,
        reason,
        "",
    )
    review = GroundTruthReviewV1(**{**vars(draft), "review_digest": content_digest(_review_value(draft, include_digest=False))})
    ground_truth_review_bytes(
        review,
        candidate=candidate,
        ecosystem_review=ecosystem_review,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )
    return review


def _expected_identity(candidate: FixSiteCandidateV1, ecosystem_review: RepositoryEcosystemReviewV1) -> tuple[object, ...]:
    return (
        candidate.canonical_repository,
        candidate.network_identity_digest,
        candidate.candidate_digest,
        ecosystem_review.review_digest,
        _change_identity(candidate),
        candidate.vulnerable.revision,
        candidate.fixed.revision,
        candidate.fixed.path,
        candidate.fixed.function,
    )


def ground_truth_review_bytes(
    review: GroundTruthReviewV1,
    *,
    candidate: FixSiteCandidateV1,
    ecosystem_review: RepositoryEcosystemReviewV1,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> bytes:
    """Revalidate exact authorities and encode one review canonically."""
    ecosystem = _validate_ecosystem_authority(candidate, ecosystem_review, expected_ecosystem_policy_digest)
    attestation = _attestation_from_review(review)
    _validate_attestation(candidate, ecosystem_review, attestation, expected_ground_truth_policy_digest)
    scopes = _scopes(review.reviewed_scopes)
    reason = _classify(ecosystem, attestation, scopes)
    status = GroundTruthStatus.ACCEPTED if reason is None else GroundTruthStatus.EXCLUDED
    verified = scopes if reason is None else ()
    identity = (
        review.canonical_repository,
        review.network_identity_digest,
        review.candidate_digest,
        review.ecosystem_review_digest,
        review.change_identity_digest,
        review.vulnerable_revision,
        review.fixed_revision,
        review.path,
        review.function,
    )
    if identity != _expected_identity(candidate, ecosystem_review):
        raise GroundTruthReviewError("ground-truth authority identity does not match exact inputs")
    if (review.status, review.exclusion_reason, review.verified_scopes) != (status, reason, verified):
        raise GroundTruthReviewError("ground-truth outcome or verified scope does not match reviewed inputs")
    if review.reviewed_scopes != scopes:
        raise GroundTruthReviewError("ground-truth reviewed scopes are not canonical")
    if not isinstance(review.status, GroundTruthStatus):
        raise GroundTruthReviewError("ground-truth status is unsupported")
    if review.exclusion_reason is not None and not isinstance(review.exclusion_reason, GroundTruthExclusionReason):
        raise GroundTruthReviewError("ground-truth exclusion reason is unsupported")
    expected = content_digest(_review_value(review, include_digest=False))
    if review.review_digest != expected:
        raise GroundTruthReviewError("ground-truth review digest does not match")
    return canonical_bytes(_review_value(review, include_digest=True))


def project_accepted_ground_truth(
    reviews: Iterable[GroundTruthReviewV1],
    *,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    ecosystem_reviews_by_digest: Mapping[str, RepositoryEcosystemReviewV1],
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> tuple[AcceptedGroundTruthV1, ...]:
    """Project every accepted change once with its exact verified scopes."""
    try:
        project_accepted_ecosystems(
            ecosystem_reviews_by_digest.values(),
            candidates_by_digest=candidates_by_digest,
            expected_policy_digest=expected_ecosystem_policy_digest,
        )
    except EcosystemReviewError as error:
        raise GroundTruthReviewError("ecosystem review identity authority is conflicting") from error
    accepted: dict[str, AcceptedGroundTruthV1] = {}
    review_bytes_by_digest: dict[str, bytes] = {}
    for review in reviews:
        candidate = candidates_by_digest.get(review.candidate_digest)
        ecosystem_review = ecosystem_reviews_by_digest.get(review.ecosystem_review_digest)
        if candidate is None or ecosystem_review is None:
            raise GroundTruthReviewError("ground-truth review authority is absent from exact input set")
        encoded = ground_truth_review_bytes(
            review,
            candidate=candidate,
            ecosystem_review=ecosystem_review,
            expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
            expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
        )
        existing_bytes = review_bytes_by_digest.get(review.review_digest)
        if existing_bytes is not None and existing_bytes != encoded:
            raise GroundTruthReviewError("same ground-truth review identity has different bytes")
        review_bytes_by_digest[review.review_digest] = encoded
        if review.status is GroundTruthStatus.EXCLUDED:
            continue
        projected = AcceptedGroundTruthV1(
            review.change_identity_digest,
            review.candidate_digest,
            review.ecosystem_review_digest,
            review.review_digest,
            review.verified_scopes,
        )
        current = accepted.get(review.change_identity_digest)
        if current is not None and current != projected:
            raise GroundTruthReviewError("one change identity has conflicting accepted ground-truth reviews")
        accepted[review.change_identity_digest] = projected
    return tuple(accepted[key] for key in sorted(accepted))


__all__ = [
    "AcceptedGroundTruthV1",
    "GroundTruthAttestationV1",
    "GroundTruthExclusionReason",
    "GroundTruthReviewError",
    "GroundTruthReviewV1",
    "GroundTruthStatus",
    "VerifiedScope",
    "ground_truth_review_bytes",
    "project_accepted_ground_truth",
    "review_ground_truth",
]
