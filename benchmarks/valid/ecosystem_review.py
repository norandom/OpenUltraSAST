"""Independent canonical ecosystem review for fix-site candidates."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1, fix_site_candidate_bytes
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

ECOSYSTEM_REVIEW_SCHEMA = "openultrasast.valid-detection-benchmark.repository-ecosystem-review.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class CanonicalEcosystem(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"


class EcosystemReviewDecision(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    UNRESOLVED = "unresolved"
    CONFLICTING = "conflicting"
    POLYGLOT_AMBIGUITY = "polyglot_ambiguity"


class EcosystemReviewStatus(StrEnum):
    ACCEPTED = "accepted"
    INSUFFICIENT = "insufficient"


class EcosystemInsufficientReason(StrEnum):
    UNRESOLVED = "unresolved"
    CONFLICTING = "conflicting"
    POLYGLOT_AMBIGUITY = "polyglot_ambiguity"
    SELF_REVIEW = "self_review"
    POLICY_UNSATISFIED = "policy_unsatisfied"
    CONFLICT_DISCLOSURE_MISSING = "conflict_disclosure_missing"


class EcosystemReviewError(ValueError):
    """Ecosystem review evidence is stale, malformed, or unsupported."""


@dataclass(frozen=True)
class EcosystemReviewAttestationV1:
    candidate_digest: str
    source_evidence_digest: str
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    policy_satisfied: bool
    decision: EcosystemReviewDecision


@dataclass(frozen=True)
class RepositoryEcosystemReviewV1:
    canonical_repository: str
    network_identity_digest: str
    candidate_digest: str
    source_evidence_digest: str
    observed_language: str
    package_evidence_digest: str
    decision: EcosystemReviewDecision
    status: EcosystemReviewStatus
    ecosystem: CanonicalEcosystem | None
    insufficient_reason: EcosystemInsufficientReason | None
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    policy_satisfied: bool
    review_digest: str


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EcosystemReviewError(f"{field} must be nonempty text")
    return value.strip()


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EcosystemReviewError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _decision(value: object) -> EcosystemReviewDecision:
    if not isinstance(value, str):
        raise EcosystemReviewError("ecosystem review decision is unsupported")
    try:
        return EcosystemReviewDecision(value)
    except ValueError as error:
        raise EcosystemReviewError("ecosystem review decision is unsupported") from error


def _package_evidence_digest(candidate: FixSiteCandidateV1) -> str:
    manifest = candidate.package_evidence.manifest
    value: JsonValue = {
        "ecosystem_hint": candidate.package_evidence.ecosystem_hint,
        "manifest": {
            "path": manifest.path,
            "content_digest": manifest.content_digest,
            "byte_length": manifest.byte_length,
        },
    }
    return content_digest(value)


def _observed_ecosystem(candidate: FixSiteCandidateV1) -> CanonicalEcosystem:
    if candidate.observed_language == "python":
        return CanonicalEcosystem.PYTHON
    if candidate.observed_language in {"javascript", "typescript"}:
        return CanonicalEcosystem.JAVASCRIPT
    raise EcosystemReviewError("observed language is outside the canonical ecosystem boundary")


def _evidence_conflicts(candidate: FixSiteCandidateV1, observed: CanonicalEcosystem) -> bool:
    hint = candidate.package_evidence.ecosystem_hint
    if hint == "unresolved":
        return False
    if hint not in {item.value for item in CanonicalEcosystem}:
        raise EcosystemReviewError("package ecosystem evidence is unsupported")
    return hint != observed.value


def _policy_reason(attestation: EcosystemReviewAttestationV1) -> EcosystemInsufficientReason | None:
    producer = _text(attestation.producer_identity, "producer identity")
    reviewer = _text(attestation.reviewer_identity, "reviewer identity")
    if producer == reviewer:
        return EcosystemInsufficientReason.SELF_REVIEW
    if type(attestation.conflict_disclosed) is not bool:
        raise EcosystemReviewError("conflict disclosure must be boolean")
    if not attestation.conflict_disclosed:
        return EcosystemInsufficientReason.CONFLICT_DISCLOSURE_MISSING
    if type(attestation.policy_satisfied) is not bool:
        raise EcosystemReviewError("policy satisfaction must be boolean")
    if not attestation.policy_satisfied:
        return EcosystemInsufficientReason.POLICY_UNSATISFIED
    return None


def _decision_reason(decision: EcosystemReviewDecision) -> EcosystemInsufficientReason | None:
    reasons = {
        EcosystemReviewDecision.UNRESOLVED: EcosystemInsufficientReason.UNRESOLVED,
        EcosystemReviewDecision.CONFLICTING: EcosystemInsufficientReason.CONFLICTING,
        EcosystemReviewDecision.POLYGLOT_AMBIGUITY: EcosystemInsufficientReason.POLYGLOT_AMBIGUITY,
    }
    return reasons.get(decision)


def _classification(
    candidate: FixSiteCandidateV1,
    attestation: EcosystemReviewAttestationV1,
) -> tuple[CanonicalEcosystem | None, EcosystemInsufficientReason | None]:
    decision = _decision(attestation.decision)
    policy_reason = _policy_reason(attestation)
    if policy_reason is not None:
        return None, policy_reason
    decision_reason = _decision_reason(decision)
    if decision_reason is not None:
        return None, decision_reason
    observed = _observed_ecosystem(candidate)
    selected = CanonicalEcosystem(decision.value)
    if _evidence_conflicts(candidate, observed) or selected is not observed:
        return None, EcosystemInsufficientReason.CONFLICTING
    return selected, None


def _review_value(review: RepositoryEcosystemReviewV1, *, include_digest: bool) -> dict[str, JsonValue]:
    ecosystem = review.ecosystem.value if review.ecosystem is not None else None
    reason = review.insufficient_reason.value if review.insufficient_reason is not None else None
    value: dict[str, JsonValue] = {
        "schema_version": ECOSYSTEM_REVIEW_SCHEMA,
        "canonical_repository": review.canonical_repository,
        "network_identity_digest": review.network_identity_digest,
        "candidate_digest": review.candidate_digest,
        "source_evidence_digest": review.source_evidence_digest,
        "observed_language": review.observed_language,
        "package_evidence_digest": review.package_evidence_digest,
        "decision": review.decision.value,
        "status": review.status.value,
        "ecosystem": ecosystem,
        "insufficient_reason": reason,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosed": review.conflict_disclosed,
        "policy_digest": review.policy_digest,
        "policy_satisfied": review.policy_satisfied,
    }
    if include_digest:
        value["review_digest"] = review.review_digest
    return value


def _validate_attestation(
    candidate: FixSiteCandidateV1,
    attestation: EcosystemReviewAttestationV1,
    expected_policy_digest: str,
) -> None:
    fix_site_candidate_bytes(candidate)
    if _digest(attestation.candidate_digest, "candidate digest") != candidate.candidate_digest:
        raise EcosystemReviewError("review candidate digest is stale")
    source_digest = _digest(attestation.source_evidence_digest, "source evidence digest")
    if source_digest != candidate.source_evidence.evidence_digest:
        raise EcosystemReviewError("review source evidence digest is stale")
    policy = _digest(attestation.policy_digest, "review policy digest")
    if policy != _digest(expected_policy_digest, "expected review policy digest"):
        raise EcosystemReviewError("review policy digest is stale")
    _decision(attestation.decision)


def review_repository_ecosystem(
    candidate: FixSiteCandidateV1,
    attestation: EcosystemReviewAttestationV1,
    *,
    expected_policy_digest: str,
) -> RepositoryEcosystemReviewV1:
    """Validate external review input without inventing an ecosystem judgment."""
    _validate_attestation(candidate, attestation, expected_policy_digest)
    ecosystem, reason = _classification(candidate, attestation)
    status = EcosystemReviewStatus.ACCEPTED if ecosystem is not None else EcosystemReviewStatus.INSUFFICIENT
    draft = RepositoryEcosystemReviewV1(
        candidate.canonical_repository,
        candidate.network_identity_digest,
        candidate.candidate_digest,
        candidate.source_evidence.evidence_digest,
        candidate.observed_language,
        _package_evidence_digest(candidate),
        _decision(attestation.decision),
        status,
        ecosystem,
        reason,
        _text(attestation.producer_identity, "producer identity"),
        _text(attestation.reviewer_identity, "reviewer identity"),
        attestation.conflict_disclosed,
        attestation.policy_digest,
        attestation.policy_satisfied,
        "",
    )
    review = RepositoryEcosystemReviewV1(**{**vars(draft), "review_digest": content_digest(_review_value(draft, include_digest=False))})
    repository_ecosystem_review_bytes(review, candidate=candidate, expected_policy_digest=expected_policy_digest)
    return review


def _validate_accepted_review(review: RepositoryEcosystemReviewV1) -> None:
    assert review.ecosystem is not None
    if review.decision.value != review.ecosystem.value:
        raise EcosystemReviewError("accepted ecosystem does not match the reviewed decision")
    expected = "python" if review.observed_language == "python" else "javascript"
    if review.ecosystem.value != expected:
        raise EcosystemReviewError("accepted ecosystem does not match the observed language")
    policy_failed = review.producer_identity == review.reviewer_identity or not review.conflict_disclosed or not review.policy_satisfied
    if policy_failed:
        raise EcosystemReviewError("accepted ecosystem review does not satisfy independent review policy")


def _validate_review_outcome(review: RepositoryEcosystemReviewV1) -> None:
    if not isinstance(review.decision, EcosystemReviewDecision) or not isinstance(review.status, EcosystemReviewStatus):
        raise EcosystemReviewError("ecosystem review contains unsupported closed values")
    if review.ecosystem is not None and not isinstance(review.ecosystem, CanonicalEcosystem):
        raise EcosystemReviewError("canonical ecosystem is unsupported")
    if review.insufficient_reason is not None and not isinstance(review.insufficient_reason, EcosystemInsufficientReason):
        raise EcosystemReviewError("ecosystem insufficiency reason is unsupported")
    if type(review.conflict_disclosed) is not bool or type(review.policy_satisfied) is not bool:
        raise EcosystemReviewError("ecosystem review policy values must be boolean")
    accepted = review.status is EcosystemReviewStatus.ACCEPTED
    if accepted != (review.ecosystem is not None and review.insufficient_reason is None):
        raise EcosystemReviewError("ecosystem review outcome is inconsistent")
    if not accepted and (review.ecosystem is not None or review.insufficient_reason is None):
        raise EcosystemReviewError("insufficient ecosystem review outcome is inconsistent")
    if accepted:
        _validate_accepted_review(review)


def _attestation_from_review(review: RepositoryEcosystemReviewV1) -> EcosystemReviewAttestationV1:
    return EcosystemReviewAttestationV1(
        review.candidate_digest,
        review.source_evidence_digest,
        review.producer_identity,
        review.reviewer_identity,
        review.conflict_disclosed,
        review.policy_digest,
        review.policy_satisfied,
        review.decision,
    )


def _validate_review_authority(
    review: RepositoryEcosystemReviewV1,
    candidate: FixSiteCandidateV1,
    expected_policy_digest: str,
) -> None:
    attestation = _attestation_from_review(review)
    _validate_attestation(candidate, attestation, expected_policy_digest)
    expected_ecosystem, expected_reason = _classification(candidate, attestation)
    expected_status = EcosystemReviewStatus.ACCEPTED if expected_ecosystem is not None else EcosystemReviewStatus.INSUFFICIENT
    expected_identity = (
        candidate.canonical_repository,
        candidate.network_identity_digest,
        candidate.candidate_digest,
        candidate.source_evidence.evidence_digest,
        candidate.observed_language,
        _package_evidence_digest(candidate),
    )
    recorded_identity = (
        review.canonical_repository,
        review.network_identity_digest,
        review.candidate_digest,
        review.source_evidence_digest,
        review.observed_language,
        review.package_evidence_digest,
    )
    if recorded_identity != expected_identity:
        raise EcosystemReviewError("ecosystem review evidence identity does not match the exact candidate")
    if (review.status, review.ecosystem, review.insufficient_reason) != (
        expected_status,
        expected_ecosystem,
        expected_reason,
    ):
        raise EcosystemReviewError("ecosystem review outcome does not match the exact reviewed inputs")


def repository_ecosystem_review_bytes(
    review: RepositoryEcosystemReviewV1,
    *,
    candidate: FixSiteCandidateV1,
    expected_policy_digest: str,
) -> bytes:
    """Validate and encode one accepted or bounded-insufficient review."""
    _validate_review_outcome(review)
    _text(review.canonical_repository, "canonical repository")
    _text(review.producer_identity, "producer identity")
    _text(review.reviewer_identity, "reviewer identity")
    if review.observed_language not in {"python", "javascript", "typescript"}:
        raise EcosystemReviewError("observed language is outside the canonical ecosystem boundary")
    _validate_review_authority(review, candidate, expected_policy_digest)
    for value, field in (
        (review.network_identity_digest, "network identity digest"),
        (review.candidate_digest, "candidate digest"),
        (review.source_evidence_digest, "source evidence digest"),
        (review.package_evidence_digest, "package evidence digest"),
        (review.policy_digest, "review policy digest"),
    ):
        _digest(value, field)
    expected = content_digest(_review_value(review, include_digest=False))
    if review.review_digest != expected:
        raise EcosystemReviewError("ecosystem review digest does not match")
    return canonical_bytes(_review_value(review, include_digest=True))


def project_accepted_ecosystems(
    reviews: Iterable[RepositoryEcosystemReviewV1],
    *,
    candidates_by_digest: Mapping[str, FixSiteCandidateV1],
    expected_policy_digest: str,
) -> tuple[tuple[str, CanonicalEcosystem], ...]:
    """Project at most one accepted ecosystem per canonical network identity."""
    accepted_by_network: dict[str, tuple[str, CanonicalEcosystem]] = {}
    network_by_repository: dict[str, str] = {}
    repository_by_network: dict[str, str] = {}
    for review in reviews:
        candidate = candidates_by_digest.get(review.candidate_digest)
        if candidate is None:
            raise EcosystemReviewError("ecosystem review candidate is not in the exact reviewed input set")
        repository_ecosystem_review_bytes(
            review,
            candidate=candidate,
            expected_policy_digest=expected_policy_digest,
        )
        known_network = network_by_repository.get(review.canonical_repository)
        if known_network is not None and known_network != review.network_identity_digest:
            raise EcosystemReviewError("canonical repository maps to conflicting network identities")
        known_repository = repository_by_network.get(review.network_identity_digest)
        if known_repository is not None and known_repository != review.canonical_repository:
            raise EcosystemReviewError("network identity maps to conflicting canonical repositories")
        network_by_repository[review.canonical_repository] = review.network_identity_digest
        repository_by_network[review.network_identity_digest] = review.canonical_repository
        if review.status is EcosystemReviewStatus.INSUFFICIENT:
            continue
        assert review.ecosystem is not None
        current = (review.canonical_repository, review.ecosystem)
        existing = accepted_by_network.get(review.network_identity_digest)
        if existing is not None and existing != current:
            raise EcosystemReviewError("repository has conflicting accepted ecosystem reviews")
        accepted_by_network[review.network_identity_digest] = current
    return tuple((network_digest, repository_ecosystem[1]) for network_digest, repository_ecosystem in sorted(accepted_by_network.items()))


__all__ = [
    "CanonicalEcosystem",
    "EcosystemInsufficientReason",
    "EcosystemReviewAttestationV1",
    "EcosystemReviewDecision",
    "EcosystemReviewError",
    "EcosystemReviewStatus",
    "RepositoryEcosystemReviewV1",
    "project_accepted_ecosystems",
    "repository_ecosystem_review_bytes",
    "review_repository_ecosystem",
]
