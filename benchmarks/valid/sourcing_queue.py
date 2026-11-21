"""Bounded label-blind replacement sourcing queues and reviewer evidence packages."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from benchmarks.valid.fix_site_catalog import (
    FixSiteCandidateV1,
    LicenseEvidence,
    PackageEcosystemEvidence,
)
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes, content_digest

SOURCING_QUEUE_SCHEMA = "openultrasast.valid-detection-benchmark.sourcing-queue.v1"
SOURCING_QUEUE_POLICY_SCHEMA = "openultrasast.valid-detection-benchmark.sourcing-queue-policy.v1"
REVIEWER_EVIDENCE_PACKAGE_SCHEMA = "openultrasast.valid-detection-benchmark.reviewer-evidence-package.v1"
MODEL_ASSISTANCE_SCHEMA = "openultrasast.valid-detection-benchmark.model-assistance.v1"
CANONICAL_ECOSYSTEMS = ("javascript", "python")
_LANGUAGE_ECOSYSTEM = {"javascript": "javascript", "python": "python", "typescript": "javascript"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_FAMILY = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")
_CWE = re.compile(r"CWE-\d+")


class SourcingQueueReason(StrEnum):
    """Closed refusal and exclusion vocabulary for sourcing queues."""

    RESERVED_REPOSITORY = "reserved_repository"
    UNRESOLVED_REPOSITORY = "unresolved_repository"
    UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"
    EVIDENCE_EMPTY = "evidence_empty"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    DUPLICATE_CANDIDATE = "duplicate_candidate"
    QUEUE_CAP_EXCEEDED = "queue_cap_exceeded"
    INSUFFICIENT_FAMILIES = "insufficient_families"
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


class QueueEntryStatus(StrEnum):
    """A queued candidate stays pending until an externally supplied review arrives."""

    PENDING_EXTERNAL_REVIEW = "pending_external_review"


_REASON_TEXT = {
    SourcingQueueReason.RESERVED_REPOSITORY: "repository identity is permanently reserved",
    SourcingQueueReason.UNRESOLVED_REPOSITORY: "repository identity is not resolved to a reviewed network",
    SourcingQueueReason.UNSUPPORTED_ECOSYSTEM: "observed language has no canonical replacement ecosystem",
    SourcingQueueReason.EVIDENCE_EMPTY: "candidate evidence is absent, empty, or unreadable",
    SourcingQueueReason.EVIDENCE_MISMATCH: "candidate evidence digests do not agree",
    SourcingQueueReason.DUPLICATE_CANDIDATE: "candidate identity is already queued",
    SourcingQueueReason.QUEUE_CAP_EXCEEDED: "bounded review queue is full",
    SourcingQueueReason.INSUFFICIENT_FAMILIES: "sourcing queue does not cover the required vulnerability families",
    SourcingQueueReason.STATE_UNREADABLE: "sourcing queue state bytes are unreadable",
    SourcingQueueReason.STATE_MISMATCH: "sourcing queue state does not match its canonical schema",
}


class SourcingQueueError(ValueError):
    """Closed sourcing queue refusal carrying one reason."""

    def __init__(self, reason: SourcingQueueReason) -> None:
        self.reason = reason
        super().__init__(_REASON_TEXT[reason])


@dataclass(frozen=True)
class SourcingQueuePolicy:
    per_ecosystem_cap: int
    required_families: int
    policy_digest: str


@dataclass(frozen=True)
class FamilyEvidence:
    vulnerability_family: str
    cwe: str
    advisory_locator: str
    advisory_digest: str


@dataclass(frozen=True)
class ReachabilityEvidence:
    entry_point: str
    evidence_digest: str


@dataclass(frozen=True)
class FixSiteEvidence:
    path: str
    function: str
    vulnerable_revision: str
    fixed_revision: str
    vulnerable_snapshot_digest: str
    fixed_snapshot_digest: str
    vulnerable_byte_length: int
    fixed_byte_length: int


@dataclass(frozen=True)
class ReviewQueueEntryV1:
    canonical_ecosystem: str
    observed_language: str
    candidate_digest: str
    canonical_repository: str
    network_identity_digest: str
    family: FamilyEvidence
    reachability: ReachabilityEvidence
    fix_site: FixSiteEvidence
    model_assistance_digest: str | None
    entry_status: QueueEntryStatus
    entry_digest: str


@dataclass(frozen=True)
class QueueExclusionV1:
    advisory_locator: str
    repository: str | None
    candidate_digest: str | None
    reason: SourcingQueueReason
    exclusion_digest: str


@dataclass(frozen=True)
class EcosystemReviewQueueV1:
    ecosystem: str
    cap: int
    policy_digest: str
    entries: tuple[ReviewQueueEntryV1, ...]
    queue_digest: str


@dataclass(frozen=True)
class SourcingQueueStateV1:
    python_queue: EcosystemReviewQueueV1
    javascript_queue: EcosystemReviewQueueV1
    exclusions: tuple[QueueExclusionV1, ...]
    census_digest: str
    policy_digest: str
    state_digest: str


@dataclass(frozen=True)
class SourcingCandidateRequest:
    case: Mapping[str, Any]
    family: FamilyEvidence
    reachability: ReachabilityEvidence
    package_evidence: PackageEcosystemEvidence
    license_evidence: LicenseEvidence
    model_assistance_digest: str | None = None


def _closed_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    return value.strip()


def _closed_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    return value


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    return value


def family_evidence(*, vulnerability_family: str, cwe: str, advisory_locator: str, advisory_text: str) -> FamilyEvidence:
    """Bind one advisory's family classification to the exact advisory bytes."""
    family = _closed_text(vulnerability_family, "vulnerability family")
    if _FAMILY.fullmatch(family) is None:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    advisory_cwe = _closed_text(cwe, "advisory cwe")
    if _CWE.fullmatch(advisory_cwe) is None:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    locator = _closed_text(advisory_locator, "advisory locator")
    text = _closed_text(advisory_text, "advisory text")
    return FamilyEvidence(family, advisory_cwe, locator, bytes_digest(text.encode("utf-8")))


def reachability_evidence(*, entry_point: str, evidence: str) -> ReachabilityEvidence:
    """Record an observed in-repository reachability route for later review."""
    point = _closed_text(entry_point, "reachability entry point")
    route = _closed_text(evidence, "reachability evidence")
    return ReachabilityEvidence(point, bytes_digest(route.encode("utf-8")))


def fix_site_evidence(
    *,
    path: str,
    function: str,
    vulnerable_revision: str,
    fixed_revision: str,
    vulnerable_snapshot_digest: str,
    fixed_snapshot_digest: str,
    vulnerable_byte_length: int,
    fixed_byte_length: int,
) -> FixSiteEvidence:
    """Nonzero fix-derived locator and snapshot identities for one candidate."""
    for revision in (vulnerable_revision, fixed_revision):
        if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
            raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    if vulnerable_revision == fixed_revision:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    return FixSiteEvidence(
        _closed_text(path, "fix-site path"),
        _closed_text(function, "fix-site function"),
        vulnerable_revision,
        fixed_revision,
        _closed_digest(vulnerable_snapshot_digest),
        _closed_digest(fixed_snapshot_digest),
        _positive_int(vulnerable_byte_length),
        _positive_int(fixed_byte_length),
    )


def sourcing_queue_policy(*, per_ecosystem_cap: int, required_families: int = 2) -> SourcingQueuePolicy:
    if isinstance(per_ecosystem_cap, bool) or not isinstance(per_ecosystem_cap, int) or per_ecosystem_cap < 1:
        raise ValueError("per-ecosystem cap must be a positive integer")
    if isinstance(required_families, bool) or not isinstance(required_families, int) or required_families < 2:
        raise ValueError("required families must be at least two")
    digest = content_digest(
        {
            "schema_version": SOURCING_QUEUE_POLICY_SCHEMA,
            "per_ecosystem_cap": per_ecosystem_cap,
            "required_families": required_families,
        }
    )
    return SourcingQueuePolicy(per_ecosystem_cap, required_families, digest)


def review_queue_entry(
    *,
    canonical_ecosystem: str,
    observed_language: str,
    candidate_digest: str,
    canonical_repository: str,
    network_identity_digest: str,
    family: FamilyEvidence,
    reachability: ReachabilityEvidence,
    fix_site: FixSiteEvidence,
    model_assistance_digest: str | None = None,
) -> ReviewQueueEntryV1:
    """Derive one pending queue entry; TypeScript stays an observed javascript language."""
    ecosystem = _LANGUAGE_ECOSYSTEM.get(observed_language)
    if ecosystem != canonical_ecosystem or ecosystem is None:
        raise SourcingQueueError(SourcingQueueReason.UNSUPPORTED_ECOSYSTEM)
    draft = ReviewQueueEntryV1(
        canonical_ecosystem,
        observed_language,
        _closed_digest(candidate_digest),
        _closed_text(canonical_repository, "canonical repository"),
        _closed_digest(network_identity_digest),
        family,
        reachability,
        fix_site,
        model_assistance_digest,
        QueueEntryStatus.PENDING_EXTERNAL_REVIEW,
        "",
    )
    return replace(draft, entry_digest=content_digest(_entry_value(draft, include_digest=False)))


def queue_exclusion(
    *,
    advisory_locator: str,
    repository: str | None,
    candidate_digest: str | None,
    reason: SourcingQueueReason,
) -> QueueExclusionV1:
    """Persist one closed exclusion reason before any review happens."""
    draft = QueueExclusionV1(_closed_text(advisory_locator, "advisory locator"), repository, candidate_digest, reason, "")
    return replace(draft, exclusion_digest=content_digest(_exclusion_value(draft)))


def ecosystem_review_queue(
    ecosystem: str,
    *,
    cap: int,
    policy_digest: str,
    entries: Iterable[ReviewQueueEntryV1],
) -> EcosystemReviewQueueV1:
    """One bounded per-ecosystem queue in canonical entry-digest order."""
    if ecosystem not in CANONICAL_ECOSYSTEMS:
        raise SourcingQueueError(SourcingQueueReason.UNSUPPORTED_ECOSYSTEM)
    ordered = tuple(sorted(entries, key=lambda item: item.entry_digest))
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1 or len(ordered) > cap:
        raise SourcingQueueError(SourcingQueueReason.QUEUE_CAP_EXCEEDED)
    draft = EcosystemReviewQueueV1(ecosystem, cap, _closed_digest(policy_digest), ordered, "")
    return replace(draft, queue_digest=content_digest(_queue_value(draft, include_digest=False)))


def sourcing_queue_state(
    *,
    python_queue: EcosystemReviewQueueV1,
    javascript_queue: EcosystemReviewQueueV1,
    exclusions: Iterable[QueueExclusionV1],
    census_digest: str,
    policy_digest: str,
) -> SourcingQueueStateV1:
    """Assemble resumable queue state bound to the reservation census snapshot."""
    if python_queue.ecosystem != "python" or javascript_queue.ecosystem != "javascript":
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    for queue in (python_queue, javascript_queue):
        if queue.policy_digest != policy_digest:
            raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    draft = SourcingQueueStateV1(
        python_queue,
        javascript_queue,
        tuple(sorted(exclusions, key=lambda item: item.exclusion_digest)),
        _closed_digest(census_digest),
        _closed_digest(policy_digest),
        "",
    )
    return replace(draft, state_digest=content_digest(_state_value(draft, include_digest=False)))


def sourcing_candidate_request(
    case: Mapping[str, Any],
    *,
    family: FamilyEvidence,
    reachability: ReachabilityEvidence,
    package_evidence: PackageEcosystemEvidence,
    license_evidence: LicenseEvidence,
    model_assistance_digest: str | None = None,
) -> SourcingCandidateRequest:
    """One label-blind fix-site case plus its reviewed repository evidence."""
    return SourcingCandidateRequest(case, family, reachability, package_evidence, license_evidence, model_assistance_digest)


def fix_site_evidence_from_candidate(candidate: FixSiteCandidateV1) -> FixSiteEvidence:
    """Project the catalog's nonzero vulnerable/fixed snapshots into queue evidence."""
    return fix_site_evidence(
        path=candidate.vulnerable.path,
        function=candidate.vulnerable.function,
        vulnerable_revision=candidate.vulnerable.revision,
        fixed_revision=candidate.fixed.revision,
        vulnerable_snapshot_digest=candidate.vulnerable.content_digest,
        fixed_snapshot_digest=candidate.fixed.content_digest,
        vulnerable_byte_length=candidate.vulnerable.byte_length,
        fixed_byte_length=candidate.fixed.byte_length,
    )


def _family_value(item: FamilyEvidence) -> dict[str, JsonValue]:
    return {
        "vulnerability_family": item.vulnerability_family,
        "cwe": item.cwe,
        "advisory_locator": item.advisory_locator,
        "advisory_digest": item.advisory_digest,
    }


def _reachability_value(item: ReachabilityEvidence) -> dict[str, JsonValue]:
    return {"entry_point": item.entry_point, "evidence_digest": item.evidence_digest}


def _fix_site_value(item: FixSiteEvidence) -> dict[str, JsonValue]:
    return {
        "path": item.path,
        "function": item.function,
        "vulnerable_revision": item.vulnerable_revision,
        "fixed_revision": item.fixed_revision,
        "vulnerable_snapshot_digest": item.vulnerable_snapshot_digest,
        "fixed_snapshot_digest": item.fixed_snapshot_digest,
        "vulnerable_byte_length": item.vulnerable_byte_length,
        "fixed_byte_length": item.fixed_byte_length,
    }


def _entry_value(entry: ReviewQueueEntryV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "canonical_ecosystem": entry.canonical_ecosystem,
        "observed_language": entry.observed_language,
        "candidate_digest": entry.candidate_digest,
        "canonical_repository": entry.canonical_repository,
        "network_identity_digest": entry.network_identity_digest,
        "family": _family_value(entry.family),
        "reachability": _reachability_value(entry.reachability),
        "fix_site": _fix_site_value(entry.fix_site),
        "model_assistance_digest": entry.model_assistance_digest,
        "entry_status": entry.entry_status.value,
    }
    if include_digest:
        value["entry_digest"] = entry.entry_digest
    return value


def _queue_value(queue: EcosystemReviewQueueV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "ecosystem": queue.ecosystem,
        "cap": queue.cap,
        "policy_digest": queue.policy_digest,
        "entries": tuple(_entry_value(entry, include_digest=True) for entry in queue.entries),
    }
    if include_digest:
        value["queue_digest"] = queue.queue_digest
    return value


def _exclusion_value(item: QueueExclusionV1) -> dict[str, JsonValue]:
    return {
        "advisory_locator": item.advisory_locator,
        "repository": item.repository,
        "candidate_digest": item.candidate_digest,
        "reason": item.reason.value,
        "exclusion_digest": item.exclusion_digest,
    }


def queue_state_value(state: SourcingQueueStateV1) -> dict[str, JsonValue]:
    """Canonical state payload used for durable persistence and exact rereads."""
    value: dict[str, JsonValue] = {
        "schema_version": SOURCING_QUEUE_SCHEMA,
        "python_queue": _queue_value(state.python_queue, include_digest=True),
        "javascript_queue": _queue_value(state.javascript_queue, include_digest=True),
        "exclusions": tuple(_exclusion_value(item) for item in state.exclusions),
        "census_digest": state.census_digest,
        "policy_digest": state.policy_digest,
        "state_digest": state.state_digest,
    }
    return value


def _state_value(state: SourcingQueueStateV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value = queue_state_value(state)
    if not include_digest:
        value.pop("state_digest")
    return value


def queue_state_bytes(state: SourcingQueueStateV1) -> bytes:
    """Encode validated queue state as canonical bytes."""
    for queue in (state.python_queue, state.javascript_queue):
        if queue.queue_digest != content_digest(_queue_value(queue, include_digest=False)):
            raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    if state.state_digest != content_digest(_state_value(state, include_digest=False)):
        raise SourcingQueueError(SourcingQueueReason.STATE_MISMATCH)
    return canonical_bytes(queue_state_value(state))


def pending_queue_identities(state: SourcingQueueStateV1) -> tuple[str, ...]:
    """Deterministic pending identities a restart must reproduce exactly."""
    return tuple(
        f"{queue.ecosystem}:{entry.entry_digest}" for queue in (state.python_queue, state.javascript_queue) for entry in queue.entries
    )


def reviewer_evidence_payload(entry: ReviewQueueEntryV1) -> dict[str, JsonValue]:
    """Canonical reviewer evidence: digests and locators only, never a verdict."""
    assistance: JsonValue = (
        None
        if entry.model_assistance_digest is None
        else {"schema_version": MODEL_ASSISTANCE_SCHEMA, "digest": entry.model_assistance_digest, "authoritative": False}
    )
    return {
        "schema_version": REVIEWER_EVIDENCE_PACKAGE_SCHEMA,
        "queue_entry_digest": entry.entry_digest,
        "entry_status": entry.entry_status.value,
        "canonical_ecosystem": entry.canonical_ecosystem,
        "observed_language": entry.observed_language,
        "canonical_repository": entry.canonical_repository,
        "candidate_digest": entry.candidate_digest,
        "family": _family_value(entry.family),
        "reachability": _reachability_value(entry.reachability),
        "fix_site": _fix_site_value(entry.fix_site),
        "model_assistance": assistance,
    }


def reviewer_evidence_package_bytes(entry: ReviewQueueEntryV1) -> bytes:
    """Canonical bytes handed to independent reviewers for external judgment."""
    return canonical_bytes(reviewer_evidence_payload(entry))


__all__ = [
    "CANONICAL_ECOSYSTEMS",
    "EcosystemReviewQueueV1",
    "FamilyEvidence",
    "FixSiteEvidence",
    "QueueEntryStatus",
    "QueueExclusionV1",
    "ReachabilityEvidence",
    "REVIEWER_EVIDENCE_PACKAGE_SCHEMA",
    "ReviewQueueEntryV1",
    "SOURCING_QUEUE_SCHEMA",
    "SourcingCandidateRequest",
    "SourcingQueueError",
    "SourcingQueuePolicy",
    "SourcingQueueReason",
    "SourcingQueueStateV1",
    "family_evidence",
    "fix_site_evidence",
    "fix_site_evidence_from_candidate",
    "pending_queue_identities",
    "queue_exclusion",
    "queue_state_bytes",
    "queue_state_value",
    "reachability_evidence",
    "review_queue_entry",
    "reviewer_evidence_package_bytes",
    "reviewer_evidence_payload",
    "sourcing_candidate_request",
    "sourcing_queue_policy",
]
