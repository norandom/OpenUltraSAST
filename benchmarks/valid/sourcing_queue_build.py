"""Build bounded sourcing queues from fix-derived candidates without labels."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from benchmarks.valid.catalog import candidate_request
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1, FixSiteReader, build_fix_site_candidate
from benchmarks.valid.reservation import (
    InfluenceDisposition,
    InfluenceKind,
    RepositoryIdentityResolver,
    ReservationAuthority,
    ReservationCensusV1,
    ReservationError,
    reviewed_influence_event,
)
from benchmarks.valid.sourcing_queue import (
    QueueExclusionV1,
    ReviewQueueEntryV1,
    SourcingCandidateRequest,
    SourcingQueueError,
    SourcingQueuePolicy,
    SourcingQueueReason,
    SourcingQueueStateV1,
    ecosystem_review_queue,
    fix_site_evidence_from_candidate,
    queue_exclusion,
    review_queue_entry,
    sourcing_queue_state,
)

ENUMERATION_EVENT_SOURCE = "valid-benchmark-sourcing-queue"
_LANGUAGE_ECOSYSTEM = {"javascript": "javascript", "python": "python", "typescript": "javascript"}


@dataclass(frozen=True)
class _Outcome:
    advisory_locator: str
    repository: str | None
    ecosystem: str | None
    candidate: FixSiteCandidateV1 | None
    reason: SourcingQueueReason | None


def _resolve_outcome(
    request: SourcingCandidateRequest,
    *,
    reader: FixSiteReader,
    resolver: RepositoryIdentityResolver,
    authority: ReservationAuthority,
    census: ReservationCensusV1,
) -> _Outcome:
    """Resolve one candidate, exclude reserved networks, and read its fix-site evidence."""
    locator = request.family.advisory_locator
    try:
        network = authority.resolve_repository(str(request.case["url"]))
    except ReservationError:
        return _Outcome(locator, None, None, None, SourcingQueueReason.UNRESOLVED_REPOSITORY)
    if authority.is_reserved(network.canonical_repository, census):
        return _Outcome(locator, network.canonical_repository, None, None, SourcingQueueReason.RESERVED_REPOSITORY)
    ecosystem = _LANGUAGE_ECOSYSTEM.get(str(request.case["language"]))
    if ecosystem is None:
        return _Outcome(locator, network.canonical_repository, None, None, SourcingQueueReason.UNSUPPORTED_ECOSYSTEM)
    try:
        fix_request = candidate_request(
            request.case,
            resolver=resolver,
            package_evidence=request.package_evidence,
            license_evidence=request.license_evidence,
        )
        candidate = build_fix_site_candidate(reader, fix_request)
    except (TypeError, ValueError, KeyError):
        return _Outcome(locator, network.canonical_repository, None, None, SourcingQueueReason.EVIDENCE_EMPTY)
    if request.family.advisory_digest != candidate.source_evidence.evidence_digest:
        return _Outcome(locator, network.canonical_repository, ecosystem, candidate, SourcingQueueReason.EVIDENCE_MISMATCH)
    return _Outcome(locator, network.canonical_repository, ecosystem, candidate, None)


def _request_order(request: SourcingCandidateRequest) -> tuple[str, str, str, str]:
    digest = request.model_assistance_digest or ""
    return (str(request.case.get("url", "")), request.family.advisory_locator, request.reachability.evidence_digest, digest)


def _entry(outcome: _Outcome, request: SourcingCandidateRequest) -> ReviewQueueEntryV1:
    candidate = outcome.candidate
    if candidate is None or outcome.ecosystem is None:
        raise SourcingQueueError(SourcingQueueReason.EVIDENCE_EMPTY)
    return review_queue_entry(
        canonical_ecosystem=outcome.ecosystem,
        observed_language=candidate.observed_language,
        candidate_digest=candidate.candidate_digest,
        canonical_repository=candidate.canonical_repository,
        network_identity_digest=candidate.network_identity_digest,
        family=request.family,
        reachability=request.reachability,
        fix_site=fix_site_evidence_from_candidate(candidate),
        model_assistance_digest=request.model_assistance_digest,
    )


def _record_enumeration(
    authority: ReservationAuthority,
    resolver: RepositoryIdentityResolver,
    entries: Sequence[ReviewQueueEntryV1],
    *,
    policy: SourcingQueuePolicy,
    actor: str,
    reviewer: str,
) -> None:
    """Record enumeration without ever counting it as repository influence."""
    for entry in sorted(entries, key=lambda item: item.candidate_digest):
        content = reviewed_influence_event(
            resolver,
            repository=entry.canonical_repository,
            event_source=ENUMERATION_EVENT_SOURCE,
            disposition=InfluenceDisposition.ENUMERATED_ONLY,
            influence_kind=InfluenceKind.ENUMERATION,
            subject_digest=entry.candidate_digest,
            actor_identity=actor,
            reviewer_identity=reviewer,
            conflict_disclosed=True,
            policy_digest=policy.policy_digest,
        )
        authority.append_influence(content)


def build_sourcing_queue(
    requests: Sequence[SourcingCandidateRequest],
    *,
    reader: FixSiteReader,
    resolver: RepositoryIdentityResolver,
    authority: ReservationAuthority,
    policy: SourcingQueuePolicy,
    enumeration_actor: str,
    enumeration_reviewer: str,
) -> SourcingQueueStateV1:
    """Queue label-blind fix-derived candidates into bounded per-ecosystem review queues."""
    if not isinstance(policy, SourcingQueuePolicy):
        raise ValueError("sourcing queue policy is required")
    census = authority.current_census()
    ordered = sorted(requests, key=_request_order)
    outcomes = [_resolve_outcome(request, reader=reader, resolver=resolver, authority=authority, census=census) for request in ordered]
    filled: dict[str, list[ReviewQueueEntryV1]] = {"javascript": [], "python": []}
    exclusions = []
    seen: set[str] = set()
    for request, outcome in zip(ordered, outcomes, strict=True):
        candidate = outcome.candidate
        if outcome.reason is not None:
            exclusions.append(_exclusion(outcome, outcome.reason))
            continue
        ecosystem = outcome.ecosystem
        digest = candidate.candidate_digest if candidate is not None else None
        capped = ecosystem is not None and len(filled[ecosystem]) >= policy.per_ecosystem_cap
        if digest is None or ecosystem is None or digest in seen or capped:
            duplicated = digest is not None and digest in seen
            reason = SourcingQueueReason.DUPLICATE_CANDIDATE if duplicated else SourcingQueueReason.QUEUE_CAP_EXCEEDED
            exclusions.append(_exclusion(outcome, reason))
            continue
        seen.add(digest)
        filled[ecosystem].append(_entry(outcome, request))
    families = {entry.family.vulnerability_family for group in filled.values() for entry in group}
    if len(families) < policy.required_families:
        raise SourcingQueueError(SourcingQueueReason.INSUFFICIENT_FAMILIES) from None
    entries = (*filled["python"], *filled["javascript"])
    _record_enumeration(authority, resolver, entries, policy=policy, actor=enumeration_actor, reviewer=enumeration_reviewer)
    return sourcing_queue_state(
        python_queue=ecosystem_review_queue(
            "python", cap=policy.per_ecosystem_cap, policy_digest=policy.policy_digest, entries=filled["python"]
        ),
        javascript_queue=ecosystem_review_queue(
            "javascript", cap=policy.per_ecosystem_cap, policy_digest=policy.policy_digest, entries=filled["javascript"]
        ),
        exclusions=exclusions,
        census_digest=authority.current_census().census_digest,
        policy_digest=policy.policy_digest,
    )


def _exclusion(outcome: _Outcome, reason: SourcingQueueReason) -> QueueExclusionV1:
    return queue_exclusion(
        advisory_locator=outcome.advisory_locator,
        repository=outcome.repository,
        candidate_digest=None if outcome.candidate is None else outcome.candidate.candidate_digest,
        reason=reason,
    )


__all__ = ["ENUMERATION_EVENT_SOURCE", "build_sourcing_queue"]
