"""Development-opening transition and its reviewed influence events."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from benchmarks.valid.lifecycle import LifecycleError, PopulationLifecycleKind, _digest, _draft, _reviewed_event, _text
from benchmarks.valid.reservation import (
    InfluenceDisposition,
    InfluenceKind,
    RepositoryIdentityResolver,
    decode_influence_event,
    reviewed_influence_event,
)


@dataclass(frozen=True)
class DevelopmentOpeningResult:
    event_content: bytes
    influence_contents: tuple[bytes, ...]


def _development_influences(
    resolver: RepositoryIdentityResolver,
    repositories: Sequence[str],
    subject_digest: str,
    review: Mapping[str, object],
) -> tuple[bytes, ...]:
    canonical = sorted({resolver.resolve(repository).canonical_repository for repository in repositories})
    if not canonical:
        raise LifecycleError("development opening requires affected repositories")
    contents = tuple(
        reviewed_influence_event(
            resolver,
            repository=repository,
            event_source="baseline_lifecycle_development_opened",
            disposition=InfluenceDisposition.INFLUENCED,
            influence_kind=InfluenceKind.DETECTOR_DEVELOPMENT,
            subject_digest=subject_digest,
            actor_identity=str(review["producer_identity"]),
            reviewer_identity=str(review["reviewer_identity"]),
            conflict_disclosed=review["conflict_disclosed"] is True,
            policy_digest=str(review["policy_digest"]),
        )
        for repository in canonical
    )
    return tuple(sorted(contents, key=lambda item: decode_influence_event(item).event_digest))


def reviewed_development_opening(
    *,
    predecessor_digest: str,
    population_digest: str,
    freeze_digest: str,
    access_evidence_digest: str,
    resolver: RepositoryIdentityResolver,
    repositories: Sequence[str],
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> DevelopmentOpeningResult:
    producer_identity = _text(producer_identity, "producer identity")
    reviewer_identity = _text(reviewer_identity, "reviewer identity")
    policy_digest = _digest(policy_digest, "lifecycle policy digest")
    _digest(access_evidence_digest, "development access evidence digest")
    if producer_identity == reviewer_identity or conflict_disclosed is not True:
        raise LifecycleError("independent lifecycle review and conflict disclosure are required")
    review = {
        "producer_identity": producer_identity,
        "reviewer_identity": reviewer_identity,
        "conflict_disclosed": conflict_disclosed,
        "policy_digest": policy_digest,
    }
    influences = _development_influences(resolver, repositories, access_evidence_digest, review)
    influence_digests = tuple(decode_influence_event(item).event_digest for item in influences)
    draft = _draft(
        PopulationLifecycleKind.DEVELOPMENT_OPENED,
        predecessor_digest=predecessor_digest,
        historical_withdrawal_digest=None,
        population_digest=population_digest,
        freeze_digest=freeze_digest,
        evidence_digest=access_evidence_digest,
        reason_code="raw_population_evidence_opened",
        influence_event_digests=influence_digests,
        producer_identity=producer_identity,
        reviewer_identity=reviewer_identity,
        conflict_disclosed=conflict_disclosed,
        policy_digest=policy_digest,
    )
    return DevelopmentOpeningResult(_reviewed_event(draft), influences)


__all__ = ["DevelopmentOpeningResult", "reviewed_development_opening"]
