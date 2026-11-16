"""Deterministic first-parent ordinary-change draws for accepted positives."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ground_truth_review import GroundTruthStatus, ground_truth_review_bytes, project_accepted_ground_truth
from benchmarks.valid.lifecycle import (
    PopulationLifecycleProjectionV1,
    PopulationLifecycleState,
    RetirementReason,
    reviewed_retirement_event,
)
from benchmarks.valid.lifecycle_projection import projection_bytes
from benchmarks.valid.ordinary_change_contract import (
    ContaminationTiming,
    OrdinaryContaminationReviewV1,
    OrdinaryDrawAssignmentV1,
    OrdinaryExclusionReason,
    OrdinaryExclusionV1,
    OrdinaryFixExclusionV1,
    OrdinaryHistoryReader,
    OrdinaryHistorySource,
    OrdinaryPushV1,
    OrdinarySelectionError,
    OrdinarySelectionV1,
    ReviewedPositiveInput,
    _digest,
    _fix_exclusion_value,
    _push_value,
    _revision,
    _selection_value,
    contamination_review_bytes,
    ordinary_selection_bytes,
    reviewed_contamination,
)
from openultrasast.core.canonical import bytes_digest, content_digest


def _validate_positive(item: ReviewedPositiveInput, ecosystem_policy: str, ground_truth_policy: str) -> tuple[str, str, CanonicalEcosystem]:
    encoded = ground_truth_review_bytes(
        item.ground_truth_review,
        candidate=item.candidate,
        ecosystem_review=item.ecosystem_review,
        expected_ecosystem_policy_digest=ecosystem_policy,
        expected_ground_truth_policy_digest=ground_truth_policy,
    )
    if not encoded or item.ground_truth_review.status is not GroundTruthStatus.ACCEPTED:
        raise OrdinarySelectionError("ordinary draw requires accepted ground truth")
    ecosystem = item.ecosystem_review.ecosystem
    if ecosystem is None:
        raise OrdinarySelectionError("ordinary draw requires accepted ecosystem")
    return item.ground_truth_review.change_identity_digest, item.candidate.network_identity_digest, ecosystem


def _contaminations(
    reviews: Iterable[OrdinaryContaminationReviewV1],
) -> dict[tuple[str, str], OrdinaryContaminationReviewV1]:
    result: dict[tuple[str, str], OrdinaryContaminationReviewV1] = {}
    for review in reviews:
        contamination_review_bytes(review)
        if review.timing is not ContaminationTiming.PRE_FREEZE:
            raise OrdinarySelectionError("post-freeze contamination cannot rewrite an ordinary draw")
        key = (review.network_identity_digest, review.tip_revision)
        existing = result.get(key)
        if existing is not None and existing != review:
            raise OrdinarySelectionError("one ordinary push has conflicting contamination reviews")
        result[key] = review
    return result


def _ordinary_push(
    item: ReviewedPositiveInput,
    ecosystem: CanonicalEcosystem,
    source_digest: str,
    base: str,
    tip: str,
    content: bytes,
) -> OrdinaryPushV1:
    if not isinstance(content, bytes) or not content:
        raise OrdinarySelectionError("ordinary change bytes are empty")
    draft = OrdinaryPushV1(
        item.candidate.canonical_repository,
        item.candidate.network_identity_digest,
        ecosystem,
        base,
        tip,
        len(content),
        bytes_digest(content),
        source_digest,
        "",
    )
    return OrdinaryPushV1(**{**vars(draft), "push_digest": content_digest(_push_value(draft, include_digest=False))})


def _draw_one(
    item: ReviewedPositiveInput,
    source: OrdinaryHistorySource,
    identity: tuple[str, str, CanonicalEcosystem],
    accepted_fixes: frozenset[tuple[str, str]],
    contamination: Mapping[tuple[str, str], OrdinaryContaminationReviewV1],
    required: int,
) -> tuple[list[OrdinaryPushV1], list[OrdinaryExclusionV1]]:
    _, network_digest, ecosystem = identity
    fixed = item.candidate.fixed.revision
    parents = tuple(source.reader.parents(fixed))
    if not parents or parents[0] != item.candidate.vulnerable.revision:
        raise OrdinarySelectionError("history does not bind the exact fix parent")
    tip = parents[0]
    pushes: list[OrdinaryPushV1] = []
    exclusions: list[OrdinaryExclusionV1] = []
    seen = {fixed}
    while len(pushes) < required:
        if tip in seen:
            raise OrdinarySelectionError("first-parent history contains a cycle")
        seen.add(tip)
        ancestors = tuple(source.reader.parents(tip))
        if not ancestors:
            break
        base = _revision(ancestors[0], "ordinary first parent")
        if (network_digest, tip) in accepted_fixes:
            tip = base
            continue
        content = source.reader.change_bytes(tip)
        if content is None:
            raise OrdinarySelectionError("ordinary change bytes are unreadable")
        review = contamination.get((network_digest, tip))
        if review is None:
            pushes.append(_ordinary_push(item, ecosystem, source.source_digest, base, tip, content))
        else:
            exclusions.append(
                OrdinaryExclusionV1(
                    network_digest,
                    tip,
                    OrdinaryExclusionReason.REVIEWED_SECURITY_DEFECT,
                    review.review_digest,
                )
            )
        tip = base
    if len(pushes) < required:
        raise OrdinarySelectionError(f"ordinary first-parent history supplies {len(pushes)} of {required} required pushes")
    return pushes, exclusions


def _validated_positives(
    positives: Iterable[ReviewedPositiveInput],
    ecosystem_policy: str,
    ground_truth_policy: str,
) -> tuple[ReviewedPositiveInput, ...]:
    values = tuple(positives)
    candidates = {item.candidate.candidate_digest: item.candidate for item in values}
    ecosystems = {item.ecosystem_review.review_digest: item.ecosystem_review for item in values}
    project_accepted_ground_truth(
        (item.ground_truth_review for item in values),
        candidates_by_digest=candidates,
        ecosystem_reviews_by_digest=ecosystems,
        expected_ecosystem_policy_digest=ecosystem_policy,
        expected_ground_truth_policy_digest=ground_truth_policy,
    )
    if not values:
        raise OrdinarySelectionError("ordinary draw requires accepted positives")
    return values


def _accepted_fixes(
    positives: tuple[ReviewedPositiveInput, ...],
) -> tuple[tuple[OrdinaryFixExclusionV1, ...], frozenset[tuple[str, str]]]:
    exclusions: set[OrdinaryFixExclusionV1] = set()
    revisions: set[tuple[str, str]] = set()
    for item in positives:
        review = item.ground_truth_review
        exclusion = OrdinaryFixExclusionV1(
            item.candidate.network_identity_digest,
            item.candidate.fixed.revision,
            review.change_identity_digest,
            review.review_digest,
        )
        exclusions.add(exclusion)
        revisions.add((exclusion.network_identity_digest, exclusion.fixed_revision))
    ordered = tuple(sorted(exclusions))
    if len(ordered) != len(positives):
        raise OrdinarySelectionError("accepted positives do not have unique fix authorities")
    return ordered, frozenset(revisions)


def _collect_draws(
    positives: tuple[ReviewedPositiveInput, ...],
    history_by_network: Mapping[str, OrdinaryHistorySource],
    accepted_fixes: frozenset[tuple[str, str]],
    contamination: Mapping[tuple[str, str], OrdinaryContaminationReviewV1],
    required: int,
    ecosystem_policy: str,
    ground_truth_policy: str,
) -> tuple[
    dict[str, OrdinaryPushV1],
    set[OrdinaryDrawAssignmentV1],
    set[OrdinaryExclusionV1],
    set[str],
    set[tuple[str, str, str]],
]:
    pushes_by_digest: dict[str, OrdinaryPushV1] = {}
    assignments: set[OrdinaryDrawAssignmentV1] = set()
    exclusions: set[OrdinaryExclusionV1] = set()
    positive_digests: set[str] = set()
    source_identities: set[tuple[str, str, str]] = set()
    for item in positives:
        identity = _validate_positive(item, ecosystem_policy, ground_truth_policy)
        change_digest, network_digest, ecosystem = identity
        if change_digest in positive_digests:
            raise OrdinarySelectionError("ordinary draw contains a duplicate positive change identity")
        positive_digests.add(change_digest)
        source = history_by_network.get(network_digest)
        if source is None:
            raise OrdinarySelectionError("ordinary history source is missing for repository network")
        if (source.canonical_repository, source.network_identity_digest) != (
            item.candidate.canonical_repository,
            network_digest,
        ):
            raise OrdinarySelectionError("ordinary history source crosses repository identity")
        source_digest = _digest(source.source_digest, "history source digest")
        source_identities.add((source.canonical_repository, network_digest, source_digest))
        drawn, excluded = _draw_one(item, source, identity, accepted_fixes, contamination, required)
        for push in drawn:
            existing = pushes_by_digest.get(push.push_digest)
            if existing is not None and existing != push:
                raise OrdinarySelectionError("same ordinary push identity has different content")
            pushes_by_digest[push.push_digest] = push
            assignments.add(OrdinaryDrawAssignmentV1(change_digest, network_digest, ecosystem, push.push_digest))
        exclusions.update(excluded)
    supplied_reviews = {review.review_digest for review in contamination.values()}
    applied_reviews = {item.contamination_review_digest for item in exclusions}
    if supplied_reviews != applied_reviews:
        raise OrdinarySelectionError("contamination review does not identify the selected first-parent histories")
    return pushes_by_digest, assignments, exclusions, positive_digests, source_identities


def draw_ordinary_selection(
    positives: Iterable[ReviewedPositiveInput],
    *,
    history_by_network: Mapping[str, OrdinaryHistorySource],
    contamination_reviews: Iterable[OrdinaryContaminationReviewV1] = (),
    required_per_positive: int = 20,
    policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> OrdinarySelectionV1:
    if isinstance(required_per_positive, bool) or required_per_positive < 20:
        raise OrdinarySelectionError("ordinary draw requires at least 20 pushes per positive")
    positives = _validated_positives(positives, expected_ecosystem_policy_digest, expected_ground_truth_policy_digest)
    policy = _digest(policy_digest, "ordinary selection policy digest")
    contamination = _contaminations(contamination_reviews)
    fix_exclusions, accepted_fixes = _accepted_fixes(positives)
    pushes, assignments, exclusions, positive_digests, source_identities = _collect_draws(
        positives,
        history_by_network,
        accepted_fixes,
        contamination,
        required_per_positive,
        expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest,
    )
    draft = OrdinarySelectionV1(
        required_per_positive,
        policy,
        tuple(sorted(positive_digests)),
        fix_exclusions,
        tuple(pushes[key] for key in sorted(pushes)),
        tuple(sorted(assignments)),
        tuple(sorted(exclusions)),
        content_digest(
            {
                "history_sources": tuple(sorted(source_identities)),
                "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in fix_exclusions),
                "policy_digest": policy,
            }
        ),
        "",
    )
    selection = OrdinarySelectionV1(**{**vars(draft), "selection_digest": content_digest(_selection_value(draft, include_digest=False))})
    ordinary_selection_bytes(selection)
    return selection


def validate_ordinary_selection(
    selection: OrdinarySelectionV1,
    positives: Iterable[ReviewedPositiveInput],
    *,
    history_by_network: Mapping[str, OrdinaryHistorySource],
    contamination_reviews: Iterable[OrdinaryContaminationReviewV1] = (),
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
) -> bytes:
    """Reproduce one draw from exact review, history, contamination, and policy inputs."""
    expected = draw_ordinary_selection(
        positives,
        history_by_network=history_by_network,
        contamination_reviews=contamination_reviews,
        required_per_positive=selection.required_per_positive,
        policy_digest=selection.policy_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
    )
    if expected != selection:
        raise OrdinarySelectionError("ordinary selection does not reproduce from exact inputs")
    return ordinary_selection_bytes(selection)


def post_freeze_contamination_retirement(
    selection: OrdinarySelectionV1,
    review: OrdinaryContaminationReviewV1,
    lifecycle: PopulationLifecycleProjectionV1,
) -> bytes:
    before = ordinary_selection_bytes(selection)
    contamination_review_bytes(review)
    projection_bytes(lifecycle)
    if review.timing is not ContaminationTiming.POST_FREEZE:
        raise OrdinarySelectionError("retirement requires post-freeze contamination review")
    matches = [
        push
        for push in selection.pushes
        if (push.network_identity_digest, push.tip_revision) == (review.network_identity_digest, review.tip_revision)
    ]
    if len(matches) != 1:
        raise OrdinarySelectionError("post-freeze contamination does not identify one selected push")
    if lifecycle.state is not PopulationLifecycleState.REPLACEMENT_COMPLETE or not lifecycle.admission_eligible:
        raise OrdinarySelectionError("post-freeze contamination requires an active replacement lifecycle")
    if lifecycle.population_digest is None or lifecycle.freeze_digest is None:
        raise OrdinarySelectionError("active replacement lifecycle lacks population identity")
    evidence = content_digest({"selection_digest": selection.selection_digest, "review_digest": review.review_digest})
    event = reviewed_retirement_event(
        predecessor_digest=lifecycle.head_event_digest,
        population_digest=lifecycle.population_digest,
        freeze_digest=lifecycle.freeze_digest,
        evidence_digest=evidence,
        reason_code=RetirementReason.CONTAMINATED_NEGATIVE.value,
        producer_identity=review.producer_identity,
        reviewer_identity=review.reviewer_identity,
        conflict_disclosed=review.conflict_disclosed,
        policy_digest=review.policy_digest,
    )
    if ordinary_selection_bytes(selection) != before:
        raise OrdinarySelectionError("post-freeze contamination rewrote the ordinary selection")
    return event


__all__ = [
    "ContaminationTiming",
    "OrdinaryContaminationReviewV1",
    "OrdinaryDrawAssignmentV1",
    "OrdinaryExclusionReason",
    "OrdinaryExclusionV1",
    "OrdinaryFixExclusionV1",
    "OrdinaryHistoryReader",
    "OrdinaryHistorySource",
    "OrdinaryPushV1",
    "OrdinarySelectionError",
    "OrdinarySelectionV1",
    "ReviewedPositiveInput",
    "contamination_review_bytes",
    "draw_ordinary_selection",
    "ordinary_selection_bytes",
    "post_freeze_contamination_retirement",
    "reviewed_contamination",
    "validate_ordinary_selection",
]
