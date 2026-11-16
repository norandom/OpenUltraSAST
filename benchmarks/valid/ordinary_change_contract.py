"""Canonical contracts for ordinary-change selection and contamination review."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from benchmarks.valid.ecosystem_review import CanonicalEcosystem, RepositoryEcosystemReviewV1
from benchmarks.valid.fix_site_catalog import FixSiteCandidateV1
from benchmarks.valid.ground_truth_review import GroundTruthReviewV1
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

ORDINARY_SELECTION_SCHEMA = "openultrasast.valid-detection-benchmark.ordinary-selection.v1"
CONTAMINATION_REVIEW_SCHEMA = "openultrasast.valid-detection-benchmark.ordinary-contamination-review.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class OrdinarySelectionError(ValueError):
    """Ordinary history or reviewed contamination cannot authorize a draw."""


class ContaminationTiming(StrEnum):
    PRE_FREEZE = "pre_freeze"
    POST_FREEZE = "post_freeze"


class OrdinaryExclusionReason(StrEnum):
    REVIEWED_SECURITY_DEFECT = "reviewed_security_defect"


class OrdinaryHistoryReader(Protocol):
    def parents(self, revision: str) -> Sequence[str]: ...

    def change_bytes(self, revision: str) -> bytes | None: ...


@dataclass(frozen=True)
class ReviewedPositiveInput:
    candidate: FixSiteCandidateV1
    ecosystem_review: RepositoryEcosystemReviewV1
    ground_truth_review: GroundTruthReviewV1


@dataclass(frozen=True)
class OrdinaryHistorySource:
    reader: OrdinaryHistoryReader
    canonical_repository: str
    network_identity_digest: str
    source_digest: str


@dataclass(frozen=True, order=True)
class OrdinaryPushV1:
    canonical_repository: str
    network_identity_digest: str
    ecosystem: CanonicalEcosystem
    base_revision: str
    tip_revision: str
    change_byte_length: int
    change_content_digest: str
    history_source_digest: str
    push_digest: str


@dataclass(frozen=True, order=True)
class OrdinaryDrawAssignmentV1:
    positive_change_digest: str
    network_identity_digest: str
    ecosystem: CanonicalEcosystem
    push_digest: str


@dataclass(frozen=True, order=True)
class OrdinaryExclusionV1:
    network_identity_digest: str
    tip_revision: str
    reason: OrdinaryExclusionReason
    contamination_review_digest: str


@dataclass(frozen=True, order=True)
class OrdinaryFixExclusionV1:
    network_identity_digest: str
    fixed_revision: str
    positive_change_digest: str
    ground_truth_review_digest: str


@dataclass(frozen=True)
class OrdinaryContaminationReviewV1:
    network_identity_digest: str
    tip_revision: str
    timing: ContaminationTiming
    evidence_digest: str
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    review_digest: str


@dataclass(frozen=True)
class OrdinarySelectionV1:
    required_per_positive: int
    policy_digest: str
    positive_change_digests: tuple[str, ...]
    fix_exclusions: tuple[OrdinaryFixExclusionV1, ...]
    pushes: tuple[OrdinaryPushV1, ...]
    assignments: tuple[OrdinaryDrawAssignmentV1, ...]
    exclusions: tuple[OrdinaryExclusionV1, ...]
    provenance_digest: str
    selection_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise OrdinarySelectionError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _revision(value: object, field: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise OrdinarySelectionError(f"{field} must be a full Git object identity")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OrdinarySelectionError(f"{field} must be nonempty text")
    return value.strip()


def _push_value(push: OrdinaryPushV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "canonical_repository": _text(push.canonical_repository, "canonical repository"),
        "network_identity_digest": _digest(push.network_identity_digest, "network identity digest"),
        "ecosystem": CanonicalEcosystem(push.ecosystem).value,
        "base_revision": _revision(push.base_revision, "ordinary base revision"),
        "tip_revision": _revision(push.tip_revision, "ordinary tip revision"),
        "change_byte_length": push.change_byte_length,
        "change_content_digest": _digest(push.change_content_digest, "ordinary change digest"),
        "history_source_digest": _digest(push.history_source_digest, "history source digest"),
    }
    if push.base_revision == push.tip_revision or push.change_byte_length <= 0:
        raise OrdinarySelectionError("ordinary push byte receipt or revisions are invalid")
    if include_digest:
        value["push_digest"] = _digest(push.push_digest, "ordinary push digest")
    return value


def _assignment_value(item: OrdinaryDrawAssignmentV1) -> dict[str, JsonValue]:
    return {
        "positive_change_digest": _digest(item.positive_change_digest, "positive change digest"),
        "network_identity_digest": _digest(item.network_identity_digest, "network identity digest"),
        "ecosystem": CanonicalEcosystem(item.ecosystem).value,
        "push_digest": _digest(item.push_digest, "ordinary push digest"),
    }


def _exclusion_value(item: OrdinaryExclusionV1) -> dict[str, JsonValue]:
    return {
        "network_identity_digest": _digest(item.network_identity_digest, "network identity digest"),
        "tip_revision": _revision(item.tip_revision, "excluded tip revision"),
        "reason": OrdinaryExclusionReason(item.reason).value,
        "contamination_review_digest": _digest(item.contamination_review_digest, "contamination review digest"),
    }


def _fix_exclusion_value(item: OrdinaryFixExclusionV1) -> dict[str, JsonValue]:
    return {
        "network_identity_digest": _digest(item.network_identity_digest, "network identity digest"),
        "fixed_revision": _revision(item.fixed_revision, "accepted fixed revision"),
        "positive_change_digest": _digest(item.positive_change_digest, "positive change digest"),
        "ground_truth_review_digest": _digest(item.ground_truth_review_digest, "ground-truth review digest"),
    }


def _selection_value(selection: OrdinarySelectionV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": ORDINARY_SELECTION_SCHEMA,
        "required_per_positive": selection.required_per_positive,
        "policy_digest": _digest(selection.policy_digest, "ordinary selection policy digest"),
        "positive_change_digests": selection.positive_change_digests,
        "fix_exclusions": tuple(_fix_exclusion_value(item) for item in selection.fix_exclusions),
        "pushes": tuple(_push_value(push, include_digest=True) for push in selection.pushes),
        "assignments": tuple(_assignment_value(item) for item in selection.assignments),
        "exclusions": tuple(_exclusion_value(item) for item in selection.exclusions),
        "provenance_digest": _digest(selection.provenance_digest, "ordinary provenance digest"),
    }
    if include_digest:
        value["selection_digest"] = _digest(selection.selection_digest, "ordinary selection digest")
    return value


def _contamination_value(review: OrdinaryContaminationReviewV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": CONTAMINATION_REVIEW_SCHEMA,
        "network_identity_digest": _digest(review.network_identity_digest, "network identity digest"),
        "tip_revision": _revision(review.tip_revision, "contaminated tip revision"),
        "timing": ContaminationTiming(review.timing).value,
        "evidence_digest": _digest(review.evidence_digest, "contamination evidence digest"),
        "producer_identity": _text(review.producer_identity, "producer identity"),
        "reviewer_identity": _text(review.reviewer_identity, "reviewer identity"),
        "conflict_disclosed": review.conflict_disclosed,
        "policy_digest": _digest(review.policy_digest, "contamination policy digest"),
    }
    if review.producer_identity == review.reviewer_identity or review.conflict_disclosed is not True:
        raise OrdinarySelectionError("independent contamination review and disclosure are required")
    if include_digest:
        value["review_digest"] = _digest(review.review_digest, "contamination review digest")
    return value


def reviewed_contamination(
    *,
    network_identity_digest: str,
    tip_revision: str,
    timing: ContaminationTiming | str,
    evidence_digest: str,
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> OrdinaryContaminationReviewV1:
    draft = OrdinaryContaminationReviewV1(
        network_identity_digest,
        tip_revision,
        ContaminationTiming(timing),
        evidence_digest,
        producer_identity,
        reviewer_identity,
        conflict_disclosed,
        policy_digest,
        "",
    )
    digest = content_digest(_contamination_value(draft, include_digest=False))
    review = OrdinaryContaminationReviewV1(**{**vars(draft), "review_digest": digest})
    contamination_review_bytes(review)
    return review


def contamination_review_bytes(review: OrdinaryContaminationReviewV1) -> bytes:
    expected = content_digest(_contamination_value(review, include_digest=False))
    if review.review_digest != expected:
        raise OrdinarySelectionError("contamination review digest does not match")
    return canonical_bytes(_contamination_value(review, include_digest=True))


def _validate_canonical_collections(selection: OrdinarySelectionV1) -> None:
    if selection.required_per_positive < 20:
        raise OrdinarySelectionError("ordinary selection minimum is below 20")
    if selection.positive_change_digests != tuple(sorted(set(selection.positive_change_digests))):
        raise OrdinarySelectionError("ordinary positive identities are not canonical")
    for digest in selection.positive_change_digests:
        _digest(digest, "positive change digest")
    if selection.fix_exclusions != tuple(sorted(set(selection.fix_exclusions))):
        raise OrdinarySelectionError("accepted fix exclusions are not canonical")
    for item in selection.fix_exclusions:
        _fix_exclusion_value(item)
    if selection.pushes != tuple(sorted(set(selection.pushes), key=lambda item: item.push_digest)):
        raise OrdinarySelectionError("ordinary pushes are not canonical")
    if selection.assignments != tuple(sorted(set(selection.assignments))):
        raise OrdinarySelectionError("ordinary assignments are not canonical")
    if selection.exclusions != tuple(sorted(set(selection.exclusions))):
        raise OrdinarySelectionError("ordinary exclusions are not canonical")


def _validate_pushes(selection: OrdinarySelectionV1) -> dict[str, OrdinaryPushV1]:
    pushes = {push.push_digest: push for push in selection.pushes}
    for push in selection.pushes:
        if push.push_digest != content_digest(_push_value(push, include_digest=False)):
            raise OrdinarySelectionError("ordinary push digest does not match")
    return pushes


def _validate_assignments(selection: OrdinarySelectionV1, pushes: dict[str, OrdinaryPushV1]) -> None:
    counts = Counter(item.positive_change_digest for item in selection.assignments)
    for item in selection.assignments:
        push = pushes.get(item.push_digest)
        if push is None or (item.network_identity_digest, item.ecosystem) != (push.network_identity_digest, push.ecosystem):
            raise OrdinarySelectionError("ordinary assignment crosses repository or ecosystem")
    selected_keys = {(push.network_identity_digest, push.tip_revision) for push in selection.pushes}
    fixed_keys = {(item.network_identity_digest, item.fixed_revision) for item in selection.fix_exclusions}
    excluded_keys = {(item.network_identity_digest, item.tip_revision) for item in selection.exclusions}
    if selected_keys & (excluded_keys | fixed_keys):
        raise OrdinarySelectionError("reviewed contaminated or accepted fixed push remains selected")
    fixed_positives = tuple(sorted(item.positive_change_digest for item in selection.fix_exclusions))
    if fixed_positives != selection.positive_change_digests:
        raise OrdinarySelectionError("accepted fix exclusions do not bind the exact positive set")
    if set(counts) != set(selection.positive_change_digests):
        raise OrdinarySelectionError("ordinary assignments do not cover the exact positive set")
    if any(count != selection.required_per_positive for count in counts.values()):
        raise OrdinarySelectionError("ordinary assignment count does not match policy")


def _validate_provenance(selection: OrdinarySelectionV1) -> None:
    provenance = content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in selection.pushes})
            ),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in selection.fix_exclusions),
            "policy_digest": selection.policy_digest,
        }
    )
    if selection.provenance_digest != provenance:
        raise OrdinarySelectionError("ordinary provenance digest does not match sources and policy")


def ordinary_selection_bytes(selection: OrdinarySelectionV1) -> bytes:
    _validate_canonical_collections(selection)
    pushes = _validate_pushes(selection)
    _validate_assignments(selection, pushes)
    _validate_provenance(selection)
    expected = content_digest(_selection_value(selection, include_digest=False))
    if selection.selection_digest != expected:
        raise OrdinarySelectionError("ordinary selection digest does not match")
    return canonical_bytes(_selection_value(selection, include_digest=True))


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
    "ordinary_selection_bytes",
    "reviewed_contamination",
]
