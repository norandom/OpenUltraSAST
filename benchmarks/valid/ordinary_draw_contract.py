"""Canonical contracts for ordinary population draws over the closed positive set.

This module owns the closed vocabulary, dataclasses, canonical value encoding,
digest binding, and assembler for one ordinary-change population draw. The
drawing machinery lives in ``ordinary_draw``; durable persistence lives in
``ordinary_draw_store``. No detector observation or admission label appears in
any serialized field.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol

from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ordinary_change_contract import (
    OrdinaryDrawAssignmentV1,
    OrdinaryExclusionV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    _assignment_value,
    _exclusion_value,
    _fix_exclusion_value,
    _push_value,
    _revision,
)
from openultrasast.core.canonical import JsonValue, canonical_bytes, content_digest

ORDINARY_POPULATION_DRAW_SCHEMA = "openultrasast.valid-detection-benchmark.ordinary-population-draw.v1"
MINIMUM_ORDINARY_PER_POSITIVE = 20
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


class OrdinaryDrawReason(StrEnum):
    """Closed draw refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    POSITIVE_SET_NOT_CLOSED = "positive_set_not_closed"
    CANDIDATE_MISSING = "candidate_missing"
    RESERVED_REPOSITORY = "reserved_repository"
    REPOSITORY_UNREADABLE = "repository_unreadable"
    HISTORY_UNBOUND = "history_unbound"
    HISTORY_UNREADABLE = "history_unreadable"
    INSUFFICIENT_HISTORY = "insufficient_history"
    ECOSYSTEM_SPLIT = "ecosystem_split"
    CONFLICTING_EXCLUSION_EVIDENCE = "conflicting_exclusion_evidence"
    POST_FREEZE_CONTAMINATION = "post_freeze_contamination"


class OrdinaryDrawError(RuntimeError):
    """Refuse one draw step with a closed reason and no caller content."""

    def __init__(self, reason: OrdinaryDrawReason, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"ordinary_draw_{reason.value}{detail}")


class OrdinaryDrawStateReason(StrEnum):
    STATE_UNREADABLE = "state_unreadable"
    STATE_MISMATCH = "state_mismatch"


class OrdinaryDrawStateError(ValueError):
    """Closed draw-state refusal carrying one structural reason."""

    def __init__(self, reason: OrdinaryDrawStateReason) -> None:
        self.reason = reason
        super().__init__(f"ordinary draw state {reason.value}")


def _mismatch() -> OrdinaryDrawStateError:
    return OrdinaryDrawStateError(OrdinaryDrawStateReason.STATE_MISMATCH)


class OrdinaryDrawRule(StrEnum):
    """Closed eligibility rules recorded for every considered change."""

    ELIGIBLE_FIRST_PARENT_ORDINARY = "eligible_first_parent_ordinary"
    EXCLUDED_ACCEPTED_FIX = "excluded_accepted_fix"
    EXCLUDED_REVIEWED_CONTAMINATION = "excluded_reviewed_contamination"
    EXCLUDED_REVIEWED_CHANGE = "excluded_reviewed_change"


@dataclass(frozen=True, order=True)
class OrdinaryDrawProvenanceV1:
    network_identity_digest: str
    tip_revision: str
    rule: OrdinaryDrawRule
    evidence_digest: str


@dataclass(frozen=True, order=True)
class OrdinaryRepositoryReceiptV1:
    canonical_repository: str
    network_identity_digest: str
    byte_length: int
    repository_content_digest: str


@dataclass(frozen=True)
class OrdinaryPopulationDrawV1:
    required_per_positive: int
    policy_digest: str
    closure_digest: str
    reservation_census_digest: str
    positive_change_digests: tuple[str, ...]
    per_positive_counts: tuple[tuple[str, int], ...]
    repository_receipts: tuple[OrdinaryRepositoryReceiptV1, ...]
    fix_exclusions: tuple[OrdinaryFixExclusionV1, ...]
    pushes: tuple[OrdinaryPushV1, ...]
    assignments: tuple[OrdinaryDrawAssignmentV1, ...]
    exclusions: tuple[OrdinaryExclusionV1, ...]
    provenance: tuple[OrdinaryDrawProvenanceV1, ...]
    provenance_digest: str
    draw_digest: str

    def __post_init__(self) -> None:
        _validate_draw(self)


class OrdinaryPopulationHistoryReader(Protocol):
    def parents(self, revision: str) -> Sequence[str]: ...

    def change_bytes(self, revision: str) -> bytes | None: ...

    def repository_bytes(self, canonical_repository: str) -> bytes | None: ...


@dataclass(frozen=True)
class OrdinaryPopulationHistorySource:
    reader: OrdinaryPopulationHistoryReader
    canonical_repository: str
    network_identity_digest: str
    source_digest: str


def _closed_digest(value: object) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise _mismatch()
    return value


def _closed_text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 200:
        raise _mismatch()
    return value


def _rule_value(row: OrdinaryDrawProvenanceV1) -> dict[str, JsonValue]:
    return {
        "network_identity_digest": _closed_digest(row.network_identity_digest),
        "tip_revision": _revision(row.tip_revision, "provenance tip revision"),
        "rule": OrdinaryDrawRule(row.rule).value,
        "evidence_digest": _closed_digest(row.evidence_digest),
    }


def _receipt_value(receipt: OrdinaryRepositoryReceiptV1) -> dict[str, JsonValue]:
    if type(receipt.byte_length) is not int or receipt.byte_length <= 0:
        raise _mismatch()
    return {
        "canonical_repository": _closed_text(receipt.canonical_repository),
        "network_identity_digest": _closed_digest(receipt.network_identity_digest),
        "byte_length": receipt.byte_length,
        "repository_content_digest": _closed_digest(receipt.repository_content_digest),
    }


def _count_value(pairs: tuple[tuple[str, int], ...]) -> tuple[dict[str, JsonValue], ...]:
    return tuple({"change_identity_digest": digest, "eligible_pushes": count} for digest, count in pairs)


def _draw_value(item: OrdinaryPopulationDrawV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": ORDINARY_POPULATION_DRAW_SCHEMA,
        "required_per_positive": item.required_per_positive,
        "policy_digest": item.policy_digest,
        "closure_digest": item.closure_digest,
        "reservation_census_digest": item.reservation_census_digest,
        "positive_change_digests": item.positive_change_digests,
        "per_positive_counts": _count_value(item.per_positive_counts),
        "repository_receipts": tuple(_receipt_value(receipt) for receipt in item.repository_receipts),
        "fix_exclusions": tuple(_fix_exclusion_value(row) for row in item.fix_exclusions),
        "pushes": tuple(_push_value(push, include_digest=True) for push in item.pushes),
        "assignments": tuple(_assignment_value(row) for row in item.assignments),
        "exclusions": tuple(_exclusion_value(row) for row in item.exclusions),
        "provenance": tuple(_rule_value(row) for row in item.provenance),
        "provenance_digest": item.provenance_digest,
    }
    if include_digest:
        value["draw_digest"] = item.draw_digest
    return value


def _validate_scalars(item: OrdinaryPopulationDrawV1) -> None:
    if type(item.required_per_positive) is not int or item.required_per_positive < MINIMUM_ORDINARY_PER_POSITIVE:
        raise _mismatch()
    for field in ("policy_digest", "closure_digest", "reservation_census_digest", "provenance_digest", "draw_digest"):
        if getattr(item, field):
            _closed_digest(getattr(item, field))
    if item.positive_change_digests != tuple(sorted(set(item.positive_change_digests))):
        raise _mismatch()
    for digest in item.positive_change_digests:
        _closed_digest(digest)
    for pair in item.per_positive_counts:
        if type(pair) is not tuple or len(pair) != 2 or type(pair[1]) is not int or pair[1] < item.required_per_positive:
            raise _mismatch()
        _closed_digest(pair[0])
    if tuple(digest for digest, _ in item.per_positive_counts) != tuple(sorted({digest for digest, _ in item.per_positive_counts})):
        raise _mismatch()
    if set(digest for digest, _ in item.per_positive_counts) != set(item.positive_change_digests):
        raise _mismatch()


def _validate_collections(item: OrdinaryPopulationDrawV1) -> None:
    if item.repository_receipts != tuple(sorted(set(item.repository_receipts))):
        raise _mismatch()
    if len({receipt.network_identity_digest for receipt in item.repository_receipts}) != len(item.repository_receipts):
        raise _mismatch()
    if item.fix_exclusions != tuple(sorted(set(item.fix_exclusions))):
        raise _mismatch()
    if item.pushes != tuple(sorted(set(item.pushes), key=lambda push: push.push_digest)):
        raise _mismatch()
    if item.assignments != tuple(sorted(set(item.assignments))):
        raise _mismatch()
    if item.exclusions != tuple(sorted(set(item.exclusions))):
        raise _mismatch()
    if item.provenance != tuple(sorted(set(item.provenance))):
        raise _mismatch()


def _validate_bindings(item: OrdinaryPopulationDrawV1) -> None:
    pushes = {push.push_digest: push for push in item.pushes}
    for push in item.pushes:
        if push.push_digest != content_digest(_push_value(push, include_digest=False)):
            raise _mismatch()
    counts = Counter(row.positive_change_digest for row in item.assignments)
    for row in item.assignments:
        bound = pushes.get(row.push_digest)
        if bound is None or (row.network_identity_digest, row.ecosystem) != (bound.network_identity_digest, bound.ecosystem):
            raise _mismatch()
    if dict(item.per_positive_counts) != dict(sorted(counts.items())):
        raise _mismatch()
    fixed_positives = tuple(sorted(row.positive_change_digest for row in item.fix_exclusions))
    if fixed_positives != item.positive_change_digests:
        raise _mismatch()
    if set(counts) != set(item.positive_change_digests):
        raise _mismatch()
    ecosystems: dict[str, str] = {}
    for push in item.pushes:
        ecosystem = CanonicalEcosystem(push.ecosystem).value
        if ecosystems.setdefault(push.network_identity_digest, ecosystem) != ecosystem:
            raise _mismatch()


def _validate_provenance_rows(item: OrdinaryPopulationDrawV1) -> None:
    eligible_rule = OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY
    eligible = {
        (row.network_identity_digest, row.tip_revision): row.evidence_digest for row in item.provenance if row.rule is eligible_rule
    }
    if set(eligible) != {(push.network_identity_digest, push.tip_revision) for push in item.pushes}:
        raise _mismatch()
    for push in item.pushes:
        if eligible[(push.network_identity_digest, push.tip_revision)] != push.push_digest:
            raise _mismatch()
    refused = {(row.network_identity_digest, row.tip_revision) for row in item.provenance if row.rule is not eligible_rule}
    if refused & set(eligible):
        raise _mismatch()
    selected = {(push.network_identity_digest, push.tip_revision) for push in item.pushes}
    excluded = {(row.network_identity_digest, row.tip_revision) for row in item.exclusions}
    fixed = {(row.network_identity_digest, row.fixed_revision) for row in item.fix_exclusions}
    if selected & (excluded | fixed):
        raise _mismatch()


def _provenance_binding(item: OrdinaryPopulationDrawV1) -> str:
    eligible_rule = OrdinaryDrawRule.ELIGIBLE_FIRST_PARENT_ORDINARY
    reviewed_evidence = tuple(sorted({row.evidence_digest for row in item.provenance if row.rule is not eligible_rule}))
    return content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in item.pushes})
            ),
            "repository_receipts": tuple(_receipt_value(receipt) for receipt in item.repository_receipts),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(row) for row in item.fix_exclusions),
            "reviewed_exclusion_evidence": reviewed_evidence,
            "reservation_census_digest": item.reservation_census_digest,
            "closure_digest": item.closure_digest,
            "policy_digest": item.policy_digest,
        }
    )


def _validate_draw(item: OrdinaryPopulationDrawV1) -> None:
    try:
        _validate_scalars(item)
        _validate_collections(item)
        _validate_bindings(item)
        _validate_provenance_rows(item)
        if item.provenance_digest and item.provenance_digest != _provenance_binding(item):
            raise _mismatch()
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _mismatch() from error


def ordinary_population_draw_value(item: OrdinaryPopulationDrawV1) -> dict[str, JsonValue]:
    """Canonical draw payload used for durable persistence and exact rereads."""
    try:
        return _draw_value(item, include_digest=True)
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _mismatch() from error


def ordinary_population_draw_bytes(item: OrdinaryPopulationDrawV1) -> bytes:
    """Encode a digest-consistent draw decision as canonical bytes."""
    try:
        if item.draw_digest != content_digest(_draw_value(item, include_digest=False)):
            raise _mismatch()
        if item.provenance_digest != _provenance_binding(item):
            raise _mismatch()
        return canonical_bytes(_draw_value(item, include_digest=True))
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _mismatch() from error


def ordinary_population_draw(
    *,
    required_per_positive: int,
    policy_digest: str,
    closure_digest: str,
    reservation_census_digest: str,
    positive_change_digests: Iterable[str],
    per_positive_counts: Iterable[tuple[str, int]],
    repository_receipts: Iterable[OrdinaryRepositoryReceiptV1],
    fix_exclusions: Iterable[OrdinaryFixExclusionV1],
    pushes: Iterable[OrdinaryPushV1],
    assignments: Iterable[OrdinaryDrawAssignmentV1],
    exclusions: Iterable[OrdinaryExclusionV1],
    provenance: Iterable[OrdinaryDrawProvenanceV1],
) -> OrdinaryPopulationDrawV1:
    """Assemble one durable ordinary-change draw bound to its exact evidence."""
    try:
        draft = OrdinaryPopulationDrawV1(
            required_per_positive,
            policy_digest,
            closure_digest,
            reservation_census_digest,
            tuple(positive_change_digests),
            tuple(per_positive_counts),
            tuple(repository_receipts),
            tuple(fix_exclusions),
            tuple(pushes),
            tuple(assignments),
            tuple(exclusions),
            tuple(provenance),
            "",
            "",
        )
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _mismatch() from error
    try:
        bound = replace(draft, provenance_digest=_provenance_binding(draft))
        return replace(bound, draw_digest=content_digest(_draw_value(bound, include_digest=False)))
    except OrdinaryDrawStateError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _mismatch() from error


__all__ = [
    "MINIMUM_ORDINARY_PER_POSITIVE",
    "ORDINARY_POPULATION_DRAW_SCHEMA",
    "OrdinaryDrawError",
    "OrdinaryDrawProvenanceV1",
    "OrdinaryDrawReason",
    "OrdinaryDrawRule",
    "OrdinaryDrawStateError",
    "OrdinaryDrawStateReason",
    "OrdinaryPopulationDrawV1",
    "OrdinaryPopulationHistorySource",
    "ordinary_population_draw",
    "ordinary_population_draw_bytes",
    "ordinary_population_draw_value",
]
