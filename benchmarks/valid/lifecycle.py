"""Immutable reviewed events for the replacement-population lifecycle."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.historical_authorization import HistoricalWithdrawalV1, withdrawal_bytes
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from openultrasast.core.canonical import JsonValue, content_digest

LIFECYCLE_EVENT_SCHEMA = "openultrasast.valid-detection-benchmark.population-lifecycle.v1"
LIFECYCLE_PROJECTION_SCHEMA = "openultrasast.valid-detection-benchmark.lifecycle-projection.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class LifecycleError(ValueError):
    """Lifecycle input is invalid or cannot authorize admission."""


class LifecycleConflict(LifecycleError):
    """Lifecycle events do not form one immutable causal chain."""


class PopulationLifecycleKind(StrEnum):
    WITHDRAWN = "withdrawn"
    REPLACEMENT_BOUND = "replacement_bound"
    RETIRED = "retired"
    DEVELOPMENT_OPENED = "development_opened"


class PopulationLifecycleState(StrEnum):
    REPLACEMENT_PENDING = "replacement_pending"
    REPLACEMENT_COMPLETE = "replacement_complete"
    RETIRED = "retired"
    DEVELOPMENT_OPENED = "development_opened"


class RetirementReason(StrEnum):
    CONTAMINATED_NEGATIVE = "contaminated_negative"
    INVALID_GROUND_TRUTH = "invalid_ground_truth"
    POLICY_INVALIDATED = "policy_invalidated"


@dataclass(frozen=True)
class PopulationLifecycleEventV1:
    kind: PopulationLifecycleKind
    predecessor_digest: str | None
    historical_withdrawal_digest: str | None
    population_digest: str | None
    freeze_digest: str | None
    evidence_digest: str
    reason_code: str
    influence_event_digests: tuple[str, ...]
    producer_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    review_digest: str
    event_digest: str


@dataclass(frozen=True)
class PopulationLifecycleProjectionV1:
    state: PopulationLifecycleState
    historical_withdrawal_digest: str
    population_digest: str | None
    freeze_digest: str | None
    head_event_digest: str
    event_digests: tuple[str, ...]
    influence_event_digests: tuple[str, ...]
    admission_eligible: bool
    projection_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LifecycleError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{field} must be nonempty text")
    return value.strip()


def _optional_digest(value: object, field: str) -> str | None:
    return None if value is None else _digest(value, field)


def _base_value(event: PopulationLifecycleEventV1) -> dict[str, JsonValue]:
    return {
        "schema_version": LIFECYCLE_EVENT_SCHEMA,
        "kind": event.kind.value,
        "predecessor_digest": event.predecessor_digest,
        "historical_withdrawal_digest": event.historical_withdrawal_digest,
        "population_digest": event.population_digest,
        "freeze_digest": event.freeze_digest,
        "evidence_digest": event.evidence_digest,
        "reason_code": event.reason_code,
        "influence_event_digests": event.influence_event_digests,
        "producer_identity": event.producer_identity,
        "reviewer_identity": event.reviewer_identity,
        "conflict_disclosed": event.conflict_disclosed,
        "policy_digest": event.policy_digest,
    }


def _review_value(event: PopulationLifecycleEventV1) -> JsonValue:
    return {
        "subject_digest": content_digest(_base_value(event)),
        "decision": f"accept_{event.kind.value}",
        "producer_identity": event.producer_identity,
        "reviewer_identity": event.reviewer_identity,
        "conflict_disclosed": event.conflict_disclosed,
        "policy_digest": event.policy_digest,
    }


def _event_value(event: PopulationLifecycleEventV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value = _base_value(event)
    value["review_digest"] = event.review_digest
    if include_digest:
        value["event_digest"] = event.event_digest
    return value


def _reviewed_event(draft: PopulationLifecycleEventV1) -> bytes:
    _validate_event_shape(draft, require_identities=True)
    reviewed = PopulationLifecycleEventV1(**{**vars(draft), "review_digest": content_digest(_review_value(draft))})
    complete = PopulationLifecycleEventV1(
        **{**vars(reviewed), "event_digest": content_digest(_event_value(reviewed, include_digest=False))}
    )
    return canonical_json_bytes(_event_value(complete, include_digest=True))


def _validate_review(event: PopulationLifecycleEventV1) -> None:
    if event.producer_identity == event.reviewer_identity or event.conflict_disclosed is not True:
        raise LifecycleError("independent lifecycle review and conflict disclosure are required")
    if event.review_digest != content_digest(_review_value(event)):
        raise LifecycleError("lifecycle review digest does not match")


def _validate_event_shape(event: PopulationLifecycleEventV1, *, require_identities: bool = False) -> None:
    _optional_digest(event.historical_withdrawal_digest, "historical withdrawal digest")
    _digest(event.evidence_digest, "lifecycle evidence digest")
    _digest(event.policy_digest, "lifecycle policy digest")
    if event.predecessor_digest is not None:
        _digest(event.predecessor_digest, "lifecycle predecessor digest")
    _optional_digest(event.population_digest, "population digest")
    _optional_digest(event.freeze_digest, "freeze digest")
    if (event.population_digest is None) != (event.freeze_digest is None):
        raise LifecycleError("population and freeze identities must appear together")
    if event.influence_event_digests != tuple(sorted(set(event.influence_event_digests))):
        raise LifecycleError("lifecycle influence identities are not canonical")
    for digest in event.influence_event_digests:
        _digest(digest, "influence event digest")
    if require_identities:
        _text(event.producer_identity, "producer identity")
        _text(event.reviewer_identity, "reviewer identity")
        _text(event.reason_code, "lifecycle reason code")
        if event.producer_identity == event.reviewer_identity or event.conflict_disclosed is not True:
            raise LifecycleError("independent lifecycle review and conflict disclosure are required")
    _validate_kind_shape(event)


def _validate_kind_shape(event: PopulationLifecycleEventV1) -> None:
    has_predecessor = event.predecessor_digest is not None
    has_replacement = event.population_digest is not None
    if event.kind is PopulationLifecycleKind.WITHDRAWN:
        valid = not has_predecessor and event.historical_withdrawal_digest is not None and not has_replacement
        valid = valid and event.reason_code == "permanent_reservation_overlap" and not event.influence_event_digests
    elif event.kind is PopulationLifecycleKind.REPLACEMENT_BOUND:
        valid = has_predecessor and event.historical_withdrawal_digest is not None and has_replacement
        valid = valid and event.reason_code == "exact_replacement_bound" and not event.influence_event_digests
    elif event.kind is PopulationLifecycleKind.RETIRED:
        valid = has_predecessor and event.historical_withdrawal_digest is None and has_replacement
        try:
            RetirementReason(event.reason_code)
        except ValueError:
            valid = False
        valid = valid and not event.influence_event_digests
    else:
        valid = has_predecessor and event.historical_withdrawal_digest is None and has_replacement
        valid = valid and event.reason_code == "raw_population_evidence_opened" and bool(event.influence_event_digests)
    if not valid:
        raise LifecycleError("lifecycle event fields do not match event kind")


def _draft(
    kind: PopulationLifecycleKind,
    *,
    predecessor_digest: str | None,
    historical_withdrawal_digest: str | None,
    population_digest: str | None,
    freeze_digest: str | None,
    evidence_digest: str,
    reason_code: str,
    influence_event_digests: Sequence[str] = (),
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> PopulationLifecycleEventV1:
    return PopulationLifecycleEventV1(
        kind,
        predecessor_digest,
        historical_withdrawal_digest,
        population_digest,
        freeze_digest,
        evidence_digest,
        _text(reason_code, "lifecycle reason code"),
        tuple(sorted(set(influence_event_digests))),
        _text(producer_identity, "producer identity"),
        _text(reviewer_identity, "reviewer identity"),
        conflict_disclosed,
        _digest(policy_digest, "lifecycle policy digest"),
        "",
        "",
    )


def withdrawn_event(withdrawal: HistoricalWithdrawalV1) -> bytes:
    withdrawal_bytes(withdrawal)
    review = withdrawal.review
    draft = _draft(
        PopulationLifecycleKind.WITHDRAWN,
        predecessor_digest=None,
        historical_withdrawal_digest=withdrawal.withdrawal_digest,
        population_digest=None,
        freeze_digest=None,
        evidence_digest=withdrawal.inventory_digest,
        reason_code=withdrawal.reason.value,
        producer_identity=review.producer_identity,
        reviewer_identity=review.reviewer_identity,
        conflict_disclosed=review.conflict_disclosed,
        policy_digest=review.policy_digest,
    )
    return _reviewed_event(draft)


def reviewed_replacement_event(
    *,
    predecessor_digest: str,
    historical_withdrawal_digest: str,
    population_digest: str,
    freeze_digest: str,
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> bytes:
    draft = _draft(
        PopulationLifecycleKind.REPLACEMENT_BOUND,
        predecessor_digest=predecessor_digest,
        historical_withdrawal_digest=historical_withdrawal_digest,
        population_digest=population_digest,
        freeze_digest=freeze_digest,
        evidence_digest=historical_withdrawal_digest,
        reason_code="exact_replacement_bound",
        producer_identity=producer_identity,
        reviewer_identity=reviewer_identity,
        conflict_disclosed=conflict_disclosed,
        policy_digest=policy_digest,
    )
    return _reviewed_event(draft)


def reviewed_retirement_event(
    *,
    predecessor_digest: str,
    population_digest: str,
    freeze_digest: str,
    evidence_digest: str,
    reason_code: str,
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> bytes:
    draft = _draft(
        PopulationLifecycleKind.RETIRED,
        predecessor_digest=predecessor_digest,
        historical_withdrawal_digest=None,
        population_digest=population_digest,
        freeze_digest=freeze_digest,
        evidence_digest=evidence_digest,
        reason_code=_retirement_reason(reason_code),
        producer_identity=producer_identity,
        reviewer_identity=reviewer_identity,
        conflict_disclosed=conflict_disclosed,
        policy_digest=policy_digest,
    )
    return _reviewed_event(draft)


def _retirement_reason(value: str) -> str:
    try:
        return RetirementReason(value).value
    except ValueError as error:
        raise LifecycleError("retirement reason code is unsupported") from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleError(f"duplicate lifecycle JSON key: {key}")
        value[key] = item
    return value


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, list):
        raise LifecycleError("lifecycle influence digests must be an array")
    return value


def _event_fields() -> frozenset[str]:
    return frozenset(
        {
            "schema_version",
            "kind",
            "predecessor_digest",
            "historical_withdrawal_digest",
            "population_digest",
            "freeze_digest",
            "evidence_digest",
            "reason_code",
            "influence_event_digests",
            "producer_identity",
            "reviewer_identity",
            "conflict_disclosed",
            "policy_digest",
            "review_digest",
            "event_digest",
        }
    )


def decode_lifecycle_event(content: bytes) -> PopulationLifecycleEventV1:
    if not isinstance(content, bytes) or not content:
        raise LifecycleError("lifecycle event bytes must be nonempty")
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LifecycleError("lifecycle event bytes are unreadable") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != content:
        raise LifecycleError("lifecycle event bytes are not canonical")
    if set(value) != _event_fields() or value.get("schema_version") != LIFECYCLE_EVENT_SCHEMA:
        raise LifecycleError("lifecycle event fields or schema are unsupported")
    try:
        event = PopulationLifecycleEventV1(
            PopulationLifecycleKind(_text(value.get("kind"), "lifecycle kind")),
            _optional_digest(value.get("predecessor_digest"), "predecessor digest"),
            _optional_digest(value.get("historical_withdrawal_digest"), "historical withdrawal digest"),
            _optional_digest(value.get("population_digest"), "population digest"),
            _optional_digest(value.get("freeze_digest"), "freeze digest"),
            _digest(value.get("evidence_digest"), "lifecycle evidence digest"),
            _text(value.get("reason_code"), "lifecycle reason code"),
            tuple(_digest(item, "influence event digest") for item in _sequence(value.get("influence_event_digests"))),
            _text(value.get("producer_identity"), "producer identity"),
            _text(value.get("reviewer_identity"), "reviewer identity"),
            value.get("conflict_disclosed") is True,
            _digest(value.get("policy_digest"), "lifecycle policy digest"),
            _digest(value.get("review_digest"), "lifecycle review digest"),
            _digest(value.get("event_digest"), "lifecycle event digest"),
        )
    except (TypeError, ValueError) as error:
        raise LifecycleError("lifecycle event contains unsupported values") from error
    _validate_event_shape(event, require_identities=True)
    _validate_review(event)
    if event.event_digest != content_digest(_event_value(event, include_digest=False)):
        raise LifecycleError("lifecycle event digest does not match")
    return event


from benchmarks.valid.lifecycle_development import (  # noqa: E402
    DevelopmentOpeningResult,
    reviewed_development_opening,
)
from benchmarks.valid.lifecycle_projection import (  # noqa: E402
    BaselineLifecycleAuthority,
    projection_bytes,
)

__all__ = [
    "BaselineLifecycleAuthority",
    "DevelopmentOpeningResult",
    "LifecycleConflict",
    "LifecycleError",
    "PopulationLifecycleEventV1",
    "PopulationLifecycleKind",
    "PopulationLifecycleProjectionV1",
    "PopulationLifecycleState",
    "RetirementReason",
    "decode_lifecycle_event",
    "projection_bytes",
    "reviewed_development_opening",
    "reviewed_replacement_event",
    "reviewed_retirement_event",
    "withdrawn_event",
]
