"""Trust resolution and eligibility checks for reviewed V3 attempt histories."""

from __future__ import annotations

import json

from openultrasast.core import canonical
from openultrasast.core.evaluation_attempt import (
    _PUBLIC_STATUS_SCHEMA,
    AttemptEventV3,
    AttemptHistoryV3,
    AttemptIdentityV3,
    EvaluationAttemptError,
    PreSpendDispositionV3,
    _digest,
    _pairs,
    decode_attempt_event,
    derive_attempt_identity,
)
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3, validate_reviewed_evaluation_plan
from openultrasast.core.factpack import (
    FactPackValidationError,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)


def _validate_policy(policy: ReviewIndependencePolicy) -> None:
    if type(policy) is not ReviewIndependencePolicy:
        raise EvaluationAttemptError("review policy must use exact ReviewIndependencePolicy")
    try:
        policy.__post_init__()
    except FactPackValidationError as exc:
        raise EvaluationAttemptError(f"review policy is invalid: {exc}") from exc
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise EvaluationAttemptError("review policy digest cannot be re-derived")


def _resolve(
    reference: canonical.ContentRef,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
    field: str,
) -> bytes:
    try:
        content = canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except (AttributeError, TypeError) as exc:
        raise EvaluationAttemptError(f"{field} resolver returned a malformed result") from exc
    if not content:
        raise EvaluationAttemptError(f"resolved {field} bytes must be nonzero")
    return content


def _validate_review(
    event: AttemptEventV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    review = event.review
    if review.subject_digest != event.payload_digest:
        raise EvaluationAttemptError("attempt review subject does not match its payload digest")
    if review.producer_identity == review.reviewer_identity:
        raise EvaluationAttemptError("attempt producer and reviewer must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise EvaluationAttemptError("attempt reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise EvaluationAttemptError("attempt producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise EvaluationAttemptError("attempt review attestation digest cannot be re-derived")
    _resolve(review.conflict_disclosure, policy, resolver, "review conflict disclosure")


def _validate_projection(
    event: AttemptEventV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    content = _resolve(event.public_status_projection, policy, resolver, "public status projection")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationAttemptError("public status projection must be valid UTF-8 JSON") from exc
    allowed = {item.value for item in event.access_policy.allowed_public_fields}
    if type(value) is not dict or value.get("schema_version") != _PUBLIC_STATUS_SCHEMA:
        raise EvaluationAttemptError("public status projection has an unknown schema")
    projected = set(value) - {"schema_version"}
    if not projected or not projected <= allowed:
        raise EvaluationAttemptError("public status projection exposes a field outside the closed access policy")
    if "status_code" in value and (type(value["status_code"]) is not str or not value["status_code"]):
        raise EvaluationAttemptError("public status projection status code must be nonempty exact text")
    if "count" in value and (type(value["count"]) is not int or value["count"] < 0):
        raise EvaluationAttemptError("public status projection count must be a non-negative integer")
    if "digest" in value:
        _digest(value["digest"], "public status projection digest")
    if canonical.canonical_bytes(value) != content:
        raise EvaluationAttemptError("public status projection must use canonical JSON")


def _resolve_events(
    history: AttemptHistoryV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[AttemptEventV3, ...]:
    events = []
    for reference in history.events:
        event = decode_attempt_event(_resolve(reference.event, policy, resolver, "attempt event"))
        if event.event_digest != reference.event_digest:
            raise EvaluationAttemptError("resolved attempt event does not match its reference")
        _validate_review(event, policy, resolver)
        _validate_projection(event, policy, resolver)
        events.append(event)
    return tuple(events)


def _ordered_chain(history: AttemptHistoryV3, events: tuple[AttemptEventV3, ...]) -> tuple[AttemptEventV3, ...]:
    by_digest = {event.event_digest: event for event in events}
    if len(by_digest) != len(events):
        raise EvaluationAttemptError("attempt history contains duplicate event identities")
    reverse_chain = []
    current: str | None = history.head_event_digest
    seen: set[str] = set()
    while current is not None:
        if current in seen:
            raise EvaluationAttemptError("attempt predecessor chain contains a cycle")
        seen.add(current)
        try:
            event = by_digest[current]
        except KeyError as exc:
            raise EvaluationAttemptError("attempt predecessor chain is broken") from exc
        reverse_chain.append(event)
        current = event.predecessor_event_digest
    chain = tuple(reversed(reverse_chain))
    if tuple(item.event_digest for item in chain) != tuple(item.event_digest for item in events):
        raise EvaluationAttemptError("attempt history is forked, skipped, or reordered")
    return chain


def _validate_eligibility(events: tuple[AttemptEventV3, ...], expected: AttemptIdentityV3) -> None:
    terminal_seen = False
    for event in events:
        is_terminal = event.disposition is not PreSpendDispositionV3.SEALED
        access_opened = (
            event.access_policy.raw_observation_access_allowed
            or event.access_policy.population_diagnostic_access_allowed
            or event.raw_observation_access_count > 0
            or event.population_diagnostic_access_count > 0
        )
        if terminal_seen and not is_terminal:
            raise EvaluationAttemptError("a sealed event cannot follow a terminal disposition")
        if not is_terminal and event.attempt_identity != expected:
            raise EvaluationAttemptError("a changed retry identity requires a terminal disposition")
        if not is_terminal and access_opened:
            raise EvaluationAttemptError("raw or diagnostic access requires a terminal disposition")
        terminal_seen = terminal_seen or is_terminal
    if terminal_seen:
        raise EvaluationAttemptError("terminal attempt history cannot authorize admission")


def validate_attempt_history(
    manifest: EvaluationPlanManifestV3,
    history: AttemptHistoryV3,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[AttemptEventV3, ...]:
    """Validate the reviewed plan, exact predecessor chain, and sealed eligibility."""
    if type(manifest) is not EvaluationPlanManifestV3 or type(history) is not AttemptHistoryV3:
        raise EvaluationAttemptError("manifest and attempt history must use exact V3 contract types")
    history.__post_init__()
    _validate_policy(review_policy)
    validate_reviewed_evaluation_plan(manifest.census, manifest, review_policy, resolver)
    expected = derive_attempt_identity(manifest)
    if history.population_digest != expected.population_digest:
        raise EvaluationAttemptError("attempt history population does not match the reviewed plan")
    events = _resolve_events(history, review_policy, resolver)
    chain = _ordered_chain(history, events)
    _validate_eligibility(chain, expected)
    return chain


__all__ = ["validate_attempt_history"]
