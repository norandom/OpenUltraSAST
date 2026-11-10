"""Reviewed immutable attempt-history validation for evaluation admission V3."""

from __future__ import annotations

import json
from dataclasses import fields, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_evaluation_plan import _digest
from test_core_evaluation_plan_review import _attestation, _case

from openultrasast.core import canonical
from openultrasast.core.evaluation_attempt import (
    AttemptEventRefV3,
    AttemptEventV3,
    AttemptHistoryV3,
    AttemptIdentityV3,
    EvaluationAttemptError,
    ObservationAccessPolicyV3,
    PreSpendDispositionV3,
    PublicStatusFieldV3,
    decode_attempt_event,
    derive_attempt_identity,
    encode_attempt_event,
    validate_evaluation_attempt_history,
)
from openultrasast.core.evaluation_version import NonAuthorizingV3


def _projection(*, artifact_id: str = "attempt-status"):
    content = canonical.canonical_bytes(
        {
            "schema_version": "openultrasast.detection-core.evaluation-public-status.v3",
            "status_code": "observation_complete",
            "count": 6,
            "digest": _digest("closed-status"),
        }
    )
    return stored_artifact(content, artifact_id=artifact_id)


def _event(
    identity: AttemptIdentityV3,
    disposition: PreSpendDispositionV3,
    access: ObservationAccessPolicyV3,
    projection: canonical.ContentRef,
    predecessor: str | None,
    disclosure: canonical.ContentRef,
    reviewer: str,
    *,
    raw_count: int = 0,
    diagnostic_count: int = 0,
    producer: str | None = None,
) -> AttemptEventV3:
    producer = producer or _digest(f"producer-{predecessor}")
    provisional = _attestation("0" * 64, producer, reviewer, disclosure)
    draft = AttemptEventV3(
        identity,
        disposition,
        access,
        raw_count,
        diagnostic_count,
        projection,
        predecessor,
        "",
        provisional,
        "",
    )
    review = _attestation(draft.payload_digest, producer, reviewer, disclosure)
    return replace(draft, review=review, event_digest="")


def _reference(event: AttemptEventV3, artifact_id: str):
    reference, resolver = stored_artifact(encode_attempt_event(event), artifact_id=artifact_id)
    return AttemptEventRefV3(reference, event.event_digest, ""), resolver.artifacts[artifact_id]


def _history_case(dispositions=(PreSpendDispositionV3.SEALED, PreSpendDispositionV3.SEALED)):
    _, manifest, policy, plan_resolver = _case()
    projection, projection_resolver = _projection()
    identity = derive_attempt_identity(manifest)
    access = ObservationAccessPolicyV3(tuple(PublicStatusFieldV3), False, False, "")
    events = []
    references = []
    artifacts = {**plan_resolver.artifacts, **projection_resolver.artifacts}
    predecessor = None
    for index, disposition in enumerate(dispositions):
        event = _event(
            identity,
            disposition,
            access,
            projection,
            predecessor,
            manifest.review.conflict_disclosure,
            manifest.review.reviewer_identity,
        )
        reference, resolved = _reference(event, f"attempt-{index}")
        events.append(event)
        references.append(reference)
        artifacts[reference.event.artifact_id] = resolved
        predecessor = event.event_digest
    history = AttemptHistoryV3(manifest.declaration.population_digest, tuple(references), predecessor, "")
    return manifest, policy, history, tuple(events), InMemoryContentResolver(artifacts)


def _validate(case):
    manifest, policy, history, _, resolver = case
    return validate_evaluation_attempt_history(manifest, history, policy, resolver)


def _replace_event(case, index: int, **changes):
    manifest, policy, history, events, resolver = case
    changed = replace(events[index], **changes, payload_digest="", event_digest="")
    changed = replace(
        changed,
        review=_attestation(
            changed.payload_digest,
            changed.review.producer_identity,
            changed.review.reviewer_identity,
            changed.review.conflict_disclosure,
        ),
        event_digest="",
    )
    reference, resolved = _reference(changed, f"changed-attempt-{index}")
    references = history.events[:index] + (reference,) + history.events[index + 1 :]
    changed_history = AttemptHistoryV3(history.population_digest, references, references[-1].event_digest, "")
    artifacts = {**resolver.artifacts, reference.event.artifact_id: resolved}
    return manifest, policy, changed_history, events[:index] + (changed,) + events[index + 1 :], InMemoryContentResolver(artifacts)


def test_unchanged_all_sealed_reviewed_retry_chain_validates() -> None:
    case = _history_case()
    assert _validate(case) == case[3]
    identity = case[3][0].attempt_identity
    declaration = case[0].declaration
    assert identity.population_digest == declaration.population_digest
    assert identity.plan_declaration_digest == declaration.declaration_digest
    assert identity.input_set_digest == declaration.input_set_digest
    assert identity.baseline_digests == tuple(row.baseline_digest for row in case[0].baselines)
    assert identity.configuration_digests == tuple(row.configuration_identity_digest for row in declaration.arm_configurations)
    assert identity.registered_budget_digests == tuple(row.registered_budget_digest for row in declaration.arm_configurations)
    assert identity.execution_identities == tuple(row.execution_identity for row in declaration.arm_configurations)


def test_contracts_are_exact_registered_non_authorizing_v3_values() -> None:
    expected = {
        AttemptIdentityV3: {
            "population_digest",
            "plan_declaration_digest",
            "baseline_digests",
            "input_set_digest",
            "configuration_digests",
            "registered_budget_digests",
            "execution_identities",
            "retry_identity_digest",
        },
        ObservationAccessPolicyV3: {
            "allowed_public_fields",
            "raw_observation_access_allowed",
            "population_diagnostic_access_allowed",
            "policy_digest",
        },
        AttemptEventV3: {
            "attempt_identity",
            "disposition",
            "access_policy",
            "raw_observation_access_count",
            "population_diagnostic_access_count",
            "public_status_projection",
            "predecessor_event_digest",
            "payload_digest",
            "review",
            "event_digest",
        },
        AttemptEventRefV3: {"event", "event_digest", "ref_digest"},
        AttemptHistoryV3: {"population_digest", "events", "head_event_digest", "history_digest"},
    }
    for value_type, names in expected.items():
        assert {field.name for field in fields(value_type)} == names
        assert issubclass(value_type, NonAuthorizingV3)
        assert "authorize" not in names


def test_event_encoding_is_strict_canonical_and_round_trips() -> None:
    event = _history_case()[3][0]
    encoded = encode_attempt_event(event)
    assert encoded
    assert decode_attempt_event(encoded) == event
    assert json.dumps(json.loads(encoded), sort_keys=True, separators=(",", ":")).encode() == encoded
    with pytest.raises(EvaluationAttemptError):
        decode_attempt_event(json.dumps(json.loads(encoded), indent=2).encode())
    with pytest.raises(EvaluationAttemptError, match="nonzero"):
        decode_attempt_event(b"")


@pytest.mark.parametrize("failure", ("broken", "skipped", "reordered", "forked", "head"))
def test_history_must_be_one_complete_declared_predecessor_chain(failure: str) -> None:
    case = _history_case()
    manifest, policy, history, events, resolver = case
    if failure == "broken":
        case = _replace_event(case, 1, predecessor_event_digest=_digest("missing-predecessor"))
    elif failure == "skipped":
        changed = AttemptHistoryV3(history.population_digest, history.events[1:], history.head_event_digest, "")
        case = manifest, policy, changed, events[1:], resolver
    elif failure == "reordered":
        changed = AttemptHistoryV3(history.population_digest, tuple(reversed(history.events)), history.head_event_digest, "")
        case = manifest, policy, changed, tuple(reversed(events)), resolver
    elif failure == "forked":
        root = events[0]
        sibling = _event(
            root.attempt_identity,
            PreSpendDispositionV3.SEALED,
            root.access_policy,
            root.public_status_projection,
            root.event_digest,
            root.review.conflict_disclosure,
            root.review.reviewer_identity,
            producer=_digest("sibling-producer"),
        )
        sibling_ref, sibling_content = _reference(sibling, "forked-attempt")
        refs = (history.events[0], history.events[1], sibling_ref)
        changed = AttemptHistoryV3(history.population_digest, refs, sibling.event_digest, "")
        case = (
            manifest,
            policy,
            changed,
            events + (sibling,),
            InMemoryContentResolver({**resolver.artifacts, "forked-attempt": sibling_content}),
        )
    else:
        changed = AttemptHistoryV3(history.population_digest, history.events, events[0].event_digest, "")
        case = manifest, policy, changed, events, resolver
    with pytest.raises(EvaluationAttemptError):
        _validate(case)


@pytest.mark.parametrize(
    "field",
    [
        "population_digest",
        "plan_declaration_digest",
        "baseline_digests",
        "input_set_digest",
        "configuration_digests",
        "registered_budget_digests",
        "execution_identities",
    ],
)
def test_each_complete_retry_identity_column_must_remain_exact(field: str) -> None:
    case = _history_case((PreSpendDispositionV3.SEALED,))
    event = case[3][0]
    identity = event.attempt_identity
    value: object = _digest(f"changed-{field}")
    if field in {"baseline_digests", "configuration_digests", "registered_budget_digests"}:
        original = getattr(identity, field)
        value = (*original[:-1], _digest(f"changed-{field}"))
    elif field == "execution_identities":
        value = (*identity.execution_identities[:-1], "changed-execution")
    changed_identity = replace(identity, **{field: value}, retry_identity_digest="")
    with pytest.raises(EvaluationAttemptError, match="identity"):
        _validate(_replace_event(case, 0, attempt_identity=changed_identity))


@pytest.mark.parametrize("count_field", ["raw_observation_access_count", "population_diagnostic_access_count"])
def test_each_access_count_requires_terminal_disposition(count_field: str) -> None:
    case = _history_case((PreSpendDispositionV3.SEALED,))
    with pytest.raises(EvaluationAttemptError, match="access"):
        _validate(_replace_event(case, 0, **{count_field: 1}))


@pytest.mark.parametrize("policy_field", ["raw_observation_access_allowed", "population_diagnostic_access_allowed"])
def test_each_open_access_policy_requires_terminal_disposition(policy_field: str) -> None:
    case = _history_case((PreSpendDispositionV3.SEALED,))
    event = case[3][0]
    opened = replace(event.access_policy, **{policy_field: True}, policy_digest="")
    with pytest.raises(EvaluationAttemptError, match="access"):
        _validate(_replace_event(case, 0, access_policy=opened))


def test_terminal_history_and_terminal_then_sealed_cannot_restore_eligibility() -> None:
    terminal = _history_case((PreSpendDispositionV3.DEVELOPMENT_OPENED,))
    with pytest.raises(EvaluationAttemptError, match="terminal"):
        _validate(terminal)
    restored = _history_case((PreSpendDispositionV3.SPENT, PreSpendDispositionV3.SEALED))
    with pytest.raises(EvaluationAttemptError, match="terminal"):
        _validate(restored)


def test_self_review_untrusted_bytes_and_open_projection_are_refused() -> None:
    case = _history_case((PreSpendDispositionV3.SEALED,))
    event = case[3][0]
    self_review = _attestation(
        event.payload_digest,
        event.review.reviewer_identity,
        event.review.reviewer_identity,
        event.review.conflict_disclosure,
    )
    with pytest.raises(EvaluationAttemptError, match="independent"):
        _validate(_replace_event(case, 0, review=self_review))

    manifest, policy, history, events, resolver = case
    open_bytes = canonical.canonical_bytes(
        {
            "schema_version": "openultrasast.detection-core.evaluation-public-status.v3",
            "raw_observations": ("secret",),
        }
    )
    open_ref, open_resolver = stored_artifact(open_bytes, artifact_id="open-status")
    changed_case = _replace_event(case, 0, public_status_projection=open_ref)
    changed_case = changed_case[:-1] + (InMemoryContentResolver({**changed_case[-1].artifacts, **open_resolver.artifacts}),)
    with pytest.raises(EvaluationAttemptError, match="projection"):
        _validate(changed_case)

    resolved = resolver.artifacts[history.events[0].event.artifact_id]
    truncated = replace(resolved, content=resolved.content[:-1])
    bad_resolver = InMemoryContentResolver({**resolver.artifacts, history.events[0].event.artifact_id: truncated})
    with pytest.raises(canonical.ArtifactValidationError):
        validate_evaluation_attempt_history(manifest, history, policy, bad_resolver)


def test_wrong_population_subclasses_and_noncanonical_policy_are_refused() -> None:
    manifest, policy, history, _, resolver = _history_case()
    with pytest.raises(EvaluationAttemptError, match="population"):
        validate_evaluation_attempt_history(
            manifest,
            replace(history, population_digest=_digest("other-population"), history_digest=""),
            policy,
            resolver,
        )
    with pytest.raises(EvaluationAttemptError, match="canonical"):
        ObservationAccessPolicyV3(tuple(reversed(tuple(PublicStatusFieldV3))), False, False, "")

    class DerivedHistory(AttemptHistoryV3):
        pass

    derived = object.__new__(DerivedHistory)
    with pytest.raises((EvaluationAttemptError, TypeError, ValueError)):
        validate_evaluation_attempt_history(manifest, derived, policy, resolver)
