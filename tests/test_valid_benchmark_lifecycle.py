"""Causal replacement, retirement, and development-opening lifecycle contracts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid import (
    lifecycle,  # noqa: E402
    reservation,  # noqa: E402
)
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POLICY = content_digest({"policy": "baseline-lifecycle-review-v1"})
POPULATION = content_digest({"population": "replacement"})
FREEZE = content_digest({"freeze": "replacement"})
EVIDENCE = content_digest({"evidence": "contamination"})
ACCESS = content_digest({"access": "raw-observations"})


def _historical_review(subject: str) -> bytes:
    value: dict[str, object] = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": subject,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "custodian",
        "reviewer_identity": "historical-reviewer",
        "conflict_disclosed": True,
        "policy_digest": POLICY,
    }
    value["review_digest"] = content_digest(value)
    return canonical_json_bytes(value)


def _withdrawal() -> historical.HistoricalWithdrawalV1:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)
    return historical.accept_reviewed_withdrawal(candidate, _historical_review(candidate.candidate_digest))


def _review() -> dict[str, object]:
    return {
        "producer_identity": "lifecycle-producer",
        "reviewer_identity": "lifecycle-reviewer",
        "conflict_disclosed": True,
        "policy_digest": POLICY,
    }


def _replacement(root: bytes) -> bytes:
    withdrawn = lifecycle.decode_lifecycle_event(root)
    return lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        **_review(),
    )


def _active() -> tuple[lifecycle.BaselineLifecycleAuthority, bytes, bytes]:
    root = lifecycle.withdrawn_event(_withdrawal())
    replacement = _replacement(root)
    authority = lifecycle.BaselineLifecycleAuthority()
    authority.append(root)
    authority.append(replacement)
    return authority, root, replacement


def _resolver() -> reservation.RepositoryIdentityResolver:
    networks = (
        reservation.build_network_identity("https://github.com/acme/one"),
        reservation.build_network_identity("https://github.com/acme/two"),
    )
    return reservation.RepositoryIdentityResolver(networks)


def test_withdrawal_is_pending_and_not_admission_eligible() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    authority = lifecycle.BaselineLifecycleAuthority()
    projection = authority.append(root)

    assert projection.state is lifecycle.PopulationLifecycleState.REPLACEMENT_PENDING
    assert not projection.admission_eligible
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        authority.require_admission_eligible(POPULATION, FREEZE)


def test_exact_replacement_binding_is_active_and_admission_eligible() -> None:
    authority, _, _ = _active()
    projection = authority.require_admission_eligible(POPULATION, FREEZE)

    assert projection.state is lifecycle.PopulationLifecycleState.REPLACEMENT_COMPLETE
    assert projection.admission_eligible
    assert lifecycle.projection_bytes(projection)


def test_equal_duplicate_events_are_idempotent_and_order_rebuilds() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    replacement = _replacement(root)
    authority = lifecycle.BaselineLifecycleAuthority()

    forward = authority.project((root, replacement, root))
    reverse = authority.project((replacement, root))

    assert forward == reverse
    assert len(forward.event_digests) == 2


def test_missing_predecessor_and_fork_fail_closed() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    replacement = _replacement(root)
    first = lifecycle.reviewed_retirement_event(
        predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=EVIDENCE,
        reason_code="contaminated_negative",
        **_review(),
    )
    second = lifecycle.reviewed_retirement_event(
        predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=content_digest({"other": "evidence"}),
        reason_code="invalid_ground_truth",
        **_review(),
    )
    authority = lifecycle.BaselineLifecycleAuthority()

    with pytest.raises(lifecycle.LifecycleConflict, match="predecessor|root"):
        authority.project((replacement,))
    with pytest.raises(lifecycle.LifecycleConflict, match="fork"):
        authority.project((root, replacement, first, second))


def test_replacement_must_bind_exact_reviewed_withdrawal() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest="0" * 64,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        **_review(),
    )

    with pytest.raises(lifecycle.LifecycleConflict, match="withdrawal"):
        lifecycle.BaselineLifecycleAuthority().project((root, replacement))


def test_retirement_is_terminal_and_preserves_active_identity() -> None:
    authority, root, replacement = _active()
    predecessor = lifecycle.decode_lifecycle_event(replacement).event_digest
    retired = lifecycle.reviewed_retirement_event(
        predecessor_digest=predecessor,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=EVIDENCE,
        reason_code="contaminated_negative",
        **_review(),
    )
    projection = authority.append(retired)

    assert projection.state is lifecycle.PopulationLifecycleState.RETIRED
    assert projection.population_digest == POPULATION
    assert projection.freeze_digest == FREEZE
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        authority.require_admission_eligible(POPULATION, FREEZE)
    successor = lifecycle.reviewed_retirement_event(
        predecessor_digest=lifecycle.decode_lifecycle_event(retired).event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=content_digest({"later": "evidence"}),
        reason_code="invalid_ground_truth",
        **_review(),
    )
    with pytest.raises(lifecycle.LifecycleConflict, match="terminal"):
        authority.project((root, replacement, retired, successor))


def test_development_opening_creates_reviewed_influence_for_each_network() -> None:
    authority, _, replacement = _active()
    result = lifecycle.reviewed_development_opening(
        predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        access_evidence_digest=ACCESS,
        resolver=_resolver(),
        repositories=("https://github.com/acme/two", "https://github.com/acme/one"),
        **_review(),
    )
    projection = authority.append(result.event_content)

    assert projection.state is lifecycle.PopulationLifecycleState.DEVELOPMENT_OPENED
    assert projection.influence_event_digests == tuple(
        sorted(reservation.decode_influence_event(item).event_digest for item in result.influence_contents)
    )
    assert len(result.influence_contents) == 2
    for content in result.influence_contents:
        event = reservation.decode_influence_event(content)
        assert event.disposition is reservation.InfluenceDisposition.INFLUENCED
        assert event.influence_kind is reservation.InfluenceKind.DETECTOR_DEVELOPMENT
        assert event.subject_digest == ACCESS


def test_development_opening_is_terminal_for_admission_and_further_events() -> None:
    authority, root, replacement = _active()
    result = lifecycle.reviewed_development_opening(
        predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        access_evidence_digest=ACCESS,
        resolver=_resolver(),
        repositories=("https://github.com/acme/one",),
        **_review(),
    )
    opened = authority.append(result.event_content)

    assert not opened.admission_eligible
    retired = lifecycle.reviewed_retirement_event(
        predecessor_digest=opened.head_event_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=EVIDENCE,
        reason_code="contaminated_negative",
        **_review(),
    )
    with pytest.raises(lifecycle.LifecycleConflict, match="terminal"):
        authority.project((root, replacement, result.event_content, retired))


@pytest.mark.parametrize("same,disclosed", ((True, True), (False, False)))
def test_lifecycle_review_must_be_independent_and_disclosed(same: bool, disclosed: bool) -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    with pytest.raises(lifecycle.LifecycleError, match="review"):
        lifecycle.reviewed_replacement_event(
            predecessor_digest=withdrawn.event_digest,
            historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            producer_identity="actor",
            reviewer_identity="actor" if same else "reviewer",
            conflict_disclosed=disclosed,
            policy_digest=POLICY,
        )


def test_population_and_freeze_identity_mismatch_refuses_terminal_transition() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    replacement = _replacement(root)
    retired = lifecycle.reviewed_retirement_event(
        predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
        population_digest="1" * 64,
        freeze_digest=FREEZE,
        evidence_digest=EVIDENCE,
        reason_code="contaminated_negative",
        **_review(),
    )
    with pytest.raises(lifecycle.LifecycleConflict, match="population|freeze"):
        lifecycle.BaselineLifecycleAuthority().project((root, replacement, retired))


def test_retirement_reason_is_closed() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    replacement = _replacement(root)
    with pytest.raises(lifecycle.LifecycleError, match="reason"):
        lifecycle.reviewed_retirement_event(
            predecessor_digest=lifecycle.decode_lifecycle_event(replacement).event_digest,
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            evidence_digest=EVIDENCE,
            reason_code="arbitrary_exception_text",
            **_review(),
        )


def test_tampered_event_bytes_fail_before_projection() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    changed = bytearray(root)
    changed[-2] = ord("0") if changed[-2] != ord("0") else ord("1")
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.BaselineLifecycleAuthority().project((bytes(changed),))
