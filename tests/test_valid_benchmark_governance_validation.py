"""Task 11.1 governance validation suite: reservation, review, history, lifecycle.

Adversarial suites over the committed population-governance machinery. Every
refusal interpreted here is preceded by a nonzero readability proof of the
fixture it was built from (instrument rule). Digest-consistent hostile inputs
are constructed only through the real constructors and committed encoders.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_lifecycle import POLICY as LIFECYCLE_POLICY  # noqa: E402
from test_valid_benchmark_lifecycle import _withdrawal  # noqa: E402
from test_valid_benchmark_population_freeze import (  # noqa: E402
    ECOSYSTEM_POLICY,
    FREEZE_POLICY,
    GROUND_TRUTH_POLICY,
    PROVENANCE,
    _positives,
    _selection,
)
from test_valid_benchmark_population_freeze import (
    _authority as _freeze_authority,
)
from test_valid_benchmark_population_freeze import (
    _census as _empty_census,
)

from benchmarks.valid import ecosystem_review as ecosystem_module  # noqa: E402
from benchmarks.valid import ground_truth_review as truth_module  # noqa: E402
from benchmarks.valid import historical_authorization as historical  # noqa: E402
from benchmarks.valid import lifecycle, population_freeze, reservation  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
    CanonicalEcosystem,
    EcosystemInsufficientReason,
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
    EcosystemReviewStatus,
    project_accepted_ecosystems,
    review_repository_ecosystem,
)
from benchmarks.valid.fix_site_catalog import (  # noqa: E402
    EvidenceRef,
    FixSiteRequest,
    LicenseEvidence,
    PackageEcosystemEvidence,
    SourceEvidence,
    build_fix_site_candidate,
)
from benchmarks.valid.ground_truth_review import (  # noqa: E402
    GroundTruthAttestationV1,
    GroundTruthExclusionReason,
    GroundTruthStatus,
    VerifiedScope,
    review_ground_truth,
)
from openultrasast.core.canonical import content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POPULATION = content_digest({"population": "governance-validation"})
FREEZE = content_digest({"freeze": "governance-validation"})
EVIDENCE = content_digest({"evidence": "governance-retirement"})
RESERVATION_POLICY = content_digest({"policy": "governance-influence-review-v1"})
SUBJECT = content_digest({"subject": "governance-selection-evidence"})
PARENT = "a" * 40
FIXED = "b" * 40


def _loads(content: bytes) -> dict[str, object]:
    """Hostile-decode-disciplined loads for asserting on encoded artifact bytes."""

    def reject(value: str) -> object:
        raise ValueError(f"non-finite constant in encoded artifact: {value}")

    def finite(value: str) -> float:
        result = float(value)
        if result != result or result in (float("inf"), float("-inf")):
            raise ValueError("non-finite float in encoded artifact")
        return result

    try:
        decoded = json.loads(content, parse_constant=reject, parse_float=finite)
    except RecursionError as error:
        raise ValueError("encoded artifact nests too deeply") from error
    if not isinstance(decoded, dict):
        raise ValueError("encoded artifact is not an object")
    return decoded


def _network() -> reservation.RepositoryNetworkIdentity:
    return reservation.build_network_identity(
        "https://github.com/acme/core",
        aliases=("https://github.com/ACME/core.git",),
        former_names=("https://github.com/acme/old-core",),
        redirects=("https://github.com/acme/redirected-core",),
        forks=("https://github.com/contributor/core-fork",),
    )


def _event(
    resolver: reservation.RepositoryIdentityResolver,
    *,
    repository: str = "https://github.com/acme/core",
    disposition: reservation.InfluenceDisposition = reservation.InfluenceDisposition.INFLUENCED,
    kind: reservation.InfluenceKind = reservation.InfluenceKind.POPULATION_SELECTION,
    actor: str = "producer@example.invalid",
    reviewer: str = "reviewer@example.invalid",
    disclosed: bool = True,
) -> bytes:
    return reservation.reviewed_influence_event(
        resolver,
        repository=repository,
        event_source="governance-validation-suite",
        disposition=disposition,
        influence_kind=kind,
        subject_digest=SUBJECT,
        actor_identity=actor,
        reviewer_identity=reviewer,
        conflict_disclosed=disclosed,
        policy_digest=RESERVATION_POLICY,
    )


class _Reader:
    def __init__(self, path: str, before: str, after: str) -> None:
        self._path = path
        self._sources = {PARENT: before, FIXED: after}

    def parents(self, revision: str) -> tuple[str, ...]:
        return (PARENT,) if revision == FIXED else ()

    def blob(self, revision: str, path: str) -> str | None:
        return self._sources.get(revision) if path == self._path else None


def _candidate(language: str = "python", hint: str | None = None, repository: str | None = None):
    suffix = "ts" if language == "typescript" else ("js" if language == "javascript" else "py")
    path = f"src/app.{suffix}"
    if language == "python":
        before = 'def handle():\n    return "before"\n'
        after = 'def handle():\n    return "after"\n'
    else:
        before = 'function handle() {\n  return "before";\n}\n'
        after = 'function handle() {\n  return "after";\n}\n'
    resolved_hint = hint or ("python" if language == "python" else "javascript")
    manifest_path = "pyproject.toml" if resolved_hint == "python" else "package.json"
    request = FixSiteRequest(
        reservation.build_network_identity(repository or "https://github.com/example/application"),
        PARENT,
        FIXED,
        path,
        "handle",
        language,
        PackageEcosystemEvidence(resolved_hint, EvidenceRef(manifest_path, content_digest({"manifest": resolved_hint}), 17)),
        LicenseEvidence("Apache-2.0", EvidenceRef("LICENSE", content_digest({"license": "Apache-2.0"}), 11)),
        SourceEvidence("security_advisory", "fixture://advisory/governance", content_digest({"advisory": "governance"})),
        content_digest({"parent": PARENT, "fixed": FIXED}),
    )
    return build_fix_site_candidate(_Reader(path, before, after), request)


def _ecosystem_attestation(candidate, decision: EcosystemReviewDecision, **changes: object):
    values: dict[str, object] = {
        "candidate_digest": candidate.candidate_digest,
        "source_evidence_digest": candidate.source_evidence.evidence_digest,
        "producer_identity": "producer@example.invalid",
        "reviewer_identity": "reviewer@example.invalid",
        "conflict_disclosed": True,
        "policy_digest": ECOSYSTEM_POLICY,
        "policy_satisfied": True,
        "decision": decision,
    }
    values.update(changes)
    return EcosystemReviewAttestationV1(**values)  # type: ignore[arg-type]


def _accepted_ecosystem_review(candidate):
    decision = (
        EcosystemReviewDecision.PYTHON
        if candidate.observed_language == "python"
        else EcosystemReviewDecision.JAVASCRIPT
    )
    return review_repository_ecosystem(
        candidate,
        _ecosystem_attestation(candidate, decision),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )


def _truth_attestation(candidate, ecosystem_review, **changes: object):
    values: dict[str, object] = {
        "candidate_digest": candidate.candidate_digest,
        "ecosystem_review_digest": ecosystem_review.review_digest,
        "producer_identity": "producer@example.invalid",
        "reviewer_identity": "reviewer@example.invalid",
        "conflict_disclosed": True,
        "policy_digest": GROUND_TRUTH_POLICY,
        "policy_satisfied": True,
        "defect_present": True,
        "fix_addresses": True,
        "in_repository_reachable": True,
        "verified_scopes": (VerifiedScope("injection", CanonicalEcosystem.PYTHON),),
        "model_assistance_digest": None,
    }
    values.update(changes)
    return GroundTruthAttestationV1(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------- reservation


def test_alias_fork_network_reserves_every_member_and_enumeration_does_not() -> None:
    enumerated_network = reservation.build_network_identity("https://github.com/acme/enumerated-only")
    resolver = reservation.RepositoryIdentityResolver((_network(), enumerated_network))
    authority = reservation.ReservationAuthority(resolver)

    census = authority.append_influence(_event(resolver))

    assert census.accepted_event_digests
    assert census.reserved_network_digests
    for member in (
        "https://github.com/acme/core",
        "https://github.com/ACME/core.git",
        "https://github.com/acme/old-core",
        "https://github.com/acme/redirected-core",
        "https://github.com/contributor/core-fork",
    ):
        assert authority.is_reserved(member, census)
    enumerated = authority.append_influence(
        _event(
            resolver,
            repository="https://github.com/acme/enumerated-only",
            disposition=reservation.InfluenceDisposition.ENUMERATED_ONLY,
            kind=reservation.InfluenceKind.ENUMERATION,
        )
    )

    assert len(enumerated.accepted_event_digests) == 2
    assert enumerated.reserved_network_digests == census.reserved_network_digests
    assert enumerated_network.network_identity_digest not in enumerated.reserved_network_digests
    assert not authority.is_reserved("https://github.com/acme/enumerated-only", enumerated)


def test_enumeration_disposition_with_influence_kind_is_refused_at_the_owning_boundary() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    honest = reservation.decode_influence_event(_event(resolver))
    assert honest.event_digest

    with pytest.raises(reservation.ReservationError, match="enumerated disposition"):
        _event(
            resolver,
            disposition=reservation.InfluenceDisposition.ENUMERATED_ONLY,
            kind=reservation.InfluenceKind.POPULATION_SELECTION,
        )


def test_self_reviewed_influence_event_is_refused_before_any_census_change() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)

    with pytest.raises(reservation.ReservationError, match="independent review"):
        _event(resolver, actor="reviewer@example.invalid", reviewer="reviewer@example.invalid")
    with pytest.raises(reservation.ReservationError, match="independent review"):
        _event(resolver, disclosed=False)
    assert authority.current_census().accepted_event_digests == ()


def test_changed_event_bytes_cannot_reproduce_the_accepted_census_identity() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)
    census = authority.append_influence(_event(resolver))
    assert census.accepted_event_digests

    different_actor = authority.project_census(
        (_event(resolver, actor="other-producer@example.invalid"),)
    )

    assert different_actor.census_digest != census.census_digest
    raw = bytearray(_event(resolver))
    raw[0] = ord(" ")
    with pytest.raises(reservation.ReservationError):
        authority.append_influence(bytes(raw))


def test_event_claiming_a_foreign_network_is_refused_as_a_conflict() -> None:
    other = reservation.build_network_identity("https://github.com/other/project")
    resolver = reservation.RepositoryIdentityResolver((_network(), other))
    authority = reservation.ReservationAuthority(resolver)
    hostile = _foreign_network_event(resolver, other.network_identity_digest)

    with pytest.raises(reservation.ReservationConflict):
        authority.append_influence(hostile)
    assert authority.current_census().accepted_event_digests == ()


def _foreign_network_event(
    resolver: reservation.RepositoryIdentityResolver,
    foreign_network_digest: str,
) -> bytes:
    """Re-hash one digest-consistent event whose observed repository belongs to another network."""
    honest = reservation.decode_influence_event(_event(resolver))
    draft = reservation.InfluenceEventV1(
        honest.canonical_repository,
        honest.observed_repository,
        foreign_network_digest,
        honest.event_source,
        honest.disposition,
        honest.influence_kind,
        honest.subject_digest,
        honest.actor_identity,
        honest.reviewer_identity,
        honest.conflict_disclosed,
        honest.policy_digest,
        "",
        "",
    )
    reviewed = reservation.InfluenceEventV1(
        **{**vars(draft), "review_digest": content_digest(reservation._review_value(draft))}
    )
    complete = reservation.InfluenceEventV1(
        **{
            **vars(reviewed),
            "event_digest": content_digest(reservation._event_value(reviewed, include_digest=False)),
        }
    )
    return reservation.canonical_event_bytes(reservation._event_value(complete, include_digest=True))


# --------------------------------------------------------- ecosystem review


@pytest.mark.parametrize(
    "decision",
    (
        EcosystemReviewDecision.UNRESOLVED,
        EcosystemReviewDecision.CONFLICTING,
        EcosystemReviewDecision.POLYGLOT_AMBIGUITY,
    ),
)
def test_unresolved_ecosystem_decisions_record_bounded_insufficient_evidence(decision) -> None:
    candidate = _candidate()
    assert candidate.candidate_digest

    review = review_repository_ecosystem(
        candidate,
        _ecosystem_attestation(candidate, decision),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.ecosystem is None
    assert review.insufficient_reason is EcosystemInsufficientReason(decision.value)


def test_conflicting_package_hint_against_observed_language_is_never_accepted() -> None:
    candidate = _candidate("typescript", hint="python")
    assert candidate.candidate_digest

    review = review_repository_ecosystem(
        candidate,
        _ecosystem_attestation(candidate, EcosystemReviewDecision.JAVASCRIPT),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.insufficient_reason is EcosystemInsufficientReason.CONFLICTING


def test_self_reviewed_ecosystem_attestation_stays_insufficient_never_accepted() -> None:
    candidate = _candidate()
    review = review_repository_ecosystem(
        candidate,
        _ecosystem_attestation(
            candidate,
            EcosystemReviewDecision.PYTHON,
            producer_identity="reviewer@example.invalid",
        ),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )

    assert review.status is EcosystemReviewStatus.INSUFFICIENT
    assert review.insufficient_reason is EcosystemInsufficientReason.SELF_REVIEW
    forged = replace(
        replace(review, status=EcosystemReviewStatus.ACCEPTED, ecosystem=CanonicalEcosystem.PYTHON, insufficient_reason=None),
        review_digest="",
    )
    forged = replace(
        forged,
        review_digest=content_digest(ecosystem_module._review_value(forged, include_digest=False)),
    )
    with pytest.raises(ecosystem_module.EcosystemReviewError, match="independent review policy|does not match"):
        ecosystem_module.repository_ecosystem_review_bytes(
            forged,
            candidate=candidate,
            expected_policy_digest=ECOSYSTEM_POLICY,
        )


def test_accepted_projection_allows_exactly_one_ecosystem_per_network() -> None:
    first = _candidate("python", repository="https://github.com/example/python-application")
    second = _candidate("javascript", repository="https://github.com/example/javascript-application")
    for candidate in (first, second):
        assert candidate.candidate_digest
    candidates = {first.candidate_digest: first, second.candidate_digest: second}
    reviews = (
        _accepted_ecosystem_review(first),
        _accepted_ecosystem_review(second),
    )

    projected = project_accepted_ecosystems(reviews, candidates_by_digest=candidates, expected_policy_digest=ECOSYSTEM_POLICY)

    assert len(projected) == 2
    assert {item[1] for item in projected} == {CanonicalEcosystem.PYTHON, CanonicalEcosystem.JAVASCRIPT}


# -------------------------------------------------------- ground truth review


@pytest.mark.parametrize(
    "changes,reason",
    (
        (
            {"defect_present": None, "model_assistance_digest": content_digest({"model": "agrees"})},
            GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT,
        ),
        ({"fix_addresses": None}, GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT),
        ({"in_repository_reachable": False}, GroundTruthExclusionReason.JUDGMENT_REJECTED),
        (
            {"producer_identity": "reviewer@example.invalid"},
            GroundTruthExclusionReason.SELF_REVIEW,
        ),
        ({"verified_scopes": ()}, GroundTruthExclusionReason.MISSING_SCOPE),
        (
            {"verified_scopes": (VerifiedScope("injection", CanonicalEcosystem.JAVASCRIPT),)},
            GroundTruthExclusionReason.SCOPE_SUBSTITUTION,
        ),
    ),
)
def test_defective_ground_truth_attestations_exclude_with_closed_reasons(changes, reason) -> None:
    candidate = _candidate()
    ecosystem = _accepted_ecosystem_review(candidate)

    review = review_ground_truth(
        candidate,
        ecosystem,
        _truth_attestation(candidate, ecosystem, **changes),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )

    assert review.status is GroundTruthStatus.EXCLUDED
    assert review.exclusion_reason is reason
    assert review.verified_scopes == ()


def test_model_only_labels_cannot_satisfy_a_missing_human_judgment() -> None:
    candidate = _candidate()
    ecosystem = _accepted_ecosystem_review(candidate)
    model_only = GroundTruthAttestationV1(
        candidate.candidate_digest,
        ecosystem.review_digest,
        "model@example.invalid",
        "model@example.invalid",
        True,
        GROUND_TRUTH_POLICY,
        True,
        None,
        None,
        None,
        (VerifiedScope("injection", CanonicalEcosystem.PYTHON),),
        content_digest({"model": "labels-everything-true"}),
    )

    review = review_ground_truth(
        candidate,
        ecosystem,
        model_only,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )

    assert review.status is GroundTruthStatus.EXCLUDED
    assert review.exclusion_reason in (
        GroundTruthExclusionReason.SELF_REVIEW,
        GroundTruthExclusionReason.MISSING_HUMAN_JUDGMENT,
    )
    assert review.verified_scopes == ()
    encoded = truth_module.ground_truth_review_bytes(
        review,
        candidate=candidate,
        ecosystem_review=ecosystem,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    assert encoded


def test_legacy_model_record_alone_leaves_verification_pending_human() -> None:
    from benchmarks.valid import verify

    record: dict[str, object] = {
        "id": "governance-case",
        "vulnerable_pre_fix": True,
        "fix_addresses_it": True,
        "reachable_in_repo": True,
        "entry_point": "app.handle",
        "model": "fixture-model",
        "confidence": 0.99,
    }

    assert verify.verdict(record) == "pending_human"
    assistance = verify.model_assistance(record)

    assert assistance["authoritative"] is False
    with pytest.raises(ValueError, match="human judgment"):
        verify.review_attestation(
            record,
            candidate_digest="0" * 64,
            ecosystem_review_digest="0" * 64,
            human_judgment={"producer_identity": "producer"},  # type: ignore[arg-type]
        )


# ------------------------------------------------- historical exact authority


def test_historical_authorization_requires_exact_path_and_digest_pairs() -> None:
    withdrawal = _withdrawal()
    assert withdrawal.candidate.entries
    entry = next(
        item
        for item in withdrawal.candidate.entries
        if item.path == "benchmarks/valid/pilot/freeze-valid.json"
    )
    assert entry.byte_length > 0

    authorized = historical.authorize_historical_path(ROOT, entry.path, entry.content_digest, withdrawal)

    assert authorized == (ROOT / entry.path).read_bytes()
    assert len(authorized) == entry.byte_length


def test_changed_bytes_relocated_paths_and_foreign_digests_are_refused(tmp_path: Path) -> None:
    withdrawal = _withdrawal()
    entry = next(
        item
        for item in withdrawal.candidate.entries
        if item.path == "benchmarks/valid/pilot/freeze-valid.json"
    )
    for relative in historical.PINNED_HISTORICAL_DIGESTS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    copied = (tmp_path / entry.path).read_bytes()
    assert copied
    (tmp_path / entry.path).write_bytes(copied + b" changed\n")

    with pytest.raises(historical.HistoricalAuthorizationError, match="changed"):
        historical.authorize_historical_path(tmp_path, entry.path, entry.content_digest, withdrawal)
    with pytest.raises(historical.HistoricalAuthorizationError):
        historical.authorize_historical_path(tmp_path, "benchmarks/valid/pilot", entry.content_digest, withdrawal)
    with pytest.raises(historical.HistoricalAuthorizationError):
        historical.authorize_historical_path(tmp_path, "benchmarks/valid/pilot/pool-valid.toml", entry.content_digest, withdrawal)


def test_historical_authorization_is_never_blanket_across_entries() -> None:
    withdrawal = _withdrawal()
    entries = sorted(withdrawal.candidate.entries, key=lambda item: item.path)
    assert len(entries) >= 2
    authorized, other = entries[0], entries[-1]

    with pytest.raises(historical.HistoricalAuthorizationError, match="not exactly authorized"):
        historical.authorize_historical_path(ROOT, other.path, authorized.content_digest, withdrawal)


# ------------------------------------------------------------------ lifecycle


def _active_chain(
    population: str = POPULATION,
    freeze: str = FREEZE,
) -> tuple[lifecycle.BaselineLifecycleAuthority, str]:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=population,
        freeze_digest=freeze,
        producer_identity="lifecycle-producer",
        reviewer_identity="lifecycle-reviewer",
        conflict_disclosed=True,
        policy_digest=LIFECYCLE_POLICY,
    )
    authority = lifecycle.BaselineLifecycleAuthority()
    authority.append(root)
    head = authority.append(replacement)
    return authority, head.head_event_digest


def _retirement(predecessor: str) -> bytes:
    return lifecycle.reviewed_retirement_event(
        predecessor_digest=predecessor,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        evidence_digest=EVIDENCE,
        reason_code="contaminated_negative",
        producer_identity="retirement-producer",
        reviewer_identity="retirement-reviewer",
        conflict_disclosed=True,
        policy_digest=LIFECYCLE_POLICY,
    )


def _development(predecessor: str) -> bytes:
    resolver = reservation.RepositoryIdentityResolver((reservation.build_network_identity("https://github.com/acme/one"),))
    return lifecycle.reviewed_development_opening(
        predecessor_digest=predecessor,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        access_evidence_digest=EVIDENCE,
        resolver=resolver,
        repositories=("https://github.com/acme/one",),
        producer_identity="opening-producer",
        reviewer_identity="opening-reviewer",
        conflict_disclosed=True,
        policy_digest=LIFECYCLE_POLICY,
    ).event_content


def test_lifecycle_fork_off_one_predecessor_is_refused() -> None:
    authority, head = _active_chain()
    first = lifecycle.decode_lifecycle_event(_retirement(head))
    second = lifecycle.decode_lifecycle_event(_development(head))
    assert first.event_digest != second.event_digest

    with pytest.raises(lifecycle.LifecycleConflict, match="fork"):
        authority.project((lifecycle.withdrawn_event(_withdrawal()), *_retired_chain_contents(head), _development(head)))


def _retired_chain_contents(head: str) -> tuple[bytes, ...]:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    replacement = lifecycle.reviewed_replacement_event(
        predecessor_digest=withdrawn.event_digest,
        historical_withdrawal_digest=withdrawn.historical_withdrawal_digest,
        population_digest=POPULATION,
        freeze_digest=FREEZE,
        producer_identity="lifecycle-producer",
        reviewer_identity="lifecycle-reviewer",
        conflict_disclosed=True,
        policy_digest=LIFECYCLE_POLICY,
    )
    return (root, replacement, _retirement(head))


def test_retirement_is_terminal_and_never_rewrites_prior_evidence() -> None:
    authority, head = _active_chain()
    contents = _retired_chain_contents(head)
    before = lifecycle.projection_bytes(authority.project(contents[:2]))

    retired = authority.append(_retirement(head))

    assert retired.state is lifecycle.PopulationLifecycleState.RETIRED
    assert not retired.admission_eligible
    assert retired.event_digests == tuple(
        lifecycle.decode_lifecycle_event(item).event_digest for item in contents
    )
    assert lifecycle.projection_bytes(authority.project(contents[:2])) == before
    with pytest.raises(lifecycle.LifecycleConflict, match="terminal"):
        authority.append(_development(retired.head_event_digest))
    with pytest.raises(lifecycle.LifecycleError, match="eligible"):
        authority.require_admission_eligible(POPULATION, FREEZE)


def test_development_opening_is_terminal_and_requires_durable_influence_events() -> None:
    authority, head = _active_chain()
    opening_content = _development(head)

    opened = authority.append(opening_content)

    assert opened.state is lifecycle.PopulationLifecycleState.DEVELOPMENT_OPENED
    assert not opened.admission_eligible
    assert opened.influence_event_digests
    event = lifecycle.decode_lifecycle_event(opening_content)
    assert event.influence_event_digests == opened.influence_event_digests
    with pytest.raises(lifecycle.LifecycleConflict, match="terminal"):
        authority.append(_retirement(opened.head_event_digest))


def test_replacement_bound_must_name_the_exact_reviewed_withdrawal() -> None:
    root = lifecycle.withdrawn_event(_withdrawal())
    withdrawn = lifecycle.decode_lifecycle_event(root)
    assert withdrawn.historical_withdrawal_digest

    with pytest.raises(lifecycle.LifecycleConflict, match="exact historical withdrawal"):
        lifecycle.BaselineLifecycleAuthority().project(
            (
                root,
                lifecycle.reviewed_replacement_event(
                    predecessor_digest=withdrawn.event_digest,
                    historical_withdrawal_digest=EVIDENCE,
                    population_digest=POPULATION,
                    freeze_digest=FREEZE,
                    producer_identity="lifecycle-producer",
                    reviewer_identity="lifecycle-reviewer",
                    conflict_disclosed=True,
                    policy_digest=LIFECYCLE_POLICY,
                ),
            )
        )


def test_self_reviewed_terminal_events_are_refused_at_encoding() -> None:
    authority, head = _active_chain()
    assert authority.require_admission_eligible(POPULATION, FREEZE)

    with pytest.raises(lifecycle.LifecycleError, match="independent lifecycle review"):
        lifecycle.reviewed_retirement_event(
            predecessor_digest=head,
            population_digest=POPULATION,
            freeze_digest=FREEZE,
            evidence_digest=EVIDENCE,
            reason_code="contaminated_negative",
            producer_identity="retirement-reviewer",
            reviewer_identity="retirement-reviewer",
            conflict_disclosed=True,
            policy_digest=LIFECYCLE_POLICY,
        )
    assert authority.require_admission_eligible(POPULATION, FREEZE)


# ------------------------------------------------- population classification


def test_scope_minimum_unmet_is_insufficient_despite_whole_population_size() -> None:
    positives = _positives()
    assert len(positives) >= 40
    authority = _freeze_authority(positives)

    freeze = population_freeze.freeze_population(
        positives,
        ordinary_selection=_selection(positives),
        reservation_census=_empty_census(),
        reservation_authority=authority,
        scope_minimums=(population_freeze.ScopeMinimumV1("injection", CanonicalEcosystem.PYTHON, 10_000),),
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )

    assert freeze.positive_count >= 40
    assert freeze.population_class is population_freeze.PopulationClass.INSUFFICIENT
    assert population_freeze.PopulationClassificationReason.SCOPE_MINIMUM_UNMET in freeze.classification_reasons
    assert population_freeze.population_freeze_bytes(freeze)
