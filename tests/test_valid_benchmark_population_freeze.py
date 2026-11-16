"""Canonical replacement population classification and freeze tests."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import population_freeze as freezer  # noqa: E402
from benchmarks.valid.ecosystem_review import (  # noqa: E402
    CanonicalEcosystem,
    EcosystemReviewAttestationV1,
    EcosystemReviewDecision,
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
    VerifiedScope,
    review_ground_truth,
)
from benchmarks.valid.ordinary_change_contract import (  # noqa: E402
    OrdinaryDrawAssignmentV1,
    OrdinaryFixExclusionV1,
    OrdinaryPushV1,
    OrdinarySelectionV1,
    ReviewedPositiveInput,
    _fix_exclusion_value,
    _push_value,
    _selection_value,
)
from benchmarks.valid.reservation import (  # noqa: E402
    InfluenceDisposition,
    InfluenceKind,
    RepositoryIdentityResolver,
    ReservationAuthority,
    ReservationCensusV1,
    _census_value,
    reviewed_influence_event,
)
from benchmarks.valid.reservation_identity import RepositoryNetworkIdentity, build_network_identity  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

ECOSYSTEM_POLICY = content_digest({"policy": "ecosystem-v1"})
GROUND_TRUTH_POLICY = content_digest({"policy": "ground-truth-v1"})
FREEZE_POLICY = content_digest({"policy": "population-freeze-v1", "minimum": 40})
DRAW_POLICY = content_digest({"policy": "ordinary-first-parent-v1", "required": 20})
PROVENANCE = content_digest({"source": "reviewed-fixture-set"})
RESERVATION_POLICY = content_digest({"policy": "reservation-review-v1"})
RESERVATION_SUBJECT = content_digest({"subject": "population-source"})


class _Reader:
    def __init__(self, parent: str, fixed: str, path: str, language: str) -> None:
        self.parent, self.fixed, self.path, self.language = parent, fixed, path, language

    def parents(self, revision: str) -> tuple[str, ...]:
        return (self.parent,) if revision == self.fixed else ()

    def blob(self, revision: str, path: str) -> str | None:
        if path != self.path:
            return None
        marker = "before" if revision == self.parent else "after" if revision == self.fixed else None
        if marker is None:
            return None
        if self.language == "python":
            return f'def handle():\n    return "{marker}"\n'
        return f'function handle() {{ return "{marker}"; }}\n'


def _positive(index: int, ecosystem: CanonicalEcosystem, family: str, *, extra_family: str | None = None) -> ReviewedPositiveInput:
    owner = "python-app" if ecosystem is CanonicalEcosystem.PYTHON else "javascript-app"
    network = build_network_identity(f"https://github.com/example/{owner}")
    parent = f"{index * 2 + 1:040x}"
    fixed = f"{index * 2 + 2:040x}"
    language = "python" if ecosystem is CanonicalEcosystem.PYTHON else "javascript"
    path = "src/app.py" if language == "python" else "src/app.js"
    manifest = "pyproject.toml" if language == "python" else "package.json"
    candidate = build_fix_site_candidate(
        _Reader(parent, fixed, path, language),
        FixSiteRequest(
            network,
            parent,
            fixed,
            path,
            "handle",
            language,
            PackageEcosystemEvidence(language, EvidenceRef(manifest, content_digest({"manifest": index}), 10)),
            LicenseEvidence("Apache-2.0", EvidenceRef("LICENSE", content_digest({"license": index}), 10)),
            SourceEvidence("security_advisory", f"fixture://advisory/{index}", content_digest({"advisory": index})),
            content_digest({"parent": parent, "fixed": fixed}),
        ),
    )
    decision = EcosystemReviewDecision.PYTHON if ecosystem is CanonicalEcosystem.PYTHON else EcosystemReviewDecision.JAVASCRIPT
    eco = review_repository_ecosystem(
        candidate,
        EcosystemReviewAttestationV1(
            candidate.candidate_digest,
            candidate.source_evidence.evidence_digest,
            f"ecosystem-producer-{index}",
            f"ecosystem-reviewer-{index}",
            True,
            ECOSYSTEM_POLICY,
            True,
            decision,
        ),
        expected_policy_digest=ECOSYSTEM_POLICY,
    )
    scopes = [VerifiedScope(family, ecosystem)]
    if extra_family is not None:
        scopes.append(VerifiedScope(extra_family, ecosystem))
    truth = review_ground_truth(
        candidate,
        eco,
        GroundTruthAttestationV1(
            candidate.candidate_digest,
            eco.review_digest,
            f"truth-producer-{index}",
            f"truth-reviewer-{index}",
            True,
            GROUND_TRUTH_POLICY,
            True,
            True,
            True,
            True,
            tuple(scopes),
        ),
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    return ReviewedPositiveInput(candidate, eco, truth)


def _positives(count: int = 40, *, one_ecosystem: bool = False, one_family: bool = False) -> tuple[ReviewedPositiveInput, ...]:
    values = []
    for index in range(count):
        ecosystem = CanonicalEcosystem.PYTHON if one_ecosystem or index < (count + 1) // 2 else CanonicalEcosystem.JAVASCRIPT
        family = "injection" if one_family or index % 2 == 0 else "path_traversal"
        values.append(_positive(index, ecosystem, family, extra_family="output_encoding" if index == 0 and not one_family else None))
    return tuple(values)


def _selection(positives: tuple[ReviewedPositiveInput, ...]) -> OrdinarySelectionV1:
    pushes: list[OrdinaryPushV1] = []
    assignments: list[OrdinaryDrawAssignmentV1] = []
    by_network: dict[str, tuple[str, CanonicalEcosystem]] = {}
    for item in positives:
        by_network[item.candidate.network_identity_digest] = (item.candidate.canonical_repository, item.ecosystem_review.ecosystem)  # type: ignore[assignment]
    for network_index, (network, (repository, ecosystem)) in enumerate(sorted(by_network.items())):
        for index in range(20):
            base = f"{9000 + network_index * 100 + index * 2:040x}"
            tip = f"{9001 + network_index * 100 + index * 2:040x}"
            push_draft = OrdinaryPushV1(
                repository,
                network,
                ecosystem,
                base,
                tip,
                8,
                content_digest({"change": tip}),
                content_digest({"history": network}),
                "",
            )
            pushes.append(replace(push_draft, push_digest=content_digest(_push_value(push_draft, include_digest=False))))
    push_by_network: dict[str, list[OrdinaryPushV1]] = {}
    for push in pushes:
        push_by_network.setdefault(push.network_identity_digest, []).append(push)
    fix_exclusions = []
    positive_digests = []
    for item in positives:
        change = item.ground_truth_review.change_identity_digest
        positive_digests.append(change)
        fix_exclusions.append(
            OrdinaryFixExclusionV1(
                item.candidate.network_identity_digest,
                item.candidate.fixed.revision,
                change,
                item.ground_truth_review.review_digest,
            )
        )
        for push in push_by_network[item.candidate.network_identity_digest]:
            assignments.append(OrdinaryDrawAssignmentV1(change, push.network_identity_digest, push.ecosystem, push.push_digest))
    fix_exclusions = sorted(fix_exclusions)
    provenance = content_digest(
        {
            "history_sources": tuple(
                sorted({(push.canonical_repository, push.network_identity_digest, push.history_source_digest) for push in pushes})
            ),
            "accepted_fix_exclusions": tuple(_fix_exclusion_value(item) for item in fix_exclusions),
            "policy_digest": DRAW_POLICY,
        }
    )
    selection_draft = OrdinarySelectionV1(
        20,
        DRAW_POLICY,
        tuple(sorted(positive_digests)),
        tuple(fix_exclusions),
        tuple(sorted(pushes, key=lambda item: item.push_digest)),
        tuple(sorted(assignments)),
        (),
        provenance,
        "",
    )
    return replace(
        selection_draft,
        selection_digest=content_digest(_selection_value(selection_draft, include_digest=False)),
    )


def _census(*reserved: str) -> ReservationCensusV1:
    draft = ReservationCensusV1(tuple(sorted(reserved)), (), (), "")
    return replace(draft, census_digest=content_digest(_census_value(draft, include_digest=False)))


def _resolver(
    positives: tuple[ReviewedPositiveInput, ...],
    *overrides: RepositoryNetworkIdentity,
) -> RepositoryIdentityResolver:
    networks = {item.candidate.canonical_repository: build_network_identity(item.candidate.canonical_repository) for item in positives}
    networks.update({item.canonical_repository: item for item in overrides})
    return RepositoryIdentityResolver(networks.values())


def _authority(
    positives: tuple[ReviewedPositiveInput, ...],
    *overrides: RepositoryNetworkIdentity,
) -> ReservationAuthority:
    return ReservationAuthority(_resolver(positives, *overrides))


def _influence_event(
    positives: tuple[ReviewedPositiveInput, ...],
    resolver: RepositoryIdentityResolver,
    disposition: InfluenceDisposition,
    kind: InfluenceKind,
) -> bytes:
    return reviewed_influence_event(
        resolver,
        repository=positives[0].candidate.canonical_repository,
        event_source=f"freeze-regression-{disposition.value}",
        disposition=disposition,
        influence_kind=kind,
        subject_digest=RESERVATION_SUBJECT,
        actor_identity="reservation-producer",
        reviewer_identity="reservation-reviewer",
        conflict_disclosed=True,
        policy_digest=RESERVATION_POLICY,
    )


def _freeze(
    positives: tuple[ReviewedPositiveInput, ...],
    *,
    census: ReservationCensusV1 | None = None,
    authority: ReservationAuthority | None = None,
    minimums: tuple[freezer.ScopeMinimumV1, ...] = (),
) -> freezer.PopulationFreezeV3:
    return freezer.freeze_population(
        positives,
        ordinary_selection=_selection(positives),
        reservation_census=census or _census(),
        reservation_authority=authority or _authority(positives),
        scope_minimums=minimums,
        exclusion_counts=(("review_excluded", 3),),
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )


def test_forty_two_ecosystem_two_family_population_is_admission_and_deterministic() -> None:
    positives = _positives()
    first = _freeze(positives)
    second = _freeze(tuple(reversed(positives)))

    assert freezer.population_freeze_bytes(first) == freezer.population_freeze_bytes(second)
    assert first.population_class is freezer.PopulationClass.ADMISSION
    assert first.classification_reasons == ()
    assert first.positive_count == 40
    assert first.ecosystems == (CanonicalEcosystem.JAVASCRIPT, CanonicalEcosystem.PYTHON)
    assert first.families == ("injection", "output_encoding", "path_traversal")
    assert sum(item.count for item in first.scope_census) == 41


def test_thirty_nine_is_development_pilot_not_admission() -> None:
    freeze = _freeze(_positives(39))
    assert freeze.population_class is freezer.PopulationClass.DEVELOPMENT_PILOT
    assert freezer.PopulationClassificationReason.BELOW_MINIMUM_POSITIVES in freeze.classification_reasons


@pytest.mark.parametrize(
    "positives,reason",
    (
        (_positives(one_ecosystem=True), freezer.PopulationClassificationReason.MISSING_ECOSYSTEM),
        (_positives(one_family=True), freezer.PopulationClassificationReason.MISSING_SECOND_FAMILY),
    ),
)
def test_missing_ecosystem_or_second_family_is_insufficient(
    positives: tuple[ReviewedPositiveInput, ...], reason: freezer.PopulationClassificationReason
) -> None:
    freeze = _freeze(positives)
    assert freeze.population_class is freezer.PopulationClass.INSUFFICIENT
    assert reason in freeze.classification_reasons


def test_infeasible_claimed_scope_is_insufficient() -> None:
    positives = _positives()
    freeze = _freeze(
        positives,
        minimums=(freezer.ScopeMinimumV1("injection", CanonicalEcosystem.PYTHON, 30),),
    )
    assert freeze.population_class is freezer.PopulationClass.INSUFFICIENT
    assert freezer.PopulationClassificationReason.SCOPE_MINIMUM_UNMET in freeze.classification_reasons


def test_reserved_repository_is_refused_before_freeze() -> None:
    positives = _positives()
    resolver = _resolver(positives)
    authority = ReservationAuthority(resolver)
    census = authority.append_influence(
        _influence_event(
            positives,
            resolver,
            InfluenceDisposition.INFLUENCED,
            InfluenceKind.POPULATION_SELECTION,
        )
    )
    with pytest.raises(freezer.PopulationFreezeError, match="reserved"):
        _freeze(positives, census=census, authority=authority)


def test_reserved_reviewed_network_cannot_be_split_by_candidate_identity() -> None:
    positives = _positives()
    reviewed_network = build_network_identity(
        positives[0].candidate.canonical_repository,
        aliases=("https://github.com/example/python-app-former",),
        forks=("https://github.com/example/python-app-fork",),
    )
    resolver = _resolver(positives, reviewed_network)
    authority = ReservationAuthority(resolver)
    census = authority.append_influence(
        _influence_event(
            positives,
            resolver,
            InfluenceDisposition.INFLUENCED,
            InfluenceKind.POPULATION_SELECTION,
        )
    )
    assert positives[0].candidate.network_identity_digest != reviewed_network.network_identity_digest
    with pytest.raises(freezer.PopulationFreezeError, match="reserved|resolved|identity"):
        freezer.freeze_population(
            positives,
            ordinary_selection=_selection(positives),
            reservation_census=census,
            reservation_authority=authority,
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_candidate_split_identity_is_refused_even_when_reviewed_network_is_not_reserved() -> None:
    positives = _positives()
    reviewed_network = build_network_identity(
        positives[0].candidate.canonical_repository,
        aliases=("https://github.com/example/python-app-former",),
    )
    with pytest.raises(freezer.PopulationFreezeError, match="resolved repository identity"):
        freezer.freeze_population(
            positives,
            ordinary_selection=_selection(positives),
            reservation_census=_census(),
            reservation_authority=_authority(positives, reviewed_network),
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


@pytest.mark.parametrize(
    "disposition,kind",
    (
        (InfluenceDisposition.INFLUENCED, InfluenceKind.POPULATION_SELECTION),
        (InfluenceDisposition.ENUMERATED_ONLY, InfluenceKind.ENUMERATION),
    ),
)
def test_stale_census_after_reviewed_event_is_refused(
    disposition: InfluenceDisposition,
    kind: InfluenceKind,
) -> None:
    positives = _positives()
    resolver = _resolver(positives)
    authority = ReservationAuthority(resolver)
    stale_census = _census()
    authority.append_influence(_influence_event(positives, resolver, disposition, kind))

    with pytest.raises(freezer.PopulationFreezeError, match="current|authoritative|snapshot"):
        freezer.freeze_population(
            positives,
            ordinary_selection=_selection(positives),
            reservation_census=stale_census,
            reservation_authority=authority,
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_later_authority_append_invalidates_replay_without_rewriting_freeze() -> None:
    positives = _positives()
    resolver = _resolver(positives)
    authority = ReservationAuthority(resolver)
    census = _census()
    selection = _selection(positives)
    freeze = freezer.freeze_population(
        positives,
        ordinary_selection=selection,
        reservation_census=census,
        reservation_authority=authority,
        source_provenance_digest=PROVENANCE,
        freeze_policy_digest=FREEZE_POLICY,
        expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
        expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
    )
    frozen_bytes = freezer.population_freeze_bytes(freeze)
    authority.append_influence(
        _influence_event(
            positives,
            resolver,
            InfluenceDisposition.ENUMERATED_ONLY,
            InfluenceKind.ENUMERATION,
        )
    )

    with pytest.raises(freezer.PopulationFreezeError, match="current|authoritative|snapshot"):
        freezer.validate_population_freeze(
            freeze,
            positives,
            ordinary_selection=selection,
            reservation_census=census,
            reservation_authority=authority,
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )
    assert freezer.population_freeze_bytes(freeze) == frozen_bytes


def test_ordinary_selection_must_bind_exact_positive_set() -> None:
    positives = _positives()
    selection = _selection(positives[:-1])
    with pytest.raises(freezer.PopulationFreezeError, match="ordinary|positive"):
        freezer.freeze_population(
            positives,
            ordinary_selection=selection,
            reservation_census=_census(),
            reservation_authority=_authority(positives),
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_structurally_valid_cross_ecosystem_ordinary_substitution_is_refused() -> None:
    positives = _positives()
    selection = _selection(positives)
    javascript_network = next(
        item.candidate.network_identity_digest for item in positives if item.ecosystem_review.ecosystem is CanonicalEcosystem.JAVASCRIPT
    )
    digest_map: dict[str, str] = {}
    pushes = []
    for push in selection.pushes:
        if push.network_identity_digest != javascript_network:
            pushes.append(push)
            continue
        push_draft = replace(push, ecosystem=CanonicalEcosystem.PYTHON, push_digest="")
        forged_push = replace(
            push_draft,
            push_digest=content_digest(_push_value(push_draft, include_digest=False)),
        )
        digest_map[push.push_digest] = forged_push.push_digest
        pushes.append(forged_push)
    assignments = tuple(
        replace(
            item,
            ecosystem=CanonicalEcosystem.PYTHON,
            push_digest=digest_map[item.push_digest],
        )
        if item.network_identity_digest == javascript_network
        else item
        for item in selection.assignments
    )
    selection_draft = replace(
        selection,
        pushes=tuple(sorted(pushes, key=lambda item: item.push_digest)),
        assignments=tuple(sorted(assignments)),
        selection_digest="",
    )
    forged_selection = replace(
        selection_draft,
        selection_digest=content_digest(_selection_value(selection_draft, include_digest=False)),
    )
    with pytest.raises(freezer.PopulationFreezeError, match="ecosystem"):
        freezer.freeze_population(
            positives,
            ordinary_selection=forged_selection,
            reservation_census=_census(),
            reservation_authority=_authority(positives),
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )


def test_same_identity_different_bytes_and_historical_identity_reuse_are_refused() -> None:
    freeze = _freeze(_positives())
    content = freezer.accept_population_freeze(freeze)
    assert freezer.accept_population_freeze(freeze, existing_content=content) == content
    with pytest.raises(freezer.PopulationFreezeConflict, match="different bytes"):
        freezer.accept_population_freeze(freeze, existing_content=content + b"\n")
    with pytest.raises(freezer.PopulationFreezeError, match="historical"):
        freezer.freeze_population(
            _positives(),
            ordinary_selection=_selection(_positives()),
            reservation_census=_census(),
            reservation_authority=_authority(_positives()),
            exclusion_counts=(("review_excluded", 3),),
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
            forbidden_historical_identities=(freeze.population_digest,),
        )


def test_rehashed_classification_cannot_replay_against_exact_authorities() -> None:
    positives = _positives()
    selection = _selection(positives)
    freeze = _freeze(positives)
    forged = replace(
        freeze,
        population_class=freezer.PopulationClass.INSUFFICIENT,
        classification_reasons=(freezer.PopulationClassificationReason.SCOPE_MINIMUM_UNMET,),
        freeze_digest="",
    )
    forged = replace(
        forged,
        freeze_digest=content_digest(freezer._freeze_value(forged, include_digest=False)),
    )
    with pytest.raises(freezer.PopulationFreezeError, match="classification"):
        freezer.population_freeze_bytes(forged)
    with pytest.raises(freezer.PopulationFreezeError, match="reproduce"):
        freezer.validate_population_freeze(
            forged,
            positives,
            ordinary_selection=selection,
            reservation_census=_census(),
            reservation_authority=_authority(positives),
            exclusion_counts=(("review_excluded", 3),),
            source_provenance_digest=PROVENANCE,
            freeze_policy_digest=FREEZE_POLICY,
            expected_ecosystem_policy_digest=ECOSYSTEM_POLICY,
            expected_ground_truth_policy_digest=GROUND_TRUTH_POLICY,
        )
