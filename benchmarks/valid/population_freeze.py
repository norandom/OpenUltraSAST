"""Replacement population classification from exact reviewed authorities."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import replace

from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ground_truth_review import AcceptedGroundTruthV1, project_accepted_ground_truth
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1, ReviewedPositiveInput, ordinary_selection_bytes
from benchmarks.valid.population_freeze_contract import (
    MINIMUM_ADMISSION_POSITIVES,
    PopulationClass,
    PopulationClassificationReason,
    PopulationFreezeConflict,
    PopulationFreezeError,
    PopulationFreezeV3,
    PopulationScopeCountV1,
    ScopeMinimumV1,
    _freeze_value,
    _population_value,
    accept_population_freeze,
    population_freeze_bytes,
)
from benchmarks.valid.reservation import ReservationAuthority, ReservationCensusV1, ReservationError, census_bytes
from openultrasast.core.canonical import content_digest


def _canonical_minimums(values: Iterable[ScopeMinimumV1]) -> tuple[ScopeMinimumV1, ...]:
    try:
        return tuple(sorted(set(ScopeMinimumV1(item.vulnerability_family, item.ecosystem, item.minimum_count) for item in values)))
    except (AttributeError, TypeError) as error:
        raise PopulationFreezeError("population scope minimums are malformed") from error


def _canonical_exclusions(values: Iterable[tuple[str, int]]) -> tuple[tuple[str, int], ...]:
    supplied = tuple(values)
    result = tuple(sorted(set(supplied)))
    if len(result) != len(supplied):
        raise PopulationFreezeError("population exclusion counts are duplicated")
    return result


def _validated_inputs(
    positives: Iterable[ReviewedPositiveInput],
    ecosystem_policy: str,
    ground_truth_policy: str,
) -> tuple[tuple[ReviewedPositiveInput, ...], tuple[AcceptedGroundTruthV1, ...]]:
    items = tuple(positives)
    candidates = {item.candidate.candidate_digest: item.candidate for item in items}
    ecosystems = {item.ecosystem_review.review_digest: item.ecosystem_review for item in items}
    reviews = tuple(item.ground_truth_review for item in items)
    if len(candidates) != len(items) or len(ecosystems) != len(items) or len({item.review_digest for item in reviews}) != len(items):
        raise PopulationFreezeError("population reviewed positive identities are duplicated")
    try:
        accepted = project_accepted_ground_truth(
            reviews,
            candidates_by_digest=candidates,
            ecosystem_reviews_by_digest=ecosystems,
            expected_ecosystem_policy_digest=ecosystem_policy,
            expected_ground_truth_policy_digest=ground_truth_policy,
        )
    except ValueError as error:
        raise PopulationFreezeError("population positive review authority is invalid") from error
    if len(accepted) != len(items):
        raise PopulationFreezeError("population contains excluded or conflicting positive reviews")
    by_change = {item.ground_truth_review.change_identity_digest: item for item in items}
    if len(by_change) != len(items) or set(by_change) != {item.change_identity_digest for item in accepted}:
        raise PopulationFreezeError("population accepted change identities do not match exact reviews")
    return tuple(by_change[key] for key in sorted(by_change)), accepted


def _validate_reservation(
    items: tuple[ReviewedPositiveInput, ...],
    census: ReservationCensusV1,
    authority: ReservationAuthority,
) -> None:
    try:
        census_bytes(census)
    except ReservationError as error:
        raise PopulationFreezeError("reservation census is invalid") from error
    reserved = set(census.reserved_network_digests)
    for item in items:
        try:
            resolved = authority.resolve_repository(item.candidate.canonical_repository)
        except ReservationError as error:
            raise PopulationFreezeError("population repository is absent from reviewed identity authority") from error
        if (resolved.canonical_repository, resolved.network_identity_digest) != (
            item.candidate.canonical_repository,
            item.candidate.network_identity_digest,
        ):
            raise PopulationFreezeError("population candidate conflicts with resolved repository identity")
        if resolved.network_identity_digest in reserved:
            raise PopulationFreezeError("population positive repository is permanently reserved")


def _require_current_reservation(census: ReservationCensusV1, authority: ReservationAuthority) -> None:
    try:
        authority.require_current_census(census)
    except ReservationError as error:
        raise PopulationFreezeError("reservation census is not the current authoritative snapshot") from error


def _validate_ordinary(selection: OrdinarySelectionV1, items: tuple[ReviewedPositiveInput, ...]) -> None:
    try:
        ordinary_selection_bytes(selection)
    except ValueError as error:
        raise PopulationFreezeError("ordinary selection is invalid") from error
    changes = tuple(item.ground_truth_review.change_identity_digest for item in items)
    if selection.positive_change_digests != changes:
        raise PopulationFreezeError("ordinary selection does not bind the exact positive set")
    fixes = {
        (item.network_identity_digest, item.fixed_revision, item.positive_change_digest, item.ground_truth_review_digest)
        for item in selection.fix_exclusions
    }
    expected = {
        (
            item.candidate.network_identity_digest,
            item.candidate.fixed.revision,
            item.ground_truth_review.change_identity_digest,
            item.ground_truth_review.review_digest,
        )
        for item in items
    }
    if fixes != expected:
        raise PopulationFreezeError("ordinary accepted-fix authority does not match reviewed positives")
    authorities = {
        item.ground_truth_review.change_identity_digest: (
            item.candidate.network_identity_digest,
            item.ecosystem_review.ecosystem,
        )
        for item in items
    }
    for assignment in selection.assignments:
        if authorities.get(assignment.positive_change_digest) != (
            assignment.network_identity_digest,
            assignment.ecosystem,
        ):
            raise PopulationFreezeError("ordinary assignment crosses reviewed repository or ecosystem authority")


def _scope_census(accepted: tuple[AcceptedGroundTruthV1, ...]) -> tuple[PopulationScopeCountV1, ...]:
    counts: Counter[tuple[str, CanonicalEcosystem]] = Counter()
    for item in accepted:
        counts.update((scope.vulnerability_family, scope.ecosystem) for scope in item.verified_scopes)
    return tuple(PopulationScopeCountV1(family, ecosystem, count) for (family, ecosystem), count in sorted(counts.items()))


def _classification(
    positive_count: int,
    ecosystems: tuple[CanonicalEcosystem, ...],
    families: tuple[str, ...],
    census: tuple[PopulationScopeCountV1, ...],
    minimums: tuple[ScopeMinimumV1, ...],
) -> tuple[PopulationClass, tuple[PopulationClassificationReason, ...]]:
    reasons: set[PopulationClassificationReason] = set()
    if positive_count < MINIMUM_ADMISSION_POSITIVES:
        reasons.add(PopulationClassificationReason.BELOW_MINIMUM_POSITIVES)
    if set(ecosystems) != {CanonicalEcosystem.PYTHON, CanonicalEcosystem.JAVASCRIPT}:
        reasons.add(PopulationClassificationReason.MISSING_ECOSYSTEM)
    if len(families) < 2:
        reasons.add(PopulationClassificationReason.MISSING_SECOND_FAMILY)
    counts = {(item.vulnerability_family, item.ecosystem): item.count for item in census}
    if any(counts.get((item.vulnerability_family, item.ecosystem), 0) < item.minimum_count for item in minimums):
        reasons.add(PopulationClassificationReason.SCOPE_MINIMUM_UNMET)
    ordered = tuple(sorted(reasons, key=lambda item: item.value))
    if not ordered:
        return PopulationClass.ADMISSION, ()
    if ordered == (PopulationClassificationReason.BELOW_MINIMUM_POSITIVES,):
        return PopulationClass.DEVELOPMENT_PILOT, ordered
    return PopulationClass.INSUFFICIENT, ordered


def _draft_freeze(
    items: tuple[ReviewedPositiveInput, ...],
    accepted: tuple[AcceptedGroundTruthV1, ...],
    ordinary: OrdinarySelectionV1,
    census: ReservationCensusV1,
    minimums: tuple[ScopeMinimumV1, ...],
    exclusions: tuple[tuple[str, int], ...],
    source_provenance: str,
    ecosystem_policy: str,
    ground_truth_policy: str,
    freeze_policy: str,
) -> PopulationFreezeV3:
    scopes = _scope_census(accepted)
    ecosystems = tuple(sorted({scope.ecosystem for item in accepted for scope in item.verified_scopes}, key=lambda item: item.value))
    families = tuple(sorted({scope.vulnerability_family for item in accepted for scope in item.verified_scopes}))
    population_class, reasons = _classification(len(accepted), ecosystems, families, scopes, minimums)
    changes = tuple(item.change_identity_digest for item in accepted)
    ecosystem_reviews = tuple(sorted(item.ecosystem_review.review_digest for item in items))
    ground_truth_reviews = tuple(sorted(item.ground_truth_review.review_digest for item in items))
    return PopulationFreezeV3(
        population_class,
        reasons,
        len(accepted),
        ecosystems,
        families,
        scopes,
        minimums,
        changes,
        content_digest(
            {"accepted_changes": changes, "scope_census": tuple((x.vulnerability_family, x.ecosystem.value, x.count) for x in scopes)}
        ),
        ecosystem_reviews,
        ground_truth_reviews,
        content_digest({"ecosystem_reviews": ecosystem_reviews, "ground_truth_reviews": ground_truth_reviews}),
        ordinary.selection_digest,
        census.census_digest,
        exclusions,
        source_provenance,
        ecosystem_policy,
        ground_truth_policy,
        freeze_policy,
        "",
        "",
    )


def freeze_population(
    positives: Iterable[ReviewedPositiveInput],
    *,
    ordinary_selection: OrdinarySelectionV1,
    reservation_census: ReservationCensusV1,
    reservation_authority: ReservationAuthority,
    scope_minimums: Iterable[ScopeMinimumV1] = (),
    exclusion_counts: Iterable[tuple[str, int]] = (),
    source_provenance_digest: str,
    freeze_policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
    forbidden_historical_identities: Iterable[str] = (),
) -> PopulationFreezeV3:
    """Build one deterministic new replacement freeze from exact authorities."""
    _require_current_reservation(reservation_census, reservation_authority)
    items, accepted = _validated_inputs(positives, expected_ecosystem_policy_digest, expected_ground_truth_policy_digest)
    _validate_reservation(items, reservation_census, reservation_authority)
    _validate_ordinary(ordinary_selection, items)
    draft = _draft_freeze(
        items,
        accepted,
        ordinary_selection,
        reservation_census,
        _canonical_minimums(scope_minimums),
        _canonical_exclusions(exclusion_counts),
        source_provenance_digest,
        expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest,
        freeze_policy_digest,
    )
    with_population = replace(draft, population_digest=content_digest(_population_value(draft)))
    freeze = replace(with_population, freeze_digest=content_digest(_freeze_value(with_population, include_digest=False)))
    forbidden = set(forbidden_historical_identities)
    if freeze.population_digest in forbidden or freeze.freeze_digest in forbidden:
        raise PopulationFreezeError("replacement population reuses a historical identity")
    population_freeze_bytes(freeze)
    _require_current_reservation(reservation_census, reservation_authority)
    return freeze


def validate_population_freeze(
    freeze: PopulationFreezeV3,
    positives: Iterable[ReviewedPositiveInput],
    *,
    ordinary_selection: OrdinarySelectionV1,
    reservation_census: ReservationCensusV1,
    reservation_authority: ReservationAuthority,
    scope_minimums: Iterable[ScopeMinimumV1] = (),
    exclusion_counts: Iterable[tuple[str, int]] = (),
    source_provenance_digest: str,
    freeze_policy_digest: str,
    expected_ecosystem_policy_digest: str,
    expected_ground_truth_policy_digest: str,
    forbidden_historical_identities: Iterable[str] = (),
) -> bytes:
    _require_current_reservation(reservation_census, reservation_authority)
    expected = freeze_population(
        positives,
        ordinary_selection=ordinary_selection,
        reservation_census=reservation_census,
        reservation_authority=reservation_authority,
        scope_minimums=scope_minimums,
        exclusion_counts=exclusion_counts,
        source_provenance_digest=source_provenance_digest,
        freeze_policy_digest=freeze_policy_digest,
        expected_ecosystem_policy_digest=expected_ecosystem_policy_digest,
        expected_ground_truth_policy_digest=expected_ground_truth_policy_digest,
        forbidden_historical_identities=forbidden_historical_identities,
    )
    if expected != freeze:
        raise PopulationFreezeError("population freeze does not reproduce from exact authorities")
    content = population_freeze_bytes(freeze)
    _require_current_reservation(reservation_census, reservation_authority)
    return content


__all__ = [
    "PopulationClass",
    "PopulationClassificationReason",
    "PopulationFreezeConflict",
    "PopulationFreezeError",
    "PopulationFreezeV3",
    "PopulationScopeCountV1",
    "ScopeMinimumV1",
    "accept_population_freeze",
    "freeze_population",
    "population_freeze_bytes",
    "validate_population_freeze",
]
