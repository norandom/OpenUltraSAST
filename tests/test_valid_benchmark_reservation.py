"""Reviewed influence projection into the permanent reservation census."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import reservation  # noqa: E402
from openultrasast.core.canonical import content_digest  # noqa: E402

POLICY = content_digest({"policy": "independent-influence-review-v1"})
SUBJECT = content_digest({"subject": "selection-evidence"})
LEGACY = content_digest({"legacy": "authoritative-reservation"})


def _network(*, canonical: str = "https://github.com/acme/core") -> reservation.RepositoryNetworkIdentity:
    return reservation.build_network_identity(
        canonical,
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
    source: str = "reviewed-sourcing-run",
) -> bytes:
    return reservation.reviewed_influence_event(
        resolver,
        repository=repository,
        event_source=source,
        disposition=disposition,
        influence_kind=kind,
        subject_digest=SUBJECT,
        actor_identity="producer@example.invalid",
        reviewer_identity="reviewer@example.invalid",
        conflict_disclosed=True,
        policy_digest=POLICY,
    )


def test_influenced_network_reserves_alias_former_redirect_and_fork() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)

    census = authority.append_influence(_event(resolver))

    for repository in (
        "https://github.com/acme/core",
        "https://github.com/ACME/core.git",
        "https://github.com/acme/old-core",
        "https://github.com/acme/redirected-core",
        "https://github.com/contributor/core-fork",
    ):
        assert authority.is_reserved(repository, census)


def test_enumerated_only_event_does_not_reserve_repository() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)
    event = _event(
        resolver,
        disposition=reservation.InfluenceDisposition.ENUMERATED_ONLY,
        kind=reservation.InfluenceKind.ENUMERATION,
    )

    census = authority.append_influence(event)

    assert not authority.is_reserved("https://github.com/acme/core", census)
    assert census.accepted_event_digests == (reservation.decode_influence_event(event).event_digest,)


@pytest.mark.parametrize(
    "kind",
    tuple(kind for kind in reservation.InfluenceKind if kind is not reservation.InfluenceKind.ENUMERATION),
)
def test_every_reviewed_influence_kind_reserves(kind: reservation.InfluenceKind) -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)

    census = authority.append_influence(_event(resolver, kind=kind))

    assert authority.is_reserved("https://github.com/acme/old-core", census)


def test_equal_events_are_idempotent() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)
    event = _event(resolver)

    first = authority.append_influence(event)
    second = authority.append_influence(bytes(event))

    assert first == second
    assert len(second.accepted_event_digests) == 1


def test_current_census_includes_legacy_and_equal_appends_are_idempotent() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    legacy = reservation.legacy_reservation_source(
        resolver,
        repository="https://github.com/acme/old-core",
        source_digest=LEGACY,
    )
    authority = reservation.ReservationAuthority(resolver, legacy_sources=(legacy,))
    initial = authority.current_census()
    event = _event(resolver)

    first = authority.append_influence(event)
    second = authority.append_influence(bytes(event))

    assert initial.legacy_source_digests == (legacy.legacy_source_digest,)
    assert first == second == authority.current_census()
    assert len(second.accepted_event_digests) == 1
    authority.require_current_census(second)


def test_census_is_deterministic_from_complete_event_set() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)
    first = _event(
        resolver,
        disposition=reservation.InfluenceDisposition.ENUMERATED_ONLY,
        kind=reservation.InfluenceKind.ENUMERATION,
        source="first",
    )
    second = _event(resolver, source="second")

    forward = authority.project_census((first, second))
    reverse = authority.project_census((second, first, first))

    assert forward == reverse
    assert reservation.census_bytes(forward) == reservation.census_bytes(reverse)


def test_changed_event_bytes_change_census_identity() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)

    first = authority.project_census((_event(resolver, source="first"),))
    changed = authority.project_census((_event(resolver, source="changed"),))

    assert first.census_digest != changed.census_digest


def test_tampered_or_noncanonical_event_bytes_fail_before_projection() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    authority = reservation.ReservationAuthority(resolver)
    event = _event(resolver)
    value = json.loads(event)
    value["event_source"] = "changed-with-stale-digest"

    with pytest.raises(reservation.ReservationError, match="digest"):
        authority.project_census((reservation.canonical_event_bytes(value),))
    with pytest.raises(reservation.ReservationError, match="canonical"):
        authority.project_census((json.dumps(json.loads(event), indent=2).encode(),))


def test_conflicting_network_members_fail_closed() -> None:
    first = _network()
    second = reservation.build_network_identity(
        "https://github.com/other/project",
        forks=("https://github.com/contributor/core-fork",),
    )

    with pytest.raises(reservation.ReservationConflict, match="multiple networks"):
        reservation.RepositoryIdentityResolver((first, second))


@pytest.mark.parametrize(
    "actor,reviewer,disclosed",
    (
        ("same", "same", True),
        ("producer", "reviewer", False),
    ),
)
def test_review_must_be_independent_and_conflict_disclosed(actor: str, reviewer: str, disclosed: bool) -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))

    with pytest.raises(reservation.ReservationError, match="review"):
        reservation.reviewed_influence_event(
            resolver,
            repository="https://github.com/acme/core",
            event_source="source",
            disposition=reservation.InfluenceDisposition.INFLUENCED,
            influence_kind=reservation.InfluenceKind.MINING,
            subject_digest=SUBJECT,
            actor_identity=actor,
            reviewer_identity=reviewer,
            conflict_disclosed=disclosed,
            policy_digest=POLICY,
        )


def test_unknown_repository_cannot_enter_reviewed_event() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))

    with pytest.raises(reservation.ReservationError, match="resolved"):
        _event(resolver, repository="https://github.com/unknown/project")


def test_authoritative_legacy_source_reserves_whole_network() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))
    legacy = reservation.legacy_reservation_source(
        resolver,
        repository="https://github.com/acme/old-core",
        source_digest=LEGACY,
    )
    authority = reservation.ReservationAuthority(resolver, legacy_sources=(legacy,))

    census = authority.project_census(())

    assert authority.is_reserved("https://github.com/contributor/core-fork", census)
    assert census.legacy_source_digests == (legacy.legacy_source_digest,)


def test_disposition_and_kind_must_agree() -> None:
    resolver = reservation.RepositoryIdentityResolver((_network(),))

    with pytest.raises(reservation.ReservationError, match="enumerated"):
        _event(
            resolver,
            disposition=reservation.InfluenceDisposition.ENUMERATED_ONLY,
            kind=reservation.InfluenceKind.TUNING,
        )


def test_network_identity_is_deterministic_and_exact() -> None:
    first = _network()
    second = reservation.build_network_identity(
        "https://github.com/acme/core",
        aliases=("https://github.com/acme/core",),
        former_names=("https://github.com/acme/old-core",),
        redirects=("https://github.com/acme/redirected-core",),
        forks=("https://github.com/contributor/core-fork",),
    )

    assert first == second
    with pytest.raises(reservation.ReservationError, match="digest"):
        reservation.RepositoryIdentityResolver((replace(first, network_identity_digest="0" * 64),))
