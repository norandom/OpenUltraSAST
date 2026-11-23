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


_MIXED_CASE_SUFFIXES = (".Git", ".gIT", ".giT", ".GIT")

_CORE_DIGEST = "730da0136fb50945132e8b281e7e28bfc0ce995fbcb2aa04fce24a816a79a0aa"

# (url, canonical member, network identity digest) captured from the unmodified
# identity function on 2026-11-23. None of these URLs carries a mixed-case ".git"
# suffix, so its identity must not move when suffix stripping becomes
# case-insensitive.
_UNCHANGED_IDENTITIES = (
    ("https://github.com/acme/core", "https://github.com/acme/core", _CORE_DIGEST),
    ("https://github.com/acme/core.git", "https://github.com/acme/core", _CORE_DIGEST),
    ("https://GITHUB.com/ACME/Core.git", "https://github.com/acme/core", _CORE_DIGEST),
    (
        "https://github.com/acme/widget.js",
        "https://github.com/acme/widget.js",
        "4bb775da3d25c77598ff4d984b3d1e854e4389d081c3f40fa4da3e3e0d9e2d20",
    ),
    (
        "https://github.com/acme/digest.git",
        "https://github.com/acme/digest",
        "c8a4e82de9913aae7c9a2b7d15b0d9d4fe6850fc92b549b37b357d4531537f18",
    ),
    (
        "https://github.com/acme/.gitlab",
        "https://github.com/acme/.gitlab",
        "7e713fdc633f805b965387050573427596967976e1209385d5f419bebbe1f097",
    ),
)


@pytest.mark.parametrize("suffix", _MIXED_CASE_SUFFIXES)
def test_mixed_case_git_suffix_shares_the_lowercase_identity(suffix: str) -> None:
    plain = reservation.build_network_identity("https://github.com/acme/core")
    resolver = reservation.RepositoryIdentityResolver((plain,))
    legacy = reservation.legacy_reservation_source(resolver, repository=plain.canonical_repository, source_digest=LEGACY)
    authority = reservation.ReservationAuthority(resolver, legacy_sources=(legacy,))
    mixed_url = "https://GITHUB.com/ACME/Core" + suffix

    mixed = reservation.build_network_identity(mixed_url)

    assert mixed == plain
    assert mixed.network_identity_digest == plain.network_identity_digest
    assert resolver.resolve(mixed_url) == plain
    assert authority.is_reserved(mixed_url, authority.current_census())


@pytest.mark.parametrize(
    "url, canonical",
    (
        ("https://github.com/acme/core.gitt", "https://github.com/acme/core.gitt"),
        ("https://github.com/acme/Core.GitHub", "https://github.com/acme/core.github"),
        ("https://github.com/acme/digi.t", "https://github.com/acme/digi.t"),
    ),
)
def test_only_the_git_suffix_is_stripped(url: str, canonical: str) -> None:
    assert reservation.build_network_identity(url).canonical_repository == canonical
    with pytest.raises(reservation.ReservationError, match="owner and repository"):
        reservation.build_network_identity("https://GITHUB.com/ACME/.GIT")


@pytest.mark.parametrize("url, canonical, digest", _UNCHANGED_IDENTITIES)
def test_identity_without_a_mixed_case_suffix_is_byte_identical(url: str, canonical: str, digest: str) -> None:
    network = reservation.build_network_identity(url)

    assert (network.canonical_repository, network.network_identity_digest) == (canonical, digest)


def test_related_identity_without_a_mixed_case_suffix_is_byte_identical() -> None:
    network = reservation.build_network_identity(
        "https://GITHUB.com/ACME/Core.git",
        aliases=("https://github.com/acme/core",),
        former_names=("https://github.com/acme/old-core.git",),
        redirects=("https://github.com/acme/redirected-core",),
        forks=("https://github.com/Contributor/Core-Fork.git",),
    )

    assert network.members == (
        "https://github.com/acme/core",
        "https://github.com/acme/old-core",
        "https://github.com/acme/redirected-core",
        "https://github.com/contributor/core-fork",
    )
    assert network.network_identity_digest == "6b0e4a87982c368045a65c3ff1c0b3cba02b52d5d0d191aa98d38ba7c2667e36"
