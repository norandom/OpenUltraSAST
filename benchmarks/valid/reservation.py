"""Reviewed influence projection for the permanent reservation census."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from benchmarks.valid.reservation_identity import (
    RepositoryNetworkIdentity,
    ReservationConflict,
    ReservationError,
    _repository_locator,
    _require_digest,
    _require_text,
    build_network_identity,
)
from openultrasast.core.canonical import JsonValue, content_digest

INFLUENCE_SCHEMA = "openultrasast.valid-detection-benchmark.influence-event.v1"
LEGACY_SOURCE_SCHEMA = "openultrasast.valid-detection-benchmark.legacy-reservation.v1"
CENSUS_SCHEMA = "openultrasast.valid-detection-benchmark.reservation-census.v1"


class InfluenceDisposition(StrEnum):
    ENUMERATED_ONLY = "enumerated_only"
    INFLUENCED = "influenced"


class InfluenceKind(StrEnum):
    ENUMERATION = "enumeration"
    POPULATION_SELECTION = "population_selection"
    DETECTOR_DEVELOPMENT = "detector_development"
    TRAINING = "training"
    TUNING = "tuning"
    MINING = "mining"
    FACT_PROMOTION = "fact_promotion"
    PROMPT_SELECTION = "prompt_selection"
    THRESHOLD_SELECTION = "threshold_selection"


@dataclass(frozen=True)
class InfluenceEventV1:
    canonical_repository: str
    observed_repository: str
    network_identity_digest: str
    event_source: str
    disposition: InfluenceDisposition
    influence_kind: InfluenceKind
    subject_digest: str
    actor_identity: str
    reviewer_identity: str
    conflict_disclosed: bool
    policy_digest: str
    review_digest: str
    event_digest: str


@dataclass(frozen=True)
class LegacyReservationSourceV1:
    canonical_repository: str
    network_identity_digest: str
    source_digest: str
    legacy_source_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.network_identity_digest, "network identity digest")
        _require_digest(self.source_digest, "legacy source content digest")
        if self.legacy_source_digest != content_digest(_legacy_value(self)):
            raise ReservationError("legacy source digest does not match")


@dataclass(frozen=True)
class ReservationCensusV1:
    reserved_network_digests: tuple[str, ...]
    accepted_event_digests: tuple[str, ...]
    legacy_source_digests: tuple[str, ...]
    census_digest: str


def _review_value(event: InfluenceEventV1) -> JsonValue:
    return {
        "actor_identity": event.actor_identity,
        "reviewer_identity": event.reviewer_identity,
        "conflict_disclosed": event.conflict_disclosed,
        "policy_digest": event.policy_digest,
    }


def _event_value(event: InfluenceEventV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": INFLUENCE_SCHEMA,
        "canonical_repository": event.canonical_repository,
        "observed_repository": event.observed_repository,
        "network_identity_digest": event.network_identity_digest,
        "event_source": event.event_source,
        "disposition": event.disposition.value,
        "influence_kind": event.influence_kind.value,
        "subject_digest": event.subject_digest,
        "actor_identity": event.actor_identity,
        "reviewer_identity": event.reviewer_identity,
        "conflict_disclosed": event.conflict_disclosed,
        "policy_digest": event.policy_digest,
        "review_digest": event.review_digest,
    }
    if include_digest:
        value["event_digest"] = event.event_digest
    return value


def _validate_review(actor: str, reviewer: str, disclosed: object) -> None:
    if actor == reviewer or disclosed is not True:
        raise ReservationError("independent review and conflict disclosure are required")


def _validate_disposition(disposition: InfluenceDisposition, kind: InfluenceKind) -> None:
    is_enumerated = disposition is InfluenceDisposition.ENUMERATED_ONLY
    if is_enumerated != (kind is InfluenceKind.ENUMERATION):
        raise ReservationError("enumerated disposition requires enumeration kind only")


def reviewed_influence_event(
    resolver: RepositoryIdentityResolver,
    *,
    repository: str,
    event_source: str,
    disposition: InfluenceDisposition | str,
    influence_kind: InfluenceKind | str,
    subject_digest: str,
    actor_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
) -> bytes:
    network = resolver.resolve(repository)
    observed = _repository_locator(repository)
    disposition = InfluenceDisposition(disposition)
    influence_kind = InfluenceKind(influence_kind)
    actor = _require_text(actor_identity, "actor identity")
    reviewer = _require_text(reviewer_identity, "reviewer identity")
    _validate_review(actor, reviewer, conflict_disclosed)
    _validate_disposition(disposition, influence_kind)
    draft = InfluenceEventV1(
        network.canonical_repository,
        observed,
        network.network_identity_digest,
        _require_text(event_source, "event source"),
        disposition,
        influence_kind,
        _require_digest(subject_digest, "subject digest"),
        actor,
        reviewer,
        True,
        _require_digest(policy_digest, "review policy digest"),
        "",
        "",
    )
    reviewed = InfluenceEventV1(**{**vars(draft), "review_digest": content_digest(_review_value(draft))})
    complete = InfluenceEventV1(**{**vars(reviewed), "event_digest": content_digest(_event_value(reviewed, include_digest=False))})
    return canonical_event_bytes(_event_value(complete, include_digest=True))


def canonical_event_bytes(value: Mapping[str, object]) -> bytes:
    return canonical_json_bytes(value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReservationError(f"duplicate canonical JSON key: {key}")
        result[key] = value
    return result


def _decoded_event(content: bytes) -> dict[str, object]:
    if not isinstance(content, bytes) or not content:
        raise ReservationError("influence event bytes must be nonempty")
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReservationError("influence event bytes are unreadable") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != content:
        raise ReservationError("influence event bytes are not canonical")
    return value


def _event_fields() -> frozenset[str]:
    return frozenset(
        {
            "schema_version",
            "canonical_repository",
            "observed_repository",
            "network_identity_digest",
            "event_source",
            "disposition",
            "influence_kind",
            "subject_digest",
            "actor_identity",
            "reviewer_identity",
            "conflict_disclosed",
            "policy_digest",
            "review_digest",
            "event_digest",
        }
    )


def decode_influence_event(content: bytes) -> InfluenceEventV1:
    value = _decoded_event(content)
    if set(value) != _event_fields() or value.get("schema_version") != INFLUENCE_SCHEMA:
        raise ReservationError("influence event fields or schema are unsupported")
    try:
        event = InfluenceEventV1(
            _repository_locator(value["canonical_repository"]),
            _repository_locator(value["observed_repository"]),
            _require_digest(value["network_identity_digest"], "network identity digest"),
            _require_text(value["event_source"], "event source"),
            InfluenceDisposition(_require_text(value["disposition"], "influence disposition")),
            InfluenceKind(_require_text(value["influence_kind"], "influence kind")),
            _require_digest(value["subject_digest"], "subject digest"),
            _require_text(value["actor_identity"], "actor identity"),
            _require_text(value["reviewer_identity"], "reviewer identity"),
            value["conflict_disclosed"] is True,
            _require_digest(value["policy_digest"], "review policy digest"),
            _require_digest(value["review_digest"], "review digest"),
            _require_digest(value["event_digest"], "event digest"),
        )
    except (KeyError, ValueError, TypeError) as error:
        raise ReservationError("influence event contains unsupported values") from error
    _validate_review(event.actor_identity, event.reviewer_identity, value["conflict_disclosed"])
    _validate_disposition(event.disposition, event.influence_kind)
    if event.review_digest != content_digest(_review_value(event)):
        raise ReservationError("review digest does not match")
    if event.event_digest != content_digest(_event_value(event, include_digest=False)):
        raise ReservationError("event digest does not match")
    return event


def _legacy_value(source: LegacyReservationSourceV1) -> JsonValue:
    return _legacy_payload(source.canonical_repository, source.network_identity_digest, source.source_digest)


def _legacy_payload(canonical: str, network_digest: str, source_digest: str) -> JsonValue:
    return {
        "schema_version": LEGACY_SOURCE_SCHEMA,
        "canonical_repository": canonical,
        "network_identity_digest": network_digest,
        "source_digest": source_digest,
    }


def legacy_reservation_source(resolver: RepositoryIdentityResolver, *, repository: str, source_digest: str) -> LegacyReservationSourceV1:
    network = resolver.resolve(repository)
    source = _require_digest(source_digest, "legacy source content digest")
    return LegacyReservationSourceV1(
        network.canonical_repository,
        network.network_identity_digest,
        source,
        content_digest(_legacy_payload(network.canonical_repository, network.network_identity_digest, source)),
    )


def _census_value(census: ReservationCensusV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": CENSUS_SCHEMA,
        "reserved_network_digests": census.reserved_network_digests,
        "accepted_event_digests": census.accepted_event_digests,
        "legacy_source_digests": census.legacy_source_digests,
    }
    if include_digest:
        value["census_digest"] = census.census_digest
    return value


def census_bytes(census: ReservationCensusV1) -> bytes:
    for field in (
        census.reserved_network_digests,
        census.accepted_event_digests,
        census.legacy_source_digests,
    ):
        if field != tuple(sorted(set(field))):
            raise ReservationError("reservation census identities are not canonical")
        for digest in field:
            _require_digest(digest, "reservation census identity")
    if census.census_digest != content_digest(_census_value(census, include_digest=False)):
        raise ReservationError("reservation census digest does not match")
    return canonical_json_bytes(_census_value(census, include_digest=True))


class RepositoryIdentityResolver:
    """Resolve aliases, former names, redirects, and forks before event admission."""

    def __init__(self, networks: Iterable[RepositoryNetworkIdentity]) -> None:
        self._network_by_member: dict[str, RepositoryNetworkIdentity] = {}
        self._network_by_digest: dict[str, RepositoryNetworkIdentity] = {}
        for network in networks:
            self._add_network(network)

    def _add_network(self, network: RepositoryNetworkIdentity) -> None:
        RepositoryNetworkIdentity(**vars(network))
        existing_digest = self._network_by_digest.get(network.network_identity_digest)
        if existing_digest is not None and existing_digest != network:
            raise ReservationConflict("network identity digest has conflicting definitions")
        for member in network.members:
            existing = self._network_by_member.get(member)
            if existing is not None and existing.network_identity_digest != network.network_identity_digest:
                raise ReservationConflict("repository member belongs to multiple networks")
            self._network_by_member[member] = network
        self._network_by_digest[network.network_identity_digest] = network

    def resolve(self, repository: str) -> RepositoryNetworkIdentity:
        normalized = _repository_locator(repository)
        try:
            return self._network_by_member[normalized]
        except KeyError as error:
            raise ReservationError("repository is not resolved to a reviewed network") from error

    def by_digest(self, digest: str) -> RepositoryNetworkIdentity:
        try:
            return self._network_by_digest[digest]
        except KeyError as error:
            raise ReservationError("network identity is not resolved") from error


class ReservationAuthority:
    """Accept reviewed events and project one deterministic permanent census."""

    def __init__(self, resolver: RepositoryIdentityResolver, *, legacy_sources: Iterable[LegacyReservationSourceV1] = ()) -> None:
        self._resolver = resolver
        self._legacy_by_digest: dict[str, LegacyReservationSourceV1] = {}
        self._accepted_bytes_by_digest: dict[str, bytes] = {}
        for source in legacy_sources:
            self._accept_legacy(source)

    def _accept_legacy(self, source: LegacyReservationSourceV1) -> None:
        network = self._resolver.by_digest(source.network_identity_digest)
        if source.canonical_repository != network.canonical_repository:
            raise ReservationConflict("legacy source canonical identity conflicts")
        existing = self._legacy_by_digest.get(source.legacy_source_digest)
        if existing is not None and existing != source:
            raise ReservationConflict("legacy source identity has conflicting content")
        self._legacy_by_digest[source.legacy_source_digest] = source

    def _accepted_events(self, contents: Iterable[bytes]) -> dict[str, tuple[InfluenceEventV1, bytes]]:
        accepted: dict[str, tuple[InfluenceEventV1, bytes]] = {}
        for content in contents:
            event = decode_influence_event(content)
            network = self._resolver.by_digest(event.network_identity_digest)
            if self._resolver.resolve(event.observed_repository) != network:
                raise ReservationConflict("event repository conflicts with network identity")
            if event.canonical_repository != network.canonical_repository:
                raise ReservationConflict("event canonical repository conflicts with network identity")
            existing = accepted.get(event.event_digest)
            if existing is not None and existing[1] != content:
                raise ReservationConflict("same event identity has different bytes")
            accepted[event.event_digest] = (event, content)
        return accepted

    def project_census(self, contents: Iterable[bytes]) -> ReservationCensusV1:
        accepted = self._accepted_events(contents)
        reserved = {source.network_identity_digest for source in self._legacy_by_digest.values()}
        reserved.update(
            event.network_identity_digest for event, _ in accepted.values() if event.disposition is InfluenceDisposition.INFLUENCED
        )
        draft = ReservationCensusV1(tuple(sorted(reserved)), tuple(sorted(accepted)), tuple(sorted(self._legacy_by_digest)), "")
        return ReservationCensusV1(
            draft.reserved_network_digests,
            draft.accepted_event_digests,
            draft.legacy_source_digests,
            content_digest(_census_value(draft, include_digest=False)),
        )

    def append_influence(self, content: bytes) -> ReservationCensusV1:
        event = decode_influence_event(content)
        existing = self._accepted_bytes_by_digest.get(event.event_digest)
        if existing is not None and existing != content:
            raise ReservationConflict("same event identity has different bytes")
        self._accepted_events((content,))
        self._accepted_bytes_by_digest[event.event_digest] = content
        return self.project_census(self._accepted_bytes_by_digest.values())

    def is_reserved(self, repository: str, census: ReservationCensusV1) -> bool:
        census_bytes(census)
        try:
            network = self._resolver.resolve(repository)
        except ReservationError:
            return False
        return network.network_identity_digest in census.reserved_network_digests


__all__ = [
    "InfluenceDisposition",
    "InfluenceKind",
    "LegacyReservationSourceV1",
    "RepositoryIdentityResolver",
    "RepositoryNetworkIdentity",
    "ReservationAuthority",
    "ReservationCensusV1",
    "ReservationConflict",
    "ReservationError",
    "build_network_identity",
    "canonical_event_bytes",
    "census_bytes",
    "decode_influence_event",
    "legacy_reservation_source",
    "reviewed_influence_event",
]
