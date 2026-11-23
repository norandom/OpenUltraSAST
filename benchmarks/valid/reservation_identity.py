"""Canonical repository-network identities for reservation authority."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from openultrasast.core.canonical import JsonValue, content_digest

NETWORK_SCHEMA = "openultrasast.valid-detection-benchmark.repository-network.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_GIT_SUFFIX = ".git"


class ReservationError(ValueError):
    """Reservation input is invalid or unauthoritative."""


class ReservationConflict(ReservationError):
    """Two records claim incompatible reservation identities."""


@dataclass(frozen=True)
class RepositoryNetworkIdentity:
    canonical_repository: str
    aliases: tuple[str, ...]
    former_names: tuple[str, ...]
    redirects: tuple[str, ...]
    forks: tuple[str, ...]
    network_identity_digest: str

    def __post_init__(self) -> None:
        _validate_network_shape(self)
        if self.network_identity_digest != content_digest(_network_value(self)):
            raise ReservationError("repository network identity digest does not match")

    @property
    def members(self) -> tuple[str, ...]:
        return (self.canonical_repository, *self.aliases, *self.former_names, *self.redirects, *self.forks)


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReservationError(f"{field} must be nonempty text")
    return value.strip()


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReservationError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def strip_git_suffix(repository: str) -> str:
    """Drop a trailing provider clone suffix in any letter case, nothing else."""
    if repository.lower().endswith(_GIT_SUFFIX):
        return repository[: len(repository) - len(_GIT_SUFFIX)]
    return repository


def _repository_locator(value: object) -> str:
    text = _require_text(value, "repository locator")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as error:
        raise ReservationError("repository locator is invalid") from error
    if parsed.scheme.lower() != "https" or not parsed.hostname or port not in {None, 443}:
        raise ReservationError("repository locator must be an HTTPS repository URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ReservationError("repository locator contains unsupported URL components")
    parts = tuple(part for part in parsed.path.split("/") if part)
    if len(parts) != 2:
        raise ReservationError("repository locator must identify owner and repository")
    owner, repository = parts
    repository = strip_git_suffix(repository)
    if not owner or not repository:
        raise ReservationError("repository locator must identify owner and repository")
    return f"https://{parsed.hostname.lower()}/{owner.lower()}/{repository.lower()}"


def _relationship_members(values: Iterable[str], canonical: str) -> tuple[str, ...]:
    return tuple(sorted({_repository_locator(value) for value in values} - {canonical}))


def _validate_network_shape(network: RepositoryNetworkIdentity) -> None:
    canonical = _repository_locator(network.canonical_repository)
    if canonical != network.canonical_repository:
        raise ReservationError("canonical repository identity is not normalized")
    groups = (network.aliases, network.former_names, network.redirects, network.forks)
    if any(group != _relationship_members(group, canonical) for group in groups):
        raise ReservationError("repository relationship identities are not canonical")
    members = tuple(member for group in groups for member in group)
    if len(members) != len(set(members)):
        raise ReservationConflict("repository member has multiple relationship roles")


def _network_value(network: RepositoryNetworkIdentity) -> JsonValue:
    return _network_payload(
        network.canonical_repository,
        network.aliases,
        network.former_names,
        network.redirects,
        network.forks,
    )


def _network_payload(
    canonical: str,
    aliases: tuple[str, ...],
    former_names: tuple[str, ...],
    redirects: tuple[str, ...],
    forks: tuple[str, ...],
) -> JsonValue:
    return {
        "schema_version": NETWORK_SCHEMA,
        "canonical_repository": canonical,
        "aliases": aliases,
        "former_names": former_names,
        "redirects": redirects,
        "forks": forks,
    }


def build_network_identity(
    canonical_repository: str,
    *,
    aliases: Iterable[str] = (),
    former_names: Iterable[str] = (),
    redirects: Iterable[str] = (),
    forks: Iterable[str] = (),
) -> RepositoryNetworkIdentity:
    """Collapse every provider relationship into one content identity."""
    canonical = _repository_locator(canonical_repository)
    groups = tuple(_relationship_members(values, canonical) for values in (aliases, former_names, redirects, forks))
    flattened = tuple(member for group in groups for member in group)
    if len(flattened) != len(set(flattened)):
        raise ReservationConflict("repository member has multiple relationship roles")
    aliases_value, former_value, redirects_value, forks_value = groups
    digest = content_digest(_network_payload(canonical, aliases_value, former_value, redirects_value, forks_value))
    return RepositoryNetworkIdentity(canonical, aliases_value, former_value, redirects_value, forks_value, digest)
