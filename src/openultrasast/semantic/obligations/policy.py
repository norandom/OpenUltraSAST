"""The declared policy: project-owned, versioned, closed (authorization-obligations, Req 4).

The tool never writes this file. Unknown fields or values are rejected by name; a missing file means no declared policy.
"""

from __future__ import annotations

import fnmatch
import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .facts import SENSITIVITIES, load_obligation_facts

ROUTE_ACCESS = ("public", "authenticated", "role")
_TOP_FIELDS = frozenset({"version", "identity_source", "resource", "route"})
_RESOURCE_FIELDS = frozenset({"name", "sensitivity", "identity_field"})
_ROUTE_FIELDS = frozenset({"path", "access", "roles"})
DEFAULT_POLICY_RELPATH = Path(".openultrasast") / "obligations.toml"


class PolicyError(ValueError):
    """Raised when a declared policy names a field or value outside the closed schema."""


@dataclass(frozen=True)
class PolicyResource:
    name: str
    sensitivity: str
    identity_field: str | None


@dataclass(frozen=True)
class PolicyRoute:
    path: str  # exact or with a trailing `*`
    access: str  # ROUTE_ACCESS
    roles: tuple[str, ...]


@dataclass(frozen=True)
class DeclaredPolicy:
    version: int
    identity_source: str | None
    resources: dict[str, PolicyResource]
    routes: tuple[PolicyRoute, ...]
    version_hash: str

    def route_access(self, path: str) -> str | None:
        for route in self.routes:
            if fnmatch.fnmatchcase(path, route.path) or path == route.path:
                return route.access
        return None

    def sensitivity(self, resource: str | None) -> str | None:
        return self.resources[resource].sensitivity if resource in self.resources else None


def load_declared_policy(path: Path) -> DeclaredPolicy | None:
    if not path.is_file():
        return None
    text = path.read_text()
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: invalid TOML: {exc}") from exc
    extra = sorted(set(payload) - _TOP_FIELDS)
    if extra:
        raise PolicyError(f"{path}: unknown field {extra[0]!r}")
    version = payload.get("version", 1)
    if not isinstance(version, int):
        raise PolicyError(f"{path}: version must be an integer")
    identity_source = payload.get("identity_source")
    if identity_source is not None:
        allowed = {source for fact in load_obligation_facts().dischargers for source in fact.identity_sources} | {"token"}
        if not isinstance(identity_source, str) or identity_source not in allowed:
            raise PolicyError(f"{path}: identity_source {identity_source!r} is not a known authenticated-context source")
    resources: dict[str, PolicyResource] = {}
    for row in _rows(payload.get("resource"), path, "resource"):
        _only(row, _RESOURCE_FIELDS, path, "resource")
        sensitivity = str(row.get("sensitivity", "medium"))
        if sensitivity not in SENSITIVITIES:
            raise PolicyError(f"{path}: resource {row.get('name')!r} has unknown sensitivity {sensitivity!r}")
        name = str(row["name"])
        identity_field = row.get("identity_field")
        resources[name] = PolicyResource(name=name, sensitivity=sensitivity, identity_field=str(identity_field) if identity_field else None)
    routes: list[PolicyRoute] = []
    for row in _rows(payload.get("route"), path, "route"):
        _only(row, _ROUTE_FIELDS, path, "route")
        access = str(row.get("access", ""))
        if access not in ROUTE_ACCESS:
            raise PolicyError(f"{path}: route {row.get('path')!r} has unknown access {access!r}")
        roles = row.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(item, str) for item in roles):
            raise PolicyError(f"{path}: route {row.get('path')!r} roles must be a list of strings")
        routes.append(PolicyRoute(path=str(row["path"]), access=access, roles=tuple(roles)))
    return DeclaredPolicy(
        version=version,
        identity_source=identity_source,
        resources=resources,
        routes=tuple(routes),
        version_hash=_version_hash(text),
    )


def _version_hash(text: str) -> str:
    normalized = "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines() if line.split("#", 1)[0].strip())
    return hashlib.sha1(normalized.encode()).hexdigest()


def _rows(value: object, path: Path, table: str) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise PolicyError(f"{path}: {table} must be an array of tables")
    return [dict(item) for item in value]


def _only(row: dict[str, object], allowed: frozenset[str], path: Path, table: str) -> None:
    extra = sorted(set(row) - allowed)
    if extra:
        raise PolicyError(f"{path}: {table} {row.get('name', row.get('path'))!r} has unknown field {extra[0]!r}")
    required = "name" if table == "resource" else "path"
    if required not in row:
        raise PolicyError(f"{path}: every {table} needs a {required}")


__all__ = [
    "DEFAULT_POLICY_RELPATH",
    "ROUTE_ACCESS",
    "DeclaredPolicy",
    "PolicyError",
    "PolicyResource",
    "PolicyRoute",
    "load_declared_policy",
]
