"""The plane's configuration surface: one ``PlaneProfile`` per cluster (plane-on-kubernetes design section 1).

A profile is a TOML file under ``ops/k8s/profiles/`` (``kind.toml`` for the server VM's kind cluster, ``k3s.toml`` for
the production cluster) holding every value that differs between clusters: the execution mode, the kube context,
the registry and the digest-pinned images file, the router and ax-server addresses (empty: tunnel through the
Kubernetes API), the memory store, the atespace, ax's snapshot bucket, the worker pools and the image pull secret.
:func:`load_profile` reads the file ``OUSAST_PLANE_PROFILE`` names (a profile name or a path; default ``kind``) and
then applies the environment: every scalar field is overridable by ``OUSAST_<FIELD>`` (``OUSAST_KUBE_CONTEXT``,
``OUSAST_REGISTRY``, ``OUSAST_MEMORY``, ``OUSAST_ROUTER_URL``, ...), a pool by ``OUSAST_POOL_<NAME>_<FIELD>``.

A profile holds no secret: a key whose name ends in ``key``, ``secret``, ``token`` or ``password`` is refused, and so
is any unknown key, an ``exec`` outside ``local``/``remote``, and an images file whose references are not pinned by
digest (Agent Substrate rejects tags). Provider and store credentials stay in the environment or ``.env``.

``python -m openultrasast.plane.profile --print FIELD`` prints one value for shell scripts (``ops/ax/up.sh``):
``registry``, ``kube_context``, ``images.runner``, ``pools.default.replicas``, ...
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_PROFILE", "PROFILES_DIR", "PlaneProfile", "Pool", "ProfileError", "load_images", "load_profile", "profiles_dir"]

DEFAULT_PROFILE = "kind"
PROFILES_DIR = Path("ops/k8s/profiles")
EXEC_MODES = ("local", "remote")
_DIGEST = re.compile(r"\S+@sha256:[0-9a-f]{64}")
_SECRET_KEY = re.compile(r"(key|secret|token|password)$", re.IGNORECASE)
_SECRET_VALUE = re.compile(r"(sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}|[A-Za-z0-9+/]{40,}={0,2}$)")
_ENV_PREFIX = "OUSAST_"


class ProfileError(ValueError):
    """A profile that cannot be used; the message names the file and the field."""


@dataclass(frozen=True)
class Pool:
    """One WorkerPool's size: how many warm workers, and each worker's CPU and memory limit."""

    replicas: int
    cpu: str
    memory: str


@dataclass(frozen=True)
class PlaneProfile:
    """The values of one cluster. ``images`` is resolved against the profile file's directory."""

    name: str
    path: Path
    exec: str = "local"
    kind_observability: bool = False
    kube_context: str = ""
    registry: str = ""
    images: Path = Path("images.json")
    router_url: str = ""
    ax_server: str = ""
    memory: str = ""
    atespace: str = "default"
    snapshots_bucket: str = ""
    image_pull_secret: str = ""
    pools: Mapping[str, Pool] = field(default_factory=dict)

    def load_images(self) -> dict[str, str]:
        """The digest-pinned image references of ``images`` (``{"runner": ..., "engine": ...}``)."""
        return load_images(self.images)

    def addresses(self) -> dict[str, str]:
        """Every configured address, for ``ousast plane doctor`` (Req 1.2); an empty router or ax-server address
        means the Kubernetes API tunnel."""
        return {
            "exec": self.exec,
            "kube_context": self.kube_context,
            "registry": self.registry,
            "images": str(self.images),
            "router_url": self.router_url or "(tunnel through the kube context)",
            "ax_server": self.ax_server or "(tunnel through the kube context)",
            "memory": self.memory,
            "atespace": self.atespace,
            "snapshots_bucket": self.snapshots_bucket,
            "image_pull_secret": self.image_pull_secret or "(none)",
        }


_SCALARS = {f.name: str(f.type) for f in fields(PlaneProfile) if f.name not in ("name", "path", "pools")}
_POOL_FIELDS = {f.name: str(f.type) for f in fields(Pool)}


def profiles_dir() -> Path:
    """``ops/k8s/profiles`` of this checkout (``OUSAST_PLANE_PROFILES`` overrides; an installed package falls back
    to the working directory)."""
    override = os.environ.get("OUSAST_PLANE_PROFILES")
    if override:
        return Path(override)
    checkout = Path(__file__).resolve().parents[3] / PROFILES_DIR
    return checkout if checkout.is_dir() else PROFILES_DIR


def load_images(path: Path) -> dict[str, str]:
    """``{"runner": "<registry>/<name>@sha256:<64 hex>", ...}`` from a JSON images file; every value must be
    digest-pinned. A one-line file holding a single reference (``ops/ax/up.sh`` before this profile) reads as
    ``{"runner": <line>}``."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ProfileError(f"images file {path}: {exc.strerror or exc}") from None
    try:
        loaded: Any = json.loads(text) if text.startswith("{") else {"runner": text}
    except ValueError as exc:
        raise ProfileError(f"images file {path}: not JSON ({exc})") from None
    if not isinstance(loaded, dict) or not loaded or not all(isinstance(k, str) and isinstance(v, str) for k, v in loaded.items()):
        raise ProfileError(f"images file {path}: expected an object of image names to references")
    for name, reference in loaded.items():
        if not _DIGEST.fullmatch(reference):
            raise ProfileError(f"images file {path}: {name} is not digest-pinned ({reference!r}); Agent Substrate rejects tags")
    return dict(loaded)


def _reject_secret(where: str, key: str, value: object, declared: bool = False) -> None:
    """A key that is not a declared field and is named like a credential, or any value shaped like one, is refused.
    ``image_pull_secret`` is declared: its value is the *name* of a Kubernetes Secret, never its content."""
    if not declared and _SECRET_KEY.search(key):
        raise ProfileError(f"{where}: {key} looks like a credential; profiles hold no secret (use the environment or .env)")
    if isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ProfileError(f"{where}: the value of {key} looks like a credential; profiles hold no secret")


def _coerce(where: str, key: str, value: object, kind: str) -> Any:
    if kind == "bool":
        if not isinstance(value, bool):
            raise ProfileError(f"{where}: {key} must be a boolean, got {value!r}")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProfileError(f"{where}: {key} must be an integer, got {value!r}")
        return value
    if kind == "Path":
        if not isinstance(value, str) or not value:
            raise ProfileError(f"{where}: {key} must be a file name")
        return Path(value)
    if not isinstance(value, str):
        raise ProfileError(f"{where}: {key} must be a string, got {value!r}")
    return value


def _pools(where: str, raw: object) -> dict[str, Pool]:
    if not isinstance(raw, dict):
        raise ProfileError(f"{where}: pools must be a table of pool names")
    out: dict[str, Pool] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            raise ProfileError(f"{where}: pools.{name} must be a table")
        unknown = sorted(set(spec) - set(_POOL_FIELDS))
        if unknown:
            raise ProfileError(f"{where}: pools.{name} has unknown keys: {', '.join(unknown)}")
        missing = sorted(set(_POOL_FIELDS) - set(spec))
        if missing:
            raise ProfileError(f"{where}: pools.{name} lacks {', '.join(missing)}")
        for key, value in spec.items():
            _reject_secret(where, f"pools.{name}.{key}", value, declared=True)
        out[str(name)] = Pool(**{k: _coerce(where, f"pools.{name}.{k}", spec[k], _POOL_FIELDS[k]) for k in _POOL_FIELDS})
    return out


def _env_overrides(environ: Mapping[str, str], where: str, values: dict[str, Any], pools: dict[str, Pool]) -> None:
    for name, kind in _SCALARS.items():
        raw = environ.get(_ENV_PREFIX + name.upper())
        if raw is not None and raw != "":
            value: Any = raw
            if kind == "bool":
                if raw.lower() not in ("true", "false", "1", "0"):
                    raise ProfileError(f"{where}: {_ENV_PREFIX}{name.upper()} must be true/false or 1/0, got {raw!r}")
                value = raw.lower() in ("true", "1")
            if kind == "int":
                try:
                    value = int(raw)
                except ValueError:
                    raise ProfileError(f"{where}: {_ENV_PREFIX}{name.upper()} must be an integer, got {raw!r}") from None
            values[name] = _coerce(where, _ENV_PREFIX + name.upper(), value, kind)
    pattern = re.compile(rf"^{_ENV_PREFIX}POOL_([A-Z0-9]+)_(REPLICAS|CPU|MEMORY)$")
    for variable, raw in environ.items():
        found = pattern.match(variable)
        if not found or raw == "":
            continue
        pool_name, key = found.group(1).lower(), found.group(2).lower()
        current = pools.get(pool_name)
        if current is None:
            raise ProfileError(f"{where}: {variable} names a pool the profile does not declare ({pool_name})")
        value = int(raw) if key == "replicas" and raw.isdigit() else raw
        pools[pool_name] = Pool(**{**vars(current), key: _coerce(where, variable, value, _POOL_FIELDS[key])})


def load_profile(name: str | None = None, environ: Mapping[str, str] | None = None) -> PlaneProfile:
    """The profile ``name`` (a name under :func:`profiles_dir` or a path to a ``.toml``; default
    ``OUSAST_PLANE_PROFILE``, else ``kind``), with the environment's overrides applied; :class:`ProfileError`
    names what is wrong."""
    env = os.environ if environ is None else environ
    chosen = name or env.get("OUSAST_PLANE_PROFILE") or DEFAULT_PROFILE
    path = Path(chosen) if chosen.endswith(".toml") or "/" in chosen else profiles_dir() / f"{chosen}.toml"
    where = str(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"profile {where}: {exc.strerror or exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"profile {where}: {exc}") from None
    for key, value in raw.items():  # a credential-shaped key is named as such before it is merely unknown
        _reject_secret(where, key, value, declared=key in _SCALARS)
    unknown = sorted(set(raw) - set(_SCALARS) - {"pools"})
    if unknown:
        raise ProfileError(f"{where}: unknown keys: {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for key, value in raw.items():
        if key != "pools":
            values[key] = _coerce(where, key, value, _SCALARS[key])
    pools = _pools(where, raw.get("pools", {}))
    _env_overrides(env, where, values, pools)
    if values.get("exec", "local") not in EXEC_MODES:
        raise ProfileError(f"{where}: exec must be one of {', '.join(EXEC_MODES)}, got {values.get('exec')!r}")
    images = Path(values.get("images", "images.json"))
    if not images.is_absolute():
        images = path.resolve().parent / images
    values["images"] = images
    if images.is_file():
        load_images(images)  # a committed file must be pinned; a file the release has not published yet is doctor's finding
    return PlaneProfile(name=path.stem, path=path, pools=pools, **values)


def _lookup(profile: PlaneProfile, dotted: str) -> str:
    head, _, rest = dotted.partition(".")
    if head == "images" and rest:
        images = profile.load_images()
        if rest not in images:
            raise ProfileError(f"{profile.images}: no image named {rest!r} (have {', '.join(sorted(images))})")
        return images[rest]
    if head == "pools":
        pool_name, _, key = rest.partition(".")
        if pool_name not in profile.pools or key not in _POOL_FIELDS:
            raise ProfileError(f"{profile.path}: no such pool field {dotted!r}")
        return str(getattr(profile.pools[pool_name], key))
    if head not in _SCALARS or rest:
        raise ProfileError(f"{profile.path}: no such field {dotted!r}")
    value = getattr(profile, head)
    return str(value).lower() if isinstance(value, bool) else str(value)


def main(argv: list[str] | None = None) -> int:
    """``python -m openultrasast.plane.profile [--profile NAME] --print FIELD [FIELD...]``: one value per line."""
    import argparse

    parser = argparse.ArgumentParser(prog="openultrasast.plane.profile", description=main.__doc__)
    parser.add_argument("--profile", help="profile name or path (default OUSAST_PLANE_PROFILE, else kind)")
    parser.add_argument("--print", dest="fields", nargs="+", required=True, metavar="FIELD")
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        for dotted in args.fields:
            print(_lookup(profile, dotted))
    except ProfileError as exc:
        print(f"profile: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
