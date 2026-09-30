"""Framework and library priors (learned-decision-engine Req 8.2, design section 2).

``frameworks.toml`` lists the framework and library ids a ruleset entry may be tagged with, each with a lexicon of
symbols. A tagged entry (``framework = "<id>"`` or ``library = "<id>"`` on a ``semantic/*.toml`` source, sink,
sanitizer or dispatch, or on a quick ``[[rule]]``) is a *prior*: the loaders keep it or drop it by ``priors``:

- ``"all"``: every entry (today's scan: the default of every loader, so output is unchanged);
- ``"off"``: language-level entries only (the decision engine's default);
- a set of ids: language-level entries plus those priors.

The lexicon is for the lint test and repository stratification, never for detection.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Literal

DEFAULT_FRAMEWORKS_PATH = Path(__file__).resolve().parent / "frameworks.toml"
KINDS = ("framework", "library")
Priors = Literal["off", "all"] | frozenset[str]


class FrameworksError(ValueError):
    """``frameworks.toml`` or a tag is malformed, or names an id the file does not list."""


@dataclass(frozen=True)
class Framework:
    id: str
    kind: str  # KINDS
    languages: tuple[str, ...]
    packages: tuple[str, ...]
    symbols: tuple[str, ...]
    markers: tuple[str, ...] = ()


def _strings(value: object, field: str, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise FrameworksError(f"{where}: {field} must be a list of non-empty strings")
    return tuple(value)


@cache
def load_frameworks(path: Path = DEFAULT_FRAMEWORKS_PATH) -> tuple[Framework, ...]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    rows: list[Framework] = []
    for item in data.get("framework", []):
        where = f"{path} framework {item.get('id')!r}"
        if not isinstance(item.get("id"), str) or item.get("kind") not in KINDS:
            raise FrameworksError(f"{where}: needs an id and a kind in {KINDS}")
        extra = set(item) - {"id", "kind", "languages", "packages", "symbols", "markers"}
        if extra:
            raise FrameworksError(f"{where}: unknown fields {sorted(extra)}")
        rows.append(
            Framework(
                id=item["id"], kind=item["kind"], languages=_strings(item.get("languages"), "languages", where),
                packages=_strings(item.get("packages", []), "packages", where), symbols=_strings(item.get("symbols"), "symbols", where),
                markers=_strings(item.get("markers", []), "markers", where),
            )
        )  # fmt: skip
    ids = [row.id for row in rows]
    if len(ids) != len(set(ids)):
        raise FrameworksError(f"{path}: an id is listed twice")
    return tuple(rows)


def framework_ids() -> frozenset[str]:
    return frozenset(row.id for row in load_frameworks())


def normalize_priors(priors: Priors | Iterable[str]) -> Priors:
    """``"all"``, ``"off"`` or a frozenset of known ids; an unknown id is refused, never silently ignored."""
    if priors in ("all", "off"):
        return priors  # type: ignore[return-value]
    if isinstance(priors, str):
        raise FrameworksError(f"priors must be 'all', 'off' or a set of framework ids, got {priors!r}")
    chosen = frozenset(priors)
    unknown = sorted(chosen - framework_ids())
    if unknown:
        raise FrameworksError(f"unknown priors {unknown} (frameworks.toml lists {sorted(framework_ids())})")
    return chosen


def tag_of(item: object) -> str | None:
    """The framework or library id an entry is tagged with, or None for a language-level entry."""
    return getattr(item, "framework", None) or getattr(item, "library", None)


def kept(tag: str | None, priors: Priors) -> bool:
    """Whether an entry with ``tag`` survives ``priors``: language-level entries always do."""
    if tag is None or priors == "all":
        return True
    if priors == "off":
        return False
    return tag in priors


def read_tag(item: dict[str, object], where: str) -> tuple[str | None, str | None]:
    """(framework, library) of a TOML entry, checked: at most one, and a listed id of the matching kind."""
    framework, library = item.get("framework"), item.get("library")
    if framework is not None and library is not None:
        raise FrameworksError(f"{where}: tagged both framework and library; one tag covers a whole entry")
    for value, kind in ((framework, "framework"), (library, "library")):
        if value is None:
            continue
        rows = {row.id: row for row in load_frameworks()}
        if not isinstance(value, str) or value not in rows or rows[value].kind != kind:
            raise FrameworksError(f"{where}: {kind} = {value!r} is not a {kind} id of frameworks.toml")
    return (framework if isinstance(framework, str) else None), (library if isinstance(library, str) else None)


def symbol_in(symbol: str, text: str) -> bool:
    """The lexicon's match rule: ``symbol`` as a whole token of ``text``."""
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])", text) is not None


__all__ = [
    "DEFAULT_FRAMEWORKS_PATH", "Framework", "FrameworksError", "Priors", "framework_ids", "kept", "load_frameworks",
    "normalize_priors", "read_tag", "symbol_in", "tag_of",
]  # fmt: skip
