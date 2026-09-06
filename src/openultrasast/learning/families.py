"""The closed family taxonomy (learning-harness, Req 1).

Ten families, loaded from ``ruleset/families.toml``. A family is the only key that routes work and
scores a pair: CWE ids and mechanism ids are attributes reached *through* a family, so no caller may
group by them. Every family names what can verify a claim in it (a sandbox canary, static
corroboration, or nothing), which is what keeps reporting honest one layer up. An unknown field, a
family outside the closed set, a missing verifier kind or a CWE claimed twice is a data bug and fails
loud, naming the offender.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

FAMILY_IDS = (
    "injection",
    "path",
    "deserialization",
    "access_control",
    "output_encoding",
    "untrusted_destination",
    "prototype",
    "config_secrets",
    "memory",
    "unknown",
)
VERIFIER_KINDS = ("canary", "static", "none")
Relation = Literal["same", "parent_child", "lateral", "fabricated"]
DEFAULT_FAMILIES_PATH = Path(__file__).resolve().parents[1] / "ruleset" / "families.toml"

_FAMILY_FIELDS = frozenset({"id", "description", "cwes", "mechanisms", "verifier", "parent"})
_TOP_FIELDS = frozenset({"version", "family"})


class FamiliesError(ValueError):
    """Raised when the taxonomy file names a family, field, verifier or CWE outside the closed sets."""


@dataclass(frozen=True)
class Family:
    id: str  # FAMILY_IDS
    description: str
    cwes: frozenset[str]
    mechanisms: frozenset[str]
    verifier: str  # VERIFIER_KINDS
    parent: str | None = None  # a family this one specializes; partial credit when one side is the other's parent


@dataclass(frozen=True)
class FamilyTaxonomy:
    version: str
    families: tuple[Family, ...]

    def by_id(self, family_id: str) -> Family:
        for family in self.families:
            if family.id == family_id:
                return family
        raise FamiliesError(f"unknown family {family_id!r}; expected one of {', '.join(f.id for f in self.families)}")

    def family_of_cwe(self, cwe: str) -> Family | None:
        """The family that claims this CWE, or None when nobody has placed it yet (a data gap, not `unknown`)."""
        token = cwe.strip().upper()
        return next((family for family in self.families if token in family.cwes), None)

    def family_of_mechanism(self, mechanism: str) -> Family | None:
        return next((family for family in self.families if mechanism in family.mechanisms), None)

    def related(self, left: str, right: str) -> Relation:
        """How two family answers relate. Abstention is not partial credit: ``unknown`` against a real
        family is ``lateral``, never ``parent_child``."""
        known = {family.id: family for family in self.families}
        if left not in known or right not in known:
            return "fabricated"
        if left == right:
            return "same"
        if known[left].parent == right or known[right].parent == left:
            return "parent_child"
        return "lateral"


def load_families(path: Path | None = None, *, require_all: bool = True) -> FamilyTaxonomy:
    """Load the taxonomy. ``require_all`` demands the full closed set in order (the shipped file);
    a scoped fixture may declare a subset, but never a family outside ``FAMILY_IDS``."""
    source = path if path is not None else DEFAULT_FAMILIES_PATH
    try:
        payload = tomllib.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FamiliesError(f"families file unreadable: {source}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise FamiliesError(f"families file is not valid TOML: {source}: {exc}") from exc
    unknown_top = sorted(set(payload) - _TOP_FIELDS)
    if unknown_top:
        raise FamiliesError(f"{source}: unknown top-level field(s) {', '.join(unknown_top)}")
    version = str(payload.get("version", "")).strip()
    if not version:
        raise FamiliesError(f"{source}: version is required")
    families: list[Family] = []
    claimed: dict[str, str] = {}
    for entry in payload.get("family", []):
        if not isinstance(entry, dict):
            raise FamiliesError(f"{source}: every [[family]] entry must be a table")
        family = _family(source, entry)
        if any(existing.id == family.id for existing in families):
            raise FamiliesError(f"{source}: family {family.id!r} declared twice")
        for cwe in sorted(family.cwes):
            if cwe in claimed:
                raise FamiliesError(f"{source}: {cwe} is claimed by both {claimed[cwe]!r} and {family.id!r}")
            claimed[cwe] = family.id
        families.append(family)
    _check_parents(source, families)
    if require_all and tuple(family.id for family in families) != FAMILY_IDS:
        raise FamiliesError(f"{source}: expected exactly {', '.join(FAMILY_IDS)} in that order, got {', '.join(f.id for f in families)}")
    if not families:
        raise FamiliesError(f"{source}: no families declared")
    return FamilyTaxonomy(version=version, families=tuple(families))


def _family(source: Path, entry: dict[str, object]) -> Family:
    unknown_fields = sorted(set(entry) - _FAMILY_FIELDS)
    if unknown_fields:
        raise FamiliesError(f"{source}: family {entry.get('id')!r} has unknown field(s) {', '.join(unknown_fields)}")
    family_id = str(entry.get("id", "")).strip()
    if family_id not in FAMILY_IDS:
        raise FamiliesError(f"{source}: unknown family {family_id!r}; expected one of {', '.join(FAMILY_IDS)}")
    verifier = str(entry.get("verifier", "")).strip()
    if verifier not in VERIFIER_KINDS:
        raise FamiliesError(f"{source}: family {family_id!r} has verifier {verifier!r}; expected one of {', '.join(VERIFIER_KINDS)}")
    description = str(entry.get("description", "")).strip()
    if not description:
        raise FamiliesError(f"{source}: family {family_id!r} needs a description")
    cwes = _tokens(source, family_id, entry.get("cwes", ()), "cwes", upper=True)
    mechanisms = _tokens(source, family_id, entry.get("mechanisms", ()), "mechanisms")
    parent = entry.get("parent")
    return Family(
        id=family_id,
        description=description,
        cwes=frozenset(cwes),
        mechanisms=frozenset(mechanisms),
        verifier=verifier,
        parent=str(parent) if parent else None,
    )


def _tokens(source: Path, family_id: str, value: object, field: str, *, upper: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise FamiliesError(f"{source}: family {family_id!r} field {field} must be a list of strings")
    tokens = [item.strip().upper() if upper else item.strip() for item in value]
    duplicates = sorted({token for token in tokens if tokens.count(token) > 1})
    if duplicates:
        raise FamiliesError(f"{source}: family {family_id!r} lists {', '.join(duplicates)} twice in {field}")
    return tokens


def _check_parents(source: Path, families: list[Family]) -> None:
    ids = {family.id for family in families}
    for family in families:
        if family.parent is None:
            continue
        if family.parent not in ids:
            raise FamiliesError(f"{source}: family {family.id!r} declares unknown parent {family.parent!r}")
        if family.parent == family.id:
            raise FamiliesError(f"{source}: family {family.id!r} is its own parent")


__all__ = [
    "DEFAULT_FAMILIES_PATH",
    "FAMILY_IDS",
    "VERIFIER_KINDS",
    "FamiliesError",
    "Family",
    "FamilyTaxonomy",
    "Relation",
    "load_families",
]
