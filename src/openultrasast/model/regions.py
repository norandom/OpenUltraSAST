"""Where to look, and what to look for there (contributor-scan, Req 2).

Pair scoring could rely on a labelled function: the corpus declares which function carries the bug and which
family it belongs to. A contributor has neither — *which code is risky* is the question they are asking. So a
repository scan derives its regions from the code itself: entry points where the mapper found them, whole
files where it did not, and each region carries only the families its shape and language actually admit.

Two restraints are deliberate:

* **The rank comes from what ``EntryPointRecord`` already carries**, not from a new signal invented here. The
  mapper has already decided whether a handler is public or local-only and whether it sits at a trust
  boundary; a second opinion computed from the same evidence would be a way of disagreeing with ourselves.
* **A family is offered only where its arbiter could answer.** An obligation needs a reachable operation, so
  ``access_control`` is offered where there is a handler and withheld from a library file that has none.
  Asking every family of every region is the unbounded version of this, and at repository scale the budget is
  the thing being spent.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .specs import config_specs, dominance_specs, taint_specs

# From `mapping.AccessLevel`. A publicly reachable handler at a trust boundary is where a missing check costs
# most, so it is looked at first when the budget is finite.
_ACCESS_RANK: dict[str, float] = {
    "public": 1.0,
    "authenticated": 0.8,
    "role-restricted": 0.6,
    "contract-only/callback": 0.4,
    "review-required": 0.3,
    "local-only": 0.2,
}

# Languages whose facts the model layer carries. Anything else yields no region rather than an empty scan
# that looks like a clean bill of health.
_LANGUAGES = {"python", "javascript", "typescript", "java", "c", "c_cpp"}
_NORMALISE = {"typescript": "javascript", "c_cpp": "c"}


@dataclass(frozen=True)
class ScanRegion:
    """A place to arbitrate, and the families worth arbitrating there."""

    path: str
    function: str | None  # None for a file-level fallback: there is no labelled function on a scan path
    language: str
    families: tuple[str, ...]
    rank: float
    source: str  # "entry_point" | "file_fallback"


def regions_for(entries: Sequence[object], targets: Sequence[object]) -> tuple[ScanRegion, ...]:
    """Regions for a repository, strongest first.

    A file with an entry point yields regions for its handlers only — a fallback region beside them would
    scan the same code twice and spend the budget on duplicates.
    """
    by_path: dict[str, str] = {}
    for target in targets:
        language = _language_of(target)
        if language:
            by_path[str(getattr(target, "path", ""))] = language

    regions: list[ScanRegion] = []
    covered: set[str] = set()
    for entry in entries:
        path = str(getattr(entry, "path", ""))
        language = by_path.get(path)
        if language is None:
            continue
        families = _families(language, has_handler=True)
        if not families:
            continue
        covered.add(path)
        regions.append(
            ScanRegion(
                path=path,
                function=(getattr(entry, "function_name", None) or None),
                language=language,
                families=families,
                rank=_ACCESS_RANK.get(str(getattr(entry, "access_level", "")), 0.5),
                source="entry_point",
            )
        )

    for path, language in by_path.items():
        if path in covered:
            continue
        families = _families(language, has_handler=False)
        if not families:
            continue
        regions.append(ScanRegion(path=path, function=None, language=language, families=families, rank=0.1, source="file_fallback"))

    # A total order: rank descending, then path and function, so two runs of one repository agree.
    return tuple(sorted(regions, key=lambda r: (-r.rank, r.path, r.function or "")))


def _language_of(target: object) -> str | None:
    language = str(getattr(target, "language", "") or "")
    if language not in _LANGUAGES:
        return None
    return _NORMALISE.get(language, language)


def _families(language: str, *, has_handler: bool) -> tuple[str, ...]:
    """The families this language has facts for, minus those whose arbiter needs a handler and has none."""
    families = set(taint_specs(language=language))
    families |= set(config_specs(language=language))
    if has_handler:
        families |= set(dominance_specs(language=language))
    return tuple(sorted(families))
