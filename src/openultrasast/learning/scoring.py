"""Class-aware, pair-wise scoring (learning-harness, Req 3, 4.1, 4.5).

A pair is scored once per family. Detection means a finding whose family tag relates to the labeled
family, sitting inside the labeled function; the words in a finding are never read, because a text
token was exactly the proxy that made the old hunter number meaningless. Silence means no such finding
on the fixed side: findings of other families and findings outside the labeled function are counted
separately and are never called leaks. A pair that cannot be scored keeps its reason and is never run.

Every evaluation runs a pair K times, because a single run misses most real changes. The recorded
outcome is the majority of the runs, and the runs that disagree with it are the pair's own flakiness.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ..findings import StaticFinding
from .families import FamilyTaxonomy

FamilyOutcome = Literal["pair_correct", "both_flagged", "both_silent", "reversed", "unscorable"]
Rung = Literal["suspicion", "static_corroboration", "proven"]
_RUNGS: tuple[Rung, ...] = ("suspicion", "static_corroboration", "proven")
FunctionRanges = Mapping[str, Sequence[tuple[str, int, int]]]


@dataclass(frozen=True)
class PairFamilyScore:
    """What one pair says about one family."""

    pair: str
    family: str
    runs: tuple[FamilyOutcome, ...]
    outcome: FamilyOutcome
    other_findings_vuln: int = 0  # right place, another family: not a detection, never a leak
    other_findings_fixed: int = 0
    fabricated_vuln: int = 0  # a family id outside the taxonomy: noise, and worth naming
    fabricated_fixed: int = 0
    flips: int = 0  # runs that disagreed with the majority
    rung: Rung = "suspicion"
    unscorable_reason: str | None = None


def score_pair_family(
    case: object,
    family: str,
    vuln_runs: Sequence[Sequence[StaticFinding]],
    fixed_runs: Sequence[Sequence[StaticFinding]],
    *,
    ranges: FunctionRanges,
    taxonomy: FamilyTaxonomy,
) -> PairFamilyScore:
    """Score one pair for one family over K runs of the detector on each side."""
    name = str(getattr(case, "name", "?"))
    reason = _unscorable(case, ranges)
    if reason is not None:
        return PairFamilyScore(pair=name, family=family, runs=(), outcome="unscorable", unscorable_reason=reason)
    spans = _spans(case, ranges)
    outcomes: list[FamilyOutcome] = []
    other_vuln = other_fixed = fabricated_vuln = fabricated_fixed = 0
    rung: Rung = "suspicion"
    for index in range(max(len(vuln_runs), len(fixed_runs))):
        vuln = list(vuln_runs[index]) if index < len(vuln_runs) else []
        fixed = list(fixed_runs[index]) if index < len(fixed_runs) else []
        hits_vuln = _hits(vuln, family, spans, taxonomy)
        hits_fixed = _hits(fixed, family, spans, taxonomy)
        other_vuln += _others(vuln, family, spans, taxonomy)
        other_fixed += _others(fixed, family, spans, taxonomy)
        fabricated_vuln += _fabricated(vuln, taxonomy)
        fabricated_fixed += _fabricated(fixed, taxonomy)
        rung = _best_rung(rung, hits_vuln)
        outcomes.append(_outcome(bool(hits_vuln), bool(hits_fixed)))
    if not outcomes:
        return PairFamilyScore(pair=name, family=family, runs=(), outcome="unscorable", unscorable_reason="no_runs")
    majority = Counter(outcomes).most_common(1)[0][0]
    return PairFamilyScore(
        pair=name,
        family=family,
        runs=tuple(outcomes),
        outcome=majority,
        other_findings_vuln=other_vuln,
        other_findings_fixed=other_fixed,
        fabricated_vuln=fabricated_vuln,
        fabricated_fixed=fabricated_fixed,
        flips=sum(1 for item in outcomes if item != majority),
        rung=rung,
    )


def _outcome(detected: bool, leaked: bool) -> FamilyOutcome:
    if detected and not leaked:
        return "pair_correct"
    if detected and leaked:
        return "both_flagged"
    return "reversed" if leaked else "both_silent"


def _unscorable(case: object, ranges: FunctionRanges) -> str | None:
    declared = getattr(case, "unscorable", None)
    if declared:
        return str(declared)
    return None if _spans(case, ranges) else "unresolved_label"


def _spans(case: object, ranges: FunctionRanges) -> tuple[tuple[str, int, int], ...]:
    """The (path, start, end) spans of the labeled functions, from the parsed vulnerable side."""
    wanted = {str(getattr(row, "function", "") or "") for row in getattr(case, "expected", ()) or ()}
    wanted.discard("")
    found: list[tuple[str, int, int]] = []
    for path, entries in ranges.items():
        for name, start, end in entries:
            if name in wanted:
                found.append((path, start, end))
    return tuple(found)


def _inside(finding: StaticFinding, spans: Sequence[tuple[str, int, int]]) -> bool:
    return finding.line is not None and any(path == finding.path and start <= finding.line <= end for path, start, end in spans)


def _families_of(finding: StaticFinding) -> tuple[str, ...]:
    return tuple(tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("family:"))


def _relation(finding: StaticFinding, family: str, taxonomy: FamilyTaxonomy) -> str:
    relations = [taxonomy.related(family, candidate) for candidate in _families_of(finding)]
    for wanted in ("same", "parent_child", "lateral"):
        if wanted in relations:
            return wanted
    return "fabricated" if relations else "none"


def _hits(
    findings: Sequence[StaticFinding], family: str, spans: Sequence[tuple[str, int, int]], taxonomy: FamilyTaxonomy
) -> list[StaticFinding]:
    return [finding for finding in findings if _inside(finding, spans) and _relation(finding, family, taxonomy) in {"same", "parent_child"}]


def _others(findings: Sequence[StaticFinding], family: str, spans: Sequence[tuple[str, int, int]], taxonomy: FamilyTaxonomy) -> int:
    return sum(1 for finding in findings if _relation(finding, family, taxonomy) == "lateral" or not _inside(finding, spans))


def _fabricated(findings: Sequence[StaticFinding], taxonomy: FamilyTaxonomy) -> int:
    known = {item.id for item in taxonomy.families}
    return sum(1 for finding in findings if any(candidate not in known for candidate in _families_of(finding)))


def _best_rung(current: Rung, hits: Sequence[StaticFinding]) -> Rung:
    best = current
    for finding in hits:
        for tag in finding.tags:
            if tag.startswith("verifier:"):
                candidate = tag.split(":", 1)[1]
                if candidate in _RUNGS and _RUNGS.index(candidate) > _RUNGS.index(best):  # type: ignore[arg-type]
                    best = candidate  # type: ignore[assignment]
    return best


__all__ = ["FamilyOutcome", "FunctionRanges", "PairFamilyScore", "Rung", "score_pair_family"]
