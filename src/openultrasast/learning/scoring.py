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

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..findings import StaticFinding
from .families import FamilyTaxonomy

FamilyOutcome = Literal["pair_correct", "both_flagged", "both_silent", "reversed", "unscorable"]
# Families whose bug shape is the absence of a check on a reached handler: without the registration that
# makes the handler reachable, the pair says nothing either way, which is a corpus defect with its own name.
CONTEXT_DEPENDENT_FAMILIES = frozenset({"access_control"})
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
    slice: str = ""
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
    parse_ok: bool = True,
    entry_points: Sequence[str] | None = None,
) -> PairFamilyScore:
    """Score one pair for one family over K runs of the detector on each side."""
    name = str(getattr(case, "name", "?"))
    slice_name = str(getattr(case, "slice", "") or "")
    reason = unscorable_reason(case, parse_ok=parse_ok, ranges=ranges, entry_points=entry_points, family=family)
    if reason is not None:
        return PairFamilyScore(pair=name, family=family, slice=slice_name, runs=(), outcome="unscorable", unscorable_reason=reason)
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
        return PairFamilyScore(pair=name, family=family, slice=slice_name, runs=(), outcome="unscorable", unscorable_reason="no_runs")
    majority = Counter(outcomes).most_common(1)[0][0]
    return PairFamilyScore(
        pair=name,
        family=family,
        slice=slice_name,
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


def unscorable_reason(
    case: object,
    *,
    parse_ok: bool = True,
    ranges: FunctionRanges,
    entry_points: Sequence[str] | None = None,
    family: str = "",
) -> str | None:
    """Why this pair cannot be scored, or None. The reasons have different owners, so they must not be conflated.

    A maintainer-declared limit wins over anything computed. An unparsable side is a tooling gap
    (``unsupported_language``), a labeled function no parsed range names is a corpus labelling defect
    (``unresolved_label``), and a handler that arrived without the registration that makes it reachable is a
    harvest defect (``missing_context``), which only matters for families whose bug shape is a missing check.
    """
    declared = getattr(case, "unscorable", None)
    if declared:
        return str(declared)
    if not parse_ok:
        return "unsupported_language"
    if not _spans(case, ranges):
        return "unresolved_label"
    labeled_family = family or next(
        (str(getattr(row, "family", "") or "") for row in getattr(case, "expected", ()) or () if getattr(row, "family", None)), ""
    )
    if entry_points is not None and labeled_family in CONTEXT_DEPENDENT_FAMILIES:
        labeled = {str(getattr(row, "function", "") or "") for row in getattr(case, "expected", ()) or ()}
        if not (labeled & set(entry_points)):
            return "missing_context"
    return None


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


@dataclass(frozen=True)
class FamilyMetrics:
    """One family's numbers, with the denominator they were computed over and why rows fell out of it."""

    family: str
    taxonomy_version: str
    scorable: int
    unscorable: dict[str, int] = field(default_factory=dict)
    outcomes: dict[str, int] = field(default_factory=dict)
    recall: float = 0.0  # flagged the vulnerable side
    silence: float = 0.0  # said nothing on the fixed side
    youden: float = 0.0
    directional_bias: float = 0.0  # positive: flags both sides; negative: silent on both. Youden cannot tell them apart.
    leak_rate: float = 0.0
    fixed_fpr_recall: float = 0.0  # recall, forfeited entirely when the leak rate exceeds the ceiling
    negative_flips: int = 0  # pairs that were correct in the baseline and are not now
    positive_flips: int = 0
    p_value: float | None = None  # two-sided sign test over the discordant pairs
    reliable_change: bool = False
    hierarchical_credit: bool = False  # False: the taxonomy is flat, so no answer could earn partial credit (Req 3.7)

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "taxonomy_version": self.taxonomy_version,
            "scorable": self.scorable,
            "unscorable": dict(sorted(self.unscorable.items())),
            "outcomes": dict(sorted(self.outcomes.items())),
            "recall": self.recall,
            "silence": self.silence,
            "youden": self.youden,
            "directional_bias": self.directional_bias,
            "leak_rate": self.leak_rate,
            "fixed_fpr_recall": self.fixed_fpr_recall,
            "negative_flips": self.negative_flips,
            "positive_flips": self.positive_flips,
            "p_value": self.p_value,
            "reliable_change": self.reliable_change,
            "hierarchical_credit": self.hierarchical_credit,
        }


def aggregate(
    scores: Sequence[PairFamilyScore],
    *,
    taxonomy: FamilyTaxonomy,
    baseline: Sequence[PairFamilyScore] | None = None,
    fpr_ceiling: float = 0.1,
    per_slice: bool = False,
    alpha: float = 0.05,
) -> dict[str, FamilyMetrics]:
    """Group scores into per-family numbers. Unscorable rows are listed by reason and leave every denominator."""
    grouped: dict[str, list[PairFamilyScore]] = {}
    for score in scores:
        grouped.setdefault(f"{score.slice}/{score.family}" if per_slice else score.family, []).append(score)
    was_correct = {(item.slice if per_slice else "", item.family, item.pair): item.outcome for item in baseline or ()}
    out: dict[str, FamilyMetrics] = {}
    for key, group in sorted(grouped.items()):
        scorable = [item for item in group if item.outcome != "unscorable"]
        reasons: dict[str, int] = {}
        for item in group:
            if item.outcome == "unscorable":
                reason = item.unscorable_reason or "unknown"
                reasons[reason] = reasons.get(reason, 0) + 1
        counts = Counter(item.outcome for item in scorable)
        total = len(scorable)
        detected = counts["pair_correct"] + counts["both_flagged"]
        silent = counts["pair_correct"] + counts["both_silent"]
        leaks = counts["both_flagged"] + counts["reversed"]
        recall = detected / total if total else 0.0
        silence = silent / total if total else 0.0
        leak_rate = leaks / total if total else 0.0
        negative = positive = 0
        for item in scorable:
            before = was_correct.get((item.slice if per_slice else "", item.family, item.pair))
            if before is None or before == "unscorable":
                continue
            if before == "pair_correct" and item.outcome != "pair_correct":
                negative += 1
            elif before != "pair_correct" and item.outcome == "pair_correct":
                positive += 1
        p_value = sign_test(positive, negative) if baseline is not None else None
        out[key] = FamilyMetrics(
            family=group[0].family,
            taxonomy_version=taxonomy.version,
            scorable=total,
            unscorable=reasons,
            outcomes={name: count for name, count in sorted(counts.items())},
            recall=recall,
            silence=silence,
            youden=(recall + silence - 1.0) if total else 0.0,
            directional_bias=((counts["both_flagged"] - counts["both_silent"]) / total) if total else 0.0,
            leak_rate=leak_rate,
            fixed_fpr_recall=recall if leak_rate <= fpr_ceiling else 0.0,
            negative_flips=negative,
            positive_flips=positive,
            p_value=p_value,
            reliable_change=bool(p_value is not None and p_value < alpha and positive != negative),
            hierarchical_credit=taxonomy.hierarchical,
        )
    return out


def sign_test(better: int, worse: int) -> float:
    """Two-sided exact sign test over the pairs that changed. 1.0 when nothing changed, so noise never reads as progress."""
    total = better + worse
    if total == 0:
        return 1.0
    smaller = min(better, worse)
    tail = sum(math.comb(total, index) for index in range(smaller + 1)) / float(2**total)
    return float(min(1.0, 2.0 * tail))


__all__ = [
    "CONTEXT_DEPENDENT_FAMILIES",
    "FamilyMetrics",
    "FamilyOutcome",
    "FunctionRanges",
    "PairFamilyScore",
    "Rung",
    "aggregate",
    "score_pair_family",
    "sign_test",
    "unscorable_reason",
]
