"""The corpus calibrates the model, not an LLM vote (model-grounded-detection, Req 9).

This is the inversion the whole feature rests on. In the prior architecture a pair the detector missed was a
*detector* failure, to be averaged away over K runs and chased with a prompt change. Here the arbiter is
deterministic: it will miss that pair the same way every time, and the only thing that moves it is better
modelling. So a pair the model cannot split is a **named gap in the model**, recorded with its reason, and
the report's job is to make those gaps legible by family and by slice rather than to produce a score.

`covered` means the model reached a strictly higher rung on the vulnerable side than on its fix. Flagging
both sides equally is not coverage — it distinguishes nothing, which is exactly the failure the group-2
measurement found taint reachability making on every parameterised SQL pair.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TypedDict


class FamilyGaps(TypedDict):
    """Gaps for one family: how many pairs, and the tally of reasons behind them."""

    pairs: int
    reasons: dict[str, int]

# Ascending, matching `ladder.Rung`. A pair is split when the vulnerable side outranks its fix.
_ORDER = {"none": 0, "": 0, "suspicion": 0, "model_corroborated": 1, "model_entailed": 2, "execution_confirmed": 3}


@dataclass(frozen=True)
class PairOutcome:
    """What the model made of one vulnerable/fixed pair."""

    pair: str
    family: str
    slice: str
    vuln_rung: str
    fixed_rung: str
    reason: str = ""


@dataclass(frozen=True)
class ModelGap:
    """A pair the model could not split, and why. Not a miss to average — a gap to close."""

    pair: str
    family: str
    slice: str
    reason: str


@dataclass(frozen=True)
class HarvestRecipe:
    """Where a pair comes from. The fix commit's parent is the vulnerable side, by construction."""

    repo: str
    fix_commit: str
    relpath: str
    function: str = ""

    @property
    def parent_ref(self) -> str:
        return f"{self.fix_commit}^"


@dataclass(frozen=True)
class CalibrationReport:
    covered: tuple[str, ...]
    gaps: tuple[ModelGap, ...]
    per_slice: Mapping[str, Mapping[str, int]]
    per_family: Mapping[str, Mapping[str, int]] = field(default_factory=dict)

    def gaps_by_family(self) -> dict[str, FamilyGaps]:
        """Gaps grouped by family, each with a tally of the reasons behind them."""
        out: dict[str, FamilyGaps] = {}
        for gap in self.gaps:
            block = out.setdefault(gap.family, {"pairs": 0, "reasons": {}})
            block["pairs"] += 1
            block["reasons"][gap.reason] = block["reasons"].get(gap.reason, 0) + 1
        return out

    def to_markdown(self) -> str:
        """Per-slice rows first; there is no headline here that is not backed by them (Req 9.3, 11.1)."""
        lines = ["## Model calibration", "", "Coverage is a pair the model *splits*: a strictly higher rung on",
                 "the vulnerable side than on its fix. Everything else is a named gap.", "",
                 "| slice | pairs | covered | gaps | coverage |", "|---|---|---|---|---|"]
        for slice_name, block in sorted(self.per_slice.items()):
            pairs = block["pairs"] or 1
            lines.append(
                f"| {slice_name} | {block['pairs']} | {block['covered']} | {block['gaps']} | "
                f"{block['covered'] / pairs:.0%} |"
            )
        by_family = self.gaps_by_family()
        if by_family:
            lines += ["", "### Gaps by family", ""]
            for family, gaps in sorted(by_family.items()):
                detail = ", ".join(f"{k} x{v}" for k, v in sorted(gaps["reasons"].items()))
                lines.append(f"- `{family}`: {gaps['pairs']} pair(s) — {detail}")
        return "\n".join(lines) + "\n"


def calibrate(outcomes: Iterable[PairOutcome]) -> CalibrationReport:
    """Split the corpus into what the model covers and what it cannot, with reasons."""
    covered: list[str] = []
    gaps: list[ModelGap] = []
    per_slice: dict[str, dict[str, int]] = {}
    per_family: dict[str, dict[str, int]] = {}

    for outcome in outcomes:
        split = _ORDER.get(outcome.vuln_rung, 0) > _ORDER.get(outcome.fixed_rung, 0)
        for key, store in ((outcome.slice, per_slice), (outcome.family, per_family)):
            block = store.setdefault(key, {"pairs": 0, "covered": 0, "gaps": 0})
            block["pairs"] += 1
            block["covered" if split else "gaps"] += 1
        if split:
            covered.append(outcome.pair)
        else:
            gaps.append(ModelGap(pair=outcome.pair, family=outcome.family, slice=outcome.slice,
                                 reason=outcome.reason or _default_reason(outcome)))
    return CalibrationReport(
        covered=tuple(sorted(covered)),
        gaps=tuple(sorted(gaps, key=lambda g: (g.family, g.pair))),
        per_slice=per_slice,
        per_family=per_family,
    )


def _default_reason(outcome: PairOutcome) -> str:
    """Every gap carries a reason, even when the caller supplied none — a bare gap teaches nothing."""
    if _ORDER.get(outcome.vuln_rung, 0) == 0:
        return "no_verdict_on_the_vulnerable_side"
    if outcome.vuln_rung == outcome.fixed_rung:
        return f"both_sides_reached_{outcome.vuln_rung}: the model distinguished nothing"
    return "fixed_side_outranked_the_vulnerable_one"


def harvest_recipe(entry: Mapping[str, object]) -> HarvestRecipe:
    """A pair from CVE history: the fix commit and its parent, with the fix diff as the oracle (Req 9.4).

    Nothing here is hand-labelled. The recipe names where to fetch both sides; what makes the pair *true* is
    the fix diff itself, read by the model rather than annotated by us.
    """
    return HarvestRecipe(
        repo=str(entry.get("repo", "")),
        fix_commit=str(entry.get("fix_commit", "")),
        relpath=str(entry.get("relpath", "")),
        function=str(entry.get("function", "") or ""),
    )


def outcomes_from_rows(rows: Sequence[Mapping[str, object]]) -> list[PairOutcome]:
    """Adapt the ceiling artifact's rows, so calibration reads the measurement rather than re-running it."""
    return [
        PairOutcome(
            pair=str(row.get("pair", "")),
            family=str(row.get("family", "")),
            slice=str(row.get("slice", "")),
            vuln_rung=str(row.get("vuln_rung", "none")),
            fixed_rung=str(row.get("fixed_rung", "none")),
            reason=str(row.get("miss_cause", "") or ""),
        )
        for row in rows
    ]


__all__ = [
    "CalibrationReport",
    "HarvestRecipe",
    "ModelGap",
    "PairOutcome",
    "calibrate",
    "harvest_recipe",
    "outcomes_from_rows",
]
