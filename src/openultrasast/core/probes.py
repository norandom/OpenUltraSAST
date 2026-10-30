"""Anti-shortcut probes for fitted components (Req 8, 9).

A fitted prompt, threshold, or model must not separate a fix from its reversed fix
using shape features (diff size, deletion count, line counts): that is pool-specific
shortcut learning, the 2026-10-14 deletion-count 0.90 finding. A component making any
detection claim must also carry per-repository holdout evidence and a GO admission on
an untouched population.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


class ShortcutDetected(ValueError):
    """A component separates a fix from its reversed fix by its decision features."""


class FittedComponentBlocked(ValueError):
    """A fitted component claims detection without holdout + admission evidence."""


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one reversed-pair probe."""

    separated: bool
    fix_score: float
    reversed_score: float


def reversed_pair_probe(
    score_fn: Callable[[Mapping[str, Any]], float], fix_change: Mapping[str, Any], reversed_change: Mapping[str, Any]
) -> ProbeResult:
    """Score a fix and its reversed fix; separated=True means the features shortcut."""
    fix_score = float(score_fn(fix_change))
    reversed_score = float(score_fn(reversed_change))
    return ProbeResult(separated=fix_score != reversed_score, fix_score=fix_score, reversed_score=reversed_score)


def assert_no_shortcut(
    score_fn: Callable[[Mapping[str, Any]], float], fix_change: Mapping[str, Any], reversed_change: Mapping[str, Any]
) -> None:
    """Raise ShortcutDetected when the component separates fix from reversed fix."""
    result = reversed_pair_probe(score_fn, fix_change, reversed_change)
    if result.separated:
        raise ShortcutDetected(f"shape shortcut: fix={result.fix_score} vs reversed={result.reversed_score}")


def require_admission_evidence(*, holdout_passed: bool, admission_decision: str) -> None:
    """Block any fitted-component claim without holdout and an admission GO (Req 8.2)."""
    if not holdout_passed:
        raise FittedComponentBlocked("fitted component lacks per-repository holdout evidence")
    if admission_decision != "GO":
        raise FittedComponentBlocked(f"fitted component admission decision is {admission_decision!r}, not GO")


__all__ = [
    "FittedComponentBlocked",
    "ProbeResult",
    "ShortcutDetected",
    "assert_no_shortcut",
    "require_admission_evidence",
    "reversed_pair_probe",
]
