"""Measured budget contract for the detection core (Req 4).

The per-change time budget is derived from measurement, never a static constant:
every analyzed change records its complexity and reply time, and each workload
class gets a budget computed as a percentile of its measured samples with the
sample count, percentile, and reference hardware disclosed (Req 12 schema).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Complexity:
    """Measured change complexity recorded per change (Req 4.1)."""

    regions: int
    calls: int
    changed_bytes: int


@dataclass(frozen=True)
class Budget:
    """A derived per-class budget with its published derivation."""

    workload_class: str
    seconds: float
    n: int
    percentile: float
    hardware: str

    def describe(self) -> str:
        """The derivation string gate failures must name (Req 4.3)."""
        return f"class={self.workload_class} n={self.n} p{int(self.percentile * 100)} hardware={self.hardware} budget={self.seconds:g}s"


class BudgetGateFailure(ValueError):
    """A change exceeded its class's measured budget."""


def _quantile(sorted_values: Sequence[float], percentile: float) -> float:
    """Linear-interpolated quantile (numpy 'linear' convention)."""
    position = percentile * (len(sorted_values) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def derive_budget(
    samples: Sequence[tuple[Complexity, float]],
    *,
    workload_class: str,
    percentile: float,
    hardware: str,
) -> Budget:
    """Derive a class budget as a percentile of measured (complexity, seconds) samples."""
    if not samples:
        raise ValueError("budget derivation needs at least one measured sample")
    if not 0.0 < percentile < 1.0:
        raise ValueError(f"percentile {percentile} outside (0, 1)")
    seconds = sorted(float(value) for _, value in samples)
    return Budget(
        workload_class=workload_class,
        seconds=_quantile(seconds, percentile),
        n=len(samples),
        percentile=percentile,
        hardware=hardware,
    )


def check_budget(change_id: str, seconds: float, budget: Budget) -> None:
    """Fail the gate naming the change, the elapsed time, and the derivation (Req 4.3)."""
    if seconds > budget.seconds:
        raise BudgetGateFailure(f"budget:{change_id}:{seconds:g}s>{budget.seconds:g}s ({budget.describe()})")


__all__ = ["Budget", "BudgetGateFailure", "Complexity", "check_budget", "derive_budget"]
