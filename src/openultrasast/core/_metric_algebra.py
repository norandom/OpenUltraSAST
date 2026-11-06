"""Version-neutral arithmetic for the closed standard metric set."""

from __future__ import annotations

import math

_WILSON_Z_95 = 1.959963984540054
_STANDARD_METRIC_ALGEBRA = {
    "paired_correctness": ("correct_pairs", "pairs", "at_least"),
    "vulnerable_recall": ("vulnerable_violation_cases", "vulnerable_sides", "at_least"),
    "fixed_false_alarm_rate": ("fixed_defect_cases", "fixed_sides", "at_most"),
    "ordinary_false_alarms_per_100": ("ordinary_defect_cases", "ordinary_cases", "at_most"),
    "precision": ("true_defect_cases", "all_defect_cases", "at_least"),
    "semantic_stage_coverage": ("sites_recognized", "sites_considered", "at_least"),
    "model_success_rate": ("successful_model_calls", "model_calls", "at_least"),
}


def metric_algebra(metric_id: str) -> tuple[str, str, str]:
    """Return numerator, denominator, and comparator identities for one metric."""
    try:
        return _STANDARD_METRIC_ALGEBRA[metric_id]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown standard metric identity") from exc


def _wilson_95(numerator: int, denominator: int) -> tuple[float, float]:
    proportion = numerator / denominator
    z_squared = _WILSON_Z_95 * _WILSON_Z_95
    denominator_term = 1.0 + z_squared / denominator
    center = (proportion + z_squared / (2.0 * denominator)) / denominator_term
    margin = (_WILSON_Z_95 / denominator_term) * math.sqrt(
        proportion * (1.0 - proportion) / denominator + z_squared / (4.0 * denominator * denominator)
    )
    return center - margin, center + margin


def metric_values(
    metric_id: str,
    numerator: int,
    denominator: int,
) -> tuple[float | None, float | None, float | None]:
    """Derive the value and Wilson interval for one closed standard metric."""
    metric_algebra(metric_id)
    if denominator == 0:
        return None, None, None
    lower, upper = _wilson_95(numerator, denominator)
    scale = 100.0 if metric_id == "ordinary_false_alarms_per_100" else 1.0
    return (numerator / denominator) * scale, lower * scale, upper * scale


__all__ = ["metric_algebra", "metric_values"]
