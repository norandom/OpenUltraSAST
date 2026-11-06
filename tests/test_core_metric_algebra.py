"""Version-neutral tests for the closed standard-metric arithmetic."""

from __future__ import annotations

import pytest

from openultrasast.core._metric_algebra import metric_algebra, metric_values

EXPECTED_ALGEBRA = {
    "paired_correctness": ("correct_pairs", "pairs", "at_least"),
    "vulnerable_recall": ("vulnerable_violation_cases", "vulnerable_sides", "at_least"),
    "fixed_false_alarm_rate": ("fixed_defect_cases", "fixed_sides", "at_most"),
    "ordinary_false_alarms_per_100": ("ordinary_defect_cases", "ordinary_cases", "at_most"),
    "precision": ("true_defect_cases", "all_defect_cases", "at_least"),
    "semantic_stage_coverage": ("sites_recognized", "sites_considered", "at_least"),
    "model_success_rate": ("successful_model_calls", "model_calls", "at_least"),
}


@pytest.mark.parametrize(("metric_id", "expected"), EXPECTED_ALGEBRA.items())
def test_closed_metric_algebra_uses_version_neutral_identities(
    metric_id: str,
    expected: tuple[str, str, str],
) -> None:
    assert metric_algebra(metric_id) == expected


def test_metric_algebra_rejects_an_identity_outside_the_closed_set() -> None:
    with pytest.raises(ValueError, match="unknown standard metric identity"):
        metric_algebra("future_metric")
    with pytest.raises(ValueError, match="unknown standard metric identity"):
        metric_values("future_metric", 1, 1)


def test_wilson_values_preserve_the_frozen_v2_operation_order() -> None:
    recall = metric_values("vulnerable_recall", 8, 10)
    ordinary = metric_values("ordinary_false_alarms_per_100", 2, 40)

    assert tuple(value.hex() for value in recall if value is not None) == (
        "0x1.999999999999ap-1",
        "0x1.f5ed26a3e7d75p-2",
        "0x1.e2fa8e9a791bcp-1",
    )
    assert tuple(value.hex() for value in ordinary if value is not None) == (
        "0x1.4000000000000p+2",
        "0x1.61cf20333d76dp+0",
        "0x1.080fe1b75a7abp+4",
    )


@pytest.mark.parametrize("metric_id", EXPECTED_ALGEBRA)
def test_zero_denominator_has_no_derived_values(metric_id: str) -> None:
    assert metric_values(metric_id, 0, 0) == (None, None, None)
