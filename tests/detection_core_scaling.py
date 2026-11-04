"""Deterministic work and isolated-memory scaling checks."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection_core_performance import PerformancePoint


@dataclass(frozen=True)
class _SlopeInterval:
    lower: Fraction
    upper: Fraction


def _work_units(point: PerformancePoint) -> int:
    return point.relation_count + point.observation_count + point.receipt_count + point.case_count


def _positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise AssertionError(f"incremental validation {name} requires exact positive integer values")
    return value


def _integer_median(values: tuple[int, ...]) -> int:
    ordered = tuple(sorted(values))
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) // 2


def _series(
    points: tuple[PerformancePoint, ...],
    sample_field: str,
    summary_field: str,
    name: str,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    samples = tuple(tuple(getattr(point, sample_field)) for point in points)
    if len({len(values) for values in samples}) != 1:
        raise AssertionError("incremental validation measurements require equal repeat counts")
    if any(len(values) < 2 for values in samples):
        raise AssertionError("incremental validation measurements require repeated positive integer samples")
    for values in samples:
        for value in values:
            _positive_integer(value, name)
    medians = tuple(_integer_median(values) for values in samples)
    summaries = tuple(_positive_integer(getattr(point, summary_field), name) for point in points)
    if medians != summaries:
        raise AssertionError(f"incremental validation {name} summary does not match repeated median")
    spreads = tuple(max(values) - min(values) for values in samples)
    return medians, spreads


def _slope_intervals(
    units: tuple[int, ...],
    medians: tuple[int, ...],
    spreads: tuple[int, ...],
) -> tuple[_SlopeInterval, ...]:
    result = []
    pairs = zip(units[:-1], units[1:], medians[:-1], medians[1:], spreads[:-1], spreads[1:], strict=True)
    for old_units, new_units, old_value, new_value, old_spread, new_spread in pairs:
        width = new_units - old_units
        increment = new_value - old_value
        uncertainty = Fraction(old_spread + new_spread, 2)
        lower = (increment - uncertainty) / width
        upper = (increment + uncertainty) / width
        result.append(_SlopeInterval(lower, upper))
    return tuple(result)


def _assert_memory(points: tuple[PerformancePoint, ...], units: tuple[int, ...]) -> None:
    medians, spreads = _series(points, "peak_samples_bytes", "peak_bytes", "memory")
    for median, spread in zip(medians, spreads, strict=True):
        if spread > max(1_024, median // 10):
            raise AssertionError("incremental validation memory is obscured by point-local variability")
    increments = tuple(new - old for old, new in zip(medians[:-1], medians[1:], strict=True))
    if any(increment <= 0 for increment in increments):
        raise AssertionError("incremental validation memory requires monotonic measured peaks")
    slopes = _slope_intervals(units, medians, spreads)
    for previous, current in zip(slopes[:-1], slopes[1:], strict=True):
        if current.lower > previous.upper * Fraction(51, 50):
            raise AssertionError(
                f"incremental validation memory slope increased beyond point-local uncertainty: {current.lower}>{previous.upper}"
            )


def _assert_work(points: tuple[PerformancePoint, ...]) -> None:
    pairs = (
        ("canonical_relations", "relation_count"),
        ("validated_relations", "relation_count"),
        ("canonical_observations", "observation_count"),
        ("validated_observations", "observation_count"),
        ("readiness_receipts", "receipt_count"),
        ("admission_cases", "case_count"),
    )
    for point in points:
        expected_total = 0
        for work_field, point_field in pairs:
            measured = _positive_integer(getattr(point.work, work_field), "work")
            expected = _positive_integer(getattr(point, point_field), "work")
            if measured != expected:
                raise AssertionError(f"incremental validation work missed {work_field}: {measured}!={expected}")
            expected_total += expected
        total = _positive_integer(point.work.total_operations, "work")
        if total != expected_total:
            raise AssertionError(f"incremental validation work total disagrees: {total}!={expected_total}")


def assert_incremental_envelope(points: tuple[PerformancePoint, ...]) -> None:
    units = tuple(_work_units(point) for point in points)
    dimensions = tuple(
        tuple(getattr(point, field) for point in points) for field in ("relation_count", "observation_count", "receipt_count", "case_count")
    )
    increasing = all(all(new > old for old, new in zip(values[:-1], values[1:], strict=True)) for values in dimensions)
    if len(units) < 3 or not increasing:
        raise AssertionError("incremental validation requires increasing workload points")
    _series(points, "elapsed_samples_ns", "elapsed_ns", "elapsed")
    _assert_work(points)
    _assert_memory(points, units)


__all__ = ["assert_incremental_envelope"]
