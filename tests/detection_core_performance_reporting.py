"""Measurement artifact and budget composition for detection-core load tests."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import replace
from typing import TYPE_CHECKING

from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import budget, canonical

if TYPE_CHECKING:
    from detection_core_performance import ConsumerMeasurement, PerformancePoint, Workload

_SAMPLE_SCHEMA = "detection-core-performance-samples-v1"


def nanoseconds_to_milliseconds(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("elapsed nanoseconds must be an exact positive integer")
    return (value + 999_999) // 1_000_000


def hardware() -> budget.ReferenceHardware:
    pages = os.sysconf("SC_PHYS_PAGES")
    page_size = os.sysconf("SC_PAGE_SIZE")
    value = budget.ReferenceHardware(
        platform.processor() or platform.machine() or "unreported-cpu",
        os.cpu_count() or 1,
        int(pages * page_size),
        platform.platform(),
        sys.version.split()[0],
        "",
    )
    return replace(value, record_digest=budget.derive_reference_hardware_digest(value))


def sample_report(
    workload: Workload,
    points: tuple[PerformancePoint, ...],
    consumers: tuple[ConsumerMeasurement, ...],
) -> bytes:
    return canonical.canonical_bytes(
        {
            "schema_version": _SAMPLE_SCHEMA,
            "workload_class": workload.workload_class,
            "workload_input_digest": workload.content_digest,
            "repeats": workload.repeats,
            "points": tuple(_point_value(point) for point in points),
            "consumer_samples": tuple(_consumer_value(item) for item in consumers),
        }
    )


def _point_value(point: PerformancePoint) -> dict[str, canonical.JsonValue]:
    return {
        "relations": point.relation_count,
        "observations": point.observation_count,
        "receipts": point.receipt_count,
        "cases": point.case_count,
        "work": {
            "canonical_relations": point.work.canonical_relations,
            "canonical_observations": point.work.canonical_observations,
            "validated_relations": point.work.validated_relations,
            "validated_observations": point.work.validated_observations,
            "readiness_receipts": point.work.readiness_receipts,
            "admission_cases": point.work.admission_cases,
            "total_operations": point.work.total_operations,
        },
        "elapsed_samples_ns": point.elapsed_samples_ns,
        "peak_samples_bytes": point.peak_samples_bytes,
        "serialized_bytes": point.serialized_bytes,
        "change_digest": point.change_digest,
        "changed_bytes": point.changed_bytes,
    }


def _consumer_value(item: ConsumerMeasurement) -> dict[str, canonical.JsonValue]:
    return {
        "mode": item.mode,
        "size": item.size,
        "change_id": item.measured.complexity.change_id,
        "changed_regions": item.measured.complexity.changed_regions,
        "transition_count": item.measured.complexity.transition_count,
        "changed_bytes": item.measured.complexity.changed_bytes,
        "total_reply_ms": item.total_reply_ms,
    }


def measurement(size: int, changed_bytes: int) -> tuple[bytes, canonical.ContentRef, InMemoryContentResolver]:
    content = canonical.canonical_bytes({"schema_version": budget.CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": changed_bytes})
    reference, resolver = stored_artifact(content, artifact_id=f"performance-changed-bytes-{size}")
    return content, reference, resolver


def reference(
    workload: Workload,
    report_ref: canonical.ContentRef,
    changed_range: tuple[int, int],
) -> budget.ReferenceWorkload:
    value = budget.ReferenceWorkload(
        "measured-detection-core-consumer",
        "complete deterministic and model+proof consumer runs; scaled relations, observations, receipts, and cases",
        (workload.changed_regions, workload.changed_regions),
        (1, workload.sizes[-1]),
        changed_range,
        report_ref,
        "",
    )
    return replace(value, record_digest=budget.derive_reference_workload_digest(value))


def seed_budget(
    workload: Workload,
    points: tuple[PerformancePoint, ...],
    reference_hardware: budget.ReferenceHardware,
) -> budget.BudgetDerivation:
    report = sample_report(workload, points, ())
    report_ref, _ = stored_artifact(report, artifact_id="performance-calibration-seed")
    reference_workload = reference(workload, report_ref, (1, max(point.changed_bytes for point in points)))
    samples = []
    for point in points:
        _, measured_bytes, _ = measurement(point.relation_count, point.changed_bytes)
        complexity = budget.ChangeComplexity(
            point.change_digest,
            workload.workload_class,
            workload.changed_regions,
            point.relation_count,
            point.changed_bytes,
            measured_bytes,
        )
        samples.extend(budget.MeasuredSample(complexity, nanoseconds_to_milliseconds(value)) for value in point.elapsed_samples_ns)
    return budget.derive_budget(tuple(samples), workload.workload_class, 1.0, reference_workload, reference_hardware)


__all__ = ["hardware", "measurement", "reference", "sample_report", "seed_budget"]
