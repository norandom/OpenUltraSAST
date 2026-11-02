"""Measured workload budgets for legacy and v2 detection-core contracts."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core import canonical

CHANGED_BYTES_MEASUREMENT_SCHEMA = "openultrasast.detection-core.changed-bytes.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class BudgetGateFailure(ValueError):
    """A change exceeded its class's measured budget."""


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be nonempty text")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a full lowercase SHA-256 digest")


def _positive_int(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")


def _nonnegative_int(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")


def _finite_number(value: object, field: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    number = float(value)
    if positive and number <= 0:
        raise ValueError(f"{field} must be positive")
    return number


@dataclass(frozen=True)
class ChangeComplexity:
    change_id: str
    workload_class: str
    changed_regions: int
    transition_count: int
    changed_bytes: int
    measurement: canonical.ContentRef

    def __post_init__(self) -> None:
        _validate_complexity(self)


def _validate_complexity(value: ChangeComplexity) -> None:
    _digest(value.change_id, "change_id")
    _text(value.workload_class, "workload_class")
    _positive_int(value.changed_regions, "changed_regions")
    _nonnegative_int(value.transition_count, "transition_count")
    _positive_int(value.changed_bytes, "changed_bytes")
    if not isinstance(value.measurement, canonical.ContentRef) or value.measurement.byte_length <= 0:
        raise ValueError("measurement must be a nonempty ContentRef")
    value.measurement.__post_init__()


@dataclass(frozen=True)
class MeasuredSample:
    complexity: ChangeComplexity
    total_reply_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.complexity, ChangeComplexity):
            raise TypeError("complexity must be ChangeComplexity")
        _positive_int(self.total_reply_ms, "total_reply_ms")


def _range(value: object, field: str, *, allow_zero: bool) -> tuple[int, int]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise ValueError(f"{field} must be a two-item tuple")
    lower, upper = value
    validator = _nonnegative_int if allow_zero else _positive_int
    validator(lower, f"{field} lower")
    validator(upper, f"{field} upper")
    if lower > upper:
        raise ValueError(f"{field} lower must not exceed upper")
    return lower, upper


@dataclass(frozen=True)
class ReferenceWorkload:
    name: str
    description: str
    changed_region_range: tuple[int, int]
    transition_count_range: tuple[int, int]
    changed_bytes_range: tuple[int, int]
    sample_artifact: canonical.ContentRef
    record_digest: str

    def __post_init__(self) -> None:
        _validate_reference_workload(self, allow_empty_digest=True)
        expected = derive_reference_workload_digest(self)
        if not self.record_digest:
            object.__setattr__(self, "record_digest", expected)
        elif self.record_digest != expected:
            raise ValueError("reference workload digest does not match fields")


def _workload_value(value: ReferenceWorkload) -> canonical.JsonValue:
    return {
        "schema_version": "openultrasast.detection-core.reference-workload.v2",
        "name": value.name,
        "description": value.description,
        "changed_region_range": value.changed_region_range,
        "transition_count_range": value.transition_count_range,
        "changed_bytes_range": value.changed_bytes_range,
        "sample_artifact": _content_ref_value(value.sample_artifact),
    }


def _content_ref_value(value: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "media_type": value.media_type,
        "byte_length": value.byte_length,
        "retention_policy_digest": value.retention_policy_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
    }


def derive_reference_workload_digest(value: ReferenceWorkload) -> str:
    return canonical.content_digest(_workload_value(value))


def _validate_reference_workload(value: ReferenceWorkload, *, allow_empty_digest: bool = False) -> None:
    _text(value.name, "reference workload name")
    _text(value.description, "reference workload description")
    _range(value.changed_region_range, "changed_region_range", allow_zero=False)
    _range(value.transition_count_range, "transition_count_range", allow_zero=True)
    _range(value.changed_bytes_range, "changed_bytes_range", allow_zero=False)
    if not isinstance(value.sample_artifact, canonical.ContentRef) or value.sample_artifact.byte_length <= 0:
        raise ValueError("sample_artifact must be a nonempty ContentRef")
    value.sample_artifact.__post_init__()
    if value.record_digest or not allow_empty_digest:
        _digest(value.record_digest, "reference workload digest")
    if value.record_digest and value.record_digest != derive_reference_workload_digest(value):
        raise ValueError("reference workload digest does not match fields")


@dataclass(frozen=True)
class ReferenceHardware:
    cpu_model: str
    logical_cpu_count: int
    memory_bytes: int
    operating_system: str
    runtime_version: str
    record_digest: str

    def __post_init__(self) -> None:
        _validate_reference_hardware(self, allow_empty_digest=True)
        expected = derive_reference_hardware_digest(self)
        if not self.record_digest:
            object.__setattr__(self, "record_digest", expected)
        elif self.record_digest != expected:
            raise ValueError("reference hardware digest does not match fields")


def _hardware_value(value: ReferenceHardware) -> canonical.JsonValue:
    return {
        "schema_version": "openultrasast.detection-core.reference-hardware.v2",
        "cpu_model": value.cpu_model,
        "logical_cpu_count": value.logical_cpu_count,
        "memory_bytes": value.memory_bytes,
        "operating_system": value.operating_system,
        "runtime_version": value.runtime_version,
    }


def derive_reference_hardware_digest(value: ReferenceHardware) -> str:
    return canonical.content_digest(_hardware_value(value))


def _validate_reference_hardware(value: ReferenceHardware, *, allow_empty_digest: bool = False) -> None:
    for field, item in (
        ("cpu_model", value.cpu_model),
        ("operating_system", value.operating_system),
        ("runtime_version", value.runtime_version),
    ):
        _text(item, field)
    _positive_int(value.logical_cpu_count, "logical_cpu_count")
    _positive_int(value.memory_bytes, "memory_bytes")
    if value.record_digest or not allow_empty_digest:
        _digest(value.record_digest, "reference hardware digest")
    if value.record_digest and value.record_digest != derive_reference_hardware_digest(value):
        raise ValueError("reference hardware digest does not match fields")


@dataclass(frozen=True)
class BudgetDerivation:
    workload_class: str
    sample_count: int
    percentile: float
    reference_workload: ReferenceWorkload
    reference_hardware: ReferenceHardware
    budget_ms: int
    derivation_digest: str

    def __post_init__(self) -> None:
        _validate_derivation(self, allow_empty_digest=True)
        expected = derive_budget_derivation_digest(self)
        if not self.derivation_digest:
            object.__setattr__(self, "derivation_digest", expected)
        elif self.derivation_digest != expected:
            raise ValueError("budget derivation digest does not match fields")


def _derivation_value(value: BudgetDerivation) -> canonical.JsonValue:
    return {
        "schema_version": "openultrasast.detection-core.budget-derivation.v2",
        "workload_class": value.workload_class,
        "sample_count": value.sample_count,
        "percentile": value.percentile,
        "reference_workload_digest": value.reference_workload.record_digest,
        "reference_hardware_digest": value.reference_hardware.record_digest,
        "budget_ms": value.budget_ms,
    }


def derive_budget_derivation_digest(value: BudgetDerivation) -> str:
    return canonical.content_digest(_derivation_value(value))


def _validate_derivation(value: BudgetDerivation, *, allow_empty_digest: bool = False) -> None:
    _text(value.workload_class, "workload_class")
    _positive_int(value.sample_count, "sample_count")
    percentile = _finite_number(value.percentile, "percentile", positive=True)
    if percentile > 1:
        raise ValueError("percentile must not exceed 1")
    if not isinstance(value.reference_workload, ReferenceWorkload):
        raise TypeError("reference_workload must be ReferenceWorkload")
    if not isinstance(value.reference_hardware, ReferenceHardware):
        raise TypeError("reference_hardware must be ReferenceHardware")
    _validate_reference_workload(value.reference_workload)
    _validate_reference_hardware(value.reference_hardware)
    _positive_int(value.budget_ms, "budget_ms")
    if value.derivation_digest or not allow_empty_digest:
        _digest(value.derivation_digest, "derivation_digest")
    if value.derivation_digest and value.derivation_digest != derive_budget_derivation_digest(value):
        raise ValueError("budget derivation digest does not match fields")


def _quantile(sorted_values: Sequence[float], percentile: float) -> float:
    position = percentile * (len(sorted_values) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def _compatible(value: ChangeComplexity, reference: ReferenceWorkload) -> bool:
    return all(
        lower <= current <= upper
        for current, (lower, upper) in (
            (value.changed_regions, reference.changed_region_range),
            (value.transition_count, reference.transition_count_range),
            (value.changed_bytes, reference.changed_bytes_range),
        )
    )


def derive_budget(
    samples: Sequence[MeasuredSample],
    workload_class: str,
    percentile: float,
    reference_workload: ReferenceWorkload,
    reference_hardware: ReferenceHardware,
) -> BudgetDerivation:
    _text(workload_class, "workload_class")
    value = _finite_number(percentile, "percentile", positive=True)
    if value > 1 or not samples:
        raise ValueError("v2 derivation requires samples and percentile in (0, 1]")
    _validate_reference_workload(reference_workload)
    _validate_reference_hardware(reference_hardware)
    measured = tuple(item for item in samples if isinstance(item, MeasuredSample))
    if len(measured) != len(samples):
        raise TypeError("v2 samples must be MeasuredSample values")
    for sample in measured:
        sample.__post_init__()
        _validate_complexity(sample.complexity)
        if sample.complexity.workload_class != workload_class:
            raise ValueError("sample workload class does not match derivation")
        if not _compatible(sample.complexity, reference_workload):
            raise ValueError("sample complexity is outside reference workload")
    budget_ms = math.ceil(_quantile(sorted(float(item.total_reply_ms) for item in measured), value))
    return BudgetDerivation(workload_class, len(measured), value, reference_workload, reference_hardware, budget_ms, "")


class _ResolvedOnce:
    def __init__(self, resolved: canonical.ResolvedContent) -> None:
        self._resolved = resolved

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        return self._resolved


def _validate_measurement(change: ChangeComplexity, resolver: canonical.ContentResolver) -> None:
    resolved = resolver.resolve(change.measurement)
    content = canonical.resolve_content(
        change.measurement,
        _ResolvedOnce(resolved),
        trusted_store_identities=(resolved.receipt.store_identity,),
        maximum_bytes=4096,
    )
    try:
        parsed = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("changed-byte measurement is not canonical JSON") from exc
    expected = {"schema_version": CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": change.changed_bytes}
    if parsed != expected or canonical.canonical_bytes(parsed) != content:
        raise ValueError("changed-byte measurement does not match complexity")


def check_budget(
    change: ChangeComplexity,
    total_reply_ms: int,
    budget: BudgetDerivation,
    resolver: canonical.ContentResolver,
) -> None:
    if not isinstance(change, ChangeComplexity) or not isinstance(budget, BudgetDerivation):
        raise TypeError("v2 budget check requires complexity, derivation, and resolver")
    _validate_complexity(change)
    _validate_derivation(budget)
    _positive_int(total_reply_ms, "total_reply_ms")
    if change.workload_class != budget.workload_class or not _compatible(change, budget.reference_workload):
        raise ValueError("change complexity is incompatible with budget derivation")
    _validate_measurement(change, resolver)
    if total_reply_ms > budget.budget_ms:
        raise BudgetGateFailure(
            f"budget:{change.change_id}:{total_reply_ms}ms>{budget.budget_ms}ms "
            f"class={budget.workload_class} derivation={budget.derivation_digest}"
        )


__all__ = [
    "BudgetDerivation",
    "BudgetGateFailure",
    "CHANGED_BYTES_MEASUREMENT_SCHEMA",
    "ChangeComplexity",
    "MeasuredSample",
    "ReferenceHardware",
    "ReferenceWorkload",
    "check_budget",
    "derive_budget",
    "derive_budget_derivation_digest",
    "derive_reference_hardware_digest",
    "derive_reference_workload_digest",
]
