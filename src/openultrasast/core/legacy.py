"""Read-only validation for committed detection-core v1 artifacts.

The v1 schemas are selected by the caller because historical artifacts do not
self-identify.  This module deliberately exposes no writer or v2 conversion.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from openultrasast.core.canonical import bytes_digest

LEGACY_TRACE_SCHEMA = "trace-v1"
LEGACY_REPORT_SCHEMA = "admission-report-v1"

_TRACE_FIELDS = frozenset(
    {
        "authority",
        "completeness_reasons",
        "digests",
        "entry",
        "guards",
        "hops",
        "judgment",
        "operation_kind",
        "resource",
        "witnesses",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "coverage",
        "criteria_pre_registered",
        "decision",
        "failed_gates",
        "families",
        "fix_recall",
        "flagged_ordinary_per_100",
        "indeterminate_rate",
        "instrument_failures",
        "manifest",
        "pair_correctness",
        "pairs",
        "precision",
        "runtime",
        "verified_location_recall",
    }
)
_RATE_FIELDS = frozenset({"count", "n", "rate", "wilson95"})
_CRITERIA_FIELDS = frozenset(
    {
        "max_flagged_ordinary_per_100",
        "max_indeterminate_rate",
        "min_fix_recall",
        "min_pair_correctness",
        "min_precision",
        "min_verified_location_recall",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "acquisition_record_digest",
        "analyzer_revision",
        "configuration_digest",
        "fact_set_digest",
        "population_digest",
        "population_role",
    }
)


class LegacyArtifactError(ValueError):
    """Historical bytes do not satisfy the explicitly selected v1 schema."""


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise LegacyArtifactError(f"duplicate legacy artifact field: {key}")
        value[key] = item
    return value


def _decode_json(content: bytes) -> object:
    try:
        return json.loads(content, object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyArtifactError("legacy artifact must be valid UTF-8 JSON") from exc


@dataclass(frozen=True)
class LegacyArtifact:
    """Validated historical bytes, retained without normalization or rewriting."""

    schema_version: str
    content: bytes
    content_digest: str
    byte_length: int

    @property
    def payload(self) -> dict[str, object]:
        """Return a fresh inspection copy of the validated JSON object."""
        value = _decode_json(self.content)
        if not isinstance(value, dict):  # Kept defensive; construction validates this.
            raise LegacyArtifactError("legacy artifact must contain a JSON object")
        return {str(key): item for key, item in value.items()}


def _object(value: object, fields: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LegacyArtifactError(f"{name} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        raise LegacyArtifactError(f"{name} has missing fields {missing} and unknown fields {unknown}")
    return {str(key): item for key, item in value.items()}


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LegacyArtifactError(f"{name} must be nonempty text")
    return value


def _text_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise LegacyArtifactError(f"{name} must be a list of nonempty text")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LegacyArtifactError(f"{name} must be a non-negative integer")
    return value


def _number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise LegacyArtifactError(f"{name} must be a finite non-negative number")
    return float(value)


def _nullable_number(value: object, name: str) -> float | None:
    if value is None:
        return None
    return _number(value, name)


def _objects(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise LegacyArtifactError(f"{name} must be a list")
    return value


def _validate_trace(value: object) -> None:
    trace = _object(value, _TRACE_FIELDS, "trace-v1")
    for name in ("entry", "operation_kind", "resource", "authority"):
        _text(trace[name], name)
    if trace["judgment"] not in {"unguarded", "discharged", "indeterminate"}:
        raise LegacyArtifactError("judgment is not a recognized v1 value")
    _text_list(trace["completeness_reasons"], "completeness_reasons")
    _validate_hops(trace["hops"])
    _validate_witnesses(trace["witnesses"])
    _validate_guards(trace["guards"])
    digests = trace["digests"]
    if not isinstance(digests, dict) or not all(
        isinstance(key, str) and key and isinstance(item, str) and item for key, item in digests.items()
    ):
        raise LegacyArtifactError("digests must map nonempty text to nonempty text")


def _validate_hops(value: object) -> None:
    for index, item in enumerate(_objects(value, "hops")):
        hop = _object(item, frozenset({"call_line", "complete", "function"}), f"hops[{index}]")
        _text(hop["function"], f"hops[{index}].function")
        _integer(hop["call_line"], f"hops[{index}].call_line")
        if not isinstance(hop["complete"], bool):
            raise LegacyArtifactError(f"hops[{index}].complete must be boolean")


def _validate_witnesses(value: object) -> None:
    fields = frozenset({"kind", "provenance", "relation"})
    for index, item in enumerate(_objects(value, "witnesses")):
        witness = _object(item, fields, f"witnesses[{index}]")
        for name in fields:
            _text(witness[name], f"witnesses[{index}].{name}")


def _validate_guards(value: object) -> None:
    fields = frozenset({"kind", "effect"})
    for index, item in enumerate(_objects(value, "guards")):
        guard = _object(item, fields, f"guards[{index}]")
        for name in fields:
            _text(guard[name], f"guards[{index}].{name}")


def _validate_report(value: object) -> None:
    report = _object(value, _REPORT_FIELDS, "admission-report-v1")
    if _number(report["coverage"], "coverage") > 1:
        raise LegacyArtifactError("coverage must be between zero and one")
    if report["decision"] not in {"GO", "NO-GO"}:
        raise LegacyArtifactError("decision is not a recognized v1 value")
    failed_gates = _text_list(report["failed_gates"], "failed_gates")
    if (report["decision"] == "GO") != (not failed_gates):
        raise LegacyArtifactError("decision and failed_gates are inconsistent")
    _text_list(report["families"], "families")
    _integer(report["instrument_failures"], "instrument_failures")
    _validate_criteria(report["criteria_pre_registered"])
    _validate_manifest(report["manifest"])
    pairs = _validate_pairs(report["pairs"])
    rates: dict[str, tuple[int, int]] = {}
    for name in (
        "fix_recall",
        "flagged_ordinary_per_100",
        "indeterminate_rate",
        "pair_correctness",
        "precision",
        "verified_location_recall",
    ):
        rates[name] = _validate_rate(report[name], name)
    if pairs != rates["pair_correctness"]:
        raise LegacyArtifactError("pairs must agree with pair_correctness")
    runtime_n = _validate_runtime(report["runtime"])
    if runtime_n != pairs[1] or runtime_n != rates["fix_recall"][1]:
        raise LegacyArtifactError("runtime.n must agree with the evaluated pair denominator")


def _validate_criteria(value: object) -> None:
    criteria = _object(value, _CRITERIA_FIELDS, "criteria_pre_registered")
    for name, item in criteria.items():
        _number(item, f"criteria_pre_registered.{name}")


def _validate_manifest(value: object) -> None:
    manifest = _object(value, _MANIFEST_FIELDS, "manifest")
    for name, item in manifest.items():
        _text(item, f"manifest.{name}")


def _validate_pairs(value: object) -> tuple[int, int]:
    pairs = _object(value, frozenset({"correct", "n"}), "pairs")
    correct = _integer(pairs["correct"], "pairs.correct")
    total = _integer(pairs["n"], "pairs.n")
    if correct > total:
        raise LegacyArtifactError("pairs.correct must not exceed pairs.n")
    return correct, total


def _validate_runtime(value: object) -> int:
    runtime = _object(value, frozenset({"max_seconds", "mean_seconds", "n"}), "runtime")
    maximum = _number(runtime["max_seconds"], "runtime.max_seconds")
    mean = _number(runtime["mean_seconds"], "runtime.mean_seconds")
    if maximum < mean:
        raise LegacyArtifactError("runtime.max_seconds must not be below runtime.mean_seconds")
    return _integer(runtime["n"], "runtime.n")


def _validate_rate(value: object, name: str) -> tuple[int, int]:
    rate = _object(value, _RATE_FIELDS, name)
    count = _integer(rate["count"], f"{name}.count")
    total = _integer(rate["n"], f"{name}.n")
    if count > total:
        raise LegacyArtifactError(f"{name}.count must not exceed {name}.n")
    actual = _nullable_number(rate["rate"], f"{name}.rate")
    interval = rate["wilson95"]
    if not isinstance(interval, list) or len(interval) != 2:
        raise LegacyArtifactError(f"{name}.wilson95 must contain two bounds")
    bounds = tuple(_nullable_number(bound, f"{name}.wilson95[{index}]") for index, bound in enumerate(interval))
    if total == 0:
        if actual is not None or bounds != (None, None):
            raise LegacyArtifactError(f"{name} must use null rate and interval when n is zero")
        return count, total
    if actual is None or any(bound is None for bound in bounds):
        raise LegacyArtifactError(f"{name} must use non-null rate and interval when n is positive")
    lower, upper = bounds
    assert lower is not None and upper is not None
    scale = 100.0 if name == "flagged_ordinary_per_100" else 1.0
    expected = count / total * scale
    if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12):
        raise LegacyArtifactError(f"{name}.rate must be derived from count and n")
    if not 0 <= lower <= upper <= scale:
        raise LegacyArtifactError(f"{name}.wilson95 bounds are invalid")
    return count, total


def decode_legacy_artifact(content: bytes, *, schema_version: str) -> LegacyArtifact:
    """Validate exact historical bytes through one explicit v1 schema route."""
    if schema_version not in {LEGACY_TRACE_SCHEMA, LEGACY_REPORT_SCHEMA}:
        raise LegacyArtifactError(f"unknown legacy schema: {schema_version!r}")
    if type(content) is not bytes:
        raise LegacyArtifactError("legacy artifact content must be exact bytes")
    if not content:
        raise LegacyArtifactError("legacy artifact content must be nonempty")
    value = _decode_json(content)
    if isinstance(value, dict) and "schema_version" in value:
        raise LegacyArtifactError("legacy artifact schema is ambiguous; use the explicit route only")
    validator = _validate_trace if schema_version == LEGACY_TRACE_SCHEMA else _validate_report
    validator(value)
    return LegacyArtifact(
        schema_version=schema_version,
        content=content,
        content_digest=bytes_digest(content),
        byte_length=len(content),
    )


def read_legacy_artifact(path: str | Path, *, schema_version: str) -> LegacyArtifact:
    """Read nonzero historical bytes and validate them without any write path."""
    try:
        content = Path(path).read_bytes()
    except OSError as exc:
        raise LegacyArtifactError(f"legacy artifact is not readable: {path}") from exc
    return decode_legacy_artifact(content, schema_version=schema_version)


__all__ = [
    "LEGACY_REPORT_SCHEMA",
    "LEGACY_TRACE_SCHEMA",
    "LegacyArtifact",
    "LegacyArtifactError",
    "decode_legacy_artifact",
    "read_legacy_artifact",
]
