"""Closed manifest validation for the downstream entry-fact handoff."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import cast

from openultrasast.core import canonical
from openultrasast.mapping._entry_fact_conformance_fs import (
    ConformanceFilesystemError,
    flat_regular_census,
    read_regular_nofollow,
    require_real_directory,
)
from openultrasast.mapping.entry_fact_conformance import ENTRY_FACT_CONFORMANCE_SCHEMA, EntryFactConformanceError

_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOP_FIELDS = {"schema_version", "handoff_digest", "core_entry_points", "cases"}
_CASE_FIELDS = {
    "case_id",
    "fixture_path",
    "fixture_digest",
    "fixture_byte_length",
    "expected_status",
    "reason",
    "artifacts",
    "validators",
    "downstream_validators",
}
_ARTIFACT_FIELDS = {"kind", "path", "content_digest", "byte_length"}
_VALIDATOR_FIELDS = {"name", "status", "reason"}
_EXPECTED_CASES = {
    "complete",
    "name_only",
    "partial",
    "authority_substitution",
    "producer_reviewer_conflict",
    "resolver_byte_substitution",
    "lineage_omission",
    "custody_contamination",
    "legacy_projection_only",
    "deterministic_replay",
}
_CORE_ENTRY_POINTS = (
    "openultrasast.core.factapply.apply_fact",
    "openultrasast.core.factmatch.validate_fact_match",
    "openultrasast.core.factpack.validate_fact_pack",
    "openultrasast.core.factvalidate.validate_fact_relations",
)
_MATCH = "openultrasast.core.factmatch.validate_fact_match"
_MATRIX = {
    "authority_substitution": ((_MATCH, "refused", "match_pack_identity_substituted"),),
    "complete": tuple((name, "passed", None) for name in _CORE_ENTRY_POINTS),
    "custody_contamination": ((_MATCH, "refused", "protected_population_contamination"),),
    "deterministic_replay": ((_MATCH, "passed", None),),
    "legacy_projection_only": ((_MATCH, "refused", "name_only_match"),),
    "lineage_omission": ((_MATCH, "refused", "matcher_lineage_omitted"),),
    "name_only": ((_MATCH, "refused", "missing_observation:receiver"),),
    "partial": ((_MATCH, "refused", "missing_observation:arguments"),),
    "producer_reviewer_conflict": (("openultrasast.core.factpack.validate_fact_pack", "refused", "self_authored_review_evidence"),),
    "resolver_byte_substitution": ((_MATCH, "refused", "resolver_byte_substitution"),),
}
_DOWNSTREAM_AUTHORITY = "openultrasast.mapping.fact_authority.authenticate_entry_fact_authority"
_DOWNSTREAM_MATRIX: dict[str, tuple[tuple[str, str, str], ...]] = {case_id: () for case_id in _EXPECTED_CASES}
_DOWNSTREAM_MATRIX["authority_substitution"] = ((_DOWNSTREAM_AUTHORITY, "refused", "authority_bundle_digest_substituted"),)
_DOWNSTREAM_MATRIX["producer_reviewer_conflict"] = ((_DOWNSTREAM_AUTHORITY, "refused", "producer_reviewer_conflict"),)


def _freeze(value: object) -> canonical.JsonValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {cast(str, key): _freeze(item) for key, item in value.items()}
    raise EntryFactConformanceError("manifest contains a value outside canonical JSON")


def _object(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields or not all(isinstance(key, str) for key in value):
        raise EntryFactConformanceError(f"{name} has unknown or missing fields")
    return cast(Mapping[str, object], value)


def _array(value: object, name: str) -> list[object]:
    if not isinstance(value, list) or not value:
        raise EntryFactConformanceError(f"{name} must be a nonempty array")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise EntryFactConformanceError(f"{name} must be an array")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EntryFactConformanceError(f"{name} must be nonempty text")
    return value


def _digest(value: object, name: str) -> str:
    text = _text(value, name)
    if _DIGEST.fullmatch(text) is None:
        raise EntryFactConformanceError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _positive(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EntryFactConformanceError(f"{name} must be a positive integer")


def _relative(value: object, name: str) -> None:
    text = _text(value, name)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        raise EntryFactConformanceError(f"{name} must be a normalized relative path")


def _validate_case(value: object) -> str:
    row = _object(value, _CASE_FIELDS, "case")
    case_id = _text(row["case_id"], "case_id")
    if case_id not in _MATRIX:
        raise EntryFactConformanceError("case identity is unknown")
    _relative(row["fixture_path"], "fixture_path")
    _digest(row["fixture_digest"], "fixture_digest")
    _positive(row["fixture_byte_length"], "fixture_byte_length")
    status = _text(row["expected_status"], "expected_status")
    reason = row["reason"]
    if status not in {"passed", "refused"} or (reason is None) is not (status == "passed"):
        raise EntryFactConformanceError("case status and stable reason are inconsistent")
    if reason is not None:
        _text(reason, "reason")
    _validate_artifacts(row["artifacts"])
    _validate_validators(case_id, row["validators"], status, reason)
    _validate_downstream(case_id, row["downstream_validators"])
    return case_id


def _validate_artifacts(value: object) -> None:
    for artifact in _array(value, "artifacts"):
        item = _object(artifact, _ARTIFACT_FIELDS, "artifact")
        _text(item["kind"], "artifact.kind")
        _relative(item["path"], "artifact.path")
        digest = _digest(item["content_digest"], "artifact.content_digest")
        if item["path"] != f"artifacts/sha256/{digest}":
            raise EntryFactConformanceError("artifact path does not equal its digest address")
        _positive(item["byte_length"], "artifact.byte_length")


def _validate_validators(case_id: str, value: object, status: str, reason: object) -> None:
    actual_validators = []
    for validator in _array(value, "validators"):
        item = _object(validator, _VALIDATOR_FIELDS, "validator")
        name = _text(item["name"], "validator.name")
        if name not in _CORE_ENTRY_POINTS:
            raise EntryFactConformanceError("validator is outside the exact core entry-point set")
        validator_status = _text(item["status"], "validator.status")
        if validator_status not in {"passed", "refused"}:
            raise EntryFactConformanceError("validator status is unknown")
        if item["reason"] is not None:
            _text(item["reason"], "validator.reason")
        if validator_status != status or item["reason"] != reason:
            raise EntryFactConformanceError("validator result differs from its enclosing case")
        actual_validators.append((name, validator_status, item["reason"]))
    if tuple(actual_validators) != _MATRIX[case_id]:
        raise EntryFactConformanceError("case validator matrix is incomplete or reordered")


def _validate_downstream(case_id: str, value: object) -> None:
    actual = []
    for validator in _list(value, "downstream_validators"):
        item = _object(validator, _VALIDATOR_FIELDS, "downstream validator")
        actual.append(
            (
                _text(item["name"], "downstream validator.name"),
                _text(item["status"], "downstream validator.status"),
                item["reason"],
            )
        )
    if tuple(actual) != _DOWNSTREAM_MATRIX[case_id]:
        raise EntryFactConformanceError("downstream validator matrix is incomplete or fabricated")


def _validate_files(root: Path, cases: list[object]) -> None:
    declared_sources = {_text(_object(raw, _CASE_FIELDS, "case")["fixture_path"], "fixture_path") for raw in cases}
    source_root = root / "sources"
    try:
        actual_sources = {f"sources/{name}" for name in flat_regular_census(source_root)}
    except ConformanceFilesystemError as exc:
        raise EntryFactConformanceError("source filesystem census differs from declared regular fixtures") from exc
    if actual_sources != declared_sources:
        raise EntryFactConformanceError("source filesystem census differs from declared regular fixtures")
    declared = _declared_artifact_paths(cases)
    artifact_root = root / "artifacts" / "sha256"
    try:
        require_real_directory(root / "artifacts")
        actual = {f"artifacts/sha256/{name}" for name in flat_regular_census(artifact_root)}
    except ConformanceFilesystemError as exc:
        raise EntryFactConformanceError("artifact filesystem census differs from the manifest") from exc
    if actual != declared:
        raise EntryFactConformanceError("artifact filesystem census differs from the manifest")
    _validate_materialized_bytes(root, cases)


def _declared_artifact_paths(cases: list[object]) -> set[str]:
    declared: set[str] = set()
    for raw in cases:
        case = _object(raw, _CASE_FIELDS, "case")
        for raw_artifact in _array(case["artifacts"], "artifacts"):
            artifact = _object(raw_artifact, _ARTIFACT_FIELDS, "artifact")
            declared.add(_text(artifact["path"], "artifact.path"))
    return declared


def _safe_read(path: Path, kind: str) -> bytes:
    try:
        return read_regular_nofollow(path)
    except ConformanceFilesystemError as exc:
        raise EntryFactConformanceError(f"{kind} filesystem census differs from the manifest") from exc


def _validate_materialized_bytes(root: Path, cases: list[object]) -> None:
    for raw in cases:
        case = _object(raw, _CASE_FIELDS, "case")
        fixture = root / _text(case["fixture_path"], "fixture_path")
        fixture_content = _safe_read(fixture, "source")
        if (
            not fixture_content
            or len(fixture_content) != case["fixture_byte_length"]
            or canonical.bytes_digest(fixture_content) != case["fixture_digest"]
        ):
            raise EntryFactConformanceError("fixture bytes do not match the manifest")
        for raw_artifact in _array(case["artifacts"], "artifacts"):
            artifact = _object(raw_artifact, _ARTIFACT_FIELDS, "artifact")
            path = _text(artifact["path"], "artifact.path")
            materialized = _safe_read(root / path, "artifact")
            if (
                not materialized
                or len(materialized) != artifact["byte_length"]
                or canonical.bytes_digest(materialized) != artifact["content_digest"]
            ):
                raise EntryFactConformanceError("artifact bytes do not match the manifest")


def validate_entry_fact_conformance(content: bytes, root: Path | None = None) -> None:
    """Refuse noncanonical, open-schema, redirected, or self-inconsistent manifests."""
    try:
        parsed = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EntryFactConformanceError("manifest is not canonical JSON") from exc
    row = _object(parsed, _TOP_FIELDS, "manifest")
    if row["schema_version"] != ENTRY_FACT_CONFORMANCE_SCHEMA:
        raise EntryFactConformanceError("manifest schema is unknown")
    frozen = cast(Mapping[str, canonical.JsonValue], _freeze(parsed))
    if canonical.canonical_record_bytes(frozen, known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,)) != content:
        raise EntryFactConformanceError("manifest bytes are not canonical")
    entry_points = _array(row["core_entry_points"], "core_entry_points")
    if not all(isinstance(item, str) and item for item in entry_points) or len(set(entry_points)) != len(entry_points):
        raise EntryFactConformanceError("core entry points must be unique nonempty text")
    core_entry_points = tuple(cast(str, item) for item in entry_points)
    if core_entry_points != _CORE_ENTRY_POINTS:
        raise EntryFactConformanceError("core entry points differ from the exact replay set")
    cases = _array(row["cases"], "cases")
    case_ids = tuple(_validate_case(item) for item in cases)
    if set(case_ids) != _EXPECTED_CASES or case_ids != tuple(sorted(case_ids)):
        raise EntryFactConformanceError("manifest cases are missing, duplicated, or unordered")
    payload: Mapping[str, canonical.JsonValue] = {
        "schema_version": ENTRY_FACT_CONFORMANCE_SCHEMA,
        "core_entry_points": core_entry_points,
        "cases": tuple(_freeze(item) for item in cases),
    }
    if _digest(row["handoff_digest"], "handoff_digest") != canonical.content_digest(payload):
        raise EntryFactConformanceError("handoff digest cannot be re-derived")
    if root is not None:
        _validate_files(Path(root), cases)


__all__ = ["validate_entry_fact_conformance"]
