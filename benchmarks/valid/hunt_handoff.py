"""Explicit, non-mutating handoff from the hunt runner to benchmark v2 storage."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from benchmarks.unseen.replay import canonical
from benchmarks.valid.artifact_contract import (
    read_benchmark_artifact,
    write_benchmark_artifact,
    write_benchmark_sequence,
)
from openultrasast.hunt.artifact import MAX_ATTEMPT_ORDINAL, RunArtifact
from openultrasast.hunt.runner import input_digest, record_path

HUNT_RUNNER_PRODUCER = "openultrasast.hunt.runner.v1"
_RESERVED = frozenset({"schema_version", "artifact_kind", "artifact_digest"})
_RECORD_REQUIRED = frozenset(
    {"id", "done", "status", "instrument", "push", "rows", "program_id", "mask", "inputs_present", "seconds", "input_digest", "usd"}
)
_RECORD_OPTIONAL = frozenset({"parse_failed", "loop_parse_failed"})


@dataclass(frozen=True)
class HuntRunContext:
    producer: str
    program_id: str
    mask: tuple[str, ...]
    manifest_digest: str
    freeze_digest: str
    only: str
    slice_id: str
    artifact_ids: tuple[str, ...]
    versions: tuple[tuple[str, str], ...]


def _hex_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"hunt handoff {field} must be a full lowercase digest")
    return value


def _validate_context(context: HuntRunContext) -> None:
    if context.producer != HUNT_RUNNER_PRODUCER:
        raise ValueError(f"unsupported hunt producer: {context.producer}")
    _hex_digest(context.program_id, "program identity")
    _hex_digest(context.manifest_digest, "manifest identity")
    _hex_digest(context.freeze_digest, "freeze identity")
    if tuple(sorted(set(context.mask))) != context.mask:
        raise ValueError("hunt handoff mask must be sorted and unique")
    if not context.only or not context.slice_id:
        raise ValueError("hunt handoff runner context is incomplete")
    if not context.artifact_ids or tuple(sorted(set(context.artifact_ids))) != context.artifact_ids:
        raise ValueError("hunt handoff attempt identities must be nonempty, sorted, and unique")
    for artifact_id in context.artifact_ids:
        _hex_digest(artifact_id, "attempt identity")
    if tuple(sorted(set(context.versions))) != context.versions:
        raise ValueError("hunt handoff versions must be sorted and unique")


def _read_json(path: Path, label: str) -> object:
    try:
        data = path.read_bytes()
        if not data:
            raise ValueError(f"{label} is empty")
        return json.loads(data)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is unreadable") from error


def _has_reserved(value: object) -> bool:
    if isinstance(value, Mapping):
        return bool(_RESERVED.intersection(value)) or any(_has_reserved(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_has_reserved(item) for item in value)
    return False


def _expected_entries(changes: Sequence[Mapping[str, Any]], context: HuntRunContext) -> tuple[dict[str, Any], ...]:
    if not changes or len({change.get("id") for change in changes}) != len(changes):
        raise ValueError("hunt handoff changes must be nonempty with unique identities")
    return tuple(
        {
            "item_id": change["id"],
            "change": dict(change),
            "input_digest": input_digest(change, context.program_id, context.mask),
        }
        for change in changes
        if context.only == "all" or change.get("kind") == context.only
    )


def _raw_entries(source: Path, expected: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    value = _read_json(source / "inputs.json", "hunt input index")
    if not isinstance(value, list) or _has_reserved(value):
        raise ValueError("hunt input index has reserved metadata or an unsupported schema")
    if not all(isinstance(row, dict) and set(row) == {"item_id", "change", "input_digest"} for row in value):
        raise ValueError("hunt input index has an unsupported row shape")
    rows = cast(tuple[dict[str, Any], ...], tuple(value))
    if rows != expected[: len(rows)]:
        raise ValueError("hunt input identity, ordering, or input digest mismatch")
    return rows


def _artifact_paths(source: Path, record_names: set[str]) -> tuple[Path, ...]:
    return tuple(sorted(path for path in source.glob("*.json") if path.name != "inputs.json" and path.name not in record_names))


def _artifact_projection(artifact: RunArtifact) -> tuple[object, ...]:
    return (
        artifact.schema_version,
        artifact.program_id,
        tuple(artifact.mask),
        tuple(sorted(artifact.data_digests.items())),
        tuple(json.dumps(value, sort_keys=True) for value in artifact.configurations),
        tuple(sorted(artifact.versions.items())),
    )


def _read_attempts(paths: Sequence[Path]) -> tuple[RunArtifact, ...]:
    artifacts: list[RunArtifact] = []
    for path in paths:
        try:
            artifact = RunArtifact.read(path)
        except (OSError, TypeError, ValueError) as error:
            raise ValueError("hunt runner context artifact is invalid") from error
        if path.stem != artifact.artifact_id:
            raise ValueError("hunt runner context artifact filename does not match its identity")
        artifacts.append(artifact)
    if not artifacts:
        raise ValueError("hunt runner context artifact collection is empty")
    ordinals = [artifact.attempt_ordinal for artifact in artifacts]
    if any(type(ordinal) is not int or not 0 < ordinal <= MAX_ATTEMPT_ORDINAL for ordinal in ordinals) or len(set(ordinals)) != len(
        ordinals
    ):
        raise ValueError("hunt runner attempt ordinals must be positive and unique")
    projection = _artifact_projection(artifacts[0])
    if any(_artifact_projection(artifact) != projection for artifact in artifacts[1:]):
        raise ValueError("hunt runner attempt invariant mismatch")
    return tuple(artifacts)


def _validate_run_artifact(source: Path, context: HuntRunContext, expected: tuple[dict[str, Any], ...]) -> None:
    record_names = {record_path(source, cast(str, entry["item_id"])).name for entry in expected}
    artifacts = _read_attempts(_artifact_paths(source, record_names))
    artifact = artifacts[0]
    if tuple(sorted(item.artifact_id for item in artifacts)) != context.artifact_ids:
        raise ValueError("hunt runner attempt identities do not match handoff context")
    if artifact.schema_version != 1:
        raise ValueError("hunt runner schema is unsupported")
    if artifact.program_id != context.program_id or tuple(artifact.mask) != context.mask:
        raise ValueError("hunt runner program identity does not match handoff context")
    if artifact.data_digests != {"manifest": context.manifest_digest}:
        raise ValueError("hunt runner manifest identity does not match handoff context")
    expected_configuration = [{"only": context.only, "slice": context.slice_id, "changes": len(expected)}]
    if artifact.configurations != expected_configuration:
        raise ValueError("hunt runner configuration identity does not match handoff context")
    if tuple(sorted(artifact.versions.items())) != context.versions:
        raise ValueError("hunt runner version identity does not match handoff context")


def _raw_record(source: Path, entry: Mapping[str, Any], context: HuntRunContext) -> dict[str, Any] | None:
    path = record_path(source, cast(str, entry["item_id"]))
    if not path.exists():
        return None
    value = _read_json(path, "hunt record")
    if not isinstance(value, dict) or _has_reserved(value):
        raise ValueError("hunt record uses reserved metadata or an unsupported schema")
    keys = frozenset(value)
    if not _RECORD_REQUIRED.issubset(keys) or not keys.issubset(_RECORD_REQUIRED | _RECORD_OPTIONAL):
        raise ValueError("hunt record has an unsupported shape")
    if value["id"] != entry["item_id"]:
        raise ValueError("hunt record identity mismatch")
    if value["input_digest"] != entry["input_digest"]:
        raise ValueError("hunt record input digest mismatch")
    if value["program_id"] != context.program_id or tuple(value["mask"]) != context.mask:
        raise ValueError("hunt record program or configuration identity mismatch")
    if value["done"] is not True or not isinstance(value["instrument"], dict) or not isinstance(value["push"], dict):
        raise ValueError("hunt record completion schema is invalid")
    return value


def read_hunt_runner_records(
    source: Path,
    *,
    context: HuntRunContext,
    changes: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Validate a named raw hunt run and return normalized rows without writing to it."""
    source = Path(source)
    _validate_context(context)
    expected = _expected_entries(changes, context)
    _validate_run_artifact(source, context, expected)
    entries = _raw_entries(source, expected)
    rows: list[dict[str, Any]] = []
    for entry in entries:
        record = _raw_record(source, entry, context) or {}
        change = cast(dict[str, Any], entry["change"])
        rows.append({**change, **record, "id": change["id"]})
    return tuple(rows)


def _handoff_payload(context: HuntRunContext, entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        **asdict(context),
        "mask": list(context.mask),
        "input_count": len(entries),
        "input_sequence_digest": hashlib.sha256(canonical(entries)).hexdigest(),
    }


def persist_hunt_runner_records(
    source: Path,
    destination: Path,
    *,
    context: HuntRunContext,
    changes: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Copy a validated raw run into distinct benchmark-owned canonical v2 files."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("hunt producer and benchmark destination must be distinct")
    rows = read_hunt_runner_records(source, context=context, changes=changes)
    expected = _expected_entries(changes, context)
    entries = _raw_entries(source, expected)
    write_benchmark_artifact(destination / "handoff.json", "hunt-runner-handoff", _handoff_payload(context, entries))
    write_benchmark_sequence(destination / "inputs.json", "benchmark-arm-inputs", entries)
    for entry in entries:
        record = _raw_record(source, entry, context)
        if record is not None:
            write_benchmark_artifact(record_path(destination, cast(str, entry["item_id"])), "benchmark-arm-record", record)
    return rows


def read_hunt_handoff_context(path: Path) -> HuntRunContext:
    """Read the bound context of an already-normalized benchmark handoff."""
    payload = read_benchmark_artifact(Path(path) / "handoff.json", "hunt-runner-handoff")
    context = HuntRunContext(
        producer=cast(str, payload["producer"]),
        program_id=cast(str, payload["program_id"]),
        mask=tuple(cast(Sequence[str], payload["mask"])),
        manifest_digest=cast(str, payload["manifest_digest"]),
        freeze_digest=cast(str, payload["freeze_digest"]),
        only=cast(str, payload["only"]),
        slice_id=cast(str, payload["slice_id"]),
        artifact_ids=tuple(cast(Sequence[str], payload["artifact_ids"])),
        versions=tuple(tuple(cast(Sequence[str], row)) for row in cast(Sequence[Sequence[str]], payload["versions"])),
    )
    _validate_context(context)
    return context


def discover_hunt_runner_context(
    source: Path,
    manifest: Path,
    *,
    producer: str,
    freeze_digest: str,
) -> HuntRunContext:
    """Resolve the content-addressed runner identity for a documented raw-run handoff."""
    if producer != HUNT_RUNNER_PRODUCER:
        raise ValueError(f"unsupported hunt producer: {producer}")
    manifest_bytes = Path(manifest).read_bytes()
    if not manifest_bytes:
        raise ValueError("hunt handoff manifest is empty")
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    paths: list[Path] = []
    for path in Path(source).glob("*.json"):
        value = _read_json(path, "hunt runner candidate")
        if isinstance(value, dict) and "artifact_id" in value:
            paths.append(path)
    artifacts = _read_attempts(tuple(sorted(paths)))
    artifact = artifacts[0]
    if len(artifact.configurations) != 1:
        raise ValueError("hunt runner configuration artifact is ambiguous")
    if artifact.data_digests != {"manifest": manifest_digest}:
        raise ValueError("hunt runner manifest identity does not match supplied manifest")
    configuration = artifact.configurations[0]
    context = HuntRunContext(
        producer=producer,
        program_id=artifact.program_id,
        mask=tuple(artifact.mask),
        manifest_digest=manifest_digest,
        freeze_digest=freeze_digest,
        only=cast(str, configuration.get("only")),
        slice_id=cast(str, configuration.get("slice")),
        artifact_ids=tuple(sorted(item.artifact_id for item in artifacts)),
        versions=tuple(sorted(artifact.versions.items())),
    )
    _validate_context(context)
    return context


__all__ = [
    "HUNT_RUNNER_PRODUCER",
    "HuntRunContext",
    "discover_hunt_runner_context",
    "persist_hunt_runner_records",
    "read_hunt_handoff_context",
    "read_hunt_runner_records",
]
