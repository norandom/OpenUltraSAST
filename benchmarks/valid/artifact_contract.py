"""Strict benchmark-owned persistence for canonical v2 artifacts."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TypeAlias, cast

from openultrasast.core.canonical import JsonValue, content_digest

BENCHMARK_ARTIFACT_SCHEMA = "openultrasast.benchmark-artifact.v2"
ArtifactPayload: TypeAlias = Mapping[str, JsonValue]
ArtifactRows: TypeAlias = Sequence[Mapping[str, JsonValue]]
_RESERVED = frozenset({"schema_version", "artifact_kind", "artifact_digest"})
_SEQUENCE_KEYS = frozenset({"artifact_mode", "sequence_count", "sequence_digest", "rows"})
_JSONL_HEADER_KEYS = frozenset({"artifact_mode", "sequence_count", "sequence_digest"})
_JSONL_ROW_KEYS = frozenset({"sequence_index", "sequence_count", "sequence_digest", "artifact"})


def _canonical_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_canonical_value(item) for item in value)
    raise ValueError(f"unsupported benchmark artifact value: {type(value).__name__}")


def _kind(kind: str) -> str:
    if not isinstance(kind, str) or not kind:
        raise ValueError("benchmark artifact kind must be nonempty text")
    return kind


def _artifact_digest(kind: str, payload: Mapping[str, JsonValue]) -> str:
    return content_digest(
        {
            "schema_version": BENCHMARK_ARTIFACT_SCHEMA,
            "artifact_kind": kind,
            "payload": _canonical_value(payload),
        }
    )


def benchmark_artifact(kind: str, payload: ArtifactPayload) -> dict[str, JsonValue]:
    """Create one v2 artifact from an unwrapped payload."""
    kind = _kind(kind)
    if not isinstance(payload, Mapping):
        raise ValueError("benchmark artifact payload must be a mapping")
    if _RESERVED.intersection(payload):
        raise ValueError("benchmark artifact payload uses reserved metadata")
    value = {str(key): _canonical_value(item) for key, item in payload.items()}
    return {
        **value,
        "schema_version": BENCHMARK_ARTIFACT_SCHEMA,
        "artifact_kind": kind,
        "artifact_digest": _artifact_digest(kind, value),
    }


def benchmark_payload(value: object, *, expected_kind: str) -> dict[str, JsonValue]:
    """Strictly validate one v2 artifact and return its domain payload."""
    expected_kind = _kind(expected_kind)
    if not isinstance(value, dict):
        raise ValueError("benchmark artifact metadata is missing")
    if _RESERVED.intersection(value) != _RESERVED:
        raise ValueError("benchmark artifact metadata is missing or incomplete")
    raw = {str(key): item for key, item in value.items() if key not in _RESERVED}
    canonical_raw = cast(dict[str, JsonValue], _canonical_value(raw))
    if (
        value["schema_version"] != BENCHMARK_ARTIFACT_SCHEMA
        or value["artifact_kind"] != expected_kind
        or value["artifact_digest"] != _artifact_digest(expected_kind, canonical_raw)
    ):
        raise ValueError("benchmark artifact metadata does not match payload")
    return cast(dict[str, JsonValue], raw)


def encode_benchmark_artifact(kind: str, payload: ArtifactPayload, *, indent: int | None = 2) -> str:
    """Encode one canonical v2 artifact."""
    return json.dumps(benchmark_artifact(kind, payload), sort_keys=True, indent=indent, ensure_ascii=False)


@contextmanager
def _target_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.with_name(f".{path.name}.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_locked(path: Path, content: bytes, *, replace: bool) -> None:
    if path.exists():
        existing = path.read_bytes()
        if existing == content:
            return
        if not replace:
            raise ValueError(f"benchmark artifact conflict: {path}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as temporary:
            temporary_name = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _write_bytes(path: Path, content: bytes, *, replace: bool) -> None:
    path = Path(path)
    with _target_lock(path):
        _write_locked(path, content, replace=replace)


def write_benchmark_artifact(path: Path, kind: str, payload: ArtifactPayload, *, replace: bool = False) -> None:
    """Atomically create one artifact; identical writes are idempotent."""
    _write_bytes(path, (encode_benchmark_artifact(kind, payload) + "\n").encode(), replace=replace)


def read_benchmark_artifact(path: Path, expected_kind: str) -> dict[str, JsonValue]:
    """Read and strictly validate one artifact from disk."""
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"benchmark artifact unreadable: {path}") from error
    return benchmark_payload(value, expected_kind=expected_kind)


def _ordered_digest(artifacts: Sequence[Mapping[str, JsonValue]]) -> str:
    return content_digest(
        tuple(
            {"sequence_index": index, "artifact_digest": cast(str, artifact["artifact_digest"])} for index, artifact in enumerate(artifacts)
        )
    )


def _sequence_artifact(kind: str, rows: ArtifactRows) -> dict[str, JsonValue]:
    artifacts = tuple(benchmark_artifact(f"{kind}.item", row) for row in rows)
    members: tuple[JsonValue, ...] = tuple({"sequence_index": index, "artifact": artifact} for index, artifact in enumerate(artifacts))
    return benchmark_artifact(
        kind,
        {
            "artifact_mode": "ordered-sequence",
            "sequence_count": len(artifacts),
            "sequence_digest": _ordered_digest(artifacts),
            "rows": members,
        },
    )


def write_benchmark_sequence(path: Path, kind: str, rows: ArtifactRows, *, replace: bool = False) -> None:
    """Persist an exact ordered collection with count, indices, and aggregate digest."""
    value = _sequence_artifact(_kind(kind), rows)
    content = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    _write_bytes(path, content, replace=replace)


def _sequence_payload(value: object, kind: str) -> tuple[dict[str, JsonValue], ...]:
    payload = benchmark_payload(value, expected_kind=kind)
    if set(payload) != _SEQUENCE_KEYS or payload.get("artifact_mode") != "ordered-sequence":
        raise ValueError("benchmark sequence metadata does not match contract")
    count = payload.get("sequence_count")
    sequence_digest = payload.get("sequence_digest")
    members = payload.get("rows")
    if (
        not isinstance(count, int)
        or count < 0
        or not isinstance(sequence_digest, str)
        or not isinstance(members, Sequence)
        or isinstance(members, (str, bytes))
    ):
        raise ValueError("benchmark sequence metadata is invalid")
    if len(members) != count:
        raise ValueError("benchmark sequence count mismatch")
    rows: list[dict[str, JsonValue]] = []
    artifacts: list[dict[str, JsonValue]] = []
    for index, member in enumerate(members):
        if not isinstance(member, dict) or set(member) != {"sequence_index", "artifact"} or member.get("sequence_index") != index:
            raise ValueError("benchmark sequence index mismatch")
        artifact = member.get("artifact")
        rows.append(benchmark_payload(artifact, expected_kind=f"{kind}.item"))
        artifacts.append(cast(dict[str, JsonValue], artifact))
    digests = tuple(cast(str, artifact["artifact_digest"]) for artifact in artifacts)
    if len(set(digests)) != len(digests) or sequence_digest != _ordered_digest(artifacts):
        raise ValueError("benchmark sequence digest mismatch or duplicate row")
    return tuple(rows)


def read_benchmark_sequence(path: Path, expected_kind: str) -> tuple[dict[str, JsonValue], ...]:
    """Read and validate a complete ordered collection."""
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"benchmark sequence unreadable: {path}") from error
    return _sequence_payload(value, _kind(expected_kind))


def _jsonl_bytes(kind: str, rows: ArtifactRows) -> bytes:
    items = tuple(benchmark_artifact(f"{kind}.item", row) for row in rows)
    sequence_digest = _ordered_digest(items)
    header = benchmark_artifact(
        f"{kind}.sequence",
        {"artifact_mode": "ordered-jsonl", "sequence_count": len(items), "sequence_digest": sequence_digest},
    )
    encoded = [json.dumps(header, sort_keys=True, ensure_ascii=False)]
    for index, artifact in enumerate(items):
        encoded.append(
            json.dumps(
                benchmark_artifact(
                    f"{kind}.row",
                    {
                        "sequence_index": index,
                        "sequence_count": len(items),
                        "sequence_digest": sequence_digest,
                        "artifact": artifact,
                    },
                ),
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    return ("\n".join(encoded) + "\n").encode()


def _jsonl_rows(content: bytes, kind: str) -> tuple[dict[str, JsonValue], ...]:
    try:
        values = tuple(json.loads(line) for line in content.decode().splitlines())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("benchmark JSONL is unreadable") from error
    if not values:
        raise ValueError("benchmark JSONL metadata is missing")
    header = benchmark_payload(values[0], expected_kind=f"{kind}.sequence")
    if set(header) != _JSONL_HEADER_KEYS or header.get("artifact_mode") != "ordered-jsonl":
        raise ValueError("benchmark JSONL metadata does not match contract")
    count = header.get("sequence_count")
    sequence_digest = header.get("sequence_digest")
    if not isinstance(count, int) or count < 0 or not isinstance(sequence_digest, str) or len(values) != count + 1:
        raise ValueError("benchmark JSONL count mismatch")
    rows: list[dict[str, JsonValue]] = []
    items: list[dict[str, JsonValue]] = []
    for index, value in enumerate(values[1:]):
        member = benchmark_payload(value, expected_kind=f"{kind}.row")
        if set(member) != _JSONL_ROW_KEYS:
            raise ValueError("benchmark JSONL row metadata does not match contract")
        if (
            member.get("sequence_index") != index
            or member.get("sequence_count") != count
            or member.get("sequence_digest") != sequence_digest
        ):
            raise ValueError("benchmark JSONL sequence binding mismatch")
        artifact = member.get("artifact")
        rows.append(benchmark_payload(artifact, expected_kind=f"{kind}.item"))
        items.append(cast(dict[str, JsonValue], artifact))
    digests = tuple(cast(str, item["artifact_digest"]) for item in items)
    if len(set(digests)) != len(digests) or sequence_digest != _ordered_digest(items):
        raise ValueError("benchmark JSONL digest mismatch or duplicate row")
    return tuple(rows)


def write_benchmark_jsonl(path: Path, kind: str, rows: ArtifactRows, *, replace: bool = False) -> None:
    """Atomically persist an ordered JSONL manifest and its bound rows."""
    _write_bytes(path, _jsonl_bytes(_kind(kind), rows), replace=replace)


def read_benchmark_jsonl(path: Path, expected_kind: str) -> tuple[dict[str, JsonValue], ...]:
    """Read and validate a complete ordered JSONL artifact."""
    try:
        content = Path(path).read_bytes()
    except OSError as error:
        raise ValueError(f"benchmark JSONL unreadable: {path}") from error
    return _jsonl_rows(content, _kind(expected_kind))


def append_benchmark_jsonl(path: Path, kind: str, row: ArtifactPayload) -> None:
    """Append one row under the target lock and rewrite the bound sequence atomically."""
    path = Path(path)
    kind = _kind(kind)
    with _target_lock(path):
        rows = _jsonl_rows(path.read_bytes(), kind) if path.exists() else ()
        _write_locked(path, _jsonl_bytes(kind, (*rows, row)), replace=True)


__all__ = [
    "BENCHMARK_ARTIFACT_SCHEMA",
    "append_benchmark_jsonl",
    "benchmark_artifact",
    "benchmark_payload",
    "encode_benchmark_artifact",
    "read_benchmark_artifact",
    "read_benchmark_jsonl",
    "read_benchmark_sequence",
    "write_benchmark_artifact",
    "write_benchmark_jsonl",
    "write_benchmark_sequence",
]
