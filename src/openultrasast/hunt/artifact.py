"""Content-addressed run metadata and budget accounting without a model runtime."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .table import canonical_json

# Persisted attempt sequences use the portable signed 64-bit integer domain.
MAX_ATTEMPT_ORDINAL = (1 << 63) - 1
_UNSUPPORTED_DIRECTORY_SYNC = frozenset(
    error for name in ("EINVAL", "ENOTSUP", "EOPNOTSUPP") if (error := getattr(errno, name, None)) is not None
)


@contextmanager
def _artifact_lock(directory: Path) -> Iterator[None]:
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / ".run-artifact.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _sync_directory(directory: Path) -> None:
    """Durably publish a directory entry where the platform supports it."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        if error.errno in _UNSUPPORTED_DIRECTORY_SYNC:
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in _UNSUPPORTED_DIRECTORY_SYNC:
            raise
    finally:
        os.close(descriptor)


def _persist_sequence(directory: Path, ordinal: int) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".attempt-sequence.", text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(f"{ordinal}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / ".attempt-sequence")
        _sync_directory(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _reserve_attempt_ordinal(directory: Path) -> int:
    sequence = directory / ".attempt-sequence"
    try:
        content = sequence.read_text()
    except FileNotFoundError:
        if _valid_attempt_artifact_exists(directory):
            raise ValueError("run attempt sequence is missing for existing artifacts; explicit recovery is required") from None
        previous = 0
    except OSError as error:
        raise ValueError("run attempt sequence is unreadable") from error
    else:
        try:
            previous = int(content.strip())
        except ValueError as error:
            raise ValueError("run attempt sequence is unreadable") from error
    if previous < 0:
        raise ValueError("run attempt sequence is invalid")
    if previous >= MAX_ATTEMPT_ORDINAL:
        raise ValueError("run attempt sequence is exhausted")
    ordinal = previous + 1
    _persist_sequence(directory, ordinal)
    return ordinal


def _create_only(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() == content:
            return
        raise ValueError(f"run artifact conflict: {path}")
    try:
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _sync_directory(path.parent)
    except FileExistsError:
        if path.read_bytes() != content:
            raise ValueError(f"run artifact conflict: {path}") from None


def _exhausted(usage: Mapping[str, float], budget: Mapping[str, float]) -> bool:
    for name in ("usd", "calls"):
        if name in budget:
            bound = budget[name]
            if not math.isfinite(bound) or bound < 0:
                raise ValueError("budget bounds must be finite and non-negative")
            if usage.get(name, 0) >= bound:
                return True
    return False


@dataclass
class RunArtifact:
    program_id: str
    schema_version: int
    mask: tuple[str, ...] | list[str]
    data_digests: dict[str, str]
    configurations: list[dict[str, Any]]
    usage: dict[str, float]
    versions: dict[str, str]
    created: str
    attempt_ordinal: int = 0

    @property
    def artifact_id(self) -> str:
        payload = asdict(self)
        if not self.attempt_ordinal:
            payload.pop("attempt_ordinal")
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def finish(self, budget: Mapping[str, float]) -> RunArtifact | None:
        """Return no completed artifact when either registered budget is exhausted."""
        return None if _exhausted(self.usage, budget) else self

    def write(
        self,
        directory: Path | str,
        *,
        budget: Mapping[str, float] | None = None,
        reserve_attempt: bool = False,
    ) -> Path | None:
        """Write metadata under its content id, after an optional final budget check."""
        if budget is not None and self.finish(budget) is None:
            return None
        directory = Path(directory)
        with _artifact_lock(directory):
            if reserve_attempt and not self.attempt_ordinal:
                self.attempt_ordinal = _reserve_attempt_ordinal(directory)
            path = directory / f"{self.artifact_id}.json"
            content = (canonical_json({**asdict(self), "artifact_id": self.artifact_id}) + "\n").encode()
            _create_only(path, content)
        return path

    @classmethod
    def read(cls, path: Path | str) -> RunArtifact:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        identifier = payload.pop("artifact_id", None)
        payload["mask"] = tuple(payload["mask"])
        payload.setdefault("attempt_ordinal", 0)
        artifact = cls(**payload)
        if identifier != artifact.artifact_id:
            raise ValueError("run artifact id does not match its contents")
        return artifact


def _valid_attempt_artifact_exists(directory: Path) -> bool:
    for path in directory.glob("*.json"):
        try:
            artifact = RunArtifact.read(path)
        except (OSError, TypeError, ValueError):
            continue
        if path.stem == artifact.artifact_id:
            return True
    return False


@dataclass
class UsageLedger:
    """Count paid calls, replay hits, spend and elapsed call time separately."""

    artifact: RunArtifact | None = None
    rows: list[dict[str, float]] = field(default_factory=list)

    @property
    def usage(self) -> dict[str, float]:
        return {name: sum(row[name] for row in self.rows) for name in ("usd", "calls", "replay_hits", "wall_seconds")}

    def add(self, call_row: Mapping[str, Any]) -> None:
        replay_hits = call_row.get("replay_hits", int(bool(call_row.get("replay_hit", False))))
        values = {
            "usd": call_row.get("usd", 0),
            "calls": call_row.get("calls", 0 if replay_hits else 1),
            "replay_hits": replay_hits,
            "wall_seconds": call_row.get("wall_seconds", 0),
        }
        if any(not isinstance(v, int | float) or not math.isfinite(v) or v < 0 for v in values.values()):
            raise ValueError("usage values must be finite and non-negative")
        if any(int(values[k]) != values[k] for k in ("calls", "replay_hits")):
            raise ValueError("call and replay counts must be integers")
        self.rows.append(values)

    def exhausted(self, budget: Mapping[str, float]) -> bool:
        return _exhausted(self.usage, budget)

    def finish(self, budget: Mapping[str, float], artifact: RunArtifact | None = None) -> RunArtifact | None:
        """Attach measured usage to a completed run, or retain only this partial ledger."""
        if self.exhausted(budget):
            return None
        result = artifact if artifact is not None else self.artifact
        if result is None:
            raise ValueError("finish needs a run artifact")
        result.usage = self.usage
        return result
