"""Private, append-only sourcing checkpoints. No identity-bearing data leaves this directory."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import time
from contextlib import contextmanager
from pathlib import Path

STAGES = ("advisories", "resolution", "eligibility", "extraction", "completion")


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


class ResumeMismatch(ValueError):
    def __init__(self, parameters):
        self.parameters = parameters
        super().__init__("resume_inputs_changed")


class Stopped(Exception):
    pass


def external(root: Path, path: Path) -> Path:
    path = path.expanduser().resolve()
    # Also reject the actual checkout when a different --root is supplied.
    if any(path.is_relative_to(p.resolve()) for p in (root, Path(__file__).resolve().parents[2])):
        raise ValueError("cache_inside_repository")
    return path


def atomic(path: Path, payload: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as handle:
        os.chmod(temporary, 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    def __init__(self, path: Path, *, max_hours=None, clock=None, rate_limit=None):
        if max_hours is not None and (not math.isfinite(max_hours) or max_hours < 0):
            raise ValueError("invalid_max_hours")
        self.path = path
        self.clock = clock or time.monotonic
        self.started = self.clock()
        self.max_seconds = None if max_hours is None else max_hours * 3600
        self.rate_limit = rate_limit or (lambda: {})
        self.rows = {stage: {} for stage in STAGES}
        self.elapsed_before = 0.0
        self.last = None
        self.previous_rate = {}

    @contextmanager
    def open(self, parameters):
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.path / "LOCK").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("journal_busy") from None
            metadata = self.path / "inputs.json"
            if metadata.exists():
                old = json.loads(metadata.read_bytes())
                # Only current, fixed parameter labels can enter stdout.
                changed = [key for key in parameters if old.get(key) != parameters[key]]
                if old.keys() != parameters.keys():
                    changed.append("parameter_schema")
                if changed:
                    raise ResumeMismatch(changed)
            else:
                if any(self.path.glob("*.jsonl")):
                    raise ValueError("journal_missing_inputs")
                atomic(metadata, encoded(parameters))
            for stage in STAGES:
                path = self.path / (stage + ".jsonl")
                if not path.exists():
                    continue
                with path.open("rb") as handle:
                    for line in handle:
                        # Fail closed on torn/corrupt writes; never silently lose a completed unit.
                        if not line.endswith(b"\n"):
                            raise ValueError("journal_incomplete_record")
                        row = json.loads(line)
                        if row["id"] in self.rows[stage]:
                            raise ValueError("journal_duplicate_unit")
                        self.rows[stage][row["id"]] = row["value"]
                        if row["elapsed_seconds"] >= self.elapsed_before:
                            self.elapsed_before = row["elapsed_seconds"]
                            self.last = {"stage": stage, "id": row["id"]}
                            self.previous_rate = row["rate_limit"]
            self.progress("sourcing")
            yield self

    def boundary(self):
        reason = None
        if (self.path / "STOP").exists():
            reason = "STOP"
        elif self.max_seconds is not None and self.clock() - self.started >= self.max_seconds:
            reason = "max_hours"
        if reason:
            self.progress("stopped", reason=reason)
            raise Stopped(reason)

    def elapsed(self):
        return self.elapsed_before + self.clock() - self.started

    def progress(self, status, **extra):
        atomic(
            self.path / "progress.json",
            encoded(
                {
                    "status": status,
                    "counts": {stage: len(rows) for stage, rows in self.rows.items()},
                    "last_unit": self.last,
                    "rate_limit": self.rate_limit() or self.previous_rate,
                    "elapsed_seconds": self.elapsed(),
                    **extra,
                }
            ),
        )

    def put(self, stage, key, value):
        if key in self.rows[stage]:
            raise ValueError("journal_duplicate_unit")
        row = {"id": key, "value": value, "elapsed_seconds": self.elapsed(), "rate_limit": self.rate_limit() or self.previous_rate}
        path = self.path / (stage + ".jsonl")
        with path.open("ab") as handle:
            os.chmod(path, 0o600)
            handle.write(encoded(row) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        sync_directory(self.path)
        self.rows[stage][key] = value
        self.last = {"stage": stage, "id": key}
        self.progress("sourcing")


class ResolvedGitHub:
    """Persist successful repository lookups and 404s used by both eligibility and the fix index."""

    def __init__(self, github, journal):
        self.github, self.journal = github, journal

    def __getattr__(self, name):
        return getattr(self.github, name)

    def get_repo(self, name):
        from .eligibility import RepositoryNotFound, normalize

        key = normalize(name)
        if key not in self.journal.rows["resolution"]:
            self.journal.boundary()
            try:
                value = self.github.get_repo(key)
            except RepositoryNotFound:
                value = None
            self.journal.put("resolution", key, value)
        value = self.journal.rows["resolution"][key]
        if value is None:
            raise RepositoryNotFound("not_found")
        return value
