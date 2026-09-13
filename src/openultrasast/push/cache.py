"""Private local artifacts with bounded locks, complete publication and leased eviction."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from openultrasast.contracts import Contract
from openultrasast.cpg.artifact import digest_value, graph_bytes, read_bytes
from openultrasast.cpg.backend import _DeadlineExpired, _remove_owned_tree
from openultrasast.model.contracts import ExecutionBudget

_KEY = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CacheEntry:
    path: Path
    metadata: dict[str, Any]


class ArtifactCache:
    def __init__(self, root: Path, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("cache_size_must_be_positive")
        if root.is_symlink():
            raise ValueError("cache_root_symlink")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = root.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("cache_root_must_be_private_and_owned")
        self.root = root.resolve()
        self.max_bytes = max_bytes
        self.last_reason = ""
        self.hits = 0
        self.misses = 0

    @contextmanager
    def _lock(self, name: str, budget: ExecutionBudget, *, shared: bool = False, wait: bool = True) -> Iterator[bool]:
        fd = None
        acquired = False
        try:
            fd = os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("cache_lock_not_regular")
            while time.monotonic() < budget.deadline_monotonic:
                try:
                    fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if not wait:
                        break
                    time.sleep(min(0.01, max(0, budget.deadline_monotonic - time.monotonic())))
            yield acquired
        finally:
            if fd is not None:
                if acquired:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    @staticmethod
    def _bucket(key: str) -> str:
        # Fixed lock stripes bound lock-file growth; never unlink a live lock inode.
        return f".lock-{int(key[:2], 16) % 64:02d}"

    def _entry(self, key: str, budget: ExecutionBudget) -> CacheEntry | None:
        directory = self.root / key
        if directory.is_symlink() or not directory.is_dir():
            return None
        manifest_path = directory / "manifest.json"
        if manifest_path.stat().st_size > 1024 * 1024:
            return None
        manifest = json.loads(read_bytes(manifest_path, budget.deadline_monotonic))
        if (
            not isinstance(manifest, dict)
            or manifest.get("version") != 1
            or manifest.get("key") != key
            or manifest.get("complete") is not True
        ):
            return None
        receipt = manifest.pop("receipt", None)
        if receipt != digest_value(manifest):
            return None
        if not isinstance(manifest.get("metadata"), dict):
            return None
        payload = directory / "payload"
        if payload.stat().st_size != manifest.get("size") or payload.stat().st_size > self.max_bytes:
            return None
        if graph_bytes(payload, budget.deadline_monotonic) != manifest.get("sha256"):
            return None
        return CacheEntry(payload, manifest["metadata"])

    @contextmanager
    def lookup(self, key: str, budget: ExecutionBudget) -> Iterator[CacheEntry | None]:
        entry = None
        if not _KEY.fullmatch(key):
            self.misses += 1
            self.last_reason = "invalid_cache_key"
            yield None
            return
        with ExitStack() as stack:
            try:
                locked = stack.enter_context(self._lock(self._bucket(key), budget, shared=True))
                if locked:
                    entry = self._entry(key, budget)
            except (OSError, ValueError, TimeoutError):
                entry = None
            if entry is None:
                self.misses += 1
                self.last_reason = "cache_miss_or_incompatible"
            else:
                self.hits += 1
            yield entry

    def get_json(self, key: str, *, kind: str, budget: ExecutionBudget) -> Any:
        with self.lookup(key, budget) as entry:
            if entry is None or entry.metadata != {"kind": kind} or entry.path.stat().st_size > 32 * 1024**2:
                return None
            try:
                return json.loads(read_bytes(entry.path, budget.deadline_monotonic))
            except (OSError, ValueError, TimeoutError):
                return None

    def put_json(self, key: str, payload: object, *, kind: str, budget: ExecutionBudget, complete: bool) -> bool:
        if not complete or time.monotonic() >= budget.deadline_monotonic:
            return False
        try:
            data = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
        except (TypeError, ValueError):
            return False
        return self.publish(key, data, {"kind": kind}, budget, complete=complete)

    def _remove(self, root: Path, budget: ExecutionBudget) -> None:
        _remove_owned_tree(root, budget.deadline_monotonic)

    def _make_room(self, incoming: int, key: str, budget: ExecutionBudget) -> bool:
        entries = []
        used = 0
        for path in self.root.iterdir():
            if time.monotonic() >= budget.deadline_monotonic:
                return False
            if path.is_symlink():
                continue
            if path.is_dir() and (_KEY.fullmatch(path.name) or path.name.startswith(".pending-")):
                size = 0
                for child in path.iterdir():
                    if time.monotonic() >= budget.deadline_monotonic:
                        return False
                    size += child.lstat().st_size
                used += size
                entries.append((path.stat().st_mtime, path, size))
        for _, path, size in sorted(entries):
            if used + incoming <= self.max_bytes:
                return True
            if path.name == key or path.name.startswith(".pending-"):
                self._remove(path, budget)
                used -= size
            else:
                with self._lock(self._bucket(path.name), budget, wait=False) as locked:
                    if locked:
                        self._remove(path, budget)
                        used -= size
        return used + incoming <= self.max_bytes

    def publish(self, key: str, payload: bytes | Path, metadata: dict[str, Any], budget: ExecutionBudget, *, complete: bool = True) -> bool:
        if not complete or not _KEY.fullmatch(key):
            self.last_reason = "partial_or_invalid_cache_publication"
            return False
        pending = None
        try:
            with self._lock(self._bucket(key), budget) as locked:
                if not locked:
                    return False
                with self._lock(".publication-lock", budget) as publishing:
                    if not publishing:
                        return False
                    size = len(payload) if isinstance(payload, bytes) else payload.stat().st_size
                    if not size or size > self.max_bytes:
                        return False
                    sha = (
                        hashlib.sha256(payload).hexdigest()
                        if isinstance(payload, bytes)
                        else graph_bytes(payload, budget.deadline_monotonic)
                    )
                    record = {"version": 1, "key": key, "complete": True, "metadata": metadata, "size": size, "sha256": sha}
                    record["receipt"] = digest_value(record)
                    manifest = json.dumps(record, sort_keys=True).encode()
                    if len(manifest) > 1024 * 1024 or not self._make_room(size + len(manifest), key, budget):
                        return False
                    pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.root))
                    target = pending / "payload"
                    if isinstance(payload, bytes):
                        with target.open("xb") as stream:
                            for offset in range(0, len(payload), 1024 * 1024):
                                if time.monotonic() >= budget.deadline_monotonic:
                                    raise TimeoutError("deadline_exhausted")
                                stream.write(payload[offset : offset + 1024 * 1024])
                    elif graph_bytes(payload, budget.deadline_monotonic, target) != sha:
                        raise ValueError("publication_source_changed")
                    target.chmod(0o600)
                    with target.open("rb") as stream:
                        os.fsync(stream.fileno())
                    with (pending / "manifest.json").open("xb") as stream:
                        stream.write(manifest)
                        stream.flush()
                        os.fsync(stream.fileno())
                    (pending / "manifest.json").chmod(0o600)
                    if time.monotonic() >= budget.deadline_monotonic:
                        raise TimeoutError("deadline_exhausted")
                    existing = self.root / key
                    if existing.exists() or existing.is_symlink():
                        self._remove(existing, budget)
                    os.replace(pending, existing)
                    pending = None
                    return True
        except (OSError, ValueError, TimeoutError, _DeadlineExpired) as error:
            self.last_reason = type(error).__name__
            return False
        finally:
            if pending is not None:
                try:
                    _remove_owned_tree(pending, budget.deadline_monotonic + budget.cancellation_allowance_seconds)
                except (OSError, _DeadlineExpired):
                    self.last_reason = "cache_partial_cleanup_incomplete"


@dataclass(frozen=True)
class SemanticKeys(Contract):
    facts: str
    queries: str
    configuration: str
    ranking: str
    admission: str
    model: str
    eligibility: str
    mode: str

    def query(self, *, graph: str, kind: str, request: object, context: object) -> str:
        return digest_value(
            {
                "layer": "query-v1",
                "graph": graph,
                "kind": kind,
                "request": request,
                "context": context,
                "facts": self.facts,
                "queries": self.queries,
                "configuration": self.configuration,
            }
        )

    def comparison(self, *, base: str, head: str, context: object, evidence: object) -> str:
        return digest_value(
            {"layer": "comparison-v1", "base": base, "head": head, "context": context, "evidence": evidence, "semantics": asdict(self)}
        )

    def result(self, *, comparisons: object, scope: object) -> str:
        return digest_value({"layer": "result-v1", "comparisons": comparisons, "scope": scope, "semantics": asdict(self)})
