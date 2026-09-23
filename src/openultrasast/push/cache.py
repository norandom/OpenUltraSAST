"""Private local artifacts with bounded locks, complete publication and leased eviction."""

from __future__ import annotations

import contextlib
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
        # The last full scan of what the cache holds, keyed by the root directory's modification stamp. Every
        # publication used to list and stat the whole cache to total its size, so a push that stores one
        # answer per question paid O(entries) per answer: on a WordPress plugin, 12,115 entries in, each new
        # answer cost ~50,000 filesystem calls and the evidence pass never finished a 7,200 s case. Any change
        # another process makes -- an entry added, evicted or removed -- moves the stamp and forces a rescan,
        # so the size limit stays exact under concurrent pushes; our own changes update the tally in place.
        self._usage: tuple[int, list[tuple[float, Path, int]], int] | None = None
        self._room: tuple[list[tuple[float, Path, int]], int] = ([], 0)
        # Every lock stripe exists from the start, so creating one on first use never moves the root's stamp
        # and invalidates the remembered scan. A stripe that cannot be created is left to `_lock`, as before.
        for name in [".publication-lock", *(f".lock-{stripe:02d}" for stripe in range(64))]:
            with contextlib.suppress(OSError):
                os.close(os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600))

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
        remembered = self._usage
        self._usage = None  # restored only by a publication that completes
        if remembered is not None and remembered[0] == self.root.stat().st_mtime_ns:
            entries, used = list(remembered[1]), remembered[2]
        else:
            scanned = self._scan(budget)
            if scanned is None:
                return False
            entries, used = scanned
        kept: list[tuple[float, Path, int]] = []
        fits = False
        for mtime, path, size in sorted(entries):
            if fits or used + incoming <= self.max_bytes:
                fits = True
                kept.append((mtime, path, size))
                continue
            if path.name == key or path.name.startswith(".pending-"):
                self._remove(path, budget)
                used -= size
            else:
                with self._lock(self._bucket(path.name), budget, wait=False) as locked:
                    if locked:
                        self._remove(path, budget)
                        used -= size
                    else:
                        kept.append((mtime, path, size))
        self._room = (kept, used)
        return used + incoming <= self.max_bytes

    def _scan(self, budget: ExecutionBudget) -> tuple[list[tuple[float, Path, int]], int] | None:
        """Every entry and pending publication with its size, or ``None`` when the deadline passed."""
        entries = []
        used = 0
        for path in self.root.iterdir():
            if time.monotonic() >= budget.deadline_monotonic:
                return None
            if path.is_symlink():
                continue
            if path.is_dir() and (_KEY.fullmatch(path.name) or path.name.startswith(".pending-")):
                size = 0
                for child in path.iterdir():
                    if time.monotonic() >= budget.deadline_monotonic:
                        return None
                    size += child.lstat().st_size
                used += size
                entries.append((path.stat().st_mtime, path, size))
        return entries, used

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
                    # No fsync. Durability is not what makes an entry safe to read: `_entry` rejects anything
                    # whose manifest receipt, payload size or payload SHA-256 does not check, so a write torn
                    # by a crash is a MISS, never a wrong answer. Two fsyncs per entry were ~18 ms, and a push
                    # publishes one entry per question -- about 22,000 on a WordPress plugin, minutes of the
                    # budget spent making a cache survive power loss that it already survives by verification.
                    with (pending / "manifest.json").open("xb") as stream:
                        stream.write(manifest)
                    (pending / "manifest.json").chmod(0o600)
                    if time.monotonic() >= budget.deadline_monotonic:
                        raise TimeoutError("deadline_exhausted")
                    existing = self.root / key
                    if existing.exists() or existing.is_symlink():
                        self._remove(existing, budget)
                    os.replace(pending, existing)
                    pending = None
                    kept, used = self._room
                    replaced = [entry for entry in kept if entry[1].name == key]
                    kept = [entry for entry in kept if entry[1].name != key]
                    used -= sum(entry[2] for entry in replaced)
                    kept.append((existing.stat().st_mtime, existing, size + len(manifest)))
                    self._usage = (self.root.stat().st_mtime_ns, kept, used + size + len(manifest))
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
