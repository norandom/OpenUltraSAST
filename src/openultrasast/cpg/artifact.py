"""Backend-owned graph provenance and live resource boundary (pre-push Req 4.3, 7.3).

Structural manifests carry provenance; the backend reads source bytes and seals a named
graph census, then verifies graph bytes and compatibility before issuing isolated leases.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from openultrasast.contracts import Contract


@dataclass(frozen=True)
class GraphIdentity(Contract):
    source_digest: str
    declarations_digest: str
    exclusions_digest: str
    unit: str
    language: str
    engine_version: str
    frontend: str
    frontend_version: str
    overlay_semantics: tuple[str, ...]
    overlay_options: tuple[tuple[str, str], ...]
    frontend_options: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        for options in (self.overlay_options, self.frontend_options):
            if len({key for key, _ in options}) != len(options):
                raise ValueError("graph option names must be unique")


@dataclass(frozen=True)
class GraphCensus(Contract):
    files: int
    methods: int
    calls: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if min(self.files, self.methods, self.calls) < 0:
            raise ValueError("graph census counts must be nonnegative")


@dataclass(frozen=True)
class GraphArtifact(Contract):
    identity: GraphIdentity
    graph_digest: str
    source_bytes: int
    census: GraphCensus
    completeness: Literal["complete", "partial"]
    diagnostics: tuple[str, ...]
    source_root: str = "relative"
    source_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.source_bytes < 0:
            raise ValueError("source byte count must be nonnegative")
        if self.completeness == "complete" and (not self.source_bytes or not self.census.files or self.diagnostics):
            raise ValueError("complete graph requires readable source, a file census and no incomplete diagnostics")
        if self.completeness == "partial" and not self.diagnostics:
            raise ValueError("partial graph requires a recorded reason")


class GraphLease(Protocol):
    """A backend-issued live lease; never reconstructed from a JSON manifest.

    The backend validates the artifact before issuing the lease and isolates loading
    when it may mutate graph bytes. The consumer owns releasing it exactly once; the
    backend's release is idempotent and bounded by the supplied monotonic deadline.
    A cached artifact survives release.
    """

    @property
    def artifact(self) -> GraphArtifact: ...

    @property
    def path(self) -> Path: ...

    def close(self, *, deadline_monotonic: float) -> None: ...


def digest_value(value: object) -> str:
    import hashlib
    import json

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def read_bytes(path: Path, deadline: float) -> bytes:
    """Read a regular local file without following a substituted final symlink."""
    import os
    import stat
    import time

    chunks: list[bytes] = []
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("artifact_not_regular")
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline_exhausted")
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def source_inventory(root: Path, deadline: float) -> tuple[str, int, tuple[str, ...]]:
    import hashlib
    import os
    import time

    rows = []
    size = 0
    if root.is_symlink():
        raise ValueError("symlink_source_root")

    def unreadable(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        if time.monotonic() >= deadline:
            raise TimeoutError("deadline_exhausted")
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise ValueError("symlink_source")
        for name in sorted(files):
            path = Path(directory) / name
            data = read_bytes(path, deadline)
            size += len(data)
            rows.append((path.relative_to(root).as_posix(), hashlib.sha256(data).hexdigest()))
    if not rows or not size:
        raise ValueError("source_unreadable_or_empty")
    rows.sort()
    return digest_value(rows), size, tuple(path for path, _ in rows)


@dataclass
class IsolatedGraphLease:
    artifact: GraphArtifact
    path: Path
    _closed: bool = False

    def close(self, *, deadline_monotonic: float) -> None:
        from .backend import _DeadlineExpired, _remove_owned_tree

        if self._closed:
            return
        try:
            _remove_owned_tree(self.path.parent, deadline_monotonic)
        except (OSError, _DeadlineExpired):
            return
        self._closed = True


def graph_bytes(path: Path, deadline: float, destination: Path | None = None) -> str:
    """Hash and optionally copy a graph in bounded chunks; never buffer the full graph."""
    import hashlib
    import os
    import stat
    import time
    from contextlib import ExitStack

    digest = hashlib.sha256()
    count = 0
    with ExitStack() as stack:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        source = stack.enter_context(os.fdopen(fd, "rb"))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("graph_not_regular")
        output = stack.enter_context(destination.open("xb")) if destination is not None else None
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline_exhausted")
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
    if not count:
        raise ValueError("graph_empty")
    return digest.hexdigest()
