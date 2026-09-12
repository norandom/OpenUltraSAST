"""Backend-owned graph provenance and live resource boundary (pre-push Req 4.3, 7.3).

Structural validity is necessary but insufficient for reuse. Task 6.1 will validate
actual source bytes, graph digest/census and engine compatibility before issuing leases.
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
    A cached artifact survives release. Implementations belong to task 6.1.
    """

    @property
    def artifact(self) -> GraphArtifact: ...

    @property
    def path(self) -> Path: ...

    def close(self, *, deadline_monotonic: float) -> None: ...
