"""Language-agnostic change evidence and exact ranker scope (pre-push Req 7.3).

These are integration contracts; constructing them neither selects nor executes work.
Revision identities are opaque to the engine. The snapshot adapter resolves Git objects.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Literal

from openultrasast.contracts import Contract


@dataclass(frozen=True)
class ExecutionBudget(Contract):
    """One absolute monotonic deadline, with a distinct bounded cleanup allowance.

    Process-local: do not carry the absolute clock value across process restarts.
    Manifests should record elapsed stage costs and configured durations instead.
    """

    deadline_monotonic: float
    cancellation_allowance_seconds: float

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.deadline_monotonic < 0 or self.cancellation_allowance_seconds <= 0:
            raise ValueError("deadline must be nonnegative and cancellation allowance positive")


@dataclass(frozen=True)
class QuestionIdentity(Contract):
    unit: str
    language: str
    path: str
    function: str | None
    family: str

    @property
    def question_id(self) -> str:
        encoded = json.dumps(self.to_payload(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ChangedSpan(Contract):
    path: str
    start_line: int
    end_line: int
    side: Literal["base", "head"]

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("changed spans require positive inclusive ordered lines")


@dataclass(frozen=True)
class PathRename(Contract):
    base_path: str
    head_path: str


@dataclass(frozen=True)
class AffectedRelationship(Contract):
    source: QuestionIdentity
    target: QuestionIdentity
    kind: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class LineCorrespondence(Contract):
    """Unique identical source lines outside edit hunks; never semantic identity proof.

    A renamed declaration can retain its unchanged operation's lexical anchor.
    Frontend evidence must still establish function/guard relationships and novelty.
    Paths use the owning ChangeContext's explicit encoding.
    """

    base_path: str
    head_path: str
    base_start_line: int
    base_end_line: int
    head_start_line: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.base_start_line < 1 or self.base_end_line < self.base_start_line or self.head_start_line < 1:
            raise ValueError("line correspondence requires positive ordered lines")


@dataclass(frozen=True)
class ChangeContext(Contract):
    base_revision: str | None
    head_revision: str
    changed_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    spans: tuple[ChangedSpan, ...]
    renames: tuple[PathRename, ...]
    declaration_paths: tuple[str, ...]
    relationships: tuple[AffectedRelationship, ...]
    unresolved_boundaries: tuple[str, ...]
    # Filesystem paths can be whitespace-only or non-UTF8. Adapter-produced contexts use
    # lowercase raw-byte hex for change paths, spans, renames and line anchors.
    # Relationship QuestionIdentity paths retain canonical question encoding; they
    # are not encoded or decoded by this field.
    path_encoding: Literal["text", "filesystem-bytes-hex"] = "text"
    line_correspondences: tuple[LineCorrespondence, ...] = ()

    def decode_path(self, path: str) -> str:
        """Return the filesystem spelling for matching ordinary question paths.

        Raw undecodable filename bytes survive through filesystem surrogate escapes;
        serialization should retain the authoritative encoded contract path instead.
        """
        return os.fsdecode(bytes.fromhex(path)) if self.path_encoding == "filesystem-bytes-hex" else path

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.path_encoding == "filesystem-bytes-hex":
            paths = [
                *self.changed_paths,
                *self.deleted_paths,
                *self.declaration_paths,
                *(s.path for s in self.spans),
                *(p for r in self.renames for p in (r.base_path, r.head_path)),
                *(p for m in self.line_correspondences for p in (m.base_path, m.head_path)),
            ]
            for path in paths:
                try:
                    raw = bytes.fromhex(path)
                except ValueError as error:
                    raise ValueError("invalid raw filesystem path hex") from error
                if not raw or b"\0" in raw or raw.hex() != path:
                    raise ValueError("invalid raw filesystem path hex")


@dataclass(frozen=True)
class RankedQuestion(Contract):
    identity: QuestionIdentity
    priority: float
    evidence: tuple[str, ...]
    tier: int | None = None
    score: float | None = None


@dataclass(frozen=True)
class DeferredQuestion(Contract):
    identity: QuestionIdentity
    reason: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ScopeDecision(Contract):
    ranker_version: str
    ranking_mode: str
    # Explicit census assertion: an empty list by itself is never proof of no work.
    population_complete: bool
    selected: tuple[RankedQuestion, ...]
    deferred: tuple[DeferredQuestion, ...]
    unresolved_boundaries: tuple[str, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        identities = [item.identity for item in self.selected] + [item.identity for item in self.deferred]
        if len(set(identities)) != len(identities):
            raise ValueError("question identities must be unique across selected and deferred scope")


@dataclass(frozen=True)
class QuestionOutcome(Contract):
    """Execution, not vulnerability disposition; raw answers survive interrupted arbitration."""

    identity: QuestionIdentity
    status: Literal["completed", "unanswered", "unresolved", "not_arbitrated"]
    reason: str
    raw_rows_json: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.raw_rows_json is not None:
            try:
                rows = json.loads(self.raw_rows_json)
            except (ValueError, TypeError) as error:
                raise ValueError("raw_rows_json must contain a JSON row list") from error
            if not isinstance(rows, list):
                raise ValueError("raw_rows_json must contain a JSON row list")
        if self.status in {"completed", "not_arbitrated"} and self.raw_rows_json is None:
            raise ValueError("answered outcome requires raw rows")
        if self.status == "unanswered" and self.raw_rows_json is not None:
            raise ValueError("unanswered outcome cannot carry an answer")


@dataclass(frozen=True)
class FamilyCoverage(Contract):
    """Counts over the supplied population; completed never means safe or admitted."""

    unit: str
    language: str
    family: str
    selected: int
    completed: int
    unanswered: int
    deferred: int
    unsupported: int

    def __post_init__(self) -> None:
        super().__post_init__()
        counts = (self.selected, self.completed, self.unanswered, self.deferred, self.unsupported)
        if any(count < 0 for count in counts):
            raise ValueError("coverage counts must be nonnegative")
        if self.completed + self.unanswered != self.selected or self.unsupported > self.deferred:
            raise ValueError("inconsistent family coverage counts")
