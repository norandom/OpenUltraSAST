"""Language-agnostic change evidence and exact ranker scope (pre-push Req 7.3).

These are integration contracts; constructing them neither selects nor executes work.
Revision identities are opaque to the engine. The snapshot adapter resolves Git objects.
"""
from __future__ import annotations

import hashlib
import json
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


@dataclass(frozen=True)
class RankedQuestion(Contract):
    identity: QuestionIdentity
    priority: float
    evidence: tuple[str, ...]


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
