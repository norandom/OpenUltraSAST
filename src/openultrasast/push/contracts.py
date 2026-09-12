"""Push-owned immutable identities and independent result statuses (Req 5.5, 7.3).

Git resolution, admission policy and execution are separate later implementations.
No default result status can turn an unexecuted contract into a complete negative.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from openultrasast.contracts import Contract
from openultrasast.model.contracts import QuestionIdentity, ScopeDecision


@dataclass(frozen=True)
class PushUpdate(Contract):
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str


@dataclass(frozen=True)
class PushComparison(Contract):
    head_oid: str
    base_oid: str | None
    base_reason: str
    refs: tuple[str, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.refs or len(set(self.refs)) != len(self.refs):
            raise ValueError("comparison must retain distinct associated refs")


@dataclass(frozen=True)
class ComparisonAnalysis(Contract):
    """Scope and completion belong to this exact base/head comparison.

    A question completed for one comparison never completes it for another base,
    even when the target graph is shared. This record does not assert admission.
    """

    comparison: PushComparison
    scopes: tuple[ScopeDecision, ...]
    completed_questions: tuple[QuestionIdentity, ...]
    coverage_status: Literal["complete_within_scope", "incomplete", "unavailable"]

    def __post_init__(self) -> None:
        super().__post_init__()
        selected_list = [item.identity for scope in self.scopes for item in scope.selected]
        selected = set(selected_list)
        completed = set(self.completed_questions)
        if len(selected) != len(selected_list):
            raise ValueError("a comparison cannot select the same question across multiple scopes")
        if len(completed) != len(self.completed_questions) or not completed <= selected:
            raise ValueError("completed questions must be unique members of this comparison's selected scope")
        if self.coverage_status == "complete_within_scope":
            if self.comparison.base_oid is None or not self.scopes:
                raise ValueError("complete coverage requires compared revisions and an explicit scope census")
            if completed != selected or any(
                not scope.population_complete or scope.deferred or scope.unresolved_boundaries for scope in self.scopes
            ):
                raise ValueError("deferred, unexecuted or unresolved work cannot be complete coverage")


@dataclass(frozen=True)
class PushResult(Contract):
    analyses: tuple[ComparisonAnalysis, ...]
    finding_status: Literal["actionable", "none"]
    coverage_status: Literal["complete_within_scope", "incomplete", "unavailable", "not_applicable"]
    push_disposition: Literal["allow", "block"]
    actionable_defect_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        if (self.finding_status == "actionable") != bool(self.actionable_defect_ids):
            raise ValueError("finding status must match admitted defect identities")
        if len(set(self.actionable_defect_ids)) != len(self.actionable_defect_ids):
            raise ValueError("admitted defect identities must be unique")
        if self.coverage_status == "complete_within_scope" and (
            not self.analyses or any(item.coverage_status != "complete_within_scope" for item in self.analyses)
        ):
            raise ValueError("aggregate complete coverage requires completed comparison analyses")
        if self.coverage_status == "not_applicable" and (self.analyses or self.actionable_defect_ids):
            raise ValueError("not applicable cannot carry analyzed scope or findings")


@dataclass(frozen=True)
class UpdateResolution(Contract):
    """One record per supplied line, including repeated ref associations."""

    update: PushUpdate
    disposition: Literal["ready", "deleted", "missing_target", "unsupported_target", "missing_base", "unsupported_base",
                         "no_merge_base", "ambiguous_base", "resolution_error"]
    head_oid: str | None
    base_oid: str | None
    base_reason: str


@dataclass(frozen=True)
class PushResolution(Contract):
    object_format: str
    updates: tuple[UpdateResolution, ...]
    comparisons: tuple[PushComparison, ...]
    targets: tuple[str, ...]


@dataclass(frozen=True)
class SnapshotFile(Contract):
    # Git paths are bytes; hex survives JSON and whitespace-only/non-UTF8 names.
    path_hex: str
    blob_oid: str
    mode: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _validate_path_hex(self.path_hex)
        if self.size_bytes < 0 or self.mode not in ("100644", "100755"):
            raise ValueError("invalid materialized file size or mode")
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.blob_oid) is None:
            raise ValueError("invalid blob identity")
        if re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError("invalid content digest")

    @property
    def path_bytes(self) -> bytes:
        return bytes.fromhex(self.path_hex)


@dataclass(frozen=True)
class SnapshotBoundary(Contract):
    path_hex: str | None
    reason: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.path_hex is not None:
            _validate_path_hex(self.path_hex)


def _validate_path_hex(value: str) -> None:
    if re.fullmatch(r"(?:[0-9a-f]{2})+", value) is None or b"\0" in bytes.fromhex(value):
        raise ValueError("path must be nonempty NUL-free bytes encoded as lowercase hex")


@dataclass(frozen=True)
class SnapshotManifest(Contract):
    commit_oid: str
    object_format: str
    files: tuple[SnapshotFile, ...]
    boundaries: tuple[SnapshotBoundary, ...]
    tree_complete: bool
    bytes_read: int

    def __post_init__(self) -> None:
        super().__post_init__()
        width = {"sha1": 40, "sha256": 64}.get(self.object_format)
        if width is None or re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", self.commit_oid) is None:
            raise ValueError("invalid snapshot identity")
        if any(len(item.blob_oid) != width for item in self.files):
            raise ValueError("blob identity does not match object format")
        if len({item.path_hex for item in self.files}) != len(self.files):
            raise ValueError("snapshot paths must be unique")
        if self.bytes_read < sum(item.size_bytes for item in self.files):
            raise ValueError("bytes read must cover every materialized blob")
        if not self.tree_complete and not self.boundaries:
            raise ValueError("incomplete tree requires an explicit boundary")

    @property
    def complete(self) -> bool:
        """Materialization completeness only, never security coverage."""
        return self.tree_complete and not self.boundaries
