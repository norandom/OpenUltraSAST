"""Push-owned immutable identities and independent result statuses (Req 5.5, 7.3).

Git resolution, admission policy and execution are separate later implementations.
No default result status can turn an unexecuted contract into a complete negative.
"""
from __future__ import annotations

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
