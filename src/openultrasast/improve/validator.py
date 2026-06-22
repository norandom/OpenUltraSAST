"""Bounded-lever edit model + validator for the self-improvement loop (tasks 7.1, 7.2).

The loop may only adjust governance *data* through two bounded levers and never the
two authorities a human/upstream owns: detection **pattern text** and the 0-5 CWE
**severity**. Edits are typed so pattern/severity changes are structurally
impossible; the validator additionally enforces status/bounds/staging/resolution.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..policy import CwePolicy
from ..ruleset import PatternRule
from ..ruleset.store import VALID_STATUS

# The only levers the loop may pull (mirrors the design's journal._VALID_LEVERS).
VALID_LEVERS = frozenset({"rule", "policy"})
# Policy constants the loop may tune; the 0-5 severity is intentionally absent.
TUNABLE_POLICY_CONSTANTS = frozenset({"K", "MIN_SCORE"})


class StrictValidationError(ValueError):
    """Raised when a proposed loop edit violates the bounded-lever contract."""

    def __init__(self, message: str, *, kind: str = "rule_change") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class RuleStatusEdit:
    """A `rule`-lever edit: change a rule's status / evidence floor / precision estimate."""

    rule_id: str
    from_status: str
    to_status: str
    rationale: str = ""
    lever: str = "rule"

    def key(self) -> str:
        return f"rule:{self.rule_id}:{self.from_status}->{self.to_status}"


@dataclass(frozen=True)
class PolicyConstantEdit:
    """A `policy`-lever edit: tune a score constant (K / MIN_SCORE). Never severity."""

    name: str
    from_value: float
    to_value: float
    rationale: str = ""
    lever: str = "policy"

    def key(self) -> str:
        return f"policy:{self.name}:{self.from_value}->{self.to_value}"


@dataclass(frozen=True)
class EvolveBounds:
    k_range: tuple[float, float] = (20.0, 200.0)
    min_score_range: tuple[int, int] = (0, 100)


class EvolveValidator:
    """Enforces the bounded-lever safety contract; raises StrictValidationError on any breach."""

    def __init__(self, bounds: EvolveBounds | None = None) -> None:
        self._bounds = bounds or EvolveBounds()

    def validate(self, edit: object, ruleset_by_id: Mapping[str, PatternRule], policy: Mapping[str, CwePolicy]) -> None:
        if isinstance(edit, RuleStatusEdit):
            self._validate_rule(edit, ruleset_by_id, policy)
        elif isinstance(edit, PolicyConstantEdit):
            self._validate_policy(edit)
        else:
            raise StrictValidationError(f"unknown edit type {type(edit).__name__}", kind="rule_change")

    def _validate_rule(self, edit: RuleStatusEdit, ruleset_by_id: Mapping[str, PatternRule], policy: Mapping[str, CwePolicy]) -> None:
        if edit.to_status not in VALID_STATUS:
            raise StrictValidationError(f"invalid status {edit.to_status!r} for {edit.rule_id}")
        rule = ruleset_by_id.get(edit.rule_id)
        if rule is None:
            raise StrictValidationError(f"edit targets unknown rule_id {edit.rule_id!r} (loop cannot add rules)")
        if edit.from_status == "enabled" and edit.to_status == "disabled":
            raise StrictValidationError(f"{edit.rule_id}: enabled->disabled jump is forbidden; stage via shadow first")
        if rule.cwe not in policy:
            raise StrictValidationError(f"{edit.rule_id}: CWE {rule.cwe} does not resolve in the policy")

    def _validate_policy(self, edit: PolicyConstantEdit) -> None:
        if edit.name not in TUNABLE_POLICY_CONSTANTS:
            raise StrictValidationError(
                f"policy constant {edit.name!r} is not loop-tunable (severity is upstream-owned)", kind="policy_change"
            )
        if edit.name == "K" and not (self._bounds.k_range[0] <= edit.to_value <= self._bounds.k_range[1]):
            raise StrictValidationError(f"K={edit.to_value} out of bounds {self._bounds.k_range}", kind="policy_change")
        if edit.name == "MIN_SCORE" and not (self._bounds.min_score_range[0] <= edit.to_value <= self._bounds.min_score_range[1]):
            raise StrictValidationError(f"MIN_SCORE={edit.to_value} out of bounds {self._bounds.min_score_range}", kind="policy_change")


def edits_to_ledger(edits: list[RuleStatusEdit], base: Mapping[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """Overlay rule-status edits onto a copy of the base ledger."""
    ledger: dict[str, dict[str, object]] = {key: dict(value) for key, value in base.items()}
    for edit in edits:
        entry = dict(ledger.get(edit.rule_id, {}))
        entry["status"] = edit.to_status
        ledger[edit.rule_id] = entry
    return ledger


__all__ = [
    "EvolveBounds",
    "EvolveValidator",
    "PolicyConstantEdit",
    "RuleStatusEdit",
    "StrictValidationError",
    "TUNABLE_POLICY_CONSTANTS",
    "VALID_LEVERS",
    "edits_to_ledger",
]
