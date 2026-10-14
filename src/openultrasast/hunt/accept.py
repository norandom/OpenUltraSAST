"""Accept a proposal only when separate compile and held-out comparisons support it."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from ..stats import Estimate
from .artifact import RunArtifact
from .propose import Candidate, _append, _write, changed_surfaces, proposer_record


@dataclass(frozen=True)
class Rule:
    """The acceptance rule fixed before measurement.

    Regression budgets are signed recall differences: -0.02 permits a loss of
    two percentage points. The 'default' entry applies to unlisted families;
    when omitted it is zero. The held-out tie band includes both endpoints.
    """

    tolerance: float
    regression_budget: Mapping[str, float]
    instruction_cap: int
    version: str = "accept-v1"

    def __post_init__(self) -> None:
        """Reject malformed or unsupported rules before using any measurements."""
        if self.version != "accept-v1":
            raise ValueError("unsupported acceptance rule version")
        if not math.isfinite(self.tolerance) or self.tolerance < 0:
            raise ValueError("tolerance must be finite and non-negative")
        if type(self.instruction_cap) is not int or self.instruction_cap < 0:
            raise ValueError("instruction cap must be a non-negative integer")
        if any(not math.isfinite(v) or not -1 <= v <= 0 for v in self.regression_budget.values()):
            raise ValueError("regression budgets must be signed differences between -1 and zero")


@dataclass(frozen=True)
class FoldResult:
    """Paired candidate-minus-current differences for one scope and one family.

    Use family='pooled' for the aggregate and scope='compile' or 'holdout'. Each
    metric accepts stats.Estimate or a record containing diff, ci, units and
    groups. Missing intervals remain explicit so decide can reject them.
    """

    scope: str
    family: str
    recall: Estimate | Mapping[str, Any]
    suspicions_per_push: Estimate | Mapping[str, Any]


@dataclass(frozen=True)
class Decision:
    """The verdict, each failed clause, and the full private comparison."""

    accepted: bool
    reasons: list[str]
    comparison: dict[str, Any]

    def record(self, out_dir: Path | str, *, artifact: RunArtifact | None = None) -> None:
        """Save comparison.json and optionally attach it to the candidate's artifact.

        The existing configurations field carries the full comparison. Call
        artifact.write afterwards to persist its new content address.
        """
        if artifact is not None and artifact.program_id != self.comparison["candidate_id"]:
            raise ValueError("comparison belongs to a different program artifact")
        _write(Path(out_dir) / "comparison.json", self.comparison)
        if artifact is not None:
            record = {"comparison": self.comparison}
            if record not in artifact.configurations:
                artifact.configurations.append(record)


def _record(value: Estimate | FoldResult | Mapping[str, Any]) -> dict[str, Any]:
    """Convert dataclass estimates and ordinary mappings to JSON records."""
    return asdict(value) if is_dataclass(value) else dict(value)


def _valid_number(value: Any) -> bool:
    """A missing or non-finite point estimate cannot support acceptance."""
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _interval_present(estimate: Mapping[str, Any]) -> bool:
    """Require an ordered finite interval and real unit and group counts."""
    ci = estimate.get("ci")
    return (
        isinstance(ci, tuple | list)
        and len(ci) == 2
        and all(_valid_number(v) for v in ci)
        and ci[0] <= ci[1]
        and _valid_number(estimate.get("diff"))
        and type(estimate.get("units")) is int
        and type(estimate.get("groups")) is int
        and 0 < estimate["groups"] <= estimate["units"]
    )


def decide(
    current_id: str, candidate: Candidate, compile_results: Mapping[str, FoldResult], holdout_results: Mapping[str, FoldResult], rule: Rule
) -> Decision:
    """Apply every clause independently and save the comparison beside the proposal.

    A zero compile difference and positive held-out difference may accept. A
    positive compile difference with a held-out tie rejects. Confidence
    intervals must exist; they need not exclude zero under this rule.
    """
    rule.__post_init__()
    reasons = []
    if candidate.base_program_id != current_id:
        reasons.append("current_program_mismatch")
    try:
        surfaces = changed_surfaces(candidate.base_state, candidate.state, candidate.base_mask, candidate.mask)
        if surfaces != {candidate.kind} or set(candidate.change) != {candidate.kind}:
            reasons.append("multiple_or_invalid_changes")
    except ValueError:
        reasons.append("multiple_or_invalid_changes")
    instructions = [state.get("signature", {}).get("instructions", "") for state in candidate.state.values()]
    if any(not isinstance(text, str) or len(text) > rule.instruction_cap for text in instructions):
        reasons.append("instruction_cap")
    compiled: dict[str, dict[str, Any]] = {}
    heldout: dict[str, dict[str, Any]] = {}
    for scope, source, target in (("compile", compile_results, compiled), ("holdout", holdout_results, heldout)):
        for family, result in source.items():
            record = _record(result)
            if record.get("scope") != scope or record.get("family") != family:
                reasons.append(f"invalid_scope:{scope}:{family}")
            target[family] = record
            for metric in ("recall", "suspicions_per_push"):
                estimate = _record(record.get(metric, {}))
                record[metric] = estimate
                if not _interval_present(estimate):
                    reasons.append(f"missing_interval:{scope}:{family}:{metric}")
        if "pooled" not in source:
            reasons.append(f"missing_pooled:{scope}")
    if set(compiled) != set(heldout):
        reasons.append("missing_family_comparison")
    compile_diff = compiled.get("pooled", {}).get("recall", {}).get("diff")
    holdout_diff = heldout.get("pooled", {}).get("recall", {}).get("diff")
    if _valid_number(compile_diff) and compile_diff < 0:
        reasons.append("compile_recall_negative")
    if _valid_number(holdout_diff) and holdout_diff < 0:
        reasons.append("holdout_recall_negative")
    if not any(_valid_number(value) and value > 0 for value in (compile_diff, holdout_diff)):
        reasons.append("no_positive_recall_difference")
    if _valid_number(holdout_diff) and abs(holdout_diff) <= rule.tolerance:
        reasons.append("holdout_tie")
    for family, heldout_record in heldout.items():
        if family == "pooled":
            continue
        diff = heldout_record["recall"].get("diff")
        floor = rule.regression_budget.get(family, rule.regression_budget.get("default", 0))
        if _valid_number(diff) and diff < floor:
            reasons.append(f"family_regression:{family}")
    comparison = {
        "current_id": current_id,
        "candidate_id": candidate.program_id,
        "compile_results": compiled,
        "holdout_results": heldout,
        "rule": asdict(rule),
        "accepted": not reasons,
        "reasons": reasons,
    }
    decision = Decision(not reasons, reasons, comparison)
    decision.record(candidate.out_dir)
    return decision


def record_rejection(out_dir: Path | str, candidate: Candidate, decision: Decision) -> None:
    """Append the compile score and reason codes, never the private comparison."""
    if decision.accepted:
        raise ValueError("cannot record an accepted candidate as rejected")
    if decision.comparison["candidate_id"] != candidate.program_id:
        raise ValueError("decision belongs to a different candidate")
    _append(Path(out_dir) / "rejected.jsonl", {**proposer_record(candidate), "reasons": decision.reasons})
