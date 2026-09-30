"""Deterministic scan stages as model-disabled, slot-contracted processors (task 6.3).

Each stage is a :class:`slot_contract.SlotContractMixin` with ``skip_model = True`` and
a declared read/write slot allow-list. Running them through a :class:`SlotPipeline`
reproduces the deterministic quick-scan path byte-for-byte while enforcing the slot
contract on every lifecycle hook. The hunter and verifier stages are *not* here; this
module is the deterministic, model-free remainder that ``test_gate`` pins.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .findings import quick_scan_findings
from .mapping import analyze_entry_points, attach_reachability_hints
from .policy import load_policy
from .preprocess import preprocess_repository
from .rank import rank_targets
from .ruleset import DEFAULT_RULESET_DIR, load_ruleset
from .scoring import build_score_artifact
from .slot_contract import SlotContractMixin, SlotPipeline


class PreprocessProcessor(SlotContractMixin):
    name = "preprocess"
    reads_slots = ("root",)
    writes_slots = ("snapshot", "targets")

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        snapshot, targets = preprocess_repository(slots["root"])
        return {"snapshot": snapshot, "targets": targets}


class EntryPointProcessor(SlotContractMixin):
    name = "entry_point"
    reads_slots = ("root", "targets")
    writes_slots = ("targets", "entry_points")

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        entry_points = analyze_entry_points(slots["root"], slots["targets"])
        targets = attach_reachability_hints(slots["targets"], entry_points)
        return {"targets": targets, "entry_points": entry_points}


class RankProcessor(SlotContractMixin):
    name = "rank"
    reads_slots = ("targets",)
    writes_slots = ("rankings",)

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        return {"rankings": rank_targets(slots["targets"])}


class QuickFindingsProcessor(SlotContractMixin):
    name = "quick_findings"
    reads_slots = ("root", "targets", "rankings", "ruleset", "policy")
    writes_slots = ("findings",)

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        findings = quick_scan_findings(slots["root"], slots["targets"], slots["rankings"], slots["ruleset"], slots["policy"])
        return {"findings": findings}


class PolicyScoringProcessor(SlotContractMixin):
    name = "policy_scoring"
    reads_slots = ("findings",)
    writes_slots = ("reported_findings", "shadow_findings")

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        findings = slots["findings"]
        shadow = [finding for finding in findings if finding.status == "shadow"]
        reported = [finding for finding in findings if finding.status != "shadow"]
        return {"reported_findings": reported, "shadow_findings": shadow}


class ScoreProcessor(SlotContractMixin):
    name = "score"
    reads_slots = ("reported_findings", "ruleset", "policy")
    writes_slots = ("score",)

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        cwe_by_rule = {rule.rule_id: rule.cwe for rule in slots["ruleset"]}
        reported = slots["reported_findings"]
        rule_cwe_by_id = {f.finding_id: cwe_by_rule.get(f.finding_id.split(":", 1)[0], "") for f in reported}
        return {"score": build_score_artifact(reported, rule_cwe_by_id, slots["policy"])}


def deterministic_processors() -> list[SlotContractMixin]:
    """The ordered deterministic stages (preprocess → entry-point → rank → findings → policy → score)."""
    return [
        PreprocessProcessor(),
        EntryPointProcessor(),
        RankProcessor(),
        QuickFindingsProcessor(),
        PolicyScoringProcessor(),
        ScoreProcessor(),
    ]


def build_deterministic_pipeline() -> SlotPipeline:
    return SlotPipeline(deterministic_processors())


def run_quick_pipeline(
    root: Path | str,
    *,
    ruleset: Any = None,
    policy: Any = None,
    runtime: Any = None,
) -> dict[str, Any]:
    """Run the deterministic quick-scan pipeline and return the final slot map.

    Defaults to the bundled ruleset and the vendored policy, which makes the
    ``reported_findings`` slot byte-identical to ``findings.quick_scan_findings`` on
    the same target.
    """
    resolved_ruleset = ruleset if ruleset is not None else load_ruleset(DEFAULT_RULESET_DIR)
    resolved_policy = policy if policy is not None else load_policy()
    initial = {"root": Path(root), "ruleset": resolved_ruleset, "policy": resolved_policy}
    return build_deterministic_pipeline().run(initial, runtime=runtime)


__all__ = [
    "EntryPointProcessor",
    "PolicyScoringProcessor",
    "PreprocessProcessor",
    "QuickFindingsProcessor",
    "RankProcessor",
    "ScoreProcessor",
    "build_deterministic_pipeline",
    "deterministic_processors",
    "run_quick_pipeline",
]
