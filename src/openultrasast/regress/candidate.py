"""Candidate selection and safety-gated regression execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..complexity.ledger import hotspot_key, select_forced_candidates
from ..complexity.map import Hotspot
from ..findings import StaticFinding
from ..sandbox import SandboxJob, SandboxResult, SandboxRunner
from .safety import UnsafeSnippetError, check_snippet_safety

INCONCLUSIVE = "inconclusive"
SAFETY_REJECTED = "safety_rejected"
TRIGGERABLE = "triggerable"
NOT_TRIGGERABLE = "not_triggerable"


def select_candidates(
    hotspots: Sequence[Hotspot],
    findings: Sequence[StaticFinding],
    *,
    max_candidates: int,
    policy_severity_by_id: Mapping[str, object] | None = None,
    rule_cwe: Mapping[str, str] | None = None,
) -> tuple[Hotspot, ...]:
    """Select min(max_candidates, ranked hotspots) ∪ sev-5 reachable inventory.

    The cap applies to the ranked hotspot slice. Forced policy-severity-5
    reachable (or inferred-file-surface) inventory stays in the set even when a
    ledger overlay demoted its hotspot out of that slice.
    """
    ranked = tuple(sorted(hotspots, key=lambda item: (-item.score, item.path, item.function_name or "")))
    selected = list(ranked[: max(max_candidates, 0)])
    seen = {hotspot_key(item.path, item.function_name) for item in selected}
    extras: list[Hotspot] = []
    for finding in select_forced_candidates(findings, policy_severity_by_id or {}, rule_cwe=rule_cwe):
        hotspot = _hotspot_for_finding(finding, ranked) or _hotspot_from_forced_finding(finding)
        key = hotspot_key(hotspot.path, hotspot.function_name)
        if key in seen:
            continue
        seen.add(key)
        extras.append(hotspot)
    return tuple(selected + extras)


def _hotspot_for_finding(finding: StaticFinding, hotspots: Sequence[Hotspot]) -> Hotspot | None:
    for hotspot in hotspots:
        if finding.finding_id in hotspot.inventory_finding_ids:
            return hotspot
    key = hotspot_key(finding.path, finding.function_name)
    for hotspot in hotspots:
        if hotspot_key(hotspot.path, hotspot.function_name) == key:
            return hotspot
    return None


def _hotspot_from_forced_finding(finding: StaticFinding) -> Hotspot:
    return Hotspot(
        path=finding.path,
        function_name=finding.function_name,
        score=0.0,
        band="low",
        signals={},
        rationale="forced reachable severity-5 inventory",
        test_hint=None,
        inventory_finding_ids=(finding.finding_id,),
    )


@dataclass(frozen=True)
class RegressionVerdict:
    verdict: str
    reason: str = ""


class RegressionRunner:
    """Run a snippet in the sandbox only after the structural safety check passes."""

    def __init__(self, sandbox: SandboxRunner) -> None:
        self._sandbox = sandbox

    def run_snippet(self, snippet: str, job: SandboxJob) -> RegressionVerdict:
        try:
            check_snippet_safety(snippet)
        except UnsafeSnippetError:
            return RegressionVerdict(verdict=INCONCLUSIVE, reason=SAFETY_REJECTED)
        return _verdict_from_result(self._sandbox.run(job))


def _verdict_from_result(result: SandboxResult) -> RegressionVerdict:
    if result.timed_out:
        return RegressionVerdict(verdict=INCONCLUSIVE, reason="timeout")
    if result.exit_code != 0:
        return RegressionVerdict(verdict=TRIGGERABLE, reason="nonzero_exit")
    return RegressionVerdict(verdict=NOT_TRIGGERABLE, reason="exit_zero")
