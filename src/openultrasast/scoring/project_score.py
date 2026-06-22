from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass

from ..findings import StaticFinding
from ..policy import CwePolicy

# Penalty weight per policy severity (0-5). Higher severity costs the score more.
SEV_WEIGHT = {5: 50, 4: 25, 3: 10, 2: 2, 1: 1, 0: 0}

# Reachability multiplier — the false-positive calibration knob. A confirmed FP
# lowers a finding's effective reachability rather than deleting the rule.
REACH_MULT = {"reachable": 1.0, "inferred-file-surface": 0.6, "unknown": 0.4}


@dataclass(frozen=True)
class ScoreArtifact:
    project_score: int
    max_severity: int
    penalty_total: float
    by_category: dict[str, int]
    out_of_scope_dynamic_only: int
    unmapped_cwe: list[str]
    gate: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def finding_penalty(finding: StaticFinding, rule_cwe: str | None, policy: Mapping[str, CwePolicy]) -> float:
    """Penalty contributed by one finding: severity weight × reachability multiplier.

    Dynamic-only or unmapped CWEs contribute zero (report-only, never scored).
    """
    pol = policy.get(rule_cwe) if rule_cwe else None
    if pol is None or not pol.static:
        return 0.0
    return SEV_WEIGHT[pol.severity] * REACH_MULT.get(finding.reachability_status, REACH_MULT["unknown"])


def project_score(
    findings: list[StaticFinding],
    rule_cwe_by_id: Mapping[str, str],
    policy: Mapping[str, CwePolicy],
    k: float = 60.0,
) -> int:
    """Compute the 0-100 project score (shadow findings excluded by the caller).

    Exponential decay of total penalty: no penalty → 100; one severity-5 reachable
    finding → ~43.
    """
    total = sum(finding_penalty(finding, rule_cwe_by_id.get(finding.finding_id), policy) for finding in findings)
    return round(100 * math.exp(-total / k))


def gate(
    findings: list[StaticFinding],
    score: int,
    rule_cwe_by_id: Mapping[str, str],
    policy: Mapping[str, CwePolicy],
    *,
    min_score: int,
    block_severity_reachable: int = 5,
    blocking: bool,
) -> dict[str, object]:
    """Two-condition gate verdict.

    A finding at ``block_severity_reachable`` severity that is ``reachable`` always
    fails. The score threshold fails only when ``blocking`` is enabled.
    """
    hard_fail = any(
        _severity(rule_cwe_by_id.get(finding.finding_id), policy) >= block_severity_reachable and finding.reachability_status == "reachable"
        for finding in findings
    )
    score_fail = blocking and score < min_score
    return {
        "min_score": min_score,
        "block_severity_reachable": block_severity_reachable,
        "blocking": blocking,
        "passed": not hard_fail and not score_fail,
    }


def build_score_artifact(
    findings: list[StaticFinding],
    rule_cwe_by_id: Mapping[str, str],
    policy: Mapping[str, CwePolicy],
    *,
    k: float = 60.0,
    min_score: int = 80,
    block_severity_reachable: int = 5,
    blocking: bool = False,
) -> ScoreArtifact:
    score = project_score(findings, rule_cwe_by_id, policy, k=k)
    penalty_total = 0.0
    max_severity = 0
    by_category: dict[str, int] = {}
    out_of_scope_dynamic_only = 0
    unmapped: set[str] = set()
    for finding in findings:
        cwe = rule_cwe_by_id.get(finding.finding_id)
        pol = policy.get(cwe) if cwe else None
        if pol is None:
            unmapped.add(cwe or "unknown")
            continue
        if not pol.static:
            if pol.dynamic:
                out_of_scope_dynamic_only += 1
            continue
        penalty_total += finding_penalty(finding, cwe, policy)
        max_severity = max(max_severity, pol.severity)
        by_category[pol.flaw_category] = by_category.get(pol.flaw_category, 0) + 1
    return ScoreArtifact(
        project_score=score,
        max_severity=max_severity,
        penalty_total=round(penalty_total, 2),
        by_category=dict(sorted(by_category.items())),
        out_of_scope_dynamic_only=out_of_scope_dynamic_only,
        unmapped_cwe=sorted(unmapped),
        gate=gate(
            findings,
            score,
            rule_cwe_by_id,
            policy,
            min_score=min_score,
            block_severity_reachable=block_severity_reachable,
            blocking=blocking,
        ),
    )


def _severity(cwe: str | None, policy: Mapping[str, CwePolicy]) -> int:
    pol = policy.get(cwe) if cwe else None
    if pol is None or not pol.static:
        return 0
    return pol.severity
