from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from .findings import StaticFinding


class EvidenceLevel(StrEnum):
    SUSPICION = "suspicion"
    STATIC_CORROBORATION = "static_corroboration"
    CRASH_REPRODUCED = "crash_reproduced"
    ROOT_CAUSE_EXPLAINED = "root_cause_explained"
    EXPLOIT_DEMONSTRATED = "exploit_demonstrated"
    PATCH_VALIDATED = "patch_validated"


class VerificationStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NEEDS_EVIDENCE = "needs_evidence"


@dataclass(frozen=True)
class VerificationResult:
    finding_id: str
    status: VerificationStatus
    evidence_level: EvidenceLevel
    verified: bool
    pro_case: str
    counter_case: str
    tie_breaker: str
    required_next_step: str
    context_sources: list[str]


def validate_evidence_transition(current: EvidenceLevel | str, target: EvidenceLevel | str) -> EvidenceLevel:
    current_level = EvidenceLevel(current)
    target_level = EvidenceLevel(target)
    if _EVIDENCE_ORDER[target_level] < _EVIDENCE_ORDER[current_level]:
        raise ValueError(f"cannot move evidence level backward: {current_level} -> {target_level}")
    if _EVIDENCE_ORDER[target_level] - _EVIDENCE_ORDER[current_level] > 1:
        raise ValueError(f"cannot skip evidence levels: {current_level} -> {target_level}")
    return target_level


def is_report_verified(evidence_level: EvidenceLevel | str, status: VerificationStatus | str) -> bool:
    level = EvidenceLevel(evidence_level)
    verification_status = VerificationStatus(status)
    return verification_status == VerificationStatus.ACCEPTED and _EVIDENCE_ORDER[level] >= _EVIDENCE_ORDER[EvidenceLevel.STATIC_CORROBORATION]


def build_independent_verifier_context(finding: StaticFinding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "path": finding.path,
        "line": finding.line,
        "function_name": finding.function_name,
        "title": finding.title,
        "severity": finding.severity,
        "evidence_level": finding.evidence_level,
        "reachability_status": finding.reachability_status,
        "reachability_evidence": finding.reachability_evidence,
        "reachability_conditions": finding.reachability_conditions,
        "tags": finding.tags,
    }


def verify_finding(finding: StaticFinding) -> VerificationResult:
    level = EvidenceLevel(finding.evidence_level)
    context = build_independent_verifier_context(finding)
    context_sources = sorted(context.keys())

    if _EVIDENCE_ORDER[level] < _EVIDENCE_ORDER[EvidenceLevel.STATIC_CORROBORATION]:
        return VerificationResult(
            finding_id=finding.finding_id,
            status=VerificationStatus.NEEDS_EVIDENCE,
            evidence_level=level,
            verified=False,
            pro_case="A candidate issue exists, but it has not reached static corroboration.",
            counter_case="The current evidence can still be a model or heuristic suspicion.",
            tie_breaker="Add static analyzer, source, or runtime evidence that corroborates the claim.",
            required_next_step="Collect static corroboration before reporting as verified.",
            context_sources=context_sources,
        )

    if finding.reachability_status == "unknown":
        return VerificationResult(
            finding_id=finding.finding_id,
            status=VerificationStatus.REJECTED,
            evidence_level=level,
            verified=False,
            pro_case="A static pattern matched the source line.",
            counter_case="No function-level attacker-reachable entry point currently reaches this line.",
            tie_breaker="Provide call-graph, route, CLI, parser, or dynamic evidence linking attacker input to this function.",
            required_next_step="Add reachability evidence before prioritizing a fix.",
            context_sources=context_sources,
        )

    return VerificationResult(
        finding_id=finding.finding_id,
        status=VerificationStatus.ACCEPTED,
        evidence_level=level,
        verified=is_report_verified(level, VerificationStatus.ACCEPTED),
        pro_case="Static corroboration exists and function-level reachability evidence is attached.",
        counter_case="Impact and exploitability still require deeper verifier or dynamic evidence.",
        tie_breaker="Confirm attacker control, sanitizer absence, and impact in the next verification depth.",
        required_next_step="Proceed to standard verifier or dynamic reproduction if severity warrants it.",
        context_sources=context_sources,
    )


def verify_findings(findings: list[StaticFinding]) -> list[VerificationResult]:
    return [verify_finding(finding) for finding in findings]


def write_verification_results(results: list[VerificationResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"verifications": [asdict(result) for result in results]}, indent=2, sort_keys=True) + "\n")


_EVIDENCE_ORDER = {
    EvidenceLevel.SUSPICION: 0,
    EvidenceLevel.STATIC_CORROBORATION: 1,
    EvidenceLevel.CRASH_REPRODUCED: 2,
    EvidenceLevel.ROOT_CAUSE_EXPLAINED: 3,
    EvidenceLevel.EXPLOIT_DEMONSTRATED: 4,
    EvidenceLevel.PATCH_VALIDATED: 5,
}
