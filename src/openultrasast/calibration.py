from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

from .findings import StaticFinding
from .rank import RankingScore, composite_priority


class FalsePositiveReason(StrEnum):
    UNREACHABLE_PATH = "unreachable_path"
    MISSING_ATTACKER_CONTROL = "missing_attacker_control"
    SANITIZER_DISPROVED = "sanitizer_disproved"
    STATIC_RULE_MISMATCH = "static_rule_mismatch"
    INCORRECT_MODEL_ASSUMPTION = "incorrect_model_assumption"
    DUPLICATE = "duplicate"
    INSUFFICIENT_IMPACT = "insufficient_impact"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"


class FindingOutcome(StrEnum):
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class FalsePositiveLearning:
    finding_id: str
    path: str
    vulnerability_class: str
    reason: FalsePositiveReason
    evidence: str
    scope: str
    demotion: float = 0.5


@dataclass(frozen=True)
class RankingMetrics:
    tier: str
    verified_findings: int
    false_positives: int
    time_to_verification_seconds: float
    missed_fixture_vulnerabilities: int
    false_positive_reasons: dict[str, int]


@dataclass(frozen=True)
class RankingCalibration:
    path: str
    original_priority: float
    calibrated_priority: float
    applied_learning_ids: list[str]
    retrieval_filter_adjustments: dict[str, str]
    prompt_constraints: list[str]


def record_false_positive_learning(
    finding: StaticFinding,
    *,
    reason: FalsePositiveReason,
    evidence: str,
    scope: str | None = None,
) -> FalsePositiveLearning:
    if not evidence.strip():
        raise ValueError("false-positive learning requires evidence")
    vulnerability_class = _vulnerability_class(finding)
    return FalsePositiveLearning(
        finding_id=finding.finding_id,
        path=finding.path,
        vulnerability_class=vulnerability_class,
        reason=reason,
        evidence=evidence,
        scope=scope or _default_scope(finding.path, vulnerability_class),
    )


def learning_from_finding_outcome(
    finding: StaticFinding,
    *,
    outcome: FindingOutcome,
    evidence: str,
    reason: FalsePositiveReason | None = None,
    scope: str | None = None,
) -> FalsePositiveLearning | None:
    if outcome == FindingOutcome.VERIFIED:
        return None
    return record_false_positive_learning(
        finding,
        reason=reason or _reason_from_outcome(outcome),
        evidence=evidence,
        scope=scope,
    )


def compute_ranking_metrics(events: list[dict[str, object]], *, tier: str) -> RankingMetrics:
    verified = 0
    false_positives = 0
    reason_counts: dict[str, int] = {}
    verification_times: list[float] = []
    missed = 0
    for event in events:
        if event.get("tier") != tier:
            continue
        outcome = event.get("outcome")
        if outcome == FindingOutcome.VERIFIED:
            verified += 1
        if outcome in _FALSE_POSITIVE_OUTCOMES:
            false_positives += 1
            reason = str(event.get("reason", FalsePositiveReason.UNVERIFIED))
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        duration = event.get("time_to_verification_seconds")
        if isinstance(duration, int | float) and not isinstance(duration, bool):
            verification_times.append(float(duration))
        missed_value = event.get("missed_fixture_vulnerabilities", 0)
        if isinstance(missed_value, int) and not isinstance(missed_value, bool):
            missed += missed_value
    return RankingMetrics(
        tier=tier,
        verified_findings=verified,
        false_positives=false_positives,
        time_to_verification_seconds=round(sum(verification_times) / len(verification_times), 2) if verification_times else 0.0,
        missed_fixture_vulnerabilities=missed,
        false_positive_reasons=dict(sorted(reason_counts.items())),
    )


def calibrate_ranking(ranking: RankingScore, learnings: list[FalsePositiveLearning]) -> RankingCalibration:
    applicable = [learning for learning in learnings if _learning_applies(ranking.path, learning)]
    calibrated = ranking.priority
    prompt_constraints: list[str] = []
    retrieval_adjustments: dict[str, str] = {}
    for learning in applicable:
        calibrated = max(1.0, calibrated - learning.demotion)
        prompt_constraints.append(f"Do not repeat unsupported {learning.vulnerability_class} claim for scope {learning.scope} without new evidence.")
        retrieval_adjustments[learning.vulnerability_class] = learning.scope
    return RankingCalibration(
        path=ranking.path,
        original_priority=ranking.priority,
        calibrated_priority=round(calibrated, 2),
        applied_learning_ids=[learning.finding_id for learning in applicable],
        retrieval_filter_adjustments=retrieval_adjustments,
        prompt_constraints=prompt_constraints,
    )


def calibrate_rankings(
    rankings: list[RankingScore],
    learnings: list[FalsePositiveLearning],
) -> tuple[list[RankingScore], list[RankingCalibration]]:
    calibrations = [calibrate_ranking(ranking, learnings) for ranking in rankings]
    calibrated = [apply_ranking_calibration(ranking, calibration) for ranking, calibration in zip(rankings, calibrations, strict=True)]
    return sorted(calibrated, key=lambda item: (-item.priority, item.path)), calibrations


def apply_ranking_calibration(ranking: RankingScore, calibration: RankingCalibration) -> RankingScore:
    if ranking.path != calibration.path:
        raise ValueError("calibration path does not match ranking path")
    return RankingScore(
        path=ranking.path,
        surface=ranking.surface,
        influence=ranking.influence,
        reachability=ranking.reachability,
        priority=max(1.0, min(ranking.priority, calibration.calibrated_priority)),
        rationale=f"{ranking.rationale}; calibrated by false-positive learning" if calibration.applied_learning_ids else ranking.rationale,
        model_id=ranking.model_id,
        static_boosts=ranking.static_boosts,
    )


def write_false_positive_learnings(learnings: list[FalsePositiveLearning], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"learnings": [asdict(learning) for learning in learnings]}, indent=2, sort_keys=True) + "\n")


def _vulnerability_class(finding: StaticFinding) -> str:
    if finding.tags:
        return finding.tags[0]
    return finding.title.lower().replace(" ", "_")[:64]


def _default_scope(path: str, vulnerability_class: str) -> str:
    parent = Path(path).parent.as_posix()
    return f"{parent if parent != '.' else path}:{vulnerability_class}"


def _learning_applies(path: str, learning: FalsePositiveLearning) -> bool:
    if learning.path == path:
        return True
    if ":" not in learning.scope:
        return False
    scope_path, _ = learning.scope.rsplit(":", 1)
    return scope_path not in ("", ".") and path.startswith(f"{scope_path}/")


def _reason_from_outcome(outcome: FindingOutcome) -> FalsePositiveReason:
    if outcome == FindingOutcome.DUPLICATE:
        return FalsePositiveReason.DUPLICATE
    if outcome == FindingOutcome.UNSUPPORTED:
        return FalsePositiveReason.UNSUPPORTED
    if outcome == FindingOutcome.CONTRADICTED:
        return FalsePositiveReason.CONTRADICTED
    if outcome == FindingOutcome.UNVERIFIED:
        return FalsePositiveReason.UNVERIFIED
    if outcome in (FindingOutcome.FALSE_POSITIVE, FindingOutcome.REJECTED):
        return FalsePositiveReason.INCORRECT_MODEL_ASSUMPTION
    raise ValueError(f"unsupported finding outcome for false-positive learning: {outcome}")


_FALSE_POSITIVE_OUTCOMES = {
    FindingOutcome.FALSE_POSITIVE,
    FindingOutcome.REJECTED,
    FindingOutcome.DUPLICATE,
    FindingOutcome.UNSUPPORTED,
    FindingOutcome.CONTRADICTED,
    FindingOutcome.UNVERIFIED,
}
