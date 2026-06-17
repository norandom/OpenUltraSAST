from pathlib import Path

from openultrasast.calibration import (
    FalsePositiveReason,
    FindingOutcome,
    apply_ranking_calibration,
    calibrate_ranking,
    calibrate_rankings,
    compute_ranking_metrics,
    learning_from_finding_outcome,
    record_false_positive_learning,
    write_false_positive_learnings,
)
from openultrasast.findings import StaticFinding
from openultrasast.rank import RankingScore


def _finding(path: str = "auth/login.py") -> StaticFinding:
    return StaticFinding(
        finding_id="python-unsafe-eval:auth/login.py:1",
        path=path,
        title="Dynamic Python execution needs review",
        severity="high",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="pattern matched",
        line=1,
        tags=["syscall_entry"],
        ranking_priority=4.0,
    )


def _ranking(path: str) -> RankingScore:
    return RankingScore(
        path=path,
        surface=4,
        influence=2,
        reachability=4,
        priority=3.6,
        rationale="heuristic",
        model_id=None,
        static_boosts=["syscall_entry"],
    )


def test_false_positive_learning_records_reason_and_scope(tmp_path: Path) -> None:
    learning = record_false_positive_learning(
        _finding(),
        reason=FalsePositiveReason.MISSING_ATTACKER_CONTROL,
        evidence="Verifier showed input is constant and not attacker-controlled.",
    )
    output = tmp_path / "false-positive-learnings.json"

    write_false_positive_learnings([learning], output)

    assert learning.vulnerability_class == "syscall_entry"
    assert learning.scope == "auth:syscall_entry"
    assert "missing_attacker_control" in output.read_text()


def test_ranking_metrics_track_false_positive_reasons_by_tier() -> None:
    metrics = compute_ranking_metrics(
        [
            {"tier": "A", "outcome": FindingOutcome.VERIFIED, "time_to_verification_seconds": 10},
            {"tier": "A", "outcome": FindingOutcome.REJECTED, "reason": FalsePositiveReason.UNREACHABLE_PATH, "time_to_verification_seconds": 20},
            {"tier": "B", "outcome": FindingOutcome.REJECTED, "reason": FalsePositiveReason.DUPLICATE},
            {"tier": "A", "outcome": FindingOutcome.UNVERIFIED, "reason": FalsePositiveReason.UNVERIFIED, "missed_fixture_vulnerabilities": 1},
        ],
        tier="A",
    )

    assert metrics.verified_findings == 1
    assert metrics.false_positives == 2
    assert metrics.time_to_verification_seconds == 15.0
    assert metrics.missed_fixture_vulnerabilities == 1
    assert metrics.false_positive_reasons["unreachable_path"] == 1


def test_scoped_false_positive_demotion_does_not_suppress_class_globally() -> None:
    learning = record_false_positive_learning(
        _finding("auth/login.py"),
        reason=FalsePositiveReason.STATIC_RULE_MISMATCH,
        evidence="Rule matched a test-only wrapper in this auth path.",
    )

    same_scope = apply_ranking_calibration(_ranking("auth/login.py"), calibrate_ranking(_ranking("auth/login.py"), [learning]))
    other_scope = apply_ranking_calibration(_ranking("payments/login.py"), calibrate_ranking(_ranking("payments/login.py"), [learning]))

    assert same_scope.priority < 3.6
    assert other_scope.priority == 3.6


def test_verifier_outcome_feeds_ranking_calibration_and_prompt_constraints() -> None:
    learning = learning_from_finding_outcome(
        _finding("auth/login.py"),
        outcome=FindingOutcome.CONTRADICTED,
        evidence="Independent verifier showed the risky call is unreachable in production flow.",
    )
    assert learning is not None

    calibrated, calibrations = calibrate_rankings([_ranking("auth/login.py")], [learning])

    assert calibrated[0].priority < 3.6
    assert calibrations[0].retrieval_filter_adjustments == {"syscall_entry": "auth:syscall_entry"}
    assert "without new evidence" in calibrations[0].prompt_constraints[0]


def test_verified_outcome_does_not_create_false_positive_learning() -> None:
    learning = learning_from_finding_outcome(
        _finding(),
        outcome=FindingOutcome.VERIFIED,
        evidence="Verifier confirmed attacker control and impact.",
    )

    assert learning is None
