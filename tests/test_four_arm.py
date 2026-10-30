"""Task 12.4 -- four-arm development comparison (Reqs 5.2, 5.5, 5.7, 11.8).

Baseline/candidate analyzer crossed with baseline/candidate facts over identical
inputs; fixture arms isolate fact-only lift from analyzer-only lift. No admission
language in any report field.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import development_runner  # noqa: E402


def _record(
    *,
    change_id: str = "change-1",
    unguarded: int = 1,
    indeterminate: int = 0,
    seconds: float = 1.0,
    judgment_transition: str = "same",
) -> development_runner.DevelopmentRecord:
    return development_runner.DevelopmentRecord(
        change_id=change_id,
        analyzer_revision="a" * 12,
        fact_set_digest="b" * 12,
        acquisition_record_digest="none",
        configuration_digest="c" * 12,
        population_digest="d" * 12,
        input_digest="e" * 12,
        stage_funnel={"judgment": {"unguarded": unguarded, "discharged": 0, "indeterminate": indeterminate}},
        judgment_transition=judgment_transition,
        seconds=seconds,
    )


def test_four_arm_report_contains_all_arms() -> None:
    baseline_analyzer_baseline_facts = (_record(),)
    baseline_analyzer_candidate_facts = (_record(unguarded=0, indeterminate=1),)
    candidate_analyzer_baseline_facts = (_record(unguarded=0, indeterminate=1),)
    candidate_analyzer_candidate_facts = (_record(unguarded=0, indeterminate=1),)
    report = development_runner.four_arm_report(
        baseline_analyzer_baseline_facts,
        baseline_analyzer_candidate_facts,
        candidate_analyzer_baseline_facts,
        candidate_analyzer_candidate_facts,
    )
    assert report["arms"] == (
        "baseline-analyzer/baseline-facts",
        "baseline-analyzer/candidate-facts",
        "candidate-analyzer/baseline-facts",
        "candidate-analyzer/candidate-facts",
    )


def test_four_arm_report_isolates_fact_only_and_analyzer_only_lift() -> None:
    """Done-when: fixture arms isolate fact-only lift from analyzer-only lift."""
    # baseline/baseline: unguarded; only-facts-changed: discharged; only-analyzer-changed: discharged.
    bab = (_record(unguarded=1),)
    bacf = (_record(unguarded=0, indeterminate=0),)
    cabf = (_record(unguarded=0, indeterminate=0),)
    cacfon = (_record(unguarded=0, indeterminate=0),)
    report = development_runner.four_arm_report(bab, bacf, cabf, cacfon)
    assert report["fact_only_lift"] == {"unguarded": -1, "discharged": 0, "indeterminate": 0}
    assert report["analyzer_only_lift"] == {"unguarded": -1, "discharged": 0, "indeterminate": 0}


def test_four_arm_report_includes_judgment_transitions() -> None:
    bab = (_record(judgment_transition="same"),)
    bacf = (_record(judgment_transition="unguarded->indeterminate"),)
    cabf = (_record(judgment_transition="same"),)
    cacfon = (_record(judgment_transition="unguarded->discharged"),)
    report = development_runner.four_arm_report(bab, bacf, cabf, cacfon)
    transitions = cast("tuple[str, ...]", report["transitions"])
    assert "unguarded->indeterminate" in transitions
    assert "unguarded->discharged" in transitions


def test_four_arm_report_contains_no_admission_language() -> None:
    bab = bacf = cabf = cacfon = (_record(),)
    report = development_runner.four_arm_report(bab, bacf, cabf, cacfon)
    text = repr(report)
    for word in ("admission", "vulnerable", "ordinary", "label"):
        assert word not in text.lower()


def test_four_arm_report_includes_metric_and_funnel_deltas() -> None:
    bab = (_record(unguarded=1, seconds=2.0),)
    bacf = (_record(unguarded=0, seconds=3.0),)
    cabf = (_record(unguarded=0, seconds=2.5),)
    cacfon = (_record(unguarded=0, seconds=3.5),)
    report = development_runner.four_arm_report(bab, bacf, cabf, cacfon)
    fact_delta = cast("dict[str, int]", report["judgment_delta_fact_only"])
    analyzer_delta = cast("dict[str, int]", report["judgment_delta_analyzer_only"])
    funnel_delta = cast("dict[str, float]", report["funnel_delta_fact_only"])
    assert fact_delta["unguarded"] == -1
    assert analyzer_delta["unguarded"] == -1
    assert "seconds" in funnel_delta
