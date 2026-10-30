"""Paired scoring and the admission report (Task 12.6, Reqs 5.2, 12.4, 12.5, 12.7-12.9)."""

import json

import pytest

from benchmarks.valid.admission_scoring import (
    AdmissionCase,
    AdmissionScoringError,
    OrdinaryChange,
    admission_report,
)
from benchmarks.valid.prover_admission import AdmissionManifest, validate_admission_manifest


def admission_manifest(role: str = "admission") -> AdmissionManifest:
    payload = {
        "produced_by": "valid-detection-benchmark",
        "reviewed": True,
        "label_isolated": True,
        "spent": False,
        "population_role": role,
        "analyzer_revision": "analyzer-1",
        "fact_set_digest": "facts-1",
        "acquisition_record_digest": "acq-1",
        "configuration_digest": "cfg-1",
        "population_digest": "pop-1",
        "labels": ("population-overview",),
    }
    return validate_admission_manifest(payload)


def correct_pair(case_id: str = "p1", *, seconds: float = 1.0) -> AdmissionCase:
    return AdmissionCase(
        case_id=case_id,
        vulnerable_judgment="unguarded",
        fixed_judgment="discharged",
        location_verified=True,
        seconds=seconds,
    )


def quiet_ordinary(change_id: str = "o1") -> OrdinaryChange:
    return OrdinaryChange(change_id=change_id, judgment="discharged", mislabeled_defect=False)


def test_vulnerable_only_pair_scores_correct() -> None:
    report = admission_report(admission_manifest(), (correct_pair(),), (quiet_ordinary(),), coverage=1.0)
    assert report["pairs"] == {"n": 1, "correct": 1}
    assert report["pair_correctness"]["rate"] == 1.0
    assert report["fix_recall"]["rate"] == 1.0
    assert report["decision"] == "GO"
    assert report["failed_gates"] == []


def test_fixed_side_regression_counts_pair_incorrect() -> None:
    regressed = AdmissionCase(
        case_id="p1",
        vulnerable_judgment="unguarded",
        fixed_judgment="unguarded",
        location_verified=True,
        seconds=1.0,
    )
    report = admission_report(admission_manifest(), (regressed,), (), coverage=1.0)
    assert report["pairs"]["correct"] == 0
    assert report["pair_correctness"]["rate"] == 0.0
    assert report["fix_recall"]["rate"] == 1.0


def test_indeterminate_vulnerable_side_is_never_clean() -> None:
    indeterminate = AdmissionCase(
        case_id="p1",
        vulnerable_judgment="indeterminate",
        fixed_judgment="discharged",
        location_verified=False,
        seconds=1.0,
    )
    report = admission_report(admission_manifest(), (indeterminate,), (), coverage=1.0)
    assert report["fix_recall"]["count"] == 0
    assert report["fix_recall"]["rate"] == 0.0
    assert report["indeterminate_rate"]["count"] == 1
    assert report["indeterminate_rate"]["rate"] > 0.0


def test_mislabeled_negative_is_refused() -> None:
    mislabeled = OrdinaryChange(change_id="o1", judgment="discharged", mislabeled_defect=True)
    with pytest.raises(AdmissionScoringError, match="mislabeled"):
        admission_report(admission_manifest(), (correct_pair(),), (mislabeled,), coverage=1.0)


def test_development_population_is_refused() -> None:
    with pytest.raises(AdmissionScoringError, match="population-role"):
        admission_report(admission_manifest(role="development"), (correct_pair(),), (), coverage=1.0)


def test_verified_location_recall_keeps_sample_count() -> None:
    unverified = AdmissionCase(
        case_id="p2",
        vulnerable_judgment="unguarded",
        fixed_judgment="discharged",
        location_verified=False,
        seconds=1.0,
    )
    report = admission_report(admission_manifest(), (correct_pair("p1"), unverified), (), coverage=1.0)
    assert report["verified_location_recall"]["n"] == 2
    assert report["verified_location_recall"]["count"] == 1
    assert report["verified_location_recall"]["rate"] == 0.5


def test_flagged_ordinary_per_100_and_precision() -> None:
    flagged = [OrdinaryChange(f"o{i}", "unguarded", False) for i in range(2)]
    quiet = [OrdinaryChange(f"q{i}", "discharged", False) for i in range(2)]
    pairs = tuple(correct_pair(f"p{i}") for i in range(3))
    report = admission_report(admission_manifest(), pairs, tuple(flagged + quiet), coverage=1.0)
    per_100 = report["flagged_ordinary_per_100"]
    assert per_100["n"] == 4
    assert per_100["count"] == 2
    assert per_100["rate"] == 50.0
    assert per_100["wilson95"][0] is not None and per_100["wilson95"][0] <= 50.0 <= per_100["wilson95"][1]
    assert report["precision"]["rate"] == pytest.approx(3 / 5)


def test_budget_gate_returns_no_go() -> None:
    slow = correct_pair("slow", seconds=121.0)
    report = admission_report(admission_manifest(), (slow,), (), coverage=1.0)
    assert report["decision"] == "NO-GO"
    assert any("budget" in gate for gate in report["failed_gates"])
    assert any("slow" in gate for gate in report["failed_gates"])


def test_instrument_gate_returns_no_go() -> None:
    report = admission_report(admission_manifest(), (correct_pair(),), (), coverage=1.0, instrument_failures=1)
    assert report["decision"] == "NO-GO"
    assert any("instrument" in gate for gate in report["failed_gates"])


def test_pre_registered_criterion_failure_returns_no_go() -> None:
    missed = AdmissionCase(
        case_id="p1",
        vulnerable_judgment="discharged",
        fixed_judgment="discharged",
        location_verified=False,
        seconds=1.0,
    )
    report = admission_report(
        admission_manifest(),
        (missed,),
        (),
        coverage=1.0,
        criteria={"min_fix_recall": 1.0},
    )
    assert report["decision"] == "NO-GO"
    assert any("min_fix_recall" in gate for gate in report["failed_gates"])


def test_invalid_judgment_is_refused() -> None:
    broken = AdmissionCase(
        case_id="p1",
        vulnerable_judgment="banana",
        fixed_judgment="discharged",
        location_verified=True,
        seconds=1.0,
    )
    with pytest.raises(AdmissionScoringError, match="judgment"):
        admission_report(admission_manifest(), (broken,), (), coverage=1.0)


def test_report_is_deterministic() -> None:
    args = (
        admission_manifest(),
        (correct_pair("p1"), correct_pair("p2")),
        (quiet_ordinary("o1"), OrdinaryChange("o2", "unguarded", False)),
    )
    first = admission_report(*args, coverage=0.75)
    second = admission_report(*args, coverage=0.75)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_report_carries_provenance_without_labels() -> None:
    report = admission_report(admission_manifest(), (correct_pair(),), (), coverage=1.0)
    manifest = report["manifest"]
    assert manifest["analyzer_revision"] == "analyzer-1"
    assert manifest["population_digest"] == "pop-1"
    assert manifest["population_role"] == "admission"
    text = json.dumps(report, sort_keys=True)
    for marker in ("vulnerability", "fix-location", "ordinary-change"):
        assert marker not in text
