"""Presentation bounds cannot alter admission, evidence, or enforcement."""

import json
import os
import time
from dataclasses import replace

import pytest
from test_push_admission import control

from openultrasast.config import PushConfig
from openultrasast.model.contracts import ExecutionBudget, QuestionOutcome
from openultrasast.model.scan import ModelScanResult
from openultrasast.push.policy import admission_push_result, admit_candidates
from openultrasast.push.report import PushReport, ScanRecord, deliver_report


def report_with(count=1, *, admitted=True, blocking=False):
    candidate, capability, analysis = control()
    candidates = tuple(replace(candidate, delta=replace(candidate.delta, defect_id=f"defect-{i}")) for i in range(count))
    admission = admit_candidates(candidates, capabilities=(capability,) if admitted else ())
    result = admission_push_result(admission, (analysis,), config=PushConfig(mode="blocking" if blocking else "advisory"))
    q = analysis.completed_questions[0]
    scan = ModelScanResult(scope=analysis.scopes[0], question_outcomes=(QuestionOutcome(q, "completed", "answered", "[]"),))
    records = (ScanRecord(analysis.comparison, "head", scan), ScanRecord(analysis.comparison, "base", scan))
    provenance = {key: "synthetic-control" for key in ("repository", "engine", "facts", "queries", "policy")}
    return PushReport(result, admission, records, provenance, {"total_seconds": 0.1})


def budget(seconds=3.0):
    return ExecutionBudget(time.monotonic() + seconds, 0.2)


def test_display_cap_preserves_all_decisions_and_complete_artifact(tmp_path):
    report = report_with(5, blocking=True)
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert delivered.exit_code == 1 and delivered.result == report.result
    assert delivered.text.count("- injection at ") == 3 and "2 more" in delivered.text
    assert "Evidence:" in delivered.text and "Change:" in delivered.text and "Fix:" in delivered.text
    data = json.loads(delivered.artifact.read_text())
    assert len(data["admission"]["defects"]) == 5 and len(data["admission"]["dispositions"]) == 5
    assert data["result"]["push_disposition"] == "block"
    assert data["scans"][0]["scan"]["question_outcomes"][0]["raw_rows_json"] == "[]"
    assert data["scans"][0]["scan"]["scope"]["selected"][0]["identity"]["path"] == "handler.src"
    assert data["provenance"] == report.provenance and data["timings"] == report.timings
    assert os.stat(delivered.artifact).st_mode & 0o777 == 0o600


def test_one_incomplete_notice_and_one_status_without_claiming_secure(tmp_path):
    report = report_with(8, admitted=False)
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert delivered.exit_code == 0 and delivered.result.coverage_status == "incomplete"
    assert delivered.text.count("Notice:") == 1
    assert delivered.text.count("No actionable defects") == 1
    assert "Review" in delivered.text and str(delivered.artifact) in delivered.text
    assert "secure" not in delivered.text.lower() and "clean" not in delivered.text.lower()


def test_complete_empty_check_is_bounded_by_scope(tmp_path):
    delivered = deliver_report(report_with(0), tmp_path / "run.json", execution_budget=budget())
    assert "1 completed" in delivered.text and "within" in delivered.text
    assert "Notice:" not in delivered.text and "secure" not in delivered.text.lower()


def test_write_failure_retains_existing_artifact_and_block_decision(tmp_path):
    target = tmp_path / "directory"
    target.mkdir()
    delivered = deliver_report(report_with(blocking=True), target, execution_budget=budget())
    assert delivered.exit_code == 1 and delivered.artifact is None and delivered.error
    assert delivered.text.count("Notice:") == 1 and "writable" in delivered.text
    assert target.is_dir()


def test_invalid_serializable_detail_fails_without_losing_decision(tmp_path):
    report = report_with(blocking=True)
    broken = replace(report.scans[0], scan=replace(report.scans[0].scan, by_rung={"invalid_metadata": object()}))
    report = replace(report, scans=(broken, report.scans[1]))
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert delivered.exit_code == 1 and delivered.artifact is None and delivered.error


def test_mismatched_result_or_missing_evidence_is_rejected():
    report = report_with()
    with pytest.raises(ValueError):
        replace(report, admission=admit_candidates(()))
    with pytest.raises(ValueError):
        replace(report, scans=())
    with pytest.raises(ValueError):
        replace(report, provenance={"engine": "only"})
    with pytest.raises(ValueError):
        replace(report, timings={"total_seconds": float("nan")})


def test_repository_control_characters_cannot_inject_terminal_notices(tmp_path):
    report = report_with()
    defect = replace(report.admission.defects[0], witnesses=("input\nNotice: fake\x1b[31m",))
    report = replace(report, admission=replace(report.admission, defects=(defect,)))
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert "\nNotice: fake" not in delivered.text and "\x1b" not in delivered.text
    assert json.loads(delivered.artifact.read_text())["admission"]["defects"][0]["witnesses"] == ["input\nNotice: fake\x1b[31m"]


def test_expired_reporting_allowance_still_returns_real_decision(tmp_path):
    delivered = deliver_report(report_with(blocking=True), tmp_path / "run.json", execution_budget=ExecutionBudget(0.0, 0.1))
    assert delivered.exit_code == 1 and delivered.error == "report_deadline_exhausted"
    assert delivered.text.count("Notice:") == 1


def test_stalled_writer_is_cancelled_without_overwriting_previous_artifact(tmp_path, monkeypatch):
    import multiprocessing

    import openultrasast.push.report as module

    def stall(*args):
        time.sleep(10)

    target = tmp_path / "run.json"
    target.write_text("previous-complete-artifact")
    children = {p.pid for p in multiprocessing.active_children()}
    monkeypatch.setattr(module, "_write_artifact", stall)
    started = time.monotonic()
    delivered = deliver_report(report_with(blocking=True), target, execution_budget=budget(0.05))
    assert time.monotonic() - started < 0.6
    assert delivered.exit_code == 1 and delivered.error == "report_deadline_exhausted"
    assert target.read_text() == "previous-complete-artifact"
    assert {p.pid for p in multiprocessing.active_children()} == children


def test_long_terminal_values_are_bounded_but_artifact_keeps_full_evidence(tmp_path):
    report = report_with()
    witness = "request.input->" + "x" * 100_000
    defect = replace(report.admission.defects[0], witnesses=(witness,))
    report = replace(report, admission=replace(report.admission, defects=(defect,)))
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert len(delivered.text) < 3000 and witness not in delivered.text
    assert json.loads(delivered.artifact.read_text())["admission"]["defects"][0]["witnesses"] == [witness]


def test_unavailable_and_not_applicable_never_read_as_completed(tmp_path):
    from openultrasast.push.contracts import PushResult
    from openultrasast.push.policy import AdmissionResult

    for coverage, expected_notice in [("unavailable", 1), ("not_applicable", 0)]:
        report = report_with(0)
        result = PushResult((), "none", coverage, "allow", ())
        report = replace(report, result=result, admission=AdmissionResult((), (), ()), scans=())
        delivered = deliver_report(report, tmp_path / (coverage + ".json"), execution_budget=budget())
        assert "completed checks" not in delivered.text and delivered.text.count("Notice:") == expected_notice
        assert delivered.result.coverage_status == coverage


def test_provenance_and_timings_are_frozen_after_construction():
    report = report_with()
    with pytest.raises(TypeError):
        report.provenance["engine"] = "different"
    with pytest.raises(TypeError):
        report.timings["total_seconds"] = 0.0


def test_writer_exiting_zero_without_receipt_is_not_success(tmp_path, monkeypatch):
    import openultrasast.push.report as module

    def empty_writer(report, target, temporary, connection):
        connection.close()

    monkeypatch.setattr(module, "_write_artifact", empty_writer)
    delivered = deliver_report(report_with(blocking=True), tmp_path / "run.json", execution_budget=budget())
    assert delivered.artifact is None and delivered.error and delivered.exit_code == 1


def test_invalid_artifact_destination_is_a_notice_not_an_exception():
    from pathlib import Path

    delivered = deliver_report(report_with(blocking=True), Path("/"), execution_budget=budget())
    assert delivered.artifact is None and delivered.error and delivered.exit_code == 1


def test_failed_base_evidence_cannot_be_presented_as_complete():
    report = report_with(0)
    failed = replace(report.scans[1], scan=ModelScanResult(degradations=({"reason": "cpg_build_failed"},)))
    with pytest.raises(ValueError, match="complete comparison"):
        replace(report, scans=(report.scans[0], failed))
