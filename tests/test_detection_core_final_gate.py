"""Task 11.4 final detection-core validation gate."""

from __future__ import annotations

from detection_core_final_gate import run_final_gate


def test_detection_core_final_gate_reads_and_executes_every_declared_input() -> None:
    report = run_final_gate()

    assert report.core_file_count > 0
    assert report.core_bytes > 0
    assert report.repository_file_count > report.core_file_count
    assert report.repository_bytes > report.core_bytes
    assert report.historical_artifact_count == 2
    assert report.historical_bytes > 0
    assert report.consumer_selector_count == 37
    assert report.declared_test_file_count > 0
    assert report.declared_test_bytes > 0
    assert report.tests_collected >= report.consumer_selector_count
    assert report.pytest_exit_code == 0
