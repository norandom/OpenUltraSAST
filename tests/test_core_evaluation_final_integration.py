"""Final compatibility, regression, and schema-export gate for evaluation admission V3."""

from __future__ import annotations

from pathlib import Path

import pytest
from detection_core_final_integration import (
    EVALUATION_ADMISSION_SCHEMA_V3,
    FinalGateInputClass,
    FinalGateInputError,
    RecordingContentResolver,
    RuntimeInputOrigin,
    collect_final_gate_inputs,
    record_final_gate_input,
)
from detection_core_fixtures import InMemoryContentResolver
from test_core_evaluation_end_to_end import _complete_replay

from openultrasast.core import __all__ as core_exports
from openultrasast.core import evaluation_admission

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"
GATE_OWNED_NAMES = frozenset(
    {
        "detection_core_final_integration.py",
        "test_core_evaluation_final_integration.py",
    }
)


def test_final_gate_reads_every_bounded_input_before_interpreting_results() -> None:
    inputs = collect_final_gate_inputs(REPO)
    gate_owned = {TESTS / name for name in GATE_OWNED_NAMES}
    matching_v3 = set(TESTS.glob("test_core_evaluation_*.py"))
    matching_core = set(TESTS.glob("test_core*.py"))

    assert set(inputs.gate_instrument_paths) == gate_owned
    assert set(inputs.v3_suite_paths) == matching_v3 - gate_owned
    assert set(inputs.core_regression_paths) == matching_core - gate_owned
    assert inputs.v2_fixture_bytes > 0
    assert inputs.v3_suite_bytes > 0
    assert inputs.core_regression_bytes >= inputs.v3_suite_bytes
    assert inputs.gate_instrument_bytes > 0
    assert inputs.support_bytes > 0
    assert inputs.external_population_inputs == ()
    assert inputs.records
    assert all(record.byte_count > 0 for record in inputs.records)
    assert all(record.resolved_path.is_relative_to(REPO.resolve()) for record in inputs.records)
    assert {record.classification for record in inputs.records} == {
        FinalGateInputClass.V2_FIXTURE,
        FinalGateInputClass.V3_SUITE,
        FinalGateInputClass.CORE_REGRESSION,
        FinalGateInputClass.GATE_INSTRUMENT,
        FinalGateInputClass.FIXTURE_SUPPORT,
    }


def test_exact_v3_schema_is_exported_only_through_the_public_v3_facade() -> None:
    assert EVALUATION_ADMISSION_SCHEMA_V3 == "openultrasast.detection-core.evaluation-admission.v3"
    assert "evaluation_admission" in core_exports
    assert evaluation_admission.EVALUATION_ADMISSION_V3_SCHEMA == EVALUATION_ADMISSION_SCHEMA_V3
    assert "EVALUATION_ADMISSION_V3_SCHEMA" in evaluation_admission.__all__


def test_final_gate_inventory_includes_compatibility_adversarial_and_growth_suites() -> None:
    inputs = collect_final_gate_inputs(REPO)
    v3_names = {path.name for path in inputs.v3_suite_paths}
    core_names = {path.name for path in inputs.core_regression_paths}
    gate_names = {path.name for path in inputs.gate_instrument_paths}

    assert "test_core_admission_v2_compatibility.py" in core_names
    assert "test_core_evaluation_pre_spend_matrix.py" in v3_names
    assert "test_core_evaluation_post_spend_matrix.py" in v3_names
    assert "test_core_evaluation_end_to_end.py" in v3_names
    assert "test_core_evaluation_boundary_performance.py" in v3_names
    assert gate_names == GATE_OWNED_NAMES
    assert GATE_OWNED_NAMES.isdisjoint(v3_names)
    assert GATE_OWNED_NAMES.isdisjoint(core_names)


def test_input_census_refuses_outside_symlink_empty_and_unclassified_paths(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(FinalGateInputError, match="outside repository"):
        record_final_gate_input(REPO, outside)

    temporary_repo = tmp_path / "repo"
    temporary_tests = temporary_repo / "tests"
    temporary_tests.mkdir(parents=True)
    unclassified = temporary_tests / "other.py"
    unclassified.write_text("pass\n", encoding="utf-8")
    with pytest.raises(FinalGateInputError, match="unclassified"):
        record_final_gate_input(temporary_repo, unclassified)

    empty = temporary_tests / "test_core_empty.py"
    empty.touch()
    with pytest.raises(FinalGateInputError, match="zero bytes"):
        record_final_gate_input(temporary_repo, empty)

    symlink = temporary_tests / "test_core_evaluation_link.py"
    symlink.symlink_to(outside)
    with pytest.raises(FinalGateInputError, match="symlink"):
        record_final_gate_input(temporary_repo, symlink)


def test_public_synthetic_replay_records_only_nonzero_in_memory_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, replay, *_ = _complete_replay(monkeypatch)
    recorder = RecordingContentResolver(bundle[4], RuntimeInputOrigin.SYNTHETIC_IN_MEMORY)

    reports = evaluation_admission.validate_evaluation_replay(
        replay,
        bundle[5][0].context,
        bundle[5][0].port,
        recorder,
    )

    assert reports == replay.reports
    assert recorder.records
    assert all(record.read_number > 0 for record in recorder.records)
    assert all(record.byte_count > 0 for record in recorder.records)
    assert {record.origin for record in recorder.records} == {RuntimeInputOrigin.SYNTHETIC_IN_MEMORY}


def test_runtime_recorder_refuses_path_backed_and_external_origins_before_validation(tmp_path: Path) -> None:
    class PathBackedResolver:
        def __init__(self) -> None:
            self.path = tmp_path / "population.json"
            self.resolve_calls = 0

        def resolve(self, reference: object) -> object:
            self.resolve_calls += 1
            raise AssertionError(f"path-backed resolver unexpectedly invoked: {reference}")

    path_backed = PathBackedResolver()
    with pytest.raises(FinalGateInputError, match="exact InMemoryContentResolver"):
        RecordingContentResolver(path_backed, RuntimeInputOrigin.SYNTHETIC_IN_MEMORY)  # type: ignore[arg-type]
    assert path_backed.resolve_calls == 0

    with pytest.raises(FinalGateInputError, match="synthetic in-memory origin"):
        RecordingContentResolver(InMemoryContentResolver({}), RuntimeInputOrigin.EXTERNAL_PATH)
