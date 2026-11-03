"""Benchmark-source closure for the detection-core v1 migration."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest
from benchmark_migration_evidence import BENCHMARK_TERMINAL_EVIDENCE
from core_migration_boundary import inspect_legacy_boundary
from core_migration_inventory import (
    REPO,
    LegacyInventoryError,
    MigrationDisposition,
    entry_identity,
    load_migration_inventory,
    validate_historical_artifacts,
    validate_inventory_sources,
    validate_inventory_transition,
)
from core_migration_scope import boundary_python

INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"
sys.path.insert(0, str(REPO))

_V2_MIGRATED = frozenset(entry_id for entry_id, evidence in BENCHMARK_TERMINAL_EVIDENCE.items() if evidence.disposition == "v2_migrated")
_RETIRED = frozenset(entry_id for entry_id, evidence in BENCHMARK_TERMINAL_EVIDENCE.items() if evidence.disposition == "retired")
_BENCHMARK_ENTRY_IDS = _V2_MIGRATED | _RETIRED


def _benchmark_program_paths(root: Path = REPO) -> tuple[Path, ...]:
    """Owned benchmark programs, excluding harvested fixtures and historical corpora."""
    return tuple(
        path
        for path in boundary_python(root)
        if (relative := path.relative_to(root).as_posix()).startswith("benchmarks/") and not relative.startswith("benchmarks/measurements/")
    )


def test_registered_benchmark_entries_close_without_rekeying_other_consumers() -> None:
    candidate = load_migration_inventory(INVENTORY)
    benchmark = {entry.entry_id: entry for entry in candidate.entries if entry.path.startswith("benchmarks/")}

    assert set(benchmark) == _BENCHMARK_ENTRY_IDS
    assert all(benchmark[entry_id].disposition is MigrationDisposition.V2_MIGRATED for entry_id in _V2_MIGRATED)
    assert all(benchmark[entry_id].disposition is MigrationDisposition.RETIRED for entry_id in _RETIRED)
    frozen = replace(
        candidate,
        entries=tuple(
            replace(entry, disposition=MigrationDisposition.OPEN) if entry.entry_id in _BENCHMARK_ENTRY_IDS else entry
            for entry in candidate.entries
        ),
    )
    validate_inventory_transition(frozen, candidate)
    validate_inventory_sources(candidate, root=REPO)


def test_source_validation_refuses_unregistered_terminal_entry() -> None:
    inventory = load_migration_inventory(INVENTORY)
    original = next(entry for entry in inventory.entries if entry.entry_id in _V2_MIGRATED)
    forged = replace(original, artifact_family="unregistered-terminal", entry_id="")
    forged = replace(forged, entry_id=entry_identity(forged))

    with pytest.raises(LegacyInventoryError, match="terminal evidence"):
        validate_inventory_sources(replace(inventory, entries=(forged,)), root=REPO)


def test_source_validation_refuses_removed_migrated_owner(tmp_path: Path) -> None:
    inventory = load_migration_inventory(INVENTORY)
    original = next(entry for entry in inventory.entries if entry.entry_id.startswith("40465a45"))
    target = tmp_path / original.path
    target.parent.mkdir(parents=True)
    target.write_text((REPO / original.path).read_text().replace("def main(", "def removed_main(", 1))

    with pytest.raises(LegacyInventoryError, match="migrated owner is absent"):
        validate_inventory_sources(replace(inventory, entries=(original,)), root=tmp_path)


def test_test_and_operational_entries_remain_open_for_task_10_6() -> None:
    candidate = load_migration_inventory(INVENTORY)
    deferred = {
        entry.disposition for entry in candidate.entries if entry.owner_boundary in {"tests", "operational-tooling", "repository-tooling"}
    }

    assert deferred == {MigrationDisposition.OPEN}


def test_old_benchmark_admission_contract_and_runner_are_not_live() -> None:
    from benchmarks.valid import admission_run, prover_admission

    assert not hasattr(admission_run, "run_admission")
    assert not hasattr(admission_run, "assemble_admission_report")
    assert not hasattr(prover_admission, "AdmissionManifest")
    assert not hasattr(prover_admission, "validate_admission_manifest")


def test_registered_live_writers_execute_strict_v2_artifact_conformance(tmp_path: Path) -> None:
    from benchmark_migration_conformance import validate_benchmark_terminal_conformance

    inventory = load_migration_inventory(INVENTORY)
    validate_benchmark_terminal_conformance(inventory, output_root=tmp_path)


@pytest.mark.parametrize("entry_id", sorted(_V2_MIGRATED))
def test_each_registered_owner_is_required_for_its_exact_probe(tmp_path: Path, monkeypatch, entry_id: str) -> None:
    from benchmark_migration_conformance import (
        OWNER_TARGETS,
        BenchmarkMigrationConformanceError,
        probe_benchmark_entry,
    )

    inventory = load_migration_inventory(INVENTORY)
    entry = next(candidate for candidate in inventory.entries if candidate.entry_id == entry_id)
    module_name, symbol = OWNER_TARGETS[entry_id]
    module = __import__(module_name, fromlist=[symbol])

    def removed_owner(*_args, **_kwargs):
        raise RuntimeError("registered owner removed")

    monkeypatch.setattr(module, symbol, removed_owner)
    with pytest.raises(BenchmarkMigrationConformanceError, match=entry_id):
        probe_benchmark_entry(entry, output_root=tmp_path)


@pytest.mark.parametrize(
    "forged",
    ["if 0", "if None", "while False", "local def", "local import", "parameter", "assignment", "comprehension"],
)
def test_dead_or_shadowed_syntax_cannot_close_an_unregistered_entry(tmp_path: Path, forged: str) -> None:
    from benchmark_migration_conformance import BenchmarkMigrationConformanceError, validate_benchmark_terminal_conformance

    inventory = load_migration_inventory(INVENTORY)
    original = next(entry for entry in inventory.entries if entry.entry_id in _V2_MIGRATED)
    unregistered = replace(original, entry_id="f" * 64)
    candidate = replace(inventory, entries=(unregistered,))
    (tmp_path / "forged.py").write_text(f"# {forged}\n")
    with pytest.raises(BenchmarkMigrationConformanceError, match="probe registry"):
        validate_benchmark_terminal_conformance(candidate, output_root=tmp_path / "out")


def test_v2_benchmark_artifact_binds_its_kind_and_payload() -> None:
    from benchmarks.valid.artifact_contract import benchmark_artifact, benchmark_payload

    artifact = benchmark_artifact("readiness-result", {"result_digest": "a" * 64})
    assert benchmark_payload(artifact, expected_kind="readiness-result") == {"result_digest": "a" * 64}

    artifact["artifact_kind"] = "admission-report"
    with pytest.raises(ValueError, match="metadata does not match"):
        benchmark_payload(artifact, expected_kind="readiness-result")


def test_v2_benchmark_jsonl_preserves_ordered_row_persistence(tmp_path: Path) -> None:
    from benchmarks.valid.artifact_contract import read_benchmark_jsonl, write_benchmark_jsonl

    path = tmp_path / "suspicions.jsonl"
    write_benchmark_jsonl(path, "suspicion", ({"id": "first"}, {"id": "second"}))

    assert read_benchmark_jsonl(path, "suspicion") == ({"id": "first"}, {"id": "second"})


def test_verified_nonzero_benchmark_program_scope_has_exact_zero_legacy_references() -> None:
    inventory = load_migration_inventory(INVENTORY)
    paths = _benchmark_program_paths()
    report = inspect_legacy_boundary(
        paths,
        frozen_inventory=inventory,
        candidate_inventory=inventory,
        expected_scope=paths,
        root=REPO,
    )

    assert report.files_read == len(paths) > 0
    assert report.bytes_read > 0
    assert report.scanned_scope_paths == report.expected_scope_paths
    assert report.consumer_legacy_import_sites == ()
    assert report.consumer_legacy_writer_sites == ()
    assert report.forbidden_dynamic_sites == ()
    assert report.compatibility_implementation_sites == ()


def test_benchmark_closure_preserves_frozen_historical_bytes() -> None:
    inventory = load_migration_inventory(INVENTORY)
    artifacts = validate_historical_artifacts(inventory, root=REPO)

    assert len(artifacts) == len(inventory.historical_artifacts) > 0
