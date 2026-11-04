"""Immutable worklist tests for the detection-core v1 migration."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import core_migration_audit
import pytest
from core_migration_audit import audit_legacy_readers, tracked_python
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

INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"
MIXED_V2_MODULES = frozenset(
    {
        "src/openultrasast/core/budget.py",
        "src/openultrasast/core/coverage.py",
        "src/openultrasast/core/factpack.py",
        "src/openultrasast/core/probes.py",
        "src/openultrasast/core/provenance.py",
    }
)


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "import openultrasast.core.probes as legacy_probes\nresult = legacy_probes.LegacyProbeResult\n",
            "module_attr:openultrasast.core.probes:LegacyProbeResult",
        ),
        (
            "from openultrasast.core import budget as legacy_budget\nresult = legacy_budget.Budget\n",
            "module_attr:openultrasast.core.budget:Budget",
        ),
    ),
)
def test_reader_audit_covers_direct_legacy_submodule_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, expected: str
) -> None:
    monkeypatch.setattr(core_migration_audit, "REPO", tmp_path)
    path = tmp_path / "reader.py"
    path.write_text(source, encoding="utf-8")

    report = audit_legacy_readers((path,))

    assert report.files_read == 1 and report.bytes_read == len(source.encode())
    assert report.capabilities == (("reader.py", expected),)


def test_reader_audit_covers_real_direct_legacy_submodule_reads() -> None:
    paths = tuple(REPO / path for path in ("tests/test_core_budget_v2.py", "tests/test_core_contract.py", "tests/test_core_probes.py"))

    report = audit_legacy_readers(paths)

    assert report.files_read == 3 and report.bytes_read > 0
    assert report.capabilities == ()


def test_frozen_inventory_resolves_nonzero_sources_and_targets() -> None:
    content = INVENTORY.read_bytes()
    assert content, "the inventory instrument must read nonzero bytes"

    inventory = load_migration_inventory(INVENTORY)

    assert inventory.entries
    assert sum(entry.disposition is MigrationDisposition.OPEN for entry in inventory.entries) == 0
    assert sum(entry.disposition is MigrationDisposition.V2_MIGRATED for entry in inventory.entries) == 65
    assert sum(entry.disposition is MigrationDisposition.RETIRED for entry in inventory.entries) == 133
    assert all(entry.entry_id == entry_identity(entry) for entry in inventory.entries)
    validate_inventory_sources(inventory, root=REPO)


def test_inventory_covers_known_live_legacy_boundaries() -> None:
    inventory = load_migration_inventory(INVENTORY)
    registered_readers = {entry.path for entry in inventory.entries if entry.dependency_kind.value == "reader"}
    registered_writers = {entry.path for entry in inventory.entries if entry.dependency_kind.value == "writer"}

    assert registered_readers == {
        "benchmarks/valid/arm_regression.py",
        "benchmarks/valid/prover_admission.py",
        "src/openultrasast/core/__init__.py",
        "src/openultrasast/core/consumer.py",
        "src/openultrasast/core/factpack.py",
        "src/openultrasast/core/trace.py",
        "src/openultrasast/hunt/prover.py",
        "src/openultrasast/semantic/obligations/core_adapter.py",
        "tests/test_core_admission.py",
        "tests/test_core_budget.py",
        "tests/test_core_budget_v2.py",
        "tests/test_core_contract.py",
        "tests/test_core_coverage_v2.py",
        "tests/test_core_factpack_consumer.py",
        "tests/test_core_factpack_file.py",
        "tests/test_core_native.py",
        "tests/test_core_probes.py",
        "tests/test_core_validation.py",
    }
    assert registered_writers == {
        "benchmarks/learn/engine_task_entry.py",
        "benchmarks/measurements/2026-10-14-access-control-hunt/analyse.py",
        "benchmarks/unseen/calibrate.py",
        "benchmarks/unseen/replay.py",
        "benchmarks/unseen/score.py",
        "benchmarks/valid/admission_run.py",
        "benchmarks/valid/arm_regression.py",
        "benchmarks/valid/development_runner.py",
        "benchmarks/valid/hunter_arm.py",
        "benchmarks/valid/judge_pass.py",
        "benchmarks/valid/metrics.py",
        "benchmarks/valid/prover_arm.py",
        "benchmarks/valid/semgrep_arm.py",
        "ops/smoke_admission.py",
        "ops/smoke_report.py",
        "src/openultrasast/core/_legacy_factpack.py",
        "src/openultrasast/core/consumer.py",
        "src/openultrasast/core/probes.py",
        "src/openultrasast/core/trace.py",
        "src/openultrasast/hunt/prover.py",
        "src/openultrasast/hunt/report.py",
        "src/openultrasast/hunt/runner.py",
        "src/openultrasast/push/runner.py",
        "src/openultrasast/semantic/obligations/core_adapter.py",
        "tests/test_admission_scoring.py",
        "tests/test_arm_regression.py",
        "tests/test_core_contract.py",
        "tests/test_core_factpack_consumer.py",
        "tests/test_development_runner.py",
        "tests/test_four_arm.py",
        "tests/test_hunt_ablation.py",
        "tests/test_hunt_artifact.py",
        "tests/test_hunt_contamination.py",
        "tests/test_hunter_arm.py",
        "tests/test_obligation_judgment.py",
        "tests/test_obligation_trace.py",
        "tests/test_push_admission.py",
        "tests/test_push_report.py",
        "tests/test_runner_gates.py",
        "tests/test_semgrep_arm.py",
        "tests/test_unseen_calibrate.py",
        "tests/test_unseen_proof.py",
        "tests/test_unseen_replay.py",
        "tests/test_unseen_score.py",
    }


def test_inventory_registers_the_active_legacy_probe_writer() -> None:
    inventory = load_migration_inventory(INVENTORY)

    assert any(
        entry.path == "src/openultrasast/core/probes.py"
        and entry.symbol == "reversed_pair_probe"
        and entry.dependency_kind.value == "writer"
        for entry in inventory.entries
    )


def test_independent_reader_audit_matches_split_inventory_capabilities() -> None:
    report = audit_legacy_readers(tracked_python())

    assert report.files_read > 0 and report.bytes_read > 0
    assert not any("legacy_v1" in capability for _path, capability in report.capabilities)
    assert not any(path in {"tests/test_core_contract.py", "tests/test_core_probes.py"} for path, _capability in report.capabilities)


def test_inventory_targets_require_exact_capability_anchors(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    terminal = next(item for item in frozen.entries if item.symbol == "<module>")
    entry = replace(terminal, disposition=MigrationDisposition.OPEN)
    assert entry.capability_anchors
    substituted = tmp_path / entry.path
    substituted.parent.mkdir(parents=True)
    substituted.write_text("def unrelated():\n    return True\n", encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="capability"):
        validate_inventory_sources(replace(frozen, entries=(entry,)), root=tmp_path)


def test_historical_artifact_manifest_pins_exact_nonzero_bytes() -> None:
    inventory = load_migration_inventory(INVENTORY)

    artifacts = validate_historical_artifacts(inventory, root=REPO)

    assert {artifact.schema_version for artifact in artifacts} == {"trace-v1", "admission-report-v1"}
    assert all(artifact.byte_length > 0 for artifact in artifacts)


@pytest.mark.parametrize("terminal", (MigrationDisposition.V2_MIGRATED, MigrationDisposition.RETIRED))
def test_inventory_entries_close_monotonically_without_identity_changes(terminal: MigrationDisposition) -> None:
    candidate = load_migration_inventory(INVENTORY)
    index = next(index for index, entry in enumerate(candidate.entries) if entry.disposition is terminal)
    open_entry = replace(candidate.entries[index], disposition=MigrationDisposition.OPEN)
    frozen = replace(candidate, entries=(*candidate.entries[:index], open_entry, *candidate.entries[index + 1 :]))

    validate_inventory_transition(frozen, candidate)

    with pytest.raises(LegacyInventoryError, match="terminal"):
        validate_inventory_transition(candidate, frozen)


def test_inventory_transition_refuses_runtime_invalid_disposition() -> None:
    frozen = load_migration_inventory(INVENTORY)
    invalid = replace(frozen.entries[0], disposition="closed")  # type: ignore[arg-type]
    candidate = replace(frozen, entries=(invalid, *frozen.entries[1:]))

    with pytest.raises(LegacyInventoryError, match="disposition"):
        validate_inventory_transition(frozen, candidate)


@pytest.mark.parametrize("mutation", ("add", "delete", "rekey"))
def test_inventory_refuses_additions_deletions_and_rekeying(mutation: str) -> None:
    frozen = load_migration_inventory(INVENTORY)
    if mutation == "add":
        added = replace(
            frozen.entries[0],
            entry_id="f" * 64,
            path="src/openultrasast/core/canonical.py",
            symbol="<module>",
        )
        candidate = replace(frozen, entries=(*frozen.entries, added))
    elif mutation == "delete":
        candidate = replace(frozen, entries=frozen.entries[1:])
    else:
        changed = replace(frozen.entries[0], symbol="different_target")
        changed = replace(changed, entry_id=entry_identity(changed))
        candidate = replace(frozen, entries=(changed, *frozen.entries[1:]))

    with pytest.raises(LegacyInventoryError, match="identities"):
        validate_inventory_transition(frozen, candidate)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (("schema_version", "v2", "schema"), ("disposition", "closed", "disposition")),
)
def test_inventory_refuses_schema_and_status_mutations(tmp_path: Path, field: str, value: str, message: str) -> None:
    document = json.loads(INVENTORY.read_bytes())
    if field == "schema_version":
        document[field] = value
    else:
        document["entries"][0][field] = value
    changed = tmp_path / "migration_inventory.json"
    changed.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match=message):
        load_migration_inventory(changed)


def test_inventory_refuses_unreadable_zero_and_unknown_targets(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    original = replace(frozen.entries[0], disposition=MigrationDisposition.OPEN)

    missing = replace(original, path="missing.py", symbol="<module>")
    missing = replace(missing, entry_id=entry_identity(missing))
    with pytest.raises(LegacyInventoryError, match="readable"):
        validate_inventory_sources(replace(frozen, entries=(missing,)), root=tmp_path)

    empty_path = tmp_path / "empty.py"
    empty_path.write_bytes(b"")
    empty = replace(original, path="empty.py", symbol="<module>")
    empty = replace(empty, entry_id=entry_identity(empty))
    with pytest.raises(LegacyInventoryError, match="nonzero"):
        validate_inventory_sources(replace(frozen, entries=(empty,)), root=tmp_path)

    source_path = tmp_path / "source.py"
    source_path.write_text("def present():\n    return True\n", encoding="utf-8")
    unknown = replace(original, path="source.py", symbol="absent")
    unknown = replace(unknown, entry_id=entry_identity(unknown))
    with pytest.raises(LegacyInventoryError, match="target"):
        validate_inventory_sources(replace(frozen, entries=(unknown,)), root=tmp_path)


@pytest.mark.parametrize("mutation", ("symbol", "anchor"))
def test_mixed_owner_transfer_refuses_rekeyed_inventory_entries(mutation: str) -> None:
    frozen = load_migration_inventory(INVENTORY)
    original = next(
        entry for entry in frozen.entries if entry.entry_id == "9eb4cba855044fe025daa7a523458c4fba0b12758ca604c894849f824f55ccb4"
    )
    if mutation == "symbol":
        changed = replace(original, symbol="InstrumentFailure", capability_anchors=("definition:InstrumentFailure",))
    else:
        changed = replace(
            original,
            capability_anchors=("import_from:openultrasast.core._legacy_factpack:InstrumentFailure",),
        )
    changed = replace(changed, entry_id=entry_identity(changed))

    with pytest.raises(LegacyInventoryError, match="target|capability"):
        validate_inventory_sources(replace(frozen, entries=(changed,)), root=REPO)


@pytest.mark.parametrize(
    ("facade_source", "owner_source"),
    (
        (
            "from openultrasast.core.legacy_v1.writer import FactPackError\n",
            "class FactPackError(ValueError):\n    pass\n",
        ),
        (
            "from openultrasast.core.legacy_v1.contracts import FactPackError\n",
            "class AnotherContract:\n    pass\n",
        ),
    ),
)
def test_mixed_owner_transfer_refuses_wrong_or_missing_destination(tmp_path: Path, facade_source: str, owner_source: str) -> None:
    frozen = load_migration_inventory(INVENTORY)
    original = next(
        entry for entry in frozen.entries if entry.entry_id == "9eb4cba855044fe025daa7a523458c4fba0b12758ca604c894849f824f55ccb4"
    )
    mixed = tmp_path / original.path
    mixed.parent.mkdir(parents=True)
    mixed.write_text("pass\n", encoding="utf-8")
    namespace = tmp_path / "src/openultrasast/core/legacy_v1"
    namespace.mkdir(parents=True)
    (namespace / "__init__.py").write_text(facade_source, encoding="utf-8")
    (namespace / "contracts.py").write_text(owner_source, encoding="utf-8")

    with pytest.raises(LegacyInventoryError, match="capability"):
        validate_inventory_sources(replace(frozen, entries=(original,)), root=tmp_path)


def test_inventory_refuses_changed_artifact_bytes(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    artifact = frozen.historical_artifacts[0]
    target = tmp_path / artifact.path
    target.parent.mkdir(parents=True)
    target.write_bytes(b"{}\n")

    with pytest.raises(LegacyInventoryError, match="digest|length"):
        validate_historical_artifacts(replace(frozen, historical_artifacts=(artifact,)), root=tmp_path)
