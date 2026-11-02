"""Production-source closure for the detection-core v1 migration."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from core_migration_boundary import inspect_legacy_boundary
from core_migration_inventory import (
    REPO,
    MigrationDisposition,
    load_migration_inventory,
    validate_historical_artifacts,
    validate_inventory_sources,
    validate_inventory_transition,
)
from core_migration_scope import COMPATIBILITY_PATHS, boundary_python

INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"

_V2_MIGRATED = frozenset(
    {
        "1c8eeb5e2b6949fb391f16030e1f9aafd676fc854761a7cd1fbf574341c90ef8",
        "85631fe892d3ae9307ea2f93de6c0e280d2d8e0054fefffaa9b6edca330247a2",
        "86a1113a0052c928c53719ff8ee4b110aa4bdd1a8d20ff9ab7492227e346e872",
        "91f404b327f8ed526ebbd1370e6f8b065af6238e3815ece46ac1de3c35845113",
        "eb963401f43fca11e38c50e5e064f58b33233b9564a3a85e5b629a6fb2820d7d",
        "f8a5c42661f6a79b0abbe668e8993fd0ec26d1c9dad5df4e141472e6de62f586",
    }
)
_RETIRED = frozenset(
    {
        "005f1fee3a1a659a65a45d8134bc71f061e314bdc28ba95516e870997c2648cd",
        "0d2cdb31783316d18cb28e987029ac7ad1e86e1e54a568df0cfbd8e138af34ac",
        "1b90ea5474dff89121dc1317a86892bb0d68f2c64117923c5979cf4bb0cd8b76",
        "23e6ccf25c185ca231d73ab02570b14a9cddae27f7506e95d517e241bb693ae4",
        "2e59a0d8bf2764879f78c5f85841ef496c53f2a89bd1eba7248cbf9020828c58",
        "4c846ba1d97e5a5b4bbf8f1e99e10c40da10906ca93d68596cb987738438582a",
        "577f8955e147afee6590d0e5735df7a963d29ca90ed508a46323d1a0a71f62e0",
        "5852ea0d3160cc0969ab05c1c2b11047bd5915e6164fe43d13744c053716d768",
        "9eb4cba855044fe025daa7a523458c4fba0b12758ca604c894849f824f55ccb4",
        "9f2097b8a673c3079a8a61cc28e9099c671e48e6c29a3e95a9e3aac3d53ccb00",
        "a5be0d8793d0048de9444366db2fd389640e99c04a9e8ef450453644c004ffa0",
        "c8aaf430009a592a8ed4361f38023d5faa12a6da6186fc0dcea9c7c522da85ad",
    }
)
_PRODUCTION_ENTRY_IDS = _V2_MIGRATED | _RETIRED


def _production_consumer_paths(root: Path = REPO) -> tuple[Path, ...]:
    paths = []
    for path in boundary_python(root):
        relative = path.relative_to(root).as_posix()
        if not relative.startswith("src/"):
            continue
        if relative in COMPATIBILITY_PATHS or relative.startswith("src/openultrasast/core/legacy_v1/"):
            continue
        paths.append(path)
    return tuple(paths)


def test_registered_production_entries_close_without_rekeying_other_consumers() -> None:
    candidate = load_migration_inventory(INVENTORY)
    production = {entry.entry_id: entry for entry in candidate.entries if entry.entry_id in _PRODUCTION_ENTRY_IDS}

    assert set(production) == _PRODUCTION_ENTRY_IDS
    assert all(production[entry_id].disposition is MigrationDisposition.V2_MIGRATED for entry_id in _V2_MIGRATED)
    assert all(production[entry_id].disposition is MigrationDisposition.RETIRED for entry_id in _RETIRED)
    assert all(entry.disposition is MigrationDisposition.OPEN for entry in candidate.entries if entry.entry_id not in production)

    frozen = replace(
        candidate,
        entries=tuple(
            replace(entry, disposition=MigrationDisposition.OPEN) if entry.entry_id in production else entry for entry in candidate.entries
        ),
    )
    validate_inventory_transition(frozen, candidate)
    validate_inventory_sources(candidate, root=REPO)


def test_verified_nonzero_production_consumer_scope_has_exact_zero_legacy_references() -> None:
    inventory = load_migration_inventory(INVENTORY)
    paths = _production_consumer_paths()

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


def test_production_closure_preserves_frozen_historical_bytes() -> None:
    inventory = load_migration_inventory(INVENTORY)

    artifacts = validate_historical_artifacts(inventory, root=REPO)

    assert len(artifacts) == len(inventory.historical_artifacts) > 0
