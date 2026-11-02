"""Task 10.3: syntax-only legacy migration boundary instrument."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from core_migration_boundary import (
    FROZEN_TOP_LEVEL_V1,
    BoundaryPhase,
    LegacyBoundaryError,
    LegacyBoundaryReport,
    boundary_python,
    inspect_legacy_boundary,
    require_cutover_ready,
    static_top_level_v1,
)
from core_migration_inventory import (
    LegacyInventoryError,
    LegacyMigrationInventory,
    MigrationDisposition,
    load_migration_inventory,
)

REPO = Path(__file__).resolve().parents[1]
INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _closed_inventory() -> LegacyMigrationInventory:
    frozen = load_migration_inventory(INVENTORY)
    entries = tuple(replace(entry, disposition=MigrationDisposition.V2_MIGRATED) for entry in frozen.entries)
    return replace(frozen, entries=entries)


def _require_cutover(
    report: LegacyBoundaryReport,
    *,
    frozen: LegacyMigrationInventory,
    candidate: LegacyMigrationInventory,
    root: Path,
    isolated_scope: tuple[Path, ...] | None = None,
) -> None:
    require_cutover_ready(
        report,
        frozen_inventory=frozen,
        candidate_inventory=candidate,
        root=root,
        isolated_scope=isolated_scope,
    )


def test_boundary_reports_explicit_syntax_without_interpreting_flow(tmp_path: Path) -> None:
    source = """try:
    from openultrasast.core.legacy_v1 import Budget
finally:
    pass
from openultrasast.core import Budget as PublicBudget
from openultrasast.core import trace as trace_shim
import openultrasast.core as core_api
from openultrasast.core.legacy_v1 import writer
items = [__import__("openultrasast.core.legacy_v1") for _ in ()]
consume(getattr(core_api, "Budget"))
writer.canonical_json({})
alias = core_api
consume(alias)
"""
    path = _write(tmp_path, "src/example.py", source)
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary((path,), frozen_inventory=frozen, root=tmp_path)

    assert report.files_read == 1
    assert report.bytes_read == len(source.encode())
    assert any("legacy_namespace_import" in site and ":2:" in site for site in report.legacy_import_sites)
    assert any("top_level_v1_import:Budget" in site for site in report.legacy_import_sites)
    assert any("compatibility_shim_import:openultrasast.core.trace" in site for site in report.legacy_import_sites)
    assert any("writer_facade_import" in site for site in report.legacy_writer_sites)
    assert any("writer_facade_reference:canonical_json" in site for site in report.legacy_writer_sites)
    assert any("writer_facade_call:canonical_json" in site for site in report.legacy_writer_sites)
    assert any("module_valued_core_import" in site for site in report.forbidden_dynamic_sites)
    assert any("dynamic_core_import" in site for site in report.forbidden_dynamic_sites)
    assert any("dynamic_compatibility_getattr:Budget" in site for site in report.forbidden_dynamic_sites)
    assert not any("alias" in site for site in (*report.legacy_import_sites, *report.legacy_writer_sites))


def test_boundary_refuses_missing_empty_and_unparseable_inputs(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    missing = tmp_path / "missing.py"
    empty = _write(tmp_path, "empty.py", "")
    broken = _write(tmp_path, "broken.py", "def nope(:\n")

    with pytest.raises(LegacyBoundaryError, match="readable"):
        inspect_legacy_boundary((missing,), frozen_inventory=frozen, root=tmp_path)
    with pytest.raises(LegacyBoundaryError, match="nonzero"):
        inspect_legacy_boundary((empty,), frozen_inventory=frozen, root=tmp_path)
    with pytest.raises(LegacyBoundaryError, match="parseable"):
        inspect_legacy_boundary((broken,), frozen_inventory=frozen, root=tmp_path)


def test_boundary_reports_direct_dynamic_compatibility_attribute_access(tmp_path: Path) -> None:
    source = """import openultrasast.core.legacy_v1 as legacy
import importlib
first = getattr(legacy, "Budget")
second = getattr(importlib.import_module("openultrasast.core.legacy_v1"), "Budget")
encoded = legacy.writer.canonical_json({})
"""
    path = _write(tmp_path, "dynamic.py", source)
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary((path,), frozen_inventory=frozen, root=tmp_path)

    assert sum("dynamic_compatibility_getattr:Budget" in site for site in report.forbidden_dynamic_sites) == 2
    assert any("writer_facade_reference:canonical_json" in site for site in report.legacy_writer_sites)


def test_migration_phase_separates_compatibility_implementation_from_consumers(tmp_path: Path) -> None:
    compatibility = _write(
        tmp_path,
        "src/openultrasast/core/trace.py",
        "from openultrasast.core.legacy_v1.contracts import TraceRecord\n",
    )
    consumer = _write(tmp_path, "src/product.py", "from openultrasast.core.legacy_v1 import TraceRecord\n")
    frozen = load_migration_inventory(INVENTORY)

    migration = inspect_legacy_boundary((compatibility, consumer), frozen_inventory=frozen, root=tmp_path)
    post_deletion = inspect_legacy_boundary(
        (compatibility, consumer),
        frozen_inventory=frozen,
        expected_scope=(compatibility, consumer),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )

    assert len(migration.compatibility_implementation_sites) == 1
    assert len(migration.consumer_legacy_import_sites) == 1
    assert post_deletion.compatibility_implementation_sites == ()
    assert len(post_deletion.consumer_legacy_import_sites) == 2


def test_cutover_requires_terminal_inventory_and_structural_zero(tmp_path: Path) -> None:
    clean = _write(tmp_path, "clean.py", "VALUE = 1\n")
    frozen = load_migration_inventory(INVENTORY)
    open_report = inspect_legacy_boundary(
        (clean,), frozen_inventory=frozen, expected_scope=(clean,), root=tmp_path, phase=BoundaryPhase.POST_DELETION
    )
    closed = _closed_inventory()
    migration_report = inspect_legacy_boundary((clean,), frozen_inventory=frozen, candidate_inventory=closed, root=tmp_path)
    clean_report = inspect_legacy_boundary(
        (clean,),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(clean,),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )
    forbidden = _write(tmp_path, "forbidden.py", "import openultrasast.core as core_api\n")
    forbidden_report = inspect_legacy_boundary(
        (forbidden,),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(forbidden,),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )

    with pytest.raises(LegacyBoundaryError, match="open inventory"):
        _require_cutover(open_report, frozen=frozen, candidate=frozen, root=tmp_path, isolated_scope=(clean,))
    with pytest.raises(LegacyBoundaryError, match="post-deletion"):
        _require_cutover(migration_report, frozen=frozen, candidate=closed, root=tmp_path, isolated_scope=(clean,))
    _require_cutover(clean_report, frozen=frozen, candidate=closed, root=tmp_path, isolated_scope=(clean,))
    with pytest.raises(LegacyBoundaryError, match="positive input"):
        _require_cutover(replace(clean_report, files_read=0), frozen=frozen, candidate=closed, root=tmp_path, isolated_scope=(clean,))
    with pytest.raises(LegacyBoundaryError, match="compatibility implementation"):
        _require_cutover(
            replace(clean_report, compatibility_implementation_sites=("trace.py:1:<module>:legacy",)),
            frozen=frozen,
            candidate=closed,
            root=tmp_path,
            isolated_scope=(clean,),
        )
    with pytest.raises(LegacyBoundaryError, match="forbidden dynamic"):
        _require_cutover(forbidden_report, frozen=frozen, candidate=closed, root=tmp_path, isolated_scope=(forbidden,))


def test_cutover_refuses_empty_scope_and_migration_compatibility(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    closed = _closed_inventory()
    compatibility = _write(
        tmp_path,
        "src/openultrasast/core/trace.py",
        "from openultrasast.core.legacy_v1.contracts import TraceRecord\n",
    )

    with pytest.raises(LegacyBoundaryError, match="nonempty"):
        inspect_legacy_boundary((), frozen_inventory=frozen, candidate_inventory=closed, root=tmp_path)
    migration = inspect_legacy_boundary((compatibility,), frozen_inventory=frozen, candidate_inventory=closed, root=tmp_path)
    assert migration.phase is BoundaryPhase.MIGRATION
    assert migration.compatibility_implementation_sites
    with pytest.raises(LegacyBoundaryError, match="post-deletion"):
        _require_cutover(migration, frozen=frozen, candidate=closed, root=tmp_path, isolated_scope=(compatibility,))


def test_complete_frozen_top_level_surface_is_reported_and_star_is_forbidden(tmp_path: Path) -> None:
    assert static_top_level_v1(REPO) == FROZEN_TOP_LEVEL_V1
    assert len(FROZEN_TOP_LEVEL_V1) == 38
    imports = ", ".join(FROZEN_TOP_LEVEL_V1)
    attributes = "\n".join(f"value_{index} = core_api.{name}" for index, name in enumerate(FROZEN_TOP_LEVEL_V1))
    dynamic = "\n".join(f'dynamic_{index} = getattr(core_api, "{name}")' for index, name in enumerate(FROZEN_TOP_LEVEL_V1))
    source = f"from openultrasast.core import {imports}\nimport openultrasast.core as core_api\n{attributes}\n{dynamic}\n"
    path = _write(tmp_path, "surface.py", source)
    star = _write(tmp_path, "star.py", "from openultrasast.core import *\n")
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary((path, star), frozen_inventory=frozen, root=tmp_path)

    assert sum("top_level_v1_import" in site for site in report.legacy_import_sites) == 38
    assert sum("top_level_v1_attribute" in site for site in report.legacy_import_sites) == 38
    assert sum("dynamic_compatibility_getattr" in site for site in report.forbidden_dynamic_sites) == 38
    assert any("top_level_star_import" in site for site in report.forbidden_dynamic_sites)


def test_dynamic_import_supports_constant_name_keyword_only(tmp_path: Path) -> None:
    source = """import importlib
from importlib import import_module as load_module
first = importlib.import_module(name="openultrasast.core.legacy_v1")
second = load_module(name="openultrasast.core")
third = __import__(name="openultrasast.core.trace")
unrelated(name="openultrasast.core.legacy_v1")
text = "openultrasast.core"
variable = "openultrasast.core"
ignored = importlib.import_module(name=variable)
"""
    path = _write(tmp_path, "keyword.py", source)
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary((path,), frozen_inventory=frozen, root=tmp_path)

    assert sum("dynamic_core_import" in site for site in report.forbidden_dynamic_sites) == 3


def test_dynamic_import_resolves_literal_relative_names(tmp_path: Path) -> None:
    source = """import importlib
first = importlib.import_module(".core", "openultrasast")
second = importlib.import_module(name=".legacy_v1", package="openultrasast.core")
third = importlib.import_module(".trace", package="openultrasast.core")
unrelated(".core", "openultrasast")
ignored = importlib.import_module(".core", package=variable)
text = ".legacy_v1 openultrasast.core"
"""
    path = _write(tmp_path, "relative.py", source)
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary((path,), frozen_inventory=frozen, root=tmp_path)

    assert sum("dynamic_core_import" in site for site in report.forbidden_dynamic_sites) == 3
    assert any("openultrasast.core.legacy_v1" in site for site in report.forbidden_dynamic_sites)


def test_boundary_validates_inventory_identity_and_status_transitions(tmp_path: Path) -> None:
    clean = _write(tmp_path, "clean.py", "VALUE = 1\n")
    frozen = load_migration_inventory(INVENTORY)
    changed = replace(frozen.entries[0], symbol="changed")
    candidate = replace(frozen, entries=(changed, *frozen.entries[1:]))

    with pytest.raises(LegacyInventoryError, match="identities"):
        inspect_legacy_boundary((clean,), frozen_inventory=frozen, candidate_inventory=candidate, root=tmp_path)


def test_repository_scope_proves_nonzero_inputs_before_reporting_sites() -> None:
    paths = boundary_python()
    frozen = load_migration_inventory(INVENTORY)

    report = inspect_legacy_boundary(paths, frozen_inventory=frozen, root=REPO)

    assert report.files_read == len(paths) > 0
    assert report.bytes_read > 0
    assert report.legacy_import_sites
    assert report.open_inventory_entries


def test_cutover_rejects_positive_but_incomplete_repository_scope() -> None:
    path = REPO / "tests/conftest.py"
    frozen = load_migration_inventory(INVENTORY)
    report = inspect_legacy_boundary(
        (path,),
        frozen_inventory=frozen,
        candidate_inventory=_closed_inventory(),
        expected_scope=(path,),
        root=REPO,
        phase=BoundaryPhase.POST_DELETION,
    )

    assert report.files_read == 1
    assert report.scanned_scope_paths == ("tests/conftest.py",)
    assert report.scanned_scope_digest != report.expected_scope_digest
    self_attested = replace(
        report,
        expected_scope_paths=report.scanned_scope_paths,
        expected_scope_digest=report.scanned_scope_digest,
    )
    for candidate in (report, self_attested):
        with pytest.raises(LegacyBoundaryError, match="complete repository scope|authoritative"):
            _require_cutover(candidate, frozen=frozen, candidate=_closed_inventory(), root=REPO)


def test_cutover_gate_remeasures_scope_and_rejects_forged_reports(tmp_path: Path) -> None:
    frozen = load_migration_inventory(INVENTORY)
    closed = _closed_inventory()
    clean = _write(tmp_path, "clean.py", "VALUE = 1\n")
    other = _write(tmp_path, "other.py", "OTHER = 2\n")
    forbidden = _write(tmp_path, "forbidden.py", "import openultrasast.core as core_api\n")
    report = inspect_legacy_boundary(
        (clean,),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(clean, other),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )
    self_attested = replace(
        report,
        expected_scope_paths=report.scanned_scope_paths,
        expected_scope_digest=report.scanned_scope_digest,
    )
    same_count_other = inspect_legacy_boundary(
        (other,),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(other,),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )
    forbidden_report = inspect_legacy_boundary(
        (clean, forbidden),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(clean, forbidden),
        root=tmp_path,
        phase=BoundaryPhase.POST_DELETION,
    )
    findings_removed = replace(forbidden_report, forbidden_dynamic_sites=())

    for forged, scope in (
        (self_attested, (clean, other)),
        (same_count_other, (clean,)),
        (findings_removed, (clean, forbidden)),
    ):
        with pytest.raises(LegacyBoundaryError, match="authoritative|complete repository scope"):
            _require_cutover(
                forged,
                frozen=frozen,
                candidate=closed,
                root=tmp_path,
                isolated_scope=scope,
            )


def test_repository_cutover_rejects_caller_scope_override() -> None:
    frozen = load_migration_inventory(INVENTORY)
    closed = _closed_inventory()
    path = REPO / "tests/conftest.py"
    report = inspect_legacy_boundary(
        (path,),
        frozen_inventory=frozen,
        candidate_inventory=closed,
        expected_scope=(path,),
        root=REPO,
        phase=BoundaryPhase.POST_DELETION,
    )

    with pytest.raises(LegacyBoundaryError, match="repository scope cannot be overridden"):
        _require_cutover(report, frozen=frozen, candidate=closed, root=REPO, isolated_scope=(path,))


def test_repository_scope_includes_owned_pair_tools_but_not_harvested_material() -> None:
    relatives = {path.relative_to(REPO).as_posix() for path in boundary_python()}

    assert "benchmarks/pairs/catalog_gen.py" in relatives
    assert "benchmarks/pairs/harvest.py" in relatives
    assert "benchmarks/pairs/github/sven-cwe-078-os-system/fixed.py" not in relatives
    assert "benchmarks/pairs/sast/owasp-python/BenchmarkTest00011.py" not in relatives
    assert "benchmarks/fixtures/python-vulnerable/app.py" not in relatives
