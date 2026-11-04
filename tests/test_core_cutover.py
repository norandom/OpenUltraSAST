"""Final deletion-backed gate for the detection-core v1 migration."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from core_migration_boundary import BoundaryPhase, boundary_python, inspect_legacy_boundary, require_cutover_ready
from core_migration_inventory import load_migration_inventory, validate_historical_artifacts

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "src/openultrasast/core"
INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"
REMOVED_PATHS = (
    CORE / "legacy_v1",
    CORE / "trace.py",
    CORE / "_legacy_factpack.py",
    CORE / "consumer_v2.py",
    CORE / "verdict_v2.py",
)
CANONICAL_V2_MODULES = ("admission", "consumer", "verdict")
OLD_TOP_LEVEL = (
    "AdmissionManifest",
    "Budget",
    "Coverage",
    "FactPack",
    "PushRequest",
    "PushVerdict",
    "TraceRecord",
)


def _module_exports(path: Path) -> tuple[str, ...]:
    content = path.read_bytes()
    assert content, f"public-surface instrument must read nonzero bytes from {path}"
    tree = ast.parse(content, filename=path.relative_to(REPO).as_posix())
    declarations = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
    ]
    assert len(declarations) == 1
    value = declarations[0].value
    assert isinstance(value, (ast.List, ast.Tuple))
    assert all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts)
    return tuple(item.value for item in value.elts)


def _fresh_import_probe(*module_names: str) -> dict[str, object]:
    program = """
import importlib
import json
import sys

core = importlib.import_module("openultrasast" + ".core")
result = {
    "all": tuple(core.__all__),
    "old_top_level": tuple(name for name in sys.argv[1].split(",") if hasattr(core, name)),
    "modules": {},
}
for name in sys.argv[2:]:
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError:
        result["modules"][name] = None
    else:
        result["modules"][name] = tuple(module.__all__)
print(json.dumps(result, sort_keys=True))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, ",".join(OLD_TOP_LEVEL), *module_names],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(REPO / "src")},
    )
    assert completed.stdout, "fresh import probe must produce nonzero output"
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def test_cutover_deletes_every_v1_write_and_temporary_shim_path() -> None:
    for path in REMOVED_PATHS:
        assert not path.exists(), f"cutover residue remains: {path.relative_to(REPO)}"
    for name in CANONICAL_V2_MODULES:
        path = CORE / f"{name}.py"
        assert path.is_file()
        assert path.stat().st_size > 0


def test_fresh_interpreter_rejects_old_imports_and_loads_canonical_v2() -> None:
    old_modules = (
        "openultrasast.core.legacy_v1",
        "openultrasast.core.trace",
        "openultrasast.core._legacy_factpack",
        "openultrasast.core." + "consumer_v2",
        "openultrasast.core." + "verdict_v2",
    )
    canonical = tuple(f"openultrasast.core.{name}" for name in CANONICAL_V2_MODULES)
    result = _fresh_import_probe(*old_modules, *canonical)

    assert result["old_top_level"] == []
    assert set(CANONICAL_V2_MODULES) <= set(result["all"])
    modules = result["modules"]
    assert isinstance(modules, dict)
    assert all(modules[name] is None for name in old_modules)
    assert "AdmissionManifestV2" in modules[canonical[0]]
    assert "consume_records" in modules[canonical[1]]
    assert "derive_verdict_outputs" in modules[canonical[2]]


def test_public_v2_surface_has_no_frozen_v1_names() -> None:
    exports = _module_exports(CORE / "__init__.py")

    assert set(CANONICAL_V2_MODULES) <= set(exports)
    assert set(OLD_TOP_LEVEL).isdisjoint(exports)


def test_repository_post_deletion_boundary_is_nonzero_and_exact_zero() -> None:
    paths = boundary_python()
    inventory = load_migration_inventory(INVENTORY)
    report = inspect_legacy_boundary(
        paths,
        frozen_inventory=inventory,
        candidate_inventory=inventory,
        expected_scope=paths,
        root=REPO,
        phase=BoundaryPhase.POST_DELETION,
    )

    assert report.files_read == len(paths) > 0
    assert report.bytes_read > 0
    assert report.open_inventory_entries == ()
    assert report.legacy_import_sites == ()
    assert report.legacy_writer_sites == ()
    assert report.consumer_legacy_import_sites == ()
    assert report.consumer_legacy_writer_sites == ()
    assert report.compatibility_implementation_sites == ()
    assert report.forbidden_dynamic_sites == ()
    require_cutover_ready(
        report,
        frozen_inventory=inventory,
        candidate_inventory=inventory,
        root=REPO,
    )


def test_historical_decoder_remains_exact_read_only_and_outside_public_v2() -> None:
    inventory_bytes = INVENTORY.read_bytes()
    assert inventory_bytes, "historical gate must read nonzero inventory bytes"
    inventory = load_migration_inventory(INVENTORY)
    artifacts = validate_historical_artifacts(inventory, root=REPO)

    assert len(artifacts) == 2
    assert all(artifact.content for artifact in artifacts)
    assert all(hashlib.sha256(artifact.content).hexdigest() == artifact.content_digest for artifact in artifacts)
    legacy_exports = _module_exports(CORE / "legacy.py")
    assert {"write", "serialize", "to_v2", "compare_identity"}.isdisjoint(legacy_exports)
    assert "legacy" not in _module_exports(CORE / "__init__.py")
