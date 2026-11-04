"""Structural ownership tests for the temporary v1 compatibility implementation."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "src/openultrasast/core"
PURE_COMPATIBILITY_MODULES = ("admission.py", "consumer.py", "trace.py", "verdict.py", "_legacy_factpack.py")
MIXED_LEGACY_NAMES = {
    "budget": {"Budget", "Complexity"},
    "coverage": {"Coverage", "ResolutionOutcome", "check_reads"},
    "factpack": {"FactPackError", "admit_fact_pack", "admit_pack_file", "load_pack_file", "verify_fact_pack"},
    "probes": {
        "FittedComponentBlocked",
        "LegacyProbeResult",
        "ShortcutDetected",
        "assert_no_shortcut",
        "require_admission_evidence",
        "reversed_pair_probe",
    },
    "provenance": {"ProvenanceMismatch", "stamp", "verify_stamp"},
}


def _tree(path: Path) -> ast.Module:
    content = path.read_bytes()
    assert content, f"ownership instrument must read nonzero bytes from {path}"
    return ast.parse(content, filename=path.as_posix())


def _defined(tree: ast.Module) -> set[str]:
    return {node.name for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))}


def _imported(tree: ast.Module) -> set[str]:
    return {alias.asname or alias.name for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}


def test_legacy_contract_values_have_one_compatibility_owner() -> None:
    contracts = _tree(CORE / "legacy_v1/contracts.py")
    expected = {
        "AdmissionManifest",
        "AdmissionManifestError",
        "BoundedSilence",
        "Budget",
        "BudgetGateFailure",
        "Complexity",
        "Coverage",
        "FactPackError",
        "FittedComponentBlocked",
        "Guard",
        "Hop",
        "InstrumentFailure",
        "Judgment",
        "LegacyFactPack",
        "LegacyProbeResult",
        "ProvenClaim",
        "ProvenanceMismatch",
        "PushRequest",
        "PushVerdict",
        "ResolutionOutcome",
        "ShortcutDetected",
        "TraceRecord",
        "Witness",
    }
    assert expected <= _defined(contracts)


def test_pure_compatibility_modules_define_no_contract_or_serializer() -> None:
    for name in PURE_COMPATIBILITY_MODULES:
        tree = _tree(CORE / name)
        assert not _defined(tree)
        assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and "json" in ast.unparse(node) for node in tree.body)
        assert any(isinstance(node, ast.ImportFrom) and node.module == "openultrasast.core.legacy_v1.contracts" for node in tree.body)


def test_writer_is_the_only_compatibility_json_serializer() -> None:
    namespace = CORE / "legacy_v1"
    paths = sorted(namespace.glob("*.py"))
    assert {path.name for path in paths} == {"__init__.py", "contracts.py", "writer.py"}
    json_importers = [
        path.name
        for path in paths
        if any(isinstance(node, (ast.Import, ast.ImportFrom)) and "json" in ast.unparse(node) for node in _tree(path).body)
    ]
    assert json_importers == ["writer.py"]


def test_namespace_and_v2_dependency_directions_are_closed() -> None:
    for path in (CORE / "legacy_v1").glob("*.py"):
        imports = {node.module for node in ast.walk(_tree(path)) if isinstance(node, ast.ImportFrom) and node.module}
        assert all(module.startswith("openultrasast.core.legacy_v1") for module in imports if module.startswith("openultrasast"))
    compatibility = {*PURE_COMPATIBILITY_MODULES, "legacy.py", "__init__.py"}
    for path in CORE.glob("*.py"):
        if path.name not in compatibility:
            imports = {node.module for node in ast.walk(_tree(path)) if isinstance(node, ast.ImportFrom) and node.module}
            assert not any(module.startswith("openultrasast.core.legacy_v1") for module in imports)


def test_historical_decoder_stays_independent_from_compatibility_namespace() -> None:
    imports = {node.module for node in ast.walk(_tree(CORE / "legacy.py")) if isinstance(node, ast.ImportFrom)}
    assert "openultrasast.core.legacy_v1" not in imports


def test_top_level_v1_api_is_only_a_closed_namespace_shim() -> None:
    tree = _tree(CORE / "__init__.py")
    modules = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert modules == {"openultrasast.core.legacy_v1"}
    assert not _defined(tree)


def test_mixed_v2_modules_expose_no_legacy_compatibility_names() -> None:
    for module_name, legacy_names in MIXED_LEGACY_NAMES.items():
        tree = _tree(CORE / f"{module_name}.py")
        assert legacy_names.isdisjoint(_defined(tree) | _imported(tree))


def test_closed_namespace_is_the_only_owner_of_moved_mixed_names() -> None:
    contracts = _tree(CORE / "legacy_v1/contracts.py")
    expected = set().union(*MIXED_LEGACY_NAMES.values())
    assert expected <= _defined(contracts)
