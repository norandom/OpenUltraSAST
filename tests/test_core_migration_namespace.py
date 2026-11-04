"""Structural ownership tests for the final v2-only core namespace."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "src/openultrasast/core"
REMOVED_COMPATIBILITY = ("trace.py", "_legacy_factpack.py", "consumer_v2.py", "verdict_v2.py")
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


def _literal_all(tree: ast.Module) -> tuple[str, ...]:
    values = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
    ]
    assert len(values) == 1 and isinstance(values[0], (ast.List, ast.Tuple))
    assert all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in values[0].elts)
    return tuple(item.value for item in values[0].elts)


def test_compatibility_namespace_writer_and_temporary_shims_are_absent() -> None:
    assert not (CORE / "legacy_v1").exists()
    for name in REMOVED_COMPATIBILITY:
        assert not (CORE / name).exists()


def test_canonical_v2_replacements_own_the_public_paths() -> None:
    consumer = _tree(CORE / "consumer.py")
    verdict = _tree(CORE / "verdict.py")
    admission = _tree(CORE / "admission.py")

    assert {"PushRequest", "PushVerdict", "consume_records"} <= _defined(consumer)
    assert {"BoundedSilence", "DefectClaim", "derive_verdict_outputs"} <= _defined(verdict)
    assert {"AdmissionManifestV2", "authorize_admission", "score_admission"} <= set(_literal_all(admission))


def test_core_modules_have_no_legacy_namespace_dependency() -> None:
    paths = tuple(sorted(CORE.glob("*.py")))
    assert paths and all(path.read_bytes() for path in paths)
    for path in paths:
        tree = _tree(path)
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        imported_modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        assert not any(module.startswith("openultrasast.core.legacy_v1") for module in imports | imported_modules)


def test_historical_decoder_stays_independent_and_read_only() -> None:
    tree = _tree(CORE / "legacy.py")
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    exports = set(_literal_all(tree))

    assert "openultrasast.core.legacy_v1" not in imports
    assert {"write", "serialize", "to_v2", "compare_identity"}.isdisjoint(exports)


def test_top_level_api_publishes_only_canonical_v2_modules() -> None:
    tree = _tree(CORE / "__init__.py")
    modules = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}

    assert modules == {"openultrasast.core"}
    assert _literal_all(tree) == ("admission", "consumer", "verdict")
    assert not _defined(tree)


def test_mixed_v2_modules_expose_no_legacy_compatibility_names() -> None:
    for module_name, legacy_names in MIXED_LEGACY_NAMES.items():
        tree = _tree(CORE / f"{module_name}.py")
        assert legacy_names.isdisjoint(_defined(tree) | _imported(tree))
