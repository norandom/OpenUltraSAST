"""Task 10.1: isolate the live v1 contract and serialization owners."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
V1_FIXTURES = REPO / "tests/fixtures/detection_core/v1"
PURE_COMPATIBILITY_MODULES = (
    "admission.py",
    "consumer.py",
    "trace.py",
    "verdict.py",
    "_legacy_factpack.py",
)
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


def _trace() -> object:
    from openultrasast.core.legacy_v1 import contracts

    return contracts.TraceRecord(
        entry="src/app.py::handler",
        hops=(contracts.Hop(function="handler", call_line=10, complete=True),),
        operation_kind="protected_read",
        resource="credentials",
        authority="admin",
        witnesses=(contracts.Witness(kind="guard", provenance="fact:checkPermission", relation="all_paths"),),
        guards=(contracts.Guard(kind="permission_check", effect="branches"),),
        completeness_reasons=(),
        judgment=contracts.Judgment.UNGUARDED,
        digests={"input": "abc123"},
    )


def test_legacy_contract_values_have_one_compatibility_owner() -> None:
    from openultrasast.core.legacy_v1 import contracts

    names = {
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
    assert {getattr(contracts, name).__module__ for name in names} == {"openultrasast.core.legacy_v1.contracts"}


def test_pure_compatibility_modules_define_no_contract_or_serializer() -> None:
    for name in PURE_COMPATIBILITY_MODULES:
        path = REPO / "src/openultrasast/core" / name
        content = path.read_bytes()
        assert content, f"ownership instrument must read nonzero bytes from {name}"
        tree = ast.parse(content, filename=path.as_posix())
        assert not [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
        assert not [node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and "json" in ast.unparse(node) for node in tree.body)
        assert any(isinstance(node, ast.ImportFrom) and node.module == "openultrasast.core.legacy_v1.contracts" for node in tree.body)


def test_writer_is_the_only_compatibility_json_serializer() -> None:
    namespace = REPO / "src/openultrasast/core/legacy_v1"
    paths = sorted(namespace.glob("*.py"))
    assert paths and all(path.read_bytes() for path in paths)
    assert {path.name for path in paths} == {"__init__.py", "contracts.py", "writer.py"}
    json_importers = []
    for path in paths:
        tree = ast.parse(path.read_bytes(), filename=path.as_posix())
        if any(isinstance(node, (ast.Import, ast.ImportFrom)) and "json" in ast.unparse(node) for node in tree.body):
            json_importers.append(path.name)
    assert json_importers == ["writer.py"]


def test_namespace_and_v2_dependency_directions_are_closed() -> None:
    namespace = REPO / "src/openultrasast/core/legacy_v1"
    for path in namespace.glob("*.py"):
        tree = ast.parse(path.read_bytes(), filename=path.as_posix())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        assert all(module.startswith("openultrasast.core.legacy_v1") for module in imports if module.startswith("openultrasast"))

    compatibility = {*PURE_COMPATIBILITY_MODULES, "legacy.py", "__init__.py"}
    for path in (REPO / "src/openultrasast/core").glob("*.py"):
        if path.name in compatibility:
            continue
        content = path.read_bytes()
        assert content, f"dependency instrument must read nonzero bytes from {path.name}"
        tree = ast.parse(content, filename=path.as_posix())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        assert not any(module.startswith("openultrasast.core.legacy_v1") for module in imports)


def test_legacy_trace_write_remains_byte_identical() -> None:
    expected = (V1_FIXTURES / "trace.json").read_bytes()
    assert len(expected) == 401
    value = _trace()
    assert value.canonical() == expected.rstrip(b"\n")  # type: ignore[attr-defined]


def test_historical_decoder_stays_independent_from_compatibility_namespace() -> None:
    path = REPO / "src/openultrasast/core/legacy.py"
    content = path.read_bytes()
    assert content
    tree = ast.parse(content, filename=path.as_posix())
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "openultrasast.core.legacy_v1" not in imports


def test_top_level_v1_api_imports_only_from_closed_namespace() -> None:
    import openultrasast.core as public_core
    from openultrasast.core import legacy_v1

    path = REPO / "src/openultrasast/core/__init__.py"
    content = path.read_bytes()
    assert content
    tree = ast.parse(content, filename=path.as_posix())
    legacy_imports = {
        node.module
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and any((alias.asname or alias.name) in public_core.__all__ for alias in node.names)
    }
    assert legacy_imports == {"openultrasast.core.legacy_v1"}
    assert all(getattr(public_core, name) is getattr(legacy_v1, name) for name in public_core.__all__)


def test_mixed_v2_modules_expose_no_legacy_compatibility_names() -> None:
    import importlib

    for module_name, legacy_names in MIXED_LEGACY_NAMES.items():
        module = importlib.import_module(f"openultrasast.core.{module_name}")
        assert legacy_names.isdisjoint(vars(module)), f"{module_name} still exposes {legacy_names & vars(module).keys()}"


def test_closed_namespace_is_the_only_owner_of_moved_mixed_names() -> None:
    from openultrasast.core import legacy_v1

    expected = set().union(*MIXED_LEGACY_NAMES.values())
    assert all(hasattr(legacy_v1, name) for name in expected)
    operation_names = {
        "assert_no_shortcut",
        "check_reads",
        "require_admission_evidence",
        "reversed_pair_probe",
        "stamp",
        "verify_stamp",
    }
    assert {getattr(legacy_v1, name).__module__ for name in operation_names} == {"openultrasast.core.legacy_v1.contracts"}
