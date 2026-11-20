"""Authoritative final validation instrument for detection-core task 11.4."""

from __future__ import annotations

import ast
import hashlib
import io
import os
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

from consumer_migration_evidence import migrated_pytest_node_ids
from core_migration_boundary import BoundaryPhase, boundary_python, inspect_legacy_boundary, require_cutover_ready
from core_migration_inventory import (
    MigrationDisposition,
    load_migration_inventory,
    validate_historical_artifacts,
    validate_inventory_sources,
)

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "src/openultrasast/core"
INVENTORY = REPO / "tests/fixtures/detection_core/v1/migration_inventory.json"
FORBIDDEN_PREFIXES = (
    "benchmarks",
    "dspy",
    "openultrasast.hunt",
    "openultrasast.mapping",
    "openultrasast.search",
    "openultrasast.semantic",
    "openultrasast.tools",
)

CORE_LAYERS = (
    frozenset({"canonical", "_closed_graph"}),
    frozenset({"semantics"}),
    frozenset({"custody", "lineage", "provenance"}),
    frozenset({"evidence"}),
    frozenset({"family", "family_catalog", "coverage", "budget"}),
    frozenset(
        {
            "factpack",
            "_factpack_digest",
            "factmatch",
            "factapply",
            "factvalidate",
            "model",
            "_model_common",
            "_model_result",
            "model_apply",
        }
    ),
    frozenset({"validation", "_validation_model", "_validation_shape"}),
    frozenset({"readiness", "verdict", "probes", "_probe_eval", "proof", "_proof_apply", "_proof_attestation"}),
    frozenset({"measurement", "measurement_record", "measurement_factory", "_metric_algebra"}),
    frozenset(
        {
            "admission",
            "admission_case",
            "_admission_case_shape",
            "_admission_funnel",
            "_admission_gates",
            "_admission_release",
            "_admission_replay",
            "_admission_review_shape",
            "admission_context",
            "admission_feasibility",
            "admission_fitted",
            "admission_metrics",
            "admission_report",
            "admission_review",
            "admission_spend",
        }
    ),
    frozenset(
        {
            "evaluation_version",
            "evaluation_authority",
            "evaluation_plan",
            "_evaluation_plan_review",
            "evaluation_measurement",
            "_evaluation_measurement_contracts",
            "evaluation_metric_derivation",
            "evaluation_feasibility",
            "evaluation_fitted",
            "_evaluation_fitted_shape",
            "evaluation_observation",
            "evaluation_attempt",
            "_evaluation_attempt_validation",
            "_evaluation_arm_configuration",
            "evaluation_spend",
            "evaluation_release",
            "_evaluation_release_validation",
            "evaluation_case_outcome",
            "evaluation_case_validation",
            "_evaluation_proof_plan",
            "evaluation_proof",
            "evaluation_combination",
            "evaluation_aggregate",
            "evaluation_ordinary_projection",
            "evaluation_scoped_metrics",
            "evaluation_report",
            "_evaluation_report_validation",
            "evaluation_replay",
            "evaluation_replay_validation",
            "_evaluation_replay_report",
            "evaluation_admission",
        }
    ),
    frozenset({"consumer"}),
    frozenset({"legacy"}),
    frozenset({"__init__"}),
)

DECLARED_TEST_FILES = (
    "tests/test_core_canonical.py",
    "tests/test_core_evidence.py",
    "tests/test_core_family.py",
    "tests/test_core_coverage_v2.py",
    "tests/test_core_budget_v2.py",
    "tests/test_core_custody.py",
    "tests/test_core_provenance.py",
    "tests/test_core_lineage.py",
    "tests/test_core_factpack.py",
    "tests/test_core_factapply.py",
    "tests/test_core_factmatch.py",
    "tests/test_core_model.py",
    "tests/test_core_family_catalog.py",
    "tests/test_core_validation_v2.py",
    "tests/test_core_verdict.py",
    "tests/test_core_readiness.py",
    "tests/test_core_measurement.py",
    "tests/test_core_measurement_record.py",
    "tests/test_core_probes.py",
    "tests/test_core_proof.py",
    "tests/test_core_semantics.py",
    "tests/test_core_native.py",
    "tests/test_core_consumer_v2.py",
    "tests/test_core_admission_context.py",
    "tests/test_core_admission_feasibility.py",
    "tests/test_core_admission_fitted.py",
    "tests/test_core_admission_funnel.py",
    "tests/test_core_admission_metrics.py",
    "tests/test_core_admission_release.py",
    "tests/test_core_admission_report.py",
    "tests/test_core_admission_review.py",
    "tests/test_core_admission_spend.py",
    "tests/test_core_fact_adapter_conformance.py",
    "tests/test_obligation_core_adapter.py",
    "tests/test_search_core_adapter.py",
    "tests/test_detection_core_admission_adapter.py",
    "tests/test_detection_core_readiness_adapter.py",
    "tests/test_core_migration.py",
    "tests/test_core_migration_benchmark.py",
    "tests/test_core_migration_boundary.py",
    "tests/test_core_migration_consumers.py",
    "tests/test_core_migration_namespace.py",
    "tests/test_core_migration_production.py",
    "tests/test_core_migration_provenance.py",
    "tests/test_core_cutover.py",
    "tests/test_core_reference_families.py",
    "tests/test_detection_core_end_to_end.py",
    "tests/test_detection_core_failure_visibility.py",
    "tests/test_detection_core_performance.py",
)


@dataclass(frozen=True)
class FinalGateReport:
    core_file_count: int
    core_bytes: int
    repository_file_count: int
    repository_bytes: int
    historical_artifact_count: int
    historical_bytes: int
    consumer_selector_count: int
    declared_test_file_count: int
    declared_test_bytes: int
    tests_collected: int
    pytest_exit_code: int


def _read_nonzero(path: Path, purpose: str) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise AssertionError(f"{purpose} could not read {path.relative_to(REPO)}: {exc}") from exc
    if not content:
        raise AssertionError(f"{purpose} read zero bytes from {path.relative_to(REPO)}")
    return content


def _core_paths() -> tuple[Path, ...]:
    paths = tuple(sorted(CORE.rglob("*.py")))
    if not paths:
        raise AssertionError("core dependency instrument discovered zero Python files")
    expected = {name for layer in CORE_LAYERS for name in layer}
    actual = {path.stem for path in paths}
    if actual != expected:
        raise AssertionError(f"core dependency authority changed: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    return paths


def _imported_modules(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if node.level:
        return (f"openultrasast.core.{node.module}",) if node.module else ()
    if node.module == "openultrasast.core":
        return tuple(f"openultrasast.core.{alias.name}" for alias in node.names)
    return (node.module,) if node.module else ()


def _core_dependency(module: str) -> str | None:
    prefix = "openultrasast.core."
    if not module.startswith(prefix):
        return None
    return module.removeprefix(prefix).partition(".")[0]


def _audit_import(source: str, imported: str, ranks: dict[str, int], path: Path, line: int) -> None:
    if imported.startswith(FORBIDDEN_PREFIXES):
        raise AssertionError(f"forbidden core dependency {imported} at {path.relative_to(REPO)}:{line}")
    dependency = _core_dependency(imported)
    if dependency is not None:
        if dependency not in ranks:
            raise AssertionError(f"unknown core dependency {imported} at {path.relative_to(REPO)}:{line}")
        if source not in {"__init__", "legacy"} and ranks[dependency] > ranks[source]:
            raise AssertionError(f"forward core dependency {source} -> {dependency} at {path.relative_to(REPO)}:{line}")
        if source == "legacy" and dependency != "canonical":
            raise AssertionError(f"historical decoder dependency {dependency} is not canonical")
        return
    root = imported.partition(".")[0]
    if root not in sys.stdlib_module_names:
        raise AssertionError(f"non-standard-library core dependency {imported} at {path.relative_to(REPO)}:{line}")


def _audit_core_dependencies(paths: tuple[Path, ...]) -> int:
    ranks = {name: index for index, layer in enumerate(CORE_LAYERS) for name in layer}
    bytes_read = 0
    for path in paths:
        content = _read_nonzero(path, "core dependency instrument")
        bytes_read += len(content)
        tree = ast.parse(content, filename=path.relative_to(REPO).as_posix())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for imported in _imported_modules(node):
                    _audit_import(path.stem, imported, ranks, path, node.lineno)
            elif isinstance(node, ast.Call) and _dynamic_import_name(node):
                raise AssertionError(f"dynamic core import at {path.relative_to(REPO)}:{node.lineno}")
    return bytes_read


def _dynamic_import_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return node.func.id
    if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
        return node.func.attr
    return ""


def _migration_gate() -> tuple[int, int, int, int]:
    inventory_bytes = _read_nonzero(INVENTORY, "migration inventory instrument")
    inventory = load_migration_inventory(INVENTORY)
    if not inventory.entries or any(entry.disposition is MigrationDisposition.OPEN for entry in inventory.entries):
        raise AssertionError("migration inventory is empty or contains an open entry")
    validate_inventory_sources(inventory, root=REPO)
    paths = boundary_python()
    report = inspect_legacy_boundary(
        paths,
        frozen_inventory=inventory,
        candidate_inventory=inventory,
        expected_scope=paths,
        root=REPO,
        phase=BoundaryPhase.POST_DELETION,
    )
    require_cutover_ready(report, frozen_inventory=inventory, candidate_inventory=inventory, root=REPO)
    artifacts = validate_historical_artifacts(inventory, root=REPO)
    historical_bytes = sum(len(artifact.content) for artifact in artifacts)
    if not artifacts or historical_bytes <= 0:
        raise AssertionError("historical validator reopened zero artifact bytes")
    for artifact in artifacts:
        if hashlib.sha256(artifact.content).hexdigest() != artifact.content_digest:
            raise AssertionError(f"historical artifact changed: {artifact.path}")
    return report.files_read, report.bytes_read + len(inventory_bytes), len(artifacts), historical_bytes


def _logical_lines(content: bytes) -> int:
    count = 0
    has_code = False
    for token in tokenize.tokenize(io.BytesIO(content).readline):
        if token.type in {tokenize.ENCODING, tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT}:
            continue
        if token.type == tokenize.NEWLINE:
            count += int(has_code)
            has_code = False
        elif token.type != tokenize.ENDMARKER:
            has_code = True
    return count + int(has_code)


def _check_new_module_size(path: Path) -> None:
    content = _read_nonzero(path, "complexity instrument")
    if _logical_lines(content) > 400:
        raise AssertionError(f"new validation module exceeds 400 logical lines: {path.relative_to(REPO)}")
    lines = content.splitlines(keepends=True)
    tree = ast.parse(content, filename=path.relative_to(REPO).as_posix())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.end_lineno is not None:
            function = b"".join(lines[node.lineno - 1 : node.end_lineno])
            if _logical_lines(function) > 50:
                raise AssertionError(f"function exceeds 50 logical lines: {path.relative_to(REPO)}:{node.lineno}:{node.name}")


def _complexity_gate(core_paths: tuple[Path, ...]) -> None:
    new_modules = (Path(__file__), REPO / "tests/test_detection_core_final_gate.py")
    for path in new_modules:
        _check_new_module_size(path)
    ruff = Path(sys.executable).with_name("ruff")
    command = [str(ruff), "check", "--select", "C901", "--config", "lint.mccabe.max-complexity=10"]
    completed = subprocess.run(
        [*command, *(str(path) for path in (*core_paths, *new_modules))],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(f"C901 gate exit={completed.returncode}\n{completed.stdout}{completed.stderr}")


def _declared_selectors() -> tuple[tuple[str, ...], int]:
    selectors = migrated_pytest_node_ids()
    if len(selectors) != 37 or len(set(selectors)) != len(selectors):
        raise AssertionError(f"consumer selector authority changed: count={len(selectors)}")
    total_bytes = 0
    for relative in DECLARED_TEST_FILES:
        total_bytes += len(_read_nonzero(REPO / relative, "declared suite instrument"))
    for selector in selectors:
        total_bytes += len(_read_nonzero(REPO / selector.partition("::")[0], "consumer seam instrument"))
    return (*DECLARED_TEST_FILES, *selectors), total_bytes


def _pytest(selectors: tuple[str, ...], collect_only: bool) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(REPO / "src"), str(REPO / "tests")))
    options = ["--collect-only"] if collect_only else []
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *options, *selectors],
        cwd=REPO,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )


def _run_declared_suites(selectors: tuple[str, ...]) -> tuple[int, int]:
    collected = _pytest(selectors, collect_only=True)
    if collected.returncode:
        raise AssertionError(f"declared suite collection exit={collected.returncode}\n{collected.stdout}{collected.stderr}")
    match = re.search(r"(\d+) tests? collected", collected.stdout)
    count = int(match.group(1)) if match else 0
    if count <= 0:
        raise AssertionError(f"declared suite collected zero tests\n{collected.stdout}")
    for relative in DECLARED_TEST_FILES:
        if f"{relative}::" not in collected.stdout:
            raise AssertionError(f"declared suite collection omitted {relative}")
    completed = _pytest(selectors, collect_only=False)
    if completed.returncode:
        raise AssertionError(f"declared suite pytest exit={completed.returncode}\n{completed.stdout}{completed.stderr}")
    return count, completed.returncode


def run_final_gate() -> FinalGateReport:
    """Run every final gate only after proving its authoritative inputs are nonzero."""
    core_paths = _core_paths()
    core_bytes = _audit_core_dependencies(core_paths)
    repository_files, repository_bytes, artifact_count, historical_bytes = _migration_gate()
    _complexity_gate(core_paths)
    selectors, declared_bytes = _declared_selectors()
    collected, pytest_exit = _run_declared_suites(selectors)
    return FinalGateReport(
        len(core_paths),
        core_bytes,
        repository_files,
        repository_bytes,
        artifact_count,
        historical_bytes,
        len(migrated_pytest_node_ids()),
        len(DECLARED_TEST_FILES),
        declared_bytes,
        collected,
        pytest_exit,
    )


__all__ = ["FinalGateReport", "run_final_gate"]
