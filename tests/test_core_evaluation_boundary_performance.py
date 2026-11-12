"""Boundary and deterministic validation-growth gates for evaluation admission V3."""

from __future__ import annotations

import ast
import copy
import io
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_core_evaluation_end_to_end import _complete_replay

from openultrasast.core import canonical, evaluation_admission
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.custody import PopulationCustodyLog, PopulationCustodyPort
from openultrasast.core.evaluation_replay import EvaluationReplayV3

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "src/openultrasast/core"
V2_AGGREGATE_ROOTS = frozenset({"_admission_replay", "admission", "consumer"})
FORBIDDEN_RUNTIME_PREFIXES = (
    "benchmarks",
    "dspy",
    "openultrasast.analyzer",
    "openultrasast.benchmarks",
    "openultrasast.hunt",
    "openultrasast.model_runtime",
    "openultrasast.proof_execution",
    "openultrasast.search",
    "openultrasast.tools",
)
FORBIDDEN_OWNER_NAMES = frozenset(
    {
        "analyze_repository",
        "execute_detector",
        "execute_proof",
        "invoke_model",
        "load_model_runtime",
        "run_benchmark",
        "store_observation",
    }
)
LAYERS = (
    (
        "_evaluation_measurement_contracts",
        "_evaluation_arm_configuration",
        "evaluation_measurement",
        "evaluation_version",
    ),
    ("_evaluation_plan_review", "evaluation_plan"),
    ("evaluation_feasibility",),
    ("evaluation_case_outcome",),
    ("_evaluation_attempt_validation", "evaluation_attempt", "evaluation_observation"),
    ("evaluation_authority",),
    ("evaluation_spend",),
    ("_evaluation_release_validation", "evaluation_release", "evaluation_case_validation", "evaluation_scoped_metrics"),
    ("_evaluation_proof_plan", "evaluation_proof", "evaluation_combination"),
    ("evaluation_ordinary_projection",),
    ("evaluation_metric_derivation",),
    ("_evaluation_report_validation", "evaluation_report", "evaluation_aggregate"),
    ("_evaluation_replay_report", "evaluation_replay"),
    ("evaluation_replay_validation",),
    ("evaluation_admission",),
    ("_evaluation_fitted_shape", "evaluation_fitted"),
)


@dataclass(frozen=True)
class BoundaryReport:
    modules_read: int
    bytes_read: int
    import_edges: int


@dataclass(frozen=True)
class ArtifactCounts:
    arms: int
    arm_scopes: int
    observations: int
    attempt_events: int
    cases: int
    reports: int

    @property
    def total(self) -> int:
        return sum((self.arms, self.arm_scopes, self.observations, self.attempt_events, self.cases, self.reports))


@dataclass(frozen=True)
class GrowthPoint:
    component_pairs: int
    artifacts: ArtifactCounts
    resolver_reads: int
    custody_reads: int

    @property
    def operations(self) -> int:
        return self.resolver_reads + self.custody_reads


class _CountingResolver:
    def __init__(self, wrapped: canonical.ContentResolver) -> None:
        self.wrapped = wrapped
        self.reads = 0
        self.bytes_read = 0

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        resolved = self.wrapped.resolve(reference)
        assert resolved.content, f"validation instrument resolved zero bytes for {reference.artifact_id}"
        self.reads += 1
        self.bytes_read += len(resolved.content)
        return resolved


class _CountingCustody:
    def __init__(self, wrapped: PopulationCustodyPort) -> None:
        self.wrapped = wrapped
        self.reads = 0

    def current_log(self, population_digest: str) -> PopulationCustodyLog:
        log = self.wrapped.current_log(population_digest)
        assert log.receipt_count > 0 and log.receipts
        self.reads += 1
        return log


def _v3_paths() -> tuple[Path, ...]:
    paths = tuple(sorted({*CORE.glob("evaluation_*.py"), *CORE.glob("_evaluation_*.py")}))
    assert paths, "V3 boundary instrument discovered zero modules"
    expected = {name for layer in LAYERS for name in layer}
    actual = {path.stem for path in paths}
    assert actual == expected, f"V3 module authority changed: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
    return paths


def _read_nonzero(path: Path, purpose: str) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise AssertionError(f"{purpose} could not read {path.relative_to(REPO)}: {exc}") from exc
    assert content, f"{purpose} read zero bytes from {path.relative_to(REPO)}"
    return content


def _import_from_module(node: ast.ImportFrom) -> str:
    if node.level == 0:
        assert node.module is not None
        return node.module
    package = ("openultrasast", "core")
    retained = len(package) - (node.level - 1)
    assert retained > 0, f"relative core import escapes package at line {node.lineno}"
    parts = (*package[:retained], *((node.module or "").split(".") if node.module else ()))
    return ".".join(parts)


def _imports(tree: ast.AST) -> tuple[tuple[str, int], ...]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = _import_from_module(node)
            if module in {"openultrasast", "openultrasast.core"}:
                found.extend((f"{module}.{alias.name}", node.lineno) for alias in node.names)
            elif any(alias.name == "*" for alias in node.names):
                found.append((f"{module}.*", node.lineno))
            else:
                found.append((module, node.lineno))
    return tuple(found)


def _core_dependency(source: str, imported: str) -> str | None:
    assert imported != "openultrasast.core", f"core package-root import is forbidden: {source}"
    if not imported.startswith("openultrasast.core."):
        return None
    assert not imported.endswith(".*"), f"core wildcard import is forbidden: {source} -> {imported}"
    return imported.removeprefix("openultrasast.core.").partition(".")[0]


def _audit_import(source: str, imported: str, line: int, ranks: dict[str, int]) -> None:
    assert not imported.startswith(FORBIDDEN_RUNTIME_PREFIXES), f"forbidden V3 runtime dependency {source}:{line}: {imported}"
    root = imported.partition(".")[0]
    is_core_namespace = imported == "openultrasast.core" or imported.startswith("openultrasast.core.")
    assert is_core_namespace or root in sys.stdlib_module_names, f"non-standard-library V3 dependency {source}:{line}: {imported}"
    dependency = _core_dependency(source, imported)
    if dependency is None:
        return
    assert dependency not in V2_AGGREGATE_ROOTS, f"V3 aggregate boundary crossed: {source} -> {dependency}"
    if dependency in ranks:
        assert ranks[dependency] <= ranks[source], f"forward V3 dependency {source} -> {dependency}"


def _audit_lower_imports(source: str, tree: ast.AST, v3_names: set[str]) -> None:
    dependencies = {dependency for imported, _ in _imports(tree) if (dependency := _core_dependency(source, imported)) is not None}
    crossed = dependencies & v3_names
    assert not crossed, f"lower core imports V3: {source} -> {sorted(crossed)}"


def _logical_lines(content: bytes) -> int:
    count = 0
    has_code = False
    ignored = {tokenize.ENCODING, tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT}
    for token in tokenize.tokenize(io.BytesIO(content).readline):
        if token.type in ignored:
            continue
        if token.type == tokenize.NEWLINE:
            count += int(has_code)
            has_code = False
        elif token.type != tokenize.ENDMARKER:
            has_code = True
    return count + int(has_code)


def _audit_complexity(path: Path, content: bytes, tree: ast.AST) -> None:
    assert _logical_lines(content) <= 400, f"V3 module exceeds 400 logical lines: {path.name}"
    lines = content.splitlines(keepends=True)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.end_lineno:
            function = b"".join(lines[node.lineno - 1 : node.end_lineno])
            assert _logical_lines(function) <= 50, f"V3 function exceeds 50 logical lines: {path.name}:{node.name}"


def _audit_v3_boundary() -> BoundaryReport:
    ranks = {name: rank for rank, layer in enumerate(LAYERS) for name in layer}
    bytes_read = 0
    edges = 0
    for path in _v3_paths():
        content = _read_nonzero(path, "V3 boundary instrument")
        bytes_read += len(content)
        tree = ast.parse(content, filename=path.as_posix())
        _audit_complexity(path, content, tree)
        defined = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert FORBIDDEN_OWNER_NAMES.isdisjoint(defined), f"V3 owns forbidden runtime action in {path.name}"
        for imported, line in _imports(tree):
            _audit_import(path.stem, imported, line, ranks)
            edges += 1
    v3_paths = set(_v3_paths())
    v3_names = {path.stem for path in v3_paths}
    lower_paths = tuple(path for path in sorted(CORE.glob("*.py")) if path not in v3_paths and path.name != "__init__.py")
    assert lower_paths, "version-boundary instrument discovered zero lower core modules"
    for path in lower_paths:
        tree = ast.parse(_read_nonzero(path, "version-boundary instrument"))
        _audit_lower_imports(path.stem, tree, v3_names)
    return BoundaryReport(len(_v3_paths()), bytes_read, edges)


def _artifact_counts(replay: EvaluationReplayV3) -> ArtifactCounts:
    configurations = replay.plan_manifest.declaration.arm_configurations
    arm_scopes = {(configuration.arm_id, scope) for configuration in configurations for scope in configuration.exact_scopes}
    counts = ArtifactCounts(
        len(configurations),
        len(arm_scopes),
        len(replay.admission_manifest.observations),
        len(replay.admission_manifest.attempt_history.events),
        sum(len(group.cases) for group in replay.cases_by_arm),
        len(replay.reports),
    )
    assert min(counts.arms, counts.arm_scopes, counts.observations, counts.attempt_events, counts.cases, counts.reports) > 0
    return counts


def _prove_fixture_inputs(replay: EvaluationReplayV3, resolver: canonical.ContentResolver) -> ArtifactCounts:
    fixture_bytes = _read_nonzero(Path(__file__), "growth fixture instrument")
    references = tuple(item.observation for item in replay.admission_manifest.observations) + tuple(
        item.event for item in replay.admission_manifest.attempt_history.events
    )
    resolved_bytes = 0
    for reference in references:
        content = resolver.resolve(reference).content
        assert content, f"growth fixture resolved zero bytes for {reference.artifact_id}"
        resolved_bytes += len(content)
    receipts = tuple(receipt for group in replay.cases_by_arm for case in group.cases for receipt in case.input_receipts)
    receipt_bytes = sum(receipt.byte_count for receipt in receipts if receipt.opened)
    assert references and resolved_bytes > 0 and receipts and receipt_bytes > 0 and len(fixture_bytes) > 0
    return _artifact_counts(replay)


def _measure_growth(
    replay: EvaluationReplayV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
    component_pairs: int,
) -> GrowthPoint:
    counted_resolver = _CountingResolver(resolver)
    counted_custody = _CountingCustody(custody)
    assert evaluation_admission.validate_evaluation_replay(replay, context, counted_custody, counted_resolver) == replay.reports
    assert counted_resolver.reads > 0 and counted_resolver.bytes_read > 0 and counted_custody.reads > 0
    return GrowthPoint(component_pairs, _artifact_counts(replay), counted_resolver.reads, counted_custody.reads)


def test_v3_boundary_report_is_clean() -> None:
    report = _audit_v3_boundary()
    assert report.modules_read > 0 and report.bytes_read > 0 and report.import_edges > 0


def test_import_aliases_cannot_hide_version_boundary_edges() -> None:
    ranks = {name: rank for rank, layer in enumerate(LAYERS) for name in layer}
    v3_names = {name for layer in LAYERS for name in layer}
    package_import = _imports(ast.parse("from openultrasast import core"))[0]

    assert package_import[0] == "openultrasast.core"
    with pytest.raises(AssertionError, match="package-root"):
        _audit_import("evaluation_admission", *package_import, ranks)
    with pytest.raises(AssertionError, match="package-root"):
        _audit_lower_imports("lower_module", ast.parse("from openultrasast import core"), v3_names)

    for source in ("from openultrasast.core import admission", "import openultrasast.core.admission"):
        with pytest.raises(AssertionError, match="aggregate boundary"):
            _audit_import("evaluation_admission", *_imports(ast.parse(source))[0], ranks)
    for source in ("from . import admission", "from .admission import authorize_admission"):
        with pytest.raises(AssertionError, match="aggregate boundary"):
            _audit_import("evaluation_admission", *_imports(ast.parse(source))[0], ranks)
    for child in ("evaluation_admission", "_evaluation_replay_report"):
        for source in (f"from openultrasast.core import {child}", f"import openultrasast.core.{child}"):
            with pytest.raises(AssertionError, match="lower core imports V3"):
                _audit_lower_imports("lower_module", ast.parse(source), v3_names)
        for source in (f"from . import {child}", f"from .{child} import public_symbol"):
            with pytest.raises(AssertionError, match="lower core imports V3"):
                _audit_lower_imports("lower_module", ast.parse(source), v3_names)
    for source in ("from openultrasast.core import *", "from openultrasast.core.evaluation_admission import *"):
        imported = _imports(ast.parse(source))[0]
        with pytest.raises(AssertionError, match="wildcard"):
            _audit_import("evaluation_admission", *imported, ranks)
        with pytest.raises(AssertionError, match="wildcard"):
            _audit_lower_imports("lower_module", ast.parse(source), v3_names)

    for imported in ("openultrasast.coreevil", "openultrasast.core_extra", "openultrasast.corex.vendor"):
        with pytest.raises(AssertionError, match="non-standard-library"):
            _audit_import("evaluation_admission", imported, 1, ranks)

    direct_child = _imports(ast.parse("from openultrasast.core import evaluation_replay_validation"))[0]
    _audit_import("evaluation_admission", *direct_child, ranks)
    relative_child = _imports(ast.parse("from . import evaluation_replay_validation"))[0]
    _audit_import("evaluation_admission", *relative_child, ranks)
    for source in (
        "from openultrasast.core import canonical",
        "import openultrasast.core.canonical",
        "from . import canonical",
        "from .canonical import digest",
    ):
        _audit_lower_imports("lower_module", ast.parse(source), v3_names)


def test_replay_validation_work_is_bounded_by_supplied_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = tuple(_complete_replay(monkeypatch, component_pairs=size) for size in (1, 2, 4))
    points = []
    for size, completed in zip((1, 2, 4), fixtures, strict=True):
        bundle, replay, *_ = completed
        context, custody, resolver = bundle[5][0].context, bundle[5][0].port, bundle[4]
        assert _prove_fixture_inputs(replay, resolver) == _artifact_counts(replay)
        points.append(_measure_growth(replay, context, custody, resolver, size))

    expected = [ArtifactCounts(3 * size, 6 * size, 6 * size, 2 * size, 18 * size, 3 * size) for size in (1, 2, 4)]
    assert [point.artifacts for point in points] == expected
    assert len({completed[1].replay_digest for completed in fixtures}) == 3
    assert points[0].operations < points[1].operations < points[2].operations
    assert all(point.operations <= points[0].operations * point.component_pairs for point in points)

    bundle, replay, *_ = fixtures[-1]
    context, custody, resolver = bundle[5][0].context, bundle[5][0].port, bundle[4]
    corrupted = copy.copy(replay)
    object.__setattr__(corrupted, "replay_digest", "0" * 64)
    with pytest.raises(Exception, match="digest|canonical|replay|derivation"):
        evaluation_admission.validate_evaluation_replay(corrupted, context, custody, resolver)
