"""Syntax-only cutover boundary for the detection-core v1 migration."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from core_migration_inventory import (
    LegacyInventoryEntry,
    LegacyMigrationInventory,
    MigrationDisposition,
    validate_inventory_transition,
)
from core_migration_scope import (
    COMPATIBILITY_PATHS,
    COMPATIBILITY_SHIMS,
    FROZEN_TOP_LEVEL_V1,
    REPLACED_SHIM_MEMBERS,
    REPO,
    MigrationScopeError,
    authoritative_cutover_scope,
    boundary_python,
    cutover_residue_error,
    cutover_scope_error,
    expected_boundary_scope,
    partition_boundary_sites,
    relative_path,
    scope_identity,
)
from core_migration_scope import static_top_level_exports as _static_top_level_exports


class LegacyBoundaryError(ValueError):
    """The structural migration boundary is unreadable or not cutover-ready."""


class BoundaryPhase(Enum):
    MIGRATION = "migration"
    POST_DELETION = "post_deletion"


@dataclass(frozen=True)
class LegacyBoundaryReport:
    phase: BoundaryPhase
    files_read: int
    bytes_read: int
    scanned_scope_paths: tuple[str, ...]
    scanned_scope_digest: str
    expected_scope_paths: tuple[str, ...]
    expected_scope_digest: str
    open_inventory_entries: tuple[LegacyInventoryEntry, ...]
    legacy_import_sites: tuple[str, ...]
    legacy_writer_sites: tuple[str, ...]
    forbidden_dynamic_sites: tuple[str, ...]
    consumer_legacy_import_sites: tuple[str, ...]
    consumer_legacy_writer_sites: tuple[str, ...]
    compatibility_implementation_sites: tuple[str, ...]


@dataclass(frozen=True)
class _Bindings:
    core_modules: frozenset[str]
    compatibility_modules: frozenset[str]
    writer_modules: frozenset[str]
    writer_members: frozenset[str]
    import_modules: frozenset[str]
    import_functions: frozenset[str]


def static_top_level_exports(root: Path = REPO) -> tuple[str, ...]:
    try:
        return _static_top_level_exports(root)
    except MigrationScopeError as exc:
        raise LegacyBoundaryError(str(exc)) from exc


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _symbol(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    names = []
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(current.name)
    return ".".join(reversed(names)) or "<module>"


def _site(relative: str, node: ast.AST, parents: dict[ast.AST, ast.AST], kind: str, detail: str = "") -> str:
    suffix = f":{detail}" if detail else ""
    return f"{relative}:{getattr(node, 'lineno', 0)}:{_symbol(node, parents)}:{kind}{suffix}"


def _bindings(tree: ast.Module) -> _Bindings:
    core_modules = {"openultrasast.core"}
    compatibility_modules = {"openultrasast.core.legacy_v1"}
    writer_modules = {"openultrasast.core.legacy_v1.writer"}
    writer_members: set[str] = set()
    import_modules = {"importlib"}
    import_functions = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "openultrasast.core":
                    core_modules.add(alias.asname or "openultrasast.core")
                elif alias.name == "openultrasast.core.legacy_v1":
                    compatibility_modules.add(alias.asname or alias.name)
                elif alias.name == "openultrasast.core.legacy_v1.writer":
                    writer_modules.add(alias.asname or alias.name)
                elif alias.name == "importlib":
                    import_modules.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom):
            _update_from_bindings(node, core_modules, compatibility_modules, writer_modules, writer_members, import_functions)
    return _Bindings(
        frozenset(core_modules),
        frozenset(compatibility_modules),
        frozenset(writer_modules),
        frozenset(writer_members),
        frozenset(import_modules),
        frozenset(import_functions),
    )


def _update_from_bindings(
    node: ast.ImportFrom,
    core_modules: set[str],
    compatibility_modules: set[str],
    writer_modules: set[str],
    writer_members: set[str],
    import_functions: set[str],
) -> None:
    if node.module == "openultrasast":
        core_modules.update(alias.asname or alias.name for alias in node.names if alias.name == "core")
    elif node.module == "openultrasast.core":
        compatibility_modules.update(alias.asname or alias.name for alias in node.names if alias.name == "legacy_v1")
    elif node.module == "openultrasast.core.legacy_v1":
        writer_modules.update(alias.asname or alias.name for alias in node.names if alias.name == "writer")
    elif node.module == "openultrasast.core.legacy_v1.writer":
        writer_members.update(alias.asname or alias.name for alias in node.names)
    elif node.module == "importlib":
        import_functions.update(alias.asname or alias.name for alias in node.names if alias.name == "import_module")


def _import_sites(relative: str, tree: ast.Module, parents: dict[ast.AST, ast.AST]) -> tuple[set[str], set[str], set[str]]:
    legacy: set[str] = set()
    writers: set[str] = set()
    dynamic: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _classify_import(relative, node, alias.name, parents, legacy, writers, dynamic)
        elif isinstance(node, ast.ImportFrom):
            _classify_import_from(relative, node, parents, legacy, writers, dynamic)
    return legacy, writers, dynamic


def _classify_import(
    relative: str,
    node: ast.Import,
    module: str,
    parents: dict[ast.AST, ast.AST],
    legacy: set[str],
    writers: set[str],
    dynamic: set[str],
) -> None:
    if module == "openultrasast.core":
        dynamic.add(_site(relative, node, parents, "module_valued_core_import", module))
    if module.startswith("openultrasast.core.legacy_v1"):
        legacy.add(_site(relative, node, parents, "legacy_namespace_import", module))
    if module == "openultrasast.core.legacy_v1.writer":
        writers.add(_site(relative, node, parents, "writer_facade_import", module))
    if module in COMPATIBILITY_SHIMS:
        legacy.add(_site(relative, node, parents, "compatibility_shim_import", module))


def _classify_import_from(
    relative: str,
    node: ast.ImportFrom,
    parents: dict[ast.AST, ast.AST],
    legacy: set[str],
    writers: set[str],
    dynamic: set[str],
) -> None:
    module = node.module or ""
    names = {alias.name for alias in node.names}
    if module == "openultrasast" and "core" in names:
        dynamic.add(_site(relative, node, parents, "module_valued_core_import", "openultrasast.core"))
    if module.startswith("openultrasast.core.legacy_v1") or (module == "openultrasast.core" and "legacy_v1" in names):
        legacy.add(_site(relative, node, parents, "legacy_namespace_import", module or "openultrasast.core.legacy_v1"))
    if module == "openultrasast.core.legacy_v1.writer" or (module == "openultrasast.core.legacy_v1" and "writer" in names):
        writers.add(_site(relative, node, parents, "writer_facade_import", module))
    if module == "openultrasast.core":
        if "*" in names:
            dynamic.add(_site(relative, node, parents, "top_level_star_import", module))
        for name in sorted(names.intersection(FROZEN_TOP_LEVEL_V1)):
            legacy.add(_site(relative, node, parents, "top_level_v1_import", name))
        for name in sorted(names):
            shim = f"openultrasast.core.{name}"
            if shim in COMPATIBILITY_SHIMS:
                legacy.add(_site(relative, node, parents, "compatibility_shim_import", shim))
    if module in COMPATIBILITY_SHIMS:
        legacy.add(_site(relative, node, parents, "compatibility_shim_import", module))
    _record_replaced_shim_members(relative, node, parents, module, names, legacy)


def _record_replaced_shim_members(
    relative: str,
    node: ast.ImportFrom,
    parents: dict[ast.AST, ast.AST],
    module: str,
    names: set[str],
    legacy: set[str],
) -> None:
    for name in sorted(names.intersection(REPLACED_SHIM_MEMBERS.get(module, frozenset()))):
        legacy.add(_site(relative, node, parents, "retired_shim_member_import", f"{module}.{name}"))


def _reference_sites(
    relative: str,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    bindings: _Bindings,
) -> tuple[set[str], set[str], set[str]]:
    legacy: set[str] = set()
    writers: set[str] = set()
    dynamic: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            _classify_attribute(relative, node, parents, bindings, legacy, writers)
        elif isinstance(node, ast.Call):
            _classify_call(relative, node, parents, bindings, writers, dynamic)
    return legacy, writers, dynamic


def _classify_attribute(
    relative: str,
    node: ast.Attribute,
    parents: dict[ast.AST, ast.AST],
    bindings: _Bindings,
    legacy: set[str],
    writers: set[str],
) -> None:
    base = _dotted(node.value)
    if base in bindings.core_modules and node.attr in FROZEN_TOP_LEVEL_V1:
        legacy.add(_site(relative, node, parents, "top_level_v1_attribute", node.attr))
    compatibility_writer_bases = {f"{module}.writer" for module in bindings.compatibility_modules}
    if base in bindings.writer_modules or base in compatibility_writer_bases:
        writers.add(_site(relative, node, parents, "writer_facade_reference", node.attr))


def _classify_call(
    relative: str,
    node: ast.Call,
    parents: dict[ast.AST, ast.AST],
    bindings: _Bindings,
    writers: set[str],
    dynamic: set[str],
) -> None:
    function = _dotted(node.func)
    if isinstance(node.func, ast.Name) and node.func.id in bindings.writer_members:
        writers.add(_site(relative, node, parents, "writer_facade_call", node.func.id))
    if isinstance(node.func, ast.Attribute):
        base = _dotted(node.func.value)
        compatibility_bases = {f"{module}.writer" for module in bindings.compatibility_modules}
        if base in bindings.writer_modules or base in compatibility_bases:
            writers.add(_site(relative, node, parents, "writer_facade_call", node.func.attr))
    if (
        _is_import_call(function, bindings)
        and (target := _import_target(node, function)) is not None
        and (target == "openultrasast.core" or target.startswith("openultrasast.core."))
    ):
        dynamic.add(_site(relative, node, parents, "dynamic_core_import", target))
    if (
        function == "getattr"
        and len(node.args) >= 2
        and (name := _constant_argument(node, 1, "name")) in FROZEN_TOP_LEVEL_V1
        and _is_direct_core_object(node.args[0], bindings)
    ):
        dynamic.add(_site(relative, node, parents, "dynamic_compatibility_getattr", name or ""))


def _is_import_call(function: str, bindings: _Bindings) -> bool:
    if function in bindings.import_functions:
        return True
    return any(function == f"{module}.import_module" for module in bindings.import_modules)


def _constant_argument(node: ast.Call, index: int, keyword: str) -> str | None:
    value: ast.AST | None = node.args[index] if len(node.args) > index else None
    if value is None:
        value = next((item.value for item in node.keywords if item.arg == keyword), None)
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _import_target(node: ast.Call, function: str) -> str | None:
    name = _constant_argument(node, 0, "name")
    if name is None or not name.startswith("."):
        return name
    if function == "__import__" or (package := _constant_argument(node, 1, "package")) is None:
        return None
    level = len(name) - len(name.lstrip("."))
    package_parts = package.split(".")
    if level > len(package_parts):
        return None
    resolved = [*package_parts[: len(package_parts) - level + 1]]
    if suffix := name[level:]:
        resolved.append(suffix)
    return ".".join(resolved)


def _is_direct_core_object(node: ast.AST, bindings: _Bindings) -> bool:
    dotted = _dotted(node)
    if dotted in bindings.core_modules or dotted in bindings.compatibility_modules:
        return True
    if not isinstance(node, ast.Call) or not _is_import_call(_dotted(node.func), bindings):
        return False
    target = _import_target(node, _dotted(node.func))
    return target is not None and (target == "openultrasast.core" or target.startswith("openultrasast.core."))


def _inspect_file(path: Path, *, root: Path) -> tuple[int, set[str], set[str], set[str]]:
    relative = relative_path(path, root)
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise LegacyBoundaryError(f"boundary input is not readable: {relative}") from exc
    if not content:
        raise LegacyBoundaryError(f"boundary input must contain nonzero bytes: {relative}")
    try:
        tree = ast.parse(content, filename=relative)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise LegacyBoundaryError(f"boundary input is not parseable: {relative}") from exc
    parents = _parents(tree)
    imports = _import_sites(relative, tree, parents)
    references = _reference_sites(relative, tree, parents, _bindings(tree))
    return (
        len(content),
        imports[0] | references[0],
        imports[1] | references[1],
        imports[2] | references[2],
    )


def inspect_legacy_boundary(
    paths: Sequence[Path],
    *,
    frozen_inventory: LegacyMigrationInventory,
    candidate_inventory: LegacyMigrationInventory | None = None,
    expected_scope: Sequence[Path] | None = None,
    root: Path = REPO,
    phase: BoundaryPhase = BoundaryPhase.MIGRATION,
) -> LegacyBoundaryReport:
    """Inspect explicit migration syntax after proving every declared input readable."""
    candidate = candidate_inventory or frozen_inventory
    validate_inventory_transition(frozen_inventory, candidate)
    legacy, writers, dynamic = set(), set(), set()
    bytes_read = 0
    unique_paths = tuple(sorted(set(paths), key=lambda value: value.as_posix()))
    if not unique_paths:
        raise LegacyBoundaryError("boundary scope must be nonempty")
    if not isinstance(phase, BoundaryPhase):
        raise LegacyBoundaryError("boundary phase must use BoundaryPhase")
    complete_paths = expected_boundary_scope(unique_paths, expected_scope, root, post_deletion=phase is BoundaryPhase.POST_DELETION)
    if complete_paths is None:
        raise LegacyBoundaryError("isolated post-deletion scope requires an explicit expected scope")
    scanned_scope, scanned_digest = scope_identity(unique_paths, root=root)
    expected_paths, expected_digest = scope_identity(complete_paths, root=root)
    for path in unique_paths:
        size, file_legacy, file_writers, file_dynamic = _inspect_file(path, root=root)
        bytes_read += size
        legacy.update(file_legacy)
        writers.update(file_writers)
        dynamic.update(file_dynamic)
    compatibility, consumer_imports, consumer_writers = partition_boundary_sites(
        legacy, writers, COMPATIBILITY_PATHS, post_deletion=phase is BoundaryPhase.POST_DELETION
    )
    open_entries = tuple(entry for entry in candidate.entries if entry.disposition is MigrationDisposition.OPEN)
    return LegacyBoundaryReport(
        phase,
        len(unique_paths),
        bytes_read,
        scanned_scope,
        scanned_digest,
        expected_paths,
        expected_digest,
        open_entries,
        tuple(sorted(legacy)),
        tuple(sorted(writers)),
        tuple(sorted(dynamic)),
        consumer_imports,
        consumer_writers,
        compatibility,
    )


def require_cutover_ready(
    report: LegacyBoundaryReport,
    *,
    frozen_inventory: LegacyMigrationInventory,
    candidate_inventory: LegacyMigrationInventory,
    root: Path = REPO,
    isolated_scope: Sequence[Path] | None = None,
) -> None:
    """Remeasure an independently authoritative scope before allowing cutover."""
    if report.phase is not BoundaryPhase.POST_DELETION:
        raise LegacyBoundaryError("cutover requires a post-deletion boundary report")
    try:
        authoritative_scope = authoritative_cutover_scope(root, isolated_scope)
    except MigrationScopeError as exc:
        raise LegacyBoundaryError(str(exc)) from exc
    scope_error = cutover_scope_error(
        report.files_read,
        report.bytes_read,
        report.scanned_scope_paths,
        report.scanned_scope_digest,
        report.expected_scope_paths,
        report.expected_scope_digest,
    )
    if scope_error:
        raise LegacyBoundaryError(f"cutover {scope_error}")
    residue_error = cutover_residue_error(
        len(report.open_inventory_entries),
        report.compatibility_implementation_sites,
        report.legacy_import_sites or report.consumer_legacy_import_sites,
        report.legacy_writer_sites or report.consumer_legacy_writer_sites,
        report.forbidden_dynamic_sites,
    )
    if residue_error:
        raise LegacyBoundaryError(f"cutover {residue_error}")
    authoritative = inspect_legacy_boundary(
        authoritative_scope,
        frozen_inventory=frozen_inventory,
        candidate_inventory=candidate_inventory,
        expected_scope=authoritative_scope,
        root=root,
        phase=BoundaryPhase.POST_DELETION,
    )
    if report != authoritative:
        raise LegacyBoundaryError("cutover report does not match the authoritative boundary scan")


__all__ = [
    "BoundaryPhase",
    "FROZEN_TOP_LEVEL_V1",
    "LegacyBoundaryError",
    "LegacyBoundaryReport",
    "boundary_python",
    "inspect_legacy_boundary",
    "require_cutover_ready",
    "static_top_level_exports",
]
