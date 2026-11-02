"""Deterministic source and compatibility-surface manifests for migration tests."""

from __future__ import annotations

import ast
import hashlib
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[1]
_TASK_FILES = (
    "tests/core_migration_boundary.py",
    "tests/core_migration_scope.py",
    "tests/test_core_migration_boundary.py",
)
_FIXTURE_PREFIXES = ("benchmarks/fixtures/", "tests/fixtures/")
COMPATIBILITY_PATHS = frozenset(
    """src/openultrasast/core/__init__.py src/openultrasast/core/_legacy_factpack.py
    src/openultrasast/core/admission.py src/openultrasast/core/consumer.py
    src/openultrasast/core/trace.py src/openultrasast/core/verdict.py""".split()  # noqa: SIM905
)
COMPATIBILITY_SHIMS = frozenset(
    """openultrasast.core._legacy_factpack openultrasast.core.admission
    openultrasast.core.consumer openultrasast.core.trace openultrasast.core.verdict""".split()  # noqa: SIM905
)
FROZEN_TOP_LEVEL_V1 = tuple(
    """REPORT_SCHEMA_KEYS AdmissionManifest AdmissionManifestError BoundedSilence Budget BudgetGateFailure
    Complexity Coverage FactPack FactPackError FittedComponentBlocked Guard Hop InstrumentFailure Judgment ProbeResult
    ProvenClaim ProvenanceMismatch PushRequest PushVerdict ResolutionOutcome ShortcutDetected TraceRecord Witness
    admit_fact_pack as_clean assert_no_shortcut check_budget check_reads consume_verdict derive_budget
    require_admission_evidence reversed_pair_probe stamp validate_admission_manifest validate_report_schema
    verify_fact_pack verify_stamp""".split()  # noqa: SIM905
)


class MigrationScopeError(ValueError):
    """A scope or compatibility manifest could not be read exactly."""


def _owned_python(relative: str) -> bool:
    if not relative.endswith(".py") or relative.startswith(_FIXTURE_PREFIXES):
        return False
    path = PurePosixPath(relative)
    if relative.startswith("benchmarks/pairs/"):
        return path.name not in {"fixed.py", "vuln.py"} and path.parts[2] != "sast"
    return True


def boundary_python(root: Path = REPO) -> tuple[Path, ...]:
    """Return owned tracked Python, excluding only harvested fixture material."""
    completed = subprocess.run(["git", "ls-files", "*.py"], cwd=root, check=True, capture_output=True, text=True)
    relatives = {value for value in completed.stdout.splitlines() if _owned_python(value)}
    relatives.update(path for path in _TASK_FILES if (root / path).is_file())
    return tuple(root / relative for relative in sorted(relatives))


def expected_boundary_scope(
    scanned: Sequence[Path], supplied: Sequence[Path] | None, root: Path, *, post_deletion: bool
) -> Sequence[Path] | None:
    if not post_deletion:
        return supplied or scanned
    return boundary_python(root) if root.resolve() == REPO else supplied


def authoritative_cutover_scope(root: Path, isolated_scope: Sequence[Path] | None) -> tuple[Path, ...]:
    """Derive cutover scope independently of the supplied measurement report."""
    if root.resolve() == REPO.resolve():
        if isolated_scope is not None:
            raise MigrationScopeError("repository scope cannot be overridden")
        return boundary_python(root)
    if isolated_scope is None:
        raise MigrationScopeError("isolated cutover requires an independent scope")
    scope = tuple(isolated_scope)
    if not scope:
        raise MigrationScopeError("isolated cutover scope must be nonempty")
    return scope


def scope_identity(paths: Sequence[Path], *, root: Path) -> tuple[tuple[str, ...], str]:
    """Return sorted relative paths and an unambiguous SHA-256 path manifest."""
    relatives = tuple(sorted({relative_path(path, root) for path in paths}))
    return relatives, manifest_digest(relatives)


def manifest_digest(relatives: Sequence[str]) -> str:
    manifest = "".join(f"{len(relative)}:{relative}\n" for relative in relatives).encode()
    return hashlib.sha256(manifest).hexdigest()


def scope_identity_error(
    scanned_paths: Sequence[str], scanned_digest: str, expected_paths: Sequence[str], expected_digest: str
) -> str | None:
    if scanned_digest != manifest_digest(scanned_paths):
        return "scope manifest is invalid"
    if expected_digest != manifest_digest(expected_paths):
        return "expected scope identity is invalid"
    if tuple(scanned_paths) != tuple(expected_paths):
        return "requires the complete repository scope"
    return None


def cutover_scope_error(
    files_read: int,
    bytes_read: int,
    scanned_paths: Sequence[str],
    scanned_digest: str,
    expected_paths: Sequence[str],
    expected_digest: str,
) -> str | None:
    if files_read <= 0 or bytes_read <= 0:
        return "requires positive input read proof"
    if files_read != len(scanned_paths):
        return "file count does not match scanned scope"
    if tuple(scanned_paths) != tuple(sorted(set(scanned_paths))):
        return "scanned scope must be normalized, sorted, and unique"
    return scope_identity_error(scanned_paths, scanned_digest, expected_paths, expected_digest)


def cutover_residue_error(
    open_count: int,
    compatibility: Sequence[str],
    imports: Sequence[str],
    writers: Sequence[str],
    dynamic: Sequence[str],
) -> str | None:
    checks = (
        (open_count > 0, f"has {open_count} open inventory entries"),
        (bool(compatibility), f"retains compatibility implementation: {compatibility[0] if compatibility else ''}"),
        (bool(imports), f"has legacy import sites: {imports[0] if imports else ''}"),
        (bool(writers), f"has legacy writer sites: {writers[0] if writers else ''}"),
        (bool(dynamic), f"has forbidden dynamic sites: {dynamic[0] if dynamic else ''}"),
    )
    return next((message for failed, message in checks if failed), None)


def partition_boundary_sites(
    legacy: set[str], writers: set[str], compatibility_paths: frozenset[str], *, post_deletion: bool
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if post_deletion:
        return (), tuple(sorted(legacy)), tuple(sorted(writers))
    compatibility = {
        site
        for site in legacy | writers
        if (path := site.split(":", 1)[0]) in compatibility_paths or path.startswith("src/openultrasast/core/legacy_v1/")
    }
    return tuple(sorted(compatibility)), tuple(sorted(legacy - compatibility)), tuple(sorted(writers - compatibility))


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def static_top_level_v1(root: Path = REPO) -> tuple[str, ...]:
    """Read the migration shim's literal ``__all__`` without importing it."""
    path = root / "src/openultrasast/core/__init__.py"
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise MigrationScopeError("top-level compatibility surface is not readable") from exc
    if not content:
        raise MigrationScopeError("top-level compatibility surface must contain nonzero bytes")
    try:
        tree = ast.parse(content, filename=path.as_posix())
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise MigrationScopeError("top-level compatibility surface is not parseable") from exc
    declared = [_literal_all(node) for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))]
    values = [value for value in declared if value is not None]
    if len(values) != 1:
        raise MigrationScopeError("top-level compatibility surface must declare one literal __all__")
    return values[0]


def _literal_all(node: ast.Assign | ast.AnnAssign) -> tuple[str, ...] | None:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
        return None
    value = node.value
    if not isinstance(value, (ast.List, ast.Tuple)):
        raise MigrationScopeError("top-level compatibility __all__ must be a literal sequence")
    if not all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts):
        raise MigrationScopeError("top-level compatibility __all__ must contain literal names")
    return tuple(item.value for item in value.elts if isinstance(item, ast.Constant) and isinstance(item.value, str))


__all__ = [
    "FROZEN_TOP_LEVEL_V1",
    "COMPATIBILITY_PATHS",
    "COMPATIBILITY_SHIMS",
    "MigrationScopeError",
    "REPO",
    "authoritative_cutover_scope",
    "boundary_python",
    "cutover_scope_error",
    "cutover_residue_error",
    "expected_boundary_scope",
    "manifest_digest",
    "partition_boundary_sites",
    "relative_path",
    "scope_identity_error",
    "scope_identity",
    "static_top_level_v1",
]
