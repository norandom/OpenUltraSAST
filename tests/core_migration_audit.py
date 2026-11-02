"""Independent syntax-only audit of explicit detection-core v1 readers."""

from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_EXCLUDED_PREFIXES = ("benchmarks/fixtures/", "benchmarks/pairs/", "tests/fixtures/")
_LEGACY_IMPORTS: dict[str, frozenset[str] | None] = {
    "openultrasast.core": frozenset(
        {
            "AdmissionManifest",
            "AdmissionManifestError",
            "BoundedSilence",
            "Budget",
            "Complexity",
            "Coverage",
            "FactPack",
            "Guard",
            "Hop",
            "InstrumentFailure",
            "Judgment",
            "ProbeResult",
            "ProvenClaim",
            "PushRequest",
            "PushVerdict",
            "TraceRecord",
            "Witness",
            "admit_fact_pack",
            "as_clean",
            "check_reads",
            "consume_verdict",
            "validate_admission_manifest",
        }
    ),
    "openultrasast.core._legacy_factpack": None,
    "openultrasast.core.admission": frozenset(
        {
            "AdmissionManifest",
            "AdmissionManifestError",
            "REPORT_SCHEMA_KEYS",
            "validate_admission_manifest",
            "validate_report_schema",
        }
    ),
    "openultrasast.core.budget": frozenset({"Budget", "Complexity"}),
    "openultrasast.core.consumer": None,
    "openultrasast.core.coverage": frozenset({"Coverage", "InstrumentFailure", "ResolutionOutcome", "check_reads"}),
    "openultrasast.core.factpack": frozenset({"FactPackError", "admit_fact_pack", "admit_pack_file", "load_pack_file", "verify_fact_pack"}),
    "openultrasast.core.probes": frozenset(
        {
            "FittedComponentBlocked",
            "LegacyProbeResult",
            "ShortcutDetected",
            "assert_no_shortcut",
            "require_admission_evidence",
            "reversed_pair_probe",
        }
    ),
    "openultrasast.core.provenance": frozenset({"ProvenanceMismatch", "stamp", "verify_stamp"}),
    "openultrasast.core.trace": None,
    "openultrasast.core.verdict": None,
}
_TOP_LEVEL_COMPATIBILITY = _LEGACY_IMPORTS["openultrasast.core"] or frozenset()


class LegacyReaderAuditError(ValueError):
    """The explicit-reader audit could not read or parse its declared scope."""


@dataclass(frozen=True)
class ReaderAuditReport:
    files_read: int
    bytes_read: int
    capabilities: tuple[tuple[str, str], ...]


def tracked_python() -> tuple[Path, ...]:
    completed = subprocess.run(["git", "ls-files", "*.py"], cwd=REPO, check=True, capture_output=True, text=True)
    return tuple(
        REPO / relative
        for relative in completed.stdout.splitlines()
        if relative.endswith(".py") and not relative.startswith(_EXCLUDED_PREFIXES)
    )


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def _explicit_imports(tree: ast.Module) -> set[str]:
    anchors = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _LEGACY_IMPORTS:
            allowed = _LEGACY_IMPORTS[node.module]
            anchors.update(f"import_from:{node.module}:{alias.name}" for alias in node.names if allowed is None or alias.name in allowed)
        elif isinstance(node, ast.Import):
            anchors.update(
                f"import:{alias.name}" for alias in node.names if alias.name in _LEGACY_IMPORTS and _LEGACY_IMPORTS[alias.name] is None
            )
    return anchors


def _direct_submodule_bindings(tree: ast.Module) -> dict[str, str]:
    bindings = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _LEGACY_IMPORTS and alias.name != "openultrasast.core":
                    bindings[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module == "openultrasast.core":
            for alias in node.names:
                module = f"openultrasast.core.{alias.name}"
                if module in _LEGACY_IMPORTS:
                    bindings[alias.asname or alias.name] = module
    return bindings


def _module_attribute_reads(tree: ast.Module) -> set[str]:
    bindings = _direct_submodule_bindings(tree)
    reads = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        module = bindings.get(_dotted(node.value))
        if module is None:
            continue
        allowed = _LEGACY_IMPORTS[module]
        if allowed is None or node.attr in allowed:
            reads.add(f"module_attr:{module}:{node.attr}")
    return reads


def _top_level_aliases(tree: ast.Module) -> set[str]:
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(alias.asname for alias in node.names if alias.name == "openultrasast.core" and alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "openultrasast":
            aliases.update(alias.asname or alias.name for alias in node.names if alias.name == "core")
    return aliases


def _top_level_reads(tree: ast.Module) -> set[str]:
    aliases = _top_level_aliases(tree)
    reads = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr not in _TOP_LEVEL_COMPATIBILITY:
            continue
        base = _dotted(node.value)
        if base in aliases or base == "openultrasast.core":
            reads.add(f"top_level:{node.attr}")
    return reads


def audit_legacy_readers(paths: tuple[Path, ...]) -> ReaderAuditReport:
    capabilities = set()
    files_read = 0
    bytes_read = 0
    for path in paths:
        relative = path.relative_to(REPO).as_posix()
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise LegacyReaderAuditError(f"reader audit input is not readable: {relative}") from exc
        if not content:
            raise LegacyReaderAuditError(f"reader audit input must contain nonzero bytes: {relative}")
        try:
            tree = ast.parse(content, filename=relative)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise LegacyReaderAuditError(f"reader audit input is not parseable: {relative}") from exc
        files_read += 1
        bytes_read += len(content)
        anchors = _explicit_imports(tree) | _module_attribute_reads(tree) | _top_level_reads(tree)
        capabilities.update((relative, anchor) for anchor in anchors)
    return ReaderAuditReport(files_read, bytes_read, tuple(sorted(capabilities)))


__all__ = ["LegacyReaderAuditError", "ReaderAuditReport", "audit_legacy_readers", "tracked_python"]
