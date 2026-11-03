"""Validation primitives for the frozen detection-core v1 migration worklist."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from benchmark_migration_evidence import BENCHMARK_TERMINAL_EVIDENCE, BenchmarkTerminalEvidence

from openultrasast.core.legacy import LegacyArtifact, decode_legacy_artifact

REPO = Path(__file__).resolve().parents[1]
INVENTORY_SCHEMA = "openultrasast.detection-core.legacy-migration.v1"
_ENTRY_FIELDS = frozenset(
    {
        "artifact_family",
        "capability_anchors",
        "dependency_kind",
        "disposition",
        "entry_id",
        "owner_boundary",
        "path",
        "symbol",
    }
)
_ARTIFACT_FIELDS = frozenset({"byte_length", "path", "schema_version", "sha256"})
_INVENTORY_FIELDS = frozenset({"entries", "historical_artifacts", "schema_version"})
_OWNER_BOUNDARIES = frozenset(
    {"authorization-adapter", "benchmark", "core", "hunt", "operational-tooling", "push", "repository-tooling", "tests"}
)


class LegacyInventoryError(ValueError):
    """The frozen migration worklist or one of its targets is invalid."""


class MigrationDisposition(Enum):
    OPEN = "open"
    V2_MIGRATED = "v2_migrated"
    RETIRED = "retired"


class DependencyKind(Enum):
    READER = "reader"
    WRITER = "writer"


_APPROVED_TERMINAL_SOURCE_CLOSURES = {
    "1c8eeb5e2b6949fb391f16030e1f9aafd676fc854761a7cd1fbf574341c90ef8": MigrationDisposition.V2_MIGRATED,
    "85631fe892d3ae9307ea2f93de6c0e280d2d8e0054fefffaa9b6edca330247a2": MigrationDisposition.V2_MIGRATED,
    "86a1113a0052c928c53719ff8ee4b110aa4bdd1a8d20ff9ab7492227e346e872": MigrationDisposition.V2_MIGRATED,
    "91f404b327f8ed526ebbd1370e6f8b065af6238e3815ece46ac1de3c35845113": MigrationDisposition.V2_MIGRATED,
    "9f2097b8a673c3079a8a61cc28e9099c671e48e6c29a3e95a9e3aac3d53ccb00": MigrationDisposition.RETIRED,
    "eb963401f43fca11e38c50e5e064f58b33233b9564a3a85e5b629a6fb2820d7d": MigrationDisposition.V2_MIGRATED,
    "f8a5c42661f6a79b0abbe668e8993fd0ec26d1c9dad5df4e141472e6de62f586": MigrationDisposition.V2_MIGRATED,
    "ae8dd5862ff8cb6fb4cdfb83f99eb0ac881fed4dd6d0e01d19f7e4bad25f1a36": MigrationDisposition.V2_MIGRATED,
    "f3ba25f48c0da317242323061f27a45213a459b93a12aeeb16389bd0f3e5525f": MigrationDisposition.V2_MIGRATED,
    "b7de07df33d29a2cba9543b53505f9789d7b51b4890797964b571c20f69fa26d": MigrationDisposition.RETIRED,
    "cb86f9a346e08246f627daa0ad1ba71b4e203d467dd08c983772b73d0926a429": MigrationDisposition.RETIRED,
    "ce683bd3299f95f9972af9e760939fc0c465a4ce0f682a0eb6e1de3e29538522": MigrationDisposition.RETIRED,
    "f206dbf8024c582e401dc14fe1dd336f0d7abfac016f6ab0c3e3980236eb6b2c": MigrationDisposition.RETIRED,
}


@dataclass(frozen=True)
class HistoricalArtifactRecord:
    path: str
    schema_version: str
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class LegacyInventoryEntry:
    entry_id: str
    path: str
    symbol: str
    dependency_kind: DependencyKind
    artifact_family: str
    capability_anchors: tuple[str, ...]
    owner_boundary: str
    disposition: MigrationDisposition


@dataclass(frozen=True)
class LegacyMigrationInventory:
    schema_version: str
    historical_artifacts: tuple[HistoricalArtifactRecord, ...]
    entries: tuple[LegacyInventoryEntry, ...]


_APPROVED_MIXED_TRANSFERS: dict[
    str,
    tuple[tuple[str, str, str, str, tuple[str, ...], str], str, tuple[str, ...]],
] = {
    "9eb4cba855044fe025daa7a523458c4fba0b12758ca604c894849f824f55ccb4": (
        (
            "src/openultrasast/core/factpack.py",
            "<module>",
            "reader",
            "v1-contract",
            ("import_from:openultrasast.core._legacy_factpack:FactPackError",),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("FactPackError",),
    ),
    "1b90ea5474dff89121dc1317a86892bb0d68f2c64117923c5979cf4bb0cd8b76": (
        (
            "src/openultrasast/core/factpack.py",
            "<module>",
            "reader",
            "v1-contract",
            ("import_from:openultrasast.core._legacy_factpack:admit_fact_pack",),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("admit_fact_pack",),
    ),
    "005f1fee3a1a659a65a45d8134bc71f061e314bdc28ba95516e870997c2648cd": (
        (
            "src/openultrasast/core/factpack.py",
            "<module>",
            "reader",
            "v1-contract",
            ("import_from:openultrasast.core._legacy_factpack:admit_pack_file",),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("admit_pack_file",),
    ),
    "4c846ba1d97e5a5b4bbf8f1e99e10c40da10906ca93d68596cb987738438582a": (
        (
            "src/openultrasast/core/factpack.py",
            "<module>",
            "reader",
            "v1-contract",
            ("import_from:openultrasast.core._legacy_factpack:load_pack_file",),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("load_pack_file",),
    ),
    "23e6ccf25c185ca231d73ab02570b14a9cddae27f7506e95d517e241bb693ae4": (
        (
            "src/openultrasast/core/factpack.py",
            "<module>",
            "reader",
            "v1-contract",
            ("import_from:openultrasast.core._legacy_factpack:verify_fact_pack",),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("verify_fact_pack",),
    ),
    "c8aaf430009a592a8ed4361f38023d5faa12a6da6186fc0dcea9c7c522da85ad": (
        (
            "src/openultrasast/core/probes.py",
            "reversed_pair_probe",
            "writer",
            "v1-probe",
            ("definition:reversed_pair_probe", "name:LegacyProbeResult"),
            "core",
        ),
        "openultrasast.core.legacy_v1.contracts",
        ("reversed_pair_probe", "LegacyProbeResult"),
    ),
}


def _object(value: object, fields: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LegacyInventoryError(f"{name} must be an object")
    actual = set(value)
    if actual != fields:
        raise LegacyInventoryError(f"{name} fields differ: missing={sorted(fields - actual)}, unknown={sorted(actual - fields)}")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LegacyInventoryError(f"{name} must be nonempty text")
    return value


def _sha256(value: object, name: str) -> str:
    text = _text(value, name)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise LegacyInventoryError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _relative_path(value: object, name: str) -> str:
    text = _text(value, name)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        raise LegacyInventoryError(f"{name} must be a normalized repository-relative path")
    return text


def _parse_artifact(value: object, index: int) -> HistoricalArtifactRecord:
    item = _object(value, _ARTIFACT_FIELDS, f"historical_artifacts[{index}]")
    length = item["byte_length"]
    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise LegacyInventoryError(f"historical_artifacts[{index}].byte_length must be positive")
    return HistoricalArtifactRecord(
        path=_relative_path(item["path"], f"historical_artifacts[{index}].path"),
        schema_version=_text(item["schema_version"], f"historical_artifacts[{index}].schema_version"),
        sha256=_sha256(item["sha256"], f"historical_artifacts[{index}].sha256"),
        byte_length=length,
    )


def _enum(enum_type: type[Enum], value: object, name: str) -> Enum:
    text = _text(value, name)
    try:
        return enum_type(text)
    except ValueError as exc:
        raise LegacyInventoryError(f"{name} has unknown value {text!r}") from exc


def _parse_entry(value: object, index: int) -> LegacyInventoryEntry:
    item = _object(value, _ENTRY_FIELDS, f"entries[{index}]")
    owner = _text(item["owner_boundary"], f"entries[{index}].owner_boundary")
    if owner not in _OWNER_BOUNDARIES:
        raise LegacyInventoryError(f"entries[{index}].owner_boundary is unknown")
    raw_anchors = item["capability_anchors"]
    if not isinstance(raw_anchors, list) or not raw_anchors:
        raise LegacyInventoryError(f"entries[{index}].capability_anchors must be a nonempty list")
    anchors = tuple(_text(anchor, f"entries[{index}].capability_anchors") for anchor in raw_anchors)
    if len(set(anchors)) != len(anchors):
        raise LegacyInventoryError(f"entries[{index}].capability_anchors contains duplicates")
    entry = LegacyInventoryEntry(
        entry_id=_sha256(item["entry_id"], f"entries[{index}].entry_id"),
        path=_relative_path(item["path"], f"entries[{index}].path"),
        symbol=_text(item["symbol"], f"entries[{index}].symbol"),
        dependency_kind=_enum(DependencyKind, item["dependency_kind"], f"entries[{index}].dependency_kind"),  # type: ignore[arg-type]
        artifact_family=_text(item["artifact_family"], f"entries[{index}].artifact_family"),
        capability_anchors=anchors,
        owner_boundary=owner,
        disposition=_enum(MigrationDisposition, item["disposition"], f"entries[{index}].disposition"),  # type: ignore[arg-type]
    )
    if entry.entry_id != entry_identity(entry):
        raise LegacyInventoryError(f"entries[{index}].entry_id does not match immutable identity fields")
    return entry


def entry_identity(entry: LegacyInventoryEntry) -> str:
    """Derive the stable identity without the mutable migration disposition."""
    value = {
        "artifact_family": entry.artifact_family,
        "capability_anchors": entry.capability_anchors,
        "dependency_kind": entry.dependency_kind.value,
        "owner_boundary": entry.owner_boundary,
        "path": entry.path,
        "symbol": entry.symbol,
    }
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _decode_inventory(content: bytes) -> LegacyMigrationInventory:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyInventoryError("migration inventory must be valid UTF-8 JSON") from exc
    root = _object(value, _INVENTORY_FIELDS, "migration inventory")
    if root["schema_version"] != INVENTORY_SCHEMA:
        raise LegacyInventoryError("migration inventory schema_version is unknown")
    raw_artifacts = root["historical_artifacts"]
    raw_entries = root["entries"]
    if not isinstance(raw_artifacts, list) or not isinstance(raw_entries, list) or not raw_entries:
        raise LegacyInventoryError("migration inventory requires artifact and nonempty entry lists")
    artifacts = tuple(_parse_artifact(item, index) for index, item in enumerate(raw_artifacts))
    entries = tuple(_parse_entry(item, index) for index, item in enumerate(raw_entries))
    if len({entry.entry_id for entry in entries}) != len(entries):
        raise LegacyInventoryError("migration inventory contains duplicate identities")
    return LegacyMigrationInventory(INVENTORY_SCHEMA, artifacts, entries)


def load_migration_inventory(path: str | Path) -> LegacyMigrationInventory:
    """Read the nonzero reviewed worklist without discovering new entries."""
    try:
        content = Path(path).read_bytes()
    except OSError as exc:
        raise LegacyInventoryError(f"migration inventory is not readable: {path}") from exc
    if not content:
        raise LegacyInventoryError("migration inventory must contain nonzero bytes")
    return _decode_inventory(content)


def _defined_symbols(tree: ast.Module) -> set[str]:
    symbols = {"<module>"}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            symbols.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            symbols.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)

    def visit(nodes: list[ast.stmt], parents: tuple[str, ...] = ()) -> None:
        for node in nodes:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                current = (*parents, node.name)
                symbols.add(".".join(current))
                visit(node.body, current)

    visit(tree.body)
    return symbols


def _call_leaf(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def _top_level_reads(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(alias.asname for alias in node.names if alias.name == "openultrasast.core" and alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "openultrasast":
            aliases.update(alias.asname or alias.name for alias in node.names if alias.name == "core")
    return {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and _dotted(node.value) in aliases | {"openultrasast.core"}
    }


def _direct_core_module_bindings(tree: ast.Module) -> dict[str, str]:
    bindings = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("openultrasast.core."):
                    bindings[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module == "openultrasast.core":
            for alias in node.names:
                bindings[alias.asname or alias.name] = f"openultrasast.core.{alias.name}"
    return bindings


def _direct_module_attributes(tree: ast.Module) -> set[str]:
    bindings = _direct_core_module_bindings(tree)
    return {
        f"{module}:{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and (module := bindings.get(_dotted(node.value))) is not None
    }


def _capability_index(tree: ast.Module) -> dict[str, set[str]]:
    imported = {
        f"{node.module}:{alias.name}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for alias in node.names
    }
    modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    constants = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names.update(node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute))
    names.update(
        alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    )
    return {
        "call": {_call_leaf(node) for node in ast.walk(tree) if isinstance(node, ast.Call)},
        "constant": constants,
        "definition": _defined_symbols(tree),
        "import": modules,
        "import_from": imported,
        "module_attr": _direct_module_attributes(tree),
        "name": names,
        "top_level": _top_level_reads(tree),
    }


def _missing_anchors(entry: LegacyInventoryEntry, tree: ast.Module) -> tuple[str, ...]:
    index = _capability_index(tree)
    missing = []
    for anchor in entry.capability_anchors:
        kind, separator, value = anchor.partition(":")
        if not separator or kind not in index or value not in index[kind]:
            missing.append(anchor)
    return tuple(missing)


def _explicit_legacy_shim(tree: ast.Module, symbol: str) -> bool:
    root_symbol = symbol.split(".", 1)[0]
    return any(
        isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith("openultrasast.core.legacy_v1")
        and (symbol == "<module>" or any((alias.asname or alias.name) == root_symbol for alias in node.names))
        for node in tree.body
    )


def _stable_entry_fields(entry: LegacyInventoryEntry) -> tuple[str, str, str, str, tuple[str, ...], str]:
    return (
        entry.path,
        entry.symbol,
        entry.dependency_kind.value,
        entry.artifact_family,
        entry.capability_anchors,
        entry.owner_boundary,
    )


def _read_owner_module(path: Path, description: str) -> ast.Module:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise LegacyInventoryError(f"{description} is not readable") from exc
    if not content:
        raise LegacyInventoryError(f"{description} must contain nonzero bytes")
    try:
        return ast.parse(content, filename=path.as_posix())
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise LegacyInventoryError(f"{description} is not parseable") from exc


def _moved_mixed_v1_owner(entry: LegacyInventoryEntry, *, root: Path) -> bool:
    transfer = _APPROVED_MIXED_TRANSFERS.get(entry.entry_id)
    if transfer is None or entry.entry_id != entry_identity(entry):
        return False
    expected_fields, destination_module, destination_symbols = transfer
    if _stable_entry_fields(entry) != expected_fields:
        return False
    facade_path = root / "src/openultrasast/core/legacy_v1/__init__.py"
    facade = _read_owner_module(facade_path, "compatibility facade")
    facade_imports = {
        (node.module, alias.name, alias.asname or alias.name)
        for node in facade.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    if not all((destination_module, symbol, symbol) in facade_imports for symbol in destination_symbols):
        return False
    destination_path = root / "src" / Path(*destination_module.split("."))
    destination = _read_owner_module(destination_path.with_suffix(".py"), "compatibility destination")
    owned = {node.name for node in destination.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))}
    return set(destination_symbols) <= owned


def _successor_path(root: Path, evidence: BenchmarkTerminalEvidence) -> Path:
    assert evidence.successor_module is not None
    relative = Path(*evidence.successor_module.split(".")).with_suffix(".py")
    direct = root / relative
    return direct if direct.is_file() else root / "src" / relative


def _validate_retired_absence(entry: LegacyInventoryEntry, tree: ast.Module) -> None:
    if entry.symbol != "<module>" and entry.symbol in _defined_symbols(tree):
        raise LegacyInventoryError(f"retired owner remains live: {entry.path}:{entry.symbol}")
    if entry.symbol == "<module>" and not _missing_anchors(entry, tree):
        raise LegacyInventoryError(f"retired capability remains live: {entry.path}:{entry.capability_anchors}")


def _benchmark_terminal_source_closure(entry: LegacyInventoryEntry, *, root: Path, tree: ast.Module) -> bool:
    if not entry.path.startswith("benchmarks/") or entry.disposition is MigrationDisposition.OPEN:
        return False
    evidence = BENCHMARK_TERMINAL_EVIDENCE.get(entry.entry_id)
    if (
        evidence is None
        or evidence.disposition != entry.disposition.value
        or evidence.stable_fields != _stable_entry_fields(entry)
        or entry.entry_id != entry_identity(entry)
    ):
        raise LegacyInventoryError(f"benchmark terminal evidence is absent or mismatched: {entry.entry_id}")
    if entry.disposition is MigrationDisposition.RETIRED:
        _validate_retired_absence(entry, tree)
        return True
    successor = _read_owner_module(_successor_path(root, evidence), "migrated benchmark successor")
    assert evidence.successor_symbol is not None
    if evidence.successor_symbol not in _defined_symbols(successor):
        raise LegacyInventoryError(f"migrated owner is absent: {evidence.successor_module}:{evidence.successor_symbol}")
    return True


def _approved_terminal_source_closure(entry: LegacyInventoryEntry, *, root: Path, tree: ast.Module) -> bool:
    if _benchmark_terminal_source_closure(entry, root=root, tree=tree):
        return True
    approved = _APPROVED_TERMINAL_SOURCE_CLOSURES.get(entry.entry_id) is entry.disposition
    return approved and entry.entry_id == entry_identity(entry)


def validate_inventory_sources(inventory: LegacyMigrationInventory, *, root: Path) -> None:
    """Prove sources are readable and every open migration target remains present."""
    for entry in inventory.entries:
        path = root / entry.path
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise LegacyInventoryError(f"inventory source is not readable: {entry.path}") from exc
        if not content:
            raise LegacyInventoryError(f"inventory source must contain nonzero bytes: {entry.path}")
        try:
            tree = ast.parse(content, filename=entry.path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise LegacyInventoryError(f"inventory source is not parseable: {entry.path}") from exc
        is_shim = _explicit_legacy_shim(tree, entry.symbol)
        moved_owner = _moved_mixed_v1_owner(entry, root=root)
        terminal_closure = _approved_terminal_source_closure(entry, root=root, tree=tree)
        if entry.symbol not in _defined_symbols(tree) and not is_shim and not moved_owner and not terminal_closure:
            raise LegacyInventoryError(f"inventory target is absent: {entry.path}:{entry.symbol}")
        missing = _missing_anchors(entry, tree)
        if missing and not is_shim and not moved_owner and not terminal_closure:
            raise LegacyInventoryError(f"inventory capability is absent: {entry.path}:{missing}")


def validate_historical_artifacts(inventory: LegacyMigrationInventory, *, root: Path) -> tuple[LegacyArtifact, ...]:
    """Re-open and validate every byte-frozen v1 artifact from its exact manifest."""
    artifacts = []
    for record in inventory.historical_artifacts:
        try:
            content = (root / record.path).read_bytes()
        except OSError as exc:
            raise LegacyInventoryError(f"historical artifact is not readable: {record.path}") from exc
        if len(content) != record.byte_length:
            raise LegacyInventoryError(f"historical artifact length changed: {record.path}")
        if hashlib.sha256(content).hexdigest() != record.sha256:
            raise LegacyInventoryError(f"historical artifact digest changed: {record.path}")
        artifact = decode_legacy_artifact(content, schema_version=record.schema_version)
        artifacts.append(artifact)
    return tuple(artifacts)


def validate_inventory_transition(frozen: LegacyMigrationInventory, candidate: LegacyMigrationInventory) -> None:
    """Allow only disposition closure while retaining the frozen worklist identity."""
    frozen_ids = tuple(entry.entry_id for entry in frozen.entries)
    candidate_ids = tuple(entry.entry_id for entry in candidate.entries)
    if frozen.schema_version != candidate.schema_version or frozen_ids != candidate_ids:
        raise LegacyInventoryError("migration inventory identities changed")
    if frozen.historical_artifacts != candidate.historical_artifacts:
        raise LegacyInventoryError("historical artifact identities changed")
    for before, after in zip(frozen.entries, candidate.entries, strict=True):
        if not isinstance(before.disposition, MigrationDisposition) or not isinstance(after.disposition, MigrationDisposition):
            raise LegacyInventoryError("migration inventory disposition is outside the closed domain")
        if not isinstance(before.dependency_kind, DependencyKind) or not isinstance(after.dependency_kind, DependencyKind):
            raise LegacyInventoryError("migration inventory dependency kind is outside the closed domain")
        if entry_identity(after) != after.entry_id or entry_identity(before) != entry_identity(after):
            raise LegacyInventoryError("migration inventory identities changed")
        if before.disposition is MigrationDisposition.OPEN:
            continue
        if after.disposition is not before.disposition:
            raise LegacyInventoryError(f"terminal migration entry reopened or changed: {before.entry_id}")


__all__ = [
    "REPO",
    "DependencyKind",
    "HistoricalArtifactRecord",
    "LegacyInventoryEntry",
    "LegacyInventoryError",
    "LegacyMigrationInventory",
    "MigrationDisposition",
    "entry_identity",
    "load_migration_inventory",
    "validate_historical_artifacts",
    "validate_inventory_sources",
    "validate_inventory_transition",
]
