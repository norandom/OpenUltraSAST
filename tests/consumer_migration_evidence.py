"""Immutable reviewed closure authority for Task 10.6 migration consumers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / "tests/fixtures/detection_core/v1/consumer_terminal_evidence.json"
SCHEMA = "openultrasast.detection-core.consumer-terminal-evidence.v1"
_FIELDS = frozenset(
    {
        "absence_anchors",
        "artifact_family",
        "binding_owner_ast_sha256",
        "binding_owner_symbol",
        "capability_anchors",
        "closure_kind",
        "dependency_kind",
        "disposition",
        "entry_id",
        "owner_boundary",
        "path",
        "probe_ast_sha256",
        "probe_symbol",
        "pytest_node_id",
        "semantic_binding",
        "semantic_contract",
        "semantic_local_name",
        "successor_ast_sha256",
        "successor_path",
        "successor_symbol",
        "symbol",
    }
)
_SEMANTIC_CONTRACT_BINDINGS = {
    "authorization_adapter_domain": frozenset({"import_from:openultrasast.semantic.obligations.trace:build_trace"}),
    "benchmark_v2_artifact": frozenset(
        {
            "dynamic_import:benchmarks.unseen.calibrate",
            "dynamic_import:benchmarks.unseen.proof",
            "dynamic_import:benchmarks.unseen.replay",
            "dynamic_import:benchmarks.unseen.score",
            "dynamic_import:benchmarks.valid.hunter_arm",
            "dynamic_import:benchmarks.valid.semgrep_arm",
            "import_from:benchmarks.valid:arm_regression",
            "import_from:benchmarks.valid:development_runner",
            "import_from:benchmarks.valid.development_runner:DevelopmentRecord",
        }
    ),
    "hunt_adapter_artifact": frozenset(
        {
            "import_from:openultrasast.hunt.artifact:RunArtifact",
            "import_from:openultrasast.hunt:contamination",
            "import_from:openultrasast.hunt:runner",
        }
    ),
    "push_adapter_domain": frozenset(
        {
            "import_from:openultrasast.push.policy:admit_candidates",
            "import_from:openultrasast.push.report:PushReport",
        }
    ),
    "v2_coverage_contract": frozenset({"import_from:openultrasast.core.coverage:InstrumentFailure"}),
}
_MODULE_FIELDS = frozenset({"path", "sha256"})


class ConsumerEvidenceError(ValueError):
    """The reviewed terminal-evidence authority is malformed."""


@dataclass(frozen=True)
class ReviewedSuccessorModule:
    """One manually reviewed successor module, authoritative down to exact bytes."""

    path: str
    sha256: str


@dataclass(frozen=True)
class ConsumerTerminalEvidence:
    entry_id: str
    path: str
    symbol: str
    dependency_kind: str
    artifact_family: str
    capability_anchors: tuple[str, ...]
    owner_boundary: str
    disposition: str
    closure_kind: str
    absence_anchors: tuple[str, ...]
    successor_path: str | None
    successor_symbol: str | None
    semantic_contract: str | None
    semantic_binding: str | None
    semantic_local_name: str | None
    binding_owner_symbol: str | None
    binding_owner_ast_sha256: str | None
    probe_symbol: str | None
    probe_ast_sha256: str | None
    successor_ast_sha256: str | None
    pytest_node_id: str | None

    @property
    def stable_fields(self) -> tuple[str, str, str, str, tuple[str, ...], str]:
        return (
            self.path,
            self.symbol,
            self.dependency_kind,
            self.artifact_family,
            self.capability_anchors,
            self.owner_boundary,
        )


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConsumerEvidenceError(f"{name} must be nonempty text")
    return value


def _optional_text(value: object, name: str) -> str | None:
    return None if value is None else _text(value, name)


def _repo_relative_posix(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConsumerEvidenceError(f"{name} must be an exact canonical repository-relative POSIX path")
    text = value
    parts = text.split("/")
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or "\0" in text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in parts)
        or posix.as_posix() != text
    ):
        raise ConsumerEvidenceError(f"{name} must be an exact canonical repository-relative POSIX path")
    return text


def _optional_repo_relative_posix(value: object, name: str) -> str | None:
    return None if value is None else _repo_relative_posix(value, name)


def _optional_sha256(value: object, name: str) -> str | None:
    text = _optional_text(value, name)
    if text is not None and (len(text) != 64 or any(character not in "0123456789abcdef" for character in text)):
        raise ConsumerEvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _sha256(value: object, name: str) -> str:
    digest = _optional_sha256(value, name)
    if digest is None:
        raise ConsumerEvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _texts(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConsumerEvidenceError(f"{name} must be a text list")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise ConsumerEvidenceError(f"{name} contains duplicates")
    return result


def _record(value: object, index: int) -> ConsumerTerminalEvidence:
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ConsumerEvidenceError(f"entries[{index}] fields differ")
    anchors = _texts(value["capability_anchors"], f"entries[{index}].capability_anchors")
    absence = _texts(value["absence_anchors"], f"entries[{index}].absence_anchors")
    record = ConsumerTerminalEvidence(
        _text(value["entry_id"], f"entries[{index}].entry_id"),
        _repo_relative_posix(value["path"], f"entries[{index}].path"),
        _text(value["symbol"], f"entries[{index}].symbol"),
        _text(value["dependency_kind"], f"entries[{index}].dependency_kind"),
        _text(value["artifact_family"], f"entries[{index}].artifact_family"),
        anchors,
        _text(value["owner_boundary"], f"entries[{index}].owner_boundary"),
        _text(value["disposition"], f"entries[{index}].disposition"),
        _text(value["closure_kind"], f"entries[{index}].closure_kind"),
        absence,
        _optional_repo_relative_posix(value["successor_path"], f"entries[{index}].successor_path"),
        _optional_text(value["successor_symbol"], f"entries[{index}].successor_symbol"),
        _optional_text(value["semantic_contract"], f"entries[{index}].semantic_contract"),
        _optional_text(value["semantic_binding"], f"entries[{index}].semantic_binding"),
        _optional_text(value["semantic_local_name"], f"entries[{index}].semantic_local_name"),
        _optional_text(value["binding_owner_symbol"], f"entries[{index}].binding_owner_symbol"),
        _optional_sha256(value["binding_owner_ast_sha256"], f"entries[{index}].binding_owner_ast_sha256"),
        _optional_text(value["probe_symbol"], f"entries[{index}].probe_symbol"),
        _optional_sha256(value["probe_ast_sha256"], f"entries[{index}].probe_ast_sha256"),
        _optional_sha256(value["successor_ast_sha256"], f"entries[{index}].successor_ast_sha256"),
        _optional_text(value["pytest_node_id"], f"entries[{index}].pytest_node_id"),
    )
    _validate_record(record, index)
    return record


def _successor_fields(record: ConsumerTerminalEvidence) -> tuple[str | None, ...]:
    return (
        record.successor_path,
        record.successor_symbol,
        record.successor_ast_sha256,
        record.semantic_contract,
        record.semantic_binding,
        record.semantic_local_name,
        record.binding_owner_symbol,
        record.binding_owner_ast_sha256,
        record.probe_symbol,
        record.probe_ast_sha256,
        record.pytest_node_id,
    )


def _validate_retired(record: ConsumerTerminalEvidence, index: int) -> None:
    if record.absence_anchors != record.capability_anchors:
        raise ConsumerEvidenceError(f"entries[{index}] must govern every frozen anchor")
    if any(_successor_fields(record)):
        raise ConsumerEvidenceError(f"entries[{index}] retired evidence has a successor")


def _validate_migrated(record: ConsumerTerminalEvidence, index: int) -> None:
    if record.absence_anchors or not all(_successor_fields(record)):
        raise ConsumerEvidenceError(f"entries[{index}] migrated evidence lacks semantic binding")
    allowed = _SEMANTIC_CONTRACT_BINDINGS.get(record.semantic_contract or "", frozenset())
    if record.semantic_binding not in allowed or not (record.successor_path or "").startswith("tests/"):
        raise ConsumerEvidenceError(f"entries[{index}] migrated evidence is outside its reviewed contract")
    expected_node = f"{record.successor_path}::{record.probe_symbol}"
    if record.pytest_node_id != expected_node or not (record.probe_symbol or "").startswith("test_"):
        raise ConsumerEvidenceError(f"entries[{index}] migrated evidence lacks an exact pytest owner")


def _validate_record(record: ConsumerTerminalEvidence, index: int) -> None:
    if len(record.entry_id) != 64 or any(character not in "0123456789abcdef" for character in record.entry_id):
        raise ConsumerEvidenceError(f"entries[{index}].entry_id is not SHA-256")
    identity = {
        "artifact_family": record.artifact_family,
        "capability_anchors": record.capability_anchors,
        "dependency_kind": record.dependency_kind,
        "owner_boundary": record.owner_boundary,
        "path": record.path,
        "symbol": record.symbol,
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != record.entry_id:
        raise ConsumerEvidenceError(f"entries[{index}].entry_id does not match frozen identity")
    if record.disposition == "retired" and record.closure_kind == "retired_exact_absence":
        _validate_retired(record, index)
        return
    if record.disposition == "v2_migrated" and record.closure_kind == "migrated_semantic_probe":
        _validate_migrated(record, index)
        return
    raise ConsumerEvidenceError(f"entries[{index}] has invalid closure/disposition")


def _module_record(value: object, index: int) -> ReviewedSuccessorModule:
    if not isinstance(value, dict) or set(value) != _MODULE_FIELDS:
        raise ConsumerEvidenceError(f"successor_modules[{index}] fields differ")
    return ReviewedSuccessorModule(
        path=_repo_relative_posix(value["path"], f"successor_modules[{index}].path"),
        sha256=_sha256(value["sha256"], f"successor_modules[{index}].sha256"),
    )


def _reviewed_modules(value: object) -> tuple[ReviewedSuccessorModule, ...]:
    if not isinstance(value, list) or not value:
        raise ConsumerEvidenceError("successor module authority must be nonempty")
    modules = tuple(_module_record(item, index) for index, item in enumerate(value))
    paths = tuple(module.path for module in modules)
    digests = tuple(module.sha256 for module in modules)
    if paths != tuple(sorted(paths)):
        raise ConsumerEvidenceError("successor module paths must be canonically ordered")
    if len(paths) != len(set(paths)):
        raise ConsumerEvidenceError("successor module paths are duplicated or conflicting")
    if len(digests) != len(set(digests)):
        raise ConsumerEvidenceError("successor module digests are duplicated or conflicting")
    return modules


def _load_consumer_authority(
    path: Path = EVIDENCE,
) -> tuple[Mapping[str, ConsumerTerminalEvidence], Mapping[str, ReviewedSuccessorModule]]:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ConsumerEvidenceError("terminal evidence is not readable") from exc
    if not content:
        raise ConsumerEvidenceError("terminal evidence must contain nonzero bytes")
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsumerEvidenceError("terminal evidence must be valid JSON") from exc
    fields = {"schema_version", "entries", "successor_modules"}
    if not isinstance(document, dict) or set(document) != fields or document["schema_version"] != SCHEMA:
        raise ConsumerEvidenceError("terminal evidence schema is invalid")
    values = document["entries"]
    if not isinstance(values, list) or not values:
        raise ConsumerEvidenceError("terminal evidence entries must be nonempty")
    records = tuple(_record(value, index) for index, value in enumerate(values))
    if len({record.entry_id for record in records}) != len(records):
        raise ConsumerEvidenceError("terminal evidence identities are duplicated")
    modules = _reviewed_modules(document["successor_modules"])
    migrated_paths = {record.successor_path for record in records if record.disposition == "v2_migrated"}
    module_paths = {module.path for module in modules}
    if None in migrated_paths or migrated_paths != module_paths:
        raise ConsumerEvidenceError("successor module authority must exactly cover migrated rows")
    entries_by_id = MappingProxyType({record.entry_id: record for record in records})
    modules_by_path = MappingProxyType({module.path: module for module in modules})
    return entries_by_id, modules_by_path


def load_consumer_terminal_evidence(path: Path = EVIDENCE) -> Mapping[str, ConsumerTerminalEvidence]:
    return _load_consumer_authority(path)[0]


def load_reviewed_successor_modules(path: Path = EVIDENCE) -> Mapping[str, ReviewedSuccessorModule]:
    return _load_consumer_authority(path)[1]


def review_successor_modules(paths: tuple[str, ...], *, root: Path = REPO) -> tuple[ReviewedSuccessorModule, ...]:
    """Explicit helper for a human-reviewed manifest update; validation never calls it."""
    reviewed = []
    for relative in paths:
        relative = _repo_relative_posix(relative, "successor module path")
        try:
            content = (root / relative).read_bytes()
        except OSError as exc:
            raise ConsumerEvidenceError(f"successor module is not readable: {relative}") from exc
        if not content:
            raise ConsumerEvidenceError(f"successor module must contain nonzero bytes: {relative}")
        reviewed.append(ReviewedSuccessorModule(relative, hashlib.sha256(content).hexdigest()))
    return tuple(reviewed)


CONSUMER_TERMINAL_EVIDENCE, REVIEWED_SUCCESSOR_MODULES = _load_consumer_authority()


def migrated_pytest_node_ids() -> tuple[str, ...]:
    """Return the reviewed executable selectors without duplicate helper owners."""
    return tuple(
        dict.fromkeys(
            evidence.pytest_node_id
            for evidence in CONSUMER_TERMINAL_EVIDENCE.values()
            if evidence.disposition == "v2_migrated" and evidence.pytest_node_id is not None
        )
    )


__all__ = [
    "CONSUMER_TERMINAL_EVIDENCE",
    "REVIEWED_SUCCESSOR_MODULES",
    "ConsumerEvidenceError",
    "ConsumerTerminalEvidence",
    "ReviewedSuccessorModule",
    "load_consumer_terminal_evidence",
    "load_reviewed_successor_modules",
    "migrated_pytest_node_ids",
    "review_successor_modules",
]
