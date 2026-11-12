"""Closed input and runtime-provenance instruments for the final V3 gate."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from detection_core_fixtures import InMemoryContentResolver

from openultrasast.core import canonical

EVALUATION_ADMISSION_SCHEMA_V3 = "openultrasast.detection-core.evaluation-admission.v3"
_GATE_OWNED_NAMES = frozenset(
    {
        "detection_core_final_integration.py",
        "test_core_evaluation_final_integration.py",
    }
)
_V2_FIXTURE_NAMES = frozenset(
    {
        "go_replay.json",
        "go_report.json",
        "manifest.json",
        "no_go_replay.json",
        "no_go_report.json",
        "validation_failures.json",
        "zero_model_replay.json",
        "zero_model_report.json",
    }
)


class FinalGateInputError(AssertionError):
    """A final-gate input or runtime source violated its closed declaration."""


class FinalGateInputClass(Enum):
    """Closed kinds of filesystem input the final gate is allowed to read."""

    V2_FIXTURE = "v2_fixture"
    V3_SUITE = "v3_suite"
    CORE_REGRESSION = "core_regression"
    GATE_INSTRUMENT = "gate_instrument"
    FIXTURE_SUPPORT = "fixture_support"
    EXTERNAL_POPULATION = "external_population"


class FinalGateInputProvenance(Enum):
    """Why one filesystem input is admitted to the final gate."""

    FROZEN_V2_ARTIFACT = "frozen_v2_artifact"
    TEST_SUITE_SOURCE = "test_suite_source"
    GATE_INSTRUMENT_SOURCE = "gate_instrument_source"
    SYNTHETIC_FIXTURE_SOURCE = "synthetic_fixture_source"


@dataclass(frozen=True)
class FinalGateInputRecord:
    """One classified, contained, regular, nonzero filesystem read."""

    source_path: Path
    resolved_path: Path
    classification: FinalGateInputClass
    provenance: FinalGateInputProvenance
    byte_count: int


@dataclass(frozen=True)
class FinalGateInputs:
    """Exact filesystem census consumed by the final validation gate."""

    repository_root: Path
    v2_fixture_paths: tuple[Path, ...]
    v3_suite_paths: tuple[Path, ...]
    core_regression_paths: tuple[Path, ...]
    gate_instrument_paths: tuple[Path, ...]
    support_paths: tuple[Path, ...]
    records: tuple[FinalGateInputRecord, ...]
    external_population_inputs: tuple[Path, ...] = field(init=False)

    def __post_init__(self) -> None:
        declared = {
            *self.v2_fixture_paths,
            *self.v3_suite_paths,
            *self.core_regression_paths,
            *self.gate_instrument_paths,
            *self.support_paths,
        }
        recorded = {record.source_path for record in self.records}
        if declared != recorded or len(recorded) != len(self.records):
            raise FinalGateInputError("final-gate input census does not exactly cover every declared path")
        external = tuple(
            record.source_path
            for record in self.records
            if not record.resolved_path.is_relative_to(self.repository_root)
            or record.classification is FinalGateInputClass.EXTERNAL_POPULATION
        )
        object.__setattr__(self, "external_population_inputs", external)
        if external:
            raise FinalGateInputError(f"external population inputs are forbidden: {external}")

    def _bytes(self, paths: tuple[Path, ...]) -> int:
        sizes = {record.source_path: record.byte_count for record in self.records}
        return sum(sizes[path] for path in paths)

    @property
    def v2_fixture_bytes(self) -> int:
        return self._bytes(self.v2_fixture_paths)

    @property
    def v3_suite_bytes(self) -> int:
        return self._bytes(self.v3_suite_paths)

    @property
    def core_regression_bytes(self) -> int:
        return self._bytes(self.core_regression_paths)

    @property
    def gate_instrument_bytes(self) -> int:
        return self._bytes(self.gate_instrument_paths)

    @property
    def support_bytes(self) -> int:
        return self._bytes(self.support_paths)


def _repository_root(repo: Path) -> Path:
    try:
        root = repo.resolve(strict=True)
    except OSError as exc:
        raise FinalGateInputError(f"repository root is unreadable: {repo}: {exc}") from exc
    if not root.is_dir():
        raise FinalGateInputError(f"repository root is not a directory: {root}")
    return root


def _reject_symlink_path(root: Path, candidate: Path) -> None:
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise FinalGateInputError(f"final-gate input path contains a symlink: {candidate}")


def _classify(relative: Path) -> tuple[FinalGateInputClass, FinalGateInputProvenance]:
    parts = relative.parts
    if len(parts) == 5 and parts[:4] == ("tests", "fixtures", "detection_core", "admission_v2") and relative.name in _V2_FIXTURE_NAMES:
        return FinalGateInputClass.V2_FIXTURE, FinalGateInputProvenance.FROZEN_V2_ARTIFACT
    if len(parts) == 2 and parts[0] == "tests":
        if relative.name in _GATE_OWNED_NAMES:
            return FinalGateInputClass.GATE_INSTRUMENT, FinalGateInputProvenance.GATE_INSTRUMENT_SOURCE
        if relative.name == "detection_core_fixtures.py":
            return FinalGateInputClass.FIXTURE_SUPPORT, FinalGateInputProvenance.SYNTHETIC_FIXTURE_SOURCE
        if relative.match("test_core_evaluation_*.py"):
            return FinalGateInputClass.V3_SUITE, FinalGateInputProvenance.TEST_SUITE_SOURCE
        if relative.match("test_core*.py"):
            return FinalGateInputClass.CORE_REGRESSION, FinalGateInputProvenance.TEST_SUITE_SOURCE
    raise FinalGateInputError(f"final-gate input path is unclassified: {relative}")


def _read_final_gate_input(repo: Path, path: Path) -> tuple[FinalGateInputRecord, bytes]:
    root = _repository_root(repo)
    candidate = path.absolute()
    if not candidate.is_relative_to(root):
        raise FinalGateInputError(f"final-gate input is outside repository: {candidate}")
    _reject_symlink_path(root, candidate)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise FinalGateInputError(f"final-gate input is unreadable: {candidate}: {exc}") from exc
    if not resolved.is_relative_to(root):
        raise FinalGateInputError(f"final-gate input resolves outside repository: {candidate}")
    if not resolved.is_file():
        raise FinalGateInputError(f"final-gate input is not a regular file: {candidate}")
    classification, provenance = _classify(resolved.relative_to(root))
    try:
        content = resolved.read_bytes()
    except OSError as exc:
        raise FinalGateInputError(f"final-gate input could not be read: {candidate}: {exc}") from exc
    if not content:
        raise FinalGateInputError(f"final-gate input read zero bytes: {candidate}")
    return FinalGateInputRecord(candidate, resolved, classification, provenance, len(content)), content


def record_final_gate_input(repo: Path, path: Path) -> FinalGateInputRecord:
    """Classify and prove one candidate filesystem input before using it."""
    return _read_final_gate_input(repo, path)[0]


def _paths(root: Path, pattern: str, purpose: str) -> tuple[Path, ...]:
    paths = tuple(sorted(root.glob(pattern)))
    if not paths:
        raise FinalGateInputError(f"{purpose} discovered zero inputs under {root}")
    return paths


def _validate_v2_manifest(contents: dict[str, bytes]) -> None:
    try:
        manifest = json.loads(contents["manifest.json"])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalGateInputError(f"V2 compatibility manifest is unreadable: {exc}") from exc
    if manifest.get("schema_version") != "openultrasast.detection-core.admission-v2-compatibility-fixtures.v1":
        raise FinalGateInputError("V2 compatibility manifest has an unexpected schema")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != 3:
        raise FinalGateInputError("V2 compatibility manifest must declare exactly three frozen cases")
    referenced = {
        value
        for row in cases
        if isinstance(row, dict)
        for key in ("report_file", "replay_file")
        if isinstance((value := row.get(key)), str)
    }
    expected = _V2_FIXTURE_NAMES - {"manifest.json", "validation_failures.json"}
    if referenced != expected:
        raise FinalGateInputError("V2 compatibility manifest does not reference the exact frozen outputs")


def collect_final_gate_inputs(repo: Path) -> FinalGateInputs:
    """Read and classify every supplied filesystem artifact before validation."""
    root = _repository_root(repo)
    tests = root / "tests"
    fixture_root = tests / "fixtures/detection_core/admission_v2"
    fixture_paths = _paths(fixture_root, "*.json", "V2 compatibility gate")
    fixture_names = {path.name for path in fixture_paths}
    if fixture_names != _V2_FIXTURE_NAMES:
        raise FinalGateInputError(
            f"V2 compatibility fixture set changed: missing={sorted(_V2_FIXTURE_NAMES - fixture_names)}, "
            f"extra={sorted(fixture_names - _V2_FIXTURE_NAMES)}"
        )
    gate_paths = tuple(sorted(tests / name for name in _GATE_OWNED_NAMES))
    gate_set = set(gate_paths)
    v3_paths = tuple(path for path in _paths(tests, "test_core_evaluation_*.py", "V3 validation gate") if path not in gate_set)
    core_paths = tuple(path for path in _paths(tests, "test_core*.py", "core regression gate") if path not in gate_set)
    support_paths = (tests / "detection_core_fixtures.py",)
    all_paths = tuple(sorted({*fixture_paths, *v3_paths, *core_paths, *gate_paths, *support_paths}))
    reads = {path: _read_final_gate_input(root, path) for path in all_paths}
    fixture_contents = {path.name: reads[path][1] for path in fixture_paths}
    _validate_v2_manifest(fixture_contents)
    return FinalGateInputs(
        root,
        fixture_paths,
        v3_paths,
        core_paths,
        gate_paths,
        support_paths,
        tuple(reads[path][0] for path in all_paths),
    )


class RuntimeInputOrigin(Enum):
    """Closed runtime sources accepted by the final synthetic replay gate."""

    SYNTHETIC_IN_MEMORY = "synthetic_in_memory"
    EXTERNAL_PATH = "external_path"


@dataclass(frozen=True)
class RuntimeContentRead:
    """One positive content read made during public replay validation."""

    artifact_id: str
    read_number: int
    byte_count: int
    origin: RuntimeInputOrigin


class RecordingContentResolver:
    """Allow and record only exact synthetic in-memory content resolution."""

    def __init__(self, wrapped: InMemoryContentResolver, origin: RuntimeInputOrigin) -> None:
        if type(wrapped) is not InMemoryContentResolver:
            raise FinalGateInputError("runtime resolver must be exact InMemoryContentResolver")
        if origin is not RuntimeInputOrigin.SYNTHETIC_IN_MEMORY:
            raise FinalGateInputError("runtime resolver must declare synthetic in-memory origin")
        self._wrapped = wrapped
        self._origin = origin
        self._records: list[RuntimeContentRead] = []

    @property
    def records(self) -> tuple[RuntimeContentRead, ...]:
        return tuple(self._records)

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        resolved = self._wrapped.resolve(reference)
        if not resolved.content:
            raise FinalGateInputError(f"runtime resolver read zero bytes for {reference.artifact_id}")
        self._records.append(RuntimeContentRead(reference.artifact_id, len(self._records) + 1, len(resolved.content), self._origin))
        return resolved


__all__ = [
    "EVALUATION_ADMISSION_SCHEMA_V3",
    "FinalGateInputClass",
    "FinalGateInputError",
    "FinalGateInputProvenance",
    "FinalGateInputRecord",
    "FinalGateInputs",
    "RecordingContentResolver",
    "RuntimeContentRead",
    "RuntimeInputOrigin",
    "collect_final_gate_inputs",
    "record_final_gate_input",
]
