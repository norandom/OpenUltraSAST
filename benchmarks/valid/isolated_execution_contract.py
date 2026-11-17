"""Closed label-blind bundle and process-outcome contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.arm_contract import ArmRole
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_measurement import ArmKindV3, ScopeKey

BUNDLE_SCHEMA = "openultrasast.valid-detection-benchmark.label-blind-execution-bundle.v1"
ENVIRONMENT_SCHEMA = "openultrasast.valid-detection-benchmark.execution-environment.v1"
PROCESS_OUTCOME_SCHEMA = "openultrasast.valid-detection-benchmark.arm-process-outcome.v1"
SAFE_EXECUTION_ENVIRONMENT: dict[str, str] = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONUNBUFFERED": "1",
    "TZ": "UTC",
}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}")


class IsolatedExecutionError(ValueError):
    """An execution value crosses or weakens the label-blind boundary."""


class ExecutionAdapterKind(StrEnum):
    LOCAL = "local"
    DOCKER = "docker"
    AX = "ax"


class ProcessOutcomeStatus(StrEnum):
    COMPLETED = "completed"
    IMPAIRED = "impaired"


class ProcessOutcomeReason(StrEnum):
    NONE = "none"
    BACKPRESSURE = "backpressure"
    DEADLINE = "deadline"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RESOURCE_LIMIT = "resource_limit"
    PROCESS_FAILURE = "process_failure"
    OUTPUT_INVALID = "output_invalid"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise IsolatedExecutionError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _opaque(value: object, field: str) -> str:
    if type(value) is not str or _OPAQUE_ID.fullmatch(value) is None:
        raise IsolatedExecutionError(f"{field} must be an opaque identifier")
    return value


def _positive(value: object, field: str, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise IsolatedExecutionError(f"{field} must be a bounded positive integer")
    return value


def _reference_value(reference: ArtifactReference) -> dict[str, JsonValue]:
    if type(reference) is not ArtifactReference:
        raise IsolatedExecutionError("code reference must use exact ArtifactReference")
    reference.__post_init__()
    if reference.artifact_kind is not ArtifactKind.POPULATION:
        raise IsolatedExecutionError("code reference must be a population artifact")
    if reference.access_class not in {ArtifactAccessClass.PUBLIC, ArtifactAccessClass.PRIVATE}:
        raise IsolatedExecutionError("sealed or operator artifacts cannot cross the execution boundary")
    _opaque(reference.content_digest, "code content digest")
    _opaque(reference.provenance_digest, "code provenance digest")
    return {
        "artifact_kind": reference.artifact_kind.value,
        "access_class": reference.access_class.value,
        "content_digest": reference.content_digest,
        "byte_length": _positive(reference.byte_length, "code byte length", 1 << 34),
        "provenance_digest": reference.provenance_digest,
    }


@dataclass(frozen=True)
class LabelBlindCaseInputV1:
    input_identity_digest: str
    change_input_digest: str
    code_reference: ArtifactReference
    case_digest: str

    def __post_init__(self) -> None:
        if type(self) is not LabelBlindCaseInputV1:
            raise IsolatedExecutionError("case input must use exact LabelBlindCaseInputV1")
        _digest(self.input_identity_digest, "input identity")
        _digest(self.change_input_digest, "change input")
        expected = canonical.content_digest(_case_value(self, include_digest=False))
        _bind_digest(self, "case_digest", expected)


def _case_value(value: LabelBlindCaseInputV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "input_identity_digest": _digest(value.input_identity_digest, "input identity"),
        "change_input_digest": _digest(value.change_input_digest, "change input"),
        "code_reference": _reference_value(value.code_reference),
    }
    if include_digest:
        result["case_digest"] = _digest(value.case_digest, "case")
    return result


@dataclass(frozen=True)
class ComponentArmExecutionV1:
    arm_id: str
    role: ArmRole
    registration_digest: str
    configuration_kind: ArmKindV3
    configuration_identity_digest: str
    analyzer_identity: str
    fact_set_digest: str
    configuration_digest: str
    judgment_vocabulary_digest: str
    outcome_mapping_digest: str
    registered_budget_digest: str
    execution_identity: str
    exact_scopes: tuple[ScopeKey, ...]
    execution_arm_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ComponentArmExecutionV1:
            raise IsolatedExecutionError("execution arm must use exact ComponentArmExecutionV1")
        _opaque(self.arm_id, "arm id")
        if type(self.role) is not ArmRole or self.role is ArmRole.COMBINED:
            raise IsolatedExecutionError("only shipped or experimental component arms may execute")
        if type(self.configuration_kind) is not ArmKindV3 or self.configuration_kind is not ArmKindV3.COMPONENT:
            raise IsolatedExecutionError("execution arm must be a component configuration")
        _opaque(self.analyzer_identity, "analyzer identity")
        _opaque(self.execution_identity, "execution identity")
        for item, field in (
            (self.registration_digest, "registration"),
            (self.configuration_identity_digest, "configuration identity"),
            (self.fact_set_digest, "fact set"),
            (self.configuration_digest, "configuration"),
            (self.judgment_vocabulary_digest, "judgment vocabulary"),
            (self.outcome_mapping_digest, "outcome mapping"),
            (self.registered_budget_digest, "registered budget"),
        ):
            _digest(item, field)
        if type(self.exact_scopes) is not tuple or not self.exact_scopes:
            raise IsolatedExecutionError("execution scopes must be a nonempty tuple")
        if any(type(item) is not ScopeKey for item in self.exact_scopes) or self.exact_scopes != tuple(sorted(set(self.exact_scopes))):
            raise IsolatedExecutionError("execution scopes must be exact, unique, and canonical")
        expected = canonical.content_digest(_arm_value(self, include_digest=False))
        _bind_digest(self, "execution_arm_digest", expected)


def _scope_value(value: ScopeKey) -> dict[str, JsonValue]:
    value.__post_init__()
    return {"family_id": value.family_id, "ecosystem": value.ecosystem}


def _arm_value(value: ComponentArmExecutionV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "arm_id": value.arm_id,
        "role": value.role.value,
        "registration_digest": value.registration_digest,
        "configuration_kind": value.configuration_kind.value,
        "configuration_identity_digest": value.configuration_identity_digest,
        "analyzer_identity": value.analyzer_identity,
        "fact_set_digest": value.fact_set_digest,
        "configuration_digest": value.configuration_digest,
        "judgment_vocabulary_digest": value.judgment_vocabulary_digest,
        "outcome_mapping_digest": value.outcome_mapping_digest,
        "registered_budget_digest": value.registered_budget_digest,
        "execution_identity": value.execution_identity,
        "exact_scopes": tuple(_scope_value(item) for item in value.exact_scopes),
    }
    if include_digest:
        result["execution_arm_digest"] = value.execution_arm_digest
    return result


@dataclass(frozen=True)
class ArmExecutionBudgetV1:
    arm_id: str
    registered_budget_digest: str
    deadline_seconds: int
    memory_bytes: int
    disk_bytes: int
    maximum_output_bytes: int
    budget_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ArmExecutionBudgetV1:
            raise IsolatedExecutionError("budget must use exact ArmExecutionBudgetV1")
        _opaque(self.arm_id, "budget arm id")
        _digest(self.registered_budget_digest, "registered budget")
        _positive(self.deadline_seconds, "deadline seconds", 86_400)
        _positive(self.memory_bytes, "memory bytes", 1 << 40)
        _positive(self.disk_bytes, "disk bytes", 1 << 42)
        _positive(self.maximum_output_bytes, "maximum output bytes", 64 * 1024 * 1024)
        expected = canonical.content_digest(_budget_value(self, include_digest=False))
        _bind_digest(self, "budget_digest", expected)


def _budget_value(value: ArmExecutionBudgetV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "arm_id": value.arm_id,
        "registered_budget_digest": value.registered_budget_digest,
        "deadline_seconds": value.deadline_seconds,
        "memory_bytes": value.memory_bytes,
        "disk_bytes": value.disk_bytes,
        "maximum_output_bytes": value.maximum_output_bytes,
    }
    if include_digest:
        result["budget_digest"] = value.budget_digest
    return result


@dataclass(frozen=True)
class ExecutionEnvironmentV1:
    adapter_kind: ExecutionAdapterKind
    variables: tuple[tuple[str, str], ...]
    environment_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ExecutionEnvironmentV1 or type(self.adapter_kind) is not ExecutionAdapterKind:
            raise IsolatedExecutionError("environment must use exact closed execution types")
        if type(self.variables) is not tuple or any(type(item) is not tuple or len(item) != 2 for item in self.variables):
            raise IsolatedExecutionError("environment variables must use an exact tuple")
        if self.variables != tuple(sorted(SAFE_EXECUTION_ENVIRONMENT.items())):
            raise IsolatedExecutionError("environment variables must equal the closed safe allowlist")
        expected = canonical.content_digest(_environment_value(self, include_digest=False))
        _bind_digest(self, "environment_digest", expected)


def _environment_value(value: ExecutionEnvironmentV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": ENVIRONMENT_SCHEMA,
        "adapter_kind": value.adapter_kind.value,
        "variables": tuple({"name": name, "value": item} for name, item in value.variables),
    }
    if include_digest:
        result["environment_digest"] = value.environment_digest
    return result


@dataclass(frozen=True)
class OutputDestinationV1:
    plan_digest: str
    arm_id: str
    namespace_digest: str
    maximum_output_bytes: int
    destination_digest: str

    def __post_init__(self) -> None:
        if type(self) is not OutputDestinationV1:
            raise IsolatedExecutionError("output destination must use exact OutputDestinationV1")
        _digest(self.plan_digest, "output plan")
        _opaque(self.arm_id, "output arm id")
        _digest(self.namespace_digest, "output namespace")
        _positive(self.maximum_output_bytes, "maximum output bytes", 64 * 1024 * 1024)
        expected = canonical.content_digest(_destination_value(self, include_digest=False))
        _bind_digest(self, "destination_digest", expected)


def _destination_value(value: OutputDestinationV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "plan_digest": value.plan_digest,
        "arm_id": value.arm_id,
        "namespace_digest": value.namespace_digest,
        "maximum_output_bytes": value.maximum_output_bytes,
    }
    if include_digest:
        result["destination_digest"] = value.destination_digest
    return result


def _bind_digest(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise IsolatedExecutionError(f"{field} does not match canonical content")


__all__ = [
    "ArmExecutionBudgetV1",
    "BUNDLE_SCHEMA",
    "ComponentArmExecutionV1",
    "ENVIRONMENT_SCHEMA",
    "ExecutionAdapterKind",
    "ExecutionEnvironmentV1",
    "IsolatedExecutionError",
    "LabelBlindCaseInputV1",
    "OutputDestinationV1",
    "PROCESS_OUTCOME_SCHEMA",
    "ProcessOutcomeReason",
    "ProcessOutcomeStatus",
    "SAFE_EXECUTION_ENVIRONMENT",
]
