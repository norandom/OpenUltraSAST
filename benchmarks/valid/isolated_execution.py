"""Isolated label-blind adapter execution and closed process outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.isolated_execution_bundle import (
    LabelBlindExecutionBundleV1,
    label_blind_execution_bundle_bytes,
)
from benchmarks.valid.isolated_execution_bundle import (
    build_component_execution_bundles as build_component_execution_bundles,
)
from benchmarks.valid.isolated_execution_bundle import (
    build_execution_environment as build_execution_environment,
)
from benchmarks.valid.isolated_execution_bundle import (
    execution_environment_bytes as execution_environment_bytes,
)
from benchmarks.valid.isolated_execution_contract import (
    PROCESS_OUTCOME_SCHEMA,
    IsolatedExecutionError,
    ProcessOutcomeReason,
    ProcessOutcomeStatus,
    _bind_digest,
    _digest,
    _opaque,
    _positive,
)
from benchmarks.valid.isolated_execution_contract import (
    SAFE_EXECUTION_ENVIRONMENT as SAFE_EXECUTION_ENVIRONMENT,
)
from benchmarks.valid.isolated_execution_contract import (
    ArmExecutionBudgetV1 as ArmExecutionBudgetV1,
)
from benchmarks.valid.isolated_execution_contract import (
    ComponentArmExecutionV1 as ComponentArmExecutionV1,
)
from benchmarks.valid.isolated_execution_contract import (
    ExecutionAdapterKind as ExecutionAdapterKind,
)
from benchmarks.valid.isolated_execution_contract import (
    ExecutionEnvironmentV1 as ExecutionEnvironmentV1,
)
from benchmarks.valid.isolated_execution_contract import (
    LabelBlindCaseInputV1 as LabelBlindCaseInputV1,
)
from benchmarks.valid.isolated_execution_contract import (
    OutputDestinationV1 as OutputDestinationV1,
)
from benchmarks.valid.isolated_execution_plan import (
    ComponentConfigurationAuthorityV1 as ComponentConfigurationAuthorityV1,
)
from benchmarks.valid.isolated_execution_plan import (
    ExecutionPlanArmBindingV1 as ExecutionPlanArmBindingV1,
)
from benchmarks.valid.isolated_execution_plan import (
    ExecutionPlanProjectionV1 as ExecutionPlanProjectionV1,
)
from benchmarks.valid.isolated_execution_source import (
    ExecutionSourceProjectionV1 as ExecutionSourceProjectionV1,
)
from benchmarks.valid.isolated_execution_source import (
    ExecutionSourceRecordV1 as ExecutionSourceRecordV1,
)
from benchmarks.valid.isolated_execution_source import (
    build_execution_source_projection as build_execution_source_projection,
)
from benchmarks.valid.isolated_execution_source import (
    execution_source_projection_bytes as execution_source_projection_bytes,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationManifestV3
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentResolver, JsonValue
from openultrasast.core.factpack import ReviewIndependencePolicy


@dataclass(frozen=True)
class ArmProcessOutcomeV1:
    bundle_digest: str
    arm_id: str
    status: ProcessOutcomeStatus
    reason: ProcessOutcomeReason
    runtime_ms: int
    output_digest: str
    output_bytes: int
    outcome_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ArmProcessOutcomeV1:
            raise IsolatedExecutionError("process outcome must use exact ArmProcessOutcomeV1")
        _digest(self.bundle_digest, "outcome bundle")
        _opaque(self.arm_id, "outcome arm id")
        if type(self.status) is not ProcessOutcomeStatus or type(self.reason) is not ProcessOutcomeReason:
            raise IsolatedExecutionError("process outcome must use closed status and reason enums")
        if type(self.runtime_ms) is not int or not 0 <= self.runtime_ms <= 86_400_000:
            raise IsolatedExecutionError("runtime must be a bounded nonnegative integer")
        _validate_outcome_state(self)
        _bind_digest(self, "outcome_digest", canonical.content_digest(_outcome_value(self, include_digest=False)))


def _validate_outcome_state(outcome: ArmProcessOutcomeV1) -> None:
    if outcome.status is ProcessOutcomeStatus.COMPLETED:
        if outcome.reason is not ProcessOutcomeReason.NONE:
            raise IsolatedExecutionError("completed outcome must use the none reason")
        _digest(outcome.output_digest, "output")
        _positive(outcome.output_bytes, "output bytes", 64 * 1024 * 1024)
        return
    if outcome.reason is ProcessOutcomeReason.NONE:
        raise IsolatedExecutionError("impaired outcome requires a closed reason")
    if outcome.output_digest != "" or outcome.output_bytes != 0:
        raise IsolatedExecutionError("impaired outcome cannot claim detector output")


def _outcome_value(outcome: ArmProcessOutcomeV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": PROCESS_OUTCOME_SCHEMA,
        "bundle_digest": outcome.bundle_digest,
        "arm_id": outcome.arm_id,
        "status": outcome.status.value,
        "reason": outcome.reason.value,
        "runtime_ms": outcome.runtime_ms,
        "output_digest": outcome.output_digest or None,
        "output_bytes": outcome.output_bytes,
    }
    if include_digest:
        value["outcome_digest"] = outcome.outcome_digest
    return value


def completed_adapter_outcome(
    bundle: LabelBlindExecutionBundleV1,
    output: bytes,
    *,
    runtime_ms: int,
) -> ArmProcessOutcomeV1:
    bundle.__post_init__()
    if type(output) is not bytes or not output or len(output) > bundle.budget.maximum_output_bytes:
        raise IsolatedExecutionError("adapter output must be nonempty and within the registered bound")
    return ArmProcessOutcomeV1(
        bundle.bundle_digest,
        bundle.arm.arm_id,
        ProcessOutcomeStatus.COMPLETED,
        ProcessOutcomeReason.NONE,
        runtime_ms,
        canonical.bytes_digest(output),
        len(output),
        "",
    )


def impaired_adapter_outcome(
    bundle: LabelBlindExecutionBundleV1,
    reason: ProcessOutcomeReason,
    *,
    runtime_ms: int,
) -> ArmProcessOutcomeV1:
    bundle.__post_init__()
    if type(reason) is not ProcessOutcomeReason or reason is ProcessOutcomeReason.NONE:
        raise IsolatedExecutionError("impairment requires a closed non-none reason")
    return ArmProcessOutcomeV1(
        bundle.bundle_digest,
        bundle.arm.arm_id,
        ProcessOutcomeStatus.IMPAIRED,
        reason,
        runtime_ms,
        "",
        0,
        "",
    )


def arm_process_outcome_bytes(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    outcome: ArmProcessOutcomeV1,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> bytes:
    label_blind_execution_bundle_bytes(
        plan,
        bundle,
        manifest,
        public_material_manifest,
        selection,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    if type(outcome) is not ArmProcessOutcomeV1:
        raise IsolatedExecutionError("process outcome must use exact ArmProcessOutcomeV1")
    outcome.__post_init__()
    if outcome.bundle_digest != bundle.bundle_digest or outcome.arm_id != bundle.arm.arm_id:
        raise IsolatedExecutionError("process outcome does not bind the authoritative bundle")
    return canonical.canonical_bytes(_outcome_value(outcome, include_digest=True))


class IsolatedExecutionAdapter(Protocol):
    def execute(self, bundle: LabelBlindExecutionBundleV1) -> ArmProcessOutcomeV1: ...


def _valid_adapter_outcome(
    outcome: object,
    bundle: LabelBlindExecutionBundleV1,
) -> ArmProcessOutcomeV1 | None:
    if type(outcome) is not ArmProcessOutcomeV1:
        return None
    try:
        outcome.__post_init__()
    except (TypeError, ValueError):
        return None
    if outcome.bundle_digest != bundle.bundle_digest or outcome.arm_id != bundle.arm.arm_id:
        return None
    if outcome.runtime_ms > bundle.budget.deadline_seconds * 1000:
        return None
    if outcome.output_bytes > bundle.budget.maximum_output_bytes:
        return None
    return outcome


def _execute_one(
    bundle: LabelBlindExecutionBundleV1,
    adapter: IsolatedExecutionAdapter,
) -> ArmProcessOutcomeV1:
    failed = False
    try:
        candidate = adapter.execute(bundle)
    except Exception:  # Adapter diagnostics are deliberately not retained.
        failed = True
        candidate = None
    if failed:
        return impaired_adapter_outcome(bundle, ProcessOutcomeReason.PROCESS_FAILURE, runtime_ms=0)
    valid = _valid_adapter_outcome(candidate, bundle)
    if valid is None:
        return impaired_adapter_outcome(bundle, ProcessOutcomeReason.OUTPUT_INVALID, runtime_ms=0)
    return valid


def execute_component_bundles(
    plan: RegisteredEvaluationPlanV1,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    adapter: IsolatedExecutionAdapter,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> tuple[ArmProcessOutcomeV1, ...]:
    if type(bundles) is not tuple or not bundles:
        raise IsolatedExecutionError("component bundles must be a nonempty tuple")
    if any(type(row) is not LabelBlindExecutionBundleV1 for row in bundles):
        raise IsolatedExecutionError("component bundles must use exact bundle values")
    for row in bundles:
        label_blind_execution_bundle_bytes(
            plan,
            row,
            manifest,
            public_material_manifest,
            selection,
            strategy_review_policy=strategy_review_policy,
            strategy_resolver=strategy_resolver,
        )
    if tuple(row.arm.arm_id for row in bundles) != tuple(sorted({row.arm.arm_id for row in bundles})):
        raise IsolatedExecutionError("component bundles must be unique and canonical")
    first = bundles[0]
    if any(
        row.case_inputs is not first.case_inputs
        or row.source_projection is not first.source_projection
        or row.input_set_digest != first.input_set_digest
        or row.plan_digest != first.plan_digest
        or row.manifest_digest != first.manifest_digest
        for row in bundles
    ):
        raise IsolatedExecutionError("component bundles must share one exact plan and ordered input set")
    return tuple(_execute_one(row, adapter) for row in bundles)


__all__ = [
    "ArmExecutionBudgetV1",
    "ArmProcessOutcomeV1",
    "ComponentArmExecutionV1",
    "ComponentConfigurationAuthorityV1",
    "ExecutionAdapterKind",
    "ExecutionEnvironmentV1",
    "ExecutionPlanArmBindingV1",
    "ExecutionPlanProjectionV1",
    "ExecutionSourceProjectionV1",
    "ExecutionSourceRecordV1",
    "IsolatedExecutionAdapter",
    "IsolatedExecutionError",
    "LabelBlindCaseInputV1",
    "LabelBlindExecutionBundleV1",
    "OutputDestinationV1",
    "ProcessOutcomeReason",
    "ProcessOutcomeStatus",
    "SAFE_EXECUTION_ENVIRONMENT",
    "arm_process_outcome_bytes",
    "build_component_execution_bundles",
    "build_execution_environment",
    "build_execution_source_projection",
    "completed_adapter_outcome",
    "execute_component_bundles",
    "execution_environment_bytes",
    "execution_source_projection_bytes",
    "impaired_adapter_outcome",
    "label_blind_execution_bundle_bytes",
]
