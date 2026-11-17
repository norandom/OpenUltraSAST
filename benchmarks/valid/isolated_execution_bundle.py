"""Canonical label-blind component bundle construction and validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.isolated_execution_contract import (
    BUNDLE_SCHEMA,
    SAFE_EXECUTION_ENVIRONMENT,
    ArmExecutionBudgetV1,
    ComponentArmExecutionV1,
    ExecutionAdapterKind,
    ExecutionEnvironmentV1,
    IsolatedExecutionError,
    LabelBlindCaseInputV1,
    OutputDestinationV1,
    _arm_value,
    _bind_digest,
    _budget_value,
    _case_value,
    _destination_value,
    _digest,
    _environment_value,
)
from benchmarks.valid.isolated_execution_plan import (
    ExecutionPlanProjectionV1,
    component_arm_from_projection,
    project_execution_plan,
)
from benchmarks.valid.isolated_execution_plan import (
    _projection_value as _plan_projection_value,
)
from benchmarks.valid.isolated_execution_source import (
    ExecutionSourceProjectionV1,
    build_execution_source_projection,
    validate_execution_cases,
)
from benchmarks.valid.isolated_execution_source import (
    _projection_value as _source_projection_value,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationManifestV3
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentResolver, JsonValue
from openultrasast.core.evaluation_measurement import ArmKindV3
from openultrasast.core.factpack import ReviewIndependencePolicy


@dataclass(frozen=True)
class LabelBlindExecutionBundleV1:
    plan_digest: str
    declaration_digest: str
    population_digest: str
    freeze_digest: str
    manifest_digest: str
    input_set_digest: str
    source_projection: ExecutionSourceProjectionV1
    plan_projection: ExecutionPlanProjectionV1
    arm: ComponentArmExecutionV1
    case_inputs: tuple[LabelBlindCaseInputV1, ...]
    budget: ArmExecutionBudgetV1
    environment: ExecutionEnvironmentV1
    output_destination: OutputDestinationV1
    bundle_digest: str

    def __post_init__(self) -> None:
        if type(self) is not LabelBlindExecutionBundleV1:
            raise IsolatedExecutionError("bundle must use exact LabelBlindExecutionBundleV1")
        for item, field in (
            (self.plan_digest, "plan"),
            (self.declaration_digest, "declaration"),
            (self.population_digest, "population"),
            (self.freeze_digest, "freeze"),
            (self.manifest_digest, "manifest"),
            (self.input_set_digest, "input set"),
        ):
            _digest(item, field)
        _validate_bundle_members(self)
        _bind_digest(self, "bundle_digest", canonical.content_digest(_bundle_value(self, include_digest=False)))


def _validate_bundle_members(bundle: LabelBlindExecutionBundleV1) -> None:
    if type(bundle.source_projection) is not ExecutionSourceProjectionV1:
        raise IsolatedExecutionError("bundle source must use exact ExecutionSourceProjectionV1")
    bundle.source_projection.__post_init__()
    if (
        bundle.source_projection.label_blind_manifest_digest != bundle.manifest_digest
        or bundle.source_projection.input_set_digest != bundle.input_set_digest
    ):
        raise IsolatedExecutionError("bundle source projection does not match the reviewed input authority")
    if type(bundle.plan_projection) is not ExecutionPlanProjectionV1:
        raise IsolatedExecutionError("bundle plan must use exact ExecutionPlanProjectionV1")
    bundle.plan_projection.__post_init__()
    expected_arm = component_arm_from_projection(bundle.plan_projection)
    if type(bundle.arm) is not ComponentArmExecutionV1 or bundle.arm != expected_arm:
        raise IsolatedExecutionError("bundle arm is not the exact registered plan component")
    validate_execution_cases(bundle.case_inputs, bundle.source_projection)
    _validate_bundle_resources(bundle)


def _validate_bundle_resources(bundle: LabelBlindExecutionBundleV1) -> None:
    if type(bundle.budget) is not ArmExecutionBudgetV1:
        raise IsolatedExecutionError("bundle budget must use exact ArmExecutionBudgetV1")
    if type(bundle.environment) is not ExecutionEnvironmentV1:
        raise IsolatedExecutionError("bundle environment must use exact ExecutionEnvironmentV1")
    if type(bundle.output_destination) is not OutputDestinationV1:
        raise IsolatedExecutionError("bundle destination must use exact OutputDestinationV1")
    bundle.budget.__post_init__()
    bundle.environment.__post_init__()
    bundle.output_destination.__post_init__()
    projection = bundle.plan_projection
    if (
        bundle.plan_digest != projection.plan_digest
        or bundle.declaration_digest != projection.declaration_digest
        or bundle.population_digest != projection.population_digest
        or bundle.freeze_digest != projection.freeze_digest
        or bundle.input_set_digest != projection.input_set_digest
    ):
        raise IsolatedExecutionError("bundle identities do not match the validated execution plan")
    arm_id = bundle.arm.arm_id
    if bundle.budget.arm_id != arm_id or bundle.output_destination.arm_id != arm_id:
        raise IsolatedExecutionError("bundle resources do not bind the same component arm")
    if bundle.output_destination.plan_digest != bundle.plan_digest:
        raise IsolatedExecutionError("output destination does not bind the plan")
    if bundle.budget.registered_budget_digest != bundle.arm.registered_budget_digest:
        raise IsolatedExecutionError("execution budget does not match the registered budget")
    if bundle.output_destination.maximum_output_bytes != bundle.budget.maximum_output_bytes:
        raise IsolatedExecutionError("output destination does not match the execution budget")


def _bundle_value(bundle: LabelBlindExecutionBundleV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": BUNDLE_SCHEMA,
        "plan_digest": bundle.plan_digest,
        "declaration_digest": bundle.declaration_digest,
        "population_digest": bundle.population_digest,
        "freeze_digest": bundle.freeze_digest,
        "manifest_digest": bundle.manifest_digest,
        "input_set_digest": bundle.input_set_digest,
        "source_projection": _source_projection_value(bundle.source_projection, include_digest=True),
        "plan_projection": _plan_projection_value(bundle.plan_projection, include_digest=True),
        "arm": _arm_value(bundle.arm, include_digest=True),
        "case_inputs": tuple(_case_value(row, include_digest=True) for row in bundle.case_inputs),
        "budget": _budget_value(bundle.budget, include_digest=True),
        "environment": _environment_value(bundle.environment, include_digest=True),
        "output_destination": _destination_value(bundle.output_destination, include_digest=True),
    }
    if include_digest:
        value["bundle_digest"] = bundle.bundle_digest
    return value


def validate_bundle_for_plan(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> None:
    if type(bundle) is not LabelBlindExecutionBundleV1:
        raise IsolatedExecutionError("bundle must use exact LabelBlindExecutionBundleV1")
    expected_plan = project_execution_plan(
        plan,
        bundle.arm.arm_id,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    expected_source = build_execution_source_projection(
        manifest,
        public_material_manifest,
        selection,
    )
    bundle.__post_init__()
    if bundle.plan_projection != expected_plan:
        raise IsolatedExecutionError("bundle projection is not derived from the authoritative registered plan")
    if bundle.source_projection != expected_source:
        raise IsolatedExecutionError("bundle source is not derived from the authoritative reviewed inputs")


def label_blind_execution_bundle_bytes(
    plan: RegisteredEvaluationPlanV1,
    bundle: LabelBlindExecutionBundleV1,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> bytes:
    validate_bundle_for_plan(
        plan,
        bundle,
        manifest,
        public_material_manifest,
        selection,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    return canonical.canonical_bytes(_bundle_value(bundle, include_digest=True))


def build_execution_environment(
    adapter_kind: ExecutionAdapterKind,
    _ambient: Mapping[str, str] | None = None,
) -> ExecutionEnvironmentV1:
    if type(adapter_kind) is not ExecutionAdapterKind:
        raise IsolatedExecutionError("adapter kind must use the closed ExecutionAdapterKind enum")
    return ExecutionEnvironmentV1(adapter_kind, tuple(sorted(SAFE_EXECUTION_ENVIRONMENT.items())), "")


def execution_environment_bytes(environment: ExecutionEnvironmentV1) -> bytes:
    if type(environment) is not ExecutionEnvironmentV1:
        raise IsolatedExecutionError("environment must use exact ExecutionEnvironmentV1")
    environment.__post_init__()
    return canonical.canonical_bytes(_environment_value(environment, include_digest=True))


def _budget_map(
    budgets: tuple[ArmExecutionBudgetV1, ...],
    component_ids: tuple[str, ...],
) -> dict[str, ArmExecutionBudgetV1]:
    if type(budgets) is not tuple or any(type(row) is not ArmExecutionBudgetV1 for row in budgets):
        raise IsolatedExecutionError("budgets must use an exact tuple of ArmExecutionBudgetV1 values")
    for row in budgets:
        row.__post_init__()
    if tuple(sorted(row.arm_id for row in budgets)) != component_ids:
        raise IsolatedExecutionError("budgets must occur exactly once for every component arm")
    return {row.arm_id: row for row in budgets}


def build_component_execution_bundles(
    plan: RegisteredEvaluationPlanV1,
    manifest: LabelBlindPopulationManifestV3,
    selection: OrdinarySelectionV1,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    cases: tuple[LabelBlindCaseInputV1, ...],
    budgets: tuple[ArmExecutionBudgetV1, ...],
    *,
    adapter_kind: ExecutionAdapterKind,
    output_namespace_digest: str,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> tuple[LabelBlindExecutionBundleV1, ...]:
    source_projection = build_execution_source_projection(manifest, public_material_manifest, selection)
    shared_cases = validate_execution_cases(cases, source_projection)
    namespace = _digest(output_namespace_digest, "output namespace")
    registrations = tuple(
        sorted(
            (row for row in plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT),
            key=lambda row: row.arm_id,
        )
    )
    if not registrations:
        raise IsolatedExecutionError("plan must contain at least one component arm")
    component_ids = tuple(row.arm_id for row in registrations)
    budget_by_arm = _budget_map(budgets, component_ids)
    environment = build_execution_environment(adapter_kind)
    projections = tuple(
        project_execution_plan(
            plan,
            row.arm_id,
            strategy_review_policy=strategy_review_policy,
            strategy_resolver=strategy_resolver,
        )
        for row in registrations
    )
    if any(
        (item.population_digest, item.freeze_digest, item.input_set_digest)
        != (manifest.population_digest, manifest.freeze_digest, manifest.input_set_digest)
        for item in projections
    ):
        raise IsolatedExecutionError("registered plan does not match the reviewed label-blind manifest")
    return tuple(
        _build_bundle(
            manifest,
            source_projection,
            projection,
            shared_cases,
            budget_by_arm[projection.target_configuration.arm_id],
            environment,
            namespace,
        )
        for projection in projections
    )


def _build_bundle(
    manifest: LabelBlindPopulationManifestV3,
    source_projection: ExecutionSourceProjectionV1,
    projection: ExecutionPlanProjectionV1,
    cases: tuple[LabelBlindCaseInputV1, ...],
    budget: ArmExecutionBudgetV1,
    environment: ExecutionEnvironmentV1,
    namespace: str,
) -> LabelBlindExecutionBundleV1:
    arm = component_arm_from_projection(projection)
    destination = OutputDestinationV1(projection.plan_digest, arm.arm_id, namespace, budget.maximum_output_bytes, "")
    return LabelBlindExecutionBundleV1(
        projection.plan_digest,
        projection.declaration_digest,
        manifest.population_digest,
        manifest.freeze_digest,
        manifest.manifest_digest,
        manifest.input_set_digest,
        source_projection,
        projection,
        arm,
        cases,
        budget,
        environment,
        destination,
        "",
    )


__all__ = [
    "LabelBlindExecutionBundleV1",
    "build_component_execution_bundles",
    "build_execution_environment",
    "execution_environment_bytes",
    "label_blind_execution_bundle_bytes",
    "validate_bundle_for_plan",
]
