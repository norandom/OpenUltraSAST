"""Review-free execution-plan projection derived from exact core authority."""

from __future__ import annotations

from dataclasses import dataclass

from benchmarks.valid.arm_contract import (
    ArmLifecycleState,
    ArmRole,
    RegisteredEvaluationPlanV1,
    validate_registered_evaluation_plan,
)
from benchmarks.valid.isolated_execution_contract import (
    ComponentArmExecutionV1,
    IsolatedExecutionError,
    _bind_digest,
    _digest,
    _opaque,
    _scope_value,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentResolver, JsonValue
from openultrasast.core.evaluation_measurement import ArmConfigurationV3, ArmKindV3, ScopeKey
from openultrasast.core.factpack import ReviewIndependencePolicy

EXECUTION_PLAN_PROJECTION_SCHEMA = "openultrasast.valid-detection-benchmark.execution-plan-projection.v1"
EXECUTION_PLAN_ARM_BINDING_SCHEMA = "openultrasast.valid-detection-benchmark.execution-plan-arm-binding.v1"
COMPONENT_CONFIGURATION_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.component-configuration-authority.v1"
_ROLE_ORDER = {ArmRole.SHIPPED: 0, ArmRole.EXPERIMENTAL: 1, ArmRole.COMBINED: 2}


@dataclass(frozen=True)
class ExecutionPlanArmBindingV1:
    arm_id: str
    role: ArmRole
    lifecycle_state: ArmLifecycleState
    registration_digest: str
    configuration_identity_digest: str
    binding_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ExecutionPlanArmBindingV1:
            raise IsolatedExecutionError("plan arm must use exact ExecutionPlanArmBindingV1")
        _opaque(self.arm_id, "plan arm id")
        if type(self.role) is not ArmRole or type(self.lifecycle_state) is not ArmLifecycleState:
            raise IsolatedExecutionError("plan arm must use closed role and lifecycle values")
        _digest(self.registration_digest, "plan registration")
        _digest(self.configuration_identity_digest, "plan configuration")
        _bind_digest(self, "binding_digest", canonical.content_digest(_binding_value(self, include_digest=False)))


def _binding_value(binding: ExecutionPlanArmBindingV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": EXECUTION_PLAN_ARM_BINDING_SCHEMA,
        "arm_id": binding.arm_id,
        "role": binding.role.value,
        "lifecycle_state": binding.lifecycle_state.value,
        "registration_digest": binding.registration_digest,
        "configuration_identity_digest": binding.configuration_identity_digest,
    }
    if include_digest:
        value["binding_digest"] = binding.binding_digest
    return value


@dataclass(frozen=True)
class ComponentConfigurationAuthorityV1:
    arm_id: str
    exact_scopes: tuple[ScopeKey, ...]
    policy_digests: tuple[str, ...]
    threshold_digests: tuple[str, ...]
    sufficiency_digests: tuple[str, ...]
    judgment_vocabulary_digest: str
    analyzer_identity: str
    fact_set_digest: str
    configuration_digest: str
    registered_budget_digest: str
    execution_identity: str
    outcome_mapping_digest: str
    configuration_identity_digest: str
    authority_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ComponentConfigurationAuthorityV1:
            raise IsolatedExecutionError("configuration authority must use its exact V1 type")
        _opaque(self.arm_id, "configuration arm id")
        _opaque(self.analyzer_identity, "analyzer identity")
        _opaque(self.execution_identity, "execution identity")
        _validate_scopes_and_digests(self)
        _digest(self.configuration_identity_digest, "configuration identity")
        _bind_digest(self, "authority_digest", canonical.content_digest(_authority_value(self, include_digest=False)))


def _validate_scopes_and_digests(authority: ComponentConfigurationAuthorityV1) -> None:
    if authority.exact_scopes != tuple(sorted(set(authority.exact_scopes))) or not authority.exact_scopes:
        raise IsolatedExecutionError("configuration scopes must be nonempty and canonical")
    if any(type(scope) is not ScopeKey for scope in authority.exact_scopes):
        raise IsolatedExecutionError("configuration scopes must use exact ScopeKey values")
    digest_groups = (authority.policy_digests, authority.threshold_digests, authority.sufficiency_digests)
    if any(type(group) is not tuple or not group for group in digest_groups):
        raise IsolatedExecutionError("configuration digest groups must be nonempty tuples")
    for item in (*digest_groups[0], *digest_groups[1], *digest_groups[2]):
        _digest(item, "configuration member")
    for item, field in (
        (authority.judgment_vocabulary_digest, "judgment vocabulary"),
        (authority.fact_set_digest, "fact set"),
        (authority.configuration_digest, "configuration"),
        (authority.registered_budget_digest, "registered budget"),
        (authority.outcome_mapping_digest, "outcome mapping"),
    ):
        _digest(item, field)


def _configuration_payload(authority: ComponentConfigurationAuthorityV1) -> dict[str, JsonValue]:
    return {
        "arm_id": authority.arm_id,
        "kind": ArmKindV3.COMPONENT.value,
        "exact_scopes": tuple(_scope_value(scope) for scope in authority.exact_scopes),
        "policy_digests": authority.policy_digests,
        "threshold_digests": authority.threshold_digests,
        "sufficiency_digests": authority.sufficiency_digests,
        "judgment_vocabulary_digest": authority.judgment_vocabulary_digest,
        "analyzer_identity": authority.analyzer_identity,
        "fact_set_digest": authority.fact_set_digest,
        "configuration_digest": authority.configuration_digest,
        "registered_budget_digest": authority.registered_budget_digest,
        "execution_identity": authority.execution_identity,
        "outcome_mapping_digest": authority.outcome_mapping_digest,
        "case_outcome_policy": "unanimous_evidence",
        "combination_rule_digest": None,
    }


def _authority_value(
    authority: ComponentConfigurationAuthorityV1,
    *,
    include_digest: bool,
) -> dict[str, JsonValue]:
    value = _configuration_payload(authority)
    value["schema_version"] = COMPONENT_CONFIGURATION_AUTHORITY_SCHEMA
    value["configuration_identity_digest"] = authority.configuration_identity_digest
    if include_digest:
        value["authority_digest"] = authority.authority_digest
    return value


@dataclass(frozen=True)
class ExecutionPlanProjectionV1:
    population_digest: str
    freeze_digest: str
    input_set_digest: str
    arm_bindings: tuple[ExecutionPlanArmBindingV1, ...]
    configuration_identity_digests: tuple[str, ...]
    expected_slot_digests: tuple[str, ...]
    baseline_digests: tuple[str, ...]
    declaration_digest: str
    plan_digest: str
    target_configuration: ComponentConfigurationAuthorityV1
    projection_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ExecutionPlanProjectionV1:
            raise IsolatedExecutionError("execution plan must use exact ExecutionPlanProjectionV1")
        for item, field in (
            (self.population_digest, "plan population"),
            (self.freeze_digest, "plan freeze"),
            (self.input_set_digest, "plan input set"),
        ):
            _digest(item, field)
        _validate_projection_members(self)
        _validate_projection_target(self)
        _bind_digest(self, "projection_digest", canonical.content_digest(_projection_value(self, include_digest=False)))


def _validate_projection_members(projection: ExecutionPlanProjectionV1) -> None:
    if type(projection.arm_bindings) is not tuple or not projection.arm_bindings:
        raise IsolatedExecutionError("plan arm bindings must be a nonempty tuple")
    for binding in projection.arm_bindings:
        if type(binding) is not ExecutionPlanArmBindingV1:
            raise IsolatedExecutionError("plan arm bindings must use exact V1 values")
        binding.__post_init__()
    keys = tuple((_ROLE_ORDER[row.role], row.arm_id) for row in projection.arm_bindings)
    if keys != tuple(sorted(keys)) or len({row.arm_id for row in projection.arm_bindings}) != len(keys):
        raise IsolatedExecutionError("plan arm bindings must be unique and registry-canonical")
    for group in (
        projection.configuration_identity_digests,
        projection.expected_slot_digests,
        projection.baseline_digests,
    ):
        if type(group) is not tuple or not group:
            raise IsolatedExecutionError("plan digest vectors must be nonempty tuples")
        for item in group:
            _digest(item, "plan vector member")
    expected_configurations = tuple(
        row.configuration_identity_digest for row in sorted(projection.arm_bindings, key=lambda row: row.arm_id)
    )
    if projection.configuration_identity_digests != expected_configurations:
        raise IsolatedExecutionError("plan configuration vector does not match registered arms")


def _validate_projection_target(projection: ExecutionPlanProjectionV1) -> None:
    _digest(projection.declaration_digest, "plan declaration")
    _digest(projection.plan_digest, "plan")
    projection.target_configuration.__post_init__()
    binding = _target_binding(projection)
    if binding.lifecycle_state is not ArmLifecycleState.ACTIVE or binding.role is ArmRole.COMBINED:
        raise IsolatedExecutionError("only an active component registration may cross execution")
    if binding.configuration_identity_digest != projection.target_configuration.configuration_identity_digest:
        raise IsolatedExecutionError("target configuration does not match its plan registration")


def _target_binding(projection: ExecutionPlanProjectionV1) -> ExecutionPlanArmBindingV1:
    matches = tuple(row for row in projection.arm_bindings if row.arm_id == projection.target_configuration.arm_id)
    if len(matches) != 1:
        raise IsolatedExecutionError("target component must occur exactly once in the plan")
    return matches[0]


def _projection_value(projection: ExecutionPlanProjectionV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": EXECUTION_PLAN_PROJECTION_SCHEMA,
        "population_digest": projection.population_digest,
        "freeze_digest": projection.freeze_digest,
        "input_set_digest": projection.input_set_digest,
        "arm_bindings": tuple(_binding_value(row, include_digest=True) for row in projection.arm_bindings),
        "configuration_identity_digests": projection.configuration_identity_digests,
        "expected_slot_digests": projection.expected_slot_digests,
        "baseline_digests": projection.baseline_digests,
        "declaration_digest": projection.declaration_digest,
        "plan_digest": projection.plan_digest,
        "target_configuration": _authority_value(projection.target_configuration, include_digest=True),
    }
    if include_digest:
        value["projection_digest"] = projection.projection_digest
    return value


def _configuration_authority(configuration: ArmConfigurationV3) -> ComponentConfigurationAuthorityV1:
    if type(configuration) is not ArmConfigurationV3 or configuration.kind is not ArmKindV3.COMPONENT:
        raise IsolatedExecutionError("execution target must be an exact component configuration")
    configuration.__post_init__()
    return ComponentConfigurationAuthorityV1(
        configuration.arm_id,
        configuration.exact_scopes,
        tuple(row.policy_digest for row in configuration.denominator_policies),
        tuple(row.threshold_digest for row in configuration.thresholds),
        tuple(row.rule_digest for row in configuration.sufficiency_rules),
        configuration.judgment_vocabulary_digest,
        configuration.analyzer_identity,
        configuration.fact_set_digest,
        configuration.configuration_digest,
        configuration.registered_budget_digest,
        configuration.execution_identity,
        configuration.outcome_mapping_digest,
        configuration.configuration_identity_digest,
        "",
    )


def project_execution_plan(
    plan: RegisteredEvaluationPlanV1,
    target_arm_id: str,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: ContentResolver | None = None,
) -> ExecutionPlanProjectionV1:
    validate_registered_evaluation_plan(
        plan,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    registrations = {row.arm_id: row for row in plan.registrations}
    if target_arm_id not in registrations:
        raise IsolatedExecutionError("target arm is absent from the registered plan")
    target = registrations[target_arm_id]
    bindings = tuple(
        ExecutionPlanArmBindingV1(
            row.arm_id,
            row.role,
            row.lifecycle_state,
            row.registration_digest,
            row.configuration.configuration_identity_digest,
            "",
        )
        for row in plan.registrations
    )
    return ExecutionPlanProjectionV1(
        plan.declaration.population_digest,
        plan.declaration.freeze_digest,
        plan.declaration.input_set_digest,
        bindings,
        tuple(row.configuration_identity_digest for row in plan.declaration.arm_configurations),
        tuple(row.slot_digest for row in plan.declaration.expected_observation_slots),
        tuple(row.baseline_digest for row in plan.baselines),
        plan.declaration.declaration_digest,
        plan.plan_digest,
        _configuration_authority(target.configuration),
        "",
    )


def component_arm_from_projection(projection: ExecutionPlanProjectionV1) -> ComponentArmExecutionV1:
    projection.__post_init__()
    binding = _target_binding(projection)
    authority = projection.target_configuration
    return ComponentArmExecutionV1(
        authority.arm_id,
        binding.role,
        binding.registration_digest,
        ArmKindV3.COMPONENT,
        authority.configuration_identity_digest,
        authority.analyzer_identity,
        authority.fact_set_digest,
        authority.configuration_digest,
        authority.judgment_vocabulary_digest,
        authority.outcome_mapping_digest,
        authority.registered_budget_digest,
        authority.execution_identity,
        authority.exact_scopes,
        "",
    )


__all__ = [
    "ComponentConfigurationAuthorityV1",
    "EXECUTION_PLAN_ARM_BINDING_SCHEMA",
    "EXECUTION_PLAN_PROJECTION_SCHEMA",
    "ExecutionPlanArmBindingV1",
    "ExecutionPlanProjectionV1",
    "component_arm_from_projection",
    "project_execution_plan",
]
