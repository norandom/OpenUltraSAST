"""Immutable label-blind arm registrations over detection-core V3 plans."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from benchmarks.valid.arm_strategy_decision import (
    ArmRegistryError,
    StrategyDecisionAuthorityV1,
    StrategyDecisionDisposition,
    review_strategy_decision_authority,
    strategy_decision_artifact_bytes,
    validate_strategy_decision_authority,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_measurement import ArmConfigurationV3, ArmKindV3
from openultrasast.core.evaluation_plan import (
    EvaluationBaselineIdentityV3,
    EvaluationPlanDeclarationV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    validate_evaluation_baselines,
)
from openultrasast.core.factpack import ReviewIndependencePolicy

ARM_REGISTRATION_SCHEMA = "openultrasast.valid-detection-benchmark.arm-registration.v1"
REGISTERED_PLAN_SCHEMA = "openultrasast.valid-detection-benchmark.registered-evaluation-plan.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ROLE_ORDER: dict[ArmRole, int]


class ArmRole(StrEnum):
    """Benchmark-visible arm roles that must remain separately reportable."""

    SHIPPED = "shipped"
    EXPERIMENTAL = "experimental"
    COMBINED = "combined"


class ArmLifecycleState(StrEnum):
    """Closed lifecycle state consumed by the benchmark registry."""

    ACTIVE = "active"
    PARKED = "parked"


_ROLE_ORDER = {ArmRole.SHIPPED: 0, ArmRole.EXPERIMENTAL: 1, ArmRole.COMBINED: 2}


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ArmRegistryError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _registration_value(registration: ArmRegistrationV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": ARM_REGISTRATION_SCHEMA,
        "role": registration.role.value,
        "lifecycle_state": registration.lifecycle_state.value,
        "strategy_decision_authority_digest": None
        if registration.strategy_decision_authority is None
        else registration.strategy_decision_authority.authority_digest,
        "arm_id": registration.configuration.arm_id,
        "configuration_identity_digest": registration.configuration.configuration_identity_digest,
    }
    if include_digest:
        value["registration_digest"] = registration.registration_digest
    return value


@dataclass(frozen=True)
class ArmRegistrationV1:
    """One lifecycle-qualified role around an exact core V3 configuration."""

    role: ArmRole
    lifecycle_state: ArmLifecycleState
    strategy_decision_authority: StrategyDecisionAuthorityV1 | None
    configuration: ArmConfigurationV3
    registration_digest: str

    @property
    def arm_id(self) -> str:
        return self.configuration.arm_id

    def __post_init__(self) -> None:
        if type(self) is not ArmRegistrationV1:
            raise ArmRegistryError("arm registration must use exact ArmRegistrationV1")
        if type(self.role) is not ArmRole:
            raise ArmRegistryError("arm role must use the closed ArmRole enum")
        if type(self.lifecycle_state) is not ArmLifecycleState:
            raise ArmRegistryError("lifecycle state must use the closed ArmLifecycleState enum")
        if type(self.configuration) is not ArmConfigurationV3:
            raise ArmRegistryError("configuration must use exact ArmConfigurationV3")
        self.configuration.__post_init__()
        _validate_role_kind(self.role, self.configuration.kind)
        _validate_strategy_decision(self.lifecycle_state, self.strategy_decision_authority)
        expected = canonical.content_digest(_registration_value(self, include_digest=False))
        if self.registration_digest == "":
            object.__setattr__(self, "registration_digest", expected)
        elif _digest(self.registration_digest, "registration digest") != expected:
            raise ArmRegistryError("registration digest does not match canonical content")


def _validate_role_kind(role: ArmRole, kind: ArmKindV3) -> None:
    if role is ArmRole.COMBINED and kind is not ArmKindV3.COMBINED:
        raise ArmRegistryError("combined role requires a combined core V3 configuration")
    if role is not ArmRole.COMBINED and kind is not ArmKindV3.COMPONENT:
        raise ArmRegistryError("shipped and experimental roles require component core V3 configurations")


def _validate_strategy_decision(state: ArmLifecycleState, authority: StrategyDecisionAuthorityV1 | None) -> None:
    if state is ArmLifecycleState.ACTIVE:
        if authority is not None:
            raise ArmRegistryError("active arm must not carry a strategy-decision reference")
        return
    if type(authority) is not StrategyDecisionAuthorityV1:
        raise ArmRegistryError("parked arm requires an exact reviewed strategy-decision authority")
    authority.__post_init__()


def _registration_key(registration: ArmRegistrationV1) -> tuple[int, str]:
    return (_ROLE_ORDER[registration.role], registration.arm_id)


def _canonical_registrations(value: object) -> tuple[ArmRegistrationV1, ...]:
    if type(value) is not tuple or not value or any(type(row) is not ArmRegistrationV1 for row in value):
        raise ArmRegistryError("registrations must be a nonempty tuple of exact ArmRegistrationV1 values")
    rows = value
    for row in rows:
        row.__post_init__()
    if rows != tuple(sorted(rows, key=_registration_key)):
        raise ArmRegistryError("registrations must use canonical role and arm order")
    if len({row.arm_id for row in rows}) != len(rows):
        raise ArmRegistryError("registrations must use unique arm identities")
    return rows


def _refuses_parked_access_control(registrations: tuple[ArmRegistrationV1, ...]) -> None:
    for registration in registrations:
        if any(scope.family_id == "access_control" for scope in registration.configuration.exact_scopes):
            raise ArmRegistryError("the access-control arm remains parked without a strategy decision supplied by this spec")


def _validate_parked_authorities(
    registrations: tuple[ArmRegistrationV1, ...],
    policy: ReviewIndependencePolicy | None,
    resolver: canonical.ContentResolver | None,
) -> None:
    parked = tuple(row for row in registrations if row.lifecycle_state is ArmLifecycleState.PARKED)
    if not parked:
        return
    if type(policy) is not ReviewIndependencePolicy or resolver is None:
        raise ArmRegistryError("parked arms require an exact strategy review policy and resolver")
    for registration in parked:
        authority = registration.strategy_decision_authority
        if type(authority) is not StrategyDecisionAuthorityV1:
            raise ArmRegistryError("parked arm strategy authority is missing")
        validate_strategy_decision_authority(authority, registration.configuration, policy, resolver)


def _plan_value(plan: RegisteredEvaluationPlanV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": REGISTERED_PLAN_SCHEMA,
        "registration_digests": tuple(row.registration_digest for row in plan.registrations),
        "declaration_digest": plan.declaration.declaration_digest,
        "baseline_digests": tuple(row.baseline_digest for row in plan.baselines),
    }
    if include_digest:
        value["plan_digest"] = plan.plan_digest
    return value


@dataclass(frozen=True)
class RegisteredEvaluationPlanV1:
    """Structural benchmark plan; parked-arm acceptance requires revalidation."""

    registrations: tuple[ArmRegistrationV1, ...]
    declaration: EvaluationPlanDeclarationV3
    baselines: tuple[EvaluationBaselineIdentityV3, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        if type(self) is not RegisteredEvaluationPlanV1:
            raise ArmRegistryError("registered plan must use exact RegisteredEvaluationPlanV1")
        registrations = _canonical_registrations(self.registrations)
        _refuses_parked_access_control(registrations)
        if type(self.declaration) is not EvaluationPlanDeclarationV3:
            raise ArmRegistryError("declaration must use exact EvaluationPlanDeclarationV3")
        self.declaration.__post_init__()
        registered_ids = tuple(sorted(row.arm_id for row in registrations))
        declared_ids = tuple(row.arm_id for row in self.declaration.arm_configurations)
        if declared_ids != registered_ids:
            raise ArmRegistryError("declaration arm identities do not equal registered arms")
        if tuple(row.configuration for row in registrations) != _configurations_by_registration(self.declaration, registrations):
            raise ArmRegistryError("declaration configurations do not match registered arms")
        validate_evaluation_baselines(self.declaration, self.baselines)
        expected = canonical.content_digest(_plan_value(self, include_digest=False))
        if self.plan_digest == "":
            object.__setattr__(self, "plan_digest", expected)
        elif _digest(self.plan_digest, "plan digest") != expected:
            raise ArmRegistryError("plan digest does not match canonical content")


def _configurations_by_registration(
    declaration: EvaluationPlanDeclarationV3,
    registrations: tuple[ArmRegistrationV1, ...],
) -> tuple[ArmConfigurationV3, ...]:
    configurations = {row.arm_id: row for row in declaration.arm_configurations}
    try:
        return tuple(configurations[row.arm_id] for row in registrations)
    except KeyError as exc:
        raise ArmRegistryError("declaration is missing a registered arm") from exc


def register_evaluation_plan(
    *,
    registrations: tuple[ArmRegistrationV1, ...],
    population_digest: str,
    freeze_digest: str,
    input_set_digest: str,
    input_identity_digests: tuple[str, ...],
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> RegisteredEvaluationPlanV1:
    """Canonicalize registry order and derive the only accepted core V3 plan."""
    if type(registrations) is not tuple or not registrations:
        raise ArmRegistryError("registrations must be a nonempty tuple")
    if any(type(row) is not ArmRegistrationV1 for row in registrations):
        raise ArmRegistryError("registrations must use exact ArmRegistrationV1 values")
    canonical_registrations = tuple(sorted(registrations, key=_registration_key))
    _canonical_registrations(canonical_registrations)
    _refuses_parked_access_control(canonical_registrations)
    declaration = create_evaluation_plan_declaration(
        population_digest=population_digest,
        freeze_digest=freeze_digest,
        input_set_digest=input_set_digest,
        arm_configurations=tuple(row.configuration for row in canonical_registrations),
        input_identity_digests=input_identity_digests,
    )
    baselines = derive_evaluation_baselines(declaration)
    plan = RegisteredEvaluationPlanV1(canonical_registrations, declaration, baselines, "")
    validate_registered_evaluation_plan(
        plan,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    return plan


def validate_registered_evaluation_plan(
    plan: RegisteredEvaluationPlanV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> None:
    """Revalidate every parked-arm authority before accepting a structural plan."""
    if type(plan) is not RegisteredEvaluationPlanV1:
        raise ArmRegistryError("plan must use exact RegisteredEvaluationPlanV1")
    plan.__post_init__()
    _refuses_parked_access_control(plan.registrations)
    _validate_parked_authorities(plan.registrations, strategy_review_policy, strategy_resolver)


def registered_evaluation_plan_bytes(
    plan: RegisteredEvaluationPlanV1,
    *,
    strategy_review_policy: ReviewIndependencePolicy | None = None,
    strategy_resolver: canonical.ContentResolver | None = None,
) -> bytes:
    """Return canonical bytes after resolving every parked-arm authority."""
    validate_registered_evaluation_plan(
        plan,
        strategy_review_policy=strategy_review_policy,
        strategy_resolver=strategy_resolver,
    )
    return canonical.canonical_bytes(_plan_value(plan, include_digest=True))


__all__ = [
    "ARM_REGISTRATION_SCHEMA",
    "REGISTERED_PLAN_SCHEMA",
    "ArmLifecycleState",
    "ArmRegistrationV1",
    "ArmRegistryError",
    "ArmRole",
    "RegisteredEvaluationPlanV1",
    "StrategyDecisionAuthorityV1",
    "StrategyDecisionDisposition",
    "register_evaluation_plan",
    "review_strategy_decision_authority",
    "registered_evaluation_plan_bytes",
    "strategy_decision_artifact_bytes",
    "validate_registered_evaluation_plan",
    "validate_strategy_decision_authority",
]
