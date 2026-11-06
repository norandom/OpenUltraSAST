"""Non-circular label-blind plan identities for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.evaluation_measurement import ArmConfigurationV3, ArmKindV3, ScopeKey
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.factpack import IndependenceAttestation, ReviewIndependencePolicy

_DIGEST = re.compile(r"[0-9a-f]{64}")
_PLAN_VALUE_SCHEMA = "openultrasast.detection-core.evaluation-plan-value.v3"


class EvaluationPlanError(ValueError):
    """A V3 plan identity is incomplete, non-canonical, or cross-bound."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationPlanError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise EvaluationPlanError(f"{field} must be nonempty exact text")
    return value


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _PLAN_VALUE_SCHEMA, "kind": kind, "payload": payload}


def _bind_digest(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
        return
    _digest(actual, field)
    if actual != expected:
        raise EvaluationPlanError(f"{field} does not match canonical content")


def _exact_plan_value(value: object, expected_type: type[object], field: str) -> None:
    if type(value) is not expected_type:
        raise EvaluationPlanError(f"{field} must use exact {expected_type.__name__}")


def _slot_id(arm_id: str, input_identity_digest: str) -> str:
    return canonical.content_digest(
        _value("expected_observation_slot_id", {"arm_id": arm_id, "input_identity_digest": input_identity_digest})
    )


def _slot_payload(slot: ExpectedObservationSlotV3) -> canonical.JsonValue:
    return {
        "slot_id": slot.slot_id,
        "arm_id": slot.arm_id,
        "input_identity_digest": slot.input_identity_digest,
        "execution_identity": slot.execution_identity,
    }


@dataclass(frozen=True)
class ExpectedObservationSlotV3(EvaluationV3Contract, NonAuthorizingV3):
    """One label-blind arm/input execution expected by the reviewed plan."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    slot_id: str
    arm_id: str
    input_identity_digest: str
    execution_identity: str
    slot_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ExpectedObservationSlotV3, field="expected observation slot")
        _text(self.arm_id, "slot arm_id")
        _digest(self.input_identity_digest, "slot input identity digest")
        _text(self.execution_identity, "slot execution identity")
        if self.slot_id != _slot_id(self.arm_id, self.input_identity_digest):
            raise EvaluationPlanError("slot_id does not match the canonical arm/input identity")
        _bind_digest(self, "slot_digest", canonical.content_digest(_value("expected_observation_slot", _slot_payload(self))))


def _declaration_payload(value: EvaluationPlanDeclarationV3) -> canonical.JsonValue:
    return {
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "input_set_digest": value.input_set_digest,
        "arm_configuration_digests": tuple(row.configuration_identity_digest for row in value.arm_configurations),
        "expected_observation_slot_digests": tuple(row.slot_digest for row in value.expected_observation_slots),
    }


def _canonical_configurations(value: object) -> tuple[ArmConfigurationV3, ...]:
    if type(value) is not tuple or not value or any(type(row) is not ArmConfigurationV3 for row in value):
        raise EvaluationPlanError("arm configurations must be a nonempty tuple of exact ArmConfigurationV3 values")
    rows = value
    if rows != tuple(sorted(rows, key=lambda row: row.arm_id)):
        raise EvaluationPlanError("arm configurations must use canonical arm order")
    arm_ids = tuple(row.arm_id for row in rows)
    if len(set(arm_ids)) != len(arm_ids):
        raise EvaluationPlanError("arm configurations must use unique arm identities")
    for row in rows:
        row.__post_init__()
    return rows


def _validate_combined_components(configurations: tuple[ArmConfigurationV3, ...]) -> None:
    configurations_by_arm = {row.arm_id: row for row in configurations}
    for row in configurations:
        if row.kind is ArmKindV3.COMBINED:
            rule = row.combination_rule
            if rule is None:
                raise EvaluationPlanError("combined arm requires its validated combination rule")
            absent = set(rule.component_arm_ids) - set(configurations_by_arm)
            if absent:
                raise EvaluationPlanError("combined arm names an absent component")
            if any(configurations_by_arm[arm_id].kind is not ArmKindV3.COMPONENT for arm_id in rule.component_arm_ids):
                raise EvaluationPlanError("combined arm component identity must resolve to a component configuration")


def _input_identities(slots: tuple[ExpectedObservationSlotV3, ...]) -> tuple[str, ...]:
    return tuple(sorted({row.input_identity_digest for row in slots}))


def _expected_slot_keys(configurations: tuple[ArmConfigurationV3, ...], input_identities: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    return tuple((configuration.arm_id, input_digest) for configuration in configurations for input_digest in input_identities)


def _validate_slots(configurations: tuple[ArmConfigurationV3, ...], slots: object) -> tuple[ExpectedObservationSlotV3, ...]:
    if type(slots) is not tuple or not slots or any(type(row) is not ExpectedObservationSlotV3 for row in slots):
        raise EvaluationPlanError("expected observation slots must be a nonempty tuple of exact slot values")
    rows = slots
    for row in rows:
        row.__post_init__()
    expected = _expected_slot_keys(configurations, _input_identities(rows))
    actual = tuple((row.arm_id, row.input_identity_digest) for row in rows)
    if actual != expected:
        raise EvaluationPlanError("expected observation slots must equal the canonical arm/input product")
    execution_by_arm = {row.arm_id: row.execution_identity for row in configurations}
    if any(row.execution_identity != execution_by_arm[row.arm_id] for row in rows):
        raise EvaluationPlanError("slot execution identity does not match its arm configuration")
    return rows


@dataclass(frozen=True)
class EvaluationPlanDeclarationV3(EvaluationV3Contract, NonAuthorizingV3):
    """Complete label-blind declaration hashed before any baseline exists."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    population_digest: str
    freeze_digest: str
    input_set_digest: str
    arm_configurations: tuple[ArmConfigurationV3, ...]
    expected_observation_slots: tuple[ExpectedObservationSlotV3, ...]
    declaration_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationPlanDeclarationV3, field="evaluation plan declaration")
        _digest(self.population_digest, "population digest")
        _digest(self.freeze_digest, "freeze digest")
        _digest(self.input_set_digest, "input set digest")
        configurations = _canonical_configurations(self.arm_configurations)
        _validate_combined_components(configurations)
        slots = _validate_slots(configurations, self.expected_observation_slots)
        expected_input_set_digest = derive_evaluation_input_set_digest(_input_identities(slots))
        if self.input_set_digest != expected_input_set_digest:
            raise EvaluationPlanError("input set digest does not match the canonical slot input identities")
        _bind_digest(
            self, "declaration_digest", canonical.content_digest(_value("evaluation_plan_declaration", _declaration_payload(self)))
        )


def _baseline_payload(value: EvaluationBaselineIdentityV3) -> canonical.JsonValue:
    return {
        "arm_id": value.arm_id,
        "plan_declaration_digest": value.plan_declaration_digest,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "input_set_digest": value.input_set_digest,
        "arm_configuration_digest": value.arm_configuration_digest,
    }


@dataclass(frozen=True)
class EvaluationBaselineIdentityV3(EvaluationV3Contract, NonAuthorizingV3):
    """One arm baseline derived only after its declaration is complete."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    arm_id: str
    plan_declaration_digest: str
    population_digest: str
    freeze_digest: str
    input_set_digest: str
    arm_configuration_digest: str
    baseline_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, EvaluationBaselineIdentityV3, field="evaluation baseline identity")
        _text(self.arm_id, "baseline arm_id")
        for item, field in (
            (self.plan_declaration_digest, "plan declaration digest"),
            (self.population_digest, "baseline population digest"),
            (self.freeze_digest, "baseline freeze digest"),
            (self.input_set_digest, "baseline input set digest"),
            (self.arm_configuration_digest, "arm configuration digest"),
        ):
            _digest(item, field)
        _bind_digest(self, "baseline_digest", canonical.content_digest(_value("evaluation_baseline_identity", _baseline_payload(self))))


def _canonical_input_identities(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationPlanError("input identities must be a nonempty tuple")
    for item in value:
        _digest(item, "input identity digest")
    if len(set(value)) != len(value):
        raise EvaluationPlanError("input identities must be unique")
    return tuple(sorted(value))


def derive_evaluation_input_set_digest(input_identity_digests: tuple[str, ...]) -> str:
    """Derive the authoritative identity of one exact label-blind input set."""
    identities = _canonical_input_identities(input_identity_digests)
    return canonical.content_digest(_value("evaluation_input_set_identity", {"input_identity_digests": identities}))


def _create_slot(configuration: ArmConfigurationV3, input_digest: str) -> ExpectedObservationSlotV3:
    return ExpectedObservationSlotV3(
        _slot_id(configuration.arm_id, input_digest),
        configuration.arm_id,
        input_digest,
        configuration.execution_identity,
        "",
    )


def create_evaluation_plan_declaration(
    *,
    population_digest: str,
    freeze_digest: str,
    input_set_digest: str,
    arm_configurations: tuple[ArmConfigurationV3, ...],
    input_identity_digests: tuple[str, ...],
) -> EvaluationPlanDeclarationV3:
    """Canonicalize caller order and construct the declaration before baselines."""
    if type(arm_configurations) is not tuple or not arm_configurations:
        raise EvaluationPlanError("arm configurations must be a nonempty tuple")
    if any(type(row) is not ArmConfigurationV3 for row in arm_configurations):
        raise EvaluationPlanError("arm configurations must use exact ArmConfigurationV3 values")
    configurations = tuple(sorted(arm_configurations, key=lambda row: row.arm_id))
    inputs = _canonical_input_identities(input_identity_digests)
    if input_set_digest != derive_evaluation_input_set_digest(inputs):
        raise EvaluationPlanError("input set digest does not match the canonical input identities")
    slots = tuple(_create_slot(configuration, input_digest) for configuration in configurations for input_digest in inputs)
    return EvaluationPlanDeclarationV3(
        population_digest,
        freeze_digest,
        input_set_digest,
        configurations,
        slots,
        "",
    )


def derive_evaluation_baselines(
    declaration: EvaluationPlanDeclarationV3,
) -> tuple[EvaluationBaselineIdentityV3, ...]:
    """Derive one baseline per arm after validating the complete declaration."""
    require_exact_v3_contract(declaration, EvaluationPlanDeclarationV3, field="evaluation plan declaration")
    declaration.__post_init__()
    return tuple(
        EvaluationBaselineIdentityV3(
            configuration.arm_id,
            declaration.declaration_digest,
            declaration.population_digest,
            declaration.freeze_digest,
            declaration.input_set_digest,
            configuration.configuration_identity_digest,
            "",
        )
        for configuration in declaration.arm_configurations
    )


def validate_evaluation_baselines(declaration: EvaluationPlanDeclarationV3, baselines: tuple[EvaluationBaselineIdentityV3, ...]) -> None:
    """Require exact equality with the declaration-derived canonical baseline set."""
    if type(baselines) is not tuple or any(type(row) is not EvaluationBaselineIdentityV3 for row in baselines):
        raise EvaluationPlanError("baselines must be a tuple of exact EvaluationBaselineIdentityV3 values")
    for row in baselines:
        row.__post_init__()
    if baselines != derive_evaluation_baselines(declaration):
        raise EvaluationPlanError("baselines do not match the canonical declaration-derived set")


@dataclass(frozen=True, order=True)
class ExactScopeCensusV3(EvaluationV3Contract, NonAuthorizingV3):
    """Label-blind vulnerable/fixed and instrument capacity for one exact scope."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    scope: ScopeKey
    pair_count: int
    vulnerable_side_count: int
    fixed_side_count: int
    semantic_site_capacity: int
    model_call_capacity: int

    def __post_init__(self) -> None:
        from openultrasast.core._evaluation_plan_review import validate_exact_scope_census_shape

        require_exact_v3_contract(self, ExactScopeCensusV3, field="exact scope census")
        validate_exact_scope_census_shape(self)


@dataclass(frozen=True, order=True)
class EcosystemOrdinaryCensusV3(EvaluationV3Contract, NonAuthorizingV3):
    """Label-blind ordinary-push capacity for one reviewed ecosystem."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    ecosystem: str
    ordinary_push_count: int

    def __post_init__(self) -> None:
        from openultrasast.core._evaluation_plan_review import validate_ordinary_census_shape

        require_exact_v3_contract(self, EcosystemOrdinaryCensusV3, field="ecosystem ordinary census")
        validate_ordinary_census_shape(self)


@dataclass(frozen=True)
class PopulationCensusV3(EvaluationV3Contract, NonAuthorizingV3):
    """Independently reviewed, label-sealed capacities for one population."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    population_digest: str
    scope_rows: tuple[ExactScopeCensusV3, ...]
    ordinary_rows: tuple[EcosystemOrdinaryCensusV3, ...]
    whole_underlying_push_count: int
    labels_exposed: bool
    payload_digest: str
    review: IndependenceAttestation
    census_digest: str

    def __post_init__(self) -> None:
        from openultrasast.core._evaluation_plan_review import validate_population_census_shape

        require_exact_v3_contract(self, PopulationCensusV3, field="population census")
        validate_population_census_shape(self)


@dataclass(frozen=True)
class EvaluationPlanManifestV3(EvaluationV3Contract, NonAuthorizingV3):
    """Reviewed plan, baseline, census, readiness, and custody binding."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    declaration: EvaluationPlanDeclarationV3
    baselines: tuple[EvaluationBaselineIdentityV3, ...]
    census: PopulationCensusV3
    readiness_digests: tuple[str, ...]
    custody_log_digest: str
    payload_digest: str
    review: IndependenceAttestation
    manifest_digest: str

    def __post_init__(self) -> None:
        from openultrasast.core._evaluation_plan_review import validate_plan_manifest_shape

        require_exact_v3_contract(self, EvaluationPlanManifestV3, field="evaluation plan manifest")
        validate_plan_manifest_shape(self)


def derive_evaluation_census_payload_digest(census: PopulationCensusV3) -> str:
    from openultrasast.core._evaluation_plan_review import census_payload_digest

    _exact_plan_value(census, PopulationCensusV3, "population census")
    return census_payload_digest(census)


def derive_evaluation_census_digest(census: PopulationCensusV3) -> str:
    from openultrasast.core._evaluation_plan_review import census_digest

    _exact_plan_value(census, PopulationCensusV3, "population census")
    return census_digest(census)


def derive_evaluation_plan_manifest_payload_digest(manifest: EvaluationPlanManifestV3) -> str:
    from openultrasast.core._evaluation_plan_review import manifest_payload_digest

    _exact_plan_value(manifest, EvaluationPlanManifestV3, "evaluation plan manifest")
    return manifest_payload_digest(manifest)


def derive_evaluation_plan_manifest_digest(manifest: EvaluationPlanManifestV3) -> str:
    from openultrasast.core._evaluation_plan_review import manifest_digest

    _exact_plan_value(manifest, EvaluationPlanManifestV3, "evaluation plan manifest")
    return manifest_digest(manifest)


def validate_reviewed_evaluation_plan(
    census: PopulationCensusV3,
    manifest: EvaluationPlanManifestV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    from openultrasast.core._evaluation_plan_review import validate_reviewed_plan

    _exact_plan_value(census, PopulationCensusV3, "population census")
    _exact_plan_value(manifest, EvaluationPlanManifestV3, "evaluation plan manifest")
    validate_reviewed_plan(census, manifest, policy, resolver)


__all__ = [
    "EvaluationBaselineIdentityV3",
    "EvaluationPlanDeclarationV3",
    "EvaluationPlanError",
    "EvaluationPlanManifestV3",
    "EcosystemOrdinaryCensusV3",
    "ExactScopeCensusV3",
    "ExpectedObservationSlotV3",
    "PopulationCensusV3",
    "create_evaluation_plan_declaration",
    "derive_evaluation_baselines",
    "derive_evaluation_input_set_digest",
    "derive_evaluation_census_digest",
    "derive_evaluation_census_payload_digest",
    "derive_evaluation_plan_manifest_digest",
    "derive_evaluation_plan_manifest_payload_digest",
    "validate_evaluation_baselines",
    "validate_reviewed_evaluation_plan",
]
