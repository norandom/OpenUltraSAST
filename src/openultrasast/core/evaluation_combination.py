"""Deterministic per-case combination replay for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionPolicyV3,
    CaseOutcomeProjectionV3,
)
from openultrasast.core.evaluation_measurement import (
    ArmConfigurationV3,
    ArmKindV3,
    ArmScopeKey,
    CombinationDecisionRowV3,
    CombinationRuleV3,
    ScopeKey,
)
from openultrasast.core.evaluation_plan import EvaluationPlanDeclarationV3
from openultrasast.core.evaluation_release import ReleasedArmCaseBindingV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.evidence import NeutralOutcome

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "openultrasast.detection-core.evaluation-combination.v3"


class CombinationValidationError(ValueError):
    """A combined-arm case set or lineage is incomplete or contradictory."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise CombinationValidationError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise CombinationValidationError(f"{field} must be nonempty exact text")
    return value


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _SCHEMA, "kind": kind, "payload": payload}


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise CombinationValidationError(f"{field} does not match canonical content")


def _scope_value(scope: ScopeKey) -> canonical.JsonValue:
    return {"family_id": scope.family_id, "ecosystem": scope.ecosystem}


def _component_value(value: ComponentCaseOutcomeV3) -> dict[str, canonical.JsonValue]:
    return {
        "component_arm_id": value.component_arm_id,
        "scope": _scope_value(value.scope),
        "case_input_digest": value.case_input_digest,
        "case_id_digest": value.case_id_digest,
        "observation_digest": value.observation_digest,
        "outcome_projection_digest": value.outcome_projection_digest,
        "normalized_outcome": value.normalized_outcome.value,
        "proof_candidate_digest": value.proof_candidate_digest,
    }


@dataclass(frozen=True)
class ComponentCaseOutcomeV3(EvaluationV3Contract, NonAuthorizingV3):
    """One exact released component case contributing to a combined case."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    component_arm_id: str
    scope: ScopeKey
    case_input_digest: str
    case_id_digest: str
    observation_digest: str
    outcome_projection_digest: str
    normalized_outcome: NeutralOutcome
    proof_candidate_digest: str | None
    component_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ComponentCaseOutcomeV3, field="component case outcome")
        _text(self.component_arm_id, "component arm identity")
        if type(self.scope) is not ScopeKey:
            raise CombinationValidationError("component scope must use exact ScopeKey")
        self.scope.__post_init__()
        for field in (
            "case_input_digest",
            "case_id_digest",
            "observation_digest",
            "outcome_projection_digest",
        ):
            _digest(getattr(self, field), field)
        if type(self.normalized_outcome) is not NeutralOutcome:
            raise CombinationValidationError("component normalized outcome must use exact NeutralOutcome")
        if self.proof_candidate_digest is not None:
            _digest(self.proof_candidate_digest, "component proof candidate digest")
        _bind(self, "component_digest", canonical.content_digest(_value("component_case_outcome", _component_value(self))))


def _combined_value(value: CombinedCaseOutcomeV3) -> dict[str, canonical.JsonValue]:
    return {
        "key": {"arm_id": value.key.arm_id, "scope": _scope_value(value.key.scope)},
        "case_id_digest": value.case_id_digest,
        "case_input_digest": value.case_input_digest,
        "observation_digest": value.observation_digest,
        "component_digests": tuple(item.component_digest for item in value.components),
        "decision_row_digest": value.decision_row_digest,
        "normalized_outcome": value.normalized_outcome.value,
        "retained_proof_candidate_digest": value.retained_proof_candidate_digest,
        "combined_projection_digest": value.combined_projection_digest,
    }


@dataclass(frozen=True)
class CombinedCaseOutcomeV3(EvaluationV3Contract, NonAuthorizingV3):
    """One table-replayed combined case with every component retained independently."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    key: ArmScopeKey
    case_id_digest: str
    case_input_digest: str
    observation_digest: str
    components: tuple[ComponentCaseOutcomeV3, ...]
    decision_row_digest: str
    normalized_outcome: NeutralOutcome
    retained_proof_candidate_digest: str | None
    combined_projection_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, CombinedCaseOutcomeV3, field="combined case outcome")
        if type(self.key) is not ArmScopeKey:
            raise CombinationValidationError("combined key must use exact ArmScopeKey")
        self.key.__post_init__()
        for field in (
            "case_id_digest",
            "case_input_digest",
            "observation_digest",
            "decision_row_digest",
            "combined_projection_digest",
        ):
            _digest(getattr(self, field), field)
        if (
            type(self.components) is not tuple
            or not self.components
            or any(type(item) is not ComponentCaseOutcomeV3 for item in self.components)
        ):
            raise CombinationValidationError("combined components must be a nonempty exact tuple")
        for item in self.components:
            item.__post_init__()
        arm_ids = tuple(item.component_arm_id for item in self.components)
        if arm_ids != tuple(sorted(set(arm_ids))):
            raise CombinationValidationError("combined components must use unique canonical arm order")
        if any(item.scope != self.key.scope or item.case_input_digest != self.case_input_digest for item in self.components):
            raise CombinationValidationError("combined components must share the exact scope and case input")
        if self.key.arm_id in arm_ids:
            raise CombinationValidationError("combined arm cannot contribute as its own component")
        if type(self.normalized_outcome) is not NeutralOutcome:
            raise CombinationValidationError("combined normalized outcome must use exact NeutralOutcome")
        if self.retained_proof_candidate_digest is not None:
            _digest(self.retained_proof_candidate_digest, "retained proof candidate digest")


def _component_observations(rule: CombinationRuleV3, cases: tuple[CombinedCaseOutcomeV3, ...]) -> tuple[str, ...]:
    return tuple(
        digest
        for arm_id in rule.component_arm_ids
        for digest in sorted(
            {component.observation_digest for case in cases for component in case.components if component.component_arm_id == arm_id}
        )
    )


def _lineage_payload(value: CombinationLineageV3) -> canonical.JsonValue:
    return {
        "rule_digest": value.rule.rule_digest,
        "component_observation_digests": value.component_observation_digests,
        "combined_cases": tuple(_combined_value(item) for item in value.combined_cases),
    }


@dataclass(frozen=True)
class CombinationLineageV3(EvaluationV3Contract, NonAuthorizingV3):
    """All per-case table replay for one reviewed combined-arm rule."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    rule: CombinationRuleV3
    component_observation_digests: tuple[str, ...]
    combined_cases: tuple[CombinedCaseOutcomeV3, ...]
    lineage_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, CombinationLineageV3, field="combination lineage")
        if type(self.rule) is not CombinationRuleV3:
            raise CombinationValidationError("lineage rule must use exact CombinationRuleV3")
        self.rule.__post_init__()
        if (
            type(self.combined_cases) is not tuple
            or not self.combined_cases
            or any(type(item) is not CombinedCaseOutcomeV3 for item in self.combined_cases)
        ):
            raise CombinationValidationError("lineage combined cases must be a nonempty exact tuple")
        for item in self.combined_cases:
            item.__post_init__()
            if item.key.arm_id != self.rule.combined_arm_id:
                raise CombinationValidationError("lineage combined case belongs to another arm")
            if tuple(component.component_arm_id for component in item.components) != self.rule.component_arm_ids:
                raise CombinationValidationError("lineage components differ from the registered rule")
            decision = _decision_row(self.rule, item.components)
            if (item.decision_row_digest, item.normalized_outcome) != (decision.row_digest, decision.combined_outcome):
                raise CombinationValidationError("lineage combined outcome differs from deterministic table replay")
            projection = CaseOutcomeProjectionV3(
                item.case_input_digest,
                CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
                tuple(component.outcome_projection_digest for component in item.components),
                decision.combined_outcome,
                "",
            )
            if item.combined_projection_digest != projection.projection_digest:
                raise CombinationValidationError("lineage combined projection differs from deterministic table replay")
        order = tuple(
            sorted(
                self.combined_cases,
                key=lambda item: (item.key.scope.family_id, item.key.scope.ecosystem, item.case_input_digest),
            )
        )
        keys = tuple((item.key.scope, item.case_input_digest) for item in self.combined_cases)
        if self.combined_cases != order or len(set(keys)) != len(keys):
            raise CombinationValidationError("lineage combined cases must be unique and canonical")
        expected_observations = _component_observations(self.rule, self.combined_cases)
        if type(self.component_observation_digests) is not tuple or self.component_observation_digests != expected_observations:
            raise CombinationValidationError("lineage component observation set is incomplete or non-canonical")
        if len(set(self.component_observation_digests)) != len(self.component_observation_digests):
            raise CombinationValidationError("lineage component observations must be unique across arms")
        for digest in self.component_observation_digests:
            _digest(digest, "component observation digest")
        _bind(self, "lineage_digest", canonical.content_digest(_value("combination_lineage", _lineage_payload(self))))


def _validate_inputs(
    declaration: object, bindings: object
) -> tuple[EvaluationPlanDeclarationV3, tuple[ReleasedArmCaseBindingV3, ...], dict[str, ArmConfigurationV3]]:
    if type(declaration) is not EvaluationPlanDeclarationV3:
        raise CombinationValidationError("combination declaration must use exact EvaluationPlanDeclarationV3")
    declaration.__post_init__()
    if type(bindings) is not tuple or not bindings or any(type(item) is not ReleasedArmCaseBindingV3 for item in bindings):
        raise CombinationValidationError("combination bindings must be a nonempty exact tuple")
    rows = bindings
    for item in rows:
        item.__post_init__()
    order = tuple(sorted(rows, key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest)))
    if rows != order:
        raise CombinationValidationError("combination bindings must use canonical release order")
    configurations = {item.arm_id: item for item in declaration.arm_configurations}
    if {item.key.arm_id for item in rows} != set(configurations):
        raise CombinationValidationError("combination bindings must cover every and only planned arm")
    for item in rows:
        configuration = configurations[item.key.arm_id]
        if item.key.scope not in configuration.exact_scopes:
            raise CombinationValidationError("combination binding scope is not claimed by its planned arm")
        if item.outcome_projection.policy is not configuration.case_outcome_policy:
            raise CombinationValidationError("combination binding projection policy differs from the planned arm")
    return declaration, rows, configurations


def _case_map(
    rows: tuple[ReleasedArmCaseBindingV3, ...], arm_id: str, scopes: set[ScopeKey]
) -> dict[tuple[ScopeKey, str], ReleasedArmCaseBindingV3]:
    selected = tuple(item for item in rows if item.key.arm_id == arm_id and item.key.scope in scopes)
    result = {(item.key.scope, item.case_input_digest): item for item in selected}
    if len(result) != len(selected):
        raise CombinationValidationError("combination arm-scope case inputs must be unique")
    return result


def _component_case(binding: ReleasedArmCaseBindingV3) -> ComponentCaseOutcomeV3:
    return ComponentCaseOutcomeV3(
        binding.key.arm_id,
        binding.key.scope,
        binding.case_input_digest,
        binding.case_id_digest,
        binding.observation_digest,
        binding.outcome_projection.projection_digest,
        binding.outcome_projection.normalized_outcome,
        binding.proof_candidate_digest,
        "",
    )


def _decision_row(rule: CombinationRuleV3, components: tuple[ComponentCaseOutcomeV3, ...]) -> CombinationDecisionRowV3:
    outcomes = tuple(item.normalized_outcome for item in components)
    matches = tuple(item for item in rule.decision_rows if item.component_outcomes == outcomes)
    if len(matches) != 1:
        raise CombinationValidationError("registered combination decision row is absent or ambiguous")
    return matches[0]


def _derive_lineage(
    configuration: ArmConfigurationV3,
    rows: tuple[ReleasedArmCaseBindingV3, ...],
) -> CombinationLineageV3:
    rule = configuration.combination_rule
    if configuration.kind is not ArmKindV3.COMBINED or type(rule) is not CombinationRuleV3:
        raise CombinationValidationError("combination lineage requires an exact combined-arm rule")
    scopes = set(configuration.exact_scopes)
    component_maps = tuple(_case_map(rows, arm_id, scopes) for arm_id in rule.component_arm_ids)
    combined_map = _case_map(rows, configuration.arm_id, scopes)
    expected_keys = set(component_maps[0])
    if not expected_keys or any(set(item) != expected_keys for item in component_maps[1:]) or set(combined_map) != expected_keys:
        raise CombinationValidationError("component and combined case sets must be identical and complete")
    if {scope for scope, _ in expected_keys} != scopes:
        raise CombinationValidationError("combination case set must cover every exact combined scope")
    combined_cases = []
    for key in sorted(expected_keys):
        component_bindings = tuple(item[key] for item in component_maps)
        components = tuple(_component_case(item) for item in component_bindings)
        decision = _decision_row(rule, components)
        combined_binding = combined_map[key]
        derived_projection = CaseOutcomeProjectionV3(
            combined_binding.case_input_digest,
            CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
            tuple(item.outcome_projection.projection_digest for item in component_bindings),
            decision.combined_outcome,
            "",
        )
        if combined_binding.outcome_projection != derived_projection:
            raise CombinationValidationError("combined case projection differs from deterministic table replay")
        combined_cases.append(
            CombinedCaseOutcomeV3(
                combined_binding.key,
                combined_binding.case_id_digest,
                combined_binding.case_input_digest,
                combined_binding.observation_digest,
                components,
                decision.row_digest,
                decision.combined_outcome,
                combined_binding.proof_candidate_digest,
                derived_projection.projection_digest,
            )
        )
    cases = tuple(combined_cases)
    return CombinationLineageV3(rule, _component_observations(rule, cases), cases, "")


def derive_combination_lineages_v3(
    declaration: EvaluationPlanDeclarationV3,
    bindings: tuple[ReleasedArmCaseBindingV3, ...],
) -> tuple[CombinationLineageV3, ...]:
    """Replay all combined arms from canonical bindings returned by case validation."""

    try:
        _, rows, configurations = _validate_inputs(declaration, bindings)
        lineages = tuple(
            _derive_lineage(configuration, rows)
            for configuration in declaration.arm_configurations
            if configuration.kind is ArmKindV3.COMBINED
        )
        if not lineages:
            raise CombinationValidationError("combination plan must contain at least one combined arm")
        return lineages
    except CombinationValidationError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise CombinationValidationError(f"combination replay refused: {exc}") from exc


__all__ = [
    "CombinedCaseOutcomeV3",
    "CombinationLineageV3",
    "CombinationValidationError",
    "ComponentCaseOutcomeV3",
    "derive_combination_lineages_v3",
]
