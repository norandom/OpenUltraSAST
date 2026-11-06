"""Closed component and combined-arm identities used by V3 measurement."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import product

from openultrasast.core import canonical
from openultrasast.core._evaluation_measurement_contracts import (
    ArmScopeKey,
    DenominatorPolicyV3,
    EvaluationMeasurementError,
    MetricId,
    ScopedThresholdV3,
    ScopeKey,
    ScopeSufficiencyRuleV3,
    _bind_digest,
    _digest,
    _exact,
    _text,
    _value,
)
from openultrasast.core.evidence import NeutralOutcome


class ArmKindV3(Enum):
    COMPONENT = "component"
    COMBINED = "combined"


class CombinationOperatorV3(Enum):
    DECLARATIVE_TABLE = "declarative_table"


class ProofCandidatePolicyV3(Enum):
    IDENTICAL_COMPONENT_ONLY = "identical_component_only"


@dataclass(frozen=True)
class CombinationDecisionRowV3:
    component_outcomes: tuple[NeutralOutcome, ...]
    combined_outcome: NeutralOutcome
    row_digest: str

    def __post_init__(self) -> None:
        _exact(self, CombinationDecisionRowV3, "combination decision row")
        if (
            type(self.component_outcomes) is not tuple
            or not self.component_outcomes
            or any(type(item) is not NeutralOutcome for item in self.component_outcomes)
        ):
            raise EvaluationMeasurementError("component outcomes must be a nonempty tuple of NeutralOutcome values")
        if type(self.combined_outcome) is not NeutralOutcome:
            raise EvaluationMeasurementError("combined outcome must use NeutralOutcome")
        payload: canonical.JsonValue = {
            "component_outcomes": tuple(item.value for item in self.component_outcomes),
            "combined_outcome": self.combined_outcome.value,
        }
        _bind_digest(self, "row_digest", canonical.content_digest(_value("combination_decision_row", payload)))


@dataclass(frozen=True)
class CombinationRuleV3:
    combined_arm_id: str
    component_arm_ids: tuple[str, ...]
    operator: CombinationOperatorV3
    decision_rows: tuple[CombinationDecisionRowV3, ...]
    candidate_policy: ProofCandidatePolicyV3
    rule_digest: str

    def __post_init__(self) -> None:
        _exact(self, CombinationRuleV3, "combination rule")
        _text(self.combined_arm_id, "combined_arm_id")
        if (
            type(self.component_arm_ids) is not tuple
            or len(self.component_arm_ids) < 2
            or any(type(item) is not str or not item for item in self.component_arm_ids)
        ):
            raise EvaluationMeasurementError("component arm ids must contain at least two exact identities")
        canonical_ids = tuple(sorted(set(self.component_arm_ids)))
        if self.component_arm_ids != canonical_ids or self.combined_arm_id in self.component_arm_ids:
            raise EvaluationMeasurementError("component arm ids must be unique and in canonical order")
        if (
            self.operator is not CombinationOperatorV3.DECLARATIVE_TABLE
            or self.candidate_policy is not ProofCandidatePolicyV3.IDENTICAL_COMPONENT_ONLY
        ):
            raise EvaluationMeasurementError("combination rule must use the closed operator and candidate policy")
        expected_outcomes = tuple(product(tuple(NeutralOutcome), repeat=len(self.component_arm_ids)))
        if (
            type(self.decision_rows) is not tuple
            or len(self.decision_rows) != len(expected_outcomes)
            or any(type(row) is not CombinationDecisionRowV3 for row in self.decision_rows)
        ):
            raise EvaluationMeasurementError("combination rule requires one canonical row for every component outcome")
        if tuple(row.component_outcomes for row in self.decision_rows) != expected_outcomes:
            raise EvaluationMeasurementError("combination decision rows must use canonical complete order")
        for row in self.decision_rows:
            row.__post_init__()
        payload: canonical.JsonValue = {
            "combined_arm_id": self.combined_arm_id,
            "component_arm_ids": self.component_arm_ids,
            "operator": self.operator.value,
            "row_digests": tuple(row.row_digest for row in self.decision_rows),
            "candidate_policy": self.candidate_policy.value,
        }
        _bind_digest(self, "rule_digest", canonical.content_digest(_value("combination_rule", payload)))


def _validate_scopes(scopes: object) -> tuple[ScopeKey, ...]:
    if type(scopes) is not tuple or not scopes or any(type(scope) is not ScopeKey for scope in scopes):
        raise EvaluationMeasurementError("exact scopes must be a nonempty tuple of exact ScopeKey values")
    if scopes != tuple(sorted(scopes)) or len(set(scopes)) != len(scopes):
        raise EvaluationMeasurementError("exact scopes must be unique canonical exact scopes")
    for scope in scopes:
        scope.__post_init__()
    return scopes


@dataclass(frozen=True)
class ArmConfigurationV3:
    arm_id: str
    kind: ArmKindV3
    exact_scopes: tuple[ScopeKey, ...]
    denominator_policies: tuple[DenominatorPolicyV3, ...]
    thresholds: tuple[ScopedThresholdV3, ...]
    sufficiency_rules: tuple[ScopeSufficiencyRuleV3, ...]
    judgment_vocabulary_digest: str
    analyzer_identity: str
    fact_set_digest: str
    configuration_digest: str
    registered_budget_digest: str
    execution_identity: str
    outcome_mapping_digest: str
    combination_rule: CombinationRuleV3 | None
    configuration_identity_digest: str

    def __post_init__(self) -> None:
        _exact(self, ArmConfigurationV3, "arm configuration")
        _text(self.arm_id, "arm_id")
        if type(self.kind) is not ArmKindV3:
            raise EvaluationMeasurementError("arm kind must use the closed ArmKindV3 enum")
        expected_keys = tuple(ArmScopeKey(self.arm_id, scope) for scope in _validate_scopes(self.exact_scopes))
        if type(self.denominator_policies) is not tuple:
            raise EvaluationMeasurementError("denominator policies must be a canonical tuple")
        actual_policy_keys = tuple(policy.key for policy in self.denominator_policies if type(policy) is DenominatorPolicyV3)
        if actual_policy_keys != expected_keys:
            raise EvaluationMeasurementError("denominator policies must occur once per canonical arm-scope key")
        for policy in self.denominator_policies:
            policy.__post_init__()
        self._validate_thresholds(expected_keys)
        if type(self.sufficiency_rules) is not tuple:
            raise EvaluationMeasurementError("sufficiency rules must be a canonical tuple")
        actual_sufficiency_keys = tuple(row.key for row in self.sufficiency_rules if type(row) is ScopeSufficiencyRuleV3)
        if actual_sufficiency_keys != expected_keys:
            raise EvaluationMeasurementError("sufficiency rules must occur once per canonical arm-scope key")
        for threshold in self.thresholds:
            threshold.__post_init__()
        for rule in self.sufficiency_rules:
            rule.__post_init__()
        self._validate_identities()
        self._validate_combination()
        _bind_digest(self, "configuration_identity_digest", derive_arm_configuration_identity_digest(self))

    def _validate_thresholds(self, expected_keys: tuple[ArmScopeKey, ...]) -> None:
        if type(self.thresholds) is not tuple:
            raise EvaluationMeasurementError("thresholds must be a canonical tuple")
        expected = tuple((key, metric_id) for key in expected_keys for metric_id in MetricId)
        actual = tuple((row.key, row.metric_id) for row in self.thresholds if type(row) is ScopedThresholdV3)
        if actual == expected:
            return
        if len(self.thresholds) != len(expected):
            raise EvaluationMeasurementError("each scoped threshold metric must occur exactly once")
        if len(actual) == len(self.thresholds) and actual == tuple(sorted(actual, key=lambda row: (row[0], list(MetricId).index(row[1])))):
            raise EvaluationMeasurementError("threshold arm-scope key does not match its configuration")
        raise EvaluationMeasurementError("thresholds must use canonical order")

    def _validate_identities(self) -> None:
        for item, field in (
            (self.judgment_vocabulary_digest, "judgment vocabulary digest"),
            (self.fact_set_digest, "fact set digest"),
            (self.configuration_digest, "configuration digest"),
            (self.registered_budget_digest, "registered budget digest"),
            (self.outcome_mapping_digest, "outcome mapping digest"),
        ):
            _digest(item, field)
        _text(self.analyzer_identity, "analyzer identity")
        _text(self.execution_identity, "execution identity")

    def _validate_combination(self) -> None:
        if self.kind is ArmKindV3.COMPONENT and self.combination_rule is not None:
            raise EvaluationMeasurementError("component arm must not carry a combination rule")
        if self.kind is ArmKindV3.COMBINED:
            if type(self.combination_rule) is not CombinationRuleV3:
                raise EvaluationMeasurementError("combined arm requires a combination rule")
            self.combination_rule.__post_init__()
            if self.combination_rule.combined_arm_id != self.arm_id:
                raise EvaluationMeasurementError("combination rule arm does not match configuration")


def derive_arm_configuration_identity_digest(value: ArmConfigurationV3) -> str:
    _exact(value, ArmConfigurationV3, "arm configuration")
    payload = {
        "arm_id": value.arm_id,
        "kind": value.kind.value,
        "exact_scopes": tuple({"family_id": scope.family_id, "ecosystem": scope.ecosystem} for scope in value.exact_scopes),
        "policy_digests": tuple(row.policy_digest for row in value.denominator_policies),
        "threshold_digests": tuple(row.threshold_digest for row in value.thresholds),
        "sufficiency_digests": tuple(row.rule_digest for row in value.sufficiency_rules),
        "judgment_vocabulary_digest": value.judgment_vocabulary_digest,
        "analyzer_identity": value.analyzer_identity,
        "fact_set_digest": value.fact_set_digest,
        "configuration_digest": value.configuration_digest,
        "registered_budget_digest": value.registered_budget_digest,
        "execution_identity": value.execution_identity,
        "outcome_mapping_digest": value.outcome_mapping_digest,
        "combination_rule_digest": None if value.combination_rule is None else value.combination_rule.rule_digest,
    }
    return canonical.content_digest(_value("arm_configuration", payload))


__all__ = [
    "ArmConfigurationV3",
    "ArmKindV3",
    "CombinationDecisionRowV3",
    "CombinationOperatorV3",
    "CombinationRuleV3",
    "ProofCandidatePolicyV3",
    "derive_arm_configuration_identity_digest",
]
