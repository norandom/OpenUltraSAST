"""Immutable contracts for deterministic benchmark arm combination."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from itertools import product

from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_measurement import ArmConfigurationV3, ArmKindV3, CombinationRuleV3, NeutralOutcome
from openultrasast.core.evaluation_observation import ArmObservationSetV3
from openultrasast.core.evaluation_release import ProofCandidateIdentityV3, derive_proof_candidate_identity_digest

COMBINATION_REGISTRATION_SCHEMA = "openultrasast.valid-detection-benchmark.combination-registration.v1"
COMBINATION_PLAN_SCHEMA = "openultrasast.valid-detection-benchmark.combination-plan.v1"
PROOF_CONTINUITY_SCHEMA = "openultrasast.valid-detection-benchmark.proof-continuity-anchor.v1"
COMPONENT_OBSERVATION_SCHEMA = "openultrasast.valid-detection-benchmark.component-observation.v1"
COMBINED_OBSERVATION_SCHEMA = "openultrasast.valid-detection-benchmark.combined-observation.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class CombinationPlannerError(ValueError):
    """A combination is incomplete, unregistered, or proof-unsafe."""


class CombinationRuleKindV1(StrEnum):
    """The only benchmark-owned combination semantics."""

    UNION = "union"
    INTERSECTION = "intersection"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise CombinationPlannerError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _bind(value: object, field: str, payload: JsonValue) -> None:
    expected = canonical.content_digest(payload)
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise CombinationPlannerError(f"{field} does not match canonical content")


def _ref_value(reference: canonical.ContentRef) -> JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _candidate_value(candidate: ProofCandidateIdentityV3) -> JsonValue:
    return {
        "component_arm_id": candidate.component_arm_id,
        "observation_digest": candidate.observation_digest,
        "family_id": candidate.family_id,
        "scope": {"family_id": candidate.scope.family_id, "ecosystem": candidate.scope.ecosystem},
        "finding_location_digest": candidate.finding_location_digest,
        "change_input_digest": candidate.change_input_digest,
        "candidate_digest": candidate.candidate_digest,
    }


@dataclass(frozen=True)
class ProofContinuityAnchorV1:
    """Non-authorizing identity needed to preserve, never create, proof continuity."""

    candidate: ProofCandidateIdentityV3
    packet_digest: str
    proof_reference: canonical.ContentRef
    anchor_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ProofContinuityAnchorV1 or type(self.candidate) is not ProofCandidateIdentityV3:
            raise CombinationPlannerError("proof anchor must use exact continuity contracts")
        self.candidate.__post_init__()
        if self.candidate.candidate_digest != derive_proof_candidate_identity_digest(self.candidate):
            raise CombinationPlannerError("proof candidate identity cannot be re-derived")
        _digest(self.packet_digest, "proof packet digest")
        if type(self.proof_reference) is not canonical.ContentRef:
            raise CombinationPlannerError("proof reference must use exact ContentRef")
        self.proof_reference.__post_init__()
        payload: JsonValue = {
            "schema_version": PROOF_CONTINUITY_SCHEMA,
            "candidate": _candidate_value(self.candidate),
            "packet_digest": self.packet_digest,
            "proof_reference": _ref_value(self.proof_reference),
        }
        _bind(self, "anchor_digest", payload)


@dataclass(frozen=True)
class ComponentObservationV1:
    """One exact component observation and its non-authorizing proof anchors."""

    observation: ArmObservationSetV3
    proof_anchors: tuple[ProofContinuityAnchorV1, ...]
    component_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ComponentObservationV1 or type(self.observation) is not ArmObservationSetV3:
            raise CombinationPlannerError("component must use exact observation contracts")
        self.observation.__post_init__()
        if type(self.proof_anchors) is not tuple or any(type(item) is not ProofContinuityAnchorV1 for item in self.proof_anchors):
            raise CombinationPlannerError("proof anchors must be an exact tuple")
        for anchor in self.proof_anchors:
            anchor.__post_init__()
        if self.proof_anchors != tuple(sorted(self.proof_anchors, key=lambda item: item.anchor_digest)):
            raise CombinationPlannerError("proof anchors must use canonical order")
        if len({item.candidate.candidate_digest for item in self.proof_anchors}) != len(self.proof_anchors):
            raise CombinationPlannerError("proof anchors must identify unique candidates")
        candidates = {case.proof_candidate_digest for case in self.observation.cases if case.proof_candidate_digest}
        for anchor in self.proof_anchors:
            candidate = anchor.candidate
            if (
                candidate.component_arm_id != self.observation.arm_id
                or candidate.observation_digest != self.observation.observation_digest
                or candidate.candidate_digest not in candidates
            ):
                raise CombinationPlannerError("proof anchor differs from its component observation")
        payload: JsonValue = {
            "schema_version": COMPONENT_OBSERVATION_SCHEMA,
            "observation_digest": self.observation.observation_digest,
            "proof_anchor_digests": tuple(item.anchor_digest for item in self.proof_anchors),
        }
        _bind(self, "component_digest", payload)


@dataclass(frozen=True)
class CombinationRuleRegistrationV1:
    combined_arm_id: str
    kind: CombinationRuleKindV1
    core_rule_digest: str
    registration_digest: str

    def __post_init__(self) -> None:
        if type(self) is not CombinationRuleRegistrationV1 or type(self.combined_arm_id) is not str or not self.combined_arm_id:
            raise CombinationPlannerError("combination registration must use exact nonempty identities")
        if type(self.kind) is not CombinationRuleKindV1:
            raise CombinationPlannerError("combination kind must use the closed enum")
        _digest(self.core_rule_digest, "core combination rule digest")
        payload: JsonValue = {
            "schema_version": COMBINATION_REGISTRATION_SCHEMA,
            "combined_arm_id": self.combined_arm_id,
            "kind": self.kind.value,
            "core_rule_digest": self.core_rule_digest,
        }
        _bind(self, "registration_digest", payload)


def _expected_outcome(kind: CombinationRuleKindV1, outcomes: tuple[NeutralOutcome, ...]) -> NeutralOutcome:
    if kind is CombinationRuleKindV1.UNION:
        if NeutralOutcome.VIOLATION in outcomes:
            return NeutralOutcome.VIOLATION
        if NeutralOutcome.INDETERMINATE in outcomes:
            return NeutralOutcome.INDETERMINATE
        return NeutralOutcome.SATISFIED
    if all(item is NeutralOutcome.VIOLATION for item in outcomes):
        return NeutralOutcome.VIOLATION
    if NeutralOutcome.SATISFIED in outcomes:
        return NeutralOutcome.SATISFIED
    return NeutralOutcome.INDETERMINATE


def _validate_rule_semantics(rule: CombinationRuleV3, kind: CombinationRuleKindV1) -> None:
    rule.__post_init__()
    outcomes = tuple(product(tuple(NeutralOutcome), repeat=len(rule.component_arm_ids)))
    expected = tuple((row, _expected_outcome(kind, row)) for row in outcomes)
    actual = tuple((row.component_outcomes, row.combined_outcome) for row in rule.decision_rows)
    if actual != expected:
        raise CombinationPlannerError("core decision table differs from the registered closed combination rule")


def _combined_configurations(plan: RegisteredEvaluationPlanV1) -> tuple[ArmConfigurationV3, ...]:
    return tuple(row for row in plan.declaration.arm_configurations if row.kind is ArmKindV3.COMBINED)


def _validate_component_scope_coverage(
    plan: RegisteredEvaluationPlanV1,
    combined: ArmConfigurationV3,
    rule: CombinationRuleV3,
) -> None:
    configurations = {item.arm_id: item for item in plan.declaration.arm_configurations}
    for component_arm_id in rule.component_arm_ids:
        component = configurations.get(component_arm_id)
        if type(component) is not ArmConfigurationV3 or component.kind is not ArmKindV3.COMPONENT:
            raise CombinationPlannerError("combination rule must identify exact registered component arms")
        if not set(combined.exact_scopes).issubset(component.exact_scopes):
            raise CombinationPlannerError("every component arm must cover every exact combined-arm scope")


def _validate_registered_rules(
    plan: RegisteredEvaluationPlanV1,
    registrations: tuple[CombinationRuleRegistrationV1, ...],
) -> None:
    combined = _combined_configurations(plan)
    if tuple(item.arm_id for item in combined) != tuple(item.combined_arm_id for item in registrations):
        raise CombinationPlannerError("rule registrations must cover every and only combined arm")
    for configuration, registration in zip(combined, registrations, strict=True):
        rule = configuration.combination_rule
        if type(rule) is not CombinationRuleV3 or rule.rule_digest != registration.core_rule_digest:
            raise CombinationPlannerError("registered rule differs from the core plan")
        _validate_rule_semantics(rule, registration.kind)
        _validate_component_scope_coverage(plan, configuration, rule)


@dataclass(frozen=True)
class RegisteredCombinationPlanV1:
    plan: RegisteredEvaluationPlanV1
    rule_registrations: tuple[CombinationRuleRegistrationV1, ...]
    combination_plan_digest: str

    def __post_init__(self) -> None:
        if type(self) is not RegisteredCombinationPlanV1 or type(self.plan) is not RegisteredEvaluationPlanV1:
            raise CombinationPlannerError("combination plan must use exact registry contracts")
        self.plan.__post_init__()
        if type(self.rule_registrations) is not tuple or any(
            type(item) is not CombinationRuleRegistrationV1 for item in self.rule_registrations
        ):
            raise CombinationPlannerError("rule registrations must be an exact tuple")
        for item in self.rule_registrations:
            item.__post_init__()
        if self.rule_registrations != tuple(sorted(self.rule_registrations, key=lambda item: item.combined_arm_id)):
            raise CombinationPlannerError("rule registrations must use canonical arm order")
        _validate_registered_rules(self.plan, self.rule_registrations)
        payload: JsonValue = {
            "schema_version": COMBINATION_PLAN_SCHEMA,
            "plan_digest": self.plan.plan_digest,
            "rule_registration_digests": tuple(item.registration_digest for item in self.rule_registrations),
        }
        _bind(self, "combination_plan_digest", payload)


def combined_value(value: CombinedObservationV1, *, include_digest: bool) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "schema_version": COMBINED_OBSERVATION_SCHEMA,
        "combination_plan_digest": value.registered_plan.combination_plan_digest,
        "rule_registration_digest": value.rule_registration.registration_digest,
        "component_digests": tuple(item.component_digest for item in value.component_observations),
        "combined_observation_digest": value.combined_observation.observation_digest,
        "retained_anchor_digests": tuple(item.anchor_digest for item in value.retained_proof_anchors),
    }
    if include_digest:
        payload["combination_digest"] = value.combination_digest
    return payload


@dataclass(frozen=True)
class CombinedObservationV1:
    """Preserved components plus one separately derived combined observation."""

    registered_plan: RegisteredCombinationPlanV1
    rule_registration: CombinationRuleRegistrationV1
    component_observations: tuple[ComponentObservationV1, ...]
    combined_observation: ArmObservationSetV3
    retained_proof_anchors: tuple[ProofContinuityAnchorV1, ...]
    combination_digest: str

    def __post_init__(self) -> None:
        if type(self) is not CombinedObservationV1 or type(self.registered_plan) is not RegisteredCombinationPlanV1:
            raise CombinationPlannerError("combined observation must use exact planner contracts")
        self.registered_plan.__post_init__()
        if type(self.rule_registration) is not CombinationRuleRegistrationV1:
            raise CombinationPlannerError("combined observation has no exact rule registration")
        self.rule_registration.__post_init__()
        if type(self.component_observations) is not tuple or any(
            type(item) is not ComponentObservationV1 for item in self.component_observations
        ):
            raise CombinationPlannerError("combined components must use exact observation wrappers")
        for component in self.component_observations:
            component.__post_init__()
        if type(self.combined_observation) is not ArmObservationSetV3:
            raise CombinationPlannerError("combined result must use exact ArmObservationSetV3")
        self.combined_observation.__post_init__()
        if type(self.retained_proof_anchors) is not tuple or any(
            type(item) is not ProofContinuityAnchorV1 for item in self.retained_proof_anchors
        ):
            raise CombinationPlannerError("retained proof anchors must be an exact tuple")
        for anchor in self.retained_proof_anchors:
            anchor.__post_init__()
        _bind(self, "combination_digest", combined_value(self, include_digest=False))
