"""Canonical reversed-surface probes for fitted-component shortcut resistance."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace

from openultrasast.core import canonical
from openultrasast.core.evidence import EvidenceRecord
from openultrasast.core.factpack import IndependenceAttestation, ReviewIndependencePolicy
from openultrasast.core.family import FamilyContract, family_contract_digest, validate_record
from openultrasast.core.semantics import FieldValue, RelationKind, RelationStatus

_DIGEST = re.compile(r"[0-9a-f]{64}")


class ProbeValidationError(ValueError):
    """A probe input or claimed result cannot be reproduced."""


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProbeValidationError(f"{field} must be a full lowercase SHA-256 digest")


def _text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ProbeValidationError(f"{field} must be nonempty text")


def _field_value(field: FieldValue) -> canonical.JsonValue:
    return {"name": field.name, "kind": field.kind.value, "value": field.value}


@dataclass(frozen=True)
class RoleProjection:
    role: str
    fields: tuple[FieldValue, ...]
    relation_kinds: tuple[RelationKind, ...]
    statuses: tuple[RelationStatus, ...]

    def __post_init__(self) -> None:
        _text(self.role, "projection role")
        if not isinstance(self.fields, tuple) or not all(isinstance(item, FieldValue) for item in self.fields):
            raise ProbeValidationError("projection fields must be FieldValue values")
        if not isinstance(self.relation_kinds, tuple) or not all(isinstance(item, RelationKind) for item in self.relation_kinds):
            raise ProbeValidationError("projection relation kinds are invalid")
        if not isinstance(self.statuses, tuple) or not all(isinstance(item, RelationStatus) for item in self.statuses):
            raise ProbeValidationError("projection statuses are invalid")


@dataclass(frozen=True)
class SemanticProjection:
    family_contract_digest: str
    security_object_fields: tuple[FieldValue, ...]
    roles: tuple[RoleProjection, ...]
    completeness_reasons: tuple[str, ...]
    family_decision: str
    projection_digest: str

    def __post_init__(self) -> None:
        _digest(self.family_contract_digest, "projection family contract")
        _text(self.family_decision, "projection family decision")
        if not isinstance(self.security_object_fields, tuple) or not all(
            isinstance(item, FieldValue) for item in self.security_object_fields
        ):
            raise ProbeValidationError("projection security-object fields are invalid")
        if not isinstance(self.roles, tuple) or not all(isinstance(item, RoleProjection) for item in self.roles):
            raise ProbeValidationError("projection roles are invalid")
        if not isinstance(self.completeness_reasons, tuple) or not all(
            isinstance(item, str) and item for item in self.completeness_reasons
        ):
            raise ProbeValidationError("projection completeness reasons are invalid")
        expected = _projection_digest(self)
        if not self.projection_digest:
            object.__setattr__(self, "projection_digest", expected)
        elif self.projection_digest != expected:
            raise ProbeValidationError("projection digest cannot be re-derived")


@dataclass(frozen=True)
class SemanticEquivalenceReview:
    forward_projection_digest: str
    reversed_projection_digest: str
    independence: IndependenceAttestation
    review_digest: str

    def __post_init__(self) -> None:
        _digest(self.forward_projection_digest, "forward projection")
        _digest(self.reversed_projection_digest, "reversed projection")
        if not isinstance(self.independence, IndependenceAttestation):
            raise ProbeValidationError("equivalence review requires an independence attestation")
        expected = _review_digest(self)
        if not self.review_digest:
            object.__setattr__(self, "review_digest", expected)
        elif self.review_digest != expected:
            raise ProbeValidationError("equivalence review digest cannot be re-derived")


@dataclass(frozen=True)
class ReversedPairProbe:
    probe_id: str
    family_contract_digest: str
    forward_record: EvidenceRecord
    reversed_record: EvidenceRecord
    forward_surface: canonical.ContentRef
    reversed_surface: canonical.ContentRef
    equivalence: SemanticEquivalenceReview
    maximum_score_delta: float

    def __post_init__(self) -> None:
        _digest(self.family_contract_digest, "probe family contract")
        if not isinstance(self.forward_record, EvidenceRecord) or not isinstance(self.reversed_record, EvidenceRecord):
            raise ProbeValidationError("probe records must be EvidenceRecord values")
        if not isinstance(self.forward_surface, canonical.ContentRef) or not isinstance(self.reversed_surface, canonical.ContentRef):
            raise ProbeValidationError("probe surfaces must be ContentRef values")
        if not isinstance(self.equivalence, SemanticEquivalenceReview):
            raise ProbeValidationError("probe equivalence review is invalid")
        if isinstance(self.maximum_score_delta, bool) or not isinstance(self.maximum_score_delta, (int, float)):
            raise ProbeValidationError("maximum score delta must be a finite non-negative number")
        if not math.isfinite(self.maximum_score_delta) or self.maximum_score_delta < 0:
            raise ProbeValidationError("maximum score delta must be a finite non-negative number")
        expected = _probe_digest(self)
        if not self.probe_id:
            object.__setattr__(self, "probe_id", expected)
        elif self.probe_id != expected:
            raise ProbeValidationError("probe identity cannot be re-derived")


@dataclass(frozen=True)
class ProbeObservation:
    probe_digest: str
    component_digest: str
    forward_decision: str
    reversed_decision: str
    forward_score: float | None
    reversed_score: float | None

    def __post_init__(self) -> None:
        _digest(self.probe_digest, "observation probe")
        _digest(self.component_digest, "observation component")
        _text(self.forward_decision, "forward decision")
        _text(self.reversed_decision, "reversed decision")
        scores = (self.forward_score, self.reversed_score)
        if (scores[0] is None) != (scores[1] is None):
            raise ProbeValidationError("probe scores must both be present or both be absent")
        if any(
            value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value))
            for value in scores
        ):
            raise ProbeValidationError("probe scores must be finite numbers")


@dataclass(frozen=True)
class ProbeEvaluationInput:
    probe: ReversedPairProbe
    observation: ProbeObservation

    def __post_init__(self) -> None:
        if not isinstance(self.probe, ReversedPairProbe) or not isinstance(self.observation, ProbeObservation):
            raise ProbeValidationError("probe evaluation input has invalid members")


@dataclass(frozen=True)
class ProbeResult:
    probe_digest: str
    component_digest: str
    valid: bool
    passed: bool
    reasons: tuple[str, ...]
    result_digest: str

    def __post_init__(self) -> None:
        _digest(self.probe_digest, "result probe")
        _digest(self.component_digest, "result component")
        if not isinstance(self.valid, bool) or not isinstance(self.passed, bool):
            raise ProbeValidationError("probe result flags must be booleans")
        if self.passed and not self.valid:
            raise ProbeValidationError("an invalid probe cannot pass")
        if not isinstance(self.reasons, tuple) or not all(isinstance(item, str) and item for item in self.reasons):
            raise ProbeValidationError("probe result reasons are invalid")
        if self.passed and self.reasons:
            raise ProbeValidationError("a passing probe cannot carry failure reasons")
        if not self.passed and not self.reasons:
            raise ProbeValidationError("a non-passing probe requires reasons")
        expected = _result_digest(self)
        if not self.result_digest:
            object.__setattr__(self, "result_digest", expected)
        elif self.result_digest != expected:
            raise ProbeValidationError("probe result digest cannot be re-derived")


def _projection_value(projection: SemanticProjection) -> canonical.JsonValue:
    return {
        "family_contract_digest": projection.family_contract_digest,
        "security_object_fields": tuple(_field_value(item) for item in projection.security_object_fields),
        "roles": tuple(
            {
                "role": role.role,
                "fields": tuple(_field_value(item) for item in role.fields),
                "relation_kinds": tuple(item.value for item in role.relation_kinds),
                "statuses": tuple(item.value for item in role.statuses),
            }
            for role in projection.roles
        ),
        "completeness_reasons": projection.completeness_reasons,
        "family_decision": projection.family_decision,
    }


def _projection_digest(projection: SemanticProjection) -> str:
    return canonical.content_digest(_projection_value(projection))


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _attestation_value(attestation: IndependenceAttestation) -> canonical.JsonValue:
    return {
        "subject_digest": attestation.subject_digest,
        "producer_identity": attestation.producer_identity,
        "reviewer_identity": attestation.reviewer_identity,
        "conflict_disclosure": _content_ref_value(attestation.conflict_disclosure),
        "attestation_digest": attestation.attestation_digest,
    }


def _review_digest(review: SemanticEquivalenceReview) -> str:
    return canonical.content_digest(
        {
            "forward_projection_digest": review.forward_projection_digest,
            "reversed_projection_digest": review.reversed_projection_digest,
            "independence": _attestation_value(review.independence),
        }
    )


def _probe_digest(probe: ReversedPairProbe) -> str:
    return canonical.content_digest(
        {
            "family_contract_digest": probe.family_contract_digest,
            "forward_record_id": probe.forward_record.record_id,
            "reversed_record_id": probe.reversed_record.record_id,
            "forward_surface": _content_ref_value(probe.forward_surface),
            "reversed_surface": _content_ref_value(probe.reversed_surface),
            "equivalence_review_digest": probe.equivalence.review_digest,
            "maximum_score_delta": probe.maximum_score_delta,
        }
    )


def _result_digest(result: ProbeResult) -> str:
    return canonical.content_digest(
        {
            "probe_digest": result.probe_digest,
            "component_digest": result.component_digest,
            "valid": result.valid,
            "passed": result.passed,
            "reasons": result.reasons,
        }
    )


def _sort_fields(values: tuple[FieldValue, ...]) -> tuple[FieldValue, ...]:
    return tuple(sorted(values, key=lambda item: canonical.canonical_bytes(_field_value(item))))


def project_semantics(record: EvidenceRecord, contract: FamilyContract) -> SemanticProjection:
    """Derive only family-declared security semantics, excluding presentation shape."""
    for relation in record.packet.transitions:
        relation.__post_init__()
    for observation in record.packet.observations:
        observation.__post_init__()
        for field in observation.fields:
            field.__post_init__()
    for field in record.packet.family_fields:
        field.__post_init__()
    record.packet.__post_init__()
    record.decision.__post_init__()
    record.__post_init__()
    validate_record(contract, record)
    rule = next(item for item in contract.decisions if item.family_code == record.decision.family_code)
    actual_fields = {item.name: item for item in record.packet.family_fields}
    object_fields = tuple(actual_fields[item.name] for item in contract.security_object.fields if item.name in actual_fields)
    roles: list[RoleProjection] = []
    for role in rule.required_roles:
        observations = tuple(item for item in record.packet.observations if item.role == role)
        relations = tuple(item for item in record.packet.transitions if item.role == role)
        fields = _sort_fields(tuple(field for item in observations for field in item.fields))
        kinds = tuple(sorted((item.kind for item in relations), key=lambda item: item.value))
        relation_statuses = tuple(item.status for item in relations)
        observation_statuses = tuple(item.status for item in observations)
        statuses = tuple(sorted((*relation_statuses, *observation_statuses), key=lambda item: item.value))
        roles.append(RoleProjection(role, fields, kinds, statuses))
    provisional = SemanticProjection(
        family_contract_digest(contract),
        object_fields,
        tuple(roles),
        tuple(sorted(record.packet.completeness_reasons)),
        record.decision.family_code,
        "",
    )
    return replace(provisional, projection_digest=_projection_digest(provisional))


def derive_equivalence_subject_digest(
    forward_projection_digest: str,
    reversed_projection_digest: str,
    contract_digest: str,
    forward_surface: canonical.ContentRef,
    reversed_surface: canonical.ContentRef,
) -> str:
    for value, field in (
        (forward_projection_digest, "forward projection"),
        (reversed_projection_digest, "reversed projection"),
        (contract_digest, "family contract"),
    ):
        _digest(value, field)
    return canonical.content_digest(
        {
            "forward_projection_digest": forward_projection_digest,
            "reversed_projection_digest": reversed_projection_digest,
            "family_contract_digest": contract_digest,
            "forward_surface": _content_ref_value(forward_surface),
            "reversed_surface": _content_ref_value(reversed_surface),
        }
    )


def evaluate_probe(
    probe: ReversedPairProbe,
    observation: ProbeObservation,
    contract: FamilyContract,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> ProbeResult:
    from openultrasast.core._probe_eval import evaluate_probe as evaluate

    return evaluate(probe, observation, contract, review_policy, resolver)


def validate_probe_result(
    evaluation: ProbeEvaluationInput,
    claimed: ProbeResult,
    contract: FamilyContract,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    actual = evaluate_probe(evaluation.probe, evaluation.observation, contract, review_policy, resolver)
    if claimed != actual:
        raise ProbeValidationError("claimed probe result does not match canonical evaluation")


__all__ = [
    "ProbeEvaluationInput",
    "ProbeObservation",
    "ProbeResult",
    "ProbeValidationError",
    "ReversedPairProbe",
    "RoleProjection",
    "SemanticEquivalenceReview",
    "SemanticProjection",
    "derive_equivalence_subject_digest",
    "evaluate_probe",
    "project_semantics",
    "validate_probe_result",
]
