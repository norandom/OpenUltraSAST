"""Canonical, label-blind observation contracts for evaluation admission V3."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionError,
    CaseOutcomeProjectionV3,
    case_outcome_projection_from_value,
    case_outcome_projection_value,
)
from openultrasast.core.evaluation_measurement import ArmConfigurationV3
from openultrasast.core.evaluation_plan import EvaluationPlanDeclarationV3, ExpectedObservationSlotV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ZERO_DIGEST = "0" * 64
_OBSERVATION_SCHEMA = "openultrasast.detection-core.evaluation-observation.v3"
_OBSERVATION_IDENTITY_SCHEMA = "openultrasast.detection-core.evaluation-observation-identity.v3"
_REFERENCE_IDENTITY_SCHEMA = "openultrasast.detection-core.sealed-observation-reference.v3"
_CASE_FIELDS = frozenset(
    {
        "case_id_digest",
        "case_input_digest",
        "underlying_push_digest",
        "result_digest",
        "outcome_projection",
        "proof_candidate_digest",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "slot_digest",
        "arm_id",
        "input_identity_digest",
        "execution_identity",
        "registered_budget_digest",
        "configuration_digest",
        "input_read_evidence_digest",
        "stage_execution_evidence_digest",
        "cases",
        "observation_digest",
    }
)


class EvaluationObservationError(ValueError):
    """A sealed V3 observation is malformed, non-canonical, or cross-bound."""


def _digest(value: object, field: str, *, nonzero: bool = False) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationObservationError(f"{field} must be a full lowercase SHA-256 digest")
    if nonzero and value == _ZERO_DIGEST:
        raise EvaluationObservationError(f"{field} must be a nonzero evidence digest")
    return value


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise EvaluationObservationError(f"{field} must be nonempty exact text")
    return value


def _bind_digest(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
        return
    _digest(actual, field)
    if actual != expected:
        raise EvaluationObservationError(f"{field} does not match canonical content")


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


@dataclass(frozen=True)
class ObservationCaseRefV3(EvaluationV3Contract, NonAuthorizingV3):
    """Opaque label-blind result and optional proof-candidate identities for one case."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    case_id_digest: str
    case_input_digest: str
    underlying_push_digest: str
    result_digest: str
    outcome_projection: CaseOutcomeProjectionV3
    proof_candidate_digest: str | None

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ObservationCaseRefV3, field="observation case reference")
        _digest(self.case_id_digest, "case identity digest")
        _digest(self.case_input_digest, "case input digest")
        _digest(self.underlying_push_digest, "underlying push digest")
        _digest(self.result_digest, "case result digest")
        if type(self.outcome_projection) is not CaseOutcomeProjectionV3:
            raise EvaluationObservationError("case outcome projection must use exact CaseOutcomeProjectionV3")
        try:
            self.outcome_projection.__post_init__()
        except CaseOutcomeProjectionError as exc:
            raise EvaluationObservationError("case outcome projection is malformed") from exc
        if self.outcome_projection.case_input_digest != self.case_input_digest:
            raise EvaluationObservationError("case outcome projection input identity does not match its observation case")
        if self.proof_candidate_digest is not None:
            _digest(self.proof_candidate_digest, "proof candidate digest")


def _case_value(value: ObservationCaseRefV3) -> canonical.JsonValue:
    return {
        "case_id_digest": value.case_id_digest,
        "case_input_digest": value.case_input_digest,
        "underlying_push_digest": value.underlying_push_digest,
        "result_digest": value.result_digest,
        "outcome_projection": case_outcome_projection_value(value.outcome_projection),
        "proof_candidate_digest": value.proof_candidate_digest,
    }


def _case_order(value: ObservationCaseRefV3) -> tuple[str, str, str, str, str, str]:
    return (
        value.case_id_digest,
        value.case_input_digest,
        value.underlying_push_digest,
        value.result_digest,
        value.outcome_projection.projection_digest,
        value.proof_candidate_digest or "",
    )


def _canonical_cases(value: object) -> tuple[ObservationCaseRefV3, ...]:
    if type(value) is not tuple or any(type(item) is not ObservationCaseRefV3 for item in value):
        raise EvaluationObservationError("observation cases must be a tuple of exact ObservationCaseRefV3 values")
    cases = value
    for item in cases:
        item.__post_init__()
    if cases != tuple(sorted(cases, key=_case_order)):
        raise EvaluationObservationError("observation cases must use canonical order")
    identities = tuple(item.case_id_digest for item in cases)
    if len(set(identities)) != len(identities):
        raise EvaluationObservationError("observation case identities must be unique")
    return cases


def _observation_identity_value(value: ArmObservationSetV3) -> canonical.JsonValue:
    return {
        "schema_version": _OBSERVATION_IDENTITY_SCHEMA,
        "slot_digest": value.slot_digest,
        "arm_id": value.arm_id,
        "input_identity_digest": value.input_identity_digest,
        "execution_identity": value.execution_identity,
        "registered_budget_digest": value.registered_budget_digest,
        "configuration_digest": value.configuration_digest,
        "input_read_evidence_digest": value.input_read_evidence_digest,
        "stage_execution_evidence_digest": value.stage_execution_evidence_digest,
        "cases": tuple(_case_value(item) for item in value.cases),
    }


@dataclass(frozen=True)
class ArmObservationSetV3(EvaluationV3Contract, NonAuthorizingV3):
    """One canonical label-blind observation for one planned arm/input slot."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    slot_digest: str
    arm_id: str
    input_identity_digest: str
    execution_identity: str
    registered_budget_digest: str
    configuration_digest: str
    input_read_evidence_digest: str
    stage_execution_evidence_digest: str
    cases: tuple[ObservationCaseRefV3, ...]
    observation_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ArmObservationSetV3, field="arm observation set")
        _digest(self.slot_digest, "observation slot digest")
        _text(self.arm_id, "observation arm_id")
        _digest(self.input_identity_digest, "observation input identity digest")
        _text(self.execution_identity, "observation execution identity")
        _digest(self.registered_budget_digest, "observation registered budget digest")
        _digest(self.configuration_digest, "observation configuration digest")
        _digest(self.input_read_evidence_digest, "input-read evidence digest", nonzero=True)
        _digest(self.stage_execution_evidence_digest, "stage-execution evidence digest", nonzero=True)
        _canonical_cases(self.cases)
        _bind_digest(self, "observation_digest", canonical.content_digest(_observation_identity_value(self)))


def _observation_record_value(value: ArmObservationSetV3) -> canonical.JsonValue:
    identity = _observation_identity_value(value)
    if not isinstance(identity, dict):  # pragma: no cover - fixed internal shape
        raise AssertionError("observation identity must be a mapping")
    return {**identity, "schema_version": _OBSERVATION_SCHEMA, "observation_digest": value.observation_digest}


def _reference_identity_value(value: SealedObservationRefV3) -> canonical.JsonValue:
    return {
        "schema_version": _REFERENCE_IDENTITY_SCHEMA,
        "slot_digest": value.slot_digest,
        "arm_id": value.arm_id,
        "input_identity_digest": value.input_identity_digest,
        "execution_identity": value.execution_identity,
        "registered_budget_digest": value.registered_budget_digest,
        "configuration_digest": value.configuration_digest,
        "observation": _content_ref_value(value.observation),
        "observation_digest": value.observation_digest,
        "read_receipt_digest": value.read_receipt_digest,
    }


@dataclass(frozen=True)
class SealedObservationRefV3(EvaluationV3Contract, NonAuthorizingV3):
    """Trusted content reference plus the planned identity expected from its bytes."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    slot_digest: str
    arm_id: str
    input_identity_digest: str
    execution_identity: str
    registered_budget_digest: str
    configuration_digest: str
    observation: canonical.ContentRef
    observation_digest: str
    read_receipt_digest: str
    ref_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, SealedObservationRefV3, field="sealed observation reference")
        _digest(self.slot_digest, "sealed slot digest")
        _text(self.arm_id, "sealed arm_id")
        _digest(self.input_identity_digest, "sealed input identity digest")
        _text(self.execution_identity, "sealed execution identity")
        _digest(self.registered_budget_digest, "sealed registered budget digest")
        _digest(self.configuration_digest, "sealed configuration digest")
        if type(self.observation) is not canonical.ContentRef:
            raise EvaluationObservationError("sealed observation must use exact ContentRef")
        self.observation.__post_init__()
        _digest(self.observation_digest, "sealed observation digest")
        _digest(self.read_receipt_digest, "read receipt digest", nonzero=True)
        _bind_digest(self, "ref_digest", canonical.content_digest(_reference_identity_value(self)))


def encode_arm_observation_set(value: ArmObservationSetV3) -> bytes:
    """Encode one exact observation as strict canonical JSON bytes."""
    if type(value) is not ArmObservationSetV3:
        raise EvaluationObservationError("observation must use exact ArmObservationSetV3")
    value.__post_init__()
    return canonical.canonical_bytes(_observation_record_value(value))


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationObservationError(f"duplicate observation field: {key}")
        result[key] = value
    return result


def _decode_document(content: bytes) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise EvaluationObservationError("observation bytes must be nonzero exact bytes")
    try:
        document = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationObservationError("observation bytes must contain valid UTF-8 JSON") from exc
    if type(document) is not dict or frozenset(document) != _OBSERVATION_FIELDS:
        raise EvaluationObservationError("observation document must use the exact canonical field set")
    if document["schema_version"] != _OBSERVATION_SCHEMA:
        raise EvaluationObservationError("observation document has an unknown schema version")
    return document


def _decode_case(value: object) -> ObservationCaseRefV3:
    if type(value) is not dict or frozenset(value) != _CASE_FIELDS:
        raise EvaluationObservationError("observation case must use the exact canonical field set")
    proof_candidate = value["proof_candidate_digest"]
    if proof_candidate is not None:
        proof_candidate = _digest(proof_candidate, "proof candidate digest")
    return ObservationCaseRefV3(
        _digest(value["case_id_digest"], "case identity digest"),
        _digest(value["case_input_digest"], "case input digest"),
        _digest(value["underlying_push_digest"], "underlying push digest"),
        _digest(value["result_digest"], "case result digest"),
        case_outcome_projection_from_value(value["outcome_projection"]),
        proof_candidate,
    )


def _document_text(document: dict[str, object], field: str) -> str:
    return _text(document[field], field.replace("_", " "))


def decode_arm_observation_set(content: bytes) -> ArmObservationSetV3:
    """Decode only the exact canonical V3 observation byte representation."""
    document = _decode_document(content)
    case_values = document["cases"]
    if type(case_values) is not list:
        raise EvaluationObservationError("observation cases must be a canonical array")
    try:
        value = ArmObservationSetV3(
            _digest(document["slot_digest"], "observation slot digest"),
            _document_text(document, "arm_id"),
            _digest(document["input_identity_digest"], "observation input identity digest"),
            _document_text(document, "execution_identity"),
            _digest(document["registered_budget_digest"], "observation registered budget digest"),
            _digest(document["configuration_digest"], "observation configuration digest"),
            _digest(document["input_read_evidence_digest"], "input-read evidence digest", nonzero=True),
            _digest(document["stage_execution_evidence_digest"], "stage-execution evidence digest", nonzero=True),
            tuple(_decode_case(item) for item in case_values),
            _digest(document["observation_digest"], "observation digest"),
        )
    except (EvaluationObservationError, TypeError, ValueError) as exc:
        if isinstance(exc, EvaluationObservationError):
            raise
        raise EvaluationObservationError("observation document contains malformed values") from exc
    if encode_arm_observation_set(value) != content:
        raise EvaluationObservationError("observation document is not canonical JSON")
    return value


def _validate_header(
    reference: SealedObservationRefV3,
    slot: ExpectedObservationSlotV3,
    configuration: ArmConfigurationV3,
) -> None:
    expected = (
        slot.slot_digest,
        slot.arm_id,
        slot.input_identity_digest,
        slot.execution_identity,
        configuration.registered_budget_digest,
        configuration.configuration_identity_digest,
    )
    actual = (
        reference.slot_digest,
        reference.arm_id,
        reference.input_identity_digest,
        reference.execution_identity,
        reference.registered_budget_digest,
        reference.configuration_digest,
    )
    if actual != expected:
        raise EvaluationObservationError("sealed observation header does not match its planned slot and arm configuration")


def _resolve_observation(
    reference: SealedObservationRefV3,
    resolver: canonical.ContentResolver,
    trusted_store_identities: tuple[str, ...],
    maximum_bytes: int,
) -> ArmObservationSetV3:
    try:
        content = canonical.resolve_content(
            reference.observation,
            resolver,
            trusted_store_identities=trusted_store_identities,
            maximum_bytes=maximum_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except (AttributeError, TypeError) as exc:
        raise EvaluationObservationError("observation resolver returned a malformed result") from exc
    if not content:
        raise EvaluationObservationError("resolved observation bytes must be nonzero")
    return decode_arm_observation_set(content)


def _validate_resolved(reference: SealedObservationRefV3, observation: ArmObservationSetV3) -> None:
    expected = (
        reference.slot_digest,
        reference.arm_id,
        reference.input_identity_digest,
        reference.execution_identity,
        reference.registered_budget_digest,
        reference.configuration_digest,
        reference.observation_digest,
        reference.read_receipt_digest,
    )
    actual = (
        observation.slot_digest,
        observation.arm_id,
        observation.input_identity_digest,
        observation.execution_identity,
        observation.registered_budget_digest,
        observation.configuration_digest,
        observation.observation_digest,
        observation.input_read_evidence_digest,
    )
    if actual != expected:
        raise EvaluationObservationError("resolved observation identities do not match its sealed reference")


def validate_evaluation_observations(
    declaration: EvaluationPlanDeclarationV3,
    references: tuple[SealedObservationRefV3, ...],
    resolver: canonical.ContentResolver,
    *,
    trusted_store_identities: tuple[str, ...],
    maximum_bytes: int,
) -> tuple[ArmObservationSetV3, ...]:
    """Resolve and validate exactly one nonzero observation per canonical planned slot."""
    if type(declaration) is not EvaluationPlanDeclarationV3:
        raise EvaluationObservationError("declaration must use exact EvaluationPlanDeclarationV3")
    declaration.__post_init__()
    if type(references) is not tuple or any(type(item) is not SealedObservationRefV3 for item in references):
        raise EvaluationObservationError("sealed observations must be a tuple of exact SealedObservationRefV3 values")
    for item in references:
        item.__post_init__()
    slots = declaration.expected_observation_slots
    if tuple(item.slot_digest for item in references) != tuple(slot.slot_digest for slot in slots):
        raise EvaluationObservationError("sealed observations must equal the canonical expected slot set exactly once")
    configurations = {item.arm_id: item for item in declaration.arm_configurations}
    resolved: list[ArmObservationSetV3] = []
    for slot, reference in zip(slots, references, strict=True):
        _validate_header(reference, slot, configurations[slot.arm_id])
        observation = _resolve_observation(reference, resolver, trusted_store_identities, maximum_bytes)
        _validate_resolved(reference, observation)
        if any(
            case.outcome_projection.policy is not configurations[slot.arm_id].case_outcome_policy
            for case in observation.cases
        ):
            raise EvaluationObservationError("observation case outcome projection policy differs from the planned arm")
        resolved.append(observation)
    return tuple(resolved)


__all__ = [
    "ArmObservationSetV3",
    "EvaluationObservationError",
    "ObservationCaseRefV3",
    "SealedObservationRefV3",
    "decode_arm_observation_set",
    "encode_arm_observation_set",
    "validate_evaluation_observations",
]
