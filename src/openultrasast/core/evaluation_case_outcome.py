"""Fail-closed per-case outcome projection contracts for evaluation admission V3."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from openultrasast.core import canonical
from openultrasast.core._evaluation_measurement_contracts import CaseOutcomeProjectionPolicyV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.evidence import Decision, EvidencePacket, EvidenceRecord, NeutralOutcome, derive_record_id
from openultrasast.core.provenance import ProvenanceStamp

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "openultrasast.detection-core.evaluation-case-outcome.v3"
_PROJECTION_FIELDS = frozenset({"case_input_digest", "policy", "source_outcome_digests", "normalized_outcome", "projection_digest"})


class CaseOutcomeProjectionError(ValueError):
    """A per-case outcome projection is incomplete, ambiguous, or non-canonical."""


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise CaseOutcomeProjectionError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _value(kind: str, payload: canonical.JsonValue) -> canonical.JsonValue:
    return {"schema_version": _SCHEMA, "kind": kind, "payload": payload}


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise CaseOutcomeProjectionError(f"{field} does not match canonical content")


def _source_digests(value: object, policy: CaseOutcomeProjectionPolicyV3) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise CaseOutcomeProjectionError("source outcome digests must be a nonempty exact tuple")
    for item in value:
        _digest(item, "source outcome digest")
    if policy is CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE:
        if len(set(value)) != len(value):
            raise CaseOutcomeProjectionError("unanimous evidence source outcome digests must be unique")
        if value != tuple(sorted(value)):
            raise CaseOutcomeProjectionError("unanimous evidence source outcome digests must use canonical order")
    return value


@dataclass(frozen=True)
class CaseOutcomeProjectionV3(EvaluationV3Contract, NonAuthorizingV3):
    """One digest-bound neutral outcome for one authenticated case input."""

    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    case_input_digest: str
    policy: CaseOutcomeProjectionPolicyV3
    source_outcome_digests: tuple[str, ...]
    normalized_outcome: NeutralOutcome
    projection_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, CaseOutcomeProjectionV3, field="case outcome projection")
        _digest(self.case_input_digest, "case input digest")
        if type(self.policy) is not CaseOutcomeProjectionPolicyV3:
            raise CaseOutcomeProjectionError("projection policy must use exact CaseOutcomeProjectionPolicyV3")
        sources = _source_digests(self.source_outcome_digests, self.policy)
        if type(self.normalized_outcome) is not NeutralOutcome:
            raise CaseOutcomeProjectionError("normalized outcome must use exact NeutralOutcome")
        payload: canonical.JsonValue = {
            "case_input_digest": self.case_input_digest,
            "policy": self.policy.value,
            "source_outcome_digests": sources,
            "normalized_outcome": self.normalized_outcome.value,
        }
        _bind(self, "projection_digest", canonical.content_digest(_value("case_outcome_projection", payload)))


def case_outcome_projection_value(value: CaseOutcomeProjectionV3) -> dict[str, canonical.JsonValue]:
    """Return the exact nested canonical value used by observation and release contracts."""

    if type(value) is not CaseOutcomeProjectionV3:
        raise CaseOutcomeProjectionError("projection must use exact CaseOutcomeProjectionV3")
    value.__post_init__()
    return {
        "case_input_digest": value.case_input_digest,
        "policy": value.policy.value,
        "source_outcome_digests": value.source_outcome_digests,
        "normalized_outcome": value.normalized_outcome.value,
        "projection_digest": value.projection_digest,
    }


def case_outcome_projection_from_value(value: object) -> CaseOutcomeProjectionV3:
    """Decode the exact nested projection value without accepting aliases or extra fields."""

    if type(value) is not dict or frozenset(value) != _PROJECTION_FIELDS:
        raise CaseOutcomeProjectionError("projection must use the exact canonical field set")
    sources = value["source_outcome_digests"]
    if type(sources) is not list:
        raise CaseOutcomeProjectionError("projection source outcome digests must be a canonical array")
    try:
        policy = CaseOutcomeProjectionPolicyV3(value["policy"])
        outcome = NeutralOutcome(value["normalized_outcome"])
    except (TypeError, ValueError) as exc:
        raise CaseOutcomeProjectionError("projection contains an unknown closed value") from exc
    return CaseOutcomeProjectionV3(
        _digest(value["case_input_digest"], "case input digest"),
        policy,
        tuple(_digest(item, "source outcome digest") for item in sources),
        outcome,
        _digest(value["projection_digest"], "projection digest"),
    )


def _canonical_records(records: object) -> tuple[EvidenceRecord, ...]:
    if type(records) is not tuple or not records:
        raise CaseOutcomeProjectionError("component evidence records must be a nonempty exact tuple")
    if any(type(record) is not EvidenceRecord for record in records):
        raise CaseOutcomeProjectionError("component evidence records must contain exact EvidenceRecord values")
    validated = records
    for record in validated:
        try:
            if type(record.packet) is not EvidencePacket:
                raise CaseOutcomeProjectionError("evidence record packet must use exact EvidencePacket")
            if type(record.decision) is not Decision:
                raise CaseOutcomeProjectionError("evidence record decision must use exact Decision")
            if type(record.packet.provenance) is not ProvenanceStamp:
                raise CaseOutcomeProjectionError("evidence record provenance change input digest must use exact ProvenanceStamp")
            _digest(record.packet.provenance.change_input_digest, "change input digest")
            record.packet.provenance.__post_init__()
            record.packet.__post_init__()
            record.decision.__post_init__()
            record.__post_init__()
            expected_record_id = derive_record_id(record.packet, record.decision)
        except CaseOutcomeProjectionError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise CaseOutcomeProjectionError("component evidence record cannot be revalidated") from exc
        if record.record_id != expected_record_id:
            raise CaseOutcomeProjectionError("evidence record identity cannot be re-derived")
    identities = tuple(record.record_id for record in validated)
    if len(set(identities)) != len(identities):
        raise CaseOutcomeProjectionError("component evidence record identities must be unique")
    return tuple(sorted(validated, key=lambda item: item.record_id))


def derive_case_input_digest(records: tuple[EvidenceRecord, ...]) -> str:
    """Derive correlation identity from exact, already trust-validated evidence records."""

    validated = _canonical_records(records)
    change_input_digests = tuple(sorted({record.packet.provenance.change_input_digest for record in validated}))
    payload: canonical.JsonValue = {"change_input_digests": change_input_digests}
    return canonical.content_digest(_value("case_input", payload))


def derive_component_case_outcome_projection(
    records: tuple[EvidenceRecord, ...],
) -> CaseOutcomeProjectionV3:
    """Project exact trust-validated component records only when every outcome agrees."""

    validated = _canonical_records(records)
    outcomes = {record.decision.outcome for record in validated}
    if len(outcomes) != 1:
        raise CaseOutcomeProjectionError("component evidence records must carry the same neutral outcome")
    outcome = next(iter(outcomes))
    return CaseOutcomeProjectionV3(
        derive_case_input_digest(validated),
        CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
        tuple(record.record_id for record in validated),
        outcome,
        "",
    )


__all__ = [
    "CaseOutcomeProjectionError",
    "CaseOutcomeProjectionPolicyV3",
    "CaseOutcomeProjectionV3",
    "case_outcome_projection_from_value",
    "case_outcome_projection_value",
    "derive_case_input_digest",
    "derive_component_case_outcome_projection",
]
