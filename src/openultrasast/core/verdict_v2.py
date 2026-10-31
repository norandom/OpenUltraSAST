"""Bounded v2 verdict outputs derived from complete evidence records."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from openultrasast.core.evidence import (
    AnalyzedScope,
    EvidenceBasis,
    EvidenceRecord,
    EvidenceValidationError,
    NeutralOutcome,
    ScopeValidationError,
    SourceRegion,
    derive_record_id,
    validate_scope,
)
from openultrasast.core.family import FamilyContract, FamilyContractError, ResidualQuestion, validate_contract, validate_record
from openultrasast.core.semantics import Observation, RelationStatus, SemanticRelation, SourceLocation

_DIGEST = re.compile(r"[0-9a-f]{64}")


class VerdictContractError(ValueError):
    """Validated evidence cannot be represented as a bounded verdict."""


@dataclass(frozen=True)
class DefectClaim:
    record: EvidenceRecord
    basis: EvidenceBasis
    location: SourceLocation
    change_anchor: SourceRegion

    def __post_init__(self) -> None:
        if not isinstance(self.record, EvidenceRecord) or self.record.decision.outcome is not NeutralOutcome.VIOLATION:
            raise VerdictContractError("defect claim requires a violation evidence record")
        try:
            self.record.__post_init__()
            validate_scope(self.record.packet, self.record.packet.scope)
        except (TypeError, ValueError) as exc:
            raise VerdictContractError(f"defect claim evidence record is invalid: {exc}") from exc
        if not isinstance(self.basis, EvidenceBasis) or self.basis is not self.record.decision.basis:
            raise VerdictContractError("defect claim basis must equal its evidence decision basis")
        if not isinstance(self.location, SourceLocation) or not isinstance(self.change_anchor, SourceRegion):
            raise VerdictContractError("defect claim requires an exact location and change anchor")
        members: tuple[SemanticRelation | Observation, ...] = (
            *self.record.packet.transitions,
            *self.record.packet.observations,
        )
        if self.record.packet.completeness_reasons or any(item.status is not RelationStatus.COMPLETE for item in members):
            raise VerdictContractError("defect claim requires complete evidence")
        if self.location not in tuple(item.location for item in members):
            raise VerdictContractError("defect location must name an exact evidence location")
        if self.change_anchor not in self.record.decision.bounded_scope.regions:
            raise VerdictContractError("defect change anchor must belong to the bounded decision scope")
        if not _region_contains(self.change_anchor, self.location):
            raise VerdictContractError("defect location is outside its change anchor")


@dataclass(frozen=True)
class BoundedSatisfaction:
    question_ids: tuple[str, ...]
    records: tuple[EvidenceRecord, ...]
    scope: AnalyzedScope

    def __post_init__(self) -> None:
        _text_tuple(self.question_ids, "satisfaction question")
        if (
            not isinstance(self.records, tuple)
            or not self.records
            or not all(isinstance(record, EvidenceRecord) for record in self.records)
        ):
            raise VerdictContractError("bounded satisfaction requires evidence records")
        if not isinstance(self.scope, AnalyzedScope):
            raise VerdictContractError("bounded satisfaction requires an AnalyzedScope")
        if any(record.decision.outcome is not NeutralOutcome.SATISFIED for record in self.records):
            raise VerdictContractError("bounded satisfaction accepts only satisfied evidence records")
        if any(record.decision.bounded_scope != self.scope for record in self.records):
            raise VerdictContractError("satisfaction scope must equal every supporting record scope")


@dataclass(frozen=True)
class BoundedSilence:
    question_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    evidence_record_digests: tuple[str, ...]
    coverage_digest: str

    def __post_init__(self) -> None:
        _text_tuple(self.question_ids, "silence question")
        _text_tuple(self.reasons, "silence reason")
        _digest_tuple(self.evidence_record_digests, "silence evidence record")
        _digest(self.coverage_digest, "coverage")


@dataclass(frozen=True)
class VerdictOutputs:
    defects: tuple[DefectClaim, ...]
    satisfactions: tuple[BoundedSatisfaction, ...]
    silence: tuple[BoundedSilence, ...]

    def __post_init__(self) -> None:
        values = (
            (self.defects, DefectClaim, "defects"),
            (self.satisfactions, BoundedSatisfaction, "satisfactions"),
            (self.silence, BoundedSilence, "silence"),
        )
        for items, item_type, field in values:
            if not isinstance(items, tuple) or not all(isinstance(item, item_type) for item in items):
                raise VerdictContractError(f"{field} must be a tuple of {item_type.__name__}")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise VerdictContractError(f"{field} must be a full lowercase SHA-256 digest")


def _text_tuple(value: object, field: str) -> None:
    if not isinstance(value, tuple) or not value or not all(isinstance(item, str) and item for item in value):
        raise VerdictContractError(f"{field} identities must be a nonempty tuple")
    if len(set(value)) != len(value):
        raise VerdictContractError(f"duplicate {field} identity")


def _digest_tuple(value: object, field: str) -> None:
    _text_tuple(value, field)
    assert isinstance(value, tuple)
    for item in value:
        _digest(item, field)


def _region_contains(region: SourceRegion, location: SourceLocation) -> bool:
    return location.path == region.path and region.start_line <= location.line <= region.end_line


def _scope_contains(scope: AnalyzedScope, location: SourceLocation) -> bool:
    return any(_region_contains(region, location) for region in scope.regions)


def _members(record: EvidenceRecord, role: str) -> tuple[SemanticRelation | Observation, ...]:
    transitions = tuple(item for item in record.packet.transitions if item.role == role)
    observations = tuple(item for item in record.packet.observations if item.role == role)
    return (*transitions, *observations)


def _question_state(record: EvidenceRecord, question: ResidualQuestion) -> tuple[bool, tuple[str, ...]]:
    reasons: set[str] = set()
    if record.decision.family_code not in question.allowed_decisions:
        reasons.add(f"decision_not_declared_for_question:{record.decision.family_code}")
    for role in question.required_roles:
        members = _members(record, role)
        if not members:
            reasons.add(f"missing_required_role:{role}")
        elif not any(
            item.status is RelationStatus.COMPLETE and _scope_contains(record.decision.bounded_scope, item.location) for item in members
        ):
            relation_reasons = {reason for item in members if isinstance(item, SemanticRelation) for reason in item.reasons}
            complete_outside = any(item.status is RelationStatus.COMPLETE for item in members)
            fallback = f"evidence_outside_bounded_scope:{role}" if complete_outside else f"incomplete_required_role:{role}"
            reasons.update(relation_reasons or record.packet.completeness_reasons or (fallback,))
    if record.decision.outcome is NeutralOutcome.INDETERMINATE:
        reasons.update(record.decision.reasons)
    complete = not reasons and record.decision.outcome is not NeutralOutcome.INDETERMINATE
    return complete, tuple(sorted(reasons))


def _location(record: EvidenceRecord, question: ResidualQuestion) -> tuple[SourceLocation, SourceRegion]:
    candidates = tuple(
        item.location for role in question.required_roles for item in _members(record, role) if item.status is RelationStatus.COMPLETE
    )
    ordered = sorted(candidates, key=lambda item: (item.path, item.line, -1 if item.column is None else item.column, item.symbol or ""))
    for location in ordered:
        anchors = tuple(region for region in record.decision.bounded_scope.regions if _region_contains(region, location))
        if anchors:
            anchor = min(anchors, key=lambda item: (item.end_line - item.start_line, item.path, item.start_line))
            return location, anchor
    raise VerdictContractError("complete defect evidence has no exact location inside its bounded change scope")


def _validate_inputs(records: Sequence[EvidenceRecord], contract: FamilyContract, coverage_digest: str) -> tuple[EvidenceRecord, ...]:
    _digest(coverage_digest, "coverage")
    try:
        validate_contract(contract)
    except (TypeError, ValueError) as exc:
        raise VerdictContractError(f"family contract is invalid: {exc}") from exc
    values = tuple(records)
    if not values or not all(isinstance(record, EvidenceRecord) for record in values):
        raise VerdictContractError("records must be a nonempty sequence of EvidenceRecord values")
    identities: set[str] = set()
    try:
        for record in values:
            record.__post_init__()
            if record.record_id != derive_record_id(record.packet, record.decision):
                raise EvidenceValidationError("record identity cannot be re-derived")
            if record.record_id in identities:
                raise EvidenceValidationError("duplicate evidence record identity")
            identities.add(record.record_id)
            validate_scope(record.packet, record.packet.scope)
            validate_record(contract, record)
    except (TypeError, ValueError, EvidenceValidationError, ScopeValidationError, FamilyContractError) as exc:
        raise VerdictContractError(f"evidence record validation failed: {exc}") from exc
    return values


def _silence(
    question: ResidualQuestion,
    reasons: set[str],
    record_ids: set[str],
    coverage_digest: str,
) -> BoundedSilence | None:
    if not reasons:
        return None
    return BoundedSilence(
        (question.question_id,),
        tuple(sorted(reasons)),
        tuple(sorted(record_ids)),
        coverage_digest,
    )


def derive_verdict_outputs(
    records: Sequence[EvidenceRecord],
    contract: FamilyContract,
    coverage_digest: str,
) -> VerdictOutputs:
    """Derive bounded outputs without converting incomplete evidence to safety."""
    validated = _validate_inputs(records, contract, coverage_digest)
    defects: dict[str, DefectClaim] = {}
    satisfactions: dict[str, set[str]] = {}
    silence: list[BoundedSilence] = []
    for question in contract.residual_questions:
        reasons: set[str] = set()
        undecided: set[str] = set()
        for record in validated:
            complete, record_reasons = _question_state(record, question)
            if not complete:
                reasons.update(record_reasons)
                undecided.add(record.record_id)
                continue
            if record.decision.outcome is NeutralOutcome.VIOLATION:
                if record.record_id not in defects:
                    location, anchor = _location(record, question)
                    defects[record.record_id] = DefectClaim(record, record.decision.basis, location, anchor)
            elif record.decision.outcome is NeutralOutcome.SATISFIED:
                satisfactions.setdefault(record.record_id, set()).add(question.question_id)
        bounded = _silence(question, reasons, undecided, coverage_digest)
        if bounded is not None:
            silence.append(bounded)
    records_by_id = {record.record_id: record for record in validated}
    satisfied = tuple(
        BoundedSatisfaction(tuple(sorted(question_ids)), (records_by_id[record_id],), records_by_id[record_id].decision.bounded_scope)
        for record_id, question_ids in sorted(satisfactions.items())
    )
    return VerdictOutputs(
        tuple(defects[identity] for identity in sorted(defects)),
        satisfied,
        tuple(sorted(silence, key=lambda item: item.question_ids)),
    )


__all__ = [
    "BoundedSatisfaction",
    "BoundedSilence",
    "DefectClaim",
    "VerdictContractError",
    "VerdictOutputs",
    "derive_verdict_outputs",
]
