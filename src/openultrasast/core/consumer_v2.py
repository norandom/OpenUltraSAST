"""Closed v2 push-consumer edge for validated bounded verdicts."""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace

from openultrasast.core import canonical
from openultrasast.core.budget import BudgetDerivation, BudgetGateFailure, ChangeComplexity, check_budget
from openultrasast.core.evidence import AnalyzedScope, EvidenceRecord, SourceRegion, derive_packet_digest, validate_scope
from openultrasast.core.family import FamilyContract, family_contract_digest
from openultrasast.core.family_catalog import resolve_contract
from openultrasast.core.proof import ProofAttachment, ProofTrustPolicy, attach_differential_proof
from openultrasast.core.provenance import PopulationCustodyPort
from openultrasast.core.semantics import SourceLocation
from openultrasast.core.validation import EvidenceValidationContext, EvidenceValidationInput, validate_evidence_input
from openultrasast.core.verdict_v2 import (
    BoundedSatisfaction,
    BoundedSilence,
    DefectClaim,
    VerdictOutputs,
    derive_verdict_outputs,
)

PUSH_REQUEST_SCHEMA = "openultrasast.detection-core.push-request.v2"
CONSUMER_COVERAGE_SCHEMA = "openultrasast.detection-core.consumer-coverage.v2"
_monotonic_ns = time.monotonic_ns


class ConsumerContractError(ValueError):
    """A raw push request cannot produce a bounded v2 verdict."""


@dataclass(frozen=True)
class PushRequest:
    request_id: str
    scope: AnalyzedScope
    workload_class: str
    complexity: ChangeComplexity
    budget: BudgetDerivation


@dataclass(frozen=True)
class PushVerdict:
    request_digest: str
    defects: tuple[DefectClaim, ...]
    satisfactions: tuple[BoundedSatisfaction, ...]
    silence: tuple[BoundedSilence, ...]
    input_record_digests: tuple[str, ...]
    complexity: ChangeComplexity
    total_reply_ms: int
    budget_derivation_digest: str


def _content_ref_value(value: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "media_type": value.media_type,
        "byte_length": value.byte_length,
        "retention_policy_digest": value.retention_policy_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
    }


def _scope_value(value: AnalyzedScope) -> canonical.JsonValue:
    return {
        "base_revision": value.base_revision,
        "head_revision": value.head_revision,
        "change_digest": value.change_digest,
        "regions": tuple({"path": region.path, "start_line": region.start_line, "end_line": region.end_line} for region in value.regions),
    }


def _request_value(request: PushRequest) -> canonical.JsonValue:
    complexity = request.complexity
    return {
        "schema_version": PUSH_REQUEST_SCHEMA,
        "scope": _scope_value(request.scope),
        "workload_class": request.workload_class,
        "complexity": {
            "change_id": complexity.change_id,
            "workload_class": complexity.workload_class,
            "changed_regions": complexity.changed_regions,
            "transition_count": complexity.transition_count,
            "changed_bytes": complexity.changed_bytes,
            "measurement": _content_ref_value(complexity.measurement),
        },
        "budget_derivation_digest": request.budget.derivation_digest,
    }


def derive_push_request_id(request: PushRequest) -> str:
    if not isinstance(request, PushRequest):
        raise ConsumerContractError("request must be a PushRequest")
    return canonical.content_digest(_request_value(request))


def make_push_request(
    *,
    scope: AnalyzedScope,
    workload_class: str,
    complexity: ChangeComplexity,
    budget: BudgetDerivation,
) -> PushRequest:
    provisional = PushRequest("0" * 64, scope, workload_class, complexity, budget)
    return PushRequest(derive_push_request_id(provisional), scope, workload_class, complexity, budget)


def _validate_request(request: PushRequest) -> None:
    if not isinstance(request, PushRequest):
        raise ConsumerContractError("request must be a PushRequest")
    try:
        request.scope.__post_init__()
        request.complexity.__post_init__()
        request.budget.__post_init__()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ConsumerContractError(f"push request is invalid: {exc}") from exc
    if request.request_id != derive_push_request_id(request):
        raise ConsumerContractError("push request identity cannot be re-derived")
    if request.workload_class != request.complexity.workload_class or request.workload_class != request.budget.workload_class:
        raise ConsumerContractError("push workload class does not match complexity and budget")
    if request.complexity.change_id != request.scope.change_digest:
        raise ConsumerContractError("complexity change identity does not match request scope")
    if request.complexity.changed_regions != len(request.scope.regions):
        raise ConsumerContractError("complexity changed-region count does not match request scope")


def _validated_records(
    values: Sequence[EvidenceValidationInput],
    context: EvidenceValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[EvidenceRecord, ...]:
    selected = tuple(values)
    if not selected:
        raise ConsumerContractError("push inputs must be nonempty")
    if not all(isinstance(value, EvidenceValidationInput) for value in selected):
        raise ConsumerContractError("every push input must be an EvidenceValidationInput")
    input_ids = tuple(value.input_digest for value in selected)
    if len(set(input_ids)) != len(input_ids):
        raise ConsumerContractError("duplicate validation input identity")
    try:
        return tuple(validate_evidence_input(value, context, custody, resolver) for value in selected)
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise ConsumerContractError(f"evidence validation failed: {exc}") from exc


def _contract(context: EvidenceValidationContext, record: EvidenceRecord) -> FamilyContract:
    packet = record.packet
    try:
        return resolve_contract(context.family_catalog, packet.family_id, packet.family_contract_digest, packet.ecosystem)
    except (LookupError, TypeError, ValueError) as exc:
        raise ConsumerContractError(f"record family cannot be resolved: {exc}") from exc


def _coverage_digest(request: PushRequest, contract: FamilyContract, records: tuple[EvidenceRecord, ...]) -> str:
    return canonical.content_digest(
        {
            "schema_version": CONSUMER_COVERAGE_SCHEMA,
            "request_id": request.request_id,
            "family_contract_digest": family_contract_digest(contract),
            "record_ids": tuple(sorted(record.record_id for record in records)),
        }
    )


def _derive_outputs(
    request: PushRequest,
    records: tuple[EvidenceRecord, ...],
    context: EvidenceValidationContext,
) -> VerdictOutputs:
    grouped: dict[str, tuple[FamilyContract, list[EvidenceRecord]]] = {}
    for record in records:
        try:
            validate_scope(record.packet, request.scope)
        except (TypeError, ValueError) as exc:
            raise ConsumerContractError(f"record scope is outside the push request: {exc}") from exc
        contract = _contract(context, record)
        digest = record.packet.family_contract_digest
        if digest not in grouped:
            grouped[digest] = (contract, [])
        grouped[digest][1].append(record)
    defects: list[DefectClaim] = []
    satisfactions: list[BoundedSatisfaction] = []
    silence: list[BoundedSilence] = []
    try:
        for digest in sorted(grouped):
            contract, members = grouped[digest]
            selected = tuple(members)
            outputs = derive_verdict_outputs(selected, contract, _coverage_digest(request, contract, selected))
            defects.extend(outputs.defects)
            satisfactions.extend(outputs.satisfactions)
            silence.extend(outputs.silence)
    except (TypeError, ValueError) as exc:
        raise ConsumerContractError(f"bounded verdict derivation failed: {exc}") from exc
    return VerdictOutputs(tuple(defects), tuple(satisfactions), tuple(silence))


def _region_within(allowed: AnalyzedScope, candidate: SourceRegion) -> bool:
    return any(
        candidate.path == region.path and candidate.start_line >= region.start_line and candidate.end_line <= region.end_line
        for region in allowed.regions
    )


def _proof_target_index(claims: tuple[DefectClaim, ...]) -> dict[tuple[str, str, SourceLocation], int]:
    keys: dict[tuple[str, str, SourceLocation], int] = {}
    for index, claim in enumerate(claims):
        key = (claim.record.packet.family_id, derive_packet_digest(claim.record.packet), claim.location)
        if key in keys:
            raise ConsumerContractError("proof target is ambiguous across defect claims")
        keys[key] = index
    return keys


def _apply_attachment(
    request: PushRequest,
    result: list[DefectClaim],
    keys: dict[tuple[str, str, SourceLocation], int],
    consumed: set[int],
    attachment: ProofAttachment,
    trust: ProofTrustPolicy,
    resolver: canonical.ContentResolver,
) -> None:
    if not isinstance(attachment, ProofAttachment):
        raise ConsumerContractError("every proof attachment must use the v2 proof contract")
    key = (attachment.family_id, attachment.packet_digest, attachment.location)
    if key not in keys:
        raise ConsumerContractError("proof attachment does not match one exact defect claim")
    index = keys[key]
    if index in consumed:
        raise ConsumerContractError("multiple proof attachments target one defect claim")
    if not _region_within(request.scope, result[index].change_anchor):
        raise ConsumerContractError("proof claim anchor is outside the push request scope")
    result[index] = attach_differential_proof(result[index], attachment, trust, resolver)
    consumed.add(index)


def _apply_proofs(
    request: PushRequest,
    claims: tuple[DefectClaim, ...],
    attachments: Sequence[ProofAttachment],
    trust: ProofTrustPolicy | None,
    resolver: canonical.ContentResolver,
) -> tuple[DefectClaim, ...]:
    selected = tuple(attachments)
    if not selected:
        return claims
    if not isinstance(trust, ProofTrustPolicy):
        raise ConsumerContractError("nonempty proof attachments require a proof trust policy")
    keys = _proof_target_index(claims)
    result = list(claims)
    consumed: set[int] = set()
    try:
        for attachment in selected:
            _apply_attachment(request, result, keys, consumed, attachment, trust, resolver)
    except ConsumerContractError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise ConsumerContractError(f"proof validation failed: {exc}") from exc
    return tuple(result)


def _total_reply_ms(elapsed_before_entry_ms: int, started_ns: int) -> int:
    if isinstance(elapsed_before_entry_ms, bool) or not isinstance(elapsed_before_entry_ms, int) or elapsed_before_entry_ms < 0:
        raise ConsumerContractError("elapsed-before-entry measurement must be a non-negative integer")
    finished_ns = _monotonic_ns()
    ticks = (started_ns, finished_ns)
    if any(isinstance(tick, bool) or not isinstance(tick, int) or tick < 0 for tick in ticks):
        raise ConsumerContractError("monotonic core timing ticks must be non-negative integers")
    if finished_ns < started_ns:
        raise ConsumerContractError("monotonic core timing measurement moved backwards")
    core_elapsed_ms = (finished_ns - started_ns + 999_999) // 1_000_000
    total_reply_ms = elapsed_before_entry_ms + core_elapsed_ms
    if total_reply_ms <= 0:
        raise ConsumerContractError("combined elapsed measurement must be a strictly positive integer")
    return total_reply_ms


def _validate_budget_artifacts(request: PushRequest, resolver: canonical.ContentResolver) -> None:
    try:
        check_budget(request.complexity, 1, request.budget, resolver)
    except (BudgetGateFailure, AttributeError, LookupError, TypeError, ValueError) as exc:
        raise ConsumerContractError(f"measured budget validation failed: {exc}") from exc


def _enforce_validated_deadline(request: PushRequest, total_reply_ms: int) -> None:
    if total_reply_ms > request.budget.budget_ms:
        raise ConsumerContractError(
            f"measured budget gate failed: budget:{request.complexity.change_id}:"
            f"{total_reply_ms}ms>{request.budget.budget_ms}ms "
            f"class={request.budget.workload_class} derivation={request.budget.derivation_digest}"
        )


def consume_records(
    request: PushRequest,
    inputs: Sequence[EvidenceValidationInput],
    validation_context: EvidenceValidationContext,
    custody: PopulationCustodyPort,
    elapsed_before_entry_ms: int,
    resolver: canonical.ContentResolver,
    attachments: Sequence[ProofAttachment] = (),
    proof_trust: ProofTrustPolicy | None = None,
) -> PushVerdict:
    started_ns = _monotonic_ns()
    _validate_request(request)
    records = _validated_records(inputs, validation_context, custody, resolver)
    transition_count = sum(len(record.packet.transitions) for record in records)
    if request.complexity.transition_count != transition_count:
        raise ConsumerContractError("complexity transition count does not match validated records")
    outputs = _derive_outputs(request, records, validation_context)
    defects = _apply_proofs(request, outputs.defects, attachments, proof_trust, resolver)
    if not defects and not outputs.satisfactions and not outputs.silence:
        raise ConsumerContractError("push verdict cannot be an unbounded clean result")
    _validate_budget_artifacts(request, resolver)
    provisional = PushVerdict(
        request.request_id,
        defects,
        outputs.satisfactions,
        outputs.silence,
        tuple(sorted(record.record_id for record in records)),
        request.complexity,
        0,
        request.budget.derivation_digest,
    )
    total_reply_ms = _total_reply_ms(elapsed_before_entry_ms, started_ns)
    _enforce_validated_deadline(request, total_reply_ms)
    return replace(provisional, total_reply_ms=total_reply_ms)


__all__ = [
    "ConsumerContractError",
    "PushRequest",
    "PushVerdict",
    "consume_records",
    "derive_push_request_id",
    "make_push_request",
]
