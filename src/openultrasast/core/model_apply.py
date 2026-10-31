"""Apply validated model results without mutating deterministic evidence."""

from __future__ import annotations

from openultrasast.core._model_common import ModelContractError
from openultrasast.core._model_result import ModelResult, ModelStatus
from openultrasast.core.canonical import ContentResolver
from openultrasast.core.custody import (
    LineagePurpose,
    PopulationCustodyError,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationUseReceipt,
    validate_population_custody_log,
)
from openultrasast.core.evidence import (
    Decision,
    EvidenceBasis,
    EvidenceRecord,
    NeutralOutcome,
    derive_packet_digest,
)
from openultrasast.core.family import FamilyContract, family_contract_digest, validate_record
from openultrasast.core.lineage import LineageExpectation, LineageValidationError, validate_lineage
from openultrasast.core.model import ModelProgramDeclaration, ModelRequest, validate_model_result
from openultrasast.core.model import completeness_snapshot as _completeness_snapshot
from openultrasast.core.provenance import DecisionProvenance
from openultrasast.core.semantics import RelationStatus


def _expectations(program: ModelProgramDeclaration) -> tuple[LineageExpectation, ...]:
    expected = [
        LineageExpectation(LineagePurpose.PROMPT, program.prompt_digest, 1, 1),
        LineageExpectation(LineagePurpose.DECISION_MAPPING, program.decision_mapping_digest, 1, 1),
    ]
    if program.example_set_digest is not None:
        expected.append(LineageExpectation(LineagePurpose.EXAMPLE, program.example_set_digest, 1, 1))
    if program.fitted_component_digest is not None:
        expected.append(LineageExpectation(LineagePurpose.FITTED_MODEL, program.fitted_component_digest, 1, 1))
    return tuple(expected)


def _expected_artifacts(program: ModelProgramDeclaration) -> set[tuple[LineagePurpose, str]]:
    return {(item.purpose, item.influenced_artifact_digest) for item in _expectations(program)}


def _authoritative_receipts(
    request: ModelRequest,
    protected_population_digest: str,
    custody: PopulationCustodyPort,
    policy: PopulationCustodyPolicy,
) -> tuple[PopulationUseReceipt, ...]:
    populations = {protected_population_digest, *(use.source_population_digest for use in request.lineage.uses)}
    expected = _expected_artifacts(request.program)
    receipts: list[PopulationUseReceipt] = []
    for population_digest in sorted(populations):
        log = custody.current_log(population_digest)
        validate_population_custody_log(log, policy, current=custody)
        receipts.extend(
            receipt
            for receipt in log.receipts
            if (receipt.request.purpose, receipt.request.influenced_artifact_digest) in expected
            and (receipt.request.arm_id == request.lineage.arm_id or receipt.request.labels_accessed)
        )
    return tuple(receipts)


def _refuse_omitted_uses(
    request: ModelRequest,
    receipts: tuple[PopulationUseReceipt, ...],
    protected_population_digest: str,
) -> None:
    declared = {use.population_use_receipt_digest for use in request.lineage.uses}
    for receipt in receipts:
        if receipt.receipt_digest in declared:
            continue
        population = receipt.request.population_digest
        if receipt.request.labels_accessed:
            reason = f"label_access_forbidden:{population}"
            if population == protected_population_digest:
                reason += f",protected_population_labels:{population}"
            raise ModelContractError(f"model lineage is contaminated: {reason}")
        raise ModelContractError(f"model lineage omitted current use: {receipt.receipt_digest}")


def _validate_program_lineage(
    request: ModelRequest,
    record: EvidenceRecord,
    custody: PopulationCustodyPort,
    policy: PopulationCustodyPolicy,
) -> None:
    protected = record.packet.provenance.population_digest
    try:
        decision = validate_lineage(
            request.lineage,
            request.program.input_bundle_digest,
            _expectations(request.program),
            protected,
            True,
            custody,
            policy,
        )
        receipts = _authoritative_receipts(request, protected, custody, policy)
    except (LineageValidationError, PopulationCustodyError, TypeError, ValueError) as exc:
        raise ModelContractError(f"model lineage cannot be validated: {exc}") from exc
    if not decision.allowed:
        raise ModelContractError("model lineage is not allowed: " + ",".join(decision.reasons))
    _refuse_omitted_uses(request, receipts, protected)


def _validate_application_inputs(
    record: EvidenceRecord,
    contract: FamilyContract,
    request: ModelRequest,
    result: ModelResult,
    resolver: ContentResolver,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> None:
    if not isinstance(record, EvidenceRecord) or not isinstance(contract, FamilyContract):
        raise ModelContractError("record and contract must use detection-core contract types")
    if record != request.record or contract != request.contract:
        raise ModelContractError("record or family contract does not match the frozen model request")
    if family_contract_digest(contract) != request.family_contract_digest:
        raise ModelContractError("family contract identity does not match the frozen model request")
    if request.custody_policy_digest != custody_policy.policy_digest:
        raise ModelContractError("custody policy does not match the frozen model request")
    if request.program.program_digest in request.proposal_program_digests:
        raise ModelContractError("one program cannot propose and adjudicate the same evidence path")
    try:
        validate_record(contract, record)
        validate_model_result(request, result, resolver)
    except (TypeError, ValueError) as exc:
        raise ModelContractError(f"model application input is invalid: {exc}") from exc
    _validate_program_lineage(request, record, custody, custody_policy)


def _residual_complete(request: ModelRequest) -> bool:
    statuses = {item.role: item.status for item in _completeness_snapshot(request.record, request.contract)}
    return all(statuses.get(role) is RelationStatus.COMPLETE for role in request.residual_question.required_roles)


def _derived_record(record: EvidenceRecord, contract: FamilyContract, request: ModelRequest, result: ModelResult) -> EvidenceRecord:
    if result.family_decision is None:
        raise ModelContractError("successful model result requires a family decision")
    rules = tuple(item for item in contract.decisions if item.family_code == result.family_decision)
    if len(rules) != 1:
        raise ModelContractError("model family decision does not resolve exactly once")
    rule = rules[0]
    if rule.outcome is NeutralOutcome.INDETERMINATE:
        raise ModelContractError("model output cannot synthesize an indeterminate reason")
    provenance = DecisionProvenance(
        result.identity,
        result.result_digest,
        request.program.declaration_digest,
        None,
        None,
        request.lineage.manifest_digest,
    )
    decision = Decision(
        result.family_decision,
        rule.outcome,
        EvidenceBasis.MODEL_CORROBORATED,
        record.decision.bounded_scope,
        (),
        derive_packet_digest(record.packet),
        provenance,
    )
    derived = EvidenceRecord(record.packet, decision, "")
    try:
        validate_record(contract, derived)
    except (TypeError, ValueError) as exc:
        raise ModelContractError(f"model-derived record is invalid: {exc}") from exc
    return derived


def apply_model_result(
    record: EvidenceRecord,
    contract: FamilyContract,
    request: ModelRequest,
    result: ModelResult,
    resolver: ContentResolver,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> EvidenceRecord:
    """Return a corroborated decision over the exact immutable deterministic packet."""
    _validate_application_inputs(record, contract, request, result, resolver, custody, custody_policy)
    if result.status is ModelStatus.FAILED:
        return record
    if not _residual_complete(request):
        if record.decision.outcome is not NeutralOutcome.INDETERMINATE:
            raise ModelContractError("incomplete model prerequisites require an indeterminate deterministic record")
        return record
    return _derived_record(record, contract, request, result)


__all__ = ["apply_model_result"]
