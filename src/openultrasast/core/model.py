"""Dependency-free, reproducible contracts for bounded model handoff."""

from __future__ import annotations

from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core._model_common import ModelContractError
from openultrasast.core._model_common import record_value as _record_value
from openultrasast.core._model_common import require_digest as _digest
from openultrasast.core._model_common import require_text as _text
from openultrasast.core._model_result import (
    MODEL_RESPONSE_SCHEMA as MODEL_RESPONSE_SCHEMA,
)
from openultrasast.core._model_result import (
    MODEL_RESULT_SCHEMA as MODEL_RESULT_SCHEMA,
)
from openultrasast.core._model_result import (
    ModelResult as ModelResult,
)
from openultrasast.core._model_result import (
    ModelStatus as ModelStatus,
)
from openultrasast.core._model_result import (
    PreservedModelResponse as PreservedModelResponse,
)
from openultrasast.core._model_result import (
    derive_model_result_digest as derive_model_result_digest,
)
from openultrasast.core._model_result import (
    make_model_result as make_model_result,
)
from openultrasast.core._model_result import (
    make_preserved_model_response as make_preserved_model_response,
)
from openultrasast.core._model_result import (
    model_result_bytes as model_result_bytes,
)
from openultrasast.core._model_result import (
    validate_model_result as validate_model_result,
)
from openultrasast.core.evidence import EvidenceRecord, derive_packet_digest, derive_record_id
from openultrasast.core.family import FamilyContract, FieldSpec, ResidualQuestion, family_contract_digest, validate_record
from openultrasast.core.lineage import LineageManifest, derive_lineage_manifest_digest
from openultrasast.core.semantics import RelationStatus

MODEL_REQUEST_SCHEMA = "openultrasast.detection-core.model-request.v2"


def _digest_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple):
        raise ModelContractError(f"{field} must be a tuple")
    for value in values:
        _digest(value, field)
    if len(set(values)) != len(values):
        raise ModelContractError(f"{field} must be unique")


def _text_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple) or not values:
        raise ModelContractError(f"{field} must be a nonempty tuple")
    for value in values:
        _text(value, field)
    if len(set(values)) != len(values):
        raise ModelContractError(f"{field} must be unique")


def _field_spec_value(value: FieldSpec) -> canonical.JsonValue:
    return {"name": value.name, "kind": value.kind.value, "required": value.required}


def _question_value(question: ResidualQuestion) -> canonical.JsonValue:
    return {
        "question_id": question.question_id,
        "required_roles": question.required_roles,
        "allowed_decisions": question.allowed_decisions,
    }


def _contract_value(contract: FamilyContract) -> canonical.JsonValue:
    return {
        "family_id": contract.family_id,
        "family_version": contract.family_version,
        "schema_version": contract.schema_version,
        "ecosystems": contract.ecosystems,
        "security_object": {
            "kind": contract.security_object.kind,
            "fields": tuple(_field_spec_value(item) for item in contract.security_object.fields),
            "identity_fields": contract.security_object.identity_fields,
        },
        "roles": tuple(
            {
                "role": role.role,
                "fields": tuple(_field_spec_value(item) for item in role.fields),
                "allowed_relation_kinds": tuple(item.value for item in role.allowed_relation_kinds),
                "origin_policy": role.origin_policy.value,
            }
            for role in contract.roles
        ),
        "decisions": tuple(
            {
                "family_code": rule.family_code,
                "outcome": rule.outcome.value,
                "required_roles": rule.required_roles,
                "allowed_statuses": tuple(item.value for item in rule.allowed_statuses),
            }
            for rule in contract.decisions
        ),
        "residual_questions": tuple(_question_value(item) for item in contract.residual_questions),
        "indeterminate_reasons": contract.indeterminate_reasons,
    }


@dataclass(frozen=True)
class CompletenessItem:
    role: str
    status: RelationStatus
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.role, "completeness role")
        if not isinstance(self.status, RelationStatus):
            raise ModelContractError("completeness status must be a RelationStatus")
        if not isinstance(self.reasons, tuple) or not all(isinstance(item, str) and item for item in self.reasons):
            raise ModelContractError("completeness reasons must be a tuple of nonempty text")
        if tuple(sorted(set(self.reasons))) != self.reasons:
            raise ModelContractError("completeness reasons must be sorted and unique")
        if self.status is RelationStatus.COMPLETE and self.reasons:
            raise ModelContractError("complete role cannot carry completeness reasons")
        if self.status is not RelationStatus.COMPLETE and not self.reasons:
            raise ModelContractError("non-complete role requires a named reason")


def _completeness_value(item: CompletenessItem) -> canonical.JsonValue:
    return {"role": item.role, "status": item.status.value, "reasons": item.reasons}


def _role_completeness(record: EvidenceRecord, role: str) -> CompletenessItem:
    relations = tuple(item for item in record.packet.transitions if item.role == role)
    observations = tuple(item for item in record.packet.observations if item.role == role)
    statuses = tuple(item.status for item in relations) + tuple(item.status for item in observations)
    if not statuses:
        return CompletenessItem(role, RelationStatus.INCOMPLETE, (f"missing_role:{role}",))
    if RelationStatus.UNRESOLVED in statuses:
        status = RelationStatus.UNRESOLVED
    elif RelationStatus.INCOMPLETE in statuses:
        status = RelationStatus.INCOMPLETE
    else:
        status = RelationStatus.COMPLETE
    reasons = {reason for relation in relations for reason in relation.reasons}
    if status is not RelationStatus.COMPLETE and not reasons:
        reasons.add(f"role_status:{role}:{status.value}")
    return CompletenessItem(role, status, tuple(sorted(reasons)))


def completeness_snapshot(record: EvidenceRecord, contract: FamilyContract) -> tuple[CompletenessItem, ...]:
    try:
        validate_record(contract, record)
    except (TypeError, ValueError) as exc:
        raise ModelContractError(f"record or family contract is invalid: {exc}") from exc
    return tuple(_role_completeness(record, role.role) for role in contract.roles)


def derive_completeness_digest(completeness: tuple[CompletenessItem, ...]) -> str:
    if not isinstance(completeness, tuple) or not all(isinstance(item, CompletenessItem) for item in completeness):
        raise ModelContractError("completeness must be a tuple of CompletenessItem values")
    return canonical.content_digest(tuple(_completeness_value(item) for item in completeness))


def derive_model_input_bundle_digest(
    record: EvidenceRecord,
    contract: FamilyContract,
    question: ResidualQuestion,
    completeness: tuple[CompletenessItem, ...],
) -> str:
    return canonical.content_digest(
        {
            "record": _record_value(record),
            "contract": _contract_value(contract),
            "residual_question": _question_value(question),
            "completeness": tuple(_completeness_value(item) for item in completeness),
        }
    )


@dataclass(frozen=True)
class ModelProgramDeclaration:
    family_contract_digest: str
    provider: str
    model: str
    program_digest: str
    prompt_digest: str
    example_set_digest: str | None
    fitted_component_digest: str | None
    configuration_digest: str
    adapter_revision: str
    decision_mapping_digest: str
    input_bundle_digest: str
    lineage_manifest_digest: str
    declaration_digest: str

    def __post_init__(self) -> None:
        _validate_program(self)


def _program_value(program: ModelProgramDeclaration) -> dict[str, canonical.JsonValue]:
    return {
        "family_contract_digest": program.family_contract_digest,
        "provider": program.provider,
        "model": program.model,
        "program_digest": program.program_digest,
        "prompt_digest": program.prompt_digest,
        "example_set_digest": program.example_set_digest,
        "fitted_component_digest": program.fitted_component_digest,
        "configuration_digest": program.configuration_digest,
        "adapter_revision": program.adapter_revision,
        "decision_mapping_digest": program.decision_mapping_digest,
        "input_bundle_digest": program.input_bundle_digest,
        "lineage_manifest_digest": program.lineage_manifest_digest,
    }


def derive_model_program_declaration_digest(program: ModelProgramDeclaration) -> str:
    return canonical.content_digest(_program_value(program))


def _validate_program(program: ModelProgramDeclaration) -> None:
    for field in ("provider", "model", "adapter_revision"):
        _text(getattr(program, field), field)
    for field in (
        "family_contract_digest",
        "program_digest",
        "prompt_digest",
        "configuration_digest",
        "decision_mapping_digest",
        "input_bundle_digest",
        "lineage_manifest_digest",
    ):
        _digest(getattr(program, field), field)
    for field in ("example_set_digest", "fitted_component_digest"):
        value = getattr(program, field)
        if value is not None:
            _digest(value, field)
    expected = derive_model_program_declaration_digest(program)
    if not program.declaration_digest:
        object.__setattr__(program, "declaration_digest", expected)
    elif program.declaration_digest != expected:
        raise ModelContractError("model program declaration digest cannot be re-derived")


def make_model_program_declaration(
    *,
    family_contract_digest: str,
    provider: str,
    model_name: str,
    program_digest: str,
    prompt_digest: str,
    example_set_digest: str | None,
    fitted_component_digest: str | None,
    configuration_digest: str,
    adapter_revision: str,
    decision_mapping_digest: str,
    input_bundle_digest: str,
    lineage_manifest_digest: str,
) -> ModelProgramDeclaration:
    return ModelProgramDeclaration(
        family_contract_digest,
        provider,
        model_name,
        program_digest,
        prompt_digest,
        example_set_digest,
        fitted_component_digest,
        configuration_digest,
        adapter_revision,
        decision_mapping_digest,
        input_bundle_digest,
        lineage_manifest_digest,
        "",
    )


def _lineage_value(lineage: LineageManifest) -> canonical.JsonValue:
    return {
        "arm_id": lineage.arm_id,
        "subject_digest": lineage.subject_digest,
        "uses": tuple(
            {
                "purpose": use.purpose.value,
                "source_population_digest": use.source_population_digest,
                "labels_accessed": use.labels_accessed,
                "influenced_artifact_digest": use.influenced_artifact_digest,
                "population_use_receipt_digest": use.population_use_receipt_digest,
            }
            for use in lineage.uses
        ),
        "manifest_digest": lineage.manifest_digest,
    }


@dataclass(frozen=True)
class ModelRequest:
    request_id: str
    record: EvidenceRecord
    contract: FamilyContract
    residual_question: ResidualQuestion
    completeness: tuple[CompletenessItem, ...]
    packet_digest: str
    family_contract_digest: str
    residual_question_id: str
    completeness_digest: str
    program: ModelProgramDeclaration
    lineage: LineageManifest
    custody_policy_digest: str
    proposal_program_digests: tuple[str, ...]
    trusted_response_store_identities: tuple[str, ...]
    maximum_response_bytes: int

    def __post_init__(self) -> None:
        _validate_request(self)


def _request_value(request: ModelRequest) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": MODEL_REQUEST_SCHEMA,
        "record": _record_value(request.record),
        "contract": _contract_value(request.contract),
        "residual_question": _question_value(request.residual_question),
        "completeness": tuple(_completeness_value(item) for item in request.completeness),
        "packet_digest": request.packet_digest,
        "family_contract_digest": request.family_contract_digest,
        "residual_question_id": request.residual_question_id,
        "completeness_digest": request.completeness_digest,
        "program": _program_value(request.program) | {"declaration_digest": request.program.declaration_digest},
        "lineage": _lineage_value(request.lineage),
        "custody_policy_digest": request.custody_policy_digest,
        "proposal_program_digests": request.proposal_program_digests,
        "trusted_response_store_identities": request.trusted_response_store_identities,
        "maximum_response_bytes": request.maximum_response_bytes,
    }


def derive_model_request_digest(request: ModelRequest) -> str:
    return canonical.content_digest(_request_value(request))


def _validate_lineage(lineage: LineageManifest, subject: str) -> None:
    if not isinstance(lineage, LineageManifest):
        raise ModelContractError("lineage must be a LineageManifest")
    for use in lineage.uses:
        use.__post_init__()
    expected = derive_lineage_manifest_digest(lineage.arm_id, lineage.subject_digest, lineage.uses)
    if lineage.manifest_digest != expected:
        raise ModelContractError("lineage manifest digest cannot be re-derived")
    if lineage.subject_digest != subject:
        raise ModelContractError("lineage subject does not match model input bundle")


def _validate_request_evidence(request: ModelRequest) -> str:
    expected_record_id = derive_record_id(request.record.packet, request.record.decision)
    if request.record.record_id != expected_record_id:
        raise ModelContractError("evidence record identity cannot be re-derived")
    try:
        request.record.__post_init__()
        validate_record(request.contract, request.record)
    except (TypeError, ValueError) as exc:
        raise ModelContractError(f"record or family contract is invalid: {exc}") from exc
    contract_digest = family_contract_digest(request.contract)
    if request.family_contract_digest != contract_digest or request.record.packet.family_contract_digest != contract_digest:
        raise ModelContractError("family contract digest does not match request content")
    if request.packet_digest != derive_packet_digest(request.record.packet):
        raise ModelContractError("packet digest does not match request record")
    questions = tuple(item for item in request.contract.residual_questions if item.question_id == request.residual_question_id)
    if len(questions) != 1 or request.residual_question != questions[0]:
        raise ModelContractError("residual question is not the exact declared family question")
    expected_completeness = completeness_snapshot(request.record, request.contract)
    if request.completeness != expected_completeness:
        raise ModelContractError("completeness snapshot does not match the evidence record")
    if request.completeness_digest != derive_completeness_digest(request.completeness):
        raise ModelContractError("completeness digest cannot be re-derived")
    return contract_digest


def _validate_request_program(request: ModelRequest, contract_digest: str) -> None:
    request.program.__post_init__()
    expected_bundle = derive_model_input_bundle_digest(request.record, request.contract, request.residual_question, request.completeness)
    if request.program.input_bundle_digest != expected_bundle:
        raise ModelContractError("program input bundle does not match request content")
    if request.program.family_contract_digest != contract_digest:
        raise ModelContractError("program family contract does not match request")
    _validate_lineage(request.lineage, expected_bundle)
    if request.program.lineage_manifest_digest != request.lineage.manifest_digest:
        raise ModelContractError("program lineage manifest does not match request lineage")


def _validate_request_policy(request: ModelRequest) -> None:
    _digest(request.custody_policy_digest, "custody_policy_digest")
    _digest_tuple(request.proposal_program_digests, "proposal_program_digests")
    _text_tuple(request.trusted_response_store_identities, "trusted_response_store_identities")
    invalid_maximum = isinstance(request.maximum_response_bytes, bool) or not isinstance(request.maximum_response_bytes, int)
    if invalid_maximum or request.maximum_response_bytes <= 0:
        raise ModelContractError("maximum_response_bytes must be a positive integer")
    expected = derive_model_request_digest(request)
    if not request.request_id:
        object.__setattr__(request, "request_id", expected)
    elif request.request_id != expected:
        raise ModelContractError("model request digest cannot be re-derived")


def _validate_request(request: ModelRequest) -> None:
    contract_digest = _validate_request_evidence(request)
    _validate_request_program(request, contract_digest)
    _validate_request_policy(request)


def make_model_request(
    *,
    record: EvidenceRecord,
    contract: FamilyContract,
    residual_question_id: str,
    program: ModelProgramDeclaration,
    lineage: LineageManifest,
    custody_policy_digest: str,
    proposal_program_digests: tuple[str, ...],
    trusted_response_store_identities: tuple[str, ...],
    maximum_response_bytes: int,
) -> ModelRequest:
    questions = tuple(item for item in contract.residual_questions if item.question_id == residual_question_id)
    if len(questions) != 1:
        raise ModelContractError("residual question is not declared exactly once")
    completeness = completeness_snapshot(record, contract)
    return ModelRequest(
        "",
        record,
        contract,
        questions[0],
        completeness,
        derive_packet_digest(record.packet),
        family_contract_digest(contract),
        residual_question_id,
        derive_completeness_digest(completeness),
        program,
        lineage,
        custody_policy_digest,
        proposal_program_digests,
        trusted_response_store_identities,
        maximum_response_bytes,
    )


def model_request_bytes(request: ModelRequest) -> bytes:
    if not isinstance(request, ModelRequest):
        raise ModelContractError("request must be a ModelRequest")
    _validate_request(request)
    return canonical.canonical_bytes(_request_value(request) | {"request_id": request.request_id})
