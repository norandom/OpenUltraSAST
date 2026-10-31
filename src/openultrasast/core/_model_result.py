"""Preserved model response and result validation internals."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from openultrasast.core import canonical
from openultrasast.core._model_common import ModelContractError
from openultrasast.core._model_common import require_digest as _digest
from openultrasast.core._model_common import require_text as _text
from openultrasast.core.provenance import ModelCallIdentity
from openultrasast.core.semantics import FieldValue

if TYPE_CHECKING:
    from openultrasast.core.model import ModelProgramDeclaration, ModelRequest

MODEL_RESPONSE_SCHEMA = "openultrasast.detection-core.model-response.v2"
MODEL_RESULT_SCHEMA = "openultrasast.detection-core.model-result.v2"


class ModelStatus(Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class PreservedModelResponse:
    schema_version: str
    normalized_fields: tuple[FieldValue, ...]
    inline_redacted_text: str | None
    artifact: canonical.ContentRef | None
    content_digest: str
    redaction_policy_digest: str

    def __post_init__(self) -> None:
        _validate_response(self)


def _content_ref_value(reference: canonical.ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _response_value(response: PreservedModelResponse) -> canonical.JsonValue:
    artifact: canonical.JsonValue = None if response.artifact is None else _content_ref_value(response.artifact)
    return {
        "schema_version": response.schema_version,
        "normalized_fields": tuple(
            {"name": item.name, "kind": item.kind.value, "value": item.value} for item in response.normalized_fields
        ),
        "inline_redacted_text": response.inline_redacted_text,
        "artifact": artifact,
        "content_digest": response.content_digest,
        "redaction_policy_digest": response.redaction_policy_digest,
    }


def _validate_response(response: PreservedModelResponse) -> None:
    if response.schema_version != MODEL_RESPONSE_SCHEMA:
        raise ModelContractError("unknown preserved response schema")
    if not isinstance(response.normalized_fields, tuple) or not all(isinstance(item, FieldValue) for item in response.normalized_fields):
        raise ModelContractError("normalized response fields must be a tuple of FieldValue values")
    for item in response.normalized_fields:
        item.__post_init__()
    names = tuple(item.name for item in response.normalized_fields)
    if len(set(names)) != len(names):
        raise ModelContractError("normalized response field names must be unique")
    inline = response.inline_redacted_text
    artifact = response.artifact
    if (inline is None) == (artifact is None):
        raise ModelContractError("response requires exactly one inline or artifact preservation form")
    if inline is not None:
        _text(inline, "inline redacted response")
        expected = canonical.bytes_digest(inline.encode("utf-8"))
    else:
        if not isinstance(artifact, canonical.ContentRef):
            raise ModelContractError("response artifact must be a ContentRef")
        artifact.__post_init__()
        expected = artifact.content_digest
    _digest(response.redaction_policy_digest, "redaction_policy_digest")
    if not response.content_digest:
        object.__setattr__(response, "content_digest", expected)
    elif response.content_digest != expected:
        raise ModelContractError("response content digest cannot be re-derived")


def make_preserved_model_response(
    *,
    normalized_fields: tuple[FieldValue, ...],
    inline_redacted_text: str | None,
    artifact: canonical.ContentRef | None,
    redaction_policy_digest: str,
) -> PreservedModelResponse:
    return PreservedModelResponse(
        MODEL_RESPONSE_SCHEMA,
        normalized_fields,
        inline_redacted_text,
        artifact,
        "",
        redaction_policy_digest,
    )


@dataclass(frozen=True)
class ModelResult:
    request_digest: str
    packet_digest: str
    identity: ModelCallIdentity
    status: ModelStatus
    response: PreservedModelResponse | None
    family_decision: str | None
    decision_mapping_digest: str | None
    failure_reason: str | None
    result_digest: str

    def __post_init__(self) -> None:
        _validate_result_shape(self)


def _identity_value(identity: ModelCallIdentity) -> canonical.JsonValue:
    return {
        "provider": identity.provider,
        "model": identity.model,
        "program_digest": identity.program_digest,
        "prompt_digest": identity.prompt_digest,
        "configuration_digest": identity.configuration_digest,
        "adapter_revision": identity.adapter_revision,
    }


def _result_value(result: ModelResult) -> dict[str, canonical.JsonValue]:
    response: canonical.JsonValue = None if result.response is None else _response_value(result.response)
    return {
        "schema_version": MODEL_RESULT_SCHEMA,
        "request_digest": result.request_digest,
        "packet_digest": result.packet_digest,
        "identity": _identity_value(result.identity),
        "status": result.status.value,
        "response": response,
        "family_decision": result.family_decision,
        "decision_mapping_digest": result.decision_mapping_digest,
        "failure_reason": result.failure_reason,
    }


def derive_model_result_digest(result: ModelResult) -> str:
    return canonical.content_digest(_result_value(result))


def _validate_result_outcome(result: ModelResult) -> None:
    if result.status is ModelStatus.SUCCEEDED:
        if result.response is None:
            raise ModelContractError("successful result requires a preserved response")
        _text(result.family_decision, "family_decision")
        _digest(result.decision_mapping_digest, "decision_mapping_digest")
        if result.failure_reason is not None:
            raise ModelContractError("successful result forbids a failure reason")
    else:
        _text(result.failure_reason, "failure_reason")
        if result.family_decision is not None or result.decision_mapping_digest is not None:
            raise ModelContractError("failed result forbids a family decision and mapping")


def _validate_result_shape(result: ModelResult) -> None:
    _digest(result.request_digest, "request_digest")
    _digest(result.packet_digest, "packet_digest")
    if not isinstance(result.identity, ModelCallIdentity):
        raise ModelContractError("result identity must be a ModelCallIdentity")
    result.identity.__post_init__()
    if not isinstance(result.status, ModelStatus):
        raise ModelContractError("result status must be a ModelStatus")
    if result.response is not None:
        if not isinstance(result.response, PreservedModelResponse):
            raise ModelContractError("result response must be a PreservedModelResponse")
        result.response.__post_init__()
    _validate_result_outcome(result)
    expected = derive_model_result_digest(result)
    if not result.result_digest:
        object.__setattr__(result, "result_digest", expected)
    elif result.result_digest != expected:
        raise ModelContractError("model result digest cannot be re-derived")


def _program_identity(program: ModelProgramDeclaration) -> ModelCallIdentity:
    return ModelCallIdentity(
        program.provider,
        program.model,
        program.program_digest,
        program.prompt_digest,
        program.configuration_digest,
        program.adapter_revision,
    )


def make_model_result(
    *,
    request: ModelRequest,
    status: ModelStatus,
    response: PreservedModelResponse | None,
    family_decision: str | None,
    failure_reason: str | None,
) -> ModelResult:
    mapping = request.program.decision_mapping_digest if status is ModelStatus.SUCCEEDED else None
    return ModelResult(
        request.request_id,
        request.packet_digest,
        _program_identity(request.program),
        status,
        response,
        family_decision,
        mapping,
        failure_reason,
        "",
    )


def _validate_response_bytes(
    request: ModelRequest,
    response: PreservedModelResponse,
    resolver: canonical.ContentResolver,
) -> None:
    response.__post_init__()
    if response.inline_redacted_text is not None:
        if len(response.inline_redacted_text.encode("utf-8")) > request.maximum_response_bytes:
            raise ModelContractError("inline response exceeds request maximum_response_bytes")
        return
    assert response.artifact is not None
    try:
        canonical.resolve_content(
            response.artifact,
            resolver,
            trusted_store_identities=request.trusted_response_store_identities,
            maximum_bytes=request.maximum_response_bytes,
        )
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError) as exc:
        raise ModelContractError(f"response artifact cannot be validated: {exc}") from exc


def validate_model_result(request: ModelRequest, result: ModelResult, resolver: canonical.ContentResolver) -> None:
    """Revalidate a preserved result against its exact frozen request identities."""
    from openultrasast.core.model import ModelRequest, _validate_request

    if not isinstance(request, ModelRequest) or not isinstance(result, ModelResult):
        raise ModelContractError("request and result must use model handoff contract types")
    if result.request_digest != request.request_id:
        raise ModelContractError("result request digest does not match request")
    if result.packet_digest != request.packet_digest:
        raise ModelContractError("result packet digest does not match request")
    if result.identity != _program_identity(request.program):
        raise ModelContractError("result program identity does not match frozen declaration")
    if result.status is ModelStatus.SUCCEEDED:
        if result.decision_mapping_digest != request.program.decision_mapping_digest:
            raise ModelContractError("result decision mapping does not match frozen declaration")
        if result.family_decision not in request.residual_question.allowed_decisions:
            raise ModelContractError("result family decision is not allowed by the residual question")
    if result.response is not None:
        _validate_response_bytes(request, result.response, resolver)
    _validate_request(request)
    _validate_result_shape(result)


def model_result_bytes(result: ModelResult) -> bytes:
    if not isinstance(result, ModelResult):
        raise ModelContractError("result must be a ModelResult")
    _validate_result_shape(result)
    return canonical.canonical_bytes(_result_value(result) | {"result_digest": result.result_digest})


__all__ = [
    "ModelResult",
    "PreservedModelResponse",
    "derive_model_result_digest",
    "make_model_result",
    "make_preserved_model_response",
    "model_result_bytes",
    "validate_model_result",
]
