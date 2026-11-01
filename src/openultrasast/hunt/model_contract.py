"""Translate injected hunt executor I/O into reproducible core model records.

Prompt rendering, provider execution, caching, parsing, storage, and redaction stay
outside this module.  The adapter only freezes the structured handoff and asks the
dependency-free core to validate the returned identities and outcome.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from openultrasast.core import canonical, model
from openultrasast.core.evidence import EvidenceRecord
from openultrasast.core.family import FamilyContract, ResidualQuestion
from openultrasast.core.provenance import ModelCallIdentity
from openultrasast.core.semantics import FieldValue


@dataclass(frozen=True)
class ExecutorModelInput:
    """Frozen structured input from which hunt-owned code may render a prompt."""

    request_digest: str
    packet_digest: str
    family_contract_digest: str
    residual_question_id: str
    completeness_digest: str
    program_declaration_digest: str
    record: EvidenceRecord
    contract: FamilyContract
    residual_question: ResidualQuestion
    completeness: tuple[model.CompletenessItem, ...]


@dataclass(frozen=True)
class ExecutorModelOutput:
    """Untrusted structured output supplied by the hunt-owned executor."""

    request_digest: str
    packet_digest: str
    provider: str
    model: str
    program_digest: str
    prompt_digest: str
    configuration_digest: str
    adapter_revision: str
    status: str
    normalized_fields: tuple[FieldValue, ...]
    inline_redacted_text: str | None
    artifact: canonical.ContentRef | None
    redaction_policy_digest: str | None
    family_decision: str | None
    decision_mapping_digest: str | None
    failure_reason: str | None


ModelExecutor = Callable[[ExecutorModelInput], ExecutorModelOutput]


def model_executor_input(request: model.ModelRequest) -> ExecutorModelInput:
    """Validate and freeze a core request for hunt-owned prompt/execution code."""
    model.model_request_bytes(request)
    return ExecutorModelInput(
        request.request_id,
        request.packet_digest,
        request.family_contract_digest,
        request.residual_question_id,
        request.completeness_digest,
        request.program.declaration_digest,
        request.record,
        request.contract,
        request.residual_question,
        request.completeness,
    )


def _response(output: ExecutorModelOutput) -> model.PreservedModelResponse | None:
    absent = (
        not output.normalized_fields
        and output.inline_redacted_text is None
        and output.artifact is None
        and output.redaction_policy_digest is None
    )
    if absent:
        return None
    if output.redaction_policy_digest is None:
        raise model.ModelContractError("preserved executor response requires redaction_policy_digest")
    return model.make_preserved_model_response(
        normalized_fields=output.normalized_fields,
        inline_redacted_text=output.inline_redacted_text,
        artifact=output.artifact,
        redaction_policy_digest=output.redaction_policy_digest,
    )


def _status(value: str) -> model.ModelStatus:
    try:
        return model.ModelStatus(value)
    except (TypeError, ValueError) as exc:
        raise model.ModelContractError("executor status must be succeeded or failed") from exc


def _result(output: ExecutorModelOutput) -> model.ModelResult:
    if type(output) is not ExecutorModelOutput:
        raise model.ModelContractError("executor must return an exact ExecutorModelOutput")
    return model.ModelResult(
        output.request_digest,
        output.packet_digest,
        ModelCallIdentity(
            output.provider,
            output.model,
            output.program_digest,
            output.prompt_digest,
            output.configuration_digest,
            output.adapter_revision,
        ),
        _status(output.status),
        _response(output),
        output.family_decision,
        output.decision_mapping_digest,
        output.failure_reason,
        "",
    )


def execute_model_contract(
    request: model.ModelRequest,
    executor: ModelExecutor,
    resolver: canonical.ContentResolver,
) -> model.ModelResult:
    """Execute once through an injected hunt boundary and validate the exact result."""
    frozen = model_executor_input(request)
    result = _result(executor(frozen))
    model.validate_model_result(request, result, resolver)
    return result


__all__ = [
    "ExecutorModelInput",
    "ExecutorModelOutput",
    "ModelExecutor",
    "execute_model_contract",
    "model_executor_input",
]
