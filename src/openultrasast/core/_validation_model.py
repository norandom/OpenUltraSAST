"""Model-derivation replay for the closed evidence validation seam."""

from __future__ import annotations

from dataclasses import fields

from openultrasast.core import canonical
from openultrasast.core.custody import PopulationCustodyPolicy, PopulationCustodyPort
from openultrasast.core.evidence import EvidenceBasis, EvidenceRecord, evidence_record_bytes
from openultrasast.core.family import FamilyContract
from openultrasast.core.lineage import LineageManifest
from openultrasast.core.model import ModelProgramDeclaration, ModelRequest, ModelResult
from openultrasast.core.model_apply import apply_model_result


class ModelReplayValidationError(ValueError):
    """A model-derived record cannot be reproduced from its closed context."""


def _require_exact_program(
    request: ModelRequest,
    programs: tuple[ModelProgramDeclaration, ...],
) -> None:
    matches = tuple(item for item in programs if item.declaration_digest == request.program.declaration_digest)
    if len(matches) != 1 or matches[0] != request.program:
        raise ModelReplayValidationError("model declaration is not an exact validation-context member")


def _require_exact_lineage(request: ModelRequest, lineages: tuple[LineageManifest, ...]) -> None:
    matches = tuple(item for item in lineages if item.manifest_digest == request.lineage.manifest_digest)
    if len(matches) != 1 or matches[0] != request.lineage:
        raise ModelReplayValidationError("model lineage is not an exact validation-context member")


def _require_deterministic_shape(record: EvidenceRecord) -> None:
    if record.decision.basis is not EvidenceBasis.DETERMINISTIC:
        raise ModelReplayValidationError("model request must start from a deterministic record")
    provenance = record.decision.provenance
    if any(getattr(provenance, item.name) is not None for item in fields(provenance)):
        raise ModelReplayValidationError("deterministic record contains model, proof, or lineage provenance")


def _same_canonical_record(expected: EvidenceRecord, supplied: EvidenceRecord) -> bool:
    return expected.record_id == supplied.record_id and evidence_record_bytes(expected) == evidence_record_bytes(supplied)


def validate_and_replay_model_derivation(
    supplied: EvidenceRecord,
    request: ModelRequest | None,
    result: ModelResult | None,
    contract: FamilyContract,
    programs: tuple[ModelProgramDeclaration, ...],
    lineages: tuple[LineageManifest, ...],
    resolver: canonical.ContentResolver,
    custody: PopulationCustodyPort,
    custody_policy: PopulationCustodyPolicy,
) -> EvidenceRecord:
    """Validate the envelope shape and replay model corroboration when present."""
    if supplied.decision.basis is EvidenceBasis.DETERMINISTIC:
        if request is not None or result is not None:
            raise ModelReplayValidationError("deterministic records must omit model request and result")
        _require_deterministic_shape(supplied)
        return supplied
    if supplied.decision.basis is not EvidenceBasis.MODEL_CORROBORATED:
        raise ModelReplayValidationError("execution-backed records require later proof replay")
    if request is None or result is None:
        raise ModelReplayValidationError("model-corroborated records require both request and result")
    _require_deterministic_shape(request.record)
    _require_exact_program(request, programs)
    _require_exact_lineage(request, lineages)
    derived = apply_model_result(request.record, contract, request, result, resolver, custody, custody_policy)
    if derived.decision.basis is not EvidenceBasis.MODEL_CORROBORATED:
        raise ModelReplayValidationError("model result did not derive a model-corroborated record")
    if not _same_canonical_record(derived, supplied):
        raise ModelReplayValidationError("model-derived record does not match canonical replay")
    return supplied


__all__ = ["ModelReplayValidationError", "validate_and_replay_model_derivation"]
