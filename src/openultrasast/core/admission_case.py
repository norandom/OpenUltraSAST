"""Immutable admission-case contracts and canonical commitments."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core._admission_case_shape import admission_case_problem
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_review import AdmissionManifestV2
from openultrasast.core.admission_spend import AdmissionPreparation, validate_pre_label_spend
from openultrasast.core.budget import BudgetDerivation, ChangeComplexity
from openultrasast.core.coverage import CoverageFunnel, InputManifest, InputReadReceipt
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.measurement import DenominatorPolicy, ScopeKey
from openultrasast.core.proof import ProofAttachment
from openultrasast.core.readiness import ReadinessResult
from openultrasast.core.validation import EvidenceValidationInput
from openultrasast.core.verdict import BoundedSatisfaction, BoundedSilence, DefectClaim

ADMISSION_CASE_RELEASE_SCHEMA = "openultrasast.detection-core.admission-case-release.v2"
ADMISSION_CASE_RELEASE_PAYLOAD_SCHEMA = "openultrasast.detection-core.admission-case-release-payload.v2"
RELEASED_CASE_BINDING_SCHEMA = "openultrasast.detection-core.released-case-binding.v2"


class AdmissionCaseReleaseError(ValueError):
    """The post-spend case release cannot authorize admission scoring."""


class AdmissionCaseRole(Enum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    ORDINARY = "ordinary"


@dataclass(frozen=True)
class AdmissionCaseResult:
    case_id_digest: str
    scope: ScopeKey
    role: AdmissionCaseRole
    pair_id_digest: str | None
    evidence_inputs: tuple[EvidenceValidationInput, ...]
    defect_claims: tuple[DefectClaim, ...]
    satisfactions: tuple[BoundedSatisfaction, ...]
    silence: tuple[BoundedSilence, ...]
    proof_attachments: tuple[ProofAttachment, ...]
    coverage: CoverageFunnel
    input_manifest: InputManifest
    input_receipts: tuple[InputReadReceipt, ...]
    complexity: ChangeComplexity
    budget: BudgetDerivation
    total_reply_ms: int
    result_digest: str


@dataclass(frozen=True)
class ReleasedCaseBinding:
    case_id_digest: str
    scope: ScopeKey
    role: AdmissionCaseRole
    pair_id_digest: str | None
    case_result_digest: str
    evidence_input_digests: tuple[str, ...]
    change_input_digests: tuple[str, ...]
    input_manifest_digest: str
    binding_digest: str


@dataclass(frozen=True)
class AdmissionCaseRelease:
    schema_version: str
    population_digest: str
    manifest_digest: str
    authorization_digest: str
    preparation_digest: str
    label_release_receipt_digest: str
    custodian_identity: str
    bindings: tuple[ReleasedCaseBinding, ...]
    release_payload_digest: str
    review: IndependenceAttestation
    release_digest: str


def _coverage_value(value: CoverageFunnel) -> canonical.JsonValue:
    return {
        "inputs_read": value.inputs_read,
        "questions_formed": value.questions_formed,
        "sites_considered": value.sites_considered,
        "sites_recognized": value.sites_recognized,
        "transitions_materialized": value.transitions_materialized,
        "security_objects_constructed": value.security_objects_constructed,
        "constraints_evaluated": value.constraints_evaluated,
        "determinate_outcomes": value.determinate_outcomes,
        "findings_emitted": value.findings_emitted,
        "relation_status_counts": tuple((item.status.value, item.count) for item in value.relation_status_counts),
        "unresolved_by_reason": tuple((item.reason, item.count) for item in value.unresolved_by_reason),
    }


def derive_case_coverage_digest(case_id_digest: str, scope: ScopeKey, coverage: CoverageFunnel) -> str:
    return canonical.content_digest(
        {
            "case_id_digest": case_id_digest,
            "scope": {"family_id": scope.family_id, "ecosystem": scope.ecosystem},
            "coverage": _coverage_value(coverage),
        }
    )


def _claim_value(value: DefectClaim) -> canonical.JsonValue:
    location = value.location
    return {
        "record_id": value.record.record_id,
        "basis": value.basis.value,
        "location": {"path": location.path, "line": location.line, "column": location.column, "symbol": location.symbol},
        "anchor": (value.change_anchor.path, value.change_anchor.start_line, value.change_anchor.end_line),
    }


def derive_admission_case_result_digest(value: AdmissionCaseResult) -> str:
    return canonical.content_digest(
        {
            "case_id_digest": value.case_id_digest,
            "scope": (value.scope.family_id, value.scope.ecosystem),
            "role": value.role.value,
            "pair_id_digest": value.pair_id_digest,
            "evidence_input_digests": tuple(item.input_digest for item in value.evidence_inputs),
            "defect_claims": tuple(_claim_value(item) for item in value.defect_claims),
            "satisfactions": tuple((item.question_ids, tuple(record.record_id for record in item.records)) for item in value.satisfactions),
            "silence": tuple(
                (item.question_ids, item.reasons, item.evidence_record_digests, item.coverage_digest) for item in value.silence
            ),
            "proof_attachment_ids": tuple(item.proof_id for item in value.proof_attachments),
            "coverage": _coverage_value(value.coverage),
            "input_manifest_digest": value.input_manifest.manifest_digest,
            "input_receipts": tuple(
                (item.input_id, item.path, item.opened, item.byte_count, item.content_digest) for item in value.input_receipts
            ),
            "complexity": (
                value.complexity.change_id,
                value.complexity.workload_class,
                value.complexity.changed_regions,
                value.complexity.transition_count,
                value.complexity.changed_bytes,
                value.complexity.measurement.content_digest,
            ),
            "budget_derivation_digest": value.budget.derivation_digest,
            "total_reply_ms": value.total_reply_ms,
        }
    )


def validate_admission_case_shape(value: AdmissionCaseResult) -> None:
    problem = admission_case_problem(value, AdmissionCaseResult, AdmissionCaseRole)
    if problem is not None:
        raise ValueError(f"closed admission case violation: {problem}")


def create_admission_case_result(**values: object) -> AdmissionCaseResult:
    draft = AdmissionCaseResult(**values, result_digest="0" * 64)  # type: ignore[arg-type]
    validate_admission_case_shape(draft)
    return AdmissionCaseResult(**values, result_digest=derive_admission_case_result_digest(draft))  # type: ignore[arg-type]


def _scope_value(scope: ScopeKey) -> dict[str, canonical.JsonValue]:
    return {"family_id": scope.family_id, "ecosystem": scope.ecosystem}


def _binding_value(binding: ReleasedCaseBinding) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": RELEASED_CASE_BINDING_SCHEMA,
        "case_id_digest": binding.case_id_digest,
        "scope": _scope_value(binding.scope),
        "role": binding.role.value,
        "pair_id_digest": binding.pair_id_digest,
        "case_result_digest": binding.case_result_digest,
        "evidence_input_digests": binding.evidence_input_digests,
        "change_input_digests": binding.change_input_digests,
        "input_manifest_digest": binding.input_manifest_digest,
    }


def derive_released_case_binding_digest(binding: ReleasedCaseBinding) -> str:
    return canonical.content_digest(_binding_value(binding))


def _content_ref_value(reference: canonical.ContentRef) -> dict[str, canonical.JsonValue]:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _review_value(review: IndependenceAttestation) -> dict[str, canonical.JsonValue]:
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": _content_ref_value(review.conflict_disclosure),
        "attestation_digest": review.attestation_digest,
    }


def _release_payload_value(release: AdmissionCaseRelease) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": ADMISSION_CASE_RELEASE_PAYLOAD_SCHEMA,
        "release_schema_version": release.schema_version,
        "population_digest": release.population_digest,
        "manifest_digest": release.manifest_digest,
        "authorization_digest": release.authorization_digest,
        "preparation_digest": release.preparation_digest,
        "label_release_receipt_digest": release.label_release_receipt_digest,
        "custodian_identity": release.custodian_identity,
        "bindings": tuple({**_binding_value(item), "binding_digest": item.binding_digest} for item in release.bindings),
    }


def derive_admission_case_release_payload_digest(release: AdmissionCaseRelease) -> str:
    return canonical.content_digest(_release_payload_value(release))


def derive_admission_case_release_digest(release: AdmissionCaseRelease) -> str:
    return canonical.content_digest(
        {
            "schema_version": ADMISSION_CASE_RELEASE_SCHEMA,
            "release_payload_digest": release.release_payload_digest,
            "review": _review_value(release.review),
        }
    )


def validate_admission_case_release(
    manifest: AdmissionManifestV2,
    denominator: DenominatorPolicy,
    readiness: Sequence[ReadinessResult],
    context: AdmissionValidationContext,
    preparation: AdmissionPreparation,
    receipt: PopulationUseReceipt,
    release: AdmissionCaseRelease,
    cases: Sequence[AdmissionCaseResult],
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionCaseRelease:
    """Validate the custodian's exact post-spend case-to-operational-input mapping."""
    from openultrasast.core._admission_release import (
        _validate_header,
        _validate_policy,
        _validate_release_shape,
        _validate_review,
        validate_case_bindings,
    )

    try:
        authorization = validate_pre_label_spend(
            manifest,
            denominator,
            readiness,
            context,
            preparation,
            receipt,
            custody,
            resolver,
        )
        _validate_policy(context.admission_review_policy)
        _validate_release_shape(release)
        _validate_header(manifest, preparation, receipt, authorization, release)
        _validate_review(release, receipt, context.admission_review_policy, resolver)
        validate_case_bindings(release, cases, context, custody, resolver)
        return release
    except AdmissionCaseReleaseError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise AdmissionCaseReleaseError(f"admission case release refused: {exc}") from exc
