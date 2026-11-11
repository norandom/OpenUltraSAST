"""Released proof-candidate continuity for evaluation admission V3."""

from __future__ import annotations

from openultrasast.core import canonical
from openultrasast.core._evaluation_proof_plan import (
    EvaluationProofPlanError,
    derive_released_combination_case,
    validate_plan_case_binding,
    validate_reviewed_proof_plan,
)
from openultrasast.core._evaluation_release_validation import _validate_release_review
from openultrasast.core.admission_case import derive_admission_case_result_digest
from openultrasast.core.admission_context import (
    AdmissionValidationContext,
    _validate_context,
    derive_admission_validation_context_digest,
)
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionPolicyV3
from openultrasast.core.evaluation_combination import CombinedCaseOutcomeV3
from openultrasast.core.evaluation_measurement import ArmKindV3
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    EvaluationReleaseError,
    ProofCandidateIdentityV3,
    ReleasedArmCaseBindingV3,
    _legacy_case,
    derive_proof_candidate_identity_digest,
)
from openultrasast.core.evidence import EvidenceBasis
from openultrasast.core.proof import (
    ProofAttachment,
    ProofTrustPolicy,
    ProofValidationError,
    attach_differential_proof,
    validate_differential_proof,
)
from openultrasast.core.semantics import SourceLocation
from openultrasast.core.verdict import DefectClaim

_LOCATION_SCHEMA = "openultrasast.detection-core.finding-location.v3"


class EvaluationProofContinuityError(ValueError):
    """Released proof material is absent, transferred, or contradictory."""


def derive_finding_location_digest(location: SourceLocation) -> str:
    """Bind the exact source-location fields used by a proof attachment."""

    if type(location) is not SourceLocation:
        raise EvaluationProofContinuityError("finding location must use exact SourceLocation")
    try:
        location.__post_init__()
    except (TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"finding location is malformed: {exc}") from exc
    return canonical.content_digest(
        {
            "schema_version": _LOCATION_SCHEMA,
            "path": location.path,
            "line": location.line,
            "column": location.column,
            "symbol": location.symbol,
        }
    )


def _validate_case_binding(case: ArmAdmissionCaseResultV3, binding: ReleasedArmCaseBindingV3) -> None:
    if type(case) is not ArmAdmissionCaseResultV3 or type(binding) is not ReleasedArmCaseBindingV3:
        raise EvaluationProofContinuityError("proof continuity requires exact released V3 case and binding values")
    try:
        case.__post_init__()
        binding.__post_init__()
    except (TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"released proof case or binding is malformed: {exc}") from exc
    if case.result_digest != derive_admission_case_result_digest(_legacy_case(case)):
        raise EvaluationProofContinuityError("released proof case result digest cannot be re-derived")
    evidence = tuple(sorted(item.input_digest for item in case.evidence_inputs))
    changes = tuple(sorted({item.record.packet.provenance.change_input_digest for item in case.evidence_inputs}))
    candidate_digest = case.proof_candidate.candidate_digest if case.proof_candidate is not None else None
    expected = (
        case.key,
        case.observation_slot_digest,
        case.observation_digest,
        case.underlying_push_digest,
        case.case_id_digest,
        case.case_input_digest,
        case.outcome_projection,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        evidence,
        changes,
        case.input_manifest.manifest_digest,
        candidate_digest,
    )
    actual = (
        binding.key,
        binding.observation_slot_digest,
        binding.observation_digest,
        binding.underlying_push_digest,
        binding.case_id_digest,
        binding.case_input_digest,
        binding.outcome_projection,
        binding.role,
        binding.pair_id_digest,
        binding.case_result_digest,
        binding.evidence_input_digests,
        binding.change_input_digests,
        binding.input_manifest_digest,
        binding.proof_candidate_digest,
    )
    if actual != expected:
        raise EvaluationProofContinuityError("released proof case differs from its canonical binding")


def _validate_candidate(candidate: ProofCandidateIdentityV3) -> None:
    if type(candidate) is not ProofCandidateIdentityV3:
        raise EvaluationProofContinuityError("proof candidate must use exact ProofCandidateIdentityV3")
    try:
        candidate.__post_init__()
        expected = derive_proof_candidate_identity_digest(candidate)
    except (TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"proof candidate identity is malformed: {exc}") from exc
    if candidate.candidate_digest != expected:
        raise EvaluationProofContinuityError("proof candidate identity cannot be re-derived")


def validate_combined_proof_retention_v3(
    combined: CombinedCaseOutcomeV3,
    candidate: ProofCandidateIdentityV3 | None,
) -> None:
    """Require a combined candidate to be identical to one named component candidate."""

    if type(combined) is not CombinedCaseOutcomeV3:
        raise EvaluationProofContinuityError("combined proof retention requires exact CombinedCaseOutcomeV3")
    try:
        combined.__post_init__()
    except (TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"combined proof lineage row is malformed: {exc}") from exc
    if candidate is None:
        if combined.retained_proof_candidate_digest is not None:
            raise EvaluationProofContinuityError("combined lineage retains proof without a released candidate")
        return
    _validate_candidate(candidate)
    if combined.retained_proof_candidate_digest != candidate.candidate_digest:
        raise EvaluationProofContinuityError("combined retained candidate differs from its lineage row")
    matches = tuple(
        component
        for component in combined.components
        if (
            component.component_arm_id,
            component.observation_digest,
            component.scope,
            component.proof_candidate_digest,
        )
        == (
            candidate.component_arm_id,
            candidate.observation_digest,
            candidate.scope,
            candidate.candidate_digest,
        )
    )
    if len(matches) != 1 or candidate.family_id != combined.key.scope.family_id:
        raise EvaluationProofContinuityError("combined candidate must be identical to one candidate from a named component observation")


def _validate_candidate_origin(
    case: ArmAdmissionCaseResultV3,
    candidate: ProofCandidateIdentityV3,
    combination_case: CombinedCaseOutcomeV3 | None,
) -> None:
    combined = case.outcome_projection.policy is CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE
    if not combined:
        if combination_case is not None:
            raise EvaluationProofContinuityError("component proof candidate cannot use combined lineage")
        if (candidate.component_arm_id, candidate.observation_digest) != (case.key.arm_id, case.observation_digest):
            raise EvaluationProofContinuityError("component proof candidate belongs to another arm or observation")
        return
    if combination_case is None:
        raise EvaluationProofContinuityError("combined proof candidate requires its exact combination lineage row")
    _validate_combination_case(case, combination_case)
    if combination_case.retained_proof_candidate_digest != candidate.candidate_digest:
        raise EvaluationProofContinuityError("combined proof candidate differs from its exact released case lineage")
    validate_combined_proof_retention_v3(combination_case, candidate)


def _validate_combination_case(
    case: ArmAdmissionCaseResultV3,
    combination_case: CombinedCaseOutcomeV3,
) -> None:
    if type(combination_case) is not CombinedCaseOutcomeV3:
        raise EvaluationProofContinuityError("combined proof continuity requires an exact combination lineage row")
    expected = (
        case.key,
        case.case_id_digest,
        case.case_input_digest,
        case.observation_digest,
        case.outcome_projection.projection_digest,
    )
    actual = (
        combination_case.key,
        combination_case.case_id_digest,
        combination_case.case_input_digest,
        combination_case.observation_digest,
        combination_case.combined_projection_digest,
    )
    if actual != expected:
        raise EvaluationProofContinuityError("combined proof lineage differs from its exact released case")


def _candidate_claim(
    case: ArmAdmissionCaseResultV3,
    binding: ReleasedArmCaseBindingV3,
    candidate: ProofCandidateIdentityV3,
) -> tuple[int, DefectClaim]:
    if binding.proof_candidate_digest != candidate.candidate_digest:
        raise EvaluationProofContinuityError("proof candidate differs from its released binding")
    if candidate.family_id != candidate.scope.family_id or candidate.scope != case.key.scope:
        raise EvaluationProofContinuityError("proof candidate family or scope differs from its released case")
    if candidate.change_input_digest not in binding.change_input_digests:
        raise EvaluationProofContinuityError("proof candidate change input differs from its released case")
    matches = tuple(
        (index, claim)
        for index, claim in enumerate(case.claims)
        if derive_finding_location_digest(claim.location) == candidate.finding_location_digest
    )
    if len(matches) != 1:
        raise EvaluationProofContinuityError("proof candidate must identify exactly one released defect claim")
    index, claim = matches[0]
    record = claim.record
    identity = (
        record.packet.family_id,
        record.packet.ecosystem,
        record.packet.provenance.change_input_digest,
    )
    expected = (candidate.family_id, candidate.scope.ecosystem, candidate.change_input_digest)
    if identity != expected:
        raise EvaluationProofContinuityError("proof candidate family, scope, or input differs from its exact claim")
    return index, claim


def _release_bound_proof_policy(
    release: AdmissionCaseReleaseV3,
    plan: EvaluationPlanManifestV3,
    context: AdmissionValidationContext,
    authority: EvaluationAdmissionAuthorityV3,
    resolver: canonical.ContentResolver,
) -> ProofTrustPolicy:
    if (
        type(release) is not AdmissionCaseReleaseV3
        or type(plan) is not EvaluationPlanManifestV3
        or type(context) is not AdmissionValidationContext
        or type(authority) is not EvaluationAdmissionAuthorityV3
    ):
        raise EvaluationProofContinuityError(
            "proof continuity requires exact AdmissionCaseReleaseV3, exact EvaluationPlanManifestV3, "
            "exact AdmissionValidationContext, and exact EvaluationAdmissionAuthorityV3 values"
        )
    try:
        _validate_context(context)
        authority.__post_init__()
        context_digest = derive_admission_validation_context_digest(context)
        validate_reviewed_proof_plan(plan, release, authority, context.admission_review_policy, resolver)
    except (EvaluationProofPlanError, TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"proof validation context or authority is malformed: {exc}") from exc
    if context.context_digest != context_digest or authority.validation_context_digest != context_digest:
        raise EvaluationProofContinuityError("proof validation context differs from the reviewed V3 authority")
    try:
        _validate_release_review(release, context, resolver)
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError, EvaluationReleaseError, TypeError, ValueError) as exc:
        raise EvaluationProofContinuityError(f"released case review is invalid: {exc}") from exc
    release_roots = (
        release.authority_digest,
        release.plan_manifest_digest,
        release.admission_manifest_digest,
    )
    authority_roots = (
        authority.authority_digest,
        authority.plan_manifest_digest,
        authority.admission_manifest_digest,
    )
    if release_roots != authority_roots:
        raise EvaluationProofContinuityError("released case roots differ from the reviewed V3 authority")
    policy = context.proof_trust_policy
    if policy is None:
        raise EvaluationProofContinuityError("authority-bound validation context has no proof trust policy")
    if type(policy) is not ProofTrustPolicy:
        raise EvaluationProofContinuityError("authority-bound proof trust policy must use exact ProofTrustPolicy")
    return policy


def _claims_without_candidate(
    case: ArmAdmissionCaseResultV3,
    combination_case: CombinedCaseOutcomeV3 | None,
) -> tuple[DefectClaim, ...]:
    if case.proof_attachments:
        raise EvaluationProofContinuityError("proof attachment has no identical released candidate")
    combined = case.outcome_projection.policy is CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE
    if combined:
        if combination_case is None:
            raise EvaluationProofContinuityError("combined proof continuity requires its exact lineage row")
        _validate_combination_case(case, combination_case)
        validate_combined_proof_retention_v3(combination_case, None)
    elif combination_case is not None:
        raise EvaluationProofContinuityError("component case cannot use combined proof lineage")
    return case.claims


def _apply_candidate_proof(
    case: ArmAdmissionCaseResultV3,
    binding: ReleasedArmCaseBindingV3,
    candidate: ProofCandidateIdentityV3,
    policy: ProofTrustPolicy,
    resolver: canonical.ContentResolver,
    combination_case: CombinedCaseOutcomeV3 | None,
) -> tuple[DefectClaim, ...]:
    _validate_candidate(candidate)
    _validate_candidate_origin(case, candidate, combination_case)
    index, claim = _candidate_claim(case, binding, candidate)
    if not case.proof_attachments:
        return case.claims
    if len(case.proof_attachments) != 1:
        raise EvaluationProofContinuityError("released proof candidate must have exactly one proof attachment")
    attachment = case.proof_attachments[0]
    if type(attachment) is not ProofAttachment or type(policy) is not ProofTrustPolicy:
        raise EvaluationProofContinuityError("proof attachment and trust policy must use exact proof contracts")
    try:
        demonstrated = validate_differential_proof(claim, attachment, policy, resolver)
        if not demonstrated:
            return case.claims
        derived = attach_differential_proof(claim, attachment, policy, resolver)
    except ProofValidationError as exc:
        raise EvaluationProofContinuityError(f"released differential proof is invalid: {exc}") from exc
    claims = list(case.claims)
    claims[index] = derived
    return tuple(claims)


def apply_released_case_proof_v3(
    case: ArmAdmissionCaseResultV3,
    binding: ReleasedArmCaseBindingV3,
    release: AdmissionCaseReleaseV3,
    plan: EvaluationPlanManifestV3,
    context: AdmissionValidationContext,
    authority: EvaluationAdmissionAuthorityV3,
    resolver: canonical.ContentResolver,
) -> tuple[DefectClaim, ...]:
    """Validate and derive claims without mutating or authorizing a released case."""

    policy = _release_bound_proof_policy(release, plan, context, authority, resolver)
    _validate_case_binding(case, binding)
    if sum(item == binding for item in release.bindings) != 1:
        raise EvaluationProofContinuityError("released proof binding must occur exactly once in the reviewed release")
    if any(claim.basis is EvidenceBasis.EXECUTION_BACKED for claim in case.claims):
        raise EvaluationProofContinuityError("released claims must be non-execution-backed before proof validation")
    try:
        kind = validate_plan_case_binding(plan, case, binding)
        combination_case = derive_released_combination_case(plan, release, case) if kind is ArmKindV3.COMBINED else None
    except EvaluationProofPlanError as exc:
        message = str(exc)
        if "complete reviewed plan" in message:
            message = f"combined proof continuity requires {message}"
        raise EvaluationProofContinuityError(message) from exc
    candidate = case.proof_candidate
    if candidate is None:
        return _claims_without_candidate(case, combination_case)
    return _apply_candidate_proof(case, binding, candidate, policy, resolver, combination_case)


__all__ = [
    "EvaluationProofContinuityError",
    "apply_released_case_proof_v3",
    "derive_finding_location_digest",
    "validate_combined_proof_retention_v3",
]
