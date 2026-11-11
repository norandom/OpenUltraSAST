"""Reviewed-plan bindings for released V3 proof continuity."""

from __future__ import annotations

from openultrasast.core import canonical
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3
from openultrasast.core.evaluation_combination import (
    CombinationValidationError,
    CombinedCaseOutcomeV3,
    derive_combination_lineages_v3,
)
from openultrasast.core.evaluation_measurement import ArmKindV3
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3, validate_reviewed_evaluation_plan
from openultrasast.core.evaluation_release import AdmissionCaseReleaseV3, ArmAdmissionCaseResultV3, ReleasedArmCaseBindingV3
from openultrasast.core.factpack import ReviewIndependencePolicy


class EvaluationProofPlanError(ValueError):
    """Reviewed plan or plan-derived combination lineage is invalid."""


def validate_reviewed_proof_plan(
    plan: EvaluationPlanManifestV3,
    release: AdmissionCaseReleaseV3,
    authority: EvaluationAdmissionAuthorityV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    if type(plan) is not EvaluationPlanManifestV3:
        raise EvaluationProofPlanError("proof continuity requires exact EvaluationPlanManifestV3")
    try:
        validate_reviewed_evaluation_plan(plan.census, plan, policy, resolver)
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError, TypeError, ValueError) as exc:
        raise EvaluationProofPlanError(f"reviewed evaluation plan is invalid: {exc}") from exc
    if plan.manifest_digest != release.plan_manifest_digest or plan.manifest_digest != authority.plan_manifest_digest:
        raise EvaluationProofPlanError("reviewed evaluation plan differs from the release and authority roots")


def validate_plan_case_binding(
    plan: EvaluationPlanManifestV3,
    case: ArmAdmissionCaseResultV3,
    binding: ReleasedArmCaseBindingV3,
) -> ArmKindV3:
    configurations = tuple(item for item in plan.declaration.arm_configurations if item.arm_id == case.key.arm_id)
    baselines = tuple(item for item in plan.baselines if item.arm_id == case.key.arm_id)
    if len(configurations) != 1 or len(baselines) != 1:
        raise EvaluationProofPlanError("released proof case is absent from the reviewed evaluation plan")
    configuration = configurations[0]
    if case.key.scope not in configuration.exact_scopes or binding.baseline_digest != baselines[0].baseline_digest:
        raise EvaluationProofPlanError("released proof case scope or baseline differs from the reviewed plan")
    if case.outcome_projection.policy is not configuration.case_outcome_policy:
        raise EvaluationProofPlanError("released proof case projection policy differs from the reviewed plan")
    return configuration.kind


def derive_released_combination_case(
    plan: EvaluationPlanManifestV3,
    release: AdmissionCaseReleaseV3,
    case: ArmAdmissionCaseResultV3,
) -> CombinedCaseOutcomeV3:
    try:
        lineages = derive_combination_lineages_v3(plan.declaration, release.bindings)
    except CombinationValidationError as exc:
        raise EvaluationProofPlanError(f"bindings for the complete reviewed plan are required: {exc}") from exc
    matches = tuple(
        combined
        for lineage in lineages
        for combined in lineage.combined_cases
        if (
            combined.key,
            combined.case_id_digest,
            combined.case_input_digest,
            combined.observation_digest,
            combined.combined_projection_digest,
        )
        == (
            case.key,
            case.case_id_digest,
            case.case_input_digest,
            case.observation_digest,
            case.outcome_projection.projection_digest,
        )
    )
    if len(matches) != 1:
        raise EvaluationProofPlanError("combined proof case must match exactly one plan-derived lineage row")
    return matches[0]


__all__ = [
    "EvaluationProofPlanError",
    "derive_released_combination_case",
    "validate_plan_case_binding",
    "validate_reviewed_proof_plan",
]
