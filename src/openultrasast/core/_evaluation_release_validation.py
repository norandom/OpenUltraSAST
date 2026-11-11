"""Complete-graph validation for the public V3 evaluation-release contracts."""

from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Set as AbstractSet

from openultrasast.core import canonical
from openultrasast.core._evaluation_plan_review import _validate_policy, _validate_review
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3, EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3, validate_evaluation_observations
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    EvaluationReleaseError,
    ReleasedArmCaseBindingV3,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_released_arm_case_binding,
)
from openultrasast.core.evaluation_spend import (
    EvaluationPreparationV3,
    EvaluationSpendBindingV3,
    _validate_preparation_graph,
    bind_evaluation_spend,
)
from openultrasast.core.factpack import ReviewIndependencePolicy


def _validate_roots(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
) -> None:
    if type(release) is not AdmissionCaseReleaseV3 or type(arm_cases) is not tuple:
        raise EvaluationReleaseError("release and arm cases must use exact V3 root types")
    if type(context) is not AdmissionValidationContext:
        raise EvaluationReleaseError("release context must use exact AdmissionValidationContext")
    _validate_context(context)
    _validate_preparation_graph(manifest, preparation, context)
    if preparation.authority != authority:
        raise EvaluationReleaseError("release authority differs from the exact preparation")
    if spend != bind_evaluation_spend(manifest, preparation, receipt, context, custody):
        raise EvaluationReleaseError("release spend binding is not the exact current shared spend")


def _validate_release_review(
    release: AdmissionCaseReleaseV3,
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> ReviewIndependencePolicy:
    release.__post_init__()
    if release.payload_digest != derive_admission_case_release_payload_digest_v3(release):
        raise EvaluationReleaseError("release payload digest cannot be re-derived")
    policy = _validate_policy(context.admission_review_policy)
    _validate_review(release.review, release.payload_digest, policy, resolver)
    if release.release_digest != derive_admission_case_release_digest_v3(release):
        raise EvaluationReleaseError("release digest cannot be re-derived")
    return policy


def _validate_header(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
) -> None:
    expected = (
        manifest.plan_manifest.manifest_digest,
        manifest.manifest_digest,
        authority.authority_digest,
        preparation.preparation_digest,
        spend.binding_digest,
    )
    actual = (
        release.plan_manifest_digest,
        release.admission_manifest_digest,
        release.authority_digest,
        release.preparation_digest,
        release.spend_binding_digest,
    )
    if actual != expected:
        raise EvaluationReleaseError("release header differs from the exact reviewed spend graph")


def _group_maps(
    manifest: EvaluationAdmissionManifestV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    observations: tuple[ArmObservationSetV3, ...],
) -> tuple[dict[str, ArmAdmissionCasesV3], dict[tuple[str, str], tuple[ArmObservationSetV3, ObservationCaseRefV3]]]:
    planned = {item.arm_id: item for item in manifest.plan_manifest.baselines}
    if len(planned) != len(manifest.plan_manifest.baselines) or len(arm_cases) != len(planned):
        raise EvaluationReleaseError("release must contain exactly one case group per planned arm")
    groups = {item.arm_id: item for item in arm_cases if type(item) is ArmAdmissionCasesV3}
    if len(groups) != len(arm_cases) or set(groups) != set(planned):
        raise EvaluationReleaseError("release arm groups are missing, duplicated, or unplanned")
    if arm_cases != tuple(sorted(arm_cases, key=lambda item: item.arm_id)):
        raise EvaluationReleaseError("release arm groups must use canonical plan order")
    for arm_id, group in groups.items():
        group.__post_init__()
        if group.baseline_digest != planned[arm_id].baseline_digest:
            raise EvaluationReleaseError("release arm baseline differs from the reviewed plan")
    observed = {
        (observation.arm_id, case.case_id_digest): (observation, case) for observation in observations for case in observation.cases
    }
    if len(observed) != sum(len(observation.cases) for observation in observations):
        raise EvaluationReleaseError("sealed observations contain duplicate arm-case identities")
    results = {(case.key.arm_id, case.case_id_digest): case for group in arm_cases for case in group.cases}
    if set(results) != set(observed) or len(results) != sum(len(group.cases) for group in arm_cases):
        raise EvaluationReleaseError("released cases do not equal the complete observed case set")
    return groups, observed


def _derive_bindings(
    manifest: EvaluationAdmissionManifestV3,
    groups: dict[str, ArmAdmissionCasesV3],
    observed: dict[tuple[str, str], tuple[ArmObservationSetV3, ObservationCaseRefV3]],
) -> tuple[ReleasedArmCaseBindingV3, ...]:
    derived = []
    configurations = {item.arm_id: item for item in manifest.plan_manifest.declaration.arm_configurations}
    for arm_id, group in groups.items():
        claimed = set(configurations[arm_id].exact_scopes)
        for case in group.cases:
            observation, reference = observed[(arm_id, case.case_id_digest)]
            _validate_case_observation(case, observation, reference, claimed)
            derived.append(derive_released_arm_case_binding(case, manifest.plan_manifest))
    return tuple(
        sorted(derived, key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest))
    )


def _validate_case_observation(
    case: ArmAdmissionCaseResultV3,
    observation: ArmObservationSetV3,
    reference: ObservationCaseRefV3,
    claimed: AbstractSet[object],
) -> None:
    if case.key.scope not in claimed:
        raise EvaluationReleaseError("released case scope is not claimed by its planned arm")
    expected = (
        observation.slot_digest,
        observation.observation_digest,
        reference.underlying_push_digest,
        reference.result_digest,
        reference.case_input_digest,
        reference.outcome_projection,
        reference.proof_candidate_digest,
    )
    candidate = case.proof_candidate.candidate_digest if case.proof_candidate is not None else None
    actual = (
        case.observation_slot_digest,
        case.observation_digest,
        case.underlying_push_digest,
        case.result_digest,
        case.case_input_digest,
        case.outcome_projection,
        candidate,
    )
    if actual != expected:
        raise EvaluationReleaseError("released case differs from its exact sealed observation")


def validate_release(
    manifest: EvaluationAdmissionManifestV3,
    authority: EvaluationAdmissionAuthorityV3,
    preparation: EvaluationPreparationV3,
    receipt: PopulationUseReceipt,
    spend: EvaluationSpendBindingV3,
    release: AdmissionCaseReleaseV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> AdmissionCaseReleaseV3:
    try:
        _validate_roots(manifest, authority, preparation, receipt, spend, release, arm_cases, context, custody)
        _validate_header(manifest, authority, preparation, spend, release)
        policy = _validate_release_review(release, context, resolver)
        observations = validate_evaluation_observations(
            manifest.plan_manifest.declaration,
            manifest.observations,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )  # type: ignore[attr-defined]
        groups, observed = _group_maps(manifest, arm_cases, observations)
        if release.bindings != _derive_bindings(manifest, groups, observed):
            raise EvaluationReleaseError("release bindings differ from the complete canonical case set")
        return release
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except EvaluationReleaseError:
        raise
    except (AttributeError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReleaseError(f"evaluation case release refused: {exc}") from exc


__all__ = ["validate_release"]
