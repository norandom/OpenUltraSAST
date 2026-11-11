"""Canonical association validation for released evaluation-admission V3 cases."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from contextlib import suppress

from openultrasast.core import canonical
from openultrasast.core._evaluation_release_validation import (
    _group_maps,
    _validate_case_observation,
    _validate_release_review,
)
from openultrasast.core.admission_case import (
    AdmissionCaseRole,
    derive_admission_case_result_digest,
)
from openultrasast.core.admission_context import AdmissionValidationContext, _validate_context
from openultrasast.core.budget import BudgetGateFailure, check_budget
from openultrasast.core.coverage import derive_input_manifest_digest, validate_instrument
from openultrasast.core.custody import PopulationCustodyPort
from openultrasast.core.evaluation_authority import EvaluationAdmissionManifestV3, _validate_manifest_review
from openultrasast.core.evaluation_observation import validate_evaluation_observations
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    EvaluationReleaseError,
    ReleasedArmCaseBindingV3,
    _legacy_case,
    derive_proof_candidate_identity_digest,
)
from openultrasast.core.evidence import EvidenceRecord
from openultrasast.core.provenance import ProvenanceInputRole
from openultrasast.core.validation import derive_evidence_validation_input_digest, validate_evidence_input


def _validated_inputs(
    case: ArmAdmissionCaseResultV3,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[EvidenceRecord, ...]]:
    evidence: list[str] = []
    changes: set[str] = set()
    records: list[EvidenceRecord] = []
    for value in case.evidence_inputs:
        if value.input_digest != derive_evidence_validation_input_digest(value):
            raise EvaluationReleaseError("released evidence input digest cannot be re-derived")
        records.append(validate_evidence_input(value, context.evidence, custody, resolver))
        packet = value.record.packet
        named = tuple(item.identity for item in value.named_inputs.inputs if item.role is ProvenanceInputRole.CHANGE_INPUT)
        if len(named) != 1 or named[0] != packet.provenance.change_input_digest:
            raise EvaluationReleaseError("released change input differs from validated provenance")
        evidence.append(value.input_digest)
        changes.add(named[0])
    validated = tuple(records)
    if len({item.record_id for item in validated}) != len(validated):
        raise EvaluationReleaseError("released evidence inputs repeat a record identity")
    scopes = {item.packet.scope for item in validated}
    if len(scopes) != 1:
        raise EvaluationReleaseError("released case evidence must share one exact analyzed scope")
    analyzed = next(iter(scopes))
    expected_complexity = (
        analyzed.change_digest,
        len(analyzed.regions),
        sum(len(item.packet.transitions) for item in validated),
    )
    actual_complexity = (case.complexity.change_id, case.complexity.changed_regions, case.complexity.transition_count)
    if actual_complexity != expected_complexity:
        raise EvaluationReleaseError("released case complexity differs from validated evidence")
    with suppress(BudgetGateFailure):
        check_budget(case.complexity, case.total_reply_ms, case.budget, resolver)
    return tuple(sorted(evidence)), tuple(sorted(changes)), validated


def _canonical_binding(
    case: ArmAdmissionCaseResultV3,
    baseline_digest: str,
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> ReleasedArmCaseBindingV3:
    case.__post_init__()
    legacy = _legacy_case(case)
    if case.input_manifest.manifest_digest != derive_input_manifest_digest(case.input_manifest.tracked_input_ids):
        raise EvaluationReleaseError("released input manifest digest cannot be re-derived")
    validate_instrument(case.input_manifest, case.input_receipts)
    if case.result_digest != derive_admission_case_result_digest(legacy):
        raise EvaluationReleaseError("released case result digest cannot be re-derived")
    evidence, changes, _ = _validated_inputs(case, context, custody, resolver)
    candidate_digest = None
    if case.proof_candidate is not None:
        candidate = case.proof_candidate
        expected = (case.key.arm_id, case.observation_digest, case.key.scope.family_id, case.key.scope)
        actual = (candidate.component_arm_id, candidate.observation_digest, candidate.family_id, candidate.scope)
        if actual != expected or candidate.change_input_digest not in changes:
            raise EvaluationReleaseError("proof candidate differs from its released case associations")
        if candidate.candidate_digest != derive_proof_candidate_identity_digest(candidate):
            raise EvaluationReleaseError("proof candidate identity cannot be re-derived")
        candidate_digest = candidate.candidate_digest
    return ReleasedArmCaseBindingV3(
        case.key,
        baseline_digest,
        case.observation_slot_digest,
        case.observation_digest,
        case.underlying_push_digest,
        case.case_id_digest,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        evidence,
        changes,
        case.input_manifest.manifest_digest,
        candidate_digest,
        "",
    )


def _validate_pairs(cases: tuple[ArmAdmissionCaseResultV3, ...]) -> None:
    pairs: dict[tuple[object, ...], list[AdmissionCaseRole]] = defaultdict(list)
    for case in cases:
        if case.role is AdmissionCaseRole.ORDINARY:
            if case.pair_id_digest is not None:
                raise EvaluationReleaseError("ordinary released case cannot carry a pair identity")
            continue
        if case.pair_id_digest is None:
            raise EvaluationReleaseError("vulnerable and fixed released cases require a pair identity")
        pairs[(case.key.arm_id, case.key.scope, case.pair_id_digest)].append(case.role)
    for roles in pairs.values():
        if Counter(roles) != Counter((AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED)):
            raise EvaluationReleaseError("released pair must contain one vulnerable and one fixed case in the exact scope")


def _validate_release_roots(
    manifest: EvaluationAdmissionManifestV3,
    release: AdmissionCaseReleaseV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    resolver: canonical.ContentResolver,
) -> tuple[ArmAdmissionCasesV3, ...]:
    if type(manifest) is not EvaluationAdmissionManifestV3 or type(release) is not AdmissionCaseReleaseV3:
        raise EvaluationReleaseError("manifest and release must use exact V3 roots")
    if type(arm_cases) is not tuple:
        raise EvaluationReleaseError("arm cases must use an exact tuple")
    if type(context) is not AdmissionValidationContext:
        raise EvaluationReleaseError("validation context must use exact AdmissionValidationContext")
    _validate_context(context)
    _validate_manifest_review(manifest, context, resolver)
    if (release.plan_manifest_digest, release.admission_manifest_digest) != (
        manifest.plan_manifest.manifest_digest,
        manifest.manifest_digest,
    ):
        raise EvaluationReleaseError("release header differs from the reviewed plan and admission manifest")
    return arm_cases


def validate_released_case_associations_v3(
    manifest: EvaluationAdmissionManifestV3,
    release: AdmissionCaseReleaseV3,
    arm_cases: Sequence[ArmAdmissionCasesV3],
    context: AdmissionValidationContext,
    custody: PopulationCustodyPort,
    resolver: canonical.ContentResolver,
) -> tuple[ReleasedArmCaseBindingV3, ...]:
    """Recompute exact case associations before any count or quality decision."""
    try:
        groups = _validate_release_roots(manifest, release, arm_cases, context, resolver)
        policy = _validate_release_review(release, context, resolver)
        observations = validate_evaluation_observations(
            manifest.plan_manifest.declaration,
            manifest.observations,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
        group_map, observed = _group_maps(manifest, groups, observations)
        cases = tuple(case for group in groups for case in group.cases)
        _validate_pairs(cases)
        configurations = {item.arm_id: item for item in manifest.plan_manifest.declaration.arm_configurations}
        derived_values = []
        for arm_id, group in group_map.items():
            claimed = set(configurations[arm_id].exact_scopes)
            for case in group.cases:
                observation, reference = observed[(arm_id, case.case_id_digest)]
                _validate_case_observation(case, observation, reference, claimed)
                derived_values.append(_canonical_binding(case, group.baseline_digest, context, custody, resolver))
        derived = tuple(
            sorted(
                derived_values,
                key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
            )
        )
        if release.bindings != derived:
            raise EvaluationReleaseError("release bindings differ from revalidated canonical case associations")
        return derived
    except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError):
        raise
    except EvaluationReleaseError:
        raise
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        raise EvaluationReleaseError(f"released case association validation refused: {exc}") from exc


__all__ = ["validate_released_case_associations_v3"]
