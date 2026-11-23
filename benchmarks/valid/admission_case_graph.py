"""Task 11.3 custodian-side case graph over the released spend products.

Graph builders for the conversion adapter: the request contract, the exact
scope assignment, and the core V3 case/release graph derivation. Every case
field is pinned to the custodian-decoded sealed observation content and the
released label join, or the conversion is refused closed.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol

from benchmarks.valid.admission_execution import AdmissionExecutionV1
from benchmarks.valid.admission_spend import AdmissionSpendReleaseV1
from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import S3ArtifactRepository
from benchmarks.valid.ecosystem_review import CanonicalEcosystem
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from openultrasast.core.admission_case import AdmissionCaseResult
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.canonical import ContentResolver
from openultrasast.core.custody import PopulationCustodyPort
from openultrasast.core.evaluation_authority import EvaluationAdmissionManifestV3
from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionV3
from openultrasast.core.evaluation_combination import CombinationRuleV3
from openultrasast.core.evaluation_measurement import ArmKindV3, ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    EvaluationPlanManifestV3,
    ExactScopeCensusV3,
    PopulationCensusV3,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
)
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    ProofCandidateIdentityV3,
    ReleasedArmCaseBindingV3,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_released_arm_case_binding,
)
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.readiness import ReadinessResult

_ZERO = "0" * 64
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ORDINARY = "ordinary"
ScopeResolver = Callable[[str, str, str], ScopeKey]


class AdmissionAdapterReason(StrEnum):
    """Closed refusal reasons; no caller content is serializable."""

    INVALID_REQUEST = "invalid_request"
    RELEASE_REFUSED = "release_refused"
    OBSERVATIONS_UNREADABLE = "observations_unreadable"
    CASE_CONTENT_UNBOUND = "case_content_unbound"
    SCOPE_UNVERIFIED = "scope_unverified"
    CENSUS_MISMATCH = "census_mismatch"
    AUTHORIZATION_REFUSED = "authorization_refused"
    COMBINATION_DIVERGED = "combination_diverged"


class AdmissionAdapterError(RuntimeError):
    """Refuse one conversion step with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionAdapterReason) -> None:
        self.reason = reason
        super().__init__(f"admission_case_adapter_{reason.value}")


def refused(reason: AdmissionAdapterReason) -> AdmissionAdapterError:
    return AdmissionAdapterError(reason)


def require_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise refused(AdmissionAdapterReason.INVALID_REQUEST)
    return value


class CaseContentPort(Protocol):
    """Custodian-owned full case-content source keyed by arm, identity, scope."""

    def __call__(self, arm_id: str, case_input_digest: str, scope: ScopeKey) -> AdmissionCaseResult: ...


class ReviewFactory(Protocol):
    """External review minting over one derived payload digest."""

    def __call__(self, subject_digest: str) -> IndependenceAttestation: ...


@dataclass(frozen=True)
class AdmissionCaseAdapterRequestV1:
    """Every authority the post-spend core conversion needs."""

    repository: S3ArtifactRepository
    custodian_access_policy_digest: str
    execution: AdmissionExecutionV1
    plan: RegisteredEvaluationPlanV1
    selection: OrdinarySelectionV1
    population_digest: str
    input_count: int
    custody: PopulationCustodyPort
    resolver: ContentResolver
    context: AdmissionValidationContext
    readiness: tuple[ReadinessResult, ...]
    case_content: CaseContentPort
    proof_candidates: Callable[[str, str, ScopeKey], ProofCandidateIdentityV3 | None]
    census_review: IndependenceAttestation
    plan_review: IndependenceAttestation
    admission_review: ReviewFactory
    release_review: ReviewFactory
    bridged_store_identity: str
    bridged_retention_policy_digest: str
    aggregate: bool = False


def validate_adapter_request(request: object) -> AdmissionCaseAdapterRequestV1:
    if (
        type(request) is not AdmissionCaseAdapterRequestV1
        or type(request.repository) is not S3ArtifactRepository
        or type(request.execution) is not AdmissionExecutionV1
        or type(request.plan) is not RegisteredEvaluationPlanV1
        or type(request.selection) is not OrdinarySelectionV1
        or type(request.context) is not AdmissionValidationContext
        or type(request.census_review) is not IndependenceAttestation
        or type(request.plan_review) is not IndependenceAttestation
        or not callable(request.release_review)
        or not callable(request.admission_review)
        or not callable(request.case_content)
        or not callable(request.proof_candidates)
        or not callable(getattr(request.custody, "current_log", None))
        or type(request.readiness) is not tuple
        or not request.readiness
        or type(request.input_count) is not int
        or request.input_count < 1
        or request.execution.refusal_reason is not None
        or request.execution.admission_manifest is None
        or request.execution.spend_authorization is None
        or request.execution.spend_authorization.may_spend is not True
        or type(request.bridged_store_identity) is not str
        or not request.bridged_store_identity
    ):
        raise refused(AdmissionAdapterReason.INVALID_REQUEST)
    for digest in (request.population_digest, request.bridged_retention_policy_digest, request.custodian_access_policy_digest):
        require_digest(digest)
    for item in request.readiness:
        if type(item) is not ReadinessResult:
            raise refused(AdmissionAdapterReason.INVALID_REQUEST)
    return request  # type: ignore[return-value]


def planned_arm_scopes(plan: RegisteredEvaluationPlanV1) -> dict[str, tuple[ScopeKey, ...]]:
    planned: dict[str, tuple[ScopeKey, ...]] = {}
    for row in plan.registrations:
        planned[row.arm_id] = tuple(sorted(set(row.configuration.exact_scopes)))
    return planned


def combined_arm_ids(plan: RegisteredEvaluationPlanV1) -> set[str]:
    return {row.arm_id for row in plan.registrations if row.configuration.kind is ArmKindV3.COMBINED}


def combined_rule(plan: RegisteredEvaluationPlanV1, arm_id: str) -> CombinationRuleV3:
    for row in plan.registrations:
        if row.arm_id == arm_id:
            rule = row.configuration.combination_rule
            if rule is None:
                raise refused(AdmissionAdapterReason.INVALID_REQUEST)
            return rule
    raise refused(AdmissionAdapterReason.INVALID_REQUEST)


def labeled_facts(release: AdmissionSpendReleaseV1) -> dict[str, tuple[str, str]]:
    """One (family, ecosystem) fact per labeled raw population identity; conflicting joins refuse.

    The committed 8.3 join keys ground-truth labels by the raw positive change
    digests and carries that identity on each released row's underlying digest,
    so the label join resolves through the underlying population identity.
    """
    labeled: dict[str, tuple[str, str]] = {}
    for row in release.released_cases:
        if row.role.value == _ORDINARY:
            continue
        fact = (row.family_id, row.ecosystem)
        if labeled.setdefault(row.underlying_push_digest, fact) != fact:
            raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    if not labeled:
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    return labeled


def scope_resolver(
    request: AdmissionCaseAdapterRequestV1,
    planned: dict[str, tuple[ScopeKey, ...]],
) -> ScopeResolver:
    """Resolve the exact scope of one observed case through the custodian port.

    Each custodian case content binds to exactly one planned scope per arm, so
    the resolution probes the planned scopes and refuses when no port content
    binds the identity. Positive-label facts are cross-checked separately after
    the spend; the resolution itself stays label-blind.
    """

    def resolve(arm_id: str, case_input_digest: str, underlying_push_digest: str) -> ScopeKey:
        for scope in planned[arm_id]:
            if _port_content(request, arm_id, case_input_digest, scope) is not None:
                return scope
        raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND)

    return resolve


def _port_content(request: AdmissionCaseAdapterRequestV1, arm_id: str, key: str, scope: ScopeKey):
    try:
        content = request.case_content(arm_id, key, scope)
    except KeyError:
        return None
    if content is None:
        return None
    if (content.scope.family_id, content.scope.ecosystem) != (scope.family_id, scope.ecosystem):
        return None
    return content


def assert_labeled_scopes(
    request: AdmissionCaseAdapterRequestV1,
    planned: dict[str, tuple[ScopeKey, ...]],
    labeled: dict[str, tuple[str, str]],
) -> None:
    """Pin every released positive label to the exact scope the custodian port binds."""
    anchor_arm = next(iter(sorted(planned)))
    for raw, (family_id, ecosystem) in labeled.items():
        for scope in planned[anchor_arm]:
            if _port_content(request, anchor_arm, raw, scope) is None:
                continue
            if (scope.family_id, scope.ecosystem) != (family_id, ecosystem):
                raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
            break
        else:
            raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND)


def _pinned_candidate(
    request: AdmissionCaseAdapterRequestV1,
    arm_id: str,
    case_input_digest: str,
    scope: ScopeKey,
    sealed_candidate_digest: object,
) -> ProofCandidateIdentityV3 | None:
    candidate = request.proof_candidates(arm_id, case_input_digest, scope)
    actual = candidate.candidate_digest if candidate is not None else None
    if actual != sealed_candidate_digest:
        raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND)
    return candidate


def _case_result(
    arm_id: str,
    scope: ScopeKey,
    reference: ObservationCaseRefV3,
    observation: ArmObservationSetV3,
    content: AdmissionCaseResult,
    projection: CaseOutcomeProjectionV3,
    candidate: ProofCandidateIdentityV3 | None,
) -> ArmAdmissionCaseResultV3:
    return ArmAdmissionCaseResultV3(
        ArmScopeKey(arm_id, scope),
        observation.slot_digest,
        observation.observation_digest,
        reference.underlying_push_digest,
        content.case_id_digest,
        reference.case_input_digest,
        projection,
        content.role,
        content.pair_id_digest,
        content.evidence_inputs,
        content.defect_claims,
        content.satisfactions,
        content.silence,
        candidate,
        content.proof_attachments,
        content.coverage,
        content.input_manifest,
        content.input_receipts,
        content.complexity,
        content.budget,
        content.total_reply_ms,
        content.result_digest,
    )


def _pinned_content(
    request: AdmissionCaseAdapterRequestV1, arm_id: str, scope: ScopeKey, reference: ObservationCaseRefV3
) -> AdmissionCaseResult:
    content = request.case_content(arm_id, reference.case_input_digest, scope)
    if (content.scope.family_id, content.scope.ecosystem) != (scope.family_id, scope.ecosystem):
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    return content


def component_case(
    request: AdmissionCaseAdapterRequestV1,
    arm_id: str,
    scope: ScopeKey,
    reference: ObservationCaseRefV3,
    observation: ArmObservationSetV3,
) -> ArmAdmissionCaseResultV3:
    """Pin one component case to its sealed observation and label join."""
    from openultrasast.core.evaluation_case_outcome import derive_component_case_outcome_projection

    content = _pinned_content(request, arm_id, scope, reference)
    records = tuple(item.record for item in content.evidence_inputs)
    try:
        projection = derive_component_case_outcome_projection(records)
    except ValueError:
        raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND) from None
    if (content.case_id_digest, content.result_digest, projection) != (
        reference.case_id_digest,
        reference.result_digest,
        reference.outcome_projection,
    ):
        raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND)
    candidate = _pinned_candidate(request, arm_id, reference.case_input_digest, scope, reference.proof_candidate_digest)
    return _case_result(arm_id, scope, reference, observation, content, projection, candidate)


def combined_projection(rule: CombinationRuleV3, projections: tuple[CaseOutcomeProjectionV3, ...]) -> CaseOutcomeProjectionV3:
    """Derive the declarative combined projection from ordered component projections."""
    from openultrasast.core.evaluation_case_outcome import (
        CaseOutcomeProjectionPolicyV3,
        CaseOutcomeProjectionV3,
    )

    outcomes = tuple(item.normalized_outcome for item in projections)
    for row in rule.decision_rows:
        if row.component_outcomes == outcomes:
            return CaseOutcomeProjectionV3(
                projections[0].case_input_digest,
                CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
                tuple(item.projection_digest for item in projections),
                row.combined_outcome,
                "",
            )
    raise refused(AdmissionAdapterReason.COMBINATION_DIVERGED)


def component_projections(
    decoded: dict[tuple[str, str], ArmObservationSetV3],
    rule: CombinationRuleV3,
    input_identity_digest: str,
    case_input_digest: str,
    underlying_push_digest: str,
) -> tuple[CaseOutcomeProjectionV3, ...]:
    """Ordered component projections for one combined case key."""
    ordered = []
    for arm_id in rule.component_arm_ids:
        observation = decoded.get((arm_id, input_identity_digest))
        if observation is None:
            raise refused(AdmissionAdapterReason.COMBINATION_DIVERGED)
        match = next(
            (
                case.outcome_projection
                for case in observation.cases
                if case.case_input_digest == case_input_digest and case.underlying_push_digest == underlying_push_digest
            ),
            None,
        )
        if match is None:
            raise refused(AdmissionAdapterReason.COMBINATION_DIVERGED)
        ordered.append(match)
    return tuple(ordered)


def combined_case(
    request: AdmissionCaseAdapterRequestV1,
    arm_id: str,
    scope: ScopeKey,
    reference: ObservationCaseRefV3,
    observation: ArmObservationSetV3,
    projections: tuple[CaseOutcomeProjectionV3, ...],
) -> ArmAdmissionCaseResultV3:
    """Pin one combined case to the rule-derived projection and port content."""
    projection = combined_projection(combined_rule(request.plan, arm_id), projections)
    if projection.projection_digest != reference.outcome_projection.projection_digest:
        raise refused(AdmissionAdapterReason.COMBINATION_DIVERGED)
    content = _pinned_content(request, arm_id, scope, reference)
    if (content.case_id_digest, content.result_digest) != (reference.case_id_digest, reference.result_digest):
        raise refused(AdmissionAdapterReason.CASE_CONTENT_UNBOUND)
    candidate = _pinned_candidate(request, arm_id, reference.case_input_digest, scope, reference.proof_candidate_digest)
    return _case_result(arm_id, scope, reference, observation, content, projection, candidate)


def corrected_census(
    request: AdmissionCaseAdapterRequestV1,
    planned: dict[str, tuple[ScopeKey, ...]],
    decoded: dict[tuple[str, str], ArmObservationSetV3],
    scope_of: ScopeResolver,
) -> PopulationCensusV3:
    """Recompose the reviewable census from the released join and case contents."""
    scopes = tuple(sorted({scope for claimed in planned.values() for scope in claimed}))
    sites: dict[ScopeKey, int] = {scope: 0 for scope in scopes}
    models: dict[ScopeKey, int] = {scope: 0 for scope in scopes}
    pairs: dict[ScopeKey, set[str]] = {scope: set() for scope in scopes}
    anchor_arm = next(iter(sorted(planned)))
    for (arm_id, _identity), observation in decoded.items():
        for reference in observation.cases:
            scope = scope_of(arm_id, reference.case_input_digest, reference.underlying_push_digest)
            content = request.case_content(arm_id, reference.case_input_digest, scope)
            if content.pair_id_digest is not None and content.role.value != _ORDINARY:
                pairs[scope].add(content.pair_id_digest)
            if arm_id == anchor_arm:
                sites[scope] += content.coverage.sites_considered
                models[scope] += sum(1 for item in content.evidence_inputs if item.model_result is not None)
    ordinary: dict[str, int] = {}
    for push in request.selection.pushes:
        ecosystem = CanonicalEcosystem(push.ecosystem).value
        ordinary[ecosystem] = ordinary.get(ecosystem, 0) + 1
    scope_rows = tuple(
        sorted(
            ExactScopeCensusV3(scope, len(pairs[scope]), len(pairs[scope]), len(pairs[scope]), sites[scope], models[scope])
            for scope in scopes
        )
    )
    ordinary_rows = tuple(EcosystemOrdinaryCensusV3(eco, ordinary[eco]) for eco in sorted(ordinary))
    draft = PopulationCensusV3(
        request.population_digest,
        scope_rows,
        ordinary_rows,
        request.input_count,
        False,
        _ZERO,
        request.census_review,
        _ZERO,
    )
    if request.census_review.subject_digest != derive_evaluation_census_payload_digest(draft):
        raise refused(AdmissionAdapterReason.CENSUS_MISMATCH)
    bound = replace(draft, payload_digest=request.census_review.subject_digest)
    return replace(bound, census_digest=derive_evaluation_census_digest(bound))


def case_release_graph(
    request: AdmissionCaseAdapterRequestV1,
    planned: dict[str, tuple[ScopeKey, ...]],
    decoded: dict[tuple[str, str], ArmObservationSetV3],
    scope_of: ScopeResolver,
    plan_manifest: EvaluationPlanManifestV3,
    admission_manifest: EvaluationAdmissionManifestV3,
    preparation: EvaluationPreparationV3,
    spend: EvaluationSpendBindingV3,
) -> tuple[tuple[ArmAdmissionCasesV3, ...], AdmissionCaseReleaseV3]:
    """Build every planned arm's case group and the reviewed V3 release."""
    groups: list[ArmAdmissionCasesV3] = []
    bindings: list[ReleasedArmCaseBindingV3] = []
    combined = combined_arm_ids(request.plan)
    for arm_id in sorted(planned):
        cases = []
        for (owner, identity), observation in sorted(decoded.items()):
            if owner != arm_id:
                continue
            for reference in observation.cases:
                scope = scope_of(arm_id, reference.case_input_digest, reference.underlying_push_digest)
                if arm_id in combined:
                    rule = combined_rule(request.plan, arm_id)
                    projections = component_projections(
                        decoded, rule, identity, reference.case_input_digest, reference.underlying_push_digest
                    )
                    cases.append(combined_case(request, arm_id, scope, reference, observation, projections))
                else:
                    cases.append(component_case(request, arm_id, scope, reference, observation))
        baseline = next(item.baseline_digest for item in plan_manifest.baselines if item.arm_id == arm_id)
        ordered = tuple(sorted(cases, key=lambda item: (item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest)))
        groups.append(ArmAdmissionCasesV3(arm_id, baseline, ordered, ""))
        bindings.extend(derive_released_arm_case_binding(case, plan_manifest) for case in ordered)
    ordered_bindings = tuple(
        sorted(
            bindings,
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    draft = AdmissionCaseReleaseV3(
        plan_manifest.manifest_digest,
        admission_manifest.manifest_digest,
        preparation.authority.authority_digest,
        preparation.preparation_digest,
        spend.binding_digest,
        ordered_bindings,
        _ZERO,
        request.release_review(_ZERO),
        _ZERO,
    )
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(draft, payload_digest=payload, review=request.release_review(payload))
    release = replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))
    return tuple(sorted(groups, key=lambda item: item.arm_id)), release


__all__ = [
    "AdmissionAdapterError",
    "AdmissionAdapterReason",
    "AdmissionCaseAdapterRequestV1",
    "CaseContentPort",
    "ReviewFactory",
    "assert_labeled_scopes",
    "case_release_graph",
    "combined_arm_ids",
    "combined_case",
    "combined_projection",
    "combined_rule",
    "component_case",
    "component_projections",
    "corrected_census",
    "labeled_facts",
    "planned_arm_scopes",
    "refused",
    "require_digest",
    "scope_resolver",
    "validate_adapter_request",
]
