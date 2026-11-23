"""Task 8.1 admission orchestrator preflight for the replacement benchmark.

Preflight refuses a run unless the replacement lifecycle is active, the store
capability report admits a real population, the admission-class freeze and the
reviewed label-blind manifest resolve, and every registered arm identity is
current. It composes the complete core V3 plan manifest, evaluates every
arm/scope threshold, minimum, and interval-precision rule before execution or
label access, persists INSUFFICIENT with exact scope/gate witnesses, and only
after complete feasibility persists and rereads one custodian-sealed retry
authority selected atomically by the initial workflow head.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from benchmarks.valid.arm_contract import (
    ArmLifecycleState,
    ArmRegistrationV1,
    ArmRegistryError,
    RegisteredEvaluationPlanV1,
    validate_registered_evaluation_plan,
)
from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadPermission,
    ArtifactRepositoryError,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.core_conformance import (
    ScopedAdmissionV3ConformanceError,
    require_scoped_admission_v3,
)
from benchmarks.valid.custody_probe_contract import (
    CustodyCapabilityReport,
    RealPopulationAdmissionDisabled,
    require_real_population_admission,
)
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from benchmarks.valid.lifecycle import LifecycleError
from benchmarks.valid.lifecycle_projection import BaselineLifecycleAuthority, PopulationLifecycleProjectionV1
from benchmarks.valid.population_freeze_contract import (
    PopulationClass,
    PopulationFreezeV3,
    population_freeze_bytes,
)
from benchmarks.valid.population_label_blind_contract import (
    LabelBlindManifestError,
    LabelBlindPopulationManifestV3,
    label_blind_population_manifest_bytes,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.store_configuration import RetentionProfile
from benchmarks.valid.workflow_journal import (
    S3WorkflowJournal,
    WorkflowHeadV1,
    WorkflowJournalEntryV1,
    WorkflowJournalError,
    require_selected_authority,
)
from benchmarks.valid.workflow_outcome import (
    BenchmarkWorkflowOutcomeV1,
    WorkflowCounts,
    WorkflowGate,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
    workflow_outcome_bytes,
)
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.custody import PopulationCustodyLog, PopulationCustodyPort, PopulationStatus
from openultrasast.core.evaluation_feasibility import (
    EvaluationFeasibilityV3,
    FeasibilityStatusV3,
    derive_evaluation_feasibility,
)
from openultrasast.core.evaluation_measurement import ArmKindV3, ScopeKey
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    EvaluationPlanManifestV3,
    ExactScopeCensusV3,
    ExpectedObservationSlotV3,
    PopulationCensusV3,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
)
from openultrasast.core.factpack import IndependenceAttestation, ReviewIndependencePolicy

RETRY_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.automatic-retry-authority.v1"
PREFLIGHT_WITNESS_SCHEMA = "openultrasast.valid-detection-benchmark.preflight-witness.v1"
SCOPE_WITNESS_REASONS = frozenset({"minimum_size", "interval_precision", "threshold_unreachable"})
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMPOSE_FAILURES = (ValueError, TypeError, KeyError, AttributeError, RuntimeError)


class AdmissionPreflightReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    CORE_UNAVAILABLE = "core_unavailable"
    LIFECYCLE_NOT_ADMISSIBLE = "lifecycle_not_admissible"
    STORE_CAPABILITY_FAILED = "store_capability_failed"
    FREEZE_NOT_ADMISSION_CLASS = "freeze_not_admission_class"
    MANIFEST_UNRESOLVED = "manifest_unresolved"
    ARM_IDENTITY_STALE = "arm_identity_stale"
    CUSTODY_HEAD_UNRESOLVED = "custody_head_unresolved"
    PLAN_COMPOSITION_FAILED = "plan_composition_failed"
    WORKFLOW_HEAD_EXISTS = "workflow_head_exists"
    PERSISTENCE_FAILED = "persistence_failed"


class AdmissionOrchestratorError(RuntimeError):
    """Refuse an admission run with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionPreflightReason) -> None:
        self.reason = reason
        super().__init__(f"admission_preflight_{reason.value}")


def _refused(reason: AdmissionPreflightReason) -> AdmissionOrchestratorError:
    return AdmissionOrchestratorError(reason)


def _require_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    return value


@dataclass(frozen=True)
class AdmissionScopeWitnessV1:
    """Exact arm/scope witness for one infeasible planned scope."""

    arm_id: str
    family_id: str
    ecosystem: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if any(type(item) is not str or not item or len(item) > 128 for item in (self.arm_id, self.family_id, self.ecosystem)):
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        if (
            not self.reasons
            or self.reasons != tuple(sorted(set(self.reasons)))
            or any(reason not in SCOPE_WITNESS_REASONS for reason in self.reasons)
        ):
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)


@dataclass(frozen=True)
class AdmissionExecutionBindingV1:
    """Per-component-arm label-blind execution identities bound before launch."""

    arm_id: str
    bundle_digest: str
    budget_digest: str
    environment_digest: str
    destination_digest: str

    def __post_init__(self) -> None:
        if type(self.arm_id) is not str or not self.arm_id or len(self.arm_id) > 128:
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        for digest in (self.bundle_digest, self.budget_digest, self.environment_digest, self.destination_digest):
            _require_digest(digest)


def _authority_value(value: AutomaticRetryAuthorityV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": RETRY_AUTHORITY_SCHEMA,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "admission_identity_digest": value.admission_identity_digest,
        "plan_digest": value.plan_digest,
        "ordered_arm_ids": value.ordered_arm_ids,
        "ordered_bundle_digests": value.ordered_bundle_digests,
        "ordered_checkpoint_slot_digests": value.ordered_checkpoint_slot_digests,
        "ordered_input_set_digests": value.ordered_input_set_digests,
        "ordered_budget_digests": value.ordered_budget_digests,
        "ordered_environment_digests": value.ordered_environment_digests,
        "ordered_destination_digests": value.ordered_destination_digests,
    }
    if include_digest:
        result["authority_digest"] = value.authority_digest
    return result


@dataclass(frozen=True)
class AutomaticRetryAuthorityV1:
    """Content-addressed pre-spend retry identity; authorizing only via head."""

    population_digest: str
    freeze_digest: str
    admission_identity_digest: str
    plan_digest: str
    ordered_arm_ids: tuple[str, ...]
    ordered_bundle_digests: tuple[str, ...]
    ordered_checkpoint_slot_digests: tuple[str, ...]
    ordered_input_set_digests: tuple[str, ...]
    ordered_budget_digests: tuple[str, ...]
    ordered_environment_digests: tuple[str, ...]
    ordered_destination_digests: tuple[str, ...]
    authority_digest: str

    def __post_init__(self) -> None:
        for digest in (
            self.population_digest,
            self.freeze_digest,
            self.admission_identity_digest,
            self.plan_digest,
        ):
            _require_digest(digest)
        for row in (
            self.ordered_bundle_digests,
            self.ordered_checkpoint_slot_digests,
            self.ordered_input_set_digests,
            self.ordered_budget_digests,
            self.ordered_environment_digests,
            self.ordered_destination_digests,
        ):
            if not row or any(_require_digest(item) != item for item in row):
                raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        if not self.ordered_arm_ids or any(type(item) is not str or not item or len(item) > 128 for item in self.ordered_arm_ids):
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        expected = canonical.content_digest(_authority_value(self, include_digest=False))
        if self.authority_digest == "":
            object.__setattr__(self, "authority_digest", expected)
        elif self.authority_digest != expected:
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)


@dataclass(frozen=True)
class AdmissionRunRequestV1:
    """Every authority an admission preflight needs before label access."""

    population_digest: str
    freeze_digest: str
    freeze: PopulationFreezeV3
    manifest: LabelBlindPopulationManifestV3
    plan: RegisteredEvaluationPlanV1
    current_registrations: tuple[ArmRegistrationV1, ...]
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...]
    census_review: IndependenceAttestation
    plan_review: IndependenceAttestation
    review_policy: ReviewIndependencePolicy
    resolver: canonical.ContentResolver
    capability_report: CustodyCapabilityReport
    expected_durable_store_identity: str
    expected_transient_store_identity: str
    transient_retention_profile: RetentionProfile
    execution_bindings: tuple[AdmissionExecutionBindingV1, ...]
    workflow_digest: str
    attempt_id: str
    lease_owner_id: str
    heartbeat_at: str
    lease_expires_at: str
    recorded_runtime_ms: int


@dataclass(frozen=True)
class AdmissionPreflightV1:
    """Complete preflight product: plan, feasibility, and selected authority."""

    plan_manifest: EvaluationPlanManifestV3
    feasibility: EvaluationFeasibilityV3
    lifecycle_projection: PopulationLifecycleProjectionV1
    input_set_digest: str
    expected_observation_slots: tuple[ExpectedObservationSlotV3, ...]
    insufficient_outcome: BenchmarkWorkflowOutcomeV1 | None
    scope_witnesses: tuple[AdmissionScopeWitnessV1, ...]
    retry_authority: AutomaticRetryAuthorityV1 | None
    retry_authority_reference: ArtifactReference | None
    workflow_head: WorkflowHeadV1 | None
    custody_log_digest: str


class IsolatedArmExecutor(Protocol):
    def execute(self, registration: ArmRegistrationV1, bundle: LabelBlindExecutionBundleV1) -> object: ...


def _planned_scopes(plan: RegisteredEvaluationPlanV1) -> tuple[ScopeKey, ...]:
    return tuple(sorted({scope for row in plan.registrations for scope in row.configuration.exact_scopes}))


def _census_scope_rows(plan: RegisteredEvaluationPlanV1, manifest: LabelBlindPopulationManifestV3) -> tuple[ExactScopeCensusV3, ...]:
    planned = _planned_scopes(plan)
    counts = {ScopeKey(row.vulnerability_family, row.ecosystem.value): row.count for row in manifest.scope_census}
    if any(scope not in counts for scope in planned):
        raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED)
    return tuple(ExactScopeCensusV3(scope, counts[scope], counts[scope], counts[scope], counts[scope], counts[scope]) for scope in planned)


def _ordinary_rows(
    plan: RegisteredEvaluationPlanV1,
    manifest: LabelBlindPopulationManifestV3,
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...],
) -> tuple[EcosystemOrdinaryCensusV3, ...]:
    if type(ordinary_census) is not tuple or not ordinary_census:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    for row in ordinary_census:
        row.__post_init__()
    ecosystems = tuple(row.ecosystem for row in ordinary_census)
    if ecosystems != tuple(sorted(set(ecosystems))) or ecosystems != tuple(sorted({scope.ecosystem for scope in _planned_scopes(plan)})):
        raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED)
    if sum(row.ordinary_push_count for row in ordinary_census) != manifest.input_count - manifest.positive_count:
        raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED)
    return ordinary_census


def _census_draft(
    plan: RegisteredEvaluationPlanV1,
    manifest: LabelBlindPopulationManifestV3,
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...],
    review: IndependenceAttestation,
) -> PopulationCensusV3:
    if type(review) is not IndependenceAttestation:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    return PopulationCensusV3(
        manifest.population_digest,
        _census_scope_rows(plan, manifest),
        _ordinary_rows(plan, manifest, ordinary_census),
        manifest.input_count,
        False,
        "0" * 64,
        review,
        "0" * 64,
    )


def admission_census_payload_digest(
    plan: RegisteredEvaluationPlanV1,
    manifest: LabelBlindPopulationManifestV3,
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...],
    review: IndependenceAttestation,
) -> str:
    """Derive the deterministic census payload subject an external review signs."""
    return derive_evaluation_census_payload_digest(_census_draft(plan, manifest, ordinary_census, review))


def compose_population_census(
    plan: RegisteredEvaluationPlanV1,
    manifest: LabelBlindPopulationManifestV3,
    ordinary_census: tuple[EcosystemOrdinaryCensusV3, ...],
    review: IndependenceAttestation,
) -> PopulationCensusV3:
    """Bind one external census review over the exact composed label-blind census."""
    draft = _census_draft(plan, manifest, ordinary_census, review)
    payload = derive_evaluation_census_payload_digest(draft)
    if review.subject_digest != payload:
        raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED)
    bound = replace(draft, payload_digest=payload)
    return replace(bound, census_digest=derive_evaluation_census_digest(bound))


def _manifest_draft(
    plan: RegisteredEvaluationPlanV1,
    census: PopulationCensusV3,
    readiness_digests: tuple[str, ...],
    custody_log_digest: str,
    review: IndependenceAttestation,
) -> EvaluationPlanManifestV3:
    if type(review) is not IndependenceAttestation:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    if type(readiness_digests) is not tuple or not readiness_digests:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    for digest in readiness_digests:
        _require_digest(digest)
    return EvaluationPlanManifestV3(
        plan.declaration,
        plan.baselines,
        census,
        readiness_digests,
        _require_digest(custody_log_digest),
        "0" * 64,
        review,
        "0" * 64,
    )


def admission_manifest_payload_digest(
    plan: RegisteredEvaluationPlanV1,
    census: PopulationCensusV3,
    readiness_digests: tuple[str, ...],
    custody_log_digest: str,
    review: IndependenceAttestation,
) -> str:
    """Derive the deterministic plan-manifest payload subject an external review signs."""
    return derive_evaluation_plan_manifest_payload_digest(_manifest_draft(plan, census, readiness_digests, custody_log_digest, review))


def compose_plan_manifest(
    plan: RegisteredEvaluationPlanV1,
    census: PopulationCensusV3,
    readiness_digests: tuple[str, ...],
    custody_log_digest: str,
    review: IndependenceAttestation,
) -> EvaluationPlanManifestV3:
    """Bind one external manifest review over the exact composed core V3 plan."""
    draft = _manifest_draft(plan, census, readiness_digests, custody_log_digest, review)
    payload = derive_evaluation_plan_manifest_payload_digest(draft)
    if review.subject_digest != payload:
        raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED)
    bound = replace(draft, payload_digest=payload)
    return replace(bound, manifest_digest=derive_evaluation_plan_manifest_digest(bound))


def _validated_request(request: AdmissionRunRequestV1) -> None:
    if type(request) is not AdmissionRunRequestV1:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    for digest in (
        request.population_digest,
        request.freeze_digest,
        request.workflow_digest,
        request.expected_durable_store_identity,
        request.expected_transient_store_identity,
    ):
        _require_digest(digest)
    if (
        type(request.freeze) is not PopulationFreezeV3
        or type(request.manifest) is not LabelBlindPopulationManifestV3
        or type(request.plan) is not RegisteredEvaluationPlanV1
        or type(request.census_review) is not IndependenceAttestation
        or type(request.plan_review) is not IndependenceAttestation
        or type(request.review_policy) is not ReviewIndependencePolicy
        or type(request.capability_report) is not CustodyCapabilityReport
        or type(request.transient_retention_profile) is not RetentionProfile
        or not callable(getattr(request.resolver, "resolve", None))
        or type(request.execution_bindings) is not tuple
        or any(type(row) is not AdmissionExecutionBindingV1 for row in request.execution_bindings)
        or type(request.current_registrations) is not tuple
        or not request.current_registrations
        or any(type(row) is not ArmRegistrationV1 for row in request.current_registrations)
        or type(request.recorded_runtime_ms) is not int
        or not 0 <= request.recorded_runtime_ms <= 1 << 31
    ):
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
    components = tuple(sorted(row.arm_id for row in request.plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT))
    if not components or tuple(row.arm_id for row in request.execution_bindings) != components:
        raise _refused(AdmissionPreflightReason.INVALID_REQUEST)


def _retry_authority(request: AdmissionRunRequestV1, manifest: LabelBlindPopulationManifestV3) -> AutomaticRetryAuthorityV1:
    plan = request.plan
    components = tuple(sorted(row.arm_id for row in plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT))
    identity = canonical.content_digest(
        {
            "schema_version": RETRY_AUTHORITY_SCHEMA,
            "manifest_digest": manifest.manifest_digest,
            "census_review": request.census_review.attestation_digest,
            "plan_review": request.plan_review.attestation_digest,
            "capability_report": request.capability_report.report_digest,
            "review_policy": request.review_policy.policy_digest,
            "workflow": request.workflow_digest,
        }
    )
    bindings = request.execution_bindings
    return AutomaticRetryAuthorityV1(
        request.population_digest,
        request.freeze_digest,
        identity,
        plan.plan_digest,
        tuple(row.arm_id for row in plan.registrations),
        tuple(row.bundle_digest for row in bindings),
        tuple(slot.slot_digest for slot in plan.declaration.expected_observation_slots),
        tuple(manifest.input_set_digest for _ in components),
        tuple(row.budget_digest for row in bindings),
        tuple(row.environment_digest for row in bindings),
        tuple(row.destination_digest for row in bindings),
        "",
    )


def _scope_witnesses(feasibility: EvaluationFeasibilityV3) -> tuple[AdmissionScopeWitnessV1, ...]:
    return tuple(
        AdmissionScopeWitnessV1(row.key.arm_id, row.key.scope.family_id, row.key.scope.ecosystem, row.reasons)
        for row in feasibility.rows
        if row.status is not FeasibilityStatusV3.FEASIBLE
    )


class AdmissionOrchestrator:
    """One atomic multi-arm admission lifecycle; this task owns preflight."""

    def __init__(
        self,
        lifecycle_authority: BaselineLifecycleAuthority,
        repository: S3ArtifactRepository,
        custody: PopulationCustodyPort,
        journal: S3WorkflowJournal,
        executor: IsolatedArmExecutor,
        custodian_access_policy_digest: str,
    ) -> None:
        if type(lifecycle_authority) is not BaselineLifecycleAuthority:
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        if type(repository) is not S3ArtifactRepository or type(journal) is not S3WorkflowJournal:
            raise _refused(AdmissionPreflightReason.INVALID_REQUEST)
        self._lifecycle = lifecycle_authority
        self._repository = repository
        self._custody = custody
        self._journal = journal
        self._executor = executor
        self._access_policy_digest = _require_digest(custodian_access_policy_digest)

    def preflight(self, request: AdmissionRunRequestV1) -> AdmissionPreflightV1:
        """Validate every gate, then select authority only after feasibility."""
        try:
            require_scoped_admission_v3()
        except ScopedAdmissionV3ConformanceError:
            raise _refused(AdmissionPreflightReason.CORE_UNAVAILABLE) from None
        _validated_request(request)
        projection = self._lifecycle_gate(request)
        self._capability_gate(request)
        self._freeze_gate(request)
        manifest = self._manifest_gate(request)
        self._arm_gate(request, manifest)
        custody_log_digest = self._custody_gate(request)
        plan_manifest, feasibility = self._composed(request, custody_log_digest)
        preflight = AdmissionPreflightV1(
            plan_manifest,
            feasibility,
            projection,
            manifest.input_set_digest,
            request.plan.declaration.expected_observation_slots,
            None,
            _scope_witnesses(feasibility),
            None,
            None,
            None,
            custody_log_digest,
        )
        if preflight.scope_witnesses:
            return self._insufficient(request, preflight)
        return self._authorized(request, preflight, manifest)

    def _lifecycle_gate(self, request: AdmissionRunRequestV1) -> PopulationLifecycleProjectionV1:
        try:
            return self._lifecycle.require_admission_eligible(request.population_digest, request.freeze_digest)
        except LifecycleError:
            raise _refused(AdmissionPreflightReason.LIFECYCLE_NOT_ADMISSIBLE) from None

    def _capability_gate(self, request: AdmissionRunRequestV1) -> None:
        try:
            require_real_population_admission(
                request.capability_report,
                request.expected_durable_store_identity,
                request.expected_transient_store_identity,
                request.transient_retention_profile,
            )
        except RealPopulationAdmissionDisabled:
            raise _refused(AdmissionPreflightReason.STORE_CAPABILITY_FAILED) from None

    def _freeze_gate(self, request: AdmissionRunRequestV1) -> None:
        try:
            population_freeze_bytes(request.freeze)
        except (TypeError, ValueError, AttributeError):
            raise _refused(AdmissionPreflightReason.FREEZE_NOT_ADMISSION_CLASS) from None
        if request.freeze.population_class is not PopulationClass.ADMISSION:
            raise _refused(AdmissionPreflightReason.FREEZE_NOT_ADMISSION_CLASS)
        if (request.freeze.population_digest, request.freeze.freeze_digest) != (
            request.population_digest,
            request.freeze_digest,
        ):
            raise _refused(AdmissionPreflightReason.FREEZE_NOT_ADMISSION_CLASS)

    def _manifest_gate(self, request: AdmissionRunRequestV1) -> LabelBlindPopulationManifestV3:
        try:
            label_blind_population_manifest_bytes(request.manifest)
        except (LabelBlindManifestError, TypeError, ValueError):
            raise _refused(AdmissionPreflightReason.MANIFEST_UNRESOLVED) from None
        if (
            request.manifest.population_digest,
            request.manifest.freeze_digest,
        ) != (request.population_digest, request.freeze_digest) or not request.manifest.scope_census:
            raise _refused(AdmissionPreflightReason.MANIFEST_UNRESOLVED)
        return request.manifest

    def _arm_gate(self, request: AdmissionRunRequestV1, manifest: LabelBlindPopulationManifestV3) -> None:
        try:
            validate_registered_evaluation_plan(request.plan)
        except ArmRegistryError:
            raise _refused(AdmissionPreflightReason.ARM_IDENTITY_STALE) from None
        declaration = request.plan.declaration
        if (
            declaration.population_digest,
            declaration.freeze_digest,
            declaration.input_set_digest,
        ) != (manifest.population_digest, manifest.freeze_digest, manifest.input_set_digest):
            raise _refused(AdmissionPreflightReason.ARM_IDENTITY_STALE)
        current = {row.arm_id: row for row in request.current_registrations}
        for row in request.plan.registrations:
            match = current.get(row.arm_id)
            if (
                match is None
                or match.registration_digest != row.registration_digest
                or match.lifecycle_state is not ArmLifecycleState.ACTIVE
            ):
                raise _refused(AdmissionPreflightReason.ARM_IDENTITY_STALE)

    def _custody_gate(self, request: AdmissionRunRequestV1) -> str:
        try:
            log = self._custody.current_log(request.population_digest)
        except Exception:
            raise _refused(AdmissionPreflightReason.CUSTODY_HEAD_UNRESOLVED) from None
        if type(log) is not PopulationCustodyLog or log.status is not PopulationStatus.AVAILABLE:
            raise _refused(AdmissionPreflightReason.CUSTODY_HEAD_UNRESOLVED)
        return log.log_digest

    def _composed(
        self, request: AdmissionRunRequestV1, custody_log_digest: str
    ) -> tuple[EvaluationPlanManifestV3, EvaluationFeasibilityV3]:
        try:
            census = compose_population_census(request.plan, request.manifest, request.ordinary_census, request.census_review)
            plan_manifest = compose_plan_manifest(
                request.plan,
                census,
                (request.capability_report.report_digest,),
                custody_log_digest,
                request.plan_review,
            )
            feasibility = derive_evaluation_feasibility(plan_manifest, request.review_policy, request.resolver)
        except AdmissionOrchestratorError:
            raise
        except _COMPOSE_FAILURES:
            raise _refused(AdmissionPreflightReason.PLAN_COMPOSITION_FAILED) from None
        return plan_manifest, feasibility

    def _insufficient(self, request: AdmissionRunRequestV1, preflight: AdmissionPreflightV1) -> AdmissionPreflightV1:
        planned_inputs = len(request.manifest.input_digests)
        counts = WorkflowCounts(len(request.plan.registrations), 0, planned_inputs, 0, planned_inputs)
        outcome = BenchmarkWorkflowOutcomeV1(
            WorkflowStatus.INSUFFICIENT,
            WorkflowPhase.PREFLIGHT,
            (WorkflowReasonCode.SCOPE_INSUFFICIENT,),
            request.population_digest,
            request.freeze_digest,
            request.plan.plan_digest,
            request.workflow_digest,
            False,
            counts,
            (WorkflowGate.PREFLIGHT_FEASIBILITY,),
            (),
            request.recorded_runtime_ms,
            "",
            "",
            None,
            "",
        )
        self._persist_witnesses(request, outcome, preflight.scope_witnesses)
        return replace(preflight, insufficient_outcome=outcome)

    def _persist_witnesses(
        self,
        request: AdmissionRunRequestV1,
        outcome: BenchmarkWorkflowOutcomeV1,
        witnesses: tuple[AdmissionScopeWitnessV1, ...],
    ) -> None:
        outcome_payload = cast("dict[str, JsonValue]", json.loads(workflow_outcome_bytes(outcome)))
        witness_payload: dict[str, JsonValue] = {
            "schema_version": PREFLIGHT_WITNESS_SCHEMA,
            "workflow_digest": request.workflow_digest,
            "outcome_digest": outcome.outcome_digest,
            "plan_digest": request.plan.plan_digest,
            "failed_gates": tuple(gate.value for gate in outcome.failed_gate_names),
            "scope_witnesses": tuple(
                {
                    "arm_id": row.arm_id,
                    "family_id": row.family_id,
                    "ecosystem": row.ecosystem,
                    "reasons": row.reasons,
                }
                for row in witnesses
            ),
        }
        provenance = canonical.content_digest({"workflow": request.workflow_digest, "stage": "preflight-witness"})
        for payload in (outcome_payload, witness_payload):
            self._persist(payload, ArtifactAccessClass.OPERATOR_SAFE, provenance)

    def _persist(self, payload: dict[str, JsonValue], access: ArtifactAccessClass, provenance: str) -> tuple[ArtifactReference, bytes]:
        content = canonical_artifact_bytes(ArtifactKind.WORKFLOW, payload, access_class=access, provenance_digest=provenance)
        reference = artifact_reference(content)
        try:
            self._repository.put_if_absent(content, reference=reference)
        except ArtifactRepositoryError:
            raise _refused(AdmissionPreflightReason.PERSISTENCE_FAILED) from None
        return reference, content

    def _reread_sealed(self, reference: ArtifactReference, content: bytes) -> None:
        authority = artifact_read_authority(
            ArtifactActorRole.CUSTODIAN,
            (ArtifactReadPermission.CUSTODIAN_SEALED,),
            self._access_policy_digest,
            expected_access_policy_digest=self._access_policy_digest,
        )
        try:
            accepted = self._repository.get(
                reference,
                expected_kind=ArtifactKind.WORKFLOW,
                authority=authority,
                expected_access_policy_digest=self._access_policy_digest,
            )
        except ArtifactRepositoryError:
            raise _refused(AdmissionPreflightReason.PERSISTENCE_FAILED) from None
        if accepted.content != content:
            raise _refused(AdmissionPreflightReason.PERSISTENCE_FAILED)

    def _authorized(
        self, request: AdmissionRunRequestV1, preflight: AdmissionPreflightV1, manifest: LabelBlindPopulationManifestV3
    ) -> AdmissionPreflightV1:
        authority = _retry_authority(request, manifest)
        provenance = canonical.content_digest(
            {"workflow": request.workflow_digest, "attempt": request.attempt_id, "stage": "retry-authority"}
        )
        reference, content = self._persist(
            _authority_value(authority, include_digest=True), ArtifactAccessClass.CUSTODIAN_SEALED, provenance
        )
        self._reread_sealed(reference, content)
        head = self._select_in_head(request, reference)
        return replace(
            preflight,
            retry_authority=authority,
            retry_authority_reference=reference,
            workflow_head=head,
        )

    def _select_in_head(self, request: AdmissionRunRequestV1, reference: ArtifactReference) -> WorkflowHeadV1:
        planned_inputs = len(request.manifest.input_digests)
        counts = WorkflowCounts(len(request.plan.registrations), 0, planned_inputs, 0, 0)
        entry = WorkflowJournalEntryV1(
            request.workflow_digest,
            0,
            None,
            request.attempt_id,
            request.lease_owner_id,
            WorkflowPhase.PREFLIGHT,
            request.heartbeat_at,
            request.lease_expires_at,
            counts,
            "",
        )
        try:
            head = self._journal.initialize(entry, reference, reference.content_digest)
            if head is None:
                raise _refused(AdmissionPreflightReason.WORKFLOW_HEAD_EXISTS)
            reread = self._journal.current_head(request.workflow_digest)
            require_selected_authority(reread, reference, reference.content_digest)
        except AdmissionOrchestratorError:
            raise
        except WorkflowJournalError:
            raise _refused(AdmissionPreflightReason.PERSISTENCE_FAILED) from None
        return reread


__all__ = [
    "PREFLIGHT_WITNESS_SCHEMA",
    "RETRY_AUTHORITY_SCHEMA",
    "AdmissionExecutionBindingV1",
    "AdmissionOrchestrator",
    "AdmissionOrchestratorError",
    "AdmissionPreflightReason",
    "AdmissionPreflightV1",
    "AdmissionRunRequestV1",
    "AdmissionScopeWitnessV1",
    "AutomaticRetryAuthorityV1",
    "IsolatedArmExecutor",
    "admission_census_payload_digest",
    "admission_manifest_payload_digest",
    "compose_plan_manifest",
    "compose_population_census",
]
