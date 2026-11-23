"""Task 9.3 benchmark-only operator run, resume, and status commands.

The entry point validates settings and store capabilities before any run,
resume, or status operation is accepted, drives the committed admission seams
in order while appending durable journal heartbeats between phases, and
renders one deterministic operator projection per command. Notifier transport,
detector rollout, worker health, bucket administration, and retry policy stay
with their owning workflows: no command constructs a client, administers a
bucket, or writes detector or infrastructure state.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar, cast

from benchmarks.valid.admission_case_adapter import bind_case_adapter_replay_stage
from benchmarks.valid.admission_case_graph import AdmissionCaseAdapterRequestV1
from benchmarks.valid.admission_execution import (
    AdmissionExecutionError,
    AdmissionExecutionV1,
)
from benchmarks.valid.admission_orchestrator import (
    AdmissionOrchestrator,
    AdmissionOrchestratorError,
    AdmissionPreflightV1,
    AdmissionRunRequestV1,
    IsolatedArmExecutor,
)
from benchmarks.valid.admission_replay import (
    AdmissionReplayError,
    ScopedReplayPublicationV1,
)
from benchmarks.valid.admission_spend import AdmissionSpendError, AdmissionSpendReleaseV1
from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadAuthority,
    ArtifactRepositoryError,
    S3ArtifactRepository,
    S3ObjectClient,
    artifact_read_authority,
)
from benchmarks.valid.custody_probe_contract import CustodyCapabilityReport
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from benchmarks.valid.lifecycle import BaselineLifecycleAuthority
from benchmarks.valid.observation_checkpoint import CheckpointSelectorV1, ObservationCheckpointAdapter
from benchmarks.valid.operator_report import (
    ResolvedOperatorReplay,
    operator_report_bytes,
    operator_report_text,
    resolve_operator_replay,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationManifestV3
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from benchmarks.valid.replacement_artifact_contract import (
    AcceptedArtifact,
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
    canonical_json_bytes,
)
from benchmarks.valid.sealed_retry import (
    AutomaticRetryError,
    AutomaticRetryStatus,
    RetryMismatchAuthorityV1,
    resume_pre_spend_sealed_retry,
)
from benchmarks.valid.sealed_retry_recovery import resume_spent_sealed_run
from benchmarks.valid.store_configuration import (
    RetentionProfile,
    StoreCapabilityEvidence,
    StoreConfiguration,
    StorePurpose,
    StoreStartupError,
    StoreStartupReport,
    StoreStartupStatus,
    assess_store_startup,
    load_store_configuration,
    require_store_startup,
    store_namespace_identity,
)
from benchmarks.valid.workflow_journal import (
    S3WorkflowJournal,
    S3WorkflowJournalClient,
    WorkflowJournalEntryV1,
    WorkflowJournalError,
    WorkflowJournalReason,
    WorkflowJournalStatus,
    successor_head,
)
from benchmarks.valid.workflow_outcome import (
    BenchmarkWorkflowOutcomeV1,
    DegradationCode,
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
    decode_workflow_outcome,
    workflow_outcome_bytes,
)
from openultrasast.core.canonical import JsonValue, content_digest
from openultrasast.core.custody import PopulationCustodyPolicy, PopulationStatus
from openultrasast.core.evaluation_replay import EvaluationReplayV3

OPERATOR_COMMAND_SCHEMA = "openultrasast.valid-detection-benchmark.operator-command.v1"
OPERATOR_READ_POLICY_DIGEST = content_digest("operator-command-read-policy")
OPERATOR_OUTCOME_PROVENANCE = content_digest({"stage": "operator-command-outcome"})


class OperatorCommandKind(StrEnum):
    """Closed benchmark-only command surface."""

    RUN = "run"
    RESUME = "resume"
    STATUS = "status"


class OperatorCommandReason(StrEnum):
    """Closed refusal reasons; the error never echoes caller content."""

    SETTINGS_INVALID = "settings_invalid"
    CAPABILITIES_UNSUPPORTED = "capabilities_unsupported"
    INVALID_REQUEST = "invalid_request"
    WORKFLOW_UNKNOWN = "workflow_unknown"
    WORKFLOW_SUPERSEDED = "workflow_superseded"
    OUTCOME_PENDING = "outcome_pending"
    OUTCOME_UNRESOLVED = "outcome_unresolved"
    RESUME_BLOCKED = "resume_blocked"


class OperatorCommandError(RuntimeError):
    """Refuse one command with a closed reason before or during operation."""

    def __init__(self, reason: OperatorCommandReason) -> None:
        self.reason = reason
        super().__init__(f"operator_command_{reason.value}")


_SEAM_REFUSALS = (
    AdmissionExecutionError,
    AdmissionOrchestratorError,
    AdmissionReplayError,
    AdmissionSpendError,
    AutomaticRetryError,
    WorkflowJournalError,
)


@dataclass(frozen=True)
class BenchmarkOperatorContextV1:
    """Stores bound to one validated configuration; commands never build clients."""

    configuration: StoreConfiguration
    journal: S3WorkflowJournal
    repository: S3ArtifactRepository
    custody: S3DurableCustodyStore
    orchestrator: AdmissionOrchestrator


@dataclass(frozen=True)
class OperatorCommandResultV1:
    """One deterministic operator projection with its durable outcome reference."""

    command: OperatorCommandKind
    outcome: BenchmarkWorkflowOutcomeV1
    report_bytes: bytes
    report_text: str
    outcome_reference: ArtifactReference | None


@dataclass(frozen=True)
class BenchmarkRunStagesV1:
    """The committed execute/spend/replay/publish seams driven in order."""

    execution: Callable[[AdmissionPreflightV1], AdmissionExecutionV1]
    spend: Callable[[AdmissionExecutionV1], AdmissionSpendReleaseV1]
    replay: Callable[[AdmissionSpendReleaseV1], EvaluationReplayV3]
    publication: Callable[[EvaluationReplayV3], ScopedReplayPublicationV1]


@dataclass(frozen=True)
class BenchmarkRunRequestV1:
    """Operator authorities for one run plus its progress counts and runtime."""

    preflight_request: AdmissionRunRequestV1
    stages: BenchmarkRunStagesV1
    counts: WorkflowCounts
    runtime_ms: int = 0


@dataclass(frozen=True)
class BenchmarkResumeRequestV1:
    """Operator authorities one resume needs after the expired validated head."""

    workflow_digest: str
    admission_identity_digest: str
    component_index: int
    bundles: tuple[LabelBlindExecutionBundleV1, ...]
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...]
    plan: RegisteredEvaluationPlanV1
    adapter: ObservationCheckpointAdapter
    artifact_authority: ArtifactReadAuthority
    manifest: LabelBlindPopulationManifestV3
    public_material_manifest: PublicPopulationMaterialManifestV1
    selection: OrdinarySelectionV1
    lifecycle_authority: BaselineLifecycleAuthority
    mismatch_authority: RetryMismatchAuthorityV1 | None = None
    access_policy_digest: str = ""
    attempt_id: str = ""
    lease_owner_id: str = ""
    heartbeat_at: str = ""
    lease_expires_at: str = ""
    now: str = ""
    runtime_ms: int = 0


@dataclass(frozen=True)
class BenchmarkStatusRequestV1:
    """Head identity, terminal-outcome reference, and replay for validation."""

    workflow_digest: str
    now: str
    population_digest: str
    freeze_digest: str
    plan_digest: str
    outcome_reference: ArtifactReference | None
    replay: EvaluationReplayV3 | None


def validated_operator_configuration(
    environ: Mapping[str, str], evidence: Mapping[StorePurpose, StoreCapabilityEvidence]
) -> StoreConfiguration:
    """Validate settings and capabilities before any operation is accepted."""
    try:
        report = assess_store_startup(environ, evidence)
        require_store_startup(report)
        return load_store_configuration(environ)
    except StoreStartupError as error:
        raise OperatorCommandError(_startup_reason(error.report)) from None


def _startup_reason(report: StoreStartupReport) -> OperatorCommandReason:
    if report.status is StoreStartupStatus.MISSING_CONFIGURATION:
        return OperatorCommandReason.SETTINGS_INVALID
    return OperatorCommandReason.CAPABILITIES_UNSUPPORTED


def bound_operator_context(
    configuration: StoreConfiguration,
    durable_client: S3ObjectClient,
    transient_client: S3WorkflowJournalClient,
    lifecycle_authority: BaselineLifecycleAuthority,
    custody_policy: PopulationCustodyPolicy,
    capability_report: CustodyCapabilityReport,
    transient_identity: str,
    transient_profile: RetentionProfile,
    executor: IsolatedArmExecutor,
    custodian_access_policy_digest: str,
) -> BenchmarkOperatorContextV1:
    """Bind every store the commands may touch to the validated configuration."""
    _validated_configuration(configuration)
    repository = S3ArtifactRepository(configuration.durable, durable_client)
    journal = S3WorkflowJournal(configuration.transient, transient_client)
    custody = S3DurableCustodyStore(
        configuration.durable, durable_client, custody_policy, capability_report, transient_identity, transient_profile
    )
    orchestrator = AdmissionOrchestrator(lifecycle_authority, repository, custody, journal, executor, custodian_access_policy_digest)
    return BenchmarkOperatorContextV1(configuration, journal, repository, custody, orchestrator)


def _validated_configuration(configuration: object) -> None:
    if (
        type(configuration) is not StoreConfiguration
        or configuration.durable.purpose is not StorePurpose.DURABLE  # type: ignore[attr-defined]
        or configuration.transient.purpose is not StorePurpose.TRANSIENT  # type: ignore[attr-defined]
        or store_namespace_identity(configuration.durable)  # type: ignore[attr-defined]
        == store_namespace_identity(configuration.transient)  # type: ignore[attr-defined]
    ):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)


def _validated_context(context: object) -> None:
    if (
        type(context) is not BenchmarkOperatorContextV1
        or type(context.journal) is not S3WorkflowJournal  # type: ignore[attr-defined]
        or type(context.repository) is not S3ArtifactRepository  # type: ignore[attr-defined]
        or type(context.custody) is not S3DurableCustodyStore  # type: ignore[attr-defined]
        or type(context.orchestrator) is not AdmissionOrchestrator  # type: ignore[attr-defined]
    ):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)
    _validated_configuration(context.configuration)  # type: ignore[attr-defined]


class _Interrupted(Exception):
    """Internal marker carrying the phase a non-seam crash interrupted."""

    def __init__(self, phase: WorkflowPhase) -> None:
        self.phase = phase


def benchmark_run_command(context: BenchmarkOperatorContextV1, request: BenchmarkRunRequestV1) -> OperatorCommandResultV1:
    """Preflight, then execute, spend, replay, and publish with durable heartbeats."""
    _validated_context(context)
    _validated_run_request(request)
    preflight = context.orchestrator.preflight(request.preflight_request)
    if preflight.insufficient_outcome is not None:
        return _terminal_result(context, OperatorCommandKind.RUN, preflight.insufficient_outcome)
    try:
        execution = _phase(context, request, WorkflowPhase.ARM_EXECUTION, request.stages.execution, preflight)
        if execution.impaired_outcome is not None:
            return _terminal_result(context, OperatorCommandKind.RUN, execution.impaired_outcome)
        release = _phase(context, request, WorkflowPhase.CUSTODY_SPEND, request.stages.spend, execution)
        if release.refusal_reason is not None:
            return _terminal_result(context, OperatorCommandKind.RUN, _spend_refused(request, release))
        replay = _phase(context, request, WorkflowPhase.SCORING, request.stages.replay, release)
        publication = _phase(context, request, WorkflowPhase.REPORTING, request.stages.publication, replay)
    except _Interrupted as interrupted:
        return _terminal_result(context, OperatorCommandKind.RUN, _interrupted(context, request, interrupted.phase))
    return _completed_result(context, publication, replay)


def _spend_refused(request: BenchmarkRunRequestV1, release: AdmissionSpendReleaseV1) -> BenchmarkWorkflowOutcomeV1:
    prior = request.preflight_request
    return BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        WorkflowPhase.LABEL_RELEASE,
        (WorkflowReasonCode.INSTRUMENT_FAILURE,),
        prior.population_digest,
        prior.freeze_digest,
        prior.plan.plan_digest,
        prior.workflow_digest,
        release.labels_spent,
        request.counts,
        (),
        (),
        request.runtime_ms,
        "",
        "",
        None,
        "",
    )


def _validated_run_request(request: object) -> None:
    if (
        type(request) is not BenchmarkRunRequestV1
        or type(request.preflight_request) is not AdmissionRunRequestV1  # type: ignore[attr-defined]
        or type(request.stages) is not BenchmarkRunStagesV1  # type: ignore[attr-defined]
        or type(request.counts) is not WorkflowCounts  # type: ignore[attr-defined]
        or type(request.runtime_ms) is not int  # type: ignore[attr-defined]
        or not 0 <= request.runtime_ms <= 1 << 31  # type: ignore[attr-defined]
        or not callable(request.stages.execution)  # type: ignore[attr-defined]
        or not callable(request.stages.spend)  # type: ignore[attr-defined]
        or not callable(request.stages.replay)  # type: ignore[attr-defined]
        or not callable(request.stages.publication)  # type: ignore[attr-defined]
    ):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)


_T = TypeVar("_T")


def _phase(
    context: BenchmarkOperatorContextV1,
    request: BenchmarkRunRequestV1,
    phase: WorkflowPhase,
    stage: Callable[..., _T],
    prior: object,
) -> _T:
    try:
        product = stage(prior)
    except _SEAM_REFUSALS:
        raise
    except Exception:
        raise _Interrupted(phase) from None
    _heartbeat(context, request, phase)
    return product


def _heartbeat(context: BenchmarkOperatorContextV1, request: BenchmarkRunRequestV1, phase: WorkflowPhase) -> None:
    prior = context.journal.current_head(request.preflight_request.workflow_digest)
    entry = WorkflowJournalEntryV1(
        request.preflight_request.workflow_digest,
        prior.sequence + 1,
        prior.entry_digest,
        request.preflight_request.attempt_id,
        request.preflight_request.lease_owner_id,
        phase,
        request.preflight_request.heartbeat_at,
        request.preflight_request.lease_expires_at,
        request.counts,
        "",
    )
    head = successor_head(prior, entry)
    if not context.journal.append_and_swap(prior.head_digest, entry, head):
        raise OperatorCommandError(OperatorCommandReason.WORKFLOW_SUPERSEDED)


def _interrupted(context: BenchmarkOperatorContextV1, request: BenchmarkRunRequestV1, phase: WorkflowPhase) -> BenchmarkWorkflowOutcomeV1:
    prior = request.preflight_request
    spent = context.custody.current_log(prior.population_digest).status is PopulationStatus.SPENT
    return BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        phase,
        (WorkflowReasonCode.INTERRUPTED,),
        prior.population_digest,
        prior.freeze_digest,
        prior.plan.plan_digest,
        prior.workflow_digest,
        spent,
        request.counts,
        (),
        (),
        request.runtime_ms,
        "",
        "",
        None,
        "",
    )


def _completed_result(
    context: BenchmarkOperatorContextV1,
    publication: ScopedReplayPublicationV1,
    replay: EvaluationReplayV3,
) -> OperatorCommandResultV1:
    reference = _persist_terminal_outcome(context, publication.outcome)
    resolved = _resolved_replay(context, publication.outcome.evaluation_replay_ref, replay)
    return _rendered(OperatorCommandKind.RUN, publication.outcome, resolved, reference)


def _terminal_result(
    context: BenchmarkOperatorContextV1, command: OperatorCommandKind, outcome: BenchmarkWorkflowOutcomeV1
) -> OperatorCommandResultV1:
    reference = _persist_terminal_outcome(context, outcome)
    return _rendered(command, outcome, None, reference)


def benchmark_resume_command(context: BenchmarkOperatorContextV1, request: BenchmarkResumeRequestV1) -> OperatorCommandResultV1:
    """Resume one interrupted workflow from the durable store via the 8.6 seams."""
    _validated_context(context)
    _validated_resume_request(request)
    _require_workflow(context, request.workflow_digest, request.now)
    counts = WorkflowCounts(len(request.plan.registrations), 0, len(request.plan.declaration.expected_observation_slots), 0, 0)
    head = context.journal.acquire_expired_lease(
        request.workflow_digest,
        context.journal.current_head(request.workflow_digest).head_digest,
        request.attempt_id,
        request.lease_owner_id,
        phase=WorkflowPhase.ARM_EXECUTION,
        counts=counts,
        heartbeat_at=request.heartbeat_at,
        lease_expires_at=request.lease_expires_at,
    )
    if head is None:
        raise OperatorCommandError(OperatorCommandReason.WORKFLOW_SUPERSEDED)
    outcome = _resume_outcome(context, request)
    return _terminal_result(context, OperatorCommandKind.RESUME, outcome)


def _validated_resume_request(request: object) -> None:
    if (
        type(request) is not BenchmarkResumeRequestV1
        or type(request.bundles) is not tuple  # type: ignore[attr-defined]
        or not request.bundles  # type: ignore[attr-defined]
        or type(request.plan) is not RegisteredEvaluationPlanV1  # type: ignore[attr-defined]
        or type(request.component_index) is not int  # type: ignore[attr-defined]
        or not 0 <= request.component_index < len(request.bundles)  # type: ignore[attr-defined]
        or type(request.artifact_authority) is not ArtifactReadAuthority  # type: ignore[attr-defined]
        or type(request.manifest) is not LabelBlindPopulationManifestV3  # type: ignore[attr-defined]
        or type(request.public_material_manifest) is not PublicPopulationMaterialManifestV1  # type: ignore[attr-defined]
        or type(request.selection) is not OrdinarySelectionV1  # type: ignore[attr-defined]
        or type(request.lifecycle_authority) is not BaselineLifecycleAuthority  # type: ignore[attr-defined]
        or type(request.checkpoint_selectors) is not tuple  # type: ignore[attr-defined]
        or len(request.checkpoint_selectors) != len(request.bundles)  # type: ignore[attr-defined]
        or type(request.runtime_ms) is not int  # type: ignore[attr-defined]
        or not callable(getattr(request.adapter, "execute", None))  # type: ignore[attr-defined]
    ):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)
    _validated_identity(
        request,  # type: ignore[arg-type]
        (
            "workflow_digest",
            "admission_identity_digest",
            "access_policy_digest",
            "attempt_id",
            "lease_owner_id",
            "heartbeat_at",
            "lease_expires_at",
            "now",
        ),
    )


def _validated_identity(request: BenchmarkResumeRequestV1, names: tuple[str, ...]) -> None:
    for name in names:
        if type(getattr(request, name)) is not str or not getattr(request, name):
            raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)


def _resume_outcome(context: BenchmarkOperatorContextV1, request: BenchmarkResumeRequestV1) -> BenchmarkWorkflowOutcomeV1:
    population = request.bundles[0].population_digest
    spent = context.custody.current_log(population).status is PopulationStatus.SPENT
    if spent:
        resume_spent_sealed_run(
            admission_identity_digest=request.admission_identity_digest,
            bundles=request.bundles,
            checkpoint_selectors=_resume_selectors(request),
            plan=request.plan,
            journal=context.journal,
            workflow_digest=request.workflow_digest,
            repository=context.repository,
            access_policy_digest=request.access_policy_digest,
            custody=context.custody,
        )
        return _resume_envelope(request, (WorkflowReasonCode.INTERRUPTED,), WorkflowPhase.CUSTODY_SPEND, True)
    result = resume_pre_spend_sealed_retry(
        component_index=request.component_index,
        admission_identity_digest=request.admission_identity_digest,
        bundles=request.bundles,
        checkpoint_selectors=_resume_selectors(request),
        plan=request.plan,
        adapter=request.adapter,
        journal=context.journal,
        workflow_digest=request.workflow_digest,
        repository=context.repository,
        artifact_authority=request.artifact_authority,
        access_policy_digest=request.access_policy_digest,
        manifest=request.manifest,
        public_material_manifest=request.public_material_manifest,
        selection=request.selection,
        lifecycle_authority=request.lifecycle_authority,
        custody=context.custody,
        mismatch_authority=request.mismatch_authority,
    )
    reasons = (
        (WorkflowReasonCode.INTERRUPTED,) if result.status is AutomaticRetryStatus.RESUMED else (WorkflowReasonCode.INSTRUMENT_FAILURE,)
    )
    if result.status is AutomaticRetryStatus.BLOCKED:
        raise OperatorCommandError(OperatorCommandReason.RESUME_BLOCKED)
    return _resume_envelope(request, reasons, WorkflowPhase.ARM_EXECUTION, False)


def _resume_selectors(request: BenchmarkResumeRequestV1) -> tuple[CheckpointSelectorV1, ...]:
    selectors = request.checkpoint_selectors
    if any(selector is None or type(selector) is not CheckpointSelectorV1 for selector in selectors):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)
    return selectors  # type: ignore[return-value]


def _resume_envelope(
    request: BenchmarkResumeRequestV1,
    reasons: tuple[WorkflowReasonCode, ...],
    phase: WorkflowPhase,
    spent: bool,
) -> BenchmarkWorkflowOutcomeV1:
    bundle = request.bundles[0]
    return BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        phase,
        reasons,
        bundle.population_digest,
        bundle.freeze_digest,
        request.plan.plan_digest,
        request.workflow_digest,
        spent,
        WorkflowCounts(len(request.plan.registrations), 0, len(request.plan.declaration.expected_observation_slots), 0, 0),
        (),
        (DegradationCode.AUTOMATIC_RETRY_USED,),
        request.runtime_ms,
        "",
        "",
        None,
        "",
    )


def benchmark_status_command(context: BenchmarkOperatorContextV1, request: BenchmarkStatusRequestV1) -> OperatorCommandResultV1:
    """Surface terminal outcomes first, else the validated journal head projection."""
    _validated_context(context)
    _validated_status_request(request)
    outcome, resolved = _terminal_outcome(context, request)
    if outcome is None:
        outcome = _head_projection(context, request, _require_workflow(context, request.workflow_digest, request.now))
    return _rendered(OperatorCommandKind.STATUS, outcome, resolved, request.outcome_reference)


def _validated_status_request(request: object) -> None:
    if (
        type(request) is not BenchmarkStatusRequestV1
        or type(request.outcome_reference) is not ArtifactReference  # type: ignore[attr-defined]
        and request.outcome_reference is not None  # type: ignore[attr-defined]
        or type(request.population_digest) is not str  # type: ignore[attr-defined]
        or not request.population_digest  # type: ignore[attr-defined]
        or type(request.freeze_digest) is not str  # type: ignore[attr-defined]
        or not request.freeze_digest  # type: ignore[attr-defined]
        or type(request.plan_digest) is not str  # type: ignore[attr-defined]
        or not request.plan_digest  # type: ignore[attr-defined]
        or type(request.workflow_digest) is not str  # type: ignore[attr-defined]
        or not request.workflow_digest  # type: ignore[attr-defined]
        or type(request.now) is not str  # type: ignore[attr-defined]
        or not request.now  # type: ignore[attr-defined]
    ):
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)
    if request.replay is not None and type(request.replay) is not EvaluationReplayV3:  # type: ignore[attr-defined]
        raise OperatorCommandError(OperatorCommandReason.INVALID_REQUEST)


def _require_workflow(context: BenchmarkOperatorContextV1, workflow_digest: str, now: str) -> WorkflowJournalStatus:
    try:
        return context.journal.rebuild_status(workflow_digest, now)
    except WorkflowJournalError as error:
        if error.reason is WorkflowJournalReason.NOT_FOUND:
            raise OperatorCommandError(OperatorCommandReason.WORKFLOW_UNKNOWN) from None
        raise


def _terminal_outcome(
    context: BenchmarkOperatorContextV1, request: BenchmarkStatusRequestV1
) -> tuple[BenchmarkWorkflowOutcomeV1 | None, ResolvedOperatorReplay | None]:
    if request.outcome_reference is None:
        return (None, None)
    accepted = _operator_read(context, request.outcome_reference, ArtifactKind.WORKFLOW)
    try:
        outcome = decode_workflow_outcome(canonical_json_bytes(accepted.artifact.payload))
    except Exception:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED) from None
    if outcome.workflow_digest != request.workflow_digest:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED)
    return (outcome, _resolved_replay(context, outcome.evaluation_replay_ref, request.replay))


def _resolved_replay(
    context: BenchmarkOperatorContextV1, reference: ArtifactReference | None, replay: EvaluationReplayV3 | None
) -> ResolvedOperatorReplay | None:
    if reference is None:
        if replay is not None:
            raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED)
        return None
    if replay is None:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED)
    content = _operator_read(context, reference, ArtifactKind.REPLAY).content
    return resolve_operator_replay(reference, content, replay)


def _operator_read(context: BenchmarkOperatorContextV1, reference: ArtifactReference, kind: ArtifactKind) -> AcceptedArtifact:
    authority = artifact_read_authority(
        ArtifactActorRole.OPERATOR,
        (),
        OPERATOR_READ_POLICY_DIGEST,
        expected_access_policy_digest=OPERATOR_READ_POLICY_DIGEST,
    )
    try:
        return context.repository.get(
            reference, expected_kind=kind, authority=authority, expected_access_policy_digest=OPERATOR_READ_POLICY_DIGEST
        )
    except (ArtifactRepositoryError, RecursionError):
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED) from None


def _head_projection(
    context: BenchmarkOperatorContextV1,
    request: BenchmarkStatusRequestV1,
    journal_status: WorkflowJournalStatus,
) -> BenchmarkWorkflowOutcomeV1:
    if not journal_status.lease_expired:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_PENDING)
    status, reason = journal_status.projected_status, journal_status.projected_reason
    if status is None or reason is None:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_PENDING)
    spent = context.custody.current_log(request.population_digest).status is PopulationStatus.SPENT
    return BenchmarkWorkflowOutcomeV1(
        status,
        journal_status.phase,
        (reason,),
        request.population_digest,
        request.freeze_digest,
        request.plan_digest,
        request.workflow_digest,
        spent,
        journal_status.counts,
        (),
        (),
        0,
        "",
        "",
        None,
        "",
    )


def _persist_terminal_outcome(context: BenchmarkOperatorContextV1, outcome: BenchmarkWorkflowOutcomeV1) -> ArtifactReference:
    payload = cast("dict[str, JsonValue]", json.loads(workflow_outcome_bytes(outcome)))
    content = canonical_artifact_bytes(
        ArtifactKind.WORKFLOW,
        payload,
        access_class=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=content_digest({"provenance": OPERATOR_OUTCOME_PROVENANCE, "outcome": outcome.outcome_digest}),
    )
    reference = artifact_reference(content)
    try:
        context.repository.put_if_absent(content, reference=reference)
    except ArtifactRepositoryError:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED) from None
    reread = _operator_read(context, reference, ArtifactKind.WORKFLOW)
    if reread.content != content:
        raise OperatorCommandError(OperatorCommandReason.OUTCOME_UNRESOLVED)
    return reference


def _rendered(
    command: OperatorCommandKind,
    outcome: BenchmarkWorkflowOutcomeV1,
    resolved: ResolvedOperatorReplay | None,
    reference: ArtifactReference | None,
) -> OperatorCommandResultV1:
    return OperatorCommandResultV1(
        command,
        outcome,
        operator_report_bytes(outcome, resolved),
        operator_report_text(outcome, resolved),
        reference,
    )


__all__ = [
    "OPERATOR_COMMAND_SCHEMA",
    "AdmissionCaseAdapterRequestV1",
    "BenchmarkOperatorContextV1",
    "BenchmarkResumeRequestV1",
    "BenchmarkRunRequestV1",
    "BenchmarkRunStagesV1",
    "BenchmarkStatusRequestV1",
    "OperatorCommandError",
    "OperatorCommandKind",
    "OperatorCommandReason",
    "OperatorCommandResultV1",
    "benchmark_resume_command",
    "benchmark_run_command",
    "benchmark_status_command",
    "bind_case_adapter_replay_stage",
    "bound_operator_context",
    "validated_operator_configuration",
]
