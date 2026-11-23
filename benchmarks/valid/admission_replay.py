"""Task 8.5 scoped reports and one complete evaluation replay publication.

The scoped admission V3 consumer seam. This module submits every arm's
released exact-scope cases through the shared core facade, validates the
complete replay against current sources, persists it as the pre-registered
OPERATOR_SAFE replay artifact whose payload binds the decoded replay digest,
and publishes one closed workflow outcome that refuses COMPLETED unless every
planned arm carries an independently valid report over a complete baseline
identity. It also repairs the committed composition gap: custodian-sealed
observation and attempt-event envelopes are re-resolved into raw documents
behind a bridged resolver, and the plan manifest is recomposed over real
readiness results, so core authorization and replay run over correctly shaped
inputs without touching the sealed admission modules.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from fractions import Fraction
from typing import cast

from benchmarks.valid.admission_execution import AdmissionExecutionV1
from benchmarks.valid.admission_orchestrator import (
    AdmissionOrchestratorError,
    AdmissionPreflightV1,
    AdmissionRunRequestV1,
    admission_manifest_payload_digest,
    compose_plan_manifest,
)
from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadPermission,
    ArtifactRepositoryError,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_outcome import (
    BenchmarkWorkflowOutcomeV1,
    WorkflowCounts,
    WorkflowGate,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
    decode_workflow_outcome,
    workflow_outcome_bytes,
)
from openultrasast.core import canonical
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.canonical import (
    ContentRef,
    ContentResolver,
    JsonValue,
    ResolvedContent,
    StorageReceipt,
)
from openultrasast.core.custody import PopulationCustodyPort, PopulationUseReceipt
from openultrasast.core.evaluation_admission import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationAdmissionV3Error,
    authorize_evaluation,
    decode_evaluation_v3,
    preflight_evaluation,
    score_and_replay,
    validate_evaluation_replay,
)
from openultrasast.core.evaluation_attempt import AttemptEventRefV3, AttemptHistoryV3, decode_attempt_event
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionManifestV3,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_feasibility import EvaluationFeasibilityV3
from openultrasast.core.evaluation_measurement import AggregateWeightV3, MetricId
from openultrasast.core.evaluation_observation import SealedObservationRefV3, decode_arm_observation_set
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import AdmissionCaseReleaseV3, ArmAdmissionCasesV3
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_report import ArmEvaluationReportV3
from openultrasast.core.evaluation_spend import EvaluationPreparationV3, EvaluationSpendBindingV3
from openultrasast.core.factpack import IndependenceAttestation
from openultrasast.core.readiness import ReadinessResult, validate_readiness_result

REPLAY_ARTIFACT_SCHEMA = "openultrasast.valid-detection-benchmark.scoped-evaluation-replay.v1"
OPERATOR_READ_POLICY_DIGEST = canonical.content_digest("scoped-replay-operator-read-policy")
_ZERO = "0" * 64
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DECODE_FAILURES = (AttributeError, KeyError, RecursionError, TypeError, UnicodeDecodeError, ValueError)
# Every core V3 contract refusal is a ValueError subclass; this module's own
# closed refusals are RuntimeError, so the boundary below never masks them.
_CORE_REFUSALS = (
    EvaluationAdmissionV3Error,
    canonical.ArtifactResolutionError,
    canonical.ArtifactValidationError,
    ValueError,
)


class AdmissionReplayReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    REPLAY_INVALID = "replay_invalid"
    REPLAY_INCOMPLETE = "replay_incomplete"
    PERSISTENCE_FAILED = "persistence_failed"


class AdmissionReplayError(RuntimeError):
    """Refuse a scoped replay step with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionReplayReason) -> None:
        self.reason = reason
        super().__init__(f"admission_replay_{reason.value}")


def _refused(reason: AdmissionReplayReason) -> AdmissionReplayError:
    return AdmissionReplayError(reason)


def _require_digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    return value


class BridgedContentResolver:
    """Serve re-resolved sealed raw documents; delegate every other reference."""

    def __init__(self, documents: Mapping[str, ResolvedContent], fallback: ContentResolver) -> None:
        if not callable(getattr(fallback, "resolve", None)):
            raise _refused(AdmissionReplayReason.INVALID_REQUEST)
        self._documents = dict(documents)
        self._fallback = fallback

    def resolve(self, reference: ContentRef) -> ResolvedContent:
        found = self._documents.get(reference.artifact_id)
        if found is not None:
            return found
        return self._fallback.resolve(reference)


@dataclass(frozen=True)
class AdmissionBridgeRequestV1:
    """Every authority the core reconciliation bridge needs after execution."""

    repository: S3ArtifactRepository
    custodian_access_policy_digest: str
    run_request: AdmissionRunRequestV1
    preflight: AdmissionPreflightV1
    execution: AdmissionExecutionV1
    readiness: tuple[ReadinessResult, ...]
    context: AdmissionValidationContext
    custody: PopulationCustodyPort
    bridged_store_identity: str
    bridged_retention_policy_digest: str
    plan_review: IndependenceAttestation
    admission_review: IndependenceAttestation | None


@dataclass(frozen=True)
class BridgedAdmissionV1:
    """Core-authorized graph over raw documents and real readiness objects."""

    plan_manifest: EvaluationPlanManifestV3
    admission_manifest: EvaluationAdmissionManifestV3
    feasibility: EvaluationFeasibilityV3
    preparation: EvaluationPreparationV3
    resolver: BridgedContentResolver

    def __post_init__(self) -> None:
        if (
            type(self.plan_manifest) is not EvaluationPlanManifestV3
            or type(self.admission_manifest) is not EvaluationAdmissionManifestV3
            or type(self.feasibility) is not EvaluationFeasibilityV3
            or type(self.preparation) is not EvaluationPreparationV3
            or type(self.resolver) is not BridgedContentResolver
        ):
            raise _refused(AdmissionReplayReason.INVALID_REQUEST)


def _validated_readiness(values: object) -> tuple[ReadinessResult, ...]:
    if type(values) is not tuple or not values:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    for item in values:
        if type(item) is not ReadinessResult:
            raise _refused(AdmissionReplayReason.INVALID_REQUEST)
        try:
            validate_readiness_result(item)
        except (AttributeError, TypeError, ValueError):
            raise _refused(AdmissionReplayReason.INVALID_REQUEST) from None
    return values


def _validated_bridge_request(request: AdmissionBridgeRequestV1) -> None:
    if (
        type(request) is not AdmissionBridgeRequestV1
        or type(request.repository) is not S3ArtifactRepository
        or type(request.run_request) is not AdmissionRunRequestV1
        or type(request.preflight) is not AdmissionPreflightV1
        or type(request.execution) is not AdmissionExecutionV1
        or type(request.context) is not AdmissionValidationContext
        or not callable(getattr(request.custody, "current_log", None))
        or type(request.plan_review) is not IndependenceAttestation
        or type(request.bridged_store_identity) is not str
        or not request.bridged_store_identity
        or request.execution.refusal_reason is not None
        or request.execution.admission_manifest is None
    ):
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    for digest in (request.custodian_access_policy_digest, request.bridged_retention_policy_digest):
        _require_digest(digest)


def _sealed_payload(
    repository: S3ArtifactRepository,
    policy: str,
    kind: ArtifactKind,
    reference: ContentRef,
    provenance: str,
) -> dict[str, JsonValue]:
    sealed_reference = ArtifactReference(
        kind, reference.content_digest, reference.byte_length, provenance, ArtifactAccessClass.CUSTODIAN_SEALED
    )
    authority = artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.CUSTODIAN_SEALED,),
        policy,
        expected_access_policy_digest=policy,
    )
    try:
        accepted = repository.get(sealed_reference, expected_kind=kind, authority=authority, expected_access_policy_digest=policy)
    except ArtifactRepositoryError:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID) from None
    payload = accepted.artifact.payload
    if type(payload) is not dict:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID)
    return payload


def _raw_document(payload: Mapping[str, JsonValue], field: str) -> bytes:
    document = payload.get(field)
    if type(document) is not str or not document:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID)
    return document.encode("utf-8")


def _bridged_pair(prefix: str, document: bytes, request: AdmissionBridgeRequestV1) -> tuple[ContentRef, ResolvedContent]:
    digest = canonical.bytes_digest(document)
    receipt_digest = canonical.derive_storage_receipt_digest(
        store_identity=request.bridged_store_identity,
        content_digest=digest,
        byte_length=len(document),
        retention_policy_digest=request.bridged_retention_policy_digest,
    )
    reference = canonical.ContentRef(
        f"{prefix}/{digest}.json",
        digest,
        "application/json",
        len(document),
        request.bridged_retention_policy_digest,
        receipt_digest,
    )
    receipt = StorageReceipt(
        request.bridged_store_identity,
        digest,
        len(document),
        request.bridged_retention_policy_digest,
        receipt_digest,
    )
    return reference, ResolvedContent(document, receipt)


def _authorized_manifest(request: AdmissionBridgeRequestV1) -> EvaluationAdmissionManifestV3:
    execution = request.execution
    if execution.refusal_reason is not None or execution.admission_manifest is None:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    return execution.admission_manifest


def _bridged_observations(request: AdmissionBridgeRequestV1, documents: dict[str, ResolvedContent]) -> tuple[SealedObservationRefV3, ...]:
    refs = []
    for sealed in _authorized_manifest(request).observations:
        payload = _sealed_payload(
            request.repository,
            request.custodian_access_policy_digest,
            ArtifactKind.OBSERVATION,
            sealed.observation,
            sealed.observation_digest,
        )
        raw = _raw_document(payload, "observation")
        try:
            decoded = decode_arm_observation_set(raw)
        except _DECODE_FAILURES:
            raise _refused(AdmissionReplayReason.REPLAY_INVALID) from None
        if decoded.observation_digest != sealed.observation_digest:
            raise _refused(AdmissionReplayReason.REPLAY_INVALID)
        reference, resolved = _bridged_pair("observations/raw", raw, request)
        documents[reference.artifact_id] = resolved
        refs.append(replace(sealed, observation=reference, ref_digest=""))
    return tuple(refs)


def _bridged_history(request: AdmissionBridgeRequestV1, documents: dict[str, ResolvedContent]) -> AttemptHistoryV3:
    history = _authorized_manifest(request).attempt_history
    events = []
    for event in history.events:
        payload = _sealed_payload(
            request.repository,
            request.custodian_access_policy_digest,
            ArtifactKind.WORKFLOW,
            event.event,
            event.event_digest,
        )
        raw = _raw_document(payload, "event")
        try:
            decoded = decode_attempt_event(raw)
        except _DECODE_FAILURES:
            raise _refused(AdmissionReplayReason.REPLAY_INVALID) from None
        if decoded.event_digest != event.event_digest:
            raise _refused(AdmissionReplayReason.REPLAY_INVALID)
        reference, resolved = _bridged_pair("workflows/raw", raw, request)
        documents[reference.artifact_id] = resolved
        events.append(AttemptEventRefV3(reference, event.event_digest, ""))
    return AttemptHistoryV3(history.population_digest, tuple(events), history.head_event_digest, "")


def _bridged_graph(
    request: AdmissionBridgeRequestV1,
) -> tuple[
    tuple[ReadinessResult, ...],
    EvaluationPlanManifestV3,
    EvaluationFeasibilityV3,
    EvaluationAdmissionManifestV3,
    BridgedContentResolver,
]:
    _validated_bridge_request(request)
    readiness = _validated_readiness(request.readiness)
    digests = tuple(sorted(item.result_digest for item in readiness))
    try:
        plan_manifest = compose_plan_manifest(
            request.run_request.plan,
            request.preflight.plan_manifest.census,
            digests,
            request.preflight.custody_log_digest,
            request.plan_review,
        )
    except AdmissionOrchestratorError:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST) from None
    documents: dict[str, ResolvedContent] = {}
    observations = _bridged_observations(request, documents)
    history = _bridged_history(request, documents)
    resolver = BridgedContentResolver(documents, request.run_request.resolver)
    feasibility = preflight_evaluation(plan_manifest, request.context, resolver)
    draft = EvaluationAdmissionManifestV3(
        plan_manifest,
        feasibility.feasibility_digest,
        observations,
        digests,
        request.preflight.custody_log_digest,
        history,
        _ZERO,
        request.plan_review,
        _ZERO,
    )
    return readiness, plan_manifest, feasibility, draft, resolver


def bridged_plan_subject(run_request: AdmissionRunRequestV1, preflight: AdmissionPreflightV1, readiness: object) -> str:
    """Derive the recomposed plan payload subject an external review signs."""
    if type(run_request) is not AdmissionRunRequestV1 or type(preflight) is not AdmissionPreflightV1:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    digests = tuple(sorted(item.result_digest for item in _validated_readiness(readiness)))
    return admission_manifest_payload_digest(
        run_request.plan,
        preflight.plan_manifest.census,
        digests,
        preflight.custody_log_digest,
        preflight.plan_manifest.review,
    )


def bridged_admission_subject(request: AdmissionBridgeRequestV1) -> str:
    """Derive the bridged admission payload subject an external review signs."""
    _, _, _, draft, _ = _bridged_graph(request)
    return derive_evaluation_admission_manifest_payload_digest(draft)


def bridge_core_authorization(request: AdmissionBridgeRequestV1) -> BridgedAdmissionV1:
    """Hand core the raw documents and real readiness objects it can validate."""
    readiness, plan_manifest, feasibility, draft, resolver = _bridged_graph(request)
    review = request.admission_review
    if type(review) is not IndependenceAttestation:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    payload = derive_evaluation_admission_manifest_payload_digest(draft)
    if review.subject_digest != payload:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    manifest = replace(draft, payload_digest=payload, review=review)
    manifest = replace(manifest, manifest_digest=derive_evaluation_admission_manifest_digest(manifest))
    try:
        preparation = authorize_evaluation(manifest, feasibility, readiness, request.context, request.custody, resolver)
    except _CORE_REFUSALS:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID) from None
    return BridgedAdmissionV1(plan_manifest, manifest, feasibility, preparation, resolver)


def equal_aggregate_weights(plan_manifest: EvaluationPlanManifestV3) -> tuple[AggregateWeightV3, ...]:
    """Explicit equal reduced-rational weights over every planned arm-scope constituent."""
    if type(plan_manifest) is not EvaluationPlanManifestV3:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    keys = tuple(
        sorted(
            {policy.key for configuration in plan_manifest.declaration.arm_configurations for policy in configuration.denominator_policies}
        )
    )
    if not keys:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID)
    share = Fraction(1, len(keys))
    return tuple(AggregateWeightV3(key, share.numerator, share.denominator, "") for key in keys)


@dataclass(frozen=True)
class ScopedReplayRequestV1:
    """Every core root the shared authority needs to score and replay."""

    admission_manifest: EvaluationAdmissionManifestV3
    feasibility: EvaluationFeasibilityV3
    preparation: EvaluationPreparationV3
    receipt: PopulationUseReceipt
    spend_binding: EvaluationSpendBindingV3
    release: AdmissionCaseReleaseV3
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...]
    readiness: tuple[ReadinessResult, ...]
    context: AdmissionValidationContext
    custody: PopulationCustodyPort
    resolver: ContentResolver
    aggregate: bool = False


def derive_scoped_replay(request: ScopedReplayRequestV1) -> EvaluationReplayV3:
    """Submit every arm's cases through the shared authority and validate the replay."""
    if type(request) is not ScopedReplayRequestV1:
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    weights = equal_aggregate_weights(request.admission_manifest.plan_manifest) if request.aggregate else None
    try:
        replay = score_and_replay(
            request.admission_manifest,
            request.feasibility,
            request.preparation,
            request.receipt,
            request.spend_binding,
            request.release,
            request.cases_by_arm,
            request.readiness,
            request.context,
            request.custody,
            request.resolver,
            aggregate_weights=weights,
        )
        validate_evaluation_replay(replay, request.context, request.custody, request.resolver)
    except _CORE_REFUSALS:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID) from None
    return replay


@dataclass(frozen=True)
class ReplayPublicationRequestV1:
    """Inputs the publication seam binds before any completed outcome exists."""

    repository: S3ArtifactRepository
    replay: EvaluationReplayV3
    planned_arm_ids: tuple[str, ...]
    planned_input_count: int
    population_digest: str
    freeze_digest: str
    plan_digest: str
    workflow_digest: str
    runtime_ms: int


@dataclass(frozen=True)
class ScopedReplayPublicationV1:
    """Closed publication product; COMPLETED only with every planned arm."""

    outcome: BenchmarkWorkflowOutcomeV1
    replay_reference: ArtifactReference | None
    replay_digest: str
    reports: tuple[ArmEvaluationReportV3, ...]
    scoped_decisions: tuple[tuple[str, str, str, str], ...]

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not BenchmarkWorkflowOutcomeV1
            or type(self.replay_reference) is not ArtifactReference
            and self.replay_reference is not None
            or type(self.reports) is not tuple
            or type(self.scoped_decisions) is not tuple
        ):
            raise _refused(AdmissionReplayReason.INVALID_REQUEST)
        if self.replay_reference is not None and self.replay_reference.artifact_kind is not ArtifactKind.REPLAY:
            raise _refused(AdmissionReplayReason.INVALID_REQUEST)
        _require_digest(self.replay_digest)


def _validated_publication_request(request: ReplayPublicationRequestV1) -> None:
    if (
        type(request) is not ReplayPublicationRequestV1
        or type(request.repository) is not S3ArtifactRepository
        or type(request.replay) is not EvaluationReplayV3
        or type(request.planned_arm_ids) is not tuple
        or not request.planned_arm_ids
        or any(type(item) is not str or not item or len(item) > 128 for item in request.planned_arm_ids)
        or type(request.planned_input_count) is not int
        or request.planned_input_count < 1
        or type(request.runtime_ms) is not int
        or not 0 <= request.runtime_ms <= 1 << 31
    ):
        raise _refused(AdmissionReplayReason.INVALID_REQUEST)
    for digest in (request.population_digest, request.freeze_digest, request.plan_digest, request.workflow_digest):
        _require_digest(digest)


def _decoded_replay(value: object) -> EvaluationReplayV3:
    if type(value) is not EvaluationReplayV3:
        raise _refused(AdmissionReplayReason.REPLAY_INVALID)
    return decode_evaluation_v3(EVALUATION_ADMISSION_V3_SCHEMA, value, EvaluationReplayV3)


def _report_defect(replay: EvaluationReplayV3, planned_arm_ids: tuple[str, ...]) -> bool:
    reports = replay.reports
    arm_ids = tuple(report.baseline.arm_id for report in reports)
    if not reports or arm_ids != tuple(sorted(arm_ids)) or len(set(arm_ids)) != len(arm_ids):
        return True
    if any(arm not in arm_ids for arm in planned_arm_ids):
        return True
    baselines = {row.baseline_digest for row in replay.plan_manifest.baselines}
    if {report.baseline.baseline_digest for report in reports} != baselines:
        return True
    for report in reports:
        if not report.scoped_results or not report.operational_evidence.completed_count >= 1:
            return True
        if tuple(metric.metric_id for metric in report.scoped_results[0].metrics) != tuple(MetricId):
            return True
    return False


def _observation_defect(replay: EvaluationReplayV3) -> bool:
    observations = replay.report_source.observations
    if not observations:
        return True
    for observation in observations:
        if observation.input_read_evidence_digest in ("", _ZERO):
            return True
        if observation.stage_execution_evidence_digest in ("", _ZERO):
            return True
    return False


def _completion_defect(replay: EvaluationReplayV3, planned_arm_ids: tuple[str, ...]) -> AdmissionReplayReason | None:
    if _report_defect(replay, planned_arm_ids):
        return AdmissionReplayReason.REPLAY_INCOMPLETE
    if _observation_defect(replay):
        return AdmissionReplayReason.REPLAY_INVALID
    return None


def _scoped_decisions(replay: EvaluationReplayV3) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (
            report.baseline.arm_id,
            result.key.scope.family_id,
            result.key.scope.ecosystem,
            result.decision.value,
        )
        for report in replay.reports
        for result in report.scoped_results
    )


def _persist_publication(
    repository: S3ArtifactRepository, payload: dict[str, JsonValue], kind: ArtifactKind, provenance: str
) -> tuple[ArtifactReference, bytes]:
    content = canonical_artifact_bytes(kind, payload, access_class=ArtifactAccessClass.OPERATOR_SAFE, provenance_digest=provenance)
    reference = artifact_reference(content)
    try:
        repository.put_if_absent(content, reference=reference)
    except ArtifactRepositoryError:
        raise _refused(AdmissionReplayReason.PERSISTENCE_FAILED) from None
    return reference, content


def _operator_reread(repository: S3ArtifactRepository, reference: ArtifactReference, expected_kind: ArtifactKind, content: bytes) -> None:
    authority = artifact_read_authority(
        ArtifactActorRole.OPERATOR,
        (),
        OPERATOR_READ_POLICY_DIGEST,
        expected_access_policy_digest=OPERATOR_READ_POLICY_DIGEST,
    )
    try:
        accepted = repository.get(
            reference,
            expected_kind=expected_kind,
            authority=authority,
            expected_access_policy_digest=OPERATOR_READ_POLICY_DIGEST,
        )
    except ArtifactRepositoryError:
        raise _refused(AdmissionReplayReason.PERSISTENCE_FAILED) from None
    if accepted.content != content:
        raise _refused(AdmissionReplayReason.PERSISTENCE_FAILED)


def _replay_payload(replay: EvaluationReplayV3) -> dict[str, JsonValue]:
    return {
        "schema_version": REPLAY_ARTIFACT_SCHEMA,
        "replay_digest": replay.replay_digest,
        "plan_manifest_digest": replay.plan_manifest.manifest_digest,
        "admission_manifest_digest": replay.admission_manifest.manifest_digest,
        "authority_digest": replay.authority.authority_digest,
        "receipt_digest": replay.receipt.receipt_digest,
        "spend_binding_digest": replay.spend_binding.binding_digest,
        "release_digest": replay.case_release.release_digest,
        "arm_ids": tuple(report.baseline.arm_id for report in replay.reports),
        "whole_underlying_push_count": replay.whole_population_coverage.underlying_push_count,
    }


def _persist_outcome(repository: S3ArtifactRepository, outcome: BenchmarkWorkflowOutcomeV1) -> None:
    payload = cast("dict[str, JsonValue]", json.loads(workflow_outcome_bytes(outcome)))
    provenance = canonical.content_digest({"workflow": outcome.workflow_digest, "stage": "scoped-replay-outcome"})
    reference, content = _persist_publication(repository, payload, ArtifactKind.WORKFLOW, provenance)
    _operator_reread(repository, reference, ArtifactKind.WORKFLOW, content)
    if decode_workflow_outcome(workflow_outcome_bytes(outcome)) != outcome:
        raise _refused(AdmissionReplayReason.PERSISTENCE_FAILED)


def _impaired_publication(request: ReplayPublicationRequestV1, replay: EvaluationReplayV3) -> ScopedReplayPublicationV1:
    counts = WorkflowCounts(len(request.planned_arm_ids), len(replay.reports), request.planned_input_count, 0, 0)
    outcome = BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        WorkflowPhase.SCORING,
        (WorkflowReasonCode.INSTRUMENT_FAILURE,),
        request.population_digest,
        request.freeze_digest,
        request.plan_digest,
        request.workflow_digest,
        True,
        counts,
        (WorkflowGate.REPLAY_VALIDATION,),
        (),
        request.runtime_ms,
        "",
        "",
        None,
        "",
    )
    _persist_outcome(request.repository, outcome)
    return ScopedReplayPublicationV1(outcome, None, replay.replay_digest, replay.reports, _scoped_decisions(replay))


def _completed_publication(request: ReplayPublicationRequestV1, replay: EvaluationReplayV3) -> ScopedReplayPublicationV1:
    observations = replay.report_source.observations
    reads = tuple(item.input_read_evidence_digest for item in observations)
    stages = tuple(item.stage_execution_evidence_digest for item in observations)
    provenance = canonical.content_digest({"workflow": request.workflow_digest, "stage": "scoped-evaluation-replay"})
    reference, content = _persist_publication(request.repository, _replay_payload(replay), ArtifactKind.REPLAY, provenance)
    _operator_reread(request.repository, reference, ArtifactKind.REPLAY, content)
    counts = WorkflowCounts(
        len(request.planned_arm_ids),
        len(request.planned_arm_ids),
        request.planned_input_count,
        request.planned_input_count,
        0,
    )
    outcome = BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.COMPLETED,
        WorkflowPhase.REPORTING,
        (),
        request.population_digest,
        request.freeze_digest,
        request.plan_digest,
        request.workflow_digest,
        True,
        counts,
        (),
        (),
        request.runtime_ms,
        canonical.content_digest({"input_read_evidence_digests": reads}),
        canonical.content_digest({"stage_execution_evidence_digests": stages}),
        reference,
        "",
    )
    _persist_outcome(request.repository, outcome)
    return ScopedReplayPublicationV1(outcome, reference, replay.replay_digest, replay.reports, _scoped_decisions(replay))


def publish_scoped_replay(request: ReplayPublicationRequestV1) -> ScopedReplayPublicationV1:
    """Publish one closed outcome; missing one planned arm or report blocks completion."""
    _validated_publication_request(request)
    replay = _decoded_replay(request.replay)
    if _completion_defect(replay, request.planned_arm_ids) is not None:
        return _impaired_publication(request, replay)
    return _completed_publication(request, replay)


__all__ = [
    "REPLAY_ARTIFACT_SCHEMA",
    "AdmissionBridgeRequestV1",
    "AdmissionReplayError",
    "AdmissionReplayReason",
    "BridgedAdmissionV1",
    "BridgedContentResolver",
    "ReplayPublicationRequestV1",
    "ScopedReplayPublicationV1",
    "ScopedReplayRequestV1",
    "bridge_core_authorization",
    "bridged_admission_subject",
    "bridged_plan_subject",
    "derive_scoped_replay",
    "equal_aggregate_weights",
    "publish_scoped_replay",
]
