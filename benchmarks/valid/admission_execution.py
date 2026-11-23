"""Task 8.2 admission execution: seal every planned observation before spend.

The execution phase resolves the retry authority selected by the CURRENT
workflow head before any checkpoint resolution, adapter call, or spend
attempt, sends the identical ordered label-blind input set to every planned
component arm, freezes every component observation custodian-sealed, derives
the registered combined observations without rerunning cases, composes the
core V3 admission manifest from the exact sealed observation references and
combination lineage, and reauthorizes immediately before custody CAS against
current bytes, current lifecycle, current readiness, and the current custody
head. The spend itself and label release stay outside this module.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import cast

from benchmarks.valid.admission_orchestrator import (
    RETRY_AUTHORITY_SCHEMA,
    AdmissionOrchestratorError,
    AdmissionPreflightV1,
    AdmissionRunRequestV1,
    AutomaticRetryAuthorityV1,
)
from benchmarks.valid.arm_combination import (
    CombinationPlannerError,
    ComponentObservationV1,
    combine_observations,
    register_combination_plan,
)
from benchmarks.valid.arm_combination_contract import CombinationRuleRegistrationV1
from benchmarks.valid.arm_contract import RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import (
    ArtifactActorRole,
    ArtifactReadAuthority,
    ArtifactReadPermission,
    ArtifactRepositoryError,
    ArtifactRepositoryReason,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.custody_probe_contract import (
    RealPopulationAdmissionDisabled,
    require_real_population_admission,
)
from benchmarks.valid.isolated_execution_bundle import (
    LabelBlindExecutionBundleV1,
    build_component_execution_bundles,
)
from benchmarks.valid.isolated_execution_contract import (
    ArmExecutionBudgetV1,
    ExecutionAdapterKind,
    IsolatedExecutionError,
    LabelBlindCaseInputV1,
)
from benchmarks.valid.lifecycle import LifecycleError
from benchmarks.valid.lifecycle_projection import BaselineLifecycleAuthority
from benchmarks.valid.observation_checkpoint import (
    ArmCheckpointResultV1,
    CheckpointSelectorV1,
    CheckpointStatus,
    ObservationCheckpointAdapter,
    execute_or_resume_component,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from benchmarks.valid.replacement_artifact_contract import (
    AcceptedArtifact,
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_journal import (
    S3WorkflowJournal,
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
from openultrasast.core.custody import PopulationCustodyPort, PopulationStatus
from openultrasast.core.evaluation_attempt import (
    AttemptEventRefV3,
    AttemptEventV3,
    AttemptHistoryV3,
    ObservationAccessPolicyV3,
    PreSpendDispositionV3,
    PublicStatusFieldV3,
    derive_attempt_identity,
    encode_attempt_event,
)
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionManifestV3,
    EvaluationPlanManifestV3,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_measurement import ArmKindV3
from openultrasast.core.evaluation_observation import (
    ArmObservationSetV3,
    SealedObservationRefV3,
    decode_arm_observation_set,
    encode_arm_observation_set,
)
from openultrasast.core.factpack import IndependenceAttestation

SPEND_AUTHORIZATION_SCHEMA = "openultrasast.valid-detection-benchmark.spend-authorization.v1"
ADMISSION_EXECUTION_WITNESS_SCHEMA = "openultrasast.valid-detection-benchmark.admission-execution-witness.v1"
SEALED_OBSERVATION_DOCUMENT_SCHEMA = "openultrasast.valid-detection-benchmark.sealed-observation-document.v1"
ATTEMPT_EVENT_DOCUMENT_SCHEMA = "openultrasast.valid-detection-benchmark.attempt-event-document.v1"
ADMISSION_MANIFEST_WITNESS_SCHEMA = "openultrasast.valid-detection-benchmark.admission-manifest-witness.v1"
_SEALED = ArtifactAccessClass.CUSTODIAN_SEALED
_FAILURES = (TypeError, ValueError, KeyError, AttributeError)
_DIGEST = re.compile(r"[0-9a-f]{64}")


class AdmissionExecutionReason(StrEnum):
    """Closed refusal reasons; no free-form failure text is serializable."""

    INVALID_REQUEST = "invalid_request"
    AUTHORITY_UNRESOLVED = "authority_unresolved"
    AUTHORITY_SUBSTITUTED = "authority_substituted"
    AUTHORITY_MISMATCHED = "authority_mismatched"
    EXECUTION_IMPAIRED = "execution_impaired"
    COMBINATION_FAILED = "combination_failed"
    OBSERVATION_MISSING = "observation_missing"
    OBSERVATION_UNREADABLE = "observation_unreadable"
    OBSERVATION_CHANGED = "observation_changed"
    OBSERVATION_UNSEALED = "observation_unsealed"
    LIFECYCLE_NOT_ADMISSIBLE = "lifecycle_not_admissible"
    READINESS_FAILED = "readiness_failed"
    CUSTODY_HEAD_MOVED = "custody_head_moved"
    MANIFEST_INVALID = "manifest_invalid"
    PERSISTENCE_FAILED = "persistence_failed"


class AdmissionExecutionError(RuntimeError):
    """Refuse an execution step with a closed reason and no caller content."""

    def __init__(self, reason: AdmissionExecutionReason) -> None:
        self.reason = reason
        super().__init__(f"admission_execution_{reason.value}")


def _refused(reason: AdmissionExecutionReason) -> AdmissionExecutionError:
    return AdmissionExecutionError(reason)


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
    return value


@dataclass(frozen=True)
class SpendAuthorizationV1:
    """Closed pre-CAS verdict; authority bytes live only in the sealed store."""

    may_spend: bool
    authorization_digest: str
    refusal_reasons: tuple[AdmissionExecutionReason, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        if type(self.may_spend) is not bool:
            raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
        reasons = tuple(sorted(set(self.refusal_reasons), key=lambda item: item.value))
        if self.refusal_reasons != reasons or any(type(item) is not AdmissionExecutionReason for item in reasons):
            raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
        if self.may_spend:
            if self.refusal_reasons or not self.authorization_digest:
                raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
            _digest(self.authorization_digest)
        elif self.authorization_digest:
            raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
        if self.manifest_digest:
            _digest(self.manifest_digest)


@dataclass(frozen=True)
class AdmissionExecutionRequestV1:
    """Every execution authority needed after an authorized preflight."""

    preflight: AdmissionPreflightV1
    run_request: AdmissionRunRequestV1
    selection: OrdinarySelectionV1
    public_material_manifest: PublicPopulationMaterialManifestV1
    cases: tuple[LabelBlindCaseInputV1, ...]
    budgets: tuple[ArmExecutionBudgetV1, ...]
    adapter: ObservationCheckpointAdapter
    checkpoint_selectors: tuple[CheckpointSelectorV1 | None, ...]
    combination_registrations: tuple[CombinationRuleRegistrationV1, ...]
    admission_review: IndependenceAttestation | None
    attempt_event_review: IndependenceAttestation
    attempt_status_ref: canonical.ContentRef
    durable_store_identity: str
    observation_retention_policy_digest: str
    output_namespace_digest: str


@dataclass(frozen=True)
class AdmissionExecutionV1:
    """Execution product: sealed observations, manifest, and spend verdict."""

    refusal_reason: AdmissionExecutionReason | None
    component_results: tuple[ArmCheckpointResultV1, ...]
    combined_arm_ids: tuple[str, ...]
    combination_plan_digest: str
    sealed_observations: tuple[SealedObservationRefV3, ...]
    manifest_subject_digest: str
    admission_manifest: EvaluationAdmissionManifestV3 | None
    spend_authorization: SpendAuthorizationV1 | None
    impaired_outcome: BenchmarkWorkflowOutcomeV1 | None


def _validated_request(request: AdmissionExecutionRequestV1) -> None:
    selectors_ok = all(item is None or type(item) is CheckpointSelectorV1 for item in request.checkpoint_selectors)
    if (
        type(request) is not AdmissionExecutionRequestV1
        or type(request.preflight) is not AdmissionPreflightV1
        or type(request.run_request) is not AdmissionRunRequestV1
        or type(request.selection) is not OrdinarySelectionV1
        or type(request.public_material_manifest) is not PublicPopulationMaterialManifestV1
        or type(request.cases) is not tuple
        or type(request.budgets) is not tuple
        or not callable(getattr(request.adapter, "execute", None))
        or type(request.checkpoint_selectors) is not tuple
        or not selectors_ok
        or type(request.combination_registrations) is not tuple
        or (request.admission_review is not None and type(request.admission_review) is not IndependenceAttestation)
        or type(request.attempt_event_review) is not IndependenceAttestation
        or type(request.attempt_status_ref) is not canonical.ContentRef
    ):
        raise _refused(AdmissionExecutionReason.INVALID_REQUEST)
    for digest in (
        request.durable_store_identity,
        request.observation_retention_policy_digest,
        request.output_namespace_digest,
    ):
        _digest(digest)


def _custodian_authority(policy_digest: str) -> ArtifactReadAuthority:
    return artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.CUSTODIAN_SEALED,),
        policy_digest,
        expected_access_policy_digest=policy_digest,
    )


def _sealed_read(
    repository: S3ArtifactRepository,
    reference: ArtifactReference,
    kind: ArtifactKind,
    policy_digest: str,
    reason: AdmissionExecutionReason,
) -> AcceptedArtifact:
    try:
        return repository.get(
            reference,
            expected_kind=kind,
            authority=_custodian_authority(policy_digest),
            expected_access_policy_digest=policy_digest,
        )
    except ArtifactRepositoryError:
        raise _refused(reason) from None


def resolve_current_retry_authority(
    journal: S3WorkflowJournal,
    repository: S3ArtifactRepository,
    custodian_access_policy_digest: str,
    workflow_digest: str,
) -> AutomaticRetryAuthorityV1:
    """Resolve the retry authority only through the current CAS head."""
    try:
        head = journal.current_head(_digest(workflow_digest))
    except WorkflowJournalError:
        raise _refused(AdmissionExecutionReason.AUTHORITY_UNRESOLVED) from None
    try:
        accepted = repository.get(
            head.retry_authority_ref,
            expected_kind=ArtifactKind.WORKFLOW,
            authority=_custodian_authority(custodian_access_policy_digest),
            expected_access_policy_digest=custodian_access_policy_digest,
        )
    except ArtifactRepositoryError as error:
        reason = (
            AdmissionExecutionReason.AUTHORITY_UNRESOLVED
            if error.reason is ArtifactRepositoryReason.NOT_FOUND
            else AdmissionExecutionReason.AUTHORITY_SUBSTITUTED
        )
        raise _refused(reason) from None
    payload = accepted.artifact.payload
    try:
        require_selected_authority(head, accepted.reference, accepted.reference.content_digest)
        authority = AutomaticRetryAuthorityV1(
            cast("str", payload["population_digest"]),
            cast("str", payload["freeze_digest"]),
            cast("str", payload["admission_identity_digest"]),
            cast("str", payload["plan_digest"]),
            _authority_row(payload, "ordered_arm_ids"),
            _authority_row(payload, "ordered_bundle_digests"),
            _authority_row(payload, "ordered_checkpoint_slot_digests"),
            _authority_row(payload, "ordered_input_set_digests"),
            _authority_row(payload, "ordered_budget_digests"),
            _authority_row(payload, "ordered_environment_digests"),
            _authority_row(payload, "ordered_destination_digests"),
            cast("str", payload["authority_digest"]),
        )
    except (*_FAILURES, AdmissionOrchestratorError, WorkflowJournalError):
        raise _refused(AdmissionExecutionReason.AUTHORITY_SUBSTITUTED) from None
    if payload.get("schema_version") != RETRY_AUTHORITY_SCHEMA:
        raise _refused(AdmissionExecutionReason.AUTHORITY_SUBSTITUTED)
    if payload.get("authority_digest") != authority.authority_digest:
        raise _refused(AdmissionExecutionReason.AUTHORITY_SUBSTITUTED)
    return authority


def _authority_row(payload: Mapping[str, JsonValue], key: str) -> tuple[str, ...]:
    return tuple(cast("tuple[str, ...]", payload[key]))


def _verify_authority_binding(authority: AutomaticRetryAuthorityV1, run: AdmissionRunRequestV1, preflight: AdmissionPreflightV1) -> None:
    if preflight.retry_authority is None or preflight.retry_authority != authority:
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    if (
        authority.population_digest,
        authority.freeze_digest,
        authority.plan_digest,
    ) != (run.population_digest, run.freeze_digest, run.plan.plan_digest):
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    if authority.ordered_arm_ids != tuple(row.arm_id for row in run.plan.registrations):
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    if authority.ordered_checkpoint_slot_digests != tuple(slot.slot_digest for slot in run.plan.declaration.expected_observation_slots):
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    components = tuple(sorted(row.arm_id for row in run.plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT))
    if not components or tuple(row.arm_id for row in run.execution_bindings) != components:
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    for ordered, field in (
        ("ordered_bundle_digests", "bundle_digest"),
        ("ordered_budget_digests", "budget_digest"),
        ("ordered_environment_digests", "environment_digest"),
        ("ordered_destination_digests", "destination_digest"),
    ):
        if getattr(authority, ordered) != tuple(getattr(row, field) for row in run.execution_bindings):
            raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)
    if authority.ordered_input_set_digests != tuple(run.manifest.input_set_digest for _ in components):
        raise _refused(AdmissionExecutionReason.AUTHORITY_MISMATCHED)


def _component_observations(
    repository: S3ArtifactRepository, policy: str, results: tuple[ArmCheckpointResultV1, ...]
) -> tuple[ArmObservationSetV3, ...]:
    observations: list[ArmObservationSetV3] = []
    for result in results:
        reference = result.reference
        if reference is None:
            raise _refused(AdmissionExecutionReason.OBSERVATION_MISSING)
        accepted = _sealed_read(repository, reference, ArtifactKind.OBSERVATION, policy, AdmissionExecutionReason.OBSERVATION_UNREADABLE)
        documents = cast("tuple[str, ...]", accepted.artifact.payload["observations"])
        try:
            observations.extend(decode_arm_observation_set(row.encode()) for row in documents)
        except _FAILURES:
            raise _refused(AdmissionExecutionReason.OBSERVATION_UNREADABLE) from None
    return tuple(observations)


def _observation_index(
    plan: RegisteredEvaluationPlanV1,
    registrations: tuple[CombinationRuleRegistrationV1, ...],
    observations: tuple[ArmObservationSetV3, ...],
) -> tuple[dict[tuple[str, str], ArmObservationSetV3], tuple[str, ...], str]:
    registered = register_combination_plan(plan, registrations)
    combined_ids = tuple(sorted(row.arm_id for row in plan.registrations if row.configuration.kind is ArmKindV3.COMBINED))
    index = {(row.arm_id, row.input_identity_digest): row for row in observations}
    inputs = tuple(sorted({row.input_identity_digest for row in observations}))
    for combined_id in combined_ids:
        for identity in inputs:
            components = tuple(ComponentObservationV1(row, (), "") for row in observations if row.input_identity_digest == identity)
            derived = combine_observations(registered, combined_id, components).combined_observation
            index[(combined_id, identity)] = derived
    return index, combined_ids, registered.combination_plan_digest


def _content_ref(reference: ArtifactReference, request: AdmissionExecutionRequestV1, prefix: str) -> canonical.ContentRef:
    retention = request.observation_retention_policy_digest
    return canonical.ContentRef(
        f"{prefix}/{_SEALED.value}/{reference.content_digest}.json",
        reference.content_digest,
        "application/json",
        reference.byte_length,
        retention,
        canonical.derive_storage_receipt_digest(
            store_identity=request.durable_store_identity,
            content_digest=reference.content_digest,
            byte_length=reference.byte_length,
            retention_policy_digest=retention,
        ),
    )


def _persist_sealed(
    repository: S3ArtifactRepository,
    policy: str,
    kind: ArtifactKind,
    payload: dict[str, JsonValue],
    provenance: str,
    reason: AdmissionExecutionReason,
) -> ArtifactReference:
    content = canonical_artifact_bytes(kind, payload, access_class=_SEALED, provenance_digest=provenance)
    reference = artifact_reference(content)
    try:
        repository.put_if_absent(content, reference=reference)
    except ArtifactRepositoryError as error:
        if error.reason is ArtifactRepositoryReason.IDENTITY_CONFLICT:
            raise _refused(AdmissionExecutionReason.OBSERVATION_CHANGED) from None
        raise _refused(reason) from None
    accepted = _sealed_read(repository, reference, kind, policy, reason)
    if accepted.content != content:
        raise _refused(AdmissionExecutionReason.OBSERVATION_CHANGED)
    return reference


def _seal_observations(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    index: dict[tuple[str, str], ArmObservationSetV3],
) -> tuple[SealedObservationRefV3, ...]:
    refs = []
    for slot in request.run_request.plan.declaration.expected_observation_slots:
        observation = index.get((slot.arm_id, slot.input_identity_digest))
        if observation is None:
            raise _refused(AdmissionExecutionReason.OBSERVATION_MISSING)
        document = encode_arm_observation_set(observation)
        payload: dict[str, JsonValue] = {
            "schema_version": SEALED_OBSERVATION_DOCUMENT_SCHEMA,
            "access_class": _SEALED.value,
            "slot_digest": slot.slot_digest,
            "observation": document.decode(),
            "observation_digest": observation.observation_digest,
        }
        reference = _persist_sealed(
            repository,
            policy,
            ArtifactKind.OBSERVATION,
            payload,
            observation.observation_digest,
            AdmissionExecutionReason.PERSISTENCE_FAILED,
        )
        refs.append(
            SealedObservationRefV3(
                slot.slot_digest,
                slot.arm_id,
                slot.input_identity_digest,
                slot.execution_identity,
                observation.registered_budget_digest,
                observation.configuration_digest,
                _content_ref(reference, request, "observations"),
                observation.observation_digest,
                observation.input_read_evidence_digest,
                "",
            )
        )
    return tuple(refs)


def initial_attempt_event(
    plan_manifest: EvaluationPlanManifestV3, status_ref: canonical.ContentRef, review: IndependenceAttestation
) -> AttemptEventV3:
    """Build the deterministic initial sealed attempt event for one run."""
    identity = derive_attempt_identity(plan_manifest)
    access = ObservationAccessPolicyV3(tuple(PublicStatusFieldV3), False, False, "")
    return AttemptEventV3(identity, PreSpendDispositionV3.SEALED, access, 0, 0, status_ref, None, "", review, "")


def initial_attempt_event_payload_digest(plan_manifest: EvaluationPlanManifestV3, status_ref: canonical.ContentRef) -> str:
    """Derive the exact subject an external attempt-event review must sign."""
    event = initial_attempt_event(plan_manifest, status_ref, _pending_review(status_ref))
    event.__post_init__()
    return event.payload_digest


def _pending_review(reference: canonical.ContentRef) -> IndependenceAttestation:
    return IndependenceAttestation("0" * 64, "0" * 64, "0" * 64, reference, "0" * 64)


def _compose_manifest(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    sealed: tuple[SealedObservationRefV3, ...],
) -> tuple[EvaluationAdmissionManifestV3 | None, str]:
    preflight = request.preflight
    event = initial_attempt_event(preflight.plan_manifest, request.attempt_status_ref, request.attempt_event_review)
    event_payload: dict[str, JsonValue] = {
        "schema_version": ATTEMPT_EVENT_DOCUMENT_SCHEMA,
        "event": encode_attempt_event(event).decode(),
        "event_digest": event.event_digest,
    }
    event_reference = _persist_sealed(
        repository,
        policy,
        ArtifactKind.WORKFLOW,
        event_payload,
        event.event_digest,
        AdmissionExecutionReason.PERSISTENCE_FAILED,
    )
    history = AttemptHistoryV3(
        preflight.plan_manifest.declaration.population_digest,
        (AttemptEventRefV3(_content_ref(event_reference, request, "workflows"), event.event_digest, ""),),
        event.event_digest,
        "",
    )
    draft = EvaluationAdmissionManifestV3(
        preflight.plan_manifest,
        preflight.feasibility.feasibility_digest,
        sealed,
        preflight.plan_manifest.readiness_digests,
        preflight.custody_log_digest,
        history,
        "0" * 64,
        request.attempt_event_review,
        "0" * 64,
    )
    subject = derive_evaluation_admission_manifest_payload_digest(draft)
    review = request.admission_review
    if review is None:
        return None, subject
    if review.subject_digest != subject:
        raise _refused(AdmissionExecutionReason.MANIFEST_INVALID)
    manifest = replace(draft, payload_digest=subject, review=review)
    manifest = replace(manifest, manifest_digest=derive_evaluation_admission_manifest_digest(manifest))
    witness: dict[str, JsonValue] = {
        "schema_version": ADMISSION_MANIFEST_WITNESS_SCHEMA,
        "manifest_digest": manifest.manifest_digest,
        "payload_digest": subject,
        "custody_log_digest": preflight.custody_log_digest,
        "observation_ref_digests": tuple(item.ref_digest for item in sealed),
        "attempt_history_digest": history.history_digest,
    }
    _persist_sealed(
        repository,
        policy,
        ArtifactKind.WORKFLOW,
        witness,
        manifest.manifest_digest,
        AdmissionExecutionReason.PERSISTENCE_FAILED,
    )
    return manifest, subject


def _classify_observation_read(repository: S3ArtifactRepository, policy: str, reference: ArtifactReference) -> AdmissionExecutionReason:
    published = _publication_probe(repository, policy, reference)
    if published is None:
        return AdmissionExecutionReason.OBSERVATION_UNREADABLE
    if published:
        return AdmissionExecutionReason.OBSERVATION_UNSEALED
    return AdmissionExecutionReason.OBSERVATION_CHANGED


def _publication_probe(repository: S3ArtifactRepository, policy: str, reference: ArtifactReference) -> bool | None:
    """Report whether the sealed identity is also reachable through a public class."""
    try:
        repository.get(
            replace(reference, access_class=ArtifactAccessClass.PUBLIC),
            expected_kind=ArtifactKind.OBSERVATION,
            authority=artifact_read_authority(ArtifactActorRole.OPERATOR, (), policy, expected_access_policy_digest=policy),
            expected_access_policy_digest=policy,
        )
    except ArtifactRepositoryError as error:
        if error.reason is ArtifactRepositoryReason.NOT_FOUND:
            return False
        if error.reason is ArtifactRepositoryReason.INVALID_OBJECT:
            return True
        return None
    return True


def _verify_sealed_observation(
    repository: S3ArtifactRepository,
    policy: str,
    sealed: SealedObservationRefV3,
) -> AdmissionExecutionReason | None:
    reference = ArtifactReference(
        ArtifactKind.OBSERVATION,
        sealed.observation.content_digest,
        sealed.observation.byte_length,
        sealed.observation_digest,
        _SEALED,
    )
    try:
        accepted = repository.get(
            reference,
            expected_kind=ArtifactKind.OBSERVATION,
            authority=_custodian_authority(policy),
            expected_access_policy_digest=policy,
        )
    except ArtifactRepositoryError as error:
        if error.reason is ArtifactRepositoryReason.NOT_FOUND:
            return AdmissionExecutionReason.OBSERVATION_MISSING
        if error.reason is ArtifactRepositoryReason.INVALID_OBJECT:
            return _classify_observation_read(repository, policy, reference)
        return AdmissionExecutionReason.OBSERVATION_UNREADABLE
    payload = accepted.artifact.payload
    if payload.get("access_class") != _SEALED.value or payload.get("observation_digest") != sealed.observation_digest:
        return AdmissionExecutionReason.OBSERVATION_CHANGED
    published = _publication_probe(repository, policy, reference)
    if published is None:
        return AdmissionExecutionReason.OBSERVATION_UNREADABLE
    if published:
        return AdmissionExecutionReason.OBSERVATION_UNSEALED
    return None


def reauthorize_before_spend(
    lifecycle: BaselineLifecycleAuthority,
    repository: S3ArtifactRepository,
    custody: PopulationCustodyPort,
    custodian_access_policy_digest: str,
    run_request: AdmissionRunRequestV1,
    preflight: AdmissionPreflightV1,
    sealed_observations: tuple[SealedObservationRefV3, ...],
    admission_manifest: EvaluationAdmissionManifestV3 | None = None,
) -> SpendAuthorizationV1:
    """Re-check current bytes, lifecycle, readiness, and custody before CAS."""
    if type(sealed_observations) is not tuple or not sealed_observations:
        return SpendAuthorizationV1(False, "", (AdmissionExecutionReason.OBSERVATION_MISSING,), "")
    refusals = [
        reason
        for reason in (_verify_sealed_observation(repository, custodian_access_policy_digest, sealed) for sealed in sealed_observations)
        if reason is not None
    ]
    try:
        lifecycle.require_admission_eligible(run_request.population_digest, run_request.freeze_digest)
    except LifecycleError:
        refusals.append(AdmissionExecutionReason.LIFECYCLE_NOT_ADMISSIBLE)
    try:
        require_real_population_admission(
            run_request.capability_report,
            run_request.expected_durable_store_identity,
            run_request.expected_transient_store_identity,
            run_request.transient_retention_profile,
        )
    except RealPopulationAdmissionDisabled:
        refusals.append(AdmissionExecutionReason.READINESS_FAILED)
    try:
        log = custody.current_log(run_request.population_digest)
    except Exception:
        refusals.append(AdmissionExecutionReason.CUSTODY_HEAD_MOVED)
    else:
        if log.status is not PopulationStatus.AVAILABLE or log.log_digest != preflight.custody_log_digest:
            refusals.append(AdmissionExecutionReason.CUSTODY_HEAD_MOVED)
    if refusals or admission_manifest is None:
        return SpendAuthorizationV1(False, "", tuple(sorted(set(refusals), key=lambda item: item.value)), "")
    return _persist_authorization(
        repository, custodian_access_policy_digest, run_request, preflight, sealed_observations, admission_manifest
    )


def _persist_authorization(
    repository: S3ArtifactRepository,
    policy: str,
    run_request: AdmissionRunRequestV1,
    preflight: AdmissionPreflightV1,
    sealed: tuple[SealedObservationRefV3, ...],
    manifest: EvaluationAdmissionManifestV3,
) -> SpendAuthorizationV1:
    witness: dict[str, JsonValue] = {
        "schema_version": SPEND_AUTHORIZATION_SCHEMA,
        "workflow_digest": run_request.workflow_digest,
        "plan_digest": run_request.plan.plan_digest,
        "custody_log_digest": preflight.custody_log_digest,
        "manifest_digest": manifest.manifest_digest,
        "observation_ref_digests": tuple(item.ref_digest for item in sealed),
    }
    try:
        reference = _persist_sealed(
            repository,
            policy,
            ArtifactKind.WORKFLOW,
            witness,
            manifest.manifest_digest,
            AdmissionExecutionReason.PERSISTENCE_FAILED,
        )
    except AdmissionExecutionError:
        return SpendAuthorizationV1(False, "", (AdmissionExecutionReason.PERSISTENCE_FAILED,), "")
    return SpendAuthorizationV1(True, reference.content_digest, (), manifest.manifest_digest)


def _impaired(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    phase: WorkflowPhase,
    gates: tuple[WorkflowGate, ...],
    reason: AdmissionExecutionReason,
    completed_arms: int,
) -> AdmissionExecutionV1:
    run = request.run_request
    planned_inputs = len(run.manifest.input_digests)
    counts = WorkflowCounts(len(run.plan.registrations), completed_arms, planned_inputs, 0, 0)
    outcome = BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        phase,
        (WorkflowReasonCode.INSTRUMENT_FAILURE,),
        run.population_digest,
        run.freeze_digest,
        run.plan.plan_digest,
        run.workflow_digest,
        False,
        counts,
        gates,
        (),
        run.recorded_runtime_ms,
        "",
        "",
        None,
        "",
    )
    _persist_witness(repository, policy, request, outcome, reason)
    return AdmissionExecutionV1(reason, (), (), "", (), "", None, None, outcome)


def _persist_witness(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    outcome: BenchmarkWorkflowOutcomeV1,
    reason: AdmissionExecutionReason,
) -> None:
    witness: dict[str, JsonValue] = {
        "schema_version": ADMISSION_EXECUTION_WITNESS_SCHEMA,
        "workflow_digest": request.run_request.workflow_digest,
        "outcome_digest": outcome.outcome_digest,
        "refusal_reason": reason.value,
    }
    try:
        outcome_payload = cast("dict[str, JsonValue]", dict(json.loads(workflow_outcome_bytes(outcome))))
        provenance = canonical.content_digest({"workflow": request.run_request.workflow_digest, "stage": "admission-execution-witness"})
        for payload in (outcome_payload, witness):
            content = canonical_artifact_bytes(
                ArtifactKind.WORKFLOW, payload, access_class=ArtifactAccessClass.OPERATOR_SAFE, provenance_digest=provenance
            )
            repository.put_if_absent(content, reference=artifact_reference(content))
    except (*_FAILURES, ArtifactRepositoryError):
        raise _refused(AdmissionExecutionReason.PERSISTENCE_FAILED) from None


def execute_planned_observations(
    lifecycle: BaselineLifecycleAuthority,
    repository: S3ArtifactRepository,
    custody: PopulationCustodyPort,
    journal: S3WorkflowJournal,
    custodian_access_policy_digest: str,
    request: AdmissionExecutionRequestV1,
) -> AdmissionExecutionV1:
    """Execute and seal every planned observation before any spend authority."""
    _validated_request(request)
    run = request.run_request
    try:
        authority = resolve_current_retry_authority(journal, repository, custodian_access_policy_digest, run.workflow_digest)
        _verify_authority_binding(authority, run, request.preflight)
    except AdmissionExecutionError as error:
        return _impaired(
            repository,
            custodian_access_policy_digest,
            request,
            WorkflowPhase.ARM_EXECUTION,
            (WorkflowGate.RETRY_AUTHORITY,),
            error.reason,
            0,
        )
    bundles = _planned_bundles(repository, custodian_access_policy_digest, request, authority)
    if isinstance(bundles, AdmissionExecutionV1):
        return bundles
    results, completed = _execute_components(repository, custodian_access_policy_digest, request, bundles)
    if results is None:
        return _impaired(
            repository,
            custodian_access_policy_digest,
            request,
            WorkflowPhase.OBSERVATION_FREEZE,
            (WorkflowGate.ARM_EXECUTION,),
            AdmissionExecutionReason.EXECUTION_IMPAIRED,
            completed,
        )
    return _freeze_and_authorize(lifecycle, repository, custody, custodian_access_policy_digest, request, results)


def _planned_bundles(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    authority: AutomaticRetryAuthorityV1,
) -> tuple[LabelBlindExecutionBundleV1, ...] | AdmissionExecutionV1:
    run = request.run_request
    try:
        bundles = build_component_execution_bundles(
            run.plan,
            run.manifest,
            request.selection,
            request.public_material_manifest,
            request.cases,
            request.budgets,
            adapter_kind=ExecutionAdapterKind.LOCAL,
            output_namespace_digest=request.output_namespace_digest,
        )
    except (IsolatedExecutionError, TypeError, ValueError):
        return _impaired(
            repository,
            policy,
            request,
            WorkflowPhase.ARM_EXECUTION,
            (WorkflowGate.ARM_EXECUTION,),
            AdmissionExecutionReason.EXECUTION_IMPAIRED,
            0,
        )
    if tuple(bundle.bundle_digest for bundle in bundles) != authority.ordered_bundle_digests:
        return _impaired(
            repository,
            policy,
            request,
            WorkflowPhase.ARM_EXECUTION,
            (WorkflowGate.RETRY_AUTHORITY,),
            AdmissionExecutionReason.AUTHORITY_MISMATCHED,
            0,
        )
    return bundles


def _execute_components(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
) -> tuple[tuple[ArmCheckpointResultV1, ...] | None, int]:
    results: list[ArmCheckpointResultV1] = []
    selectors = request.checkpoint_selectors
    if len(selectors) != len(bundles):
        return None, 0
    for bundle, selector in zip(bundles, selectors, strict=True):
        result = execute_or_resume_component(
            request.run_request.plan,
            bundle,
            request.adapter,
            repository,
            _custodian_authority(policy),
            policy,
            request.run_request.manifest,
            request.public_material_manifest,
            request.selection,
            checkpoint=selector,
        )
        results.append(result)
        if result.status is not CheckpointStatus.COMPLETE:
            return None, len(results) - 1
    return tuple(results), len(results)


def _freeze_and_authorize(
    lifecycle: BaselineLifecycleAuthority,
    repository: S3ArtifactRepository,
    custody: PopulationCustodyPort,
    policy: str,
    request: AdmissionExecutionRequestV1,
    results: tuple[ArmCheckpointResultV1, ...],
) -> AdmissionExecutionV1:
    run = request.run_request
    try:
        observations = _component_observations(repository, policy, results)
        index, combined_ids, combination_digest = _observation_index(run.plan, request.combination_registrations, observations)
        sealed = _seal_observations(repository, policy, request, index)
    except AdmissionExecutionError as error:
        return _impaired(
            repository,
            policy,
            request,
            WorkflowPhase.OBSERVATION_FREEZE,
            (WorkflowGate.OBSERVATION_DURABILITY,),
            error.reason,
            len(results),
        )
    except CombinationPlannerError:
        return _impaired(
            repository,
            policy,
            request,
            WorkflowPhase.OBSERVATION_FREEZE,
            (WorkflowGate.OBSERVATION_DURABILITY,),
            AdmissionExecutionReason.COMBINATION_FAILED,
            len(results),
        )
    try:
        manifest, subject = _compose_manifest(repository, policy, request, sealed)
    except AdmissionExecutionError as error:
        return _impaired(
            repository, policy, request, WorkflowPhase.OBSERVATION_FREEZE, (WorkflowGate.ADMISSION_MANIFEST,), error.reason, len(results)
        )
    if manifest is None:
        return AdmissionExecutionV1(None, results, combined_ids, combination_digest, sealed, subject, None, None, None)
    authorization = reauthorize_before_spend(lifecycle, repository, custody, policy, run, request.preflight, sealed, manifest)
    product = AdmissionExecutionV1(None, results, combined_ids, combination_digest, sealed, subject, manifest, authorization, None)
    if not authorization.may_spend:
        return _impaired_from_authorization(repository, policy, request, authorization, len(results), product)
    return product


def _impaired_from_authorization(
    repository: S3ArtifactRepository,
    policy: str,
    request: AdmissionExecutionRequestV1,
    authorization: SpendAuthorizationV1,
    completed_arms: int,
    product: AdmissionExecutionV1,
) -> AdmissionExecutionV1:
    reason = authorization.refusal_reasons[0] if authorization.refusal_reasons else AdmissionExecutionReason.MANIFEST_INVALID
    impaired = _impaired(repository, policy, request, WorkflowPhase.CUSTODY_SPEND, (WorkflowGate.SPEND_AUTHORITY,), reason, completed_arms)
    return AdmissionExecutionV1(
        impaired.refusal_reason,
        product.component_results,
        product.combined_arm_ids,
        product.combination_plan_digest,
        product.sealed_observations,
        product.manifest_subject_digest,
        product.admission_manifest,
        authorization,
        impaired.impaired_outcome,
    )


__all__ = [
    "ADMISSION_EXECUTION_WITNESS_SCHEMA",
    "ADMISSION_MANIFEST_WITNESS_SCHEMA",
    "ATTEMPT_EVENT_DOCUMENT_SCHEMA",
    "SEALED_OBSERVATION_DOCUMENT_SCHEMA",
    "SPEND_AUTHORIZATION_SCHEMA",
    "AdmissionExecutionError",
    "AdmissionExecutionReason",
    "AdmissionExecutionRequestV1",
    "AdmissionExecutionV1",
    "SpendAuthorizationV1",
    "execute_planned_observations",
    "initial_attempt_event",
    "initial_attempt_event_payload_digest",
    "reauthorize_before_spend",
    "resolve_current_retry_authority",
]
