"""Task 8.6 exact automatic retry over sealed completed component checkpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum

from benchmarks.valid.admission_execution import (
    AdmissionExecutionError,
    AdmissionExecutionReason,
    resolve_current_retry_authority,
)
from benchmarks.valid.admission_orchestrator import AdmissionOrchestratorError, AutomaticRetryAuthorityV1
from benchmarks.valid.arm_contract import ArmRegistryError, RegisteredEvaluationPlanV1
from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore
from benchmarks.valid.isolated_execution_bundle import LabelBlindExecutionBundleV1
from benchmarks.valid.lifecycle import (
    BaselineLifecycleAuthority,
    LifecycleError,
    PopulationLifecycleKind,
    PopulationLifecycleState,
    decode_lifecycle_event,
    reviewed_retirement_event,
)
from benchmarks.valid.observation_checkpoint import (
    ArmCheckpointResultV1,
    CheckpointSelectorV1,
    CheckpointStatus,
    ObservationCheckpointAdapter,
    execute_or_resume_component,
)
from benchmarks.valid.ordinary_change_contract import OrdinarySelectionV1
from benchmarks.valid.population_label_blind_contract import LabelBlindPopulationManifestV3
from benchmarks.valid.population_material_contract import PublicPopulationMaterialManifestV1
from benchmarks.valid.replacement_artifact_contract import ArtifactAccessClass, ArtifactKind, ArtifactReference
from benchmarks.valid.sealed_diagnostics import (
    SealedDiagnosticError,
    _reference_value,
    persist_private_authority_event,
)
from benchmarks.valid.workflow_journal import S3WorkflowJournal
from openultrasast.core import canonical
from openultrasast.core.canonical import JsonValue
from openultrasast.core.custody import PopulationStatus
from openultrasast.core.evaluation_measurement import ArmKindV3

AUTOMATIC_RETRY_SCHEMA = "openultrasast.valid-detection-benchmark.automatic-retry.v1"
AUTOMATIC_RETRY_RESULT_SCHEMA = "openultrasast.valid-detection-benchmark.automatic-retry-result.v1"
RETRY_MISMATCH_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.retry-mismatch-authority.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class AutomaticRetryStatus(StrEnum):
    RESUMED = "resumed"
    IMPAIRED = "impaired"
    BLOCKED = "blocked"


class AutomaticRetryReason(StrEnum):
    NONE = "none"
    IDENTITY_CHANGED = "identity_changed"
    CHECKPOINT_IMPAIRED = "checkpoint_impaired"
    LIFECYCLE_INELIGIBLE = "lifecycle_ineligible"


class AutomaticRetryAuthorityReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    AUTHORITY_UNRESOLVED = "authority_unresolved"
    AUTHORITY_SUBSTITUTED = "authority_substituted"
    MISMATCH_AUTHORITY_REQUIRED = "mismatch_authority_required"
    AUTHORITY_PERSISTENCE_FAILED = "authority_persistence_failed"
    SPEND_ALREADY_COMMITTED = "spend_already_committed"
    CUSTODY_NOT_SPENT = "custody_not_spent"


class AutomaticRetryError(RuntimeError):
    """Closed retry refusal before detector execution."""

    def __init__(self, reason: AutomaticRetryAuthorityReason) -> None:
        self.reason = reason
        super().__init__(f"automatic_retry_{reason.value}")


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    return value


@dataclass(frozen=True)
class AutomaticRetryIdentityV1:
    population_digest: str
    freeze_digest: str
    admission_identity_digest: str
    plan_digest: str
    arm_registration_digests: tuple[str, ...]
    bundle_digests: tuple[str, ...]
    input_set_digest: str
    budget_digests: tuple[str, ...]
    environment_digests: tuple[str, ...]
    output_destination_digests: tuple[str, ...]
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...]
    retry_digest: str

    def __post_init__(self) -> None:
        if type(self) is not AutomaticRetryIdentityV1:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        for value in (
            self.population_digest,
            self.freeze_digest,
            self.admission_identity_digest,
            self.plan_digest,
            self.input_set_digest,
        ):
            _digest(value)
        _validate_retry_rows(self)
        expected = canonical.content_digest(_retry_value(self, include_digest=False))
        if not self.retry_digest:
            object.__setattr__(self, "retry_digest", expected)
        elif _digest(self.retry_digest) != expected:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _validate_retry_rows(value: AutomaticRetryIdentityV1) -> None:
    rows = (
        value.arm_registration_digests,
        value.bundle_digests,
        value.budget_digests,
        value.environment_digests,
        value.output_destination_digests,
        value.checkpoint_selectors,
    )
    size = len(value.arm_registration_digests)
    if not size or any(type(row) is not tuple or len(row) != size for row in rows):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    for row in rows[:-1]:
        for item in row:
            _digest(item)
    if len(set(value.arm_registration_digests)) != size or len(set(value.bundle_digests)) != size:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    if any(type(selector) is not CheckpointSelectorV1 for selector in value.checkpoint_selectors):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    for selector in value.checkpoint_selectors:
        selector.__post_init__()
    identities = tuple((selector.reference.content_digest, selector.checkpoint_digest) for selector in value.checkpoint_selectors)
    if len(set(identities)) != size:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _retry_value(value: AutomaticRetryIdentityV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": AUTOMATIC_RETRY_SCHEMA,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "admission_identity_digest": value.admission_identity_digest,
        "plan_digest": value.plan_digest,
        "arm_registration_digests": value.arm_registration_digests,
        "bundle_digests": value.bundle_digests,
        "input_set_digest": value.input_set_digest,
        "budget_digests": value.budget_digests,
        "environment_digests": value.environment_digests,
        "output_destination_digests": value.output_destination_digests,
        "checkpoint_selectors": tuple(
            {
                "checkpoint_digest": selector.checkpoint_digest,
                "reference": _reference_value(selector.reference),
            }
            for selector in value.checkpoint_selectors
        ),
    }
    if include_digest:
        result["retry_digest"] = value.retry_digest
    return result


def automatic_retry_identity_bytes(value: AutomaticRetryIdentityV1) -> bytes:
    value.__post_init__()
    return canonical.canonical_bytes(_retry_value(value, include_digest=True))


def build_automatic_retry_identity(
    population_digest: str,
    freeze_digest: str,
    admission_identity_digest: str,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...],
) -> AutomaticRetryIdentityV1:
    if type(bundles) is not tuple or not bundles or any(type(bundle) is not LabelBlindExecutionBundleV1 for bundle in bundles):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    if type(checkpoint_selectors) is not tuple or len(checkpoint_selectors) != len(bundles):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    for bundle in bundles:
        bundle.__post_init__()
    if tuple(bundle.arm.arm_id for bundle in bundles) != tuple(sorted(bundle.arm.arm_id for bundle in bundles)):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    shared = {(bundle.population_digest, bundle.freeze_digest, bundle.plan_digest, bundle.input_set_digest) for bundle in bundles}
    if len(shared) != 1 or shared.pop() != (
        population_digest,
        freeze_digest,
        bundles[0].plan_digest,
        bundles[0].input_set_digest,
    ):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    return AutomaticRetryIdentityV1(
        population_digest,
        freeze_digest,
        admission_identity_digest,
        bundles[0].plan_digest,
        tuple(bundle.arm.registration_digest for bundle in bundles),
        tuple(bundle.bundle_digest for bundle in bundles),
        bundles[0].input_set_digest,
        tuple(bundle.budget.budget_digest for bundle in bundles),
        tuple(bundle.environment.environment_digest for bundle in bundles),
        tuple(bundle.output_destination.destination_digest for bundle in bundles),
        checkpoint_selectors,
        "",
    )


def _actual_retry_identity(
    candidate: AutomaticRetryIdentityV1,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...],
    plan: RegisteredEvaluationPlanV1,
) -> AutomaticRetryIdentityV1:
    try:
        if type(plan) is not RegisteredEvaluationPlanV1:
            raise ArmRegistryError("retry plan must use exact RegisteredEvaluationPlanV1")
        plan.__post_init__()
    except (ArmRegistryError, TypeError, ValueError):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST) from None
    actual = build_automatic_retry_identity(
        bundles[0].population_digest,
        bundles[0].freeze_digest,
        candidate.admission_identity_digest,
        bundles,
        checkpoint_selectors,
    )
    if actual.plan_digest == plan.plan_digest:
        return actual
    return replace(actual, plan_digest=plan.plan_digest, retry_digest="")


def resolve_head_selected_retry_authority(
    journal: S3WorkflowJournal,
    repository: S3ArtifactRepository,
    access_policy_digest: str,
    workflow_digest: str,
) -> AutomaticRetryAuthorityV1:
    """Resolve the original retry authority only through the current CAS head."""
    try:
        return resolve_current_retry_authority(journal, repository, access_policy_digest, workflow_digest)
    except AdmissionExecutionError as error:
        if error.reason is AdmissionExecutionReason.AUTHORITY_UNRESOLVED:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.AUTHORITY_UNRESOLVED) from None
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.AUTHORITY_SUBSTITUTED) from None


def retry_identity_matches_authority(
    candidate: AutomaticRetryIdentityV1,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    plan: RegisteredEvaluationPlanV1,
    authority: AutomaticRetryAuthorityV1,
) -> bool:
    """Compare the candidate identity against every head-selected dimension."""
    if (
        type(candidate) is not AutomaticRetryIdentityV1
        or type(bundles) is not tuple
        or not bundles
        or type(plan) is not RegisteredEvaluationPlanV1
        or type(authority) is not AutomaticRetryAuthorityV1
    ):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    try:
        plan.__post_init__()
        authority.__post_init__()
    except (ArmRegistryError, AdmissionOrchestratorError, TypeError, ValueError):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST) from None
    return all(left == right for left, right in _identity_rows(candidate, bundles, plan, authority))


def _identity_rows(
    candidate: AutomaticRetryIdentityV1,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    plan: RegisteredEvaluationPlanV1,
    authority: AutomaticRetryAuthorityV1,
) -> tuple[tuple[object, object], ...]:
    components = tuple(sorted(row.arm_id for row in plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT))
    registered = {row.arm_id: row.registration_digest for row in plan.registrations}
    return (
        (
            (
                candidate.population_digest,
                candidate.freeze_digest,
                candidate.admission_identity_digest,
                candidate.plan_digest,
                plan.plan_digest,
            ),
            (
                authority.population_digest,
                authority.freeze_digest,
                authority.admission_identity_digest,
                authority.plan_digest,
                authority.plan_digest,
            ),
        ),
        (tuple(row.arm_id for row in plan.registrations), authority.ordered_arm_ids),
        (tuple(bundle.arm.arm_id for bundle in bundles), components),
        (tuple(registered.get(bundle.arm.arm_id, "") for bundle in bundles), candidate.arm_registration_digests),
        (candidate.bundle_digests, authority.ordered_bundle_digests),
        (candidate.budget_digests, authority.ordered_budget_digests),
        (candidate.environment_digests, authority.ordered_environment_digests),
        (candidate.output_destination_digests, authority.ordered_destination_digests),
        (len(authority.ordered_input_set_digests), len(bundles)),
        (tuple(digest for digest in authority.ordered_input_set_digests if digest != candidate.input_set_digest), ()),
        (
            tuple(slot.slot_digest for slot in plan.declaration.expected_observation_slots),
            authority.ordered_checkpoint_slot_digests,
        ),
    )


def _mismatch_evidence(registered: str, candidate: str, actual: str, supplied_plan: str) -> str:
    return canonical.content_digest(
        {
            "registered_retry_digest": registered,
            "candidate_retry_digest": candidate,
            "actual_retry_digest": actual,
            "supplied_plan_digest": supplied_plan,
        }
    )


@dataclass(frozen=True)
class RetryMismatchAuthorityV1:
    population_digest: str
    freeze_digest: str
    predecessor_digest: str
    component_index: int
    registered_retry_digest: str
    candidate_retry_digest: str
    actual_retry_digest: str
    supplied_plan_digest: str
    evidence_digest: str
    retirement_event_content: bytes
    retirement_event_digest: str
    authority_digest: str

    def __post_init__(self) -> None:
        if type(self) is not RetryMismatchAuthorityV1 or type(self.component_index) is not int:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        if self.component_index < 0 or type(self.retirement_event_content) is not bytes:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        for value in (
            self.population_digest,
            self.freeze_digest,
            self.predecessor_digest,
            self.registered_retry_digest,
            self.candidate_retry_digest,
            self.actual_retry_digest,
            self.supplied_plan_digest,
            self.evidence_digest,
            self.retirement_event_digest,
        ):
            _digest(value)
        expected_evidence = _mismatch_evidence(
            self.registered_retry_digest,
            self.candidate_retry_digest,
            self.actual_retry_digest,
            self.supplied_plan_digest,
        )
        if self.evidence_digest != expected_evidence:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        self._validate_event()
        expected = canonical.content_digest(_mismatch_authority_value(self, include_digest=False))
        if not self.authority_digest:
            object.__setattr__(self, "authority_digest", expected)
        elif _digest(self.authority_digest) != expected:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)

    def _validate_event(self) -> None:
        try:
            event = decode_lifecycle_event(self.retirement_event_content)
            valid = (
                event.kind is PopulationLifecycleKind.RETIRED
                and event.predecessor_digest == self.predecessor_digest
                and event.population_digest == self.population_digest
                and event.freeze_digest == self.freeze_digest
                and event.evidence_digest == self.evidence_digest
                and event.reason_code == "policy_invalidated"
                and event.event_digest == self.retirement_event_digest
            )
        except (LifecycleError, TypeError, ValueError, RecursionError):
            valid = False
        if not valid:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _mismatch_authority_value(value: RetryMismatchAuthorityV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": RETRY_MISMATCH_AUTHORITY_SCHEMA,
        "population_digest": value.population_digest,
        "freeze_digest": value.freeze_digest,
        "predecessor_digest": value.predecessor_digest,
        "component_index": value.component_index,
        "registered_retry_digest": value.registered_retry_digest,
        "candidate_retry_digest": value.candidate_retry_digest,
        "actual_retry_digest": value.actual_retry_digest,
        "supplied_plan_digest": value.supplied_plan_digest,
        "evidence_digest": value.evidence_digest,
        "retirement_event_digest": value.retirement_event_digest,
    }
    if include_digest:
        result["authority_digest"] = value.authority_digest
    return result


def review_retry_mismatch_authority(
    authority: AutomaticRetryAuthorityV1,
    candidate: AutomaticRetryIdentityV1,
    *,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...],
    plan: RegisteredEvaluationPlanV1,
    lifecycle_authority: BaselineLifecycleAuthority,
    producer_identity: str,
    reviewer_identity: str,
    conflict_disclosed: bool,
    policy_digest: str,
    component_index: int = 0,
) -> RetryMismatchAuthorityV1:
    """Independently review one identity-bound mismatch disposition."""
    if type(candidate) is not AutomaticRetryIdentityV1:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    candidate.__post_init__()
    actual = _actual_retry_identity(candidate, bundles, checkpoint_selectors, plan)
    if actual.retry_digest == candidate.retry_digest and retry_identity_matches_authority(candidate, bundles, plan, authority):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    try:
        active = lifecycle_authority.require_admission_eligible(authority.population_digest, authority.freeze_digest)
        evidence = _mismatch_evidence(
            authority.authority_digest,
            candidate.retry_digest,
            actual.retry_digest,
            plan.plan_digest,
        )
        content = reviewed_retirement_event(
            predecessor_digest=active.head_event_digest,
            population_digest=authority.population_digest,
            freeze_digest=authority.freeze_digest,
            evidence_digest=evidence,
            reason_code="policy_invalidated",
            producer_identity=producer_identity,
            reviewer_identity=reviewer_identity,
            conflict_disclosed=conflict_disclosed,
            policy_digest=policy_digest,
        )
        event = decode_lifecycle_event(content)
    except (LifecycleError, TypeError, ValueError, RecursionError):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST) from None
    return RetryMismatchAuthorityV1(
        authority.population_digest,
        authority.freeze_digest,
        active.head_event_digest,
        component_index,
        authority.authority_digest,
        candidate.retry_digest,
        actual.retry_digest,
        plan.plan_digest,
        evidence,
        content,
        event.event_digest,
        "",
    )


@dataclass(frozen=True)
class AutomaticRetryResultV1:
    status: AutomaticRetryStatus
    reason: AutomaticRetryReason
    retry_digest: str
    component_index: int
    checkpoint: ArmCheckpointResultV1 | None
    lifecycle_reference: ArtifactReference | None
    lifecycle_projection_digest: str
    result_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not AutomaticRetryResultV1
            or type(self.status) is not AutomaticRetryStatus
            or type(self.reason) is not AutomaticRetryReason
        ):
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        _digest(self.retry_digest)
        if type(self.component_index) is not int or self.component_index < 0:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
        if self.checkpoint is not None:
            self.checkpoint.__post_init__()
        if self.lifecycle_reference is not None:
            self.lifecycle_reference.__post_init__()
        if self.lifecycle_projection_digest:
            _digest(self.lifecycle_projection_digest)
        _validate_result_state(self)
        expected = canonical.content_digest(_result_value(self, include_digest=False))
        if not self.result_digest:
            object.__setattr__(self, "result_digest", expected)
        elif _digest(self.result_digest) != expected:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _validate_result_state(value: AutomaticRetryResultV1) -> None:
    checkpoint = value.checkpoint
    lifecycle_reference = value.lifecycle_reference
    if value.status is AutomaticRetryStatus.RESUMED:
        valid = value.reason is AutomaticRetryReason.NONE and checkpoint is not None
        valid = valid and checkpoint is not None and checkpoint.status is CheckpointStatus.COMPLETE
        valid = valid and value.lifecycle_reference is None and not value.lifecycle_projection_digest
    elif value.status is AutomaticRetryStatus.IMPAIRED:
        valid = value.reason is AutomaticRetryReason.CHECKPOINT_IMPAIRED and checkpoint is not None
        valid = valid and checkpoint is not None and checkpoint.status is CheckpointStatus.IMPAIRED
        valid = valid and value.lifecycle_reference is None and not value.lifecycle_projection_digest
    else:
        valid = value.reason in {AutomaticRetryReason.IDENTITY_CHANGED, AutomaticRetryReason.LIFECYCLE_INELIGIBLE}
        valid = valid and value.checkpoint is None
        if value.reason is AutomaticRetryReason.IDENTITY_CHANGED:
            valid = valid and lifecycle_reference is not None and bool(value.lifecycle_projection_digest)
            if lifecycle_reference is not None:
                valid = valid and lifecycle_reference.artifact_kind is ArtifactKind.LIFECYCLE
                valid = valid and lifecycle_reference.access_class is ArtifactAccessClass.PRIVATE
        else:
            valid = valid and lifecycle_reference is None and not value.lifecycle_projection_digest
    if not valid:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)


def _result_value(value: AutomaticRetryResultV1, *, include_digest: bool) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "schema_version": AUTOMATIC_RETRY_RESULT_SCHEMA,
        "status": value.status.value,
        "reason": value.reason.value,
        "retry_digest": value.retry_digest,
        "component_index": value.component_index,
        "checkpoint_result_digest": None if value.checkpoint is None else value.checkpoint.result_digest,
        "lifecycle_reference": (None if value.lifecycle_reference is None else _reference_value(value.lifecycle_reference)),
        "lifecycle_projection_digest": value.lifecycle_projection_digest or None,
    }
    if include_digest:
        result["result_digest"] = value.result_digest
    return result


def automatic_retry_result_bytes(value: AutomaticRetryResultV1) -> bytes:
    value.__post_init__()
    return canonical.canonical_bytes(_result_value(value, include_digest=True))


def _result(
    status: AutomaticRetryStatus,
    reason: AutomaticRetryReason,
    retry_digest: str,
    component_index: int,
    checkpoint: ArmCheckpointResultV1 | None = None,
    lifecycle_reference: ArtifactReference | None = None,
    lifecycle_projection_digest: str = "",
) -> AutomaticRetryResultV1:
    return AutomaticRetryResultV1(
        status,
        reason,
        retry_digest,
        component_index,
        checkpoint,
        lifecycle_reference,
        lifecycle_projection_digest,
        "",
    )


def _block_changed_retry(
    authority: AutomaticRetryAuthorityV1,
    candidate: AutomaticRetryIdentityV1,
    actual: AutomaticRetryIdentityV1,
    supplied_plan_digest: str,
    component_index: int,
    repository: S3ArtifactRepository,
    artifact_authority: ArtifactReadAuthority,
    access_policy_digest: str,
    lifecycle_authority: BaselineLifecycleAuthority,
    mismatch_authority: RetryMismatchAuthorityV1 | None,
) -> AutomaticRetryResultV1:
    try:
        active = lifecycle_authority.require_admission_eligible(authority.population_digest, authority.freeze_digest)
    except LifecycleError:
        return _result(
            AutomaticRetryStatus.BLOCKED,
            AutomaticRetryReason.LIFECYCLE_INELIGIBLE,
            candidate.retry_digest,
            component_index,
        )
    expected = (
        authority.population_digest,
        authority.freeze_digest,
        active.head_event_digest,
        component_index,
        authority.authority_digest,
        candidate.retry_digest,
        actual.retry_digest,
        supplied_plan_digest,
    )
    try:
        if mismatch_authority is None:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED)
        mismatch_authority.__post_init__()
        binding = (
            mismatch_authority.population_digest,
            mismatch_authority.freeze_digest,
            mismatch_authority.predecessor_digest,
            mismatch_authority.component_index,
            mismatch_authority.registered_retry_digest,
            mismatch_authority.candidate_retry_digest,
            mismatch_authority.actual_retry_digest,
            mismatch_authority.supplied_plan_digest,
        )
        if binding != expected:
            raise AutomaticRetryError(AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED)
        reference = persist_private_authority_event(
            ArtifactKind.LIFECYCLE,
            mismatch_authority.retirement_event_content,
            mismatch_authority.retirement_event_digest,
            repository,
            artifact_authority,
            access_policy_digest,
        )
        projection = lifecycle_authority.append(mismatch_authority.retirement_event_content)
        if projection.state is not PopulationLifecycleState.RETIRED or projection.admission_eligible:
            raise LifecycleError("changed retry did not terminally retire baseline")
    except AutomaticRetryError:
        raise
    except SealedDiagnosticError:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.AUTHORITY_PERSISTENCE_FAILED) from None
    except (LifecycleError, TypeError, ValueError):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.MISMATCH_AUTHORITY_REQUIRED) from None
    return _result(
        AutomaticRetryStatus.BLOCKED,
        AutomaticRetryReason.IDENTITY_CHANGED,
        candidate.retry_digest,
        component_index,
        lifecycle_reference=reference,
        lifecycle_projection_digest=projection.projection_digest,
    )


def resume_pre_spend_sealed_retry(
    *,
    component_index: int,
    admission_identity_digest: str,
    bundles: tuple[LabelBlindExecutionBundleV1, ...],
    checkpoint_selectors: tuple[CheckpointSelectorV1, ...],
    plan: RegisteredEvaluationPlanV1,
    adapter: ObservationCheckpointAdapter,
    journal: S3WorkflowJournal,
    workflow_digest: str,
    repository: S3ArtifactRepository,
    artifact_authority: ArtifactReadAuthority,
    access_policy_digest: str,
    manifest: LabelBlindPopulationManifestV3,
    public_material_manifest: PublicPopulationMaterialManifestV1,
    selection: OrdinarySelectionV1,
    lifecycle_authority: BaselineLifecycleAuthority,
    custody: S3DurableCustodyStore,
    mismatch_authority: RetryMismatchAuthorityV1 | None = None,
) -> AutomaticRetryResultV1:
    """Resume pre-spend only from the head-selected authority over unchanged identity."""
    _digest(admission_identity_digest)
    if type(bundles) is not tuple or not bundles or type(component_index) is not int or not 0 <= component_index < len(bundles):
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.INVALID_REQUEST)
    authority = resolve_head_selected_retry_authority(journal, repository, access_policy_digest, workflow_digest)
    if custody.current_log(authority.population_digest).status is not PopulationStatus.AVAILABLE:
        raise AutomaticRetryError(AutomaticRetryAuthorityReason.SPEND_ALREADY_COMMITTED)
    candidate = build_automatic_retry_identity(
        bundles[0].population_digest,
        bundles[0].freeze_digest,
        admission_identity_digest,
        bundles,
        checkpoint_selectors,
    )
    actual = _actual_retry_identity(candidate, bundles, checkpoint_selectors, plan)
    if actual.retry_digest != candidate.retry_digest or not retry_identity_matches_authority(candidate, bundles, plan, authority):
        return _block_changed_retry(
            authority,
            candidate,
            actual,
            plan.plan_digest,
            component_index,
            repository,
            artifact_authority,
            access_policy_digest,
            lifecycle_authority,
            mismatch_authority,
        )
    try:
        lifecycle_authority.require_admission_eligible(authority.population_digest, authority.freeze_digest)
    except LifecycleError:
        return _result(
            AutomaticRetryStatus.BLOCKED,
            AutomaticRetryReason.LIFECYCLE_INELIGIBLE,
            candidate.retry_digest,
            component_index,
        )
    checkpoint = execute_or_resume_component(
        plan,
        bundles[component_index],
        adapter,
        repository,
        artifact_authority,
        access_policy_digest,
        manifest,
        public_material_manifest,
        selection,
        checkpoint=checkpoint_selectors[component_index],
    )
    if checkpoint.status is CheckpointStatus.COMPLETE:
        return _result(
            AutomaticRetryStatus.RESUMED,
            AutomaticRetryReason.NONE,
            candidate.retry_digest,
            component_index,
            checkpoint,
        )
    return _result(
        AutomaticRetryStatus.IMPAIRED,
        AutomaticRetryReason.CHECKPOINT_IMPAIRED,
        candidate.retry_digest,
        component_index,
        checkpoint,
    )


__all__ = [
    "AUTOMATIC_RETRY_RESULT_SCHEMA",
    "AUTOMATIC_RETRY_SCHEMA",
    "RETRY_MISMATCH_AUTHORITY_SCHEMA",
    "AutomaticRetryAuthorityReason",
    "AutomaticRetryError",
    "AutomaticRetryIdentityV1",
    "AutomaticRetryReason",
    "AutomaticRetryResultV1",
    "AutomaticRetryStatus",
    "RetryMismatchAuthorityV1",
    "automatic_retry_identity_bytes",
    "automatic_retry_result_bytes",
    "build_automatic_retry_identity",
    "resolve_head_selected_retry_authority",
    "resume_pre_spend_sealed_retry",
    "retry_identity_matches_authority",
    "review_retry_mismatch_authority",
]
