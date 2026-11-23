"""Task 11.3 conversion adapter: benchmark spend products to the core V3 replay.

Closes the R1 final-validation gap by converting the benchmark-owned 8.3 spend
release plus the custodian-sealed 8.2 observations into the exact core V3 case
graph that ``derive_scoped_replay`` scores. Every field either derives from
real sealed observation content decoded inside the custodian boundary, the
released label join, or the custodian-owned case-content port -- or the
conversion refuses closed.

Documented derivation decisions:

1. Case identity convention (proven end to end by task 11.3). The committed
   8.3 label join keys ground truth by the raw population change digests and
   the core observation contract pins each ref's outcome projection to its
   case input digest, so sealed refs carry the raw identity the projection
   was sealed under while ``underlying_push_digest`` carries the same raw
   population identity. The core V3 case graph instead requires the
   ``derive_case_input_digest`` wrapper over the validated evidence records,
   so the bridge rebuilds every observation ref -- component and combined --
   re-keying to that wrapper after pinning the sealed case identity, result
   digest, projection, and proof candidate.
2. Label-blind scope resolution plus post-spend label cross-check. Scopes
   resolve through the custodian case-content port, which binds each identity
   to exactly one planned scope per arm, so the derivation never opens
   ground truth; ``derive_case_adapter_replay`` then cross-checks every
   released positive label against the port-bound scope.
3. Corrected reviewable census. The orchestrator preflight census sets every
   scope capacity to the positive count, while core reconciliation requires
   pair/vulnerable/fixed capacities equal to the released pair structure and
   nonzero site and model capacities. The adapter recomposes the census from
   the case contents and the ordinary selection, and reviews it through the
   committed ``compose_plan_manifest`` seam.
4. Pre-spend authority over a reconstructed head. ``authorize_evaluation``
   requires the population to be currently available, so the production
   spend stage commits the custody compare-and-swap from
   ``derive_case_adapter_preparation`` while the population is available,
   and the post-spend conversion re-derives that exact preparation over the
   committed chain's prior head before binding the receipt through
   ``validate_shared_spend`` against the real store.
5. Combined arms. 8.2 derives combined observations through
   ``arm_combination``. The adapter rebuilds each combined observation in
   core form from the same sealed component bytes plus the registered rule
   after proving projection policy, sources, and outcome equivalence with
   the sealed combined observation, and refuses on divergence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from benchmarks.valid.admission_case_graph import (  # noqa: E402
    AdmissionAdapterReason,
    AdmissionCaseAdapterRequestV1,
    _pinned_candidate,
    assert_labeled_scopes,
    case_release_graph,
    combined_arm_ids,
    combined_projection,
    combined_rule,
    component_projections,
    corrected_census,
    labeled_facts,
    planned_arm_scopes,
    refused,
    scope_resolver,
    validate_adapter_request,
)
from benchmarks.valid.admission_execution import AdmissionExecutionV1
from benchmarks.valid.admission_orchestrator import compose_plan_manifest
from benchmarks.valid.admission_replay import (
    BridgedContentResolver,
    ScopedReplayRequestV1,
    derive_scoped_replay,
)
from benchmarks.valid.admission_spend import (
    AdmissionSpendReleaseV1,
    AdmissionSpendRequestV1,
    CustodyCompareAndSwap,
    commit_preparation_spend_and_release,
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
)
from openultrasast.core import canonical
from openultrasast.core.canonical import ContentRef, ContentResolver, ResolvedContent, StorageReceipt
from openultrasast.core.custody import PopulationUseReceipt
from openultrasast.core.evaluation_admission import (
    EvaluationAdmissionV3Error,
    authorize_evaluation,
    preflight_evaluation,
    validate_shared_spend,
)
from openultrasast.core.evaluation_attempt import AttemptHistoryV3
from openultrasast.core.evaluation_authority import (
    EvaluationAdmissionManifestV3,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_measurement import ScopeKey
from openultrasast.core.evaluation_observation import (
    ArmObservationSetV3,
    ObservationCaseRefV3,
    SealedObservationRefV3,
    decode_arm_observation_set,
    encode_arm_observation_set,
)
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3, PopulationCensusV3
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_spend import EvaluationPreparationV3
from openultrasast.core.factpack import IndependenceAttestation, ReviewIndependencePolicy

_ZERO = "0" * 64
_DECODE_FAILURES = (AttributeError, KeyError, RecursionError, TypeError, UnicodeDecodeError, ValueError)
_CORE_REFUSALS = (
    EvaluationAdmissionV3Error,
    canonical.ArtifactResolutionError,
    canonical.ArtifactValidationError,
    ValueError,
)


@dataclass(frozen=True)
class BridgedCaseGraphV1:
    """Bridged custodian-decoded observations and raw core-form documents."""

    decoded: dict[tuple[str, str], ArmObservationSetV3]
    documents: dict[str, ResolvedContent]
    sealed: tuple[SealedObservationRefV3, ...]


def _sealed_raw(
    repository: S3ArtifactRepository,
    policy: str,
    content: ContentRef,
    expected_digest: str,
    kind: ArtifactKind,
    field: str,
) -> bytes:
    reference = ArtifactReference(kind, content.content_digest, content.byte_length, expected_digest, ArtifactAccessClass.CUSTODIAN_SEALED)
    authority = artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.CUSTODIAN_SEALED,),
        policy,
        expected_access_policy_digest=policy,
    )
    try:
        accepted = repository.get(reference, expected_kind=kind, authority=authority, expected_access_policy_digest=policy)
    except ArtifactRepositoryError:
        raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE) from None
    payload = accepted.artifact.payload
    if type(payload) is not dict or payload.get("observation_digest") != expected_digest and payload.get("event_digest") != expected_digest:
        raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE)
    document = payload.get(field)
    if type(document) is not str or not document:
        raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE)
    return document.encode("utf-8")


def _decode_observation(raw: bytes) -> ArmObservationSetV3:
    try:
        return decode_arm_observation_set(raw)
    except _DECODE_FAILURES:
        raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE) from None


def _bridged_reference(document: bytes, prefix: str, request: AdmissionCaseAdapterRequestV1) -> tuple[ContentRef, ResolvedContent]:
    digest = canonical.bytes_digest(document)
    receipt_digest = canonical.derive_storage_receipt_digest(
        store_identity=request.bridged_store_identity,
        content_digest=digest,
        byte_length=len(document),
        retention_policy_digest=request.bridged_retention_policy_digest,
    )
    reference = ContentRef(
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


def _core_form_combined(
    request: AdmissionCaseAdapterRequestV1,
    sealed: SealedObservationRefV3,
    observation: ArmObservationSetV3,
    decoded: dict[tuple[str, str], ArmObservationSetV3],
    resolve: Callable[[str, str, str], ScopeKey],
) -> ArmObservationSetV3:
    """Rebuild one combined observation over full contents, equivalence-checked."""
    rule = combined_rule(request.plan, sealed.arm_id)
    cases = []
    for reference in observation.cases:
        scope = resolve(sealed.arm_id, reference.case_input_digest, reference.underlying_push_digest)
        projections = component_projections(
            decoded, rule, sealed.input_identity_digest, reference.case_input_digest, reference.underlying_push_digest
        )
        projection = combined_projection(rule, projections)
        sealed_projection = reference.outcome_projection
        if (
            projection.policy is not sealed_projection.policy
            or projection.source_outcome_digests != sealed_projection.source_outcome_digests
            or projection.normalized_outcome != sealed_projection.normalized_outcome
        ):
            raise refused(AdmissionAdapterReason.COMBINATION_DIVERGED)
        content = request.case_content(sealed.arm_id, reference.case_input_digest, scope)
        cases.append(
            ObservationCaseRefV3(
                content.case_id_digest,
                projection.case_input_digest,
                reference.underlying_push_digest,
                content.result_digest,
                projection,
                reference.proof_candidate_digest,
            )
        )
    return ArmObservationSetV3(
        observation.slot_digest,
        observation.arm_id,
        observation.input_identity_digest,
        observation.execution_identity,
        observation.registered_budget_digest,
        observation.configuration_digest,
        observation.input_read_evidence_digest,
        observation.stage_execution_evidence_digest,
        tuple(sorted(cases, key=_case_order)),
        "",
    )


def _core_form_component(
    request: AdmissionCaseAdapterRequestV1,
    sealed: SealedObservationRefV3,
    observation: ArmObservationSetV3,
    resolve: Callable[[str, str, str], ScopeKey],
) -> ArmObservationSetV3:
    """Rebuild one component observation, re-keying cases to core wrapper digests.

    The committed 8.3 label join keys ground truth by the raw population
    identity, so sealed component case refs carry that identity as their case
    input digest; the core V3 graph instead requires the wrapper digest
    derived from the validated evidence records. Each rebuilt ref is pinned to
    the sealed case identity and projection before the re-keying.
    """
    from openultrasast.core.evaluation_case_outcome import derive_component_case_outcome_projection

    cases = []
    for reference in observation.cases:
        scope = resolve(sealed.arm_id, reference.case_input_digest, reference.underlying_push_digest)
        content = request.case_content(sealed.arm_id, reference.case_input_digest, scope)
        _pinned_candidate(request, sealed.arm_id, reference.case_input_digest, scope, reference.proof_candidate_digest)
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
        cases.append(
            ObservationCaseRefV3(
                content.case_id_digest,
                projection.case_input_digest,
                reference.underlying_push_digest,
                content.result_digest,
                projection,
                reference.proof_candidate_digest,
            )
        )
    return ArmObservationSetV3(
        observation.slot_digest,
        observation.arm_id,
        observation.input_identity_digest,
        observation.execution_identity,
        observation.registered_budget_digest,
        observation.configuration_digest,
        observation.input_read_evidence_digest,
        observation.stage_execution_evidence_digest,
        tuple(sorted(cases, key=_case_order)),
        "",
    )


def _case_order(case: ObservationCaseRefV3) -> tuple[str, ...]:
    return (
        case.case_id_digest,
        case.case_input_digest,
        case.underlying_push_digest,
        case.result_digest,
        case.outcome_projection.projection_digest,
        case.proof_candidate_digest or "",
    )


def _bridge(request: AdmissionCaseAdapterRequestV1, resolve: Callable[[str, str, str], ScopeKey]) -> BridgedCaseGraphV1:
    manifest = request.execution.admission_manifest
    assert manifest is not None
    combined = combined_arm_ids(request.plan)
    raw = {
        (sealed.arm_id, sealed.input_identity_digest): _decode_observation(
            _sealed_raw(
                request.repository,
                request.custodian_access_policy_digest,
                sealed.observation,
                sealed.observation_digest,
                ArtifactKind.OBSERVATION,
                "observation",
            )
        )
        for sealed in manifest.observations
    }
    decoded = dict(raw)
    documents: dict[str, ResolvedContent] = {}
    sealed_refs = []
    for sealed in manifest.observations:
        observation = raw[(sealed.arm_id, sealed.input_identity_digest)]
        if sealed.arm_id in combined:
            core_form = _core_form_combined(request, sealed, observation, raw, resolve)
        else:
            core_form = _core_form_component(request, sealed, observation, resolve)
        document = encode_arm_observation_set(core_form)
        reference, resolved = _bridged_reference(document, "observations/raw", request)
        documents[reference.artifact_id] = resolved
        decoded[(sealed.arm_id, sealed.input_identity_digest)] = core_form
        sealed_refs.append(replace(sealed, observation=reference, observation_digest=core_form.observation_digest, ref_digest=""))
    return BridgedCaseGraphV1(decoded, documents, tuple(sealed_refs))


def _bridged_history(request: AdmissionCaseAdapterRequestV1, documents: dict[str, ResolvedContent]) -> AttemptHistoryV3:
    from openultrasast.core.evaluation_attempt import AttemptEventRefV3, decode_attempt_event

    manifest = request.execution.admission_manifest
    assert manifest is not None
    history = manifest.attempt_history
    events = []
    for event in history.events:
        raw = _sealed_raw(
            request.repository,
            request.custodian_access_policy_digest,
            event.event,
            event.event_digest,
            ArtifactKind.WORKFLOW,
            "event",
        )
        try:
            decoded = decode_attempt_event(raw)
        except _DECODE_FAILURES:
            raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE) from None
        if decoded.event_digest != event.event_digest:
            raise refused(AdmissionAdapterReason.OBSERVATIONS_UNREADABLE)
        reference, resolved = _bridged_reference(raw, "workflows/raw", request)
        documents[reference.artifact_id] = resolved
        events.append(AttemptEventRefV3(reference, event.event_digest, ""))
    return type(history)(history.population_digest, tuple(events), history.head_event_digest, "")


def _committed_receipt(request: AdmissionCaseAdapterRequestV1, release: AdmissionSpendReleaseV1) -> PopulationUseReceipt:
    log = request.custody.current_log(request.population_digest)
    receipts = log.receipts
    if not receipts or receipts[-1].receipt_digest != release.custody_receipt_digest:
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    return receipts[-1]


class _PreSpendCustodyView:
    """Custody port restricted to the exact pre-spend head the receipt chained from.

    ``authorize_evaluation`` derives pre-spend authority and therefore requires
    the population to be currently available; the conversion runs after the
    shared custody spend has already committed the exact available-to-spent
    successor. The view reconstructs the committed chain's prior head and the
    real port still binds the receipt through ``validate_shared_spend``.
    """

    def __init__(self, prior) -> None:
        self._prior = prior

    def current_log(self, population_digest: str):
        if self._prior.population_digest != population_digest:
            raise ValueError("pre-spend custody population differs from the reviewed plan")
        return self._prior


def _pre_spend_view(request: AdmissionCaseAdapterRequestV1, release: AdmissionSpendReleaseV1) -> _PreSpendCustodyView:
    from openultrasast.core.custody import append_population_use, empty_population_custody_log

    current = request.custody.current_log(request.population_digest)
    receipts = current.receipts
    if not receipts or receipts[-1].receipt_digest != release.custody_receipt_digest:
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    policy = request.context.evidence.custody_policy
    prior = empty_population_custody_log(current.population_digest, current.custodian_identity)
    for receipt in receipts[:-1]:
        try:
            prior = append_population_use(prior, receipt, policy)
        except (TypeError, ValueError):
            raise refused(AdmissionAdapterReason.AUTHORIZATION_REFUSED) from None
    return _PreSpendCustodyView(prior)


def derive_case_adapter_preparation(request: AdmissionCaseAdapterRequestV1) -> EvaluationPreparationV3:
    """Derive the exact pre-spend core preparation the shared custody spend commits against.

    The custody compare-and-swap that opens the labels must chain from the
    preparation's own label-release request, so the production spend stage
    calls this seam while the population is still available. The derivation is
    label-blind: scope resolution runs through the custodian case-content port.
    """

    (
        validated,
        _resolve,
        _bridge,
        plan_manifest,
        resolver,
        feasibility,
        admission_manifest,
    ) = _bridged_preparation_graph(request)
    try:
        return authorize_evaluation(admission_manifest, feasibility, validated.readiness, validated.context, validated.custody, resolver)
    except _CORE_REFUSALS:
        raise refused(AdmissionAdapterReason.AUTHORIZATION_REFUSED) from None


def _bridged_preparation_graph(request: AdmissionCaseAdapterRequestV1):
    """Derive every deterministic pre-spend root without any opened label."""

    validated = validate_adapter_request(request)
    manifest = validated.execution.admission_manifest
    assert manifest is not None
    planned = planned_arm_scopes(validated.plan)
    resolve = scope_resolver(validated, planned)
    bridge = _bridge(validated, resolve)
    history = _bridged_history(validated, bridge.documents)
    census = corrected_census(validated, planned, bridge.decoded, resolve)
    readiness_digests = tuple(sorted(item.result_digest for item in validated.readiness))
    plan_manifest = _composed_plan_manifest(validated, manifest, census, readiness_digests)
    resolver = BridgedContentResolver(bridge.documents, validated.resolver)
    try:
        feasibility = preflight_evaluation(plan_manifest, validated.context, resolver)
    except _CORE_REFUSALS:
        raise refused(AdmissionAdapterReason.CENSUS_MISMATCH) from None
    draft = EvaluationAdmissionManifestV3(
        plan_manifest,
        feasibility.feasibility_digest,
        bridge.sealed,
        readiness_digests,
        manifest.custody_log_digest,
        history,
        _ZERO,
        validated.plan_review,
        _ZERO,
    )
    payload = derive_evaluation_admission_manifest_payload_digest(draft)
    admission_manifest = replace(draft, payload_digest=payload, review=validated.admission_review(payload))
    admission_manifest = replace(admission_manifest, manifest_digest=derive_evaluation_admission_manifest_digest(admission_manifest))
    return validated, resolve, bridge, plan_manifest, resolver, feasibility, admission_manifest


def derive_case_adapter_replay(request: AdmissionCaseAdapterRequestV1, release: AdmissionSpendReleaseV1) -> EvaluationReplayV3:
    """Convert one reviewed spend release into the scored core V3 replay."""

    if type(release) is not AdmissionSpendReleaseV1 or release.refusal_reason is not None or not release.released_cases:
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED)
    validated, resolve, bridge, plan_manifest, resolver, feasibility, admission_manifest = _bridged_preparation_graph(request)
    assert_labeled_scopes(validated, planned_arm_scopes(validated.plan), labeled_facts(release))
    view = _pre_spend_view(validated, release)
    try:
        preparation = authorize_evaluation(admission_manifest, feasibility, validated.readiness, validated.context, view, resolver)
        receipt = _committed_receipt(validated, release)
        spend = validate_shared_spend(admission_manifest, preparation, receipt, validated.context, validated.custody)
    except _CORE_REFUSALS:
        raise refused(AdmissionAdapterReason.AUTHORIZATION_REFUSED) from None
    groups, v3_release = case_release_graph(
        validated, planned_arm_scopes(validated.plan), bridge.decoded, resolve, plan_manifest, admission_manifest, preparation, spend
    )
    ordered_readiness = tuple(sorted(validated.readiness, key=lambda item: item.result_digest))
    try:
        return derive_scoped_replay(
            ScopedReplayRequestV1(
                admission_manifest,
                feasibility,
                preparation,
                receipt,
                spend,
                v3_release,
                groups,
                ordered_readiness,
                validated.context,
                validated.custody,
                resolver,
                validated.aggregate,
            )
        )
    except _CORE_REFUSALS:
        raise refused(AdmissionAdapterReason.RELEASE_REFUSED) from None


def _composed_plan_manifest(
    validated: AdmissionCaseAdapterRequestV1,
    manifest: EvaluationAdmissionManifestV3,
    census: PopulationCensusV3,
    readiness_digests: tuple[str, ...],
) -> EvaluationPlanManifestV3:
    try:
        return compose_plan_manifest(validated.plan, census, readiness_digests, manifest.custody_log_digest, validated.plan_review)
    except ValueError:
        raise refused(AdmissionAdapterReason.CENSUS_MISMATCH) from None


def bind_case_adapter_replay_stage(
    request: AdmissionCaseAdapterRequestV1,
) -> Callable[[AdmissionSpendReleaseV1], EvaluationReplayV3]:
    """Bind one production replay stage satisfying the run command's seam."""

    def stage(release: AdmissionSpendReleaseV1) -> EvaluationReplayV3:
        return derive_case_adapter_replay(request, release)

    return stage


def bind_case_adapter_spend_stage(
    request: AdmissionCaseAdapterRequestV1,
    *,
    custody: CustodyCompareAndSwap,
    custodian_identity: str,
    positive_change_digests: tuple[str, ...],
    scope_census: tuple[tuple[str, str, int], ...],
    load_labels: Callable[[], bytes],
    review: IndependenceAttestation,
    review_policy: ReviewIndependencePolicy,
    resolver: ContentResolver,
) -> Callable[[AdmissionExecutionV1], AdmissionSpendReleaseV1]:
    """Bind one production spend stage that roots the custody receipt in the core preparation.

    The stage derives the exact pre-spend preparation of ``request.execution`` and commits
    the shared spend from its label-release request, so the post-spend replay (bound to the
    same execution) binds the committed receipt. A product that differs from
    ``request.execution`` is refused before any custody read or write. The custody policy is
    the adapter context's: the one the core validates the receipt chain against.
    """

    def stage(execution: AdmissionExecutionV1) -> AdmissionSpendReleaseV1:
        if request.execution != execution:
            raise refused(AdmissionAdapterReason.INVALID_REQUEST)
        preparation = derive_case_adapter_preparation(request)
        return commit_preparation_spend_and_release(
            AdmissionSpendRequestV1(
                execution=execution,
                custody=custody,
                repository=request.repository,
                custodian_access_policy_digest=request.custodian_access_policy_digest,
                custody_policy=request.context.evidence.custody_policy,
                custodian_identity=custodian_identity,
                population_digest=request.population_digest,
                positive_change_digests=positive_change_digests,
                scope_census=scope_census,
                load_labels=load_labels,
                review=review,
                review_policy=review_policy,
                resolver=resolver,
            ),
            preparation,
        )

    return stage


__all__ = [
    "BridgedCaseGraphV1",
    "bind_case_adapter_replay_stage",
    "bind_case_adapter_spend_stage",
    "derive_case_adapter_preparation",
    "derive_case_adapter_replay",
]
