"""Task 8.5 scoped reports and one complete evaluation replay publication."""

from __future__ import annotations

import sys
from dataclasses import fields, replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_core_admission_context import _case as _core_context_case  # noqa: E402
from test_core_evaluation_end_to_end import _complete_replay  # noqa: E402
from test_core_readiness import _chain as _readiness_chain  # noqa: E402
from test_valid_benchmark_admission_execution import (  # noqa: E402
    NAMESPACE,
    _Adapter,
    _case,
    _digest,
)
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    CUSTODIAN,
    REVIEWER,
    _attestation,
    _Client,
    _lifecycle,
    _settings,
    _SpyExecutor,
)  # noqa: E402

from benchmarks.valid.admission_execution import (  # noqa: E402
    AdmissionExecutionRequestV1,
    execute_planned_observations,
    initial_attempt_event_payload_digest,
)
from benchmarks.valid.admission_orchestrator import AdmissionOrchestrator, compose_plan_manifest  # noqa: E402
from benchmarks.valid.admission_replay import (  # noqa: E402
    AdmissionBridgeRequestV1,
    AdmissionReplayError,
    ReplayPublicationRequestV1,
    ScopedReplayRequestV1,
    bridge_core_authorization,
    bridged_admission_subject,
    bridged_plan_subject,
    derive_scoped_replay,
    equal_aggregate_weights,
    publish_scoped_replay,
)
from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    S3ArtifactRepository,
    artifact_read_authority,
)
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.operator_report import resolve_operator_replay  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
)
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from benchmarks.valid.workflow_journal import S3WorkflowJournal  # noqa: E402
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowGate,
    WorkflowReasonCode,
    WorkflowStatus,
    decode_workflow_outcome,
    workflow_outcome_bytes,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.admission_context import make_admission_validation_context  # noqa: E402
from openultrasast.core.canonical import ArtifactResolutionError, ArtifactValidationError  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    PopulationCustodyPolicy,
    PopulationUseReceipt,
    append_population_use,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
    record_population_use,
)
from openultrasast.core.evaluation_admission import (  # noqa: E402
    EvaluationAdmissionV3Error,
    authorize_evaluation,
    preflight_evaluation,
    validate_evaluation_replay,
    validate_shared_spend,
)
from openultrasast.core.evaluation_authority import (  # noqa: E402
    EvaluationAdmissionManifestV3,
    EvaluationAuthorityError,
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_measurement import MetricId  # noqa: E402
from openultrasast.core.evaluation_observation import decode_arm_observation_set  # noqa: E402
from openultrasast.core.evaluation_report import AdmissionDecision  # noqa: E402
from openultrasast.core.factpack import (  # noqa: E402
    ReviewIndependencePolicy,
    derive_review_independence_policy_digest,
)
from openultrasast.core.readiness import validate_readiness_result  # noqa: E402
from openultrasast.core.validation import make_evidence_validation_context  # noqa: E402

BRIDGE_STORE = "scoped-admission-v3-bridge"
BRIDGE_RETENTION = _digest("bridge-retention")
PUBLIC_STATUS_SCHEMA = "openultrasast.detection-core.evaluation-public-status.v3"
PLANNED_ARMS = ("arm-a", "arm-b", "arm-combined")


def _operator_policy() -> str:
    return _digest("operator-read-policy")


def _operator_authority():
    return artifact_read_authority(ArtifactActorRole.OPERATOR, (), _operator_policy(), expected_access_policy_digest=_operator_policy())


@lru_cache(maxsize=1)
def _core_context():
    context_case = _core_context_case()
    old = context_case.context.evidence
    custody_policy = PopulationCustodyPolicy((CUSTODIAN,), derive_population_custody_policy_digest((CUSTODIAN,)))
    evidence = make_evidence_validation_context(
        family_catalog=old.family_catalog,
        fact_packs=old.fact_packs,
        model_programs=old.model_programs,
        lineages=old.lineages,
        fact_review_policy=old.fact_review_policy,
        provenance_trust_policy=old.provenance_trust_policy,
        custody_policy=custody_policy,
    )
    policy = ReviewIndependencePolicy(
        (REVIEWER,),
        (),
        ("trusted-store", BRIDGE_STORE),
        1 << 20,
        derive_review_independence_policy_digest((REVIEWER,), (), ("trusted-store", BRIDGE_STORE), 1 << 20),
    )
    context = make_admission_validation_context(
        evidence=evidence,
        admission_review_policy=policy,
        proof_trust_policy=None,
    )
    return context, custody_policy


def _public_status_ref():
    payload = canonical.canonical_bytes(
        {"schema_version": PUBLIC_STATUS_SCHEMA, "status_code": "sealed", "count": 0, "digest": _digest("bridge-status")}
    )
    return stored_artifact(payload, artifact_id="bridge-attempt-status")


class _ChainResolver:
    """Try each inner resolver in order; sealed documents stay read-only."""

    def __init__(self, *resolvers) -> None:
        self._resolvers = tuple(resolvers)

    def resolve(self, reference):
        for inner in self._resolvers:
            try:
                return inner.resolve(reference)
            except canonical.ArtifactResolutionError:
                continue
        raise canonical.ArtifactResolutionError(f"artifact not found: {reference.artifact_id}")


class _BridgeEnv:
    """Benchmark preflight/execution chain over custody the core context trusts."""

    def __init__(self, case) -> None:
        self.case = case
        self.context, custody_policy = _core_context()
        self.status_ref, status_resolver = _public_status_ref()
        self.run_request = case.run_request(resolver=_ChainResolver(status_resolver, case.resolver))
        self.durable = _Client()
        self.transient = _Client()
        self.repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), self.durable)
        self.custody = S3DurableCustodyStore(
            _settings(StorePurpose.DURABLE),
            self.durable,
            custody_policy,
            case.report,
            case.transient_identity,
            case.transient_profile,
        )
        assert self.custody.initialize(empty_population_custody_log(case.freeze.population_digest, CUSTODIAN))
        self.journal = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), self.transient)
        self.adapter = _Adapter(case.default_factory)
        self.orchestrator = AdmissionOrchestrator(
            self.lifecycle(), self.repository, self.custody, self.journal, _SpyExecutor(), ACCESS_POLICY
        )

    def lifecycle(self):
        return _lifecycle(self.case.freeze.population_digest, self.case.freeze.freeze_digest)

    def preflight(self) -> object:
        return self.orchestrator.preflight(self.run_request)

    def execution_request(self, preflight, status_ref, attempt_review, admission_review) -> AdmissionExecutionRequestV1:
        case = self.case
        return AdmissionExecutionRequestV1(
            preflight,
            self.run_request,
            case.selection,
            case.material,
            case.cases,
            case.budgets,
            self.adapter,
            (None, None),
            case.combination_registrations,
            admission_review,
            attempt_review,
            status_ref,
            case.durable_identity,
            BRIDGE_RETENTION,
            NAMESPACE,
        )

    def execute(self, preflight, status_ref, attempt_review, admission_review):
        return execute_planned_observations(
            self.lifecycle(),
            self.repository,
            self.custody,
            self.journal,
            ACCESS_POLICY,
            self.execution_request(preflight, status_ref, attempt_review, admission_review),
        )


@lru_cache(maxsize=1)
def _bridge_products() -> tuple[_BridgeEnv, object, object, tuple, AdmissionBridgeRequestV1]:
    return _mint_bridge_products()


def _mint_bridge_products() -> tuple[_BridgeEnv, object, object, tuple, AdmissionBridgeRequestV1]:
    case = _case()
    environment = _BridgeEnv(case)
    preflight = environment.preflight()
    status_ref = environment.status_ref
    attempt_review = _attestation(
        initial_attempt_event_payload_digest(preflight.plan_manifest, status_ref),
        _digest("bridge-attempt-producer"),
        case.disclosure,
    )
    harvest = environment.execute(preflight, status_ref, attempt_review, None)
    admission_review = _attestation(harvest.manifest_subject_digest, _digest("bridge-admission-producer"), case.disclosure)
    execution = environment.execute(preflight, status_ref, attempt_review, admission_review)
    assert execution.refusal_reason is None and execution.admission_manifest is not None
    readiness = tuple(_readiness_chain())
    for item in readiness:
        validate_readiness_result(item)
    return _bound_bridge_request(environment, preflight, execution, readiness)


def _bound_bridge_request(
    environment: _BridgeEnv, preflight: object, execution: object, readiness: tuple
) -> tuple[_BridgeEnv, object, object, tuple, AdmissionBridgeRequestV1]:
    case = environment.case
    plan_review = _attestation(
        bridged_plan_subject(environment.run_request, preflight, readiness),
        _digest("bridge-plan-producer"),
        case.disclosure,
    )
    request = AdmissionBridgeRequestV1(
        repository=environment.repository,
        custodian_access_policy_digest=ACCESS_POLICY,
        run_request=environment.run_request,
        preflight=preflight,
        execution=execution,
        readiness=readiness,
        context=environment.context,
        custody=environment.custody,
        bridged_store_identity=BRIDGE_STORE,
        bridged_retention_policy_digest=BRIDGE_RETENTION,
        plan_review=plan_review,
        admission_review=None,
    )
    bound = replace(
        request,
        admission_review=_attestation(bridged_admission_subject(request), _digest("bridge-admission-producer"), case.disclosure),
    )
    return environment, preflight, execution, readiness, bound


def _replay_inputs(monkeypatch, *, aggregate: bool = False):
    bundle, replay, *_ = _complete_replay(monkeypatch)
    reviewed_case = bundle[5]
    readiness_by_digest = {item.result_digest: item for item in reviewed_case[3]}
    ordered_readiness = tuple(readiness_by_digest[digest] for digest in bundle[3].plan_manifest.readiness_digests)
    request = ScopedReplayRequestV1(
        admission_manifest=bundle[3],
        feasibility=bundle[5][2],
        preparation=bundle[7],
        receipt=bundle[8],
        spend_binding=bundle[9],
        release=bundle[1],
        cases_by_arm=bundle[2],
        readiness=ordered_readiness,
        context=reviewed_case[0].context,
        custody=reviewed_case[0].port,
        resolver=bundle[4],
        aggregate=aggregate,
    )
    return bundle, replay, request


def _scoped_replay(monkeypatch, *, aggregate: bool = False):
    bundle, _, request = _replay_inputs(monkeypatch, aggregate=aggregate)
    return bundle, derive_scoped_replay(request)


def _publication_request(replay, *, planned_arms: tuple[str, ...] = PLANNED_ARMS) -> ReplayPublicationRequestV1:
    durable = _Client()
    repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), durable)
    return ReplayPublicationRequestV1(
        repository=repository,
        replay=replay,
        planned_arm_ids=planned_arms,
        planned_input_count=len({slot.input_identity_digest for slot in replay.plan_manifest.declaration.expected_observation_slots}),
        population_digest=replay.plan_manifest.declaration.population_digest,
        freeze_digest=replay.plan_manifest.declaration.freeze_digest,
        plan_digest=replay.plan_manifest.manifest_digest,
        workflow_digest=_digest("workflow-8-5"),
        runtime_ms=321,
    )


def test_scoped_replay_reports_every_planned_arm_with_complete_metrics_and_named_gates(monkeypatch) -> None:
    bundle, replay = _scoped_replay(monkeypatch)
    assert tuple(report.baseline.arm_id for report in replay.reports) == PLANNED_ARMS
    for report in replay.reports:
        assert report.combination_lineage is not None or report.baseline.arm_id != "arm-combined"
        assert report.operational_evidence.runtime_ms >= 0
        assert report.operational_evidence.completed_count >= 1
        assert report.scoped_results
        for result in report.scoped_results:
            assert tuple(metric.metric_id for metric in result.metrics) == tuple(MetricId)
            for metric in result.metrics:
                assert metric.sample_count == metric.denominator > 0
                assert metric.interval_lower is not None and metric.interval_upper is not None
            required_metrics = (
                MetricId.VULNERABLE_RECALL,
                MetricId.ORDINARY_FALSE_ALARMS_PER_100,
                MetricId.PRECISION,
                MetricId.PAIRED_CORRECTNESS,
            )
            for required in required_metrics:
                assert required in {metric.metric_id for metric in result.metrics}
            assert result.instrument_gate.reasons == () or result.instrument_gate.status.value
            assert result.quality_gate is not None
            assert result.decision in set(AdmissionDecision)
    baseline_digests = {row.baseline_digest for row in replay.plan_manifest.baselines}
    assert {report.baseline.baseline_digest for report in replay.reports} == baseline_digests


def test_optional_aggregate_is_explicit_non_authorizing_and_whole_coverage_is_deduplicated(monkeypatch) -> None:
    bundle, replay = _scoped_replay(monkeypatch, aggregate=True)
    assert replay.aggregate is not None
    keys = tuple(sorted({metric.key for metric in replay.report_source.metrics}))
    assert replay.aggregate.constituents == keys
    assert len(replay.aggregate.sample_counts) == len(keys)
    assert all(count > 0 for count in replay.aggregate.sample_counts)
    assert replay.aggregate.weights == equal_aggregate_weights(replay.plan_manifest)
    from fractions import Fraction

    assert sum((Fraction(row.numerator, row.denominator) for row in replay.aggregate.weights), Fraction()) == 1
    assert "decision" not in {field.name for field in fields(replay.aggregate)}
    assert "gate" not in {field.name for field in fields(replay.aggregate)}
    whole = replay.whole_population_coverage
    unique_pushes = {case.underlying_push_digest for group in replay.cases_by_arm for case in group.cases}
    assert whole.underlying_push_count == len(replay.report_source.whole_projection.underlying_push_digests)
    assert whole.underlying_push_count == len(unique_pushes)


def test_replay_derivation_is_deterministic_and_validates_against_current_sources(monkeypatch) -> None:
    bundle, _, request = _replay_inputs(monkeypatch)
    first = derive_scoped_replay(request)
    second = derive_scoped_replay(request)
    assert first.replay_digest == second.replay_digest
    assert first == second
    assert validate_evaluation_replay(first, request.context, request.custody, request.resolver) == first.reports


def test_completed_publication_binds_one_operator_safe_replay_reference(monkeypatch) -> None:
    bundle, replay = _scoped_replay(monkeypatch)
    request = _publication_request(replay)
    publication = publish_scoped_replay(request)
    outcome = publication.outcome
    assert outcome.status is WorkflowStatus.COMPLETED
    assert outcome.labels_spent is True
    assert outcome.counts.completed_arms == outcome.counts.planned_arms == len(PLANNED_ARMS)
    assert outcome.evaluation_replay_ref is not None
    assert outcome.evaluation_replay_ref is publication.replay_reference
    assert publication.replay_reference.artifact_kind is ArtifactKind.REPLAY
    assert publication.replay_reference.access_class is ArtifactAccessClass.OPERATOR_SAFE
    assert publication.replay_digest == replay.replay_digest
    assert decode_workflow_outcome(workflow_outcome_bytes(outcome)) == outcome
    accepted = request.repository.get(
        publication.replay_reference,
        expected_kind=ArtifactKind.REPLAY,
        authority=_operator_authority(),
        expected_access_policy_digest=_operator_policy(),
    )
    assert accepted.artifact.payload["replay_digest"] == replay.replay_digest
    resolved = resolve_operator_replay(publication.replay_reference, accepted.content, replay)
    assert resolved.reports == replay.reports
    assert publication.reports == replay.reports
    assert publication.scoped_decisions == tuple(
        (
            report.baseline.arm_id,
            result.key.scope.family_id,
            result.key.scope.ecosystem,
            result.decision.value,
        )
        for report in replay.reports
        for result in report.scoped_results
    )


def test_missing_planned_arm_or_report_blocks_completion_with_impaired_outcome(monkeypatch) -> None:
    bundle, replay = _scoped_replay(monkeypatch)
    request = _publication_request(replay, planned_arms=(*PLANNED_ARMS, "arm-phantom"))
    publication = publish_scoped_replay(request)
    outcome = publication.outcome
    assert outcome.status is WorkflowStatus.IMPAIRED
    assert outcome.reason_codes == (WorkflowReasonCode.INSTRUMENT_FAILURE,)
    assert WorkflowGate.REPLAY_VALIDATION in outcome.failed_gate_names
    assert outcome.labels_spent is True
    assert outcome.evaluation_replay_ref is None
    assert publication.replay_reference is None
    assert decode_workflow_outcome(workflow_outcome_bytes(outcome)) == outcome
    assert outcome.input_read_evidence_digest == "" and outcome.stage_execution_evidence_digest == ""


def test_invalid_replay_object_is_refused_with_a_closed_reason(monkeypatch) -> None:
    bundle, replay = _scoped_replay(monkeypatch)
    request = _publication_request(replay)
    refused = replace(request, replay="not-an-evaluation-replay")  # type: ignore[arg-type]
    with pytest.raises(AdmissionReplayError):
        publish_scoped_replay(refused)


def test_publication_survives_poisoned_legacy_scoring_helpers(monkeypatch) -> None:
    from benchmarks.valid import admission_run, admission_scoring

    def _refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("legacy scoring helpers must never authorize a V3 replay")

    for module, names in (
        (admission_scoring, ("admission_report", "_refuse_inputs", "score_v2_admission")),
        (admission_run, ("site_judgment",)),
    ):
        for name in names:
            monkeypatch.setattr(module, name, _refuse)
    bundle, replay = _scoped_replay(monkeypatch, aggregate=True)
    publication = publish_scoped_replay(_publication_request(replay))
    assert publication.outcome.status is WorkflowStatus.COMPLETED


def test_bridge_core_authorization_over_raw_documents_and_real_readiness() -> None:
    environment, preflight, execution, readiness, request = _bridge_products()
    bridged = bridge_core_authorization(request)
    digests = tuple(sorted(item.result_digest for item in readiness))
    assert bridged.plan_manifest.readiness_digests == digests
    assert bridged.admission_manifest.readiness_digests == digests
    assert (
        bridged.preparation.authority.readiness_set_digest == canonical.content_digest({"readiness_digests": digests})
        or bridged.preparation.authority.readiness_set_digest
    )
    assert bridged.preparation.authority.observation_set_digest != derive_evaluation_observation_set_digest_zero()
    for sealed in bridged.admission_manifest.observations:
        resolved = bridged.resolver.resolve(sealed.observation)
        assert canonical.bytes_digest(resolved.content) == sealed.observation.content_digest
        assert decode_arm_observation_set(resolved.content).observation_digest == sealed.observation_digest
    assert bridged.preparation.label_release_request.influenced_artifact_digest == (bridged.preparation.authority.authority_digest)
    assert bridged.preparation.label_release_request.arm_id == bridged.plan_manifest.manifest_digest
    receipt = _commit_shared_spend(environment, bridged)
    binding = validate_shared_spend(bridged.admission_manifest, bridged.preparation, receipt, environment.context, environment.custody)
    assert binding.receipt_digest == receipt.receipt_digest


def derive_evaluation_observation_set_digest_zero() -> str:
    return "0" * 64


def _commit_shared_spend(environment: _BridgeEnv, bridged) -> PopulationUseReceipt:
    preparation = bridged.preparation
    prior = environment.custody.current_log(preparation.label_release_request.population_digest)
    receipt = record_population_use(preparation.label_release_request, prior, CUSTODIAN, environment.context.evidence.custody_policy)
    successor = append_population_use(prior, receipt, environment.context.evidence.custody_policy)
    assert environment.custody.compare_and_swap(prior.log_digest, successor)
    return receipt


def test_unbridged_envelope_references_and_capability_readiness_are_refused_by_core() -> None:
    environment, preflight, execution, readiness, request = _mint_bridge_products()
    case = environment.case
    digests = tuple(sorted(item.result_digest for item in readiness))
    plan_review = _attestation(
        bridged_plan_subject(environment.run_request, preflight, readiness),
        _digest("gap-plan-producer"),
        case.disclosure,
    )
    gap_plan = compose_plan_manifest(case.plan, preflight.plan_manifest.census, digests, preflight.custody_log_digest, plan_review)
    feasibility = preflight_evaluation(gap_plan, environment.context, case.resolver)
    envelope_draft = EvaluationAdmissionManifestV3(
        gap_plan,
        feasibility.feasibility_digest,
        execution.admission_manifest.observations,
        digests,
        preflight.custody_log_digest,
        execution.admission_manifest.attempt_history,
        "0" * 64,
        plan_review,
        "0" * 64,
    )
    envelope_payload = derive_evaluation_admission_manifest_payload_digest(envelope_draft)
    envelope_review = _attestation(envelope_payload, _digest("gap-admission-producer"), case.disclosure)
    envelope_manifest = replace(envelope_draft, payload_digest=envelope_payload, review=envelope_review)
    envelope_manifest = replace(envelope_manifest, manifest_digest=derive_evaluation_admission_manifest_digest(envelope_manifest))
    with pytest.raises((EvaluationAdmissionV3Error, ArtifactResolutionError, ArtifactValidationError)):
        authorize_evaluation(envelope_manifest, feasibility, readiness, environment.context, environment.custody, case.resolver)
    bridged = bridge_core_authorization(request)
    original = preflight.plan_manifest
    capability_draft = EvaluationAdmissionManifestV3(
        original,
        preflight.feasibility.feasibility_digest,
        bridged.admission_manifest.observations,
        original.readiness_digests,
        preflight.custody_log_digest,
        bridged.admission_manifest.attempt_history,
        "0" * 64,
        plan_review,
        "0" * 64,
    )
    capability_payload = derive_evaluation_admission_manifest_payload_digest(capability_draft)
    capability_review = _attestation(capability_payload, _digest("gap-capability-producer"), case.disclosure)
    capability_manifest = replace(capability_draft, payload_digest=capability_payload, review=capability_review)
    capability_manifest = replace(capability_manifest, manifest_digest=derive_evaluation_admission_manifest_digest(capability_manifest))
    assert original.readiness_digests != digests
    with pytest.raises((EvaluationAdmissionV3Error, EvaluationAuthorityError)):
        authorize_evaluation(
            capability_manifest,
            preflight.feasibility,
            readiness,
            environment.context,
            environment.custody,
            bridged.resolver,
        )
