"""Task 11.3 conversion adapter: closed refusal surface (first slice).

The full end-to-end conversion suite drives the committed 8.1-8.5 chain over
the group-10 population; this slice pins the adapter's closed refusal surface
and stage wiring before that lifecycle runs.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_admission_execution import _Adapter, _case  # noqa: E402
from test_valid_benchmark_admission_replay import _core_context  # noqa: E402
from test_valid_benchmark_admission_spend import _CountingCustody, _LabelSource, _scope_census, _SpendEnv  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    _attestation,
    _Client,
    _digest,
    _policy,
    _settings,
)
from valid_benchmark_e2e_fixtures import (  # noqa: E402
    BRIDGE_RETENTION,
    BRIDGE_STORE,
    E2E_CUSTODIAN,
    E2EEnvironment,
    _ChainedCustodyPort,
    authorized_execution,
)

from benchmarks.valid import admission_case_adapter as adapter  # noqa: E402
from benchmarks.valid import admission_spend as spend  # noqa: E402
from benchmarks.valid import isolated_execution as execution  # noqa: E402
from benchmarks.valid import observation_checkpoint as checkpoint  # noqa: E402
from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.admission_case_adapter import (  # noqa: E402
    _bridged_preparation_graph,
    bind_case_adapter_replay_stage,
    derive_case_adapter_preparation,
    derive_case_adapter_replay,
)
from benchmarks.valid.admission_case_graph import (  # noqa: E402
    AdmissionAdapterError,
    AdmissionAdapterReason,
    AdmissionCaseAdapterRequestV1,
    validate_adapter_request,
)
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendReleaseV1,
    AdmissionSpendRequestV1,
    commit_spend_and_release,
    decode_sealed_labels,
    join_released_cases,
    label_open_request,
    release_review_subject,
)
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from openultrasast.core.custody import PopulationStatus, empty_population_custody_log, record_population_use  # noqa: E402
from openultrasast.core.evaluation_admission import validate_shared_spend  # noqa: E402
from openultrasast.core.evaluation_replay import EvaluationReplayV3  # noqa: E402
from openultrasast.core.evaluation_spend import EvaluationSharedSpendError  # noqa: E402


@lru_cache(maxsize=1)
def _environment():
    environment = _SpendEnv(_case())
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="adapter-conflicts")
    context, _custody_policy = _core_context()
    request = AdmissionCaseAdapterRequestV1(
        repository=environment.repository,
        custodian_access_policy_digest=_digest("adapter-access-policy"),
        execution=environment.product,
        plan=environment.case.plan,
        selection=environment.case.selection,
        population_digest=environment.case.freeze.population_digest,
        input_count=len(environment.case.manifest.input_digests),
        custody=environment.custody,
        resolver=resolver,
        context=context,
        readiness=(),
        case_content=lambda *_args, **_kwargs: None,
        proof_candidates=lambda *_args, **_kwargs: None,
        census_review=_attestation(_digest("census"), _digest("producer"), disclosure),
        plan_review=_attestation(_digest("plan"), _digest("producer"), disclosure),
        admission_review=lambda subject: _attestation(subject, _digest("producer"), disclosure),
        release_review=lambda subject: _attestation(subject, _digest("producer"), disclosure),
        bridged_store_identity="adapter-bridge",
        bridged_retention_policy_digest=_digest("adapter-retention"),
    )
    return request


def test_request_missing_readiness_is_refused_with_a_closed_reason() -> None:
    with pytest.raises(AdmissionAdapterError) as raised:
        validate_adapter_request(_environment())
    assert raised.value.reason is AdmissionAdapterReason.INVALID_REQUEST


def test_refused_spend_release_never_reaches_the_core_boundary() -> None:
    request = _environment()
    validate_adapter_request(_replace_readiness(request))
    refused = AdmissionSpendReleaseV1("labels_unreadable", "", False, 0, "", (), None, "")
    stage = bind_case_adapter_replay_stage(_replace_readiness(request))
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(_replace_readiness(request), refused)
    assert raised.value.reason is AdmissionAdapterReason.RELEASE_REFUSED
    assert callable(stage)


def _replace_readiness(request: AdmissionCaseAdapterRequestV1) -> AdmissionCaseAdapterRequestV1:
    from dataclasses import replace

    from test_core_readiness import _chain as _readiness_chain
    from test_valid_benchmark_admission_replay import _BridgeEnv  # noqa: F401  (readiness source)

    return replace(request, readiness=tuple(_readiness_chain()))


class _Bridged:
    """One label-blind e2e execution and the adapter authorities its core preparation derives from."""

    def __init__(self) -> None:
        self.environment = E2EEnvironment()
        self.case = self.environment.case
        self.execution = authorized_execution(self.environment)
        self.population = self.case.freeze.population_digest
        assert self.environment.custody_policy == self.case.context.evidence.custody_policy
        self.preparation = derive_case_adapter_preparation(self.adapter_request(self.environment.custody))

    def store(self) -> S3DurableCustodyStore:
        """A fresh store at the byte-identical available head the execution was authorized against.

        A population spends once and the durable store is monotonic, so every spend under test
        starts from its own store at that same head.
        """
        case = self.case
        store = S3DurableCustodyStore(
            _settings(StorePurpose.DURABLE),
            _Client(),
            self.environment.custody_policy,
            case.report,
            case.transient_identity,
            case.transient_profile,
        )
        assert store.initialize(empty_population_custody_log(self.population, E2E_CUSTODIAN))
        assert store.current_log(self.population).log_digest == self.preparation.authority.custody_log_digest
        return store

    def adapter_request(self, custody) -> AdmissionCaseAdapterRequestV1:
        case = self.case
        return AdmissionCaseAdapterRequestV1(
            repository=self.environment.repository,
            custodian_access_policy_digest=ACCESS_POLICY,
            execution=self.execution,
            plan=case.plan,
            selection=case.selection,
            population_digest=self.population,
            input_count=len(case.manifest.input_digests),
            custody=custody,
            resolver=case.evidence_resolver,
            context=case.context,
            readiness=case.readiness,
            case_content=case.content.port,
            proof_candidates=case.content.candidate_port,
            census_review=case.adapter_census_review,
            plan_review=case.adapter_plan_review,
            admission_review=lambda subject: _attestation(subject, _digest("adapter-admission-producer"), case.disclosure),
            release_review=lambda subject: _attestation(subject, _digest("adapter-release-producer"), case.disclosure),
            bridged_store_identity=BRIDGE_STORE,
            bridged_retention_policy_digest=BRIDGE_RETENTION,
        )

    def review(self, store, use) -> object:
        """External post-spend review over the subject the spend of ``use`` will produce."""
        case = self.case
        prior = store.current_log(self.population)
        receipt = record_population_use(use, prior, E2E_CUSTODIAN, self.environment.custody_policy)
        cases = join_released_cases(
            self.execution,
            self.environment.repository,
            ACCESS_POLICY,
            decode_sealed_labels(case.labels),
            case.freeze.positive_change_digests,
            _scope_census(case.freeze),
        )
        subject = release_review_subject(self.execution.admission_manifest.manifest_digest, receipt.receipt_digest, cases, case.labels)
        return _attestation(subject, _digest("adapter-release-producer"), case.disclosure)

    def spend_request(self, store, loader, review) -> AdmissionSpendRequestV1:
        case = self.case
        return AdmissionSpendRequestV1(
            execution=self.execution,
            custody=store,
            repository=self.environment.repository,
            custodian_access_policy_digest=ACCESS_POLICY,
            custody_policy=self.environment.custody_policy,
            custodian_identity=E2E_CUSTODIAN,
            population_digest=self.population,
            positive_change_digests=case.freeze.positive_change_digests,
            scope_census=_scope_census(case.freeze),
            load_labels=loader,
            review=review,
            review_policy=_policy(),
            resolver=case.evidence_resolver,
        )


@lru_cache(maxsize=1)
def _bridged() -> _Bridged:
    return _Bridged()


def _bound_spend_stage(bridged: _Bridged, store):
    """Build the adapter path's spend stage from production code only."""
    case = bridged.case
    return adapter.bind_case_adapter_spend_stage(
        bridged.adapter_request(_ChainedCustodyPort(store, bridged.environment.custody)),
        custody=store,
        custodian_identity=E2E_CUSTODIAN,
        positive_change_digests=case.freeze.positive_change_digests,
        scope_census=_scope_census(case.freeze),
        load_labels=_LabelSource(case.labels, store, bridged.population),
        review=bridged.review(store, bridged.preparation.label_release_request),
        review_policy=_policy(),
        resolver=case.evidence_resolver,
    )


def test_run_module_exports_the_bound_spend_stage_next_to_the_replay_stage() -> None:
    assert "bind_case_adapter_spend_stage" in run.__all__
    assert "bind_case_adapter_replay_stage" in run.__all__
    assert run.bind_case_adapter_spend_stage is adapter.bind_case_adapter_spend_stage


def test_preparation_spend_replays_in_core_where_the_legacy_label_open_spend_is_refused() -> None:
    """Same execution and adapter authorities over byte-identical available heads; one minting path replays."""
    bridged = _bridged()
    case = bridged.case
    preparation = bridged.preparation
    manifest = bridged.execution.admission_manifest

    legacy_store = bridged.store()
    legacy_head = legacy_store.current_log(bridged.population).log_digest
    legacy_request = bridged.adapter_request(_ChainedCustodyPort(legacy_store, bridged.environment.custody))
    legacy_review = bridged.review(
        legacy_store,
        label_open_request(bridged.population, manifest.manifest_digest, legacy_store.current_log(bridged.population).log_digest),
    )
    legacy = commit_spend_and_release(
        bridged.spend_request(legacy_store, _LabelSource(case.labels, legacy_store, bridged.population), legacy_review)
    )

    assert legacy.refusal_reason is None
    assert legacy.review_reference is not None
    legacy_receipt = legacy_store.current_log(bridged.population).receipts[-1]
    assert legacy_receipt.request.arm_id == spend.LABEL_OPEN_ARM_ID
    assert legacy_receipt.request != preparation.label_release_request

    store = bridged.store()
    assert store.current_log(bridged.population).log_digest == legacy_head
    request = bridged.adapter_request(_ChainedCustodyPort(store, bridged.environment.custody))

    release = _bound_spend_stage(bridged, store)(bridged.execution)

    assert release.refusal_reason is None
    assert release.review_reference is not None
    assert release.released_cases == legacy.released_cases
    receipt = store.current_log(bridged.population).receipts[-1]
    assert receipt.request == preparation.label_release_request
    assert release.custody_receipt_digest == receipt.receipt_digest
    replay = derive_case_adapter_replay(request, release)
    assert type(replay) is EvaluationReplayV3
    with pytest.raises(AdmissionAdapterError) as refused:
        derive_case_adapter_replay(legacy_request, legacy)
    assert refused.value.reason is AdmissionAdapterReason.AUTHORIZATION_REFUSED

    *_graph, admission_manifest = _bridged_preparation_graph(request)
    binding = validate_shared_spend(admission_manifest, preparation, receipt, case.context, store)
    assert binding.receipt_digest == receipt.receipt_digest
    with pytest.raises(EvaluationSharedSpendError, match="^shared-spend receipt does not match the preparation$"):
        validate_shared_spend(admission_manifest, preparation, legacy_receipt, case.context, legacy_store)


def _distinct_execution():
    """A second real execution of the same population whose arm runtime receipts differ (11 ms, not 9 ms)."""
    environment = E2EEnvironment()
    inner = environment.adapter.factory

    def factory(bundle):
        capture = inner(bundle)
        output = checkpoint.component_observation_output_bytes(capture.observations)
        return replace(capture, process_outcome=execution.completed_adapter_outcome(bundle, output, runtime_ms=11))

    environment.adapter = _Adapter(factory)
    return authorized_execution(environment)


def test_bound_spend_stage_refuses_a_distinct_execution_before_any_write() -> None:
    """The stage is bound to one execution; another product of the same population never reaches custody."""
    bridged = _bridged()
    store = bridged.store()
    custody = _CountingCustody(store)
    stage = _bound_spend_stage(bridged, custody)
    distinct = _distinct_execution()
    assert distinct != bridged.execution
    assert distinct.refusal_reason is None
    assert distinct.admission_manifest.custody_log_digest == bridged.execution.admission_manifest.custody_log_digest
    head = store.current_log(bridged.population)
    reads = custody.reads

    with pytest.raises(AdmissionAdapterError) as refused:
        stage(distinct)

    assert refused.value.reason is AdmissionAdapterReason.INVALID_REQUEST
    assert custody.reads == reads
    assert custody.swaps == 0
    assert store.current_log(bridged.population) == head
    assert head.status is PopulationStatus.AVAILABLE
    release = stage(bridged.execution)
    assert release.refusal_reason is None
    assert custody.swaps == 1
