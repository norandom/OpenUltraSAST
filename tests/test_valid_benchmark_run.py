"""Task 9.3 benchmark-only operator run, resume, and status commands."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection_core_fixtures import stored_artifact  # noqa: E402
from test_valid_benchmark_admission_execution import (  # noqa: E402
    WORKFLOW,
    _Adapter,
    _admission_review,
    _case,
    _selectors,
)
from test_valid_benchmark_admission_replay import PLANNED_ARMS, _scoped_replay  # noqa: E402
from test_valid_benchmark_admission_spend import (  # noqa: E402
    _label_bytes,
    _LabelSource,
    _scope_census,
)
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    CUSTODIAN,
    _attestation,
    _Client,
    _digest,
    _lifecycle,
    _policy,
    _settings,
    _SpyExecutor,
)
from test_valid_benchmark_orchestrator import WORKFLOW as PREFLIGHT_WORKFLOW  # noqa: E402
from test_valid_benchmark_orchestrator import (
    _case as _preflight_case,
)

from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.admission_execution import execute_planned_observations  # noqa: E402
from benchmarks.valid.admission_replay import ReplayPublicationRequestV1, publish_scoped_replay  # noqa: E402
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendError,
    AdmissionSpendRequestV1,
    commit_spend_and_release,
    decode_sealed_labels,
    join_released_cases,
    label_open_request,
    release_review_subject,
)
from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    ArtifactReadPermission,
    S3ArtifactRepository,
    artifact_object_location,
    artifact_read_authority,
)
from benchmarks.valid.durable_custody_store import S3DurableCustodyStore  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from benchmarks.valid.sealed_retry import resolve_head_selected_retry_authority  # noqa: E402
from benchmarks.valid.store_configuration import (  # noqa: E402
    StoreCapabilityEvidence,
    StoreConfiguration,
    StorePurpose,
)
from benchmarks.valid.workflow_journal import S3WorkflowJournal  # noqa: E402
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    DegradationCode,
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core.custody import (  # noqa: E402
    PopulationCustodyPolicy,
    PopulationStatus,
    derive_population_custody_policy_digest,
    empty_population_custody_log,
    record_population_use,
)

LEASE_EXPIRES = "2026-11-21T09:30:00Z"
LATER = "2026-11-21T10:00:00Z"
LATER_LEASE = "2026-11-21T10:30:00Z"
DURABLE_PREFIXES = (
    "reservations/",
    "reviews/",
    "lifecycles/",
    "populations/",
    "observations/",
    "workflows/",
    "reports/",
    "replays/",
    "custody/",
)


def _environ() -> dict[str, str]:
    environ: dict[str, str] = {}
    for purpose in StorePurpose:
        prefix = f"VALID_BENCHMARK_{purpose.value.upper()}"
        environ[f"{prefix}_S3_ENDPOINT"] = f"https://{purpose.value}.invalid:9000"
        environ[f"{prefix}_S3_BUCKET"] = f"valid-{purpose.value}"
        environ[f"{prefix}_AWS_ACCESS_KEY_ID"] = "ACCESS-SECRET"
        environ[f"{prefix}_AWS_SECRET_ACCESS_KEY"] = "SECRET-SECRET"
    return environ


def _evidence() -> dict[StorePurpose, StoreCapabilityEvidence]:
    return {
        StorePurpose.DURABLE: StoreCapabilityEvidence(StorePurpose.DURABLE, True, True, True, None, 30),
        StorePurpose.TRANSIENT: StoreCapabilityEvidence(StorePurpose.TRANSIENT, True, True, True, 14, 1),
    }


class _RecordingClient(_Client):
    def __init__(self) -> None:
        super().__init__()
        self.operations: list[str] = []

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.operations.append(f"put:{kwargs['Key']}")
        return super().put_object(**kwargs)

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.operations.append(f"get:{kwargs['Key']}")
        return super().get_object(**kwargs)


class _CrashingLoader:
    """Crash exactly between the committed custody CAS and the first label byte."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.reads = 0

    def __call__(self) -> bytes:
        self.reads += 1
        raise RuntimeError("crash between custody CAS and label load")


class _RaceClient(_Client):
    """Swap the journal head through a rival lease exactly at the next entry write."""

    def __init__(self) -> None:
        super().__init__()
        self._armed = False
        self._rival = None

    def arm(self, rival) -> None:
        self._armed = True
        self._rival = rival

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        if self._armed and kwargs.get("IfNoneMatch") == "*" and key.startswith(f"workflow/{WORKFLOW}/entries/"):
            self._armed = False
            assert self._rival is not None
            self._rival()
        return super().put_object(**kwargs)


@dataclass
class _Stores:
    durable: _RecordingClient
    transient: _RecordingClient
    repository: S3ArtifactRepository
    custody: S3DurableCustodyStore
    journal: S3WorkflowJournal
    custody_policy: PopulationCustodyPolicy


def _stores(case, durable: _RecordingClient, transient: _RecordingClient) -> _Stores:
    repository = S3ArtifactRepository(_settings(StorePurpose.DURABLE), durable)
    custody_policy = PopulationCustodyPolicy((CUSTODIAN,), derive_population_custody_policy_digest((CUSTODIAN,)))
    custody = S3DurableCustodyStore(
        _settings(StorePurpose.DURABLE), durable, custody_policy, case.report, case.transient_identity, case.transient_profile
    )
    assert custody.initialize(empty_population_custody_log(case.freeze.population_digest, CUSTODIAN))
    return _Stores(
        durable,
        transient,
        repository,
        custody,
        S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), transient),
        custody_policy,
    )


class _CommandEnv:
    """Execution-case environment whose stages call the committed seams."""

    def __init__(self, case=None, *, factory=None, transient_client=None) -> None:
        self.case = case if case is not None else _case()
        stores = _stores(
            self.case,
            _RecordingClient(),
            transient_client if transient_client is not None else _RecordingClient(),
        )
        self.durable, self.transient = stores.durable, stores.transient
        self.repository, self.custody, self.journal = stores.repository, stores.custody, stores.journal
        self.custody_policy = stores.custody_policy
        self.adapter = _Adapter(factory if factory is not None else self.case.default_factory)
        self.population = self.case.freeze.population_digest
        self.loader = _LabelSource(_label_bytes(self.case.freeze), self.custody, self.population)
        self.disclosure, self.resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="run-release-disclosures")
        self.last_execution = None

    def lifecycle(self):
        return _lifecycle(self.population, self.case.freeze.freeze_digest)

    def context(self):
        return run.bound_operator_context(
            run.validated_operator_configuration(_environ(), _evidence()),
            self.durable,
            self.transient,
            self.lifecycle(),
            self.custody_policy,
            self.case.report,
            self.case.transient_identity,
            self.case.transient_profile,
            _SpyExecutor(),
            ACCESS_POLICY,
        )

    def counts(self) -> WorkflowCounts:
        planned_inputs = len(self.case.manifest.input_digests)
        return WorkflowCounts(len(self.case.plan.registrations), 0, planned_inputs, 0, planned_inputs)

    def run_request(self, stages, **preflight_overrides: object):
        return run.BenchmarkRunRequestV1(self.case.run_request(**preflight_overrides), stages, self.counts(), 250)

    def release_review(self, execution, loader):
        manifest = execution.admission_manifest
        assert manifest is not None
        try:
            cases = join_released_cases(
                execution,
                self.repository,
                ACCESS_POLICY,
                decode_sealed_labels(loader.payload),
                self.case.freeze.positive_change_digests,
                _scope_census(self.case.freeze),
            )
            prior = self.custody.current_log(self.population)
            request = label_open_request(self.population, manifest.manifest_digest, prior.log_digest)
            subject = release_review_subject(
                manifest.manifest_digest,
                record_population_use(request, prior, CUSTODIAN, self.custody_policy).receipt_digest,
                cases,
                loader.payload,
            )
        except AdmissionSpendError:
            subject = _digest("underivable-release-subject")
        return _attestation(subject, _digest("release-producer"), self.disclosure)

    def spend_request(self, execution, loader) -> AdmissionSpendRequestV1:
        value: dict[str, object] = {
            "execution": execution,
            "custody": self.custody,
            "repository": self.repository,
            "custodian_access_policy_digest": ACCESS_POLICY,
            "custody_policy": self.custody_policy,
            "custodian_identity": CUSTODIAN,
            "population_digest": self.population,
            "positive_change_digests": self.case.freeze.positive_change_digests,
            "scope_census": _scope_census(self.case.freeze),
            "load_labels": loader,
            "review": self.release_review(execution, loader),
            "review_policy": _policy(),
            "resolver": self.resolver,
        }
        return AdmissionSpendRequestV1(**value)

    def publication_request(self, replay_value) -> ReplayPublicationRequestV1:
        declaration = replay_value.plan_manifest.declaration
        return ReplayPublicationRequestV1(
            repository=self.repository,
            replay=replay_value,
            planned_arm_ids=PLANNED_ARMS,
            planned_input_count=len({slot.input_identity_digest for slot in declaration.expected_observation_slots}),
            population_digest=declaration.population_digest,
            freeze_digest=declaration.freeze_digest,
            plan_digest=replay_value.plan_manifest.manifest_digest,
            workflow_digest=WORKFLOW,
            runtime_ms=321,
        )

    def stages(self, *, replay=None, spend_loader=None, crash_before_spend=False, pending_review=False, after_execution=None):
        case = self.case

        def _execution(preflight):
            review = None if pending_review else _admission_review(case)
            product = execute_planned_observations(
                self.lifecycle(),
                self.repository,
                self.custody,
                self.journal,
                ACCESS_POLICY,
                case.execution_request(preflight, adapter=self.adapter, review=review),
            )
            self.last_execution = product
            if after_execution is not None:
                after_execution()
            return product

        def _spend(execution):
            if crash_before_spend:
                raise RuntimeError("interrupted before custody spend")
            return commit_spend_and_release(self.spend_request(execution, self.loader if spend_loader is None else spend_loader))

        def _replay(release):
            return replay

        def _publication(replay_value):
            return publish_scoped_replay(self.publication_request(replay_value))

        return run.BenchmarkRunStagesV1(_execution, _spend, _replay, _publication)

    def resume_request(self, **overrides: object):
        authority = resolve_head_selected_retry_authority(self.journal, self.repository, ACCESS_POLICY, WORKFLOW)
        value: dict[str, object] = {
            "workflow_digest": WORKFLOW,
            "admission_identity_digest": authority.admission_identity_digest,
            "component_index": 0,
            "bundles": self.case.bundles,
            "checkpoint_selectors": _selectors(self.last_execution),
            "plan": self.case.plan,
            "adapter": self.adapter,
            "artifact_authority": _custodian(),
            "manifest": self.case.manifest,
            "public_material_manifest": self.case.material,
            "selection": self.case.selection,
            "lifecycle_authority": self.lifecycle(),
            "mismatch_authority": None,
            "access_policy_digest": ACCESS_POLICY,
            "attempt_id": "attempt-2",
            "lease_owner_id": "owner-b",
            "heartbeat_at": LATER,
            "lease_expires_at": LATER_LEASE,
            "now": LATER,
            "runtime_ms": 0,
        }
        value.update(overrides)
        return run.BenchmarkResumeRequestV1(**value)

    def status_request(self, outcome_reference=None, replay=None, *, now=LATER):
        return run.BenchmarkStatusRequestV1(
            WORKFLOW,
            now,
            self.population,
            self.case.freeze.freeze_digest,
            self.case.plan.plan_digest,
            outcome_reference,
            replay,
        )


class _PreflightEnv:
    """Orchestrator-case environment for the preflight-insufficient path."""

    def __init__(self) -> None:
        self.case = _preflight_case(small_scope_claimed=True)
        stores = _stores(self.case, _RecordingClient(), _RecordingClient())
        self.durable, self.transient = stores.durable, stores.transient
        self.repository, self.custody, self.journal = stores.repository, stores.custody, stores.journal
        self.custody_policy = stores.custody_policy

    def lifecycle(self):
        return _lifecycle(self.case.freeze.population_digest, self.case.freeze.freeze_digest)

    def context(self):
        return run.bound_operator_context(
            run.validated_operator_configuration(_environ(), _evidence()),
            self.durable,
            self.transient,
            self.lifecycle(),
            self.custody_policy,
            self.case.report,
            self.case.transient_identity,
            self.case.transient_profile,
            _SpyExecutor(),
            ACCESS_POLICY,
        )

    def run_request(self):
        planned_inputs = len(self.case.manifest.input_digests)
        counts = WorkflowCounts(len(self.case.plan.registrations), 0, planned_inputs, 0, planned_inputs)
        return run.BenchmarkRunRequestV1(self.case.request(), run.BenchmarkRunStagesV1(*_never_stages()), counts, 250)

    def status_request(self, outcome_reference=None):
        return run.BenchmarkStatusRequestV1(
            PREFLIGHT_WORKFLOW,
            LATER,
            self.case.freeze.population_digest,
            self.case.freeze.freeze_digest,
            self.case.plan.plan_digest,
            outcome_reference,
            None,
        )


def _custodian():
    return artifact_read_authority(
        ArtifactActorRole.CUSTODIAN,
        (ArtifactReadPermission.CUSTODIAN_SEALED, ArtifactReadPermission.PRIVATE),
        ACCESS_POLICY,
        expected_access_policy_digest=ACCESS_POLICY,
    )


def _never_stages():
    def _refused(prior):
        raise AssertionError("stages must not run after an insufficient preflight")

    return (_refused, _refused, _refused, _refused)


def _custody_status(env) -> PopulationStatus:
    return env.custody.current_log(env.case.freeze.population_digest).status


def test_command_entry_refuses_invalid_settings_and_capabilities_before_any_operation() -> None:
    missing = _environ()
    missing.pop("VALID_BENCHMARK_TRANSIENT_S3_BUCKET")
    with pytest.raises(run.OperatorCommandError) as settings_refusal:
        run.validated_operator_configuration(missing, _evidence())
    assert settings_refusal.value.reason is run.OperatorCommandReason.SETTINGS_INVALID

    unsupported = _evidence()
    unsupported[StorePurpose.TRANSIENT] = StoreCapabilityEvidence(StorePurpose.TRANSIENT, True, False, True, 14, 1)
    with pytest.raises(run.OperatorCommandError) as capability_refusal:
        run.validated_operator_configuration(_environ(), unsupported)
    assert capability_refusal.value.reason is run.OperatorCommandReason.CAPABILITIES_UNSUPPORTED

    environment = _CommandEnv()
    before = (list(environment.durable.operations), list(environment.transient.operations))
    with pytest.raises(run.OperatorCommandError) as collision:
        run.validated_operator_configuration(
            _environ() | {"VALID_BENCHMARK_TRANSIENT_S3_BUCKET": "valid-durable"}, unsupported
        )
    assert collision.value.reason in {
        run.OperatorCommandReason.SETTINGS_INVALID,
        run.OperatorCommandReason.CAPABILITIES_UNSUPPORTED,
    }
    assert (environment.durable.operations, environment.transient.operations) == before


def test_commands_refuse_a_context_not_bound_to_validated_settings() -> None:
    environment = _CommandEnv()
    crashed = _CommandEnv()
    run.benchmark_run_command(crashed.context(), crashed.run_request(crashed.stages(crash_before_spend=True)))
    colliding = StoreConfiguration(
        replace(
            _settings(StorePurpose.DURABLE),
            bucket="valid-transient",
            endpoint="https://transient.invalid:9000",
        ),
        _settings(StorePurpose.TRANSIENT),
    )
    bound_orchestrator = environment.context().orchestrator
    before = (list(environment.durable.operations), list(environment.transient.operations))
    with pytest.raises(run.OperatorCommandError) as refused:
        context = run.bound_operator_context(
            colliding,
            environment.durable,
            environment.transient,
            environment.lifecycle(),
            environment.custody_policy,
            environment.case.report,
            environment.case.transient_identity,
            environment.case.transient_profile,
            _SpyExecutor(),
            ACCESS_POLICY,
        )
    assert refused.value.reason is run.OperatorCommandReason.INVALID_REQUEST
    assert str(refused.value) == "operator_command_invalid_request"
    context = run.BenchmarkOperatorContextV1(
        colliding,
        environment.journal,
        environment.repository,
        environment.custody,
        bound_orchestrator,
    )
    for command in (
        lambda: run.benchmark_status_command(context, environment.status_request()),
        lambda: run.benchmark_resume_command(context, crashed.resume_request()),
    ):
        with pytest.raises(run.OperatorCommandError) as direct:
            command()
        assert direct.value.reason is run.OperatorCommandReason.INVALID_REQUEST
    assert (environment.durable.operations, environment.transient.operations) == before


def test_run_command_completes_with_incremental_durable_outputs_and_deterministic_reports(monkeypatch) -> None:
    _, replay = _scoped_replay(monkeypatch)
    environment = _CommandEnv()
    result = run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(replay=replay)))

    assert result.command is run.OperatorCommandKind.RUN
    assert result.outcome.status is WorkflowStatus.COMPLETED
    assert result.outcome.labels_spent is True
    assert result.outcome.workflow_digest == WORKFLOW
    assert result.outcome.evaluation_replay_ref is not None
    assert result.outcome_reference is not None
    assert _custody_status(environment) is PopulationStatus.SPENT
    journal_status = environment.journal.rebuild_status(WORKFLOW, LATER)
    assert journal_status.chain_length >= 4
    assert journal_status.phase is not None
    assert any(key.startswith(f"workflow/{WORKFLOW}/entries/") for key in environment.transient.versions)
    assert any(operation.startswith("put:workflows/") for operation in environment.durable.operations)
    assert any(operation.startswith("put:replays/") for operation in environment.durable.operations)

    canonical_bytes = canonical_json_bytes(json.loads(result.report_bytes))
    assert canonical_bytes == result.report_bytes
    assert result.report_text.isascii()

    repeated = _CommandEnv()
    repeat = run.benchmark_run_command(repeated.context(), repeated.run_request(repeated.stages(replay=replay)))
    assert repeat.report_bytes == result.report_bytes
    assert repeat.report_text == result.report_text
    assert repeat.outcome.outcome_digest == result.outcome.outcome_digest


def test_run_command_surfaces_preflight_insufficiency_without_spend_or_execution() -> None:
    environment = _PreflightEnv()
    result = run.benchmark_run_command(environment.context(), environment.run_request())

    assert result.outcome.status is WorkflowStatus.INSUFFICIENT
    assert result.outcome.reason_codes == (WorkflowReasonCode.SCOPE_INSUFFICIENT,)
    assert result.outcome.labels_spent is False
    assert result.outcome_reference is not None
    assert _custody_status(environment) is PopulationStatus.AVAILABLE
    assert environment.transient.versions == {}

    status = run.benchmark_status_command(environment.context(), environment.status_request(result.outcome_reference))
    assert status.outcome.status is WorkflowStatus.INSUFFICIENT
    assert status.report_bytes == result.report_bytes

    with pytest.raises(run.OperatorCommandError) as unknown:
        run.benchmark_status_command(environment.context(), environment.status_request())
    assert unknown.value.reason is run.OperatorCommandReason.WORKFLOW_UNKNOWN


def test_run_command_surfaces_the_seam_impaired_product_without_spend() -> None:
    environment = _CommandEnv()
    result = run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(pending_review=True)))

    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.labels_spent is False
    assert _custody_status(environment) is PopulationStatus.AVAILABLE


def test_interrupted_pre_spend_run_resumes_from_the_durable_store_without_rerun_or_release() -> None:
    environment = _CommandEnv()
    interrupted = run.benchmark_run_command(
        environment.context(), environment.run_request(environment.stages(crash_before_spend=True))
    )

    assert interrupted.outcome.status is WorkflowStatus.IMPAIRED
    assert interrupted.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert interrupted.outcome.labels_spent is False
    assert interrupted.outcome_reference is not None
    assert _custody_status(environment) is PopulationStatus.AVAILABLE
    executions_before = len(environment.adapter.calls)

    resumed = run.benchmark_resume_command(environment.context(), environment.resume_request())

    assert resumed.command is run.OperatorCommandKind.RESUME
    assert resumed.outcome.status is WorkflowStatus.IMPAIRED
    assert resumed.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert resumed.outcome.labels_spent is False
    assert resumed.outcome.degradation_codes == (DegradationCode.AUTOMATIC_RETRY_USED,)
    assert len(environment.adapter.calls) == executions_before
    assert environment.loader.reads == 0
    assert _custody_status(environment) is PopulationStatus.AVAILABLE
    assert environment.custody.current_log(environment.population).receipt_count == 0


def test_interrupted_post_spend_run_resumes_without_duplicate_release() -> None:
    environment = _CommandEnv()
    loader = _CrashingLoader(_label_bytes(environment.case.freeze))
    interrupted = run.benchmark_run_command(
        environment.context(), environment.run_request(environment.stages(spend_loader=loader))
    )

    assert interrupted.outcome.status is WorkflowStatus.IMPAIRED
    assert interrupted.outcome.reason_codes == (WorkflowReasonCode.INSTRUMENT_FAILURE,)
    assert interrupted.outcome.labels_spent is True
    assert _custody_status(environment) is PopulationStatus.SPENT

    resumed = run.benchmark_resume_command(environment.context(), environment.resume_request())

    assert resumed.outcome.status is WorkflowStatus.IMPAIRED
    assert resumed.outcome.labels_spent is True
    assert resumed.outcome.degradation_codes == (DegradationCode.AUTOMATIC_RETRY_USED,)
    log = environment.custody.current_log(environment.population)
    assert log.status is PopulationStatus.SPENT
    assert log.receipt_count == 1
    assert canonical_json_bytes(json.loads(resumed.report_bytes)) == resumed.report_bytes
    assert resumed.report_text.isascii()


def test_status_reports_stalled_only_from_the_expired_validated_head() -> None:
    environment = _CommandEnv()
    run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(crash_before_spend=True)))

    with pytest.raises(run.OperatorCommandError) as pending:
        run.benchmark_status_command(environment.context(), environment.status_request(now="2026-11-21T09:10:00Z"))
    assert pending.value.reason is run.OperatorCommandReason.OUTCOME_PENDING

    stalled = run.benchmark_status_command(environment.context(), environment.status_request())
    assert stalled.outcome.status is WorkflowStatus.IMPAIRED
    assert stalled.outcome.reason_codes == (WorkflowReasonCode.STALLED,)
    assert stalled.outcome.labels_spent is False
    assert stalled.outcome.phase is not None


def test_status_resolves_terminal_outcomes_bound_to_the_requested_workflow(monkeypatch) -> None:
    _, replay = _scoped_replay(monkeypatch)
    environment = _CommandEnv()
    result = run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(replay=replay)))

    status = run.benchmark_status_command(
        environment.context(), environment.status_request(result.outcome_reference, replay, now=LATER_LEASE)
    )
    assert status.outcome.status is WorkflowStatus.COMPLETED
    assert status.report_bytes == result.report_bytes

    with pytest.raises(run.OperatorCommandError) as unresolved:
        run.benchmark_status_command(environment.context(), environment.status_request(result.outcome_reference, None))
    assert unresolved.value.reason is run.OperatorCommandReason.OUTCOME_UNRESOLVED

    other = _CommandEnv()
    with pytest.raises(run.OperatorCommandError) as foreign:
        run.benchmark_status_command(other.context(), other.status_request(result.outcome_reference, replay))
    assert foreign.value.reason is run.OperatorCommandReason.OUTCOME_UNRESOLVED


def test_commands_never_mutate_detector_or_infrastructure_state(monkeypatch) -> None:
    _, replay = _scoped_replay(monkeypatch)
    environment = _CommandEnv()
    run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(replay=replay)))
    run.benchmark_status_command(environment.context(), environment.status_request())
    crashed = _CommandEnv()
    run.benchmark_run_command(crashed.context(), crashed.run_request(crashed.stages(crash_before_spend=True)))
    run.benchmark_resume_command(crashed.context(), crashed.resume_request())

    for env in (environment, crashed):
        methods = {operation.split(":", 1)[0] for operation in env.durable.operations + env.transient.operations}
        assert methods <= {"put", "get"}
        assert all(
            operation.split(":", 1)[1].startswith(DURABLE_PREFIXES) for operation in env.durable.operations
        )
        assert all(
            operation.split(":", 1)[1].startswith(f"workflow/{WORKFLOW}/") for operation in env.transient.operations
        )
        assert not any("detector" in operation or "lifecycle-policy" in operation for operation in env.durable.operations)


def test_status_refuses_hostile_outcome_bytes_without_a_traceback() -> None:
    environment = _CommandEnv()
    result = run.benchmark_run_command(
        environment.context(), environment.run_request(environment.stages(crash_before_spend=True))
    )
    reference = result.outcome_reference
    assert reference is not None
    location = artifact_object_location(_settings(StorePurpose.DURABLE), reference)
    hostile = b'{"schema_version":' + b"[" * 60000
    environment.durable.put_object(Bucket=location.bucket, Key=location.key, Body=hostile)

    with pytest.raises(run.OperatorCommandError) as refused:
        run.benchmark_status_command(environment.context(), environment.status_request(reference))

    assert refused.value.reason is run.OperatorCommandReason.OUTCOME_UNRESOLVED
    assert str(refused.value) == "operator_command_outcome_unresolved"


def test_run_command_reports_workflow_superseded_after_a_mid_run_head_race() -> None:
    race = _RaceClient()
    environment = _CommandEnv(transient_client=race)

    def _rival() -> None:
        rival = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), race)
        rival.acquire_expired_lease(
            WORKFLOW,
            rival.current_head(WORKFLOW).head_digest,
            "attempt-rival",
            "owner-rival",
            phase=WorkflowPhase.ARM_EXECUTION,
            counts=environment.counts(),
            heartbeat_at=LATER,
            lease_expires_at=LATER_LEASE,
        )

    with pytest.raises(run.OperatorCommandError) as superseded:
        run.benchmark_run_command(
            environment.context(),
            environment.run_request(environment.stages(after_execution=lambda: race.arm(_rival))),
        )

    assert superseded.value.reason is run.OperatorCommandReason.WORKFLOW_SUPERSEDED
    assert str(superseded.value) == "operator_command_workflow_superseded"
    assert _custody_status(environment) is PopulationStatus.AVAILABLE
    assert environment.loader.reads == 0


def test_resume_command_reports_blocked_when_the_seam_terminally_blocks() -> None:
    environment = _CommandEnv()
    run.benchmark_run_command(environment.context(), environment.run_request(environment.stages(crash_before_spend=True)))
    ineligible = _lifecycle(environment.population, environment.case.freeze.freeze_digest, active=False)

    with pytest.raises(run.OperatorCommandError) as blocked:
        run.benchmark_resume_command(
            environment.context(), environment.resume_request(lifecycle_authority=ineligible)
        )

    assert blocked.value.reason is run.OperatorCommandReason.RESUME_BLOCKED
    assert str(blocked.value) == "operator_command_resume_blocked"
    assert _custody_status(environment) is PopulationStatus.AVAILABLE
    assert environment.loader.reads == 0


def test_command_refusals_stay_closed_without_caller_content() -> None:
    environment = _CommandEnv()
    with pytest.raises(run.OperatorCommandError) as invalid:
        run.benchmark_run_command(environment.context(), replace(environment.run_request(environment.stages()), stages=None))
    assert invalid.value.reason is run.OperatorCommandReason.INVALID_REQUEST
    assert str(invalid.value) == "operator_command_invalid_request"

    crashed = _CommandEnv()
    run.benchmark_run_command(crashed.context(), crashed.run_request(crashed.stages(crash_before_spend=True)))
    with pytest.raises(run.OperatorCommandError) as unknown:
        run.benchmark_resume_command(
            crashed.context(), crashed.resume_request(workflow_digest=_digest("missing-workflow"))
        )
    assert unknown.value.reason is run.OperatorCommandReason.WORKFLOW_UNKNOWN
    assert str(unknown.value) == "operator_command_workflow_unknown"
