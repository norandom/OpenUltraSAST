"""Task 11.4 spend-ordering, crash, retry, and failure-visibility matrix.

The failure-matrix sibling of the 11.3 end-to-end suite: every injected
pre-spend, post-spend, and workflow failure over the same synthetic
two-ecosystem population must converge to the exact durable terminal
outcome or replay, never restore untouched custody, never rerun a
completed arm, and never surface as a clean metric or a raw exception.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_admission_execution import _selectors  # noqa: E402
from test_valid_benchmark_end_to_end import _LabelSource, _operator_context  # noqa: E402
from test_valid_benchmark_orchestrator import _settings  # noqa: E402
from valid_benchmark_e2e_fixtures import (  # noqa: E402
    E2E_CUSTODIAN,
    PLANNED_ARMS,
    WORKFLOW,
    E2EEnvironment,
    E2EPopulation,
)
from valid_benchmark_failure_injection import (  # noqa: E402
    EXPECTED_FAILURE_SLUGS,
    RECORDS,
    BoomAdapter,
    CountingCrashLoader,
    ExecutionDefect,
    FailureRun,
    OutcomeRefusingClient,
    adapter_request,
    defect_marker,
    population_labels,
    racing_environment,
    record_failure,
    resume_request,
)

from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.admission_execution import AdmissionExecutionReason  # noqa: E402
from benchmarks.valid.admission_replay import (  # noqa: E402
    AdmissionReplayError,
    AdmissionReplayReason,
    ReplayPublicationRequestV1,
    publish_scoped_replay,
)
from benchmarks.valid.artifact_repository import S3ArtifactRepository  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from benchmarks.valid.workflow_journal import (  # noqa: E402
    S3WorkflowJournal,
    WorkflowJournalEntryV1,
    WorkflowJournalError,
    WorkflowJournalReason,
    successor_head,
)
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    WorkflowCounts,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core.custody import PopulationStatus  # noqa: E402

NOW_LATER = "2026-11-23T10:30:00Z"


def _population_digest(failure: FailureRun) -> str:
    return failure.case.freeze.population_digest


def _log(failure: FailureRun):
    return failure.environment.store.current_log(_population_digest(failure))


def _assert_pre_spend_instrument_failure(failure: FailureRun) -> None:
    result = failure.result
    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.reason_codes == (WorkflowReasonCode.INSTRUMENT_FAILURE,)
    assert result.outcome.labels_spent is False
    assert result.outcome.evaluation_replay_ref is None
    assert result.outcome.counts.completed_arms < result.outcome.counts.planned_arms
    log = _log(failure)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0
    assert failure.loader.reads == 0


def _assert_spent_state_preserved(failure: FailureRun, *, loader_reads: int) -> None:
    log = _log(failure)
    assert log.status is PopulationStatus.SPENT
    assert log.receipt_count == 1
    assert failure.loader.reads == loader_reads


def _status_request(failure: FailureRun, outcome_reference: object) -> run.BenchmarkStatusRequestV1:
    return run.BenchmarkStatusRequestV1(
        WORKFLOW,
        NOW_LATER,
        _population_digest(failure),
        failure.case.freeze.freeze_digest,
        failure.case.plan.plan_digest,
        outcome_reference,
        None,
    )


def test_insufficient_scope_preflight_spends_nothing_and_reads_no_labels() -> None:
    population = E2EPopulation(mint_cases=False, minimum_ordinary=15)
    assert population.freeze.positive_count == 40
    environment = E2EEnvironment(population)
    loader = _LabelSource(population.labels, environment.store, population.freeze.population_digest)
    adapter = BoomAdapter("insufficient scope must never execute an arm")

    def _refused(prior: object) -> object:
        loader()
        adapter.execute(None)
        raise AssertionError("insufficient scope must never run a stage")

    stages = run.BenchmarkRunStagesV1(_refused, _refused, _refused, _refused)
    counts = WorkflowCounts(len(population.plan.registrations), 0, len(population.manifest.input_digests), 0, 0)
    result = run.benchmark_run_command(
        _operator_context(environment),
        run.BenchmarkRunRequestV1(population.run_request(), stages, counts, 250),
    )

    assert result.outcome.status is WorkflowStatus.INSUFFICIENT
    assert result.outcome.reason_codes == (WorkflowReasonCode.SCOPE_INSUFFICIENT,)
    assert result.outcome.labels_spent is False
    log = environment.store.current_log(population.freeze.population_digest)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0
    assert loader.reads == 0
    record_failure("insufficient-scope", result.outcome, result.report_text, result.report_bytes, ())


def test_missing_arm_refuses_impaired_before_the_spend() -> None:
    failure = FailureRun(ExecutionDefect.MISSING_ARM.value, defect=ExecutionDefect.MISSING_ARM).execute()
    _assert_pre_spend_instrument_failure(failure)
    product = failure.environment.last_execution
    assert product is not None and product.refusal_reason is AdmissionExecutionReason.EXECUTION_IMPAIRED


@pytest.mark.parametrize(
    "defect",
    [ExecutionDefect.INPUT_UNREADABLE, ExecutionDefect.INPUT_EMPTY],
)
def test_zero_or_unreadable_input_closes_as_an_instrument_failure(defect: ExecutionDefect) -> None:
    failure = FailureRun(defect.value, defect=defect).execute()
    _assert_pre_spend_instrument_failure(failure)


@pytest.mark.parametrize(
    "defect",
    [ExecutionDefect.STAGE_SKIPPED, ExecutionDefect.STAGE_PREMATURE],
)
def test_skipped_stage_or_early_exit_never_reaches_the_spend(defect: ExecutionDefect) -> None:
    failure = FailureRun(defect.value, defect=defect).execute()
    _assert_pre_spend_instrument_failure(failure)


@pytest.mark.parametrize(
    "defect",
    [ExecutionDefect.DEADLINE_OVERRUN, ExecutionDefect.BUDGET_EXHAUSTED, ExecutionDefect.RESOURCE_LIMIT],
)
def test_timeout_budget_and_resource_exhaustion_close_as_instrument_failures(defect: ExecutionDefect) -> None:
    failure = FailureRun(defect.value, defect=defect).execute()
    _assert_pre_spend_instrument_failure(failure)


def test_adapter_crash_is_a_closed_execution_impairment() -> None:
    failure = FailureRun(ExecutionDefect.ADAPTER_CRASH.value, defect=ExecutionDefect.ADAPTER_CRASH).execute()
    _assert_pre_spend_instrument_failure(failure)


def _rival_custody_spend(failure: FailureRun) -> None:
    from benchmarks.valid.admission_case_adapter import derive_case_adapter_preparation
    from openultrasast.core.custody import append_population_use, record_population_use

    preparation = derive_case_adapter_preparation(
        adapter_request(failure.environment, failure.environment.last_execution)
    )
    store = failure.environment.store
    prior = store.current_log(_population_digest(failure))
    receipt = record_population_use(
        preparation.label_release_request, prior, E2E_CUSTODIAN, failure.environment.custody_policy
    )
    successor = append_population_use(prior, receipt, failure.environment.custody_policy)
    assert store.compare_and_swap(prior.log_digest, successor)


def test_failed_custody_cas_rival_wins_without_any_label_read() -> None:
    failure = FailureRun("custody_cas_lost")
    failure.before_cas = lambda: _rival_custody_spend(failure)
    failure.execute()

    result = failure.result
    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert result.outcome.phase is WorkflowPhase.CUSTODY_SPEND
    assert result.outcome.evaluation_replay_ref is None
    _assert_spent_state_preserved(failure, loader_reads=0)


def test_after_spend_interruption_preserves_spent_state_and_resume_converges() -> None:
    marker = defect_marker("after_spend_interruption", "loader")
    failure = FailureRun(
        "after_spend_interruption",
        loader=CountingCrashLoader(population_labels(), marker),
        markers=(marker,),
    ).execute()

    result = failure.result
    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert result.outcome.labels_spent is True
    assert result.outcome.evaluation_replay_ref is None
    _assert_spent_state_preserved(failure, loader_reads=1)

    failure.environment.adapter = BoomAdapter("exact resume must never rerun a completed arm")
    resumed = run.benchmark_resume_command(
        _operator_context(failure.environment),
        resume_request(failure.environment, selectors=_selectors(failure.environment.last_execution)),
    )
    assert resumed.outcome.status is WorkflowStatus.IMPAIRED
    assert resumed.outcome.labels_spent is True
    assert resumed.outcome.degradation_codes == (run.DegradationCode.AUTOMATIC_RETRY_USED,)
    _assert_spent_state_preserved(failure, loader_reads=1)


def test_scoring_failure_is_impaired_never_a_partial_clean_metric() -> None:
    failure = FailureRun("scoring_failure", scoring_crash=True).execute()

    result = failure.result
    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert result.outcome.phase is WorkflowPhase.SCORING
    assert result.outcome.labels_spent is True
    assert result.outcome.evaluation_replay_ref is None
    _assert_spent_state_preserved(failure, loader_reads=1)

    status = run.benchmark_status_command(_operator_context(failure.environment), _status_request(failure, result.outcome_reference))
    assert status.outcome.status is WorkflowStatus.IMPAIRED
    assert status.report_bytes == result.report_bytes


def _publication_request(failure: FailureRun, repository: object) -> ReplayPublicationRequestV1:
    replay = failure.replay
    assert replay is not None
    declaration = replay.plan_manifest.declaration
    return ReplayPublicationRequestV1(
        repository=repository,
        replay=replay,
        planned_arm_ids=PLANNED_ARMS,
        planned_input_count=len({slot.input_identity_digest for slot in declaration.expected_observation_slots}),
        population_digest=declaration.population_digest,
        freeze_digest=declaration.freeze_digest,
        plan_digest=replay.plan_manifest.manifest_digest,
        workflow_digest=WORKFLOW,
        runtime_ms=321,
    )


def test_publication_failure_keeps_the_validated_replay_and_never_completes() -> None:
    failure = FailureRun("publication_failure", publication_crash=True).execute()

    result = failure.result
    assert result.outcome.status is WorkflowStatus.IMPAIRED
    assert result.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert result.outcome.phase is WorkflowPhase.REPORTING
    assert result.outcome.labels_spent is True
    assert result.outcome.evaluation_replay_ref is None
    _assert_spent_state_preserved(failure, loader_reads=1)
    assert failure.replay is not None

    refusing = S3ArtifactRepository(
        _settings(StorePurpose.DURABLE), OutcomeRefusingClient(failure.environment.durable)
    )
    with pytest.raises(AdmissionReplayError) as seam:
        publish_scoped_replay(_publication_request(failure, refusing))
    assert seam.value.reason is AdmissionReplayReason.PERSISTENCE_FAILED
    assert str(seam.value) == "admission_replay_persistence_failed"
    replay_keys = [key for key in failure.environment.durable.versions if key.startswith("replays/")]
    assert replay_keys and all(failure.environment.durable.body(key) for key in replay_keys)

    recovered = publish_scoped_replay(_publication_request(failure, failure.environment.repository))
    assert recovered.outcome.status is WorkflowStatus.COMPLETED
    assert recovered.replay_digest == failure.replay.replay_digest

    status = run.benchmark_status_command(_operator_context(failure.environment), _status_request(failure, result.outcome_reference))
    assert status.outcome.status is WorkflowStatus.IMPAIRED


def test_expired_lease_projects_stalled_never_instrument_failure() -> None:
    environment = E2EEnvironment()
    environment.preflight()
    case = environment.case
    request = run.BenchmarkStatusRequestV1(
        WORKFLOW, NOW_LATER, case.freeze.population_digest, case.freeze.freeze_digest, case.plan.plan_digest, None, None
    )

    with pytest.raises(run.OperatorCommandError) as pending:
        run.benchmark_status_command(_operator_context(environment), replace_now(request, "2026-11-23T09:10:00Z"))
    assert pending.value.reason is run.OperatorCommandReason.OUTCOME_PENDING

    stalled = run.benchmark_status_command(_operator_context(environment), request)
    assert stalled.outcome.status is WorkflowStatus.IMPAIRED
    assert stalled.outcome.reason_codes == (WorkflowReasonCode.STALLED,)
    assert WorkflowReasonCode.INSTRUMENT_FAILURE not in stalled.outcome.reason_codes
    assert stalled.outcome.labels_spent is False
    log = environment.store.current_log(case.freeze.population_digest)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0
    record_failure("expired-lease", stalled.outcome, stalled.report_text, stalled.report_bytes, ())


def replace_now(request: run.BenchmarkStatusRequestV1, now: str) -> run.BenchmarkStatusRequestV1:
    from dataclasses import replace

    return replace(request, now=now)


def test_exact_resume_never_reruns_a_completed_arm_and_stale_owners_are_refused() -> None:
    failure = FailureRun("pre_spend_crash_resume", crash_before_spend=True).execute()
    assert failure.result.outcome.status is WorkflowStatus.IMPAIRED
    assert failure.result.outcome.labels_spent is False
    assert _log(failure).status is PopulationStatus.AVAILABLE

    failure.environment.adapter = BoomAdapter("exact resume must never rerun a completed arm")
    resumed = run.benchmark_resume_command(
        _operator_context(failure.environment),
        resume_request(failure.environment, selectors=_selectors(failure.environment.last_execution)),
    )
    assert resumed.outcome.status is WorkflowStatus.IMPAIRED
    assert resumed.outcome.reason_codes == (WorkflowReasonCode.INTERRUPTED,)
    assert resumed.outcome.labels_spent is False
    assert _log(failure).receipt_count == 0
    assert failure.loader.reads == 0

    journal = failure.environment.journal
    head = journal.current_head(WORKFLOW)
    counts = WorkflowCounts(len(failure.case.plan.registrations), 0, len(failure.case.manifest.input_digests), 0, 0)
    stale = WorkflowJournalEntryV1(
        WORKFLOW,
        head.sequence + 1,
        head.entry_digest,
        "attempt-1",
        "owner-a",
        WorkflowPhase.ARM_EXECUTION,
        "2026-11-23T10:45:00Z",
        "2026-11-23T11:15:00Z",
        counts,
        "",
    )
    with pytest.raises(WorkflowJournalError) as append_refused:
        journal.append_and_swap(head.head_digest, stale, successor_head(head, stale))
    assert append_refused.value.reason is WorkflowJournalReason.LEASE_OWNER_MISMATCH
    assert str(append_refused.value) == "workflow_journal_lease_owner_mismatch"

    with pytest.raises(WorkflowJournalError) as stale_resume:
        run.benchmark_resume_command(
            _operator_context(failure.environment),
            resume_request(
                failure.environment,
                selectors=_selectors(failure.environment.last_execution),
                attempt_id="attempt-1",
                lease_owner_id="owner-a",
                heartbeat_at="2026-11-23T10:45:00Z",
                lease_expires_at="2026-11-23T11:15:00Z",
                now="2026-11-23T10:45:00Z",
            ),
        )
    assert stale_resume.value.reason is WorkflowJournalReason.LEASE_NOT_EXPIRED
    assert str(stale_resume.value) == "workflow_journal_lease_not_expired"
    assert _log(failure).status is PopulationStatus.AVAILABLE and _log(failure).receipt_count == 0
    assert failure.loader.reads == 0
    record_failure(
        "stale-resume-owner",
        None,
        str(stale_resume.value),
        str(stale_resume.value).encode("ascii"),
        (),
        closed_text=str(append_refused.value),
    )


def test_mid_run_head_race_reports_workflow_superseded_without_spend() -> None:
    environment = racing_environment()
    race = environment.transient
    counts = WorkflowCounts(
        len(environment.case.plan.registrations), 0, len(environment.case.manifest.input_digests), 0, 0
    )

    def _rival() -> None:
        rival = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), race)
        rival.acquire_expired_lease(
            WORKFLOW,
            rival.current_head(WORKFLOW).head_digest,
            "attempt-rival",
            "owner-rival",
            phase=WorkflowPhase.ARM_EXECUTION,
            counts=counts,
            heartbeat_at="2026-11-23T10:00:00Z",
            lease_expires_at="2026-11-23T10:30:00Z",
        )

    failure = FailureRun("head_race", environment=environment)
    failure.after_execution = lambda: race.arm(_rival)
    with pytest.raises(run.OperatorCommandError) as superseded:
        failure.execute()
    assert superseded.value.reason is run.OperatorCommandReason.WORKFLOW_SUPERSEDED
    assert str(superseded.value) == "operator_command_workflow_superseded"
    log = environment.store.current_log(environment.case.freeze.population_digest)
    assert log.status is PopulationStatus.AVAILABLE and log.receipt_count == 0
    assert failure.loader.reads == 0
    record_failure(
        "head-race",
        None,
        str(superseded.value),
        str(superseded.value).encode("ascii"),
        (),
    )


def test_every_injected_failure_surfaces_a_closed_reason_never_a_clean_metric() -> None:
    records = {record.slug: record for record in RECORDS}
    assert set(records) == EXPECTED_FAILURE_SLUGS
    closed_reasons = {code.value for code in WorkflowReasonCode}
    for record in RECORDS:
        assert record.report_text.isascii()
        assert "Traceback (most recent call last)" not in record.report_text
        for marker in record.markers:
            assert marker not in record.report_text
        if record.outcome is not None:
            assert record.outcome.status is not WorkflowStatus.COMPLETED
            assert record.outcome.evaluation_replay_ref is None
            assert all(code.value in closed_reasons for code in record.outcome.reason_codes)
            document = json.loads(record.report_bytes)
            assert "replay" not in document
            assert canonical_json_bytes(document) == record.report_bytes
        else:
            closed = record.closed_text or record.report_text
            assert closed == closed.lower()
            assert closed.isascii() and closed.replace("_", "a").isalnum()
