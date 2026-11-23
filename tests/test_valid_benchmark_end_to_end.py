"""Task 11.3 synthetic two-ecosystem, multi-family, multi-arm lifecycle end to end.

Drives the committed 8.1-8.6 chain over a full synthetic two-ecosystem
admission population: label-blind observation sealing, one shared custody
spend (CAS plus reread) chained from the core preparation, the reviewed
release, the 11.3 case-adapter conversion into the core V3 case graph,
exact-scope reports, whole deduplication, one validated replay publication,
restart recovery, and the deterministic redacted operator surface.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_admission_spend import _scope_census  # noqa: E402
from test_valid_benchmark_orchestrator import ACCESS_POLICY, _attestation, _digest  # noqa: E402
from test_valid_benchmark_run import _environ, _evidence  # noqa: E402
from valid_benchmark_e2e_fixtures import (  # noqa: E402
    ANCHOR_ARM,
    E2E_CUSTODIAN,
    EXPERIMENTAL_ARM,
    FAMILY_JS,
    FAMILY_PY,
    PLANNED_ARMS,
    E2EEnvironment,
    E2EPopulation,
    authorized_execution,
)

from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.admission_case_adapter import (  # noqa: E402
    derive_case_adapter_preparation,
    derive_case_adapter_replay,
)
from benchmarks.valid.admission_case_graph import (  # noqa: E402
    AdmissionAdapterError,
    AdmissionAdapterReason,
    AdmissionCaseAdapterRequestV1,
    case_release_graph,
    corrected_census,
    labeled_facts,
    planned_arm_scopes,
    scope_resolver,
)
from benchmarks.valid.admission_projection import ProjectionRequestV1, project_exact_scopes  # noqa: E402
from benchmarks.valid.admission_replay import ReplayPublicationRequestV1, publish_scoped_replay  # noqa: E402
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendReleaseV1,
    decode_sealed_labels,
    join_released_cases,
    release_review_subject,
)
from benchmarks.valid.artifact_repository import (  # noqa: E402
    ArtifactActorRole,
    ArtifactReadPermission,
    artifact_read_authority,
)
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_outcome import WorkflowCounts, WorkflowStatus  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    PopulationStatus,
    append_population_use,
    record_population_use,
)
from openultrasast.core.evaluation_measurement import MetricId  # noqa: E402
from openultrasast.core.evaluation_report import AdmissionDecision  # noqa: E402


class _LabelSource:
    """Custodian-bound label loader proving labels open only after the spend."""

    def __init__(self, payload: bytes, custody, population: str) -> None:
        self.payload = payload
        self.custody = custody
        self.population = population
        self.reads = 0

    def __call__(self) -> bytes:
        self.reads += 1
        head = self.custody.current_log(self.population)
        assert head.status is PopulationStatus.SPENT, "labels opened before committed spend"
        return self.payload


class _Lifecycle:
    """One complete converted lifecycle over fresh durable stores."""

    def __init__(self) -> None:
        self.environment = E2EEnvironment()
        self.case = self.environment.case
        self.execution = authorized_execution(self.environment)
        self.request = self._adapter_request()
        self.preparation = derive_case_adapter_preparation(self.request)
        self.loader = _LabelSource(self.case.labels, self.environment.store, self.case.freeze.population_digest)
        self.receipt = self._commit_shared_spend()
        self.released_cases = self._join_released_cases()
        self.release = self._release_product()
        self.replay = derive_case_adapter_replay(self.request, self.release)

    def _adapter_request(self) -> AdmissionCaseAdapterRequestV1:
        case = self.case
        return AdmissionCaseAdapterRequestV1(
            repository=self.environment.repository,
            custodian_access_policy_digest=ACCESS_POLICY,
            execution=self.execution,
            plan=case.plan,
            selection=case.selection,
            population_digest=case.freeze.population_digest,
            input_count=len(case.manifest.input_digests),
            custody=self.environment.custody,
            resolver=case.evidence_resolver,
            context=case.context,
            readiness=case.readiness,
            case_content=case.content.port,
            proof_candidates=case.content.candidate_port,
            census_review=case.adapter_census_review,
            plan_review=case.adapter_plan_review,
            admission_review=lambda subject: _attestation(
                subject, _digest("e2e-adapter-admission-producer"), case.disclosure
            ),
            release_review=lambda subject: _attestation(
                subject, _digest("e2e-adapter-release-producer"), case.disclosure
            ),
            bridged_store_identity="scoped-admission-v3-bridge",
            bridged_retention_policy_digest=_digest("bridge-retention-11-3"),
        )

    def _commit_shared_spend(self):
        prior = self.environment.store.current_log(self.case.freeze.population_digest)
        assert prior.status is PopulationStatus.AVAILABLE
        receipt = record_population_use(
            self.preparation.label_release_request,
            prior,
            E2E_CUSTODIAN,
            self.environment.custody_policy,
        )
        successor = append_population_use(prior, receipt, self.environment.custody_policy)
        assert self.environment.store.compare_and_swap(prior.log_digest, successor)
        head = self.environment.store.current_log(receipt.population_digest)
        assert head.status is PopulationStatus.SPENT
        assert head.log_digest == successor.log_digest
        assert head.receipt_count == receipt.sequence and head.receipts[-1] == receipt
        assert self.loader.reads == 0
        return receipt

    def _join_released_cases(self):
        raw = self.loader()
        labels = decode_sealed_labels(raw)
        return join_released_cases(
            self.execution,
            self.environment.repository,
            ACCESS_POLICY,
            labels,
            self.case.freeze.positive_change_digests,
            _scope_census(self.case.freeze),
        )

    def _release_product(self):
        manifest = self.execution.admission_manifest
        assert manifest is not None
        raw = self.case.labels
        subject = release_review_subject(
            manifest.manifest_digest, self.receipt.receipt_digest, self.released_cases, raw
        )
        review = _attestation(subject, _digest("e2e-release-producer"), self.case.disclosure)
        assert review.subject_digest == subject
        value = {
            "admission_manifest_digest": manifest.manifest_digest,
            "custody_receipt_digest": self.receipt.receipt_digest,
            "label_bytes_digest": canonical.bytes_digest(raw),
            "label_bytes_read": len(raw),
            "case_digests": tuple(row.case_digest for row in self.released_cases),
        }
        release_digest = canonical.content_digest(value)
        content = canonical_artifact_bytes(
            ArtifactKind.WORKFLOW, dict(value), access_class=ArtifactAccessClass.CUSTODIAN_SEALED, provenance_digest=subject
        )
        reference = artifact_reference(content)
        self.environment.repository.put_if_absent(content, reference=reference)
        accepted = self.environment.repository.get(
            reference,
            expected_kind=ArtifactKind.WORKFLOW,
            authority=artifact_read_authority(
                ArtifactActorRole.CUSTODIAN,
                (ArtifactReadPermission.CUSTODIAN_SEALED,),
                ACCESS_POLICY,
                expected_access_policy_digest=ACCESS_POLICY,
            ),
            expected_access_policy_digest=ACCESS_POLICY,
        )
        assert accepted.content == content
        return AdmissionSpendReleaseV1(
            None,
            self.receipt.receipt_digest,
            True,
            len(raw),
            canonical.bytes_digest(raw),
            self.released_cases,
            reference,
            release_digest,
        )


@pytest.fixture(scope="module")
def lifecycle() -> _Lifecycle:
    return _Lifecycle()


def test_label_blind_observations_and_one_shared_spend_precede_the_release(lifecycle: _Lifecycle) -> None:
    assert lifecycle.execution.refusal_reason is None
    assert lifecycle.execution.admission_manifest is not None
    assert lifecycle.execution.spend_authorization is not None and lifecycle.execution.spend_authorization.may_spend
    assert lifecycle.loader.reads == 1
    log = lifecycle.environment.store.current_log(lifecycle.case.freeze.population_digest)
    assert log.status is PopulationStatus.SPENT and log.receipt_count == 1
    assert lifecycle.receipt.request == lifecycle.preparation.label_release_request
    assert lifecycle.release.refusal_reason is None and lifecycle.release.labels_spent


def test_validated_replay_contains_every_planned_arm_with_exact_scopes(lifecycle: _Lifecycle) -> None:
    replay = lifecycle.replay
    assert tuple(report.baseline.arm_id for report in replay.reports) == PLANNED_ARMS
    expected_scopes = {(FAMILY_PY, "python"), (FAMILY_JS, "javascript")}
    for report in replay.reports:
        assert {
            (result.key.scope.family_id, result.key.scope.ecosystem) for result in report.scoped_results
        } == expected_scopes
        assert report.combination_lineage is not None or report.baseline.arm_id != ANCHOR_ARM
        for result in report.scoped_results:
            assert tuple(metric.metric_id for metric in result.metrics) == tuple(MetricId)
            for metric in result.metrics:
                assert metric.sample_count == metric.denominator > 0
                assert metric.interval_lower is not None and metric.interval_upper is not None
            assert result.decision in set(AdmissionDecision)
    unique_pushes = {case.underlying_push_digest for group in replay.cases_by_arm for case in group.cases}
    assert replay.whole_population_coverage.underlying_push_count == len(unique_pushes)
    assert len(unique_pushes) == len(lifecycle.case.manifest.input_digests)


def test_presenter_reports_standard_metrics_and_demonstration_status(lifecycle: _Lifecycle) -> None:
    counts = {arm: {} for arm in PLANNED_ARMS}
    for report in lifecycle.replay.reports:
        for result in report.scoped_results:
            for metric in result.metrics:
                counts[report.baseline.arm_id][metric.metric_id] = (metric.numerator, metric.denominator)
    for arm in PLANNED_ARMS:
        assert set(counts[arm]) == set(MetricId)
    demonstration = {}
    for group in lifecycle.replay.cases_by_arm:
        flagged = sum(1 for case in group.cases if case.role.value == "vulnerable" and case.claims)
        candidates = sum(1 for case in group.cases if case.proof_candidate is not None)
        demonstrated = sum(
            1
            for case in group.cases
            if case.role.value == "vulnerable"
            and case.claims
            and any(attachment.proof.outcome.value == "demonstrated" for attachment in case.proof_attachments)
        )
        demonstration[group.arm_id] = (flagged, candidates, demonstrated)
    assert demonstration[EXPERIMENTAL_ARM][0] > 0 and demonstration[EXPERIMENTAL_ARM][2] == demonstration[EXPERIMENTAL_ARM][0]
    assert demonstration["arm-shipped"][0] > 0 and demonstration["arm-shipped"][2] == 0
    assert demonstration[ANCHOR_ARM][0] > 0 and demonstration[ANCHOR_ARM][2] == 0


def test_exact_scope_projection_cross_checks_the_core_case_graph(lifecycle: _Lifecycle) -> None:
    rekeyed = replace(
        lifecycle.release,
        released_cases=tuple(
            replace(row, case_input_digest=row.underlying_push_digest, case_digest="")
            for row in lifecycle.release.released_cases
        ),
    )
    projection = project_exact_scopes(
        ProjectionRequestV1(release=rekeyed, execution=lifecycle.execution, selection=lifecycle.case.selection)
    )
    core_counts = {}
    for report in lifecycle.replay.reports:
        for result in report.scoped_results:
            by_metric = {metric.metric_id: metric for metric in result.metrics}
            core_counts[(result.key.arm_id, result.key.scope.family_id, result.key.scope.ecosystem)] = (
                by_metric[MetricId.VULNERABLE_RECALL].denominator,
                by_metric[MetricId.FIXED_FALSE_ALARM_RATE].denominator,
                by_metric[MetricId.ORDINARY_FALSE_ALARMS_PER_100].denominator,
            )
    for row in projection.scopes:
        key = (row.arm_id, row.family_id, row.ecosystem)
        assert core_counts[key] == (len(row.vulnerable_case_digests), len(row.fixed_case_digests), len(row.ordinary_case_digests))
    assert projection.whole_coverage.change_input_count == len(lifecycle.case.manifest.input_digests)
    assert projection.projection_digest


def test_case_graph_covers_the_full_closed_population_without_scoring(lifecycle: _Lifecycle) -> None:
    from benchmarks.valid.admission_case_adapter import _bridge

    request = lifecycle.request
    planned = planned_arm_scopes(request.plan)
    resolve = scope_resolver(request, planned)
    bridge = _bridge(request, resolve)
    census = corrected_census(request, planned, bridge.decoded, resolve)
    labels = labeled_facts(lifecycle.release)
    assert len(labels) == lifecycle.case.freeze.positive_count
    groups, release = case_release_graph(
        request,
        planned,
        bridge.decoded,
        resolve,
        lifecycle.replay.plan_manifest,
        lifecycle.replay.admission_manifest,
        lifecycle.preparation,
        lifecycle.replay.spend_binding,
    )
    assert {group.arm_id for group in groups} == set(PLANNED_ARMS)
    for group in groups:
        assert len(group.cases) == len(lifecycle.case.manifest.input_digests)
        for case in group.cases:
            assert (case.key.scope.family_id, case.key.scope.ecosystem) in {(FAMILY_PY, "python"), (FAMILY_JS, "javascript")}
    assert len(release.bindings) == sum(len(group.cases) for group in groups)
    assert census.whole_underlying_push_count == len(lifecycle.case.manifest.input_digests)


def test_sub_forty_freeze_is_non_authorizing_without_spend_or_adapter_activity() -> None:
    population = E2EPopulation(pairs_python=5, pairs_javascript=4, mint_cases=False)
    assert population.freeze.positive_count == 18
    assert population.freeze.population_class.value == "development_pilot"
    environment = E2EEnvironment(population)
    assert environment.adapter.calls == []

    def _refused(prior):
        raise AssertionError("stages must not run for a sub-forty freeze")

    with pytest.raises(Exception) as refused_run:  # noqa: B017  (closed orchestrator refusal)
        run.benchmark_run_command(
            _operator_context(environment),
            run.BenchmarkRunRequestV1(
                population.run_request(),
                run.BenchmarkRunStagesV1(_refused, _refused, _refused, _refused),
                WorkflowCounts(len(population.plan.registrations), 0, len(population.manifest.input_digests), 0, 0),
                250,
            ),
        )
    assert "admission_preflight_freeze_not_admission_class" in str(refused_run.value)
    assert environment.adapter.calls == []
    assert environment.store.current_log(population.freeze.population_digest).status is PopulationStatus.AVAILABLE
    with pytest.raises(Exception) as refused:  # noqa: B017  (closed orchestrator refusal)
        environment.orchestrator.preflight(population.run_request())
    assert "admission_preflight_freeze_not_admission_class" in str(refused.value)


def test_adapter_refusal_matrix_stays_closed_without_partial_replay(lifecycle: _Lifecycle) -> None:
    def _request(**overrides: object) -> AdmissionCaseAdapterRequestV1:
        return replace(lifecycle.request, **overrides)

    missing_content = _request(case_content=lambda *_args, **_kwargs: None)
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(missing_content, lifecycle.release)
    assert raised.value.reason is AdmissionAdapterReason.CASE_CONTENT_UNBOUND

    mismatched_candidates = _request(proof_candidates=lambda *_args, **_kwargs: None)
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(mismatched_candidates, lifecycle.release)
    assert raised.value.reason is AdmissionAdapterReason.CASE_CONTENT_UNBOUND

    wrong_census = _request(
        census_review=_attestation(_digest("e2e-wrong-census"), _digest("e2e-wrong-producer"), lifecycle.case.disclosure)
    )
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(wrong_census, lifecycle.release)
    assert raised.value.reason is AdmissionAdapterReason.CENSUS_MISMATCH

    wrong_labels = replace(
        lifecycle.release,
        released_cases=tuple(
            replace(row, family_id="other_family", case_digest="")
            if row.role.value == "vulnerable" and row.family_id == FAMILY_PY
            else row
            for row in lifecycle.release.released_cases
        ),
    )
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(lifecycle.request, wrong_labels)
    assert raised.value.reason in {AdmissionAdapterReason.RELEASE_REFUSED, AdmissionAdapterReason.CASE_CONTENT_UNBOUND}

    tampered_receipt = replace(lifecycle.release, custody_receipt_digest=_digest("e2e-forged-receipt"))
    with pytest.raises(AdmissionAdapterError) as raised:
        derive_case_adapter_replay(lifecycle.request, tampered_receipt)
    assert raised.value.reason in {AdmissionAdapterReason.RELEASE_REFUSED, AdmissionAdapterReason.AUTHORIZATION_REFUSED}


def _operator_context(environment: E2EEnvironment):
    return run.bound_operator_context(
        run.validated_operator_configuration(_environ(), _evidence()),
        environment.durable,
        environment.transient,
        environment.lifecycle(),
        environment.custody_policy,
        environment.case.report,
        environment.case.transient_identity,
        environment.case.transient_profile,
        _spy_executor(),
        ACCESS_POLICY,
    )


def _spy_executor():
    from test_valid_benchmark_orchestrator import _SpyExecutor  # noqa: E402

    return _SpyExecutor()


class _RunLifecycle:
    """The same production stages wired through the operator run command."""

    def __init__(self, *, crash_before_spend: bool = False) -> None:
        self.environment = E2EEnvironment()
        self.case = self.environment.case
        self.crash_before_spend = crash_before_spend
        self.loader = _LabelSource(self.case.labels, self.environment.store, self.case.freeze.population_digest)
        self.publication = None
        self.replay = None
        counts = WorkflowCounts(
            len(self.case.plan.registrations), 0, len(self.case.manifest.input_digests), 0, len(self.case.manifest.input_digests)
        )
        self.result = run.benchmark_run_command(
            _operator_context(self.environment),
            run.BenchmarkRunRequestV1(self.case.run_request(), self._stages(), counts, 250),
        )

    def _stages(self):
        case = self.case

        def _execution(preflight):
            from valid_benchmark_e2e_fixtures import _admission_review, _attempt_review  # noqa: E402

            return self.environment.execute(
                preflight,
                review=_admission_review(case),
                attempt_review=_attempt_review(case, preflight),
                status_ref=case.status_ref,
            )

        def _spend(execution):
            if self.crash_before_spend:
                raise RuntimeError("interrupted before the shared custody spend")
            preparation = derive_case_adapter_preparation(self._adapter_request(execution))
            prior = self.environment.store.current_log(case.freeze.population_digest)
            receipt = record_population_use(
                preparation.label_release_request, prior, E2E_CUSTODIAN, self.environment.custody_policy
            )
            successor = append_population_use(prior, receipt, self.environment.custody_policy)
            assert self.environment.store.compare_and_swap(prior.log_digest, successor)
            head = self.environment.store.current_log(receipt.population_digest)
            assert head.status is PopulationStatus.SPENT and head.receipts[-1] == receipt
            raw = self.loader()
            labels = decode_sealed_labels(raw)
            released = join_released_cases(
                execution,
                self.environment.repository,
                ACCESS_POLICY,
                labels,
                case.freeze.positive_change_digests,
                _scope_census(case.freeze),
            )
            manifest = execution.admission_manifest
            assert manifest is not None
            subject = release_review_subject(manifest.manifest_digest, receipt.receipt_digest, released, raw)
            value = {
                "admission_manifest_digest": manifest.manifest_digest,
                "custody_receipt_digest": receipt.receipt_digest,
                "label_bytes_digest": canonical.bytes_digest(raw),
                "label_bytes_read": len(raw),
                "case_digests": tuple(row.case_digest for row in released),
            }
            from benchmarks.valid.replacement_artifact_contract import artifact_reference, canonical_artifact_bytes  # noqa: E402

            content = canonical_artifact_bytes(
                ArtifactKind.WORKFLOW, dict(value), access_class=ArtifactAccessClass.CUSTODIAN_SEALED, provenance_digest=subject
            )
            reference = artifact_reference(content)
            self.environment.repository.put_if_absent(content, reference=reference)
            return AdmissionSpendReleaseV1(
                None, receipt.receipt_digest, True, len(raw), canonical.bytes_digest(raw), released, reference,
                canonical.content_digest(value),
            )

        def _replay(release):
            self.replay = derive_case_adapter_replay(self._adapter_request(_last_execution(self.environment)), release)
            return self.replay

        def _publication(replay_value):
            declaration = replay_value.plan_manifest.declaration
            self.publication = publish_scoped_replay(
                ReplayPublicationRequestV1(
                    repository=self.environment.repository,
                    replay=replay_value,
                    planned_arm_ids=PLANNED_ARMS,
                    planned_input_count=len({slot.input_identity_digest for slot in declaration.expected_observation_slots}),
                    population_digest=declaration.population_digest,
                    freeze_digest=declaration.freeze_digest,
                    plan_digest=replay_value.plan_manifest.manifest_digest,
                    workflow_digest=run_workflow_digest(),
                    runtime_ms=321,
                )
            )
            return self.publication

        return run.BenchmarkRunStagesV1(_execution, _spend, _replay, _publication)

    def _adapter_request(self, execution):
        case = self.case
        return AdmissionCaseAdapterRequestV1(
            repository=self.environment.repository,
            custodian_access_policy_digest=ACCESS_POLICY,
            execution=execution,
            plan=case.plan,
            selection=case.selection,
            population_digest=case.freeze.population_digest,
            input_count=len(case.manifest.input_digests),
            custody=self.environment.custody,
            resolver=case.evidence_resolver,
            context=case.context,
            readiness=case.readiness,
            case_content=case.content.port,
            proof_candidates=case.content.candidate_port,
            census_review=case.adapter_census_review,
            plan_review=case.adapter_plan_review,
            admission_review=lambda subject: _attestation(
                subject, _digest("e2e-adapter-admission-producer"), case.disclosure
            ),
            release_review=lambda subject: _attestation(
                subject, _digest("e2e-adapter-release-producer"), case.disclosure
            ),
            bridged_store_identity="scoped-admission-v3-bridge",
            bridged_retention_policy_digest=_digest("bridge-retention-11-3"),
        )


def run_workflow_digest() -> str:
    from valid_benchmark_e2e_fixtures import WORKFLOW  # noqa: E402

    return WORKFLOW


def _last_execution(environment: E2EEnvironment):
    assert environment.last_execution is not None
    return environment.last_execution


@pytest.fixture(scope="module")
def run_lifecycle() -> _RunLifecycle:
    return _RunLifecycle()


def test_run_command_completes_the_whole_lifecycle_with_deterministic_redacted_output(run_lifecycle: _RunLifecycle) -> None:
    result = run_lifecycle.result
    assert result.command is run.OperatorCommandKind.RUN
    assert result.outcome.status is WorkflowStatus.COMPLETED
    assert result.outcome.labels_spent is True
    assert result.outcome.counts.completed_arms == result.outcome.counts.planned_arms == len(PLANNED_ARMS)
    assert result.outcome.evaluation_replay_ref is not None
    assert run_lifecycle.publication.outcome.status is WorkflowStatus.COMPLETED
    assert run_lifecycle.publication.replay_digest == run_lifecycle.replay.replay_digest
    document = json.loads(result.report_bytes)
    assert document["status"] == "completed"
    assert document["counts"]["completed_arms"] == len(PLANNED_ARMS)
    arms = {arm["arm_id"]: arm for arm in document["replay"]["arms"]}
    assert set(arms) == set(PLANNED_ARMS)
    assert arms[EXPERIMENTAL_ARM]["demonstrated"]["status"] == "demonstrated"
    assert arms["arm-shipped"]["demonstrated"]["status"] == "not_demonstrated"
    for arm in arms.values():
        for scope in arm["scopes"]:
            assert {metric["metric_id"] for metric in scope["metrics"]} == {metric.value for metric in MetricId}
    assert result.report_text.isascii()
    assert run_lifecycle.case.labels[:64].decode("utf-8", "ignore") not in result.report_text
    assert "confidential-ground-truth-judgment" not in result.report_text


def test_workflow_persists_and_recovers_through_restart(run_lifecycle: _RunLifecycle) -> None:
    environment = run_lifecycle.environment
    status = run.benchmark_status_command(
        _operator_context(environment),
        run.BenchmarkStatusRequestV1(
            run_workflow_digest(),
            "2026-11-23T10:00:00Z",
            environment.case.freeze.population_digest,
            environment.case.freeze.freeze_digest,
            environment.case.plan.plan_digest,
            run_lifecycle.result.outcome_reference,
            run_lifecycle.replay,
        ),
    )
    assert status.outcome.status is WorkflowStatus.COMPLETED
    assert status.report_bytes == run_lifecycle.result.report_bytes
    assert status.report_text == run_lifecycle.result.report_text


def test_interrupted_pre_spend_run_resumes_without_rerunning_completed_arms() -> None:
    interrupted = _RunLifecycle(crash_before_spend=True)
    assert interrupted.result.outcome.status is WorkflowStatus.IMPAIRED
    assert interrupted.result.outcome.reason_codes[0].value == "interrupted"
    assert interrupted.result.outcome.labels_spent is False
    environment = interrupted.environment
    executions_before = len(environment.adapter.calls)
    assert environment.store.current_log(environment.case.freeze.population_digest).status is PopulationStatus.AVAILABLE

    from test_valid_benchmark_admission_execution import _selectors  # noqa: E402

    from benchmarks.valid.sealed_retry import resolve_head_selected_retry_authority

    authority = resolve_head_selected_retry_authority(environment.journal, environment.repository, ACCESS_POLICY, run_workflow_digest())
    resumed = run.benchmark_resume_command(
        _operator_context(environment),
        run.BenchmarkResumeRequestV1(
            workflow_digest=run_workflow_digest(),
            admission_identity_digest=authority.admission_identity_digest,
            component_index=0,
            bundles=environment.case.bundles,
            checkpoint_selectors=_selectors(environment.last_execution),
            plan=environment.case.plan,
            adapter=environment.adapter,
            artifact_authority=artifact_read_authority(
                ArtifactActorRole.CUSTODIAN,
                (ArtifactReadPermission.CUSTODIAN_SEALED, ArtifactReadPermission.PRIVATE),
                ACCESS_POLICY,
                expected_access_policy_digest=ACCESS_POLICY,
            ),
            manifest=environment.case.manifest,
            public_material_manifest=environment.case.material,
            selection=environment.case.selection,
            lifecycle_authority=environment.lifecycle(),
            mismatch_authority=None,
            access_policy_digest=ACCESS_POLICY,
            attempt_id="attempt-2",
            lease_owner_id="owner-b",
            heartbeat_at="2026-11-23T10:30:00Z",
            lease_expires_at="2026-11-23T11:00:00Z",
            now="2026-11-23T10:30:00Z",
            runtime_ms=0,
        ),
    )
    assert resumed.command is run.OperatorCommandKind.RESUME
    assert resumed.outcome.status is WorkflowStatus.IMPAIRED
    assert resumed.outcome.labels_spent is False
    assert len(environment.adapter.calls) == executions_before
    assert environment.store.current_log(environment.case.freeze.population_digest).receipt_count == 0


def test_poisoned_legacy_scorers_never_participate(lifecycle: _Lifecycle, monkeypatch) -> None:
    from benchmarks.valid import admission_run, admission_scoring

    def _refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("legacy scoring helpers must never authorize a V3 replay")

    for module, names in (
        (admission_scoring, ("admission_report", "_refuse_inputs", "score_v2_admission")),
        (admission_run, ("site_judgment",)),
    ):
        for name in names:
            monkeypatch.setattr(module, name, _refuse)
    replay = derive_case_adapter_replay(lifecycle.request, lifecycle.release)
    publication = publish_scoped_replay(
        ReplayPublicationRequestV1(
            repository=lifecycle.environment.repository,
            replay=replay,
            planned_arm_ids=PLANNED_ARMS,
            planned_input_count=len(lifecycle.case.manifest.input_digests),
            population_digest=lifecycle.case.freeze.population_digest,
            freeze_digest=lifecycle.case.freeze.freeze_digest,
            plan_digest=replay.plan_manifest.manifest_digest,
            workflow_digest=run_workflow_digest(),
            runtime_ms=321,
        )
    )
    assert publication.outcome.status is WorkflowStatus.COMPLETED
    assert publication.replay_digest == lifecycle.replay.replay_digest
