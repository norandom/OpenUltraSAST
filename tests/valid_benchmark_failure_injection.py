"""Task 11.4 failure-injection harness over the committed e2e substrate.

Wraps the committed admission seams (the operator run stages, the execution
adapter factory, the label loader, and the fixture store clients) so one
closed instrument defect at a time can be injected without editing any
committed production module. Every injected raise carries a unique marker
string so the closing visibility sweep can prove no raw failure text ever
reaches the operator surface.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_admission_execution import (  # noqa: E402
    _Adapter,
    _read_rows,
    _stage_rows,
)
from test_valid_benchmark_admission_spend import _scope_census  # noqa: E402
from test_valid_benchmark_end_to_end import _LabelSource, _operator_context  # noqa: E402
from test_valid_benchmark_orchestrator import ACCESS_POLICY, _attestation, _Client, _digest, _settings  # noqa: E402
from valid_benchmark_e2e_fixtures import (  # noqa: E402
    BRIDGE_RETENTION,
    E2E_CUSTODIAN,
    PLANNED_ARMS,
    WORKFLOW,
    E2EEnvironment,
    _admission_review,
    _attempt_review,
    _population,
)

from benchmarks.valid import isolated_execution as execution  # noqa: E402
from benchmarks.valid import observation_checkpoint as checkpoint  # noqa: E402
from benchmarks.valid import run  # noqa: E402
from benchmarks.valid.admission_case_adapter import (  # noqa: E402
    derive_case_adapter_preparation,
    derive_case_adapter_replay,
)
from benchmarks.valid.admission_case_graph import AdmissionCaseAdapterRequestV1  # noqa: E402
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
from benchmarks.valid.isolated_execution_contract import ProcessOutcomeReason  # noqa: E402
from benchmarks.valid.observation_receipt import InputReadStatus, StageExecutionStatus  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.sealed_retry import resolve_head_selected_retry_authority  # noqa: E402
from benchmarks.valid.store_configuration import StorePurpose  # noqa: E402
from benchmarks.valid.workflow_journal import S3WorkflowJournal  # noqa: E402
from benchmarks.valid.workflow_outcome import WorkflowCounts  # noqa: E402
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    PopulationStatus,
    append_population_use,
    record_population_use,
)

TARGET_ARM = "arm-shipped"
RESUME_HEARTBEAT = "2026-11-23T10:30:00Z"
RESUME_LEASE_EXPIRES = "2026-11-23T11:00:00Z"


class ExecutionDefect(StrEnum):
    """Closed instrument defects injectable into one component arm."""

    INPUT_UNREADABLE = "input_unreadable"
    INPUT_EMPTY = "input_empty"
    STAGE_SKIPPED = "stage_skipped"
    STAGE_PREMATURE = "stage_premature"
    DEADLINE_OVERRUN = "deadline_overrun"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RESOURCE_LIMIT = "resource_limit"
    MISSING_ARM = "missing_arm"
    ADAPTER_CRASH = "adapter_crash"


@dataclass
class FailureRecord:
    """One injected failure's operator-visible durable surface."""

    slug: str
    outcome: Any
    report_text: str
    report_bytes: bytes
    markers: tuple[str, ...] = ()
    closed_text: str = ""


RECORDS: list[FailureRecord] = []
EXPECTED_FAILURE_SLUGS = frozenset(
    {
        "insufficient-scope",
        "missing_arm",
        "input_unreadable",
        "input_empty",
        "stage_skipped",
        "stage_premature",
        "deadline_overrun",
        "budget_exhausted",
        "resource_limit",
        "adapter_crash",
        "custody_cas_lost",
        "after_spend_interruption",
        "scoring_failure",
        "publication_failure",
        "pre_spend_crash_resume",
        "expired-lease",
        "stale-resume-owner",
        "head-race",
    }
)


def record_failure(
    slug: str,
    outcome: Any,
    report_text: str,
    report_bytes: bytes,
    markers: tuple[str, ...],
    closed_text: str = "",
) -> None:
    """Register one injected failure for the closing visibility sweep."""
    RECORDS.append(FailureRecord(slug, outcome, report_text, report_bytes, tuple(markers), closed_text))


def defect_marker(*labels: str) -> str:
    """Unique marker carried by every injected raise; never operator-visible."""
    return "defect-marker-" + "-".join(labels)


def population_labels() -> bytes:
    """Sealed label bytes of the shared e2e population."""
    return _population().labels


class BoomAdapter:
    """Any execution call fails the test: completed arms must never rerun."""

    def __init__(self, message: str) -> None:
        self._message = message

    def execute(self, bundle: object) -> object:
        raise AssertionError(self._message)


class CountingCrashLoader:
    """Crash exactly between the committed custody CAS and the first label byte."""

    def __init__(self, payload: bytes, marker: str) -> None:
        self.payload = payload
        self.marker = marker
        self.reads = 0

    def __call__(self) -> bytes:
        self.reads += 1
        raise RuntimeError(self.marker)


class OutcomeRefusingClient:
    """Delegate store operations but refuse durable workflow-outcome writes."""

    def __init__(self, inner: _Client) -> None:
        self._inner = inner

    def put_object(self, **kwargs: object) -> dict[str, object]:
        if str(kwargs["Key"]).startswith("workflows/"):
            raise RuntimeError(defect_marker("publication", "outcome-refused"))
        return self._inner.put_object(**kwargs)

    def get_object(self, **kwargs: object) -> dict[str, object]:
        return self._inner.get_object(**kwargs)


class RaceWorkflowClient(_Client):
    """Swap the journal head through a rival lease exactly at the next entry write."""

    def __init__(self, workflow: str) -> None:
        super().__init__()
        self._workflow = workflow
        self._armed = False
        self._rival = None

    def arm(self, rival: Any) -> None:
        self._armed = True
        self._rival = rival

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = str(kwargs["Key"])
        if self._armed and kwargs.get("IfNoneMatch") == "*" and key.startswith(f"workflow/{self._workflow}/entries/"):
            self._armed = False
            assert self._rival is not None
            self._rival()
        return super().put_object(**kwargs)


def racing_environment() -> E2EEnvironment:
    """E2E environment whose transient journal store can race the head."""
    environment = E2EEnvironment()
    environment.transient = RaceWorkflowClient(WORKFLOW)
    environment.journal = S3WorkflowJournal(_settings(StorePurpose.TRANSIENT), environment.transient)
    return environment


def _last_execution(environment: E2EEnvironment) -> Any:
    assert environment.last_execution is not None
    return environment.last_execution


def adapter_request(environment: E2EEnvironment, product: Any) -> AdmissionCaseAdapterRequestV1:
    """The 11.3 case-adapter request bound to one execution product."""
    case = environment.case
    return AdmissionCaseAdapterRequestV1(
        repository=environment.repository,
        custodian_access_policy_digest=ACCESS_POLICY,
        execution=product,
        plan=case.plan,
        selection=case.selection,
        population_digest=case.freeze.population_digest,
        input_count=len(case.manifest.input_digests),
        custody=environment.custody,
        resolver=case.evidence_resolver,
        context=case.context,
        readiness=case.readiness,
        case_content=case.content.port,
        proof_candidates=case.content.candidate_port,
        census_review=case.adapter_census_review,
        plan_review=case.adapter_plan_review,
        admission_review=lambda subject: _attestation(subject, _digest("e2e-adapter-admission-producer"), case.disclosure),
        release_review=lambda subject: _attestation(subject, _digest("e2e-adapter-release-producer"), case.disclosure),
        bridged_store_identity="scoped-admission-v3-bridge",
        bridged_retention_policy_digest=BRIDGE_RETENTION,
    )


def resume_request(
    environment: E2EEnvironment,
    *,
    selectors: tuple,
    attempt_id: str = "attempt-2",
    lease_owner_id: str = "owner-b",
    heartbeat_at: str = RESUME_HEARTBEAT,
    lease_expires_at: str = RESUME_LEASE_EXPIRES,
    now: str = RESUME_HEARTBEAT,
) -> run.BenchmarkResumeRequestV1:
    """The 8.6 resume authorities resolved from the current CAS head."""
    authority = resolve_head_selected_retry_authority(environment.journal, environment.repository, ACCESS_POLICY, WORKFLOW)
    return run.BenchmarkResumeRequestV1(
        workflow_digest=WORKFLOW,
        admission_identity_digest=authority.admission_identity_digest,
        component_index=0,
        bundles=environment.case.bundles,
        checkpoint_selectors=selectors,
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
        attempt_id=attempt_id,
        lease_owner_id=lease_owner_id,
        heartbeat_at=heartbeat_at,
        lease_expires_at=lease_expires_at,
        now=now,
        runtime_ms=0,
    )


def injecting_adapter_factory(environment: E2EEnvironment, defect: ExecutionDefect, target_arm: str) -> Any:
    """Wrap the e2e factory so one component arm reports the injected defect."""
    base = environment._factory()

    def factory(bundle: Any) -> Any:
        if bundle.arm.arm_id != target_arm:
            return base(bundle)
        return _defective_capture(bundle, defect, base)

    return factory


def _defective_capture(bundle: Any, defect: ExecutionDefect, base: Any) -> Any:
    if defect is ExecutionDefect.ADAPTER_CRASH:
        raise RuntimeError(defect_marker(defect.value, "adapter"))
    capture = base(bundle)
    reads, stages = capture.input_reads, capture.stage_executions
    outcome, observations = capture.process_outcome, capture.observations
    if defect is ExecutionDefect.INPUT_UNREADABLE:
        reads = _read_rows(bundle, status=InputReadStatus.UNREADABLE)
    elif defect is ExecutionDefect.INPUT_EMPTY:
        reads = _read_rows(bundle, status=InputReadStatus.EMPTY)
    elif defect is ExecutionDefect.STAGE_SKIPPED:
        stages = _stage_rows(status=StageExecutionStatus.SKIPPED)
    elif defect is ExecutionDefect.STAGE_PREMATURE:
        stages = _stage_rows(status=StageExecutionStatus.PREMATURE)
    elif defect is ExecutionDefect.MISSING_ARM:
        observations = ()
    elif defect is ExecutionDefect.DEADLINE_OVERRUN:
        outcome = execution.completed_adapter_outcome(
            bundle,
            checkpoint.component_observation_output_bytes(capture.observations),
            runtime_ms=bundle.budget.deadline_seconds * 1000 + 1,
        )
    elif defect in (ExecutionDefect.BUDGET_EXHAUSTED, ExecutionDefect.RESOURCE_LIMIT):
        reason = (
            ProcessOutcomeReason.BUDGET_EXHAUSTED if defect is ExecutionDefect.BUDGET_EXHAUSTED else ProcessOutcomeReason.RESOURCE_LIMIT
        )
        outcome = execution.impaired_adapter_outcome(bundle, reason, runtime_ms=9)
    return checkpoint.ArmExecutionCaptureV1(outcome, reads, stages, capture.degradations, observations)


def _publication_request(environment: E2EEnvironment, replay_value: Any) -> ReplayPublicationRequestV1:
    declaration = replay_value.plan_manifest.declaration
    return ReplayPublicationRequestV1(
        repository=environment.repository,
        replay=replay_value,
        planned_arm_ids=PLANNED_ARMS,
        planned_input_count=len({slot.input_identity_digest for slot in declaration.expected_observation_slots}),
        population_digest=declaration.population_digest,
        freeze_digest=declaration.freeze_digest,
        plan_digest=replay_value.plan_manifest.manifest_digest,
        workflow_digest=WORKFLOW,
        runtime_ms=321,
    )


class FailureRun:
    """One operator run over the e2e population with injectable failures."""

    def __init__(
        self,
        slug: str,
        *,
        environment: E2EEnvironment | None = None,
        defect: ExecutionDefect | None = None,
        target_arm: str = TARGET_ARM,
        loader: Any = None,
        markers: tuple[str, ...] = (),
        crash_before_spend: bool = False,
        scoring_crash: bool = False,
        publication_crash: bool = False,
    ) -> None:
        self.slug = slug
        self.environment = environment if environment is not None else E2EEnvironment()
        self.case = self.environment.case
        self.defect = defect
        if defect is not None:
            self.environment.adapter = _Adapter(injecting_adapter_factory(self.environment, defect, target_arm))
            self.review = None
        else:
            self.review = _admission_review(self.case)
        self.loader = (
            loader if loader is not None else _LabelSource(self.case.labels, self.environment.store, self.case.freeze.population_digest)
        )
        self.extra_markers = markers
        self.crash_before_spend = crash_before_spend
        self.after_execution = None
        self.before_cas = None
        self.scoring_crash = scoring_crash
        self.publication_crash = publication_crash
        self.result = None
        self.replay = None
        self.publication = None

    def execute(self) -> FailureRun:
        counts = WorkflowCounts(
            len(self.case.plan.registrations), 0, len(self.case.manifest.input_digests), 0, len(self.case.manifest.input_digests)
        )
        self.result = run.benchmark_run_command(
            _operator_context(self.environment),
            run.BenchmarkRunRequestV1(self.case.run_request(), self._stages(), counts, 250),
        )
        record_failure(
            self.slug,
            self.result.outcome,
            self.result.report_text,
            self.result.report_bytes,
            self._markers(),
        )
        return self

    def _markers(self) -> tuple[str, ...]:
        markers = list(self.extra_markers)
        if self.crash_before_spend:
            markers.append(defect_marker(self.slug, "pre-spend"))
        if self.before_cas is not None:
            markers.append(defect_marker(self.slug, "cas-lost"))
        if self.scoring_crash:
            markers.append(defect_marker(self.slug, "scoring"))
        if self.publication_crash:
            markers.append(defect_marker(self.slug, "publication"))
        return tuple(markers)

    def _stages(self) -> run.BenchmarkRunStagesV1:
        return run.BenchmarkRunStagesV1(
            self._execution_stage,
            self._spend_stage,
            self._replay_stage,
            self._publication_stage,
        )

    def _execution_stage(self, preflight: Any) -> Any:
        environment, case = self.environment, self.case
        product = environment.execute(
            preflight,
            review=self.review,
            attempt_review=_attempt_review(case, preflight),
            status_ref=case.status_ref,
        )
        if self.after_execution is not None:
            self.after_execution()
        return product

    def _spend_stage(self, execution_product: Any) -> Any:
        if self.crash_before_spend:
            raise RuntimeError(defect_marker(self.slug, "pre-spend"))
        environment, case = self.environment, self.case
        preparation = derive_case_adapter_preparation(adapter_request(environment, _last_execution(environment)))
        prior = environment.store.current_log(case.freeze.population_digest)
        receipt = record_population_use(preparation.label_release_request, prior, E2E_CUSTODIAN, environment.custody_policy)
        successor = append_population_use(prior, receipt, environment.custody_policy)
        if self.before_cas is not None:
            self.before_cas()
        if not environment.store.compare_and_swap(prior.log_digest, successor):
            raise RuntimeError(defect_marker(self.slug, "cas-lost"))
        return self._release_after_spend(execution_product, receipt)

    def _release_after_spend(self, execution_product: Any, receipt: Any) -> Any:
        environment, case = self.environment, self.case
        head = environment.store.current_log(receipt.population_digest)
        assert head.status is PopulationStatus.SPENT and head.receipts[-1] == receipt
        raw = self.loader()
        labels = decode_sealed_labels(raw)
        released = join_released_cases(
            execution_product,
            environment.repository,
            ACCESS_POLICY,
            labels,
            case.freeze.positive_change_digests,
            _scope_census(case.freeze),
        )
        manifest = execution_product.admission_manifest
        assert manifest is not None
        subject = release_review_subject(manifest.manifest_digest, receipt.receipt_digest, released, raw)
        value = {
            "admission_manifest_digest": manifest.manifest_digest,
            "custody_receipt_digest": receipt.receipt_digest,
            "label_bytes_digest": canonical.bytes_digest(raw),
            "label_bytes_read": len(raw),
            "case_digests": tuple(row.case_digest for row in released),
        }
        content = canonical_artifact_bytes(
            ArtifactKind.WORKFLOW, dict(value), access_class=ArtifactAccessClass.CUSTODIAN_SEALED, provenance_digest=subject
        )
        reference = artifact_reference(content)
        environment.repository.put_if_absent(content, reference=reference)
        return AdmissionSpendReleaseV1(
            None,
            receipt.receipt_digest,
            True,
            len(raw),
            canonical.bytes_digest(raw),
            released,
            reference,
            canonical.content_digest(value),
        )

    def _replay_stage(self, release: Any) -> Any:
        if self.scoring_crash:
            raise RuntimeError(defect_marker(self.slug, "scoring"))
        self.replay = derive_case_adapter_replay(adapter_request(self.environment, _last_execution(self.environment)), release)
        return self.replay

    def _publication_stage(self, replay_value: Any) -> Any:
        if self.publication_crash:
            raise RuntimeError(defect_marker(self.slug, "publication"))
        self.publication = publish_scoped_replay(_publication_request(self.environment, replay_value))
        return self.publication
