"""Task 11.5 scale fixtures, streaming harness, and bounded execution lane.

The scale population extends the committed 11.3 fixture machinery to forty
positives plus eight hundred ordinary pushes (four hundred per ecosystem,
twenty per positive). Case/object batches stream one batch at a time through
strict hostile-decode validation with per-batch nonzero read receipts; cold,
warm, and per-arm runtime receipts are retained as measurements rather than
asserted absolutes. The bounded execution lane refuses work beyond its
configured bound, and every truncated or unreadable stream reports an
impairment with a closed reason instead of a partial clean result.
"""

from __future__ import annotations

import io
import json
import math
import queue
import re
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import lru_cache
from itertools import islice
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_valid_benchmark_admission_spend import _scope_census  # noqa: E402
from test_valid_benchmark_end_to_end import _LabelSource  # noqa: E402
from test_valid_benchmark_orchestrator import (  # noqa: E402
    ACCESS_POLICY,
    _attestation,
    _digest,
    _SpyExecutor,
)
from test_valid_benchmark_run import _environ, _evidence  # noqa: E402
from valid_benchmark_e2e_fixtures import (  # noqa: E402
    BRIDGE_RETENTION,
    BRIDGE_STORE,
    E2E_CUSTODIAN,
    PLANNED_ARMS,
    WORKFLOW,
    E2EEnvironment,
    E2EPopulation,
    _attempt_review,
    _pushes,
)

from benchmarks.valid import run, store_configuration  # noqa: E402
from benchmarks.valid.admission_case_adapter import (  # noqa: E402
    derive_case_adapter_preparation,
    derive_case_adapter_replay,
)
from benchmarks.valid.admission_case_graph import AdmissionCaseAdapterRequestV1  # noqa: E402
from benchmarks.valid.admission_projection import ProjectionRequestV1, project_exact_scopes  # noqa: E402
from benchmarks.valid.admission_replay import ReplayPublicationRequestV1, publish_scoped_replay  # noqa: E402
from benchmarks.valid.admission_spend import (  # noqa: E402
    AdmissionSpendReleaseV1,
    decode_sealed_labels,
    join_released_cases,
    release_review_subject,
)
from benchmarks.valid.operator_report import operator_report_bytes  # noqa: E402
from benchmarks.valid.replacement_artifact_contract import (  # noqa: E402
    ArtifactAccessClass,
    ArtifactKind,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.workflow_outcome import (  # noqa: E402
    BenchmarkWorkflowOutcomeV1,
    WorkflowCounts,
    WorkflowGate,
    WorkflowPhase,
    WorkflowReasonCode,
    WorkflowStatus,
)
from openultrasast.core import canonical  # noqa: E402
from openultrasast.core.custody import (  # noqa: E402
    PopulationStatus,
    append_population_use,
    record_population_use,
)

SCALE_PAIRS_PYTHON = 10
SCALE_PAIRS_JAVASCRIPT = 10
SCALE_PUSHES_PER_ECOSYSTEM = 400
SCALE_REQUIRED_PER_POSITIVE = 2 * SCALE_PUSHES_PER_ECOSYSTEM
SCALE_POSITIVES = 2 * (SCALE_PAIRS_PYTHON + SCALE_PAIRS_JAVASCRIPT)
SCALE_ORDINARY = 2 * SCALE_PUSHES_PER_ECOSYSTEM
SCALE_INPUTS = SCALE_POSITIVES + SCALE_ORDINARY
# Execution-bound tier. The committed execution/sealing seam measured 7.4 s at
# 60 inputs and 615.6 s at 840 inputs (super-linear), so a second full-scale
# lifecycle would exceed twenty minutes on execution alone. Every positive
# (40) plus the ordinary pushes below flow through execution, the shared
# spend, the release join, the exact-scope projection, one validated core
# replay, publication, and reporting; the full 840-input population flows
# through freeze, manifest, policy, serialization, and streaming validation
# in the other tests of this suite. Declared for reviewer ratification.
EXECUTION_TIER_PUSHES_PER_ECOSYSTEM = 100
EXECUTION_TIER_INPUTS = SCALE_POSITIVES + 2 * EXECUTION_TIER_PUSHES_PER_ECOSYSTEM
CORE_REPLAY_DECLARATION = (
    f"representative-subset: every positive (40) plus {2 * EXECUTION_TIER_PUSHES_PER_ECOSYSTEM} ordinary "
    f"pushes ({EXECUTION_TIER_PUSHES_PER_ECOSYSTEM} per ecosystem, {EXECUTION_TIER_INPUTS} inputs) flow "
    "through execution, spend, release, exact-scope projection, one validated "
    "core replay, and reporting; the full 840-input population flows through "
    "freeze, manifest, policy, serialization, and streaming validation"
)
STREAM_OBJECT_SCHEMA = "openultrasast.valid-detection-benchmark.scale-stream-object.v1"
_ZERO = "0" * 64
_PROBE_KEY = "scale-validation/readability-probe"


@lru_cache(maxsize=1)
def scale_population() -> E2EPopulation:
    """The full scale population: forty positives and eight hundred pushes."""
    return E2EPopulation(pushes=_pushes(SCALE_PUSHES_PER_ECOSYSTEM))


def default_population_shape() -> tuple[int, int, int]:
    """Committed default fixture shape (positives, pushes, manifest inputs)."""
    population = E2EPopulation(mint_cases=False)
    return (
        population.freeze.positive_count,
        len(population.selection.pushes),
        len(population.manifest.input_digests),
    )


def component_arm_ids(population: E2EPopulation) -> tuple[str, ...]:
    """Arms that execute on an adapter lane (the combined arm is rule-derived)."""
    from openultrasast.core.evaluation_measurement import ArmKindV3  # noqa: E402

    return tuple(row.arm_id for row in population.plan.registrations if row.configuration.kind is ArmKindV3.COMPONENT)


def durable_bucket() -> str:
    return store_configuration.load_store_settings(store_configuration.StorePurpose.DURABLE, _environ()).bucket


def prove_store_nonzero(client: object, bucket: str) -> int:
    """Write and read back one real nonzero object before interpreting results."""
    payload = b"scale-validation-readability-probe"
    client.put_object(Bucket=bucket, Key=_PROBE_KEY, Body=payload, IfNoneMatch="*")
    response = client.get_object(Bucket=bucket, Key=_PROBE_KEY)
    body = response["Body"]
    assert isinstance(body, io.BytesIO)
    read_back = body.read()
    assert read_back == payload and len(read_back) > 0
    return len(read_back)


class StreamObjectError(ValueError):
    """Closed unreadable-object refusal; no caller content is echoed."""


def _reject_constant(name: str) -> None:
    raise StreamObjectError("nonfinite_json_constant")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise StreamObjectError("nonfinite_json_number")
    return value


def strict_decode(raw: bytes) -> dict:
    """Hostile-decode discipline over untrusted object bytes."""
    if type(raw) is not bytes or not raw:
        raise StreamObjectError("empty_stream_object")
    try:
        document = json.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float)
    except StreamObjectError:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError):
        raise StreamObjectError("undecodable_stream_object") from None
    if type(document) is not dict:
        raise StreamObjectError("non_object_stream_payload")
    return document


@dataclass(frozen=True)
class StreamObject:
    """One canonical nonzero stream object with its exact content digest."""

    index: int
    raw: bytes
    digest: str


def _object_for(index: int, payload: dict) -> StreamObject:
    raw = canonical.canonical_bytes(payload)
    return StreamObject(index, raw, canonical.bytes_digest(raw))


def probe_objects_factory(total_objects: int) -> Callable[[], Iterator[StreamObject]]:
    """Deterministic fixture-generated probe objects (no network access)."""

    def factory() -> Iterator[StreamObject]:
        return (
            _object_for(
                index,
                {
                    "schema_version": STREAM_OBJECT_SCHEMA,
                    "index": index,
                    "content": "scale-stream-object-" + ("payload-" * 64) + str(index),
                },
            )
            for index in range(total_objects)
        )

    return factory


def case_objects_factory(population: E2EPopulation, limit: int | None = None) -> Callable[[], Iterator[StreamObject]]:
    """Canonical label-blind case-input objects from the scale population."""

    def factory() -> Iterator[StreamObject]:
        rows = population.cases if limit is None else population.cases[:limit]
        return (
            _object_for(
                index,
                {
                    "schema_version": STREAM_OBJECT_SCHEMA,
                    "index": index,
                    "input_identity_digest": row.input_identity_digest,
                    "change_input_digest": row.change_input_digest,
                    "case_digest": row.case_digest,
                    "code_reference": {
                        "artifact_kind": row.code_reference.artifact_kind.value,
                        "content_digest": row.code_reference.content_digest,
                        "byte_length": row.code_reference.byte_length,
                        "provenance_digest": row.code_reference.provenance_digest,
                        "access_class": row.code_reference.access_class.value,
                    },
                },
            )
            for index, row in enumerate(rows)
        )

    return factory


class StreamFault(StrEnum):
    """Closed stream-impairment injection modes."""

    MISSING_BATCH = "missing_batch"
    SHORT_BATCH = "short_batch"
    UNREADABLE_OBJECT = "unreadable_object"


@dataclass(frozen=True)
class BatchReceipt:
    """Per-batch nonzero read evidence retained by the streaming run."""

    index: int
    object_count: int
    byte_count: int
    batch_digest: str
    nonzero: bool


@dataclass
class StreamRunReceipt:
    """Closed streaming result: receipts and runtimes, never a metric block."""

    status: WorkflowStatus
    reason_codes: tuple[WorkflowReasonCode, ...]
    declared_total: int
    consumed_objects: int
    batch_count: int
    byte_count: int
    chain_digest: str
    batch_receipts: tuple[BatchReceipt, ...]
    last_batch: BatchReceipt | None
    runtime_ms: int
    all_batches_nonzero: bool


def _batches(iterator: Iterator[StreamObject], size: int) -> Iterator[tuple[StreamObject, ...]]:
    while True:
        chunk = tuple(islice(iterator, size))
        if not chunk:
            return
        yield chunk


def _chain_step(chain: str, batch_digest: str) -> str:
    return canonical.bytes_digest((chain + batch_digest).encode("ascii"))


def _validate_batch(index: int, batch: tuple[StreamObject, ...], fault: StreamFault | None, anchor: int) -> BatchReceipt:
    byte_count = 0
    digests: list[str] = []
    for position, item in enumerate(batch):
        raw = item.raw
        if fault is StreamFault.UNREADABLE_OBJECT and index == anchor and position == 0:
            raw = b"\x00" + item.raw[1:]
        byte_count += len(raw)
        document = strict_decode(raw)
        if canonical.bytes_digest(raw) != item.digest:
            raise StreamObjectError("stream_object_digest_mismatch")
        if document.get("schema_version") != STREAM_OBJECT_SCHEMA:
            raise StreamObjectError("stream_object_schema_mismatch")
        digests.append(item.digest)
    digest = canonical.bytes_digest("".join(digests).encode("ascii"))
    return BatchReceipt(index, len(batch), byte_count, digest, byte_count > 0 and len(batch) > 0)


def run_streaming_validation(
    objects_factory: Callable[[], Iterator[StreamObject]],
    batch_size: int,
    declared_total: int,
    *,
    fault: StreamFault | None = None,
) -> StreamRunReceipt:
    """Stream one batch at a time; any truncation reports impairment, not a metric."""
    started = time.perf_counter()
    expected_batches = -(-declared_total // batch_size)
    anchor = expected_batches // 2
    iterator = objects_factory()
    if fault is StreamFault.MISSING_BATCH:
        iterator = islice(iterator, anchor * batch_size)
    receipts: list[BatchReceipt] = []
    reasons: list[WorkflowReasonCode] = []
    consumed = 0
    total_bytes = 0
    chain = _ZERO
    try:
        for index, batch in enumerate(_batches(iterator, batch_size)):
            if fault is StreamFault.SHORT_BATCH and index == anchor and len(batch) > 1:
                batch = batch[:-1]
                reasons.append(WorkflowReasonCode.INSTRUMENT_FAILURE)
            receipt = _validate_batch(index, batch, fault, anchor)
            receipts.append(receipt)
            consumed += receipt.object_count
            total_bytes += receipt.byte_count
            chain = _chain_step(chain, receipt.batch_digest)
    except StreamObjectError:
        reasons.append(WorkflowReasonCode.INSTRUMENT_FAILURE)
    if fault is StreamFault.MISSING_BATCH and consumed < declared_total:
        reasons.append(WorkflowReasonCode.INTERRUPTED)
    elif consumed != declared_total and not reasons:
        reasons.append(WorkflowReasonCode.INSTRUMENT_FAILURE)
    runtime_ms = int((time.perf_counter() - started) * 1000)
    status = WorkflowStatus.IMPAIRED if reasons or consumed != declared_total else WorkflowStatus.COMPLETED
    return StreamRunReceipt(
        status,
        tuple(dict.fromkeys(reasons)),
        declared_total,
        consumed,
        len(receipts),
        total_bytes,
        chain,
        tuple(receipts),
        receipts[-1] if receipts else None,
        runtime_ms,
        bool(receipts) and all(receipt.nonzero for receipt in receipts),
    )


@dataclass(frozen=True)
class ColdWarmReceipt:
    """Cold and warm runtime measurements with a registered monotonicity note."""

    cold_ms: int
    warm_ms: int
    registered_reason: str | None


def measure_cold_warm(operation: Callable[[], object]) -> tuple[object, ColdWarmReceipt]:
    started = time.perf_counter()
    value = operation()
    cold_ms = max(1, int((time.perf_counter() - started) * 1000))
    started = time.perf_counter()
    operation()
    warm_ms = max(1, int((time.perf_counter() - started) * 1000))
    reason = None if warm_ms <= cold_ms else "warm_slower_registered"
    return value, ColdWarmReceipt(cold_ms, warm_ms, reason)


class TimingAdapterProxy:
    """Wrap the committed execution adapter to retain per-arm runtime receipts."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.arm_runtimes: list[tuple[str, int]] = []

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)

    def execute(self, bundle: object):  # noqa: ANN201 - committed test seam type
        started = time.perf_counter()
        result = self._inner.execute(bundle)
        arm_id = getattr(getattr(bundle, "arm", None), "arm_id", "unknown-arm")
        self.arm_runtimes.append((arm_id, max(0, int((time.perf_counter() - started) * 1000))))
        return result


class LaneReason(StrEnum):
    """Closed execution-lane refusal reasons; never detector or infrastructure vocabulary."""

    BUSY = "execution_lane_busy"
    UNAVAILABLE = "execution_lane_unavailable"


class LaneRefusal(RuntimeError):
    """The bounded lane refused work; closed reason, no caller content."""

    def __init__(self, reason: LaneReason) -> None:
        self.reason = reason
        super().__init__(f"execution_lane_refusal_{reason.value}")


class BoundedExecutionLane:
    """Bounded execution lane honoring adapter back-pressure beyond its bound."""

    def __init__(self, maxsize: int = 2) -> None:
        if type(maxsize) is not int or maxsize < 1:
            raise ValueError("lane bound must be a positive integer")
        self.maxsize = maxsize
        self._pending: queue.Queue = queue.Queue(maxsize=maxsize)
        self._closed = False
        self.accepted_items = 0
        self.refused_items = 0
        self.drained_items = 0
        self.max_pending = 0

    def submit(self, item: object) -> None:
        if self._closed:
            self.refused_items += 1
            raise LaneRefusal(LaneReason.UNAVAILABLE) from None
        try:
            self._pending.put_nowait(item)
        except queue.Full:
            self.refused_items += 1
            raise LaneRefusal(LaneReason.BUSY) from None
        self.accepted_items += 1
        self.max_pending = max(self.max_pending, self._pending.qsize())

    def pending(self) -> int:
        return self._pending.qsize()

    def drain(self, count: int) -> int:
        drained = 0
        while drained < count:
            try:
                self._pending.get_nowait()
            except queue.Empty:
                break
            drained += 1
            self.drained_items += 1
        return drained

    def close(self) -> None:
        self._closed = True


@dataclass
class LaneRunRecord:
    """Back-pressure evidence: bounded pending, closed refusals, impairment."""

    accepted_batches: int
    refused_batches: int
    max_pending: int
    refusals: tuple[LaneRefusal, ...]
    receipt: StreamRunReceipt
    outcome: BenchmarkWorkflowOutcomeV1


def _lane_marker(batch: tuple[StreamObject, ...]) -> tuple[int, int, str]:
    digest = canonical.bytes_digest(b"".join(item.digest.encode("ascii") for item in batch))
    return (batch[0].index, len(batch), digest)


def stream_with_lane(
    objects_factory: Callable[[], Iterator[StreamObject]],
    batch_size: int,
    declared_total: int,
    lane: BoundedExecutionLane,
) -> LaneRunRecord:
    """Submit one batch at a time; a lane refusal stops the run as an impairment."""
    started = time.perf_counter()
    refusals: list[LaneRefusal] = []
    accepted = 0
    consumed = 0
    total_bytes = 0
    chain = _ZERO
    for batch in _batches(objects_factory(), batch_size):
        try:
            lane.submit(_lane_marker(batch))
        except LaneRefusal as refusal:
            refusals.append(refusal)
            break
        accepted += 1
        consumed += len(batch)
        total_bytes += sum(len(item.raw) for item in batch)
        chain = _chain_step(chain, _lane_marker(batch)[2])
    runtime_ms = int((time.perf_counter() - started) * 1000)
    impaired = bool(refusals) or consumed < declared_total
    receipt = StreamRunReceipt(
        WorkflowStatus.IMPAIRED if impaired else WorkflowStatus.COMPLETED,
        (WorkflowReasonCode.RESOURCE_EXHAUSTED,) if refusals else (() if not impaired else (WorkflowReasonCode.INTERRUPTED,)),
        declared_total,
        consumed,
        accepted,
        total_bytes,
        chain,
        (),
        None,
        runtime_ms,
        total_bytes > 0,
    )
    return LaneRunRecord(accepted, len(refusals), lane.max_pending, tuple(refusals), receipt, impaired_stream_outcome(receipt))


def impaired_stream_outcome(receipt: StreamRunReceipt) -> BenchmarkWorkflowOutcomeV1:
    """Bind an impaired streaming receipt to the closed workflow outcome."""
    counts = WorkflowCounts(len(PLANNED_ARMS), 0, max(1, receipt.declared_total), receipt.consumed_objects, 0)
    return BenchmarkWorkflowOutcomeV1(
        WorkflowStatus.IMPAIRED,
        WorkflowPhase.ARM_EXECUTION,
        receipt.reason_codes or (WorkflowReasonCode.INSTRUMENT_FAILURE,),
        _digest("scale-stream-population"),
        _digest("scale-stream-freeze"),
        _digest("scale-stream-plan"),
        _digest("scale-stream-workflow"),
        False,
        counts,
        (WorkflowGate.ARM_EXECUTION,),
        (),
        receipt.runtime_ms,
        "",
        "",
        None,
        "",
    )


def operator_report_for_outcome(outcome: BenchmarkWorkflowOutcomeV1) -> bytes:
    return operator_report_bytes(outcome, None)


def lane_refusal_texts(record: LaneRunRecord) -> tuple[str, ...]:
    return tuple(str(refusal) for refusal in record.refusals) + tuple(code.value for code in record.receipt.reason_codes)


_DETECTOR_VOCABULARY = (
    "finding",
    "findings",
    "alert",
    "alerts",
    "detector",
    "detection",
    "true_positive",
    "false_positive",
    "false_alarm",
    "precision",
    "recall",
    "vulnerability",
)
_INFRASTRUCTURE_VOCABULARY = (
    "cluster",
    "kubernetes",
    "k8s",
    "node",
    "nodes",
    "pod",
    "pods",
    "datacenter",
    "machine",
    "machines",
    "hostname",
    "dns",
)
_VOCABULARY_PATTERN = re.compile(
    "|".join(rf"\b{term}\b" for term in sorted(set(_DETECTOR_VOCABULARY + _INFRASTRUCTURE_VOCABULARY), reverse=True)),
    re.IGNORECASE,
)


_CLOSED_SCHEMA_NAMESPACES = ("valid-detection-benchmark", "detection-core")


def vocabulary_findings(text: str) -> tuple[str, ...]:
    """Detector or infrastructure diagnosis terms found in shared text.

    Closed schema namespaces (the benchmark's own product identifiers) are
    normalized away first: they name the contracts, never a detector result.
    """
    normalized = text
    for namespace in _CLOSED_SCHEMA_NAMESPACES:
        normalized = normalized.replace(namespace, "")
    return tuple(match.lower() for match in _VOCABULARY_PATTERN.findall(normalized))


_REDACTION_MARKERS = (
    b"/home/",
    b"/tmp/",
    b"SECRET",
    b"confidential-ground-truth-judgment",
    b"defect-present",
    b"AKIA",
    b"arn:aws",
    b"https://",
    b"http://",
    b"aws_secret_access_key",
)


def redaction_findings(raw: bytes) -> tuple[str, ...]:
    return tuple(marker.decode("ascii") for marker in _REDACTION_MARKERS if marker in raw)


def _execution_subject(environment: E2EEnvironment, case: E2EPopulation) -> str:
    """Harvest the admission-review subject for this population's execution."""
    preflight = environment.orchestrator.preflight(case.run_request())
    product = environment.execute(
        preflight,
        review=None,
        attempt_review=_attempt_review(case, preflight),
        status_ref=case.status_ref,
    )
    return product.manifest_subject_digest


class ScaleLifecycle:
    """One execution-tier lifecycle: timed arms, spend, release, projection, replay, reporting.

    A single committed run-command lifecycle over the execution-tier
    population: the preflight harvest mints the admission-review subject,
    the run stages execute every planned arm (per-arm runtime receipts are
    retained through the timing adapter proxy), commit the one shared spend,
    derive the exact-scope projection inputs, publish the one validated core
    replay, and render the deterministic redacted operator report.
    """

    def __init__(self) -> None:
        self.population = execution_tier_population()
        harvest = E2EEnvironment(self.population)
        subject = _execution_subject(harvest, self.population)
        self.environment = E2EEnvironment(self.population)
        self.case = self.population
        self.admission_review = _attestation(subject, _digest("scale-admission-producer"), self.population.disclosure)
        self.environment.adapter = TimingAdapterProxy(self.environment.adapter)
        self.loader = _LabelSource(self.case.labels, self.environment.store, self.case.freeze.population_digest)
        self.publication = None
        self.replay = None
        self.release = None
        self.context = self._operator_context()
        counts = WorkflowCounts(
            len(self.case.plan.registrations),
            0,
            len(self.case.manifest.input_digests),
            0,
            len(self.case.manifest.input_digests),
        )
        self.result = run.benchmark_run_command(
            self.context, run.BenchmarkRunRequestV1(self.case.run_request(), self._stages(), counts, 250)
        )
        self.execution = self.environment.last_execution
        self.arm_runtimes = tuple(self.environment.adapter.arm_runtimes)
        self.projection = self._projection()

    def _operator_context(self):
        return run.bound_operator_context(
            run.validated_operator_configuration(_environ(), _evidence()),
            self.environment.durable,
            self.environment.transient,
            self.environment.lifecycle(),
            self.environment.custody_policy,
            self.environment.case.report,
            self.environment.case.transient_identity,
            self.environment.case.transient_profile,
            _SpyExecutor(),
            ACCESS_POLICY,
        )

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
            admission_review=lambda subject: _attestation(subject, _digest("scale-adapter-admission"), case.disclosure),
            release_review=lambda subject: _attestation(subject, _digest("scale-adapter-release"), case.disclosure),
            bridged_store_identity=BRIDGE_STORE,
            bridged_retention_policy_digest=BRIDGE_RETENTION,
        )

    def _stages(self):
        case = self.case

        def _execution(preflight):
            return self.environment.execute(
                preflight,
                review=self.admission_review,
                attempt_review=_attempt_review(case, preflight),
                status_ref=case.status_ref,
            )

        def _spend(execution):
            preparation = derive_case_adapter_preparation(self._adapter_request(execution))
            prior = self.environment.store.current_log(case.freeze.population_digest)
            receipt = record_population_use(preparation.label_release_request, prior, E2E_CUSTODIAN, self.environment.custody_policy)
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
            content = canonical_artifact_bytes(
                ArtifactKind.WORKFLOW, dict(value), access_class=ArtifactAccessClass.CUSTODIAN_SEALED, provenance_digest=subject
            )
            reference = artifact_reference(content)
            self.environment.repository.put_if_absent(content, reference=reference)
            self.release = AdmissionSpendReleaseV1(
                None,
                receipt.receipt_digest,
                True,
                len(raw),
                canonical.bytes_digest(raw),
                released,
                reference,
                canonical.content_digest(value),
            )
            return self.release

        def _replay(release):
            self.replay = derive_case_adapter_replay(self._adapter_request(self.environment.last_execution), release)
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
                    workflow_digest=WORKFLOW,
                    runtime_ms=321,
                )
            )
            return self.publication

        return run.BenchmarkRunStagesV1(_execution, _spend, _replay, _publication)

    def _projection(self):
        assert self.release is not None
        rekeyed = replace(
            self.release,
            released_cases=tuple(
                replace(row, case_input_digest=row.underlying_push_digest, case_digest="") for row in self.release.released_cases
            ),
        )
        return project_exact_scopes(ProjectionRequestV1(release=rekeyed, execution=self.execution, selection=self.population.selection))

    def render_again(self) -> bytes:
        """Deterministic re-render through the committed status command."""
        request = run.BenchmarkStatusRequestV1(
            workflow_digest=WORKFLOW,
            now="2026-11-23T11:00:00Z",
            population_digest=self.case.freeze.population_digest,
            freeze_digest=self.case.freeze.freeze_digest,
            plan_digest=self.replay.plan_manifest.manifest_digest,
            outcome_reference=self.result.outcome_reference,
            replay=self.replay,
        )
        return run.benchmark_status_command(self.context, request).report_bytes


@lru_cache(maxsize=1)
def scale_lifecycle() -> ScaleLifecycle:
    return ScaleLifecycle()


@lru_cache(maxsize=1)
def execution_tier_population() -> E2EPopulation:
    """The execution-tier population the one lifecycle covers (see CORE_REPLAY_DECLARATION)."""
    return E2EPopulation(pushes=_pushes(EXECUTION_TIER_PUSHES_PER_ECOSYSTEM))


def replay_run() -> ScaleLifecycle:
    """Committed-convention alias: the one lifecycle carries the core replay pass."""
    return scale_lifecycle()
