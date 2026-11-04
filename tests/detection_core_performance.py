"""Test-owned measured workload composition over production detection-core validators."""

from __future__ import annotations

import gc
import json
import time
import tracemalloc
from dataclasses import dataclass, replace
from functools import lru_cache, partial
from pathlib import Path

import detection_core_performance_reporting as reporting
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from detection_core_scaling import _integer_median
from detection_core_work import ValidationWork, count_validation_work
from test_core_admission_metrics import _setup as admission_setup
from test_core_family import _contract as family_contract
from test_core_family import _stamp as family_stamp
from test_core_readiness import _chain as readiness_chain

from openultrasast.core import admission_case, budget, canonical, evidence, family, readiness, semantics
from openultrasast.core.consumer import PushRequest
from openultrasast.core.proof import ProofAttachment, ProofTrustPolicy
from openultrasast.core.provenance import DecisionProvenance, PopulationCustodyPort
from openultrasast.core.validation import EvidenceValidationContext, EvidenceValidationInput

PERFORMANCE_FIXTURE = Path(__file__).parent / "fixtures/detection_core/performance_workload.json"
_SCHEMA = "detection-core-performance-workload-v1"


@dataclass(frozen=True)
class Workload:
    workload_class: str
    sizes: tuple[int, ...]
    repeats: int
    percentile: float
    changed_regions: int
    changed_bytes: int
    bytes_read: int
    content_digest: str


@dataclass(frozen=True)
class PerformancePoint:
    relation_count: int
    observation_count: int
    receipt_count: int
    case_count: int
    work: ValidationWork
    elapsed_ns: int
    elapsed_samples_ns: tuple[int, ...]
    peak_bytes: int
    peak_samples_bytes: tuple[int, ...]
    serialized_bytes: int
    change_digest: str
    changed_bytes: int
    changed_bytes_measurement: bytes
    change_content: bytes

    @property
    def elapsed_ms(self) -> int:
        return reporting.nanoseconds_to_milliseconds(self.elapsed_ns)


@dataclass(frozen=True)
class ConsumerMeasurement:
    mode: str
    size: int
    measured: budget.MeasuredSample

    @property
    def total_reply_ms(self) -> int:
        return self.measured.total_reply_ms


@dataclass(frozen=True)
class PerformanceProfile:
    workload: Workload
    points: tuple[PerformancePoint, ...]
    consumer_samples: tuple[ConsumerMeasurement, ...]
    samples: tuple[budget.MeasuredSample, ...]
    reference_workload: budget.ReferenceWorkload
    reference_hardware: budget.ReferenceHardware
    budget: budget.BudgetDerivation
    resolver: InMemoryContentResolver
    sample_bytes: int


@dataclass(frozen=True)
class OptionalConsumerCase:
    value: EvidenceValidationInput
    context: EvidenceValidationContext
    custody: PopulationCustodyPort
    resolver: InMemoryContentResolver
    request: PushRequest
    attachment: ProofAttachment
    trust: ProofTrustPolicy


def _strict_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("performance workload must be an object")
    return value


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def read_workload(path: Path) -> Workload:
    content = path.read_bytes()
    if not content:
        raise ValueError("performance workload input is empty")
    raw = _strict_object(json.loads(content))
    expected = {"schema_version", "workload_class", "sizes", "repeats", "percentile", "changed_regions", "changed_bytes"}
    if set(raw) != expected or raw["schema_version"] != _SCHEMA:
        raise ValueError("performance workload schema is not the reviewed closed schema")
    sizes_raw = raw["sizes"]
    if not isinstance(sizes_raw, list):
        raise ValueError("performance workload sizes must be a list")
    sizes = tuple(_positive_int(item, "workload size") for item in sizes_raw)
    if len(sizes) < 3 or tuple(sorted(set(sizes))) != sizes:
        raise ValueError("performance workload sizes must be unique and increasing")
    workload_class = raw["workload_class"]
    percentile = raw["percentile"]
    if not isinstance(workload_class, str) or not workload_class:
        raise ValueError("workload class must be nonempty")
    if isinstance(percentile, bool) or not isinstance(percentile, (int, float)) or not 0 < percentile <= 1:
        raise ValueError("percentile must be in (0, 1]")
    return Workload(
        workload_class,
        sizes,
        _positive_int(raw["repeats"], "repeats"),
        float(percentile),
        _positive_int(raw["changed_regions"], "changed regions"),
        _positive_int(raw["changed_bytes"], "changed bytes"),
        len(content),
        canonical.bytes_digest(content),
    )


def _location(line: int) -> semantics.SourceLocation:
    return semantics.SourceLocation("src/app.py", line, 0, "handle")


def _provenance() -> semantics.EvidenceProvenance:
    return semantics.EvidenceProvenance(
        semantics.ProvenanceKind.PRODUCT_CODE,
        canonical.content_digest("performance-source"),
        None,
        None,
        None,
    )


def _relation(index: int) -> semantics.SemanticRelation:
    line = index * 2 + 2
    return semantics.make_relation(
        kind=semantics.RelationKind.CONSTRAINT_EFFECT,
        role="constraint",
        source=semantics.SemanticNode(f"operation-{index}", "operation", _location(line)),
        target=semantics.SemanticNode(f"policy-{index}", "policy", _location(line + 1)),
        location=_location(line),
        status=semantics.RelationStatus.COMPLETE,
        conditions=(f"policy-{index}",),
        reasons=(),
        provenance=_provenance(),
    )


def _observation(index: int) -> semantics.Observation:
    return semantics.make_observation(
        role="security_object",
        location=_location(index * 2 + 2),
        fields=(semantics.FieldValue("resource", semantics.FieldKind.TEXT, f"document-{index}"),),
        status=semantics.RelationStatus.COMPLETE,
        provenance=_provenance(),
    )


def _change_content(workload: Workload, size: int) -> bytes:
    return canonical.canonical_bytes(
        {"workload_input_digest": workload.content_digest, "size": size, "source": "x" * (workload.changed_bytes + size)}
    )


def _record(workload: Workload, size: int) -> tuple[family.FamilyContract, evidence.EvidenceRecord, bytes]:
    contract = family_contract()
    content = _change_content(workload, size)
    change_digest = canonical.bytes_digest(content)
    fields = (semantics.FieldValue("operation", semantics.FieldKind.TEXT, "read"),)
    scope = evidence.AnalyzedScope(
        "base",
        "head",
        change_digest,
        (evidence.SourceRegion("src/app.py", 1, size * 2 + 4),),
    )
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        family.family_contract_digest(contract),
        family.derive_security_object_id(contract.security_object, fields),
        "python",
        scope,
        tuple(_relation(index) for index in range(size)),
        tuple(_observation(index) for index in range(size)),
        fields,
        (),
        replace(family_stamp(contract), change_input_digest=change_digest),
    )
    decision = evidence.Decision(
        "blocked",
        evidence.NeutralOutcome.VIOLATION,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        (),
        evidence.derive_packet_digest(packet),
        DecisionProvenance(None, None, None, None, None, None),
    )
    return contract, evidence.EvidenceRecord(packet, decision, ""), content


def _validate_work(
    record: evidence.EvidenceRecord,
    contract: family.FamilyContract,
    size: int,
    receipts: tuple[readiness.ReadinessResult, ...],
    cases: tuple[admission_case.AdmissionCaseResult, ...],
) -> int:
    content = evidence.evidence_record_bytes(record)
    family.validate_record(contract, record)
    for index in range(size):
        readiness.validate_readiness_result(receipts[index % len(receipts)])
    for index in range(size):
        admission_case.validate_admission_case_shape(cases[index % len(cases)])
    return len(content)


def _measure_point(
    workload: Workload,
    size: int,
    receipts: tuple[readiness.ReadinessResult, ...],
    cases: tuple[admission_case.AdmissionCaseResult, ...],
) -> PerformancePoint:
    contract, record, content = _record(workload, size)
    elapsed: list[int] = []
    peaks: list[int] = []
    _validate_work(record, contract, size, receipts, cases)
    for _ in range(workload.repeats):
        started = time.perf_counter_ns()
        _validate_work(record, contract, size, receipts, cases)
        elapsed.append(max(1, time.perf_counter_ns() - started))
    tracemalloc.start()
    _validate_work(record, contract, size, receipts, cases)
    tracemalloc.stop()
    for _ in range(workload.repeats):
        gc.collect()
        tracemalloc.start()
        _validate_work(record, contract, size, receipts, cases)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
    serialized, work = count_validation_work(lambda: _validate_work(record, contract, size, receipts, cases))
    measurement, _, _ = reporting.measurement(size, len(content))
    return PerformancePoint(
        size,
        size,
        size,
        size,
        work,
        _integer_median(tuple(elapsed)),
        tuple(elapsed),
        _integer_median(tuple(peaks)),
        tuple(peaks),
        serialized,
        record.packet.scope.change_digest,
        len(content),
        measurement,
        content,
    )


@lru_cache(maxsize=1)
def measured_profile(workload: Workload) -> PerformanceProfile:
    import detection_core_consumer_performance as consumer_performance

    cases = admission_setup().cases
    receipts = readiness_chain()
    points = tuple(_measure_point(workload, size, receipts, cases) for size in workload.sizes)
    hardware = reporting.hardware()
    seed = reporting.seed_budget(workload, points, hardware)
    complete = []
    for point in points:
        for _ in range(workload.repeats):
            setup = partial(consumer_performance.deterministic_prepared, workload, point.relation_count, seed)
            complete.append(consumer_performance.measure_complete(setup, "deterministic", point.relation_count))
    for repeat in range(workload.repeats):
        setup = partial(consumer_performance.optional_prepared, workload, seed, f"optional-measurement-{repeat}")
        complete.append(consumer_performance.measure_complete(setup, "model_and_proof", 1))
    consumers = tuple(ConsumerMeasurement(item.mode, item.size, item.measured) for item in complete)
    report = reporting.sample_report(workload, points, consumers)
    report_ref, report_resolver = stored_artifact(report, artifact_id="performance-complete-samples")
    changed = tuple(item.measured.complexity.changed_bytes for item in complete)
    reference = reporting.reference(workload, report_ref, (min(changed), max(changed)))
    samples = tuple(item.measured for item in complete)
    derived = budget.derive_budget(samples, workload.workload_class, workload.percentile, reference, hardware)
    return PerformanceProfile(
        workload,
        points,
        consumers,
        samples,
        reference,
        hardware,
        derived,
        consumer_performance.merge_resolvers((report_resolver, *(item.resolver for item in complete))),
        len(report),
    )


def assert_large_set_envelope(profile: PerformanceProfile) -> None:
    from detection_core_scaling import assert_incremental_envelope

    assert_incremental_envelope(profile.points)


def reject_invalid_large_set(workload: Workload, size: int) -> None:
    contract, record, _ = _record(workload, size)
    invalid = replace(record.packet.transitions[-1], role="undeclared-role", relation_id="")
    packet = replace(record.packet, transitions=(*record.packet.transitions[:-1], invalid))
    decision = replace(record.decision, packet_digest=evidence.derive_packet_digest(packet))
    candidate = evidence.EvidenceRecord(packet, decision, "")
    try:
        family.validate_record(contract, candidate)
    except family.FamilyContractError:
        return
    raise AssertionError("large invalid semantic set was accepted")


def optional_consumer_case(profile: PerformanceProfile) -> OptionalConsumerCase:
    from detection_core_consumer_performance import optional_prepared

    prepared = optional_prepared(profile.workload, profile.budget, "optional-final-measurement")
    return OptionalConsumerCase(
        prepared.value,
        prepared.context,
        prepared.custody,
        prepared.resolver,
        prepared.request,
        prepared.attachments[0],
        prepared.trust,
    )
