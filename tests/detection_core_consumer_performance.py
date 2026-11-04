"""Complete consumer measurements used by the detection-core load contract."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from detection_core_fixtures import (
    InMemoryContentResolver,
    InMemoryPopulationCustody,
    custody_contract,
    stored_artifact,
)
from detection_core_performance_reporting import nanoseconds_to_milliseconds
from test_core_consumer_v2 import _proof
from test_core_validation_v2 import _catalog, _model_validation_case, _review_policy, _trust_policy, _with_fact_set

from openultrasast.core import budget, canonical, family, provenance, validation
from openultrasast.core.consumer import PushRequest, consume_records, make_push_request
from openultrasast.core.proof import ProofAttachment, ProofTrustPolicy
from openultrasast.core.validation import EvidenceValidationContext, EvidenceValidationInput

if TYPE_CHECKING:
    from detection_core_performance import Workload

    from openultrasast.core.evidence import EvidenceRecord


@dataclass(frozen=True)
class PreparedConsumer:
    value: EvidenceValidationInput
    context: EvidenceValidationContext
    custody: provenance.PopulationCustodyPort
    resolver: InMemoryContentResolver
    request: PushRequest
    attachments: tuple[ProofAttachment, ...]
    trust: ProofTrustPolicy | None


@dataclass(frozen=True)
class CompleteRun:
    mode: str
    size: int
    measured: budget.MeasuredSample
    resolver: InMemoryContentResolver


def merge_resolvers(values: tuple[InMemoryContentResolver, ...]) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for value in values:
        artifacts.update(value.artifacts)
    return InMemoryContentResolver(artifacts)


def measurement(changed_bytes: int, artifact_id: str) -> tuple[bytes, canonical.ContentRef, InMemoryContentResolver]:
    content = canonical.canonical_bytes({"schema_version": budget.CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": changed_bytes})
    reference, resolver = stored_artifact(content, artifact_id=artifact_id)
    if not content or reference.byte_length != len(content):
        raise AssertionError("changed-byte measurement input was not opened")
    return content, reference, resolver


def _named_inputs(
    record: EvidenceRecord,
    contract: family.FamilyContract,
    change: bytes,
) -> tuple[provenance.NamedInputs, InMemoryContentResolver]:
    stamp = record.packet.provenance
    contents = {
        provenance.ProvenanceInputRole.ANALYZER: canonical.canonical_bytes("analyzer"),
        provenance.ProvenanceInputRole.FAMILY_CONTRACT: canonical.canonical_bytes(family._contract_value(contract)),
        provenance.ProvenanceInputRole.FACT_SET: validation.fact_set_bytes(()),
        provenance.ProvenanceInputRole.ACQUISITION: canonical.canonical_bytes("acquisition"),
        provenance.ProvenanceInputRole.CONFIGURATION: canonical.canonical_bytes("configuration"),
        provenance.ProvenanceInputRole.POPULATION: canonical.canonical_bytes("population"),
        provenance.ProvenanceInputRole.CHANGE_INPUT: change,
    }
    digests = {
        provenance.ProvenanceInputRole.ANALYZER: stamp.analyzer_revision,
        provenance.ProvenanceInputRole.FAMILY_CONTRACT: stamp.family_contract_digest,
        provenance.ProvenanceInputRole.FACT_SET: stamp.fact_set_digest,
        provenance.ProvenanceInputRole.ACQUISITION: stamp.acquisition_record_digest,
        provenance.ProvenanceInputRole.CONFIGURATION: stamp.configuration_digest,
        provenance.ProvenanceInputRole.POPULATION: stamp.population_digest,
        provenance.ProvenanceInputRole.CHANGE_INPUT: stamp.change_input_digest,
    }
    items: list[provenance.NamedInput] = []
    resolvers: list[InMemoryContentResolver] = []
    for role in provenance.ProvenanceInputRole:
        reference, resolver = stored_artifact(contents[role], artifact_id=f"performance-{role.value}-{stamp.change_input_digest}")
        if reference.content_digest != digests[role] or reference.byte_length <= 0:
            raise AssertionError(f"performance input {role.value} did not bind its exact bytes")
        items.append(provenance.NamedInput(role, digests[role], reference))
        resolvers.append(resolver)
    selected = tuple(items)
    named = provenance.NamedInputs(selected, provenance.derive_named_inputs_digest(selected))
    return named, merge_resolvers(tuple(resolvers))


def deterministic_prepared(
    workload: Workload,
    size: int,
    derivation: budget.BudgetDerivation,
) -> PreparedConsumer:
    from detection_core_performance import _record

    contract, raw, change = _record(workload, size)
    record = _with_fact_set(raw, ())
    named, named_resolver = _named_inputs(record, contract, change)
    initial, custody_policy, _ = custody_contract()
    context = validation.make_evidence_validation_context(
        family_catalog=_catalog(contract),
        fact_packs=(),
        model_programs=(),
        lineages=(),
        fact_review_policy=_review_policy(),
        provenance_trust_policy=_trust_policy(),
        custody_policy=custody_policy,
    )
    measured, reference, measure_resolver = measurement(len(change), f"consumer-changed-bytes-{size}")
    if measured != canonical.canonical_bytes({"schema_version": budget.CHANGED_BYTES_MEASUREMENT_SCHEMA, "changed_bytes": len(change)}):
        raise AssertionError("changed-byte measurement serialization is unstable")
    complexity = budget.ChangeComplexity(
        record.packet.scope.change_digest,
        workload.workload_class,
        len(record.packet.scope.regions),
        len(record.packet.transitions),
        len(change),
        reference,
    )
    request = make_push_request(
        scope=record.packet.scope,
        workload_class=workload.workload_class,
        complexity=complexity,
        budget=derivation,
    )
    value = validation.make_evidence_validation_input(record=record, named_inputs=named)
    resolver = merge_resolvers((named_resolver, measure_resolver))
    custody = InMemoryPopulationCustody(initial, custody_policy)
    return PreparedConsumer(value, context, custody, resolver, request, (), None)


def optional_prepared(
    workload: Workload,
    derivation: budget.BudgetDerivation,
    artifact_id: str,
) -> PreparedConsumer:
    value, context, custody, resolver, _ = _model_validation_case()
    attachment, trust, proof_resolver = _proof(value.record)
    selected = next(item for item in value.named_inputs.inputs if item.role is provenance.ProvenanceInputRole.CHANGE_INPUT)
    change = resolver.resolve(selected.content).content
    if (
        not change
        or canonical.bytes_digest(change) != selected.content.content_digest
        or selected.content.content_digest != value.record.packet.provenance.change_input_digest
    ):
        raise AssertionError("optional consumer did not open its exact change input")
    _, reference, measure_resolver = measurement(len(change), artifact_id)
    complexity = budget.ChangeComplexity(
        value.record.packet.scope.change_digest,
        workload.workload_class,
        len(value.record.packet.scope.regions),
        len(value.record.packet.transitions),
        len(change),
        reference,
    )
    request = make_push_request(
        scope=value.record.packet.scope,
        workload_class=workload.workload_class,
        complexity=complexity,
        budget=derivation,
    )
    combined = merge_resolvers((resolver, proof_resolver, measure_resolver))
    return PreparedConsumer(value, context, custody, combined, request, (attachment,), trust)


def measure_complete(
    setup: Callable[[], PreparedConsumer],
    mode: str,
    size: int,
) -> CompleteRun:
    started = time.monotonic_ns()
    prepared = setup()
    preparation_ms = nanoseconds_to_milliseconds(max(1, time.monotonic_ns() - started))
    verdict = consume_records(
        prepared.request,
        (prepared.value,),
        prepared.context,
        prepared.custody,
        preparation_ms,
        prepared.resolver,
        attachments=prepared.attachments,
        proof_trust=prepared.trust,
    )
    wall_ms = nanoseconds_to_milliseconds(max(1, time.monotonic_ns() - started))
    elapsed = max(wall_ms, verdict.total_reply_ms)
    sample = budget.MeasuredSample(prepared.request.complexity, elapsed)
    return CompleteRun(mode, size, sample, prepared.resolver)


__all__ = [
    "CompleteRun",
    "PreparedConsumer",
    "deterministic_prepared",
    "measure_complete",
    "measurement",
    "merge_resolvers",
    "optional_prepared",
]
