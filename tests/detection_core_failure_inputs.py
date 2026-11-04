"""Mutated inputs that production detection-core validators must refuse."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from detection_core_end_to_end import _fixtures, _PreparedFamily
from test_core_admission_metrics import _setup

from benchmarks.valid import readiness_contract
from openultrasast.core import canonical, evidence, family, semantics
from openultrasast.core._admission_release import _validate_release_shape
from openultrasast.core.admission_case import (
    ADMISSION_CASE_RELEASE_SCHEMA,
    AdmissionCaseRelease,
    AdmissionCaseRole,
    ReleasedCaseBinding,
    derive_released_case_binding_digest,
)
from openultrasast.core.coverage import (
    CoverageFunnel,
    CoverageStage,
    RelationStatusCount,
    StageDiagnosis,
    StageExpectation,
    diagnose_first_zero,
)
from openultrasast.core.measurement import ScopeKey
from openultrasast.core.readiness import AnalysisIdentity, ReadinessResult, ReadinessStage
from openultrasast.core.semantics import RelationStatus


def _coverage_diagnosis(stage: ReadinessStage, record: evidence.EvidenceRecord) -> StageDiagnosis | None:
    if stage not in (ReadinessStage.RECOGNITION, ReadinessStage.CONSTRAINTS):
        return None
    transitions = record.packet.transitions if stage is ReadinessStage.CONSTRAINTS else ()
    statuses = tuple(RelationStatusCount(status, sum(item.status is status for item in transitions)) for status in RelationStatus)
    counts = (1, 1, 1, 0, 0, 0, 0, 0, 0) if stage is ReadinessStage.RECOGNITION else (1, 1, 1, 1, len(transitions), 1, 0, 0, 0)
    funnel = CoverageFunnel(*counts, statuses, ())
    expected = tuple(StageExpectation(item, item is not CoverageStage.INPUTS, True) for item in CoverageStage)
    return diagnose_first_zero(funnel, expected)


def _record_with_packet(record: evidence.EvidenceRecord, packet: evidence.EvidencePacket) -> evidence.EvidenceRecord:
    decision = replace(record.decision, packet_digest=evidence.derive_packet_digest(packet))
    return evidence.EvidenceRecord(packet, decision, "")


def _recognition_failure(prepared: _PreparedFamily) -> tuple[str, StageDiagnosis, str]:
    record = prepared.inputs[0].record
    packet = replace(record.packet, security_object_id=canonical.content_digest("unrecognized-object"))
    mutated = _record_with_packet(record, packet)
    try:
        family.validate_record(prepared.contract, mutated)
    except ValueError as exc:
        diagnosis = _coverage_diagnosis(ReadinessStage.RECOGNITION, mutated)
        assert diagnosis is not None
        return str(exc), diagnosis, "openultrasast.core.family.validate_record"
    raise AssertionError("missing recognition was accepted")


def _transition_failure(prepared: _PreparedFamily) -> tuple[str, None, str]:
    record = prepared.inputs[0].record
    relation = record.packet.transitions[0]
    incomplete = semantics.make_relation(
        kind=relation.kind,
        role=relation.role,
        source=relation.source,
        target=relation.target,
        location=relation.location,
        status=RelationStatus.INCOMPLETE,
        conditions=relation.conditions,
        reasons=("missing framework call relation",),
        provenance=relation.provenance,
    )
    packet = replace(
        record.packet,
        transitions=(incomplete, *record.packet.transitions[1:]),
        completeness_reasons=("missing framework call relation",),
    )
    try:
        _record_with_packet(record, packet)
    except ValueError as exc:
        return str(exc), None, "openultrasast.core.evidence.EvidenceRecord"
    raise AssertionError("incomplete transition was accepted")


def _constraint_failure(prepared: _PreparedFamily) -> tuple[str, StageDiagnosis, str]:
    record = prepared.inputs[0].record
    rule = next(item for item in prepared.contract.decisions if item.family_code == record.decision.family_code)
    missing_role = rule.required_roles[-1]
    packet = replace(
        record.packet,
        transitions=tuple(item for item in record.packet.transitions if item.role != missing_role),
        observations=tuple(item for item in record.packet.observations if item.role != missing_role),
    )
    mutated = _record_with_packet(record, packet)
    try:
        family.validate_record(prepared.contract, mutated)
    except ValueError as exc:
        diagnosis = _coverage_diagnosis(ReadinessStage.CONSTRAINTS, mutated)
        assert diagnosis is not None
        return str(exc), diagnosis, "openultrasast.core.family.validate_record"
    raise AssertionError("missing constraint was accepted")


def _binding(scope: ScopeKey, role: AdmissionCaseRole, pair_id: str, name: str) -> ReleasedCaseBinding:
    draft = ReleasedCaseBinding(
        canonical.content_digest(f"{name}:case"),
        scope,
        role,
        pair_id,
        canonical.content_digest(f"{name}:result"),
        (canonical.content_digest(f"{name}:evidence"),),
        (canonical.content_digest(f"{name}:change"),),
        canonical.content_digest(f"{name}:manifest"),
        "0" * 64,
    )
    return replace(draft, binding_digest=derive_released_case_binding_digest(draft))


def _pair_failure(prepared: _PreparedFamily) -> tuple[str, None, str]:
    scope = ScopeKey(prepared.contract.family_id, prepared.ecosystem)
    bindings = tuple(
        sorted(
            (
                _binding(scope, AdmissionCaseRole.VULNERABLE, canonical.content_digest("pair-a"), "vulnerable"),
                _binding(scope, AdmissionCaseRole.FIXED, canonical.content_digest("pair-b"), "fixed"),
            ),
            key=lambda item: item.case_id_digest,
        )
    )
    digest = canonical.content_digest("release-header")
    release = AdmissionCaseRelease(
        ADMISSION_CASE_RELEASE_SCHEMA,
        digest,
        digest,
        digest,
        digest,
        digest,
        digest,
        bindings,
        digest,
        _setup().manifest.review,
        digest,
    )
    try:
        _validate_release_shape(release)
    except ValueError as exc:
        return str(exc), None, "openultrasast.core._admission_release._validate_release_shape"
    raise AssertionError("mismatched case pair was accepted")


def _development_failure(
    prepared: _PreparedFamily,
    identity: AnalysisIdentity,
    prior: tuple[ReadinessResult, ...],
    scratch: Path,
) -> str:
    zero_path = scratch / f"{prepared.contract.family_id}-zero-development-input"
    zero_path.write_bytes(b"")
    manifest, receipts = readiness_contract.read_tracked_inputs((("development-case", zero_path),))
    try:
        readiness_contract.build_development_observation(
            arm_id="reference-arm",
            family_id=prepared.contract.family_id,
            ecosystem=prepared.ecosystem,
            identity=identity,
            population_digest=canonical.content_digest("development-population"),
            population_freeze_digest=canonical.content_digest("development-freeze"),
            population_use_receipt_digests=(canonical.content_digest("development-use"),),
            predecessor_digests=tuple(item.result_digest for item in prior),
            fixture_results=_fixtures(prepared.inputs),
            input_manifest=manifest,
            input_read_receipts=receipts,
        )
    except ValueError as exc:
        return str(exc)
    raise AssertionError("zero-input development observation was accepted")


def observe_semantic_failure(
    prepared: _PreparedFamily,
    stage: ReadinessStage,
    identity: AnalysisIdentity,
    prior: tuple[ReadinessResult, ...],
    scratch: Path,
) -> tuple[str, StageDiagnosis | None, str]:
    observers = {
        ReadinessStage.RECOGNITION: _recognition_failure,
        ReadinessStage.TRANSITIONS: _transition_failure,
        ReadinessStage.CONSTRAINTS: _constraint_failure,
        ReadinessStage.PAIRS: _pair_failure,
    }
    if stage is ReadinessStage.DEVELOPMENT:
        return (
            _development_failure(prepared, identity, prior, scratch),
            None,
            "benchmarks.valid.readiness_contract.build_development_observation",
        )
    observer = observers.get(stage)
    if observer is None:
        raise AssertionError(f"unsupported semantic failure stage: {stage.value}")
    return observer(prepared)


__all__ = ["observe_semantic_failure"]
