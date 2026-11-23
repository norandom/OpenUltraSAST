"""Task 7.3 deterministic transport-neutral operator projections.

The presenter renders one redacted, byte-deterministic projection of a closed
workflow outcome. Completion renders only from an evaluation replay that was
resolved under the exact outcome reference, proved nonzero and readable, and
revalidated through the pinned core V3 facade; impairment renders only the
outcome's closed fields. The projection never decides eligibility, cannot
express product blocking or rollout, and keeps proof-backed demonstration
distinct from scope decisions. Identifier text is restricted to a closed safe
profile, and free-form core evidence text is reduced to counts, so exception
text, filesystem paths, labels, repository contents, payloads, secrets, and
customer content have no byte to leak into a shared report.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from benchmarks.valid.core_conformance import ScopedAdmissionV3ConformanceError, decode_scoped_admission_v3
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactContractError,
    ArtifactKind,
    ArtifactReference,
    accept_artifact,
    canonical_json_bytes,
)
from benchmarks.valid.workflow_outcome import BenchmarkWorkflowOutcomeV1, WorkflowCounts, WorkflowStatus
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.canonical import JsonValue
from openultrasast.core.evaluation_admission import EvaluationAdmissionV3Error
from openultrasast.core.evaluation_aggregate import EvaluationAggregateV3
from openultrasast.core.evaluation_combination import CombinationLineageV3
from openultrasast.core.evaluation_measurement import ScopedMetricResultV3
from openultrasast.core.evaluation_release import ArmAdmissionCasesV3
from openultrasast.core.evaluation_replay import EvaluationReplayV3
from openultrasast.core.evaluation_report import (
    ArmEvaluationReportV3,
    ScopeAdmissionResultV3,
    WholePopulationCoverageV3,
)
from openultrasast.core.proof import ProofOutcome

OPERATOR_REPORT_SCHEMA = "openultrasast.valid-detection-benchmark.operator-report.v1"
V3_EVALUATION_SCHEMA = "openultrasast.detection-core.evaluation-admission.v3"
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_COUNT_ORDER = ("planned_arms", "completed_arms", "planned_inputs", "completed_inputs", "deferred_inputs")


class OperatorReportErrorReason(StrEnum):
    """Closed refusal reasons; the error never echoes caller content."""

    INVALID_REQUEST = "invalid_request"
    REPLAY_REQUIRED = "replay_required"
    REPLAY_MISMATCH = "replay_mismatch"
    REPLAY_INVALID = "replay_invalid"
    INCONSISTENT_STATE = "inconsistent_state"


class OperatorReportError(ValueError):
    """Refuse unsafe or non-canonical operator projections with a closed reason."""

    def __init__(self, reason: OperatorReportErrorReason) -> None:
        self.reason = reason
        super().__init__(f"operator_report_{reason.value}")


class OperatorScopeStatus(StrEnum):
    """Closed per-scope vocabulary; it cannot express blocking or rollout."""

    GO = "go"
    NO_GO = "no_go"
    INSUFFICIENT = "insufficient"


class OperatorDemonstrationStatus(StrEnum):
    """Closed proof-strength vocabulary, kept distinct from scope decisions."""

    DEMONSTRATED = "demonstrated"
    NOT_DEMONSTRATED = "not_demonstrated"
    NO_FLAGGED_POSITIVES = "no_flagged_positives"


@dataclass(frozen=True)
class ResolvedOperatorReplay:
    """Replay admitted only after nonzero readable artifact and facade validation."""

    reference: ArtifactReference
    content: bytes
    replay_digest: str
    reports: tuple[ArmEvaluationReportV3, ...]
    cases_by_arm: tuple[ArmAdmissionCasesV3, ...]
    whole_population_coverage: WholePopulationCoverageV3
    aggregate: EvaluationAggregateV3 | None

    def __post_init__(self) -> None:
        _validate_resolved(self)


def resolve_operator_replay(reference: object, content: object, replay: object) -> ResolvedOperatorReplay:
    """Resolve one replay against its artifact bytes through the pinned core facade."""
    if type(reference) is not ArtifactReference or type(content) is not bytes:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    if reference.artifact_kind is not ArtifactKind.REPLAY or reference.access_class is not ArtifactAccessClass.OPERATOR_SAFE:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    if type(replay) is not EvaluationReplayV3:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_INVALID)
    try:
        decoded = decode_scoped_admission_v3(V3_EVALUATION_SCHEMA, replay, EvaluationReplayV3)
        accepted = accept_artifact(content, reference=reference)
    except (ScopedAdmissionV3ConformanceError, EvaluationAdmissionV3Error, ArtifactContractError):
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_INVALID) from None
    if accepted.artifact.payload.get("replay_digest") != decoded.replay_digest:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_MISMATCH)
    return ResolvedOperatorReplay(
        reference,
        content,
        decoded.replay_digest,
        decoded.reports,
        decoded.cases_by_arm,
        decoded.whole_population_coverage,
        decoded.aggregate,
    )


def _safe_text(value: object) -> str:
    if type(value) is not str or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    return value


def _hex(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    return value


def _validate_resolved(value: ResolvedOperatorReplay) -> None:
    if type(value) is not ResolvedOperatorReplay or type(value.content) is not bytes or not value.content:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    if value.reference.artifact_kind is not ArtifactKind.REPLAY or value.reference.access_class is not ArtifactAccessClass.OPERATOR_SAFE:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    _hex(value.replay_digest)
    try:
        accepted = accept_artifact(value.content, reference=value.reference)
    except ArtifactContractError:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_INVALID) from None
    if accepted.artifact.payload.get("replay_digest") != value.replay_digest:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_MISMATCH)
    _validate_resolved_collections(value)


def _validate_resolved_collections(value: ResolvedOperatorReplay) -> None:
    reports, groups = value.reports, value.cases_by_arm
    if type(reports) is not tuple or type(groups) is not tuple or not reports or len(reports) != len(groups):
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    arm_ids = tuple(_validated_arm_pair(report, group) for report, group in zip(reports, groups, strict=True))
    if arm_ids != tuple(sorted(arm_ids)):
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    if type(value.whole_population_coverage) is not WholePopulationCoverageV3:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    value.whole_population_coverage.__post_init__()
    if value.whole_population_coverage.underlying_push_count < 1:
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    if value.aggregate is not None and type(value.aggregate) is not EvaluationAggregateV3:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    if value.aggregate is not None:
        value.aggregate.__post_init__()


def _validated_arm_pair(report: object, group: object) -> str:
    if type(report) is not ArmEvaluationReportV3 or type(group) is not ArmAdmissionCasesV3:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    report.__post_init__()
    group.__post_init__()
    arm_id = _safe_text(report.baseline.arm_id)
    if arm_id != group.arm_id:
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    return arm_id


def operator_report_json(outcome: object, resolved: object) -> dict[str, JsonValue]:
    """Project one validated outcome as a closed redacted canonical mapping."""
    return _report_value(outcome, resolved)


def operator_report_bytes(outcome: object, resolved: object) -> bytes:
    """Encode the projection as deterministic canonical JSON bytes."""
    return canonical_json_bytes(_report_value(outcome, resolved))


def operator_report_text(outcome: object, resolved: object) -> str:
    """Encode the same facts as one concise deterministic ASCII text summary."""
    return _render_text(_report_value(outcome, resolved))


def _report_value(outcome: object, resolved: object) -> dict[str, JsonValue]:
    if type(outcome) is not BenchmarkWorkflowOutcomeV1:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    outcome.__post_init__()
    if outcome.status is WorkflowStatus.COMPLETED:
        return _completed_value(outcome, _require_completed_replay(outcome, resolved))
    if resolved is not None:
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    return _safe_value(outcome)


def _require_completed_replay(outcome: BenchmarkWorkflowOutcomeV1, resolved: object) -> ResolvedOperatorReplay:
    if resolved is None:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_REQUIRED)
    if type(resolved) is not ResolvedOperatorReplay:
        raise OperatorReportError(OperatorReportErrorReason.INVALID_REQUEST)
    resolved.__post_init__()
    if resolved.reference != outcome.evaluation_replay_ref:
        raise OperatorReportError(OperatorReportErrorReason.REPLAY_MISMATCH)
    if len(resolved.reports) != outcome.counts.planned_arms:
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    return resolved


def _codes(codes: Sequence[StrEnum]) -> tuple[str, ...]:
    return tuple(item.value for item in codes)


def _counts_value(counts: WorkflowCounts) -> dict[str, JsonValue]:
    return {key: getattr(counts, key) for key in _COUNT_ORDER}


def _safe_value(outcome: BenchmarkWorkflowOutcomeV1) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": OPERATOR_REPORT_SCHEMA,
        "outcome_digest": _hex(outcome.outcome_digest),
        "status": outcome.status.value,
        "labels_spent": outcome.labels_spent,
        "runtime_ms": outcome.runtime_ms,
        "reason_codes": _codes(outcome.reason_codes),
        "counts": _counts_value(outcome.counts),
        "degradation_codes": _codes(outcome.degradation_codes),
    }
    if outcome.status is WorkflowStatus.INSUFFICIENT:
        value["scope_status"] = OperatorScopeStatus.INSUFFICIENT.value
        value["failed_gate_names"] = _codes(outcome.failed_gate_names)
    return value


def _completed_value(outcome: BenchmarkWorkflowOutcomeV1, resolved: ResolvedOperatorReplay) -> dict[str, JsonValue]:
    return {
        "schema_version": OPERATOR_REPORT_SCHEMA,
        "status": outcome.status.value,
        "outcome_digest": _hex(outcome.outcome_digest),
        "labels_spent": outcome.labels_spent,
        "runtime_ms": outcome.runtime_ms,
        "reason_codes": _codes(outcome.reason_codes),
        "population_digest": _hex(outcome.population_digest),
        "freeze_digest": _hex(outcome.freeze_digest),
        "plan_digest": _hex(outcome.plan_digest),
        "workflow_digest": _hex(outcome.workflow_digest),
        "counts": _counts_value(outcome.counts),
        "degradation_codes": _codes(outcome.degradation_codes),
        "input_read_evidence_digest": _hex(outcome.input_read_evidence_digest),
        "stage_execution_evidence_digest": _hex(outcome.stage_execution_evidence_digest),
        "replay": _replay_value(resolved),
    }


def _replay_value(resolved: ResolvedOperatorReplay) -> dict[str, JsonValue]:
    coverage = resolved.whole_population_coverage
    return {
        "content_digest": resolved.reference.content_digest,
        "provenance_digest": resolved.reference.provenance_digest,
        "byte_length": resolved.reference.byte_length,
        "replay_digest": resolved.replay_digest,
        "arms": tuple(_arm_value(report, group) for report, group in zip(resolved.reports, resolved.cases_by_arm, strict=True)),
        "whole_population_coverage": {
            "underlying_push_count": coverage.underlying_push_count,
            "completed_underlying_push_count": coverage.completed_underlying_push_count,
            "deferred_underlying_push_count": coverage.deferred_underlying_push_count,
            "coverage_digest": coverage.coverage_digest,
        },
        "optional_aggregate": None if resolved.aggregate is None else _aggregate_value(resolved.aggregate),
    }


def _arm_value(report: ArmEvaluationReportV3, group: ArmAdmissionCasesV3) -> dict[str, JsonValue]:
    evidence = report.operational_evidence
    return {
        "arm_id": _safe_text(report.baseline.arm_id),
        "baseline_digest": _hex(report.baseline.baseline_digest),
        "report_digest": _hex(report.report_digest),
        "combination": _combination_value(report.combination_lineage),
        "operational": {
            "completed_cases": evidence.completed_count,
            "deferred_cases": evidence.deferred_count,
            "instrument_failure_count": len(evidence.instrument_failures),
            "model_failure_count": len(evidence.model_failures),
            "runtime_ms": evidence.runtime_ms,
            "degradation_reasons": tuple(item.value for item in evidence.degradation_reasons),
        },
        "demonstrated": _demonstration_value(group),
        "failed_gate_names": tuple(sorted({name for item in report.scoped_results for name in _failed_gate_names(item)})),
        "scopes": tuple(_scope_value(item) for item in report.scoped_results),
    }


def _failed_gate_names(result: ScopeAdmissionResultV3) -> tuple[str, ...]:
    gates = (result.instrument_gate, result.budget_gate, result.readiness_gate, result.quality_gate)
    return tuple(gate.kind.value for gate in gates if not gate.passed)


def _scope_value(result: ScopeAdmissionResultV3) -> dict[str, JsonValue]:
    status = OperatorScopeStatus.GO if result.decision is AdmissionDecision.GO else OperatorScopeStatus.NO_GO
    return {
        "family_id": _safe_text(result.key.scope.family_id),
        "ecosystem": _safe_text(result.key.scope.ecosystem),
        "status": status.value,
        "failed_gates": _failed_gate_names(result),
        "metrics": tuple(_metric_value(metric) for metric in result.metrics),
        "result_digest": _hex(result.result_digest),
    }


def _metric_value(metric: ScopedMetricResultV3) -> dict[str, JsonValue]:
    return {
        "metric_id": metric.metric_id.value,
        "numerator": metric.numerator,
        "denominator": metric.denominator,
        "sample_count": metric.sample_count,
        "value": metric.value,
        "interval_method": metric.interval_method.value,
        "interval_lower": metric.interval_lower,
        "interval_upper": metric.interval_upper,
    }


def _combination_value(lineage: CombinationLineageV3 | None) -> JsonValue:
    if lineage is None:
        return None
    return {
        "operator": lineage.rule.operator.value,
        "component_arm_ids": tuple(_safe_text(item) for item in lineage.rule.component_arm_ids),
        "lineage_digest": _hex(lineage.lineage_digest),
    }


def _demonstration_value(group: ArmAdmissionCasesV3) -> dict[str, JsonValue]:
    flagged = 0
    demonstrated = 0
    candidates = 0
    for case in group.cases:
        if case.proof_candidate is not None:
            candidates += 1
        if case.role is AdmissionCaseRole.VULNERABLE and case.claims:
            flagged += 1
            if any(attachment.proof.outcome is ProofOutcome.DEMONSTRATED for attachment in case.proof_attachments):
                demonstrated += 1
    if not flagged:
        status = OperatorDemonstrationStatus.NO_FLAGGED_POSITIVES
    elif demonstrated == flagged:
        status = OperatorDemonstrationStatus.DEMONSTRATED
    else:
        status = OperatorDemonstrationStatus.NOT_DEMONSTRATED
    return {
        "status": status.value,
        "flagged_positive_cases": flagged,
        "proof_candidate_cases": candidates,
        "demonstrated_proof_cases": demonstrated,
    }


def _aggregate_value(aggregate: EvaluationAggregateV3) -> dict[str, JsonValue]:
    return {
        "aggregate_digest": _hex(aggregate.aggregate_digest),
        "constituents": tuple(
            {
                "arm_id": _safe_text(key.arm_id),
                "family_id": _safe_text(key.scope.family_id),
                "ecosystem": _safe_text(key.scope.ecosystem),
                "sample_count": sample,
            }
            for key, sample in zip(aggregate.constituents, aggregate.sample_counts, strict=True)
        ),
        "weights": tuple(
            {
                "arm_id": _safe_text(item.key.arm_id),
                "family_id": _safe_text(item.key.scope.family_id),
                "ecosystem": _safe_text(item.key.scope.ecosystem),
                "numerator": item.numerator,
                "denominator": item.denominator,
            }
            for item in aggregate.weights
        ),
    }


def _render_text(value: Mapping[str, JsonValue]) -> str:
    lines = _common_lines(value)
    if value["status"] == "completed":
        lines.extend(_completed_lines(value))
    else:
        lines.extend(_non_completed_lines(value))
    return "\n".join(lines) + "\n"


def _common_lines(value: Mapping[str, JsonValue]) -> list[str]:
    counts = cast(Mapping[str, JsonValue], value["counts"])
    return [
        f"operator report: {value['status']}",
        f"outcome_digest: {value['outcome_digest']}",
        f"labels_spent: {str(value['labels_spent']).lower()}",
        f"runtime_ms: {value['runtime_ms']}",
        _codes_line("reasons", value["reason_codes"]),
        "counts: " + " ".join(f"{key}={counts[key]}" for key in _COUNT_ORDER),
        _codes_line("degradations", value["degradation_codes"]),
    ]


def _non_completed_lines(value: Mapping[str, JsonValue]) -> list[str]:
    if "scope_status" not in value:
        return []
    return [
        f"scope_status={value['scope_status']}",
        _codes_line("failed_gates", value["failed_gate_names"]),
    ]


def _completed_lines(value: Mapping[str, JsonValue]) -> list[str]:
    replay_value = cast(Mapping[str, JsonValue], value["replay"])
    lines = [
        f"digests: population={value['population_digest']} freeze={value['freeze_digest']}"
        f" plan={value['plan_digest']} workflow={value['workflow_digest']}",
        f"evidence: input_reads={value['input_read_evidence_digest']} stage_execution={value['stage_execution_evidence_digest']}",
        f"replay: digest={replay_value['replay_digest']} content_digest={replay_value['content_digest']}"
        f" provenance_digest={replay_value['provenance_digest']} byte_length={replay_value['byte_length']}",
    ]
    for arm in cast(tuple[JsonValue, ...], replay_value["arms"]):
        lines.extend(_arm_lines(cast(Mapping[str, JsonValue], arm)))
    coverage = cast(Mapping[str, JsonValue], replay_value["whole_population_coverage"])
    lines.append(
        f"whole_population_coverage: underlying_pushes={coverage['underlying_push_count']}"
        f" completed={coverage['completed_underlying_push_count']} deferred={coverage['deferred_underlying_push_count']}"
        f" digest={coverage['coverage_digest']}"
    )
    aggregate = replay_value["optional_aggregate"]
    if aggregate is None:
        lines.append("optional_aggregate: none")
    else:
        rows = cast(Mapping[str, JsonValue], aggregate)
        lines.append(
            f"optional_aggregate: digest={rows['aggregate_digest']}"
            f" constituents={len(cast(tuple[JsonValue, ...], rows['constituents']))}"
            f" weights={len(cast(tuple[JsonValue, ...], rows['weights']))}"
        )
    return lines


def _arm_lines(arm: Mapping[str, JsonValue]) -> list[str]:
    combination = arm["combination"]
    operational = cast(Mapping[str, JsonValue], arm["operational"])
    demonstrated = cast(Mapping[str, JsonValue], arm["demonstrated"])
    lines = [
        f"arm: {arm['arm_id']}",
        f"  baseline_digest: {arm['baseline_digest']}",
        f"  report_digest: {arm['report_digest']}",
        f"  failed_gates={_joined(arm['failed_gate_names'])}",
    ]
    if combination is None:
        lines.append("  combination: none")
    else:
        combined = cast(Mapping[str, JsonValue], combination)
        components = _joined(combined["component_arm_ids"])
        lines.append(f"  combination: operator={combined['operator']} components={components} lineage={combined['lineage_digest']}")
    lines.append(
        f"  operational: completed_cases={operational['completed_cases']} deferred_cases={operational['deferred_cases']}"
        f" instrument_failures={operational['instrument_failure_count']} model_failures={operational['model_failure_count']}"
        f" runtime_ms={operational['runtime_ms']} degradations={_joined(operational['degradation_reasons'])}"
    )
    lines.append(
        f"  demonstrated: status={demonstrated['status']} flagged_positive_cases={demonstrated['flagged_positive_cases']}"
        f" proof_candidate_cases={demonstrated['proof_candidate_cases']}"
        f" demonstrated_proof_cases={demonstrated['demonstrated_proof_cases']}"
    )
    for scope in cast(tuple[JsonValue, ...], arm["scopes"]):
        lines.extend(_scope_lines(cast(Mapping[str, JsonValue], scope)))
    return lines


def _scope_lines(scope: Mapping[str, JsonValue]) -> list[str]:
    lines = [
        f"  scope: {scope['family_id']}/{scope['ecosystem']} status={scope['status']}"
        f" failed_gates={_joined(scope['failed_gates'])} result_digest={scope['result_digest']}",
    ]
    for metric in cast(tuple[JsonValue, ...], scope["metrics"]):
        row = cast(Mapping[str, JsonValue], metric)
        lines.append(
            f"    metric: {row['metric_id']} count={row['numerator']}/{row['denominator']}"
            f" sample={row['sample_count']} value={row['value']!r}"
            f" interval=[{row['interval_lower']!r},{row['interval_upper']!r}] method={row['interval_method']}"
        )
    return lines


def _codes_line(label: str, codes: object) -> str:
    return f"{label}={_joined(codes)}"


def _joined(codes: object) -> str:
    if not isinstance(codes, tuple):
        raise OperatorReportError(OperatorReportErrorReason.INCONSISTENT_STATE)
    return ",".join(str(item) for item in codes) if codes else "none"


__all__ = [
    "OPERATOR_REPORT_SCHEMA",
    "OperatorDemonstrationStatus",
    "OperatorReportError",
    "OperatorReportErrorReason",
    "OperatorScopeStatus",
    "ResolvedOperatorReplay",
    "operator_report_bytes",
    "operator_report_json",
    "operator_report_text",
    "resolve_operator_replay",
]
