"""Canonical admission funnel derivation from validated case evidence."""

from __future__ import annotations

from collections import Counter

from openultrasast.core.admission_case import AdmissionCaseResult
from openultrasast.core.coverage import CoverageFunnel, ReasonCount, RelationStatusCount
from openultrasast.core.evidence import EvidenceRecord, NeutralOutcome
from openultrasast.core.semantics import RelationStatus, SemanticRelation


def _relation_reason(relation: SemanticRelation) -> str:
    return "|".join(relation.reasons)


def derive_case_funnel(
    case: AdmissionCaseResult,
    records: tuple[EvidenceRecord, ...],
    finding_count: int,
) -> CoverageFunnel:
    transitions = tuple(item for record in records for item in record.packet.transitions)
    observations = tuple(item for record in records for item in record.packet.observations)
    statuses = Counter(item.status for item in transitions)
    reasons = Counter(_relation_reason(item) for item in transitions if item.status is not RelationStatus.COMPLETE)
    return CoverageFunnel(
        inputs_read=len(case.input_receipts),
        questions_formed=len(records),
        sites_considered=len(transitions) + len(observations),
        sites_recognized=sum(item.status is RelationStatus.COMPLETE for item in transitions)
        + sum(item.status is RelationStatus.COMPLETE for item in observations),
        transitions_materialized=len(transitions),
        security_objects_constructed=len({record.packet.security_object_id for record in records}),
        constraints_evaluated=len(records),
        determinate_outcomes=sum(record.decision.outcome is not NeutralOutcome.INDETERMINATE for record in records),
        findings_emitted=finding_count,
        relation_status_counts=tuple(RelationStatusCount(status, statuses[status]) for status in RelationStatus),
        unresolved_by_reason=tuple(ReasonCount(reason, count) for reason, count in sorted(reasons.items())),
    )


def aggregate_funnels(funnels: tuple[CoverageFunnel, ...]) -> CoverageFunnel:
    statuses = tuple(
        RelationStatusCount(
            status,
            sum(next(item.count for item in funnel.relation_status_counts if item.status is status) for funnel in funnels),
        )
        for status in RelationStatus
    )
    reasons: Counter[str] = Counter()
    for funnel in funnels:
        reasons.update({item.reason: item.count for item in funnel.unresolved_by_reason})
    return CoverageFunnel(
        inputs_read=sum(item.inputs_read for item in funnels),
        questions_formed=sum(item.questions_formed for item in funnels),
        sites_considered=sum(item.sites_considered for item in funnels),
        sites_recognized=sum(item.sites_recognized for item in funnels),
        transitions_materialized=sum(item.transitions_materialized for item in funnels),
        security_objects_constructed=sum(item.security_objects_constructed for item in funnels),
        constraints_evaluated=sum(item.constraints_evaluated for item in funnels),
        determinate_outcomes=sum(item.determinate_outcomes for item in funnels),
        findings_emitted=sum(item.findings_emitted for item in funnels),
        relation_status_counts=statuses,
        unresolved_by_reason=tuple(ReasonCount(reason, count) for reason, count in sorted(reasons.items())),
    )
