"""Conformance adapters from the prover's shapes onto the detection-core contracts.

Task 3.1/3.2 of detection-core: the access-control arm's trace and coverage satisfy
the core schema field-for-field, without changing existing analysis behavior.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from openultrasast.core.coverage import Coverage as CoreCoverage
from openultrasast.core.trace import Guard as CoreGuard
from openultrasast.core.trace import Hop as CoreHop
from openultrasast.core.trace import TraceRecord
from openultrasast.core.trace import Witness as CoreWitness
from openultrasast.core.verdict import Judgment
from openultrasast.semantic.obligations.abstract_domain import PairJudgment
from openultrasast.semantic.obligations.trace import Trace

_JUDGMENT_MAP = {
    PairJudgment.UNGUARDED: Judgment.UNGUARDED,
    PairJudgment.DISCHARGED: Judgment.DISCHARGED,
    PairJudgment.INDETERMINATE: Judgment.INDETERMINATE,
}

_RESOLUTION_KEYS = {
    "complete_calls": "complete",
    "incomplete_calls": "incomplete",
    "unresolved_calls": "unresolved",
}


def trace_to_core(trace: Trace, *, entry: str, digests: Mapping[str, str], complete: bool = False) -> TraceRecord:
    """Map one prover trace onto the canonical core trace record.

    ``complete`` defaults to False: the prover Trace carries no per-hop
    completeness, so the adapter never asserts resolved call targets it did not
    see (Req 2.2 -- incomplete evidence never becomes clean).
    """
    state = trace.abstract_state
    if state is None:
        judgment = Judgment.INDETERMINATE
        reasons: tuple[str, ...] = ("abstract_state_unset",)
        witnesses: tuple[CoreWitness, ...] = ()
        resource = "unknown"
        authority = "unknown"
    else:
        judgment = _JUDGMENT_MAP[state.path_judgment.judgment]
        reasons = tuple(state.path_judgment.completeness.reasons) or (
            ("incomplete",) if not state.path_judgment.completeness.is_complete else ()
        )
        witnesses = tuple(
            CoreWitness(kind="witness", provenance=evidence, relation=match.relation.value)
            for match in state.path_judgment.matches
            for evidence in match.evidence
        )
        resource = ",".join(state.resource.values) or "unknown"
        authority = ",".join(state.authority.values) or "unknown"
    hops = tuple(CoreHop(function=hop.function, call_line=hop.call_line, complete=complete) for hop in trace.hops)
    hop_guards = tuple(guard for hop in trace.hops for guard in hop.guards_before_call)
    guards = tuple(CoreGuard(kind=guard.kind, effect=guard.effect) for guard in (*hop_guards, *trace.guards_after))
    return TraceRecord(
        entry=entry,
        hops=hops,
        operation_kind=trace.operation_kind,
        resource=resource,
        authority=authority,
        witnesses=witnesses,
        guards=guards,
        completeness_reasons=reasons,
        judgment=judgment,
        digests=dict(digests),
    )


def coverage_to_core(coverage: Any) -> CoreCoverage:
    """Map the prover's coverage counters onto the core coverage schema."""
    resolution = dict(getattr(coverage, "resolution_counts", {}) or {})
    unknown = sorted(key for key in resolution if key not in _RESOLUTION_KEYS)
    if unknown:
        raise ValueError(f"unknown resolution bucket keys, refusing to under-count calls: {unknown}")
    buckets = {name: 0 for name in ("complete", "incomplete", "unresolved")}
    for key, value in resolution.items():
        buckets[_RESOLUTION_KEYS[key]] = buckets[_RESOLUTION_KEYS[key]] + int(value)
    return CoreCoverage(
        entry_points=int(coverage.entry_points),
        frameworks_recognised=dict(coverage.frameworks_recognised),
        calls=sum(buckets.values()),
        complete=buckets["complete"],
        incomplete=buckets["incomplete"],
        unresolved=buckets["unresolved"],
        unchecked_reasons=dict(coverage.unchecked_by_reason),
    )


__all__ = ["coverage_to_core", "trace_to_core"]
