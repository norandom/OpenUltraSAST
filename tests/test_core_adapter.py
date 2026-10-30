"""Conformance tests: the prover's trace/coverage satisfy the detection-core contracts (task 3.1, 3.2)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.trace import TraceRecord  # noqa: E402
from openultrasast.core.verdict import Judgment  # noqa: E402
from openultrasast.hunt.core_adapter import coverage_to_core, trace_to_core  # noqa: E402
from openultrasast.hunt.prover import Coverage, PairJudgmentCounts  # noqa: E402
from openultrasast.semantic.obligations.abstract_domain import (  # noqa: E402
    AuthorityRef,
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    ResourceRef,
    WitnessMatch,
)
from openultrasast.semantic.obligations.trace import AbstractTraceState, Guard, Hop, Trace  # noqa: E402


def _trace() -> Trace:
    state = AbstractTraceState(
        path_judgment=PathJudgment(
            judgment=PairJudgment.UNGUARDED,
            missing=("identity_constraint",),
            completeness=Completeness(is_complete=True, reasons=()),
            matches=(
                WitnessMatch(
                    relation=EvidenceRelation.MUST,
                    resource_relation=EvidenceRelation.MUST,
                    authority_relation=EvidenceRelation.NO,
                    evidence=("fact:checkPermission",),
                ),
            ),
        ),
        resource=ResourceRef(kind="exact", values=("credentials",)),
        authority=AuthorityRef(values=("admin",), is_unknown=False),
        resource_relation=EvidenceRelation.MUST,
        authority_relation=EvidenceRelation.MUST,
    )
    return Trace(
        entry_kind="route",
        boundary="request",
        access="public",
        parameters=("request",),
        hops=(
            Hop(
                function="handler",
                call_line=10,
                guards_before_call=(Guard("permission_check", "path", 9, "fact:f", "f1", "all_paths", "branches"),),
                forwarded=(),
            ),
        ),
        operation_kind="protected_read",
        fact_id="obligation:protected_read:src/app.py:30",
        operation_line=30,
        arguments=(),
        guards_after=(),
        requires=("identity_constraint",),
        dominating=(),
        missing="identity_constraint",
        abstract_state=state,
    )


def test_trace_conforms_to_core_schema() -> None:
    record = trace_to_core(_trace(), entry="src/app.py::handler", digests={"input": "abc123"})
    assert isinstance(record, TraceRecord)
    assert record.entry == "src/app.py::handler"
    assert record.operation_kind == "protected_read"
    assert record.resource == "credentials"
    assert record.authority == "admin"
    assert record.judgment is Judgment.UNGUARDED
    assert record.hops[0].function == "handler"
    assert record.hops[0].complete is False  # conservative default: Trace carries no completeness
    assert trace_to_core(_trace(), entry="e", digests={}, complete=True).hops[0].complete is True
    assert record.guards[0].kind == "permission_check"
    assert record.guards[0].effect == "branches"
    assert record.witnesses[0].provenance == "fact:checkPermission"
    assert record.digests == {"input": "abc123"}
    # deterministic serialization round-trips
    assert record.canonical() == trace_to_core(_trace(), entry="src/app.py::handler", digests={"input": "abc123"}).canonical()


def test_trace_without_abstract_state_is_indeterminate() -> None:
    trace = _trace()
    legacy = Trace(
        entry_kind=trace.entry_kind,
        boundary=trace.boundary,
        access=trace.access,
        parameters=trace.parameters,
        hops=trace.hops,
        operation_kind=trace.operation_kind,
        fact_id=trace.fact_id,
        operation_line=trace.operation_line,
        arguments=trace.arguments,
        guards_after=trace.guards_after,
        requires=trace.requires,
        dominating=trace.dominating,
        missing=trace.missing,
    )
    record = trace_to_core(legacy, entry="src/app.py::handler", digests={})
    assert record.judgment is Judgment.INDETERMINATE
    assert record.completeness_reasons  # legacy trace without abstract state is incomplete


def test_coverage_conforms_to_core_schema() -> None:
    coverage = Coverage(
        files_by_language={"java": 2},
        frameworks_recognised={"jenkins": 1},
        entry_points=3,
        reached=2,
        unreached=1,
        operations_checked=4,
        operations_discharged=1,
        unchecked_by_reason={"unreached": 1},
        pair_judgments=PairJudgmentCounts(unguarded=1, discharged=1, indeterminate=2),
        resolution_counts={"complete_calls": 5, "incomplete_calls": 3, "unresolved_calls": 2},
    )
    core = coverage_to_core(coverage)
    assert core.entry_points == 3
    assert core.frameworks_recognised == {"jenkins": 1}
    assert core.calls == 10
    assert core.complete == 5 and core.incomplete == 3 and core.unresolved == 2
    assert core.unchecked_reasons == {"unreached": 1}
    core.validate()


def test_coverage_adapter_refuses_unknown_resolution_keys() -> None:
    coverage = Coverage(
        files_by_language={},
        frameworks_recognised={},
        entry_points=1,
        reached=1,
        unreached=0,
        operations_checked=1,
        operations_discharged=0,
        unchecked_by_reason={},
        pair_judgments=PairJudgmentCounts(unguarded=0, discharged=0, indeterminate=1),
        resolution_counts={"complete_calls": 2, "mystery_key": 7},
    )
    try:
        coverage_to_core(coverage)
        raise AssertionError("unknown resolution keys must fail loud, not under-count calls")
    except ValueError as error:
        assert "mystery_key" in str(error)


def test_adapter_maps_guards_from_every_hop() -> None:
    trace = _trace()
    second = Hop(
        function="helper",
        call_line=20,
        guards_before_call=(Guard("inner", "path", 19, "fact:g", "g1", "some_paths", "returns"),),
        forwarded=(),
    )
    with_second = Trace(
        entry_kind=trace.entry_kind,
        boundary=trace.boundary,
        access=trace.access,
        parameters=trace.parameters,
        hops=(*trace.hops, second),
        operation_kind=trace.operation_kind,
        fact_id=trace.fact_id,
        operation_line=trace.operation_line,
        arguments=trace.arguments,
        guards_after=(Guard("after", "op", 31, "fact:h", "h1", "none", "exits"),),
        requires=trace.requires,
        dominating=trace.dominating,
        missing=trace.missing,
        abstract_state=trace.abstract_state,
    )
    record = trace_to_core(with_second, entry="e", digests={})
    kinds = [guard.kind for guard in record.guards]
    assert kinds == ["permission_check", "inner", "after"]
