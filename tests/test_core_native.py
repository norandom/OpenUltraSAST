"""Native conformance tests: prover Trace/Coverage implement the core contracts directly (task 8.1)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.trace import TraceRecord  # noqa: E402
from openultrasast.core.verdict import Judgment  # noqa: E402
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
            matches=(WitnessMatch(EvidenceRelation.MUST, EvidenceRelation.MUST, EvidenceRelation.NO, ("fact:f",)),),
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
            Hop("handler", 10, (Guard("permission_check", "path", 9, "fact:f", "f1", "all_paths", "branches"),), ()),
            Hop("helper", 20, (Guard("inner", "path", 19, "fact:g", "g1", "some_paths", "returns"),), ()),
        ),
        operation_kind="protected_read",
        fact_id="obligation:protected_read:src/app.py:30",
        operation_line=30,
        arguments=(),
        guards_after=(Guard("after", "op", 31, "fact:h", "h1", "none", "exits"),),
        requires=("identity_constraint",),
        dominating=(),
        missing="identity_constraint",
        abstract_state=state,
    )


def test_trace_natively_conforms_to_core_schema() -> None:
    record = _trace().to_core_record(entry="src/app.py::handler", digests={"input": "abc123"})
    assert isinstance(record, TraceRecord)
    assert record.entry == "src/app.py::handler"
    assert record.judgment is Judgment.UNGUARDED
    assert record.resource == "credentials"
    assert [g.kind for g in record.guards] == ["permission_check", "inner", "after"]
    assert record.hops[0].complete is False  # conservative default
    assert record.canonical() == _trace().to_core_record(entry="src/app.py::handler", digests={"input": "abc123"}).canonical()


def test_legacy_trace_without_abstract_state_is_indeterminate() -> None:
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
    record = legacy.to_core_record(entry="e", digests={})
    assert record.judgment is Judgment.INDETERMINATE
    assert record.completeness_reasons


def test_coverage_natively_conforms_to_core_schema() -> None:
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
    core = coverage.to_core()
    assert core.calls == 10 and core.complete == 5 and core.incomplete == 3 and core.unresolved == 2
    core.validate()
    bad = Coverage(
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
        bad.to_core()
        raise AssertionError("unknown resolution keys must fail loud")
    except ValueError as error:
        assert "mystery_key" in str(error)
