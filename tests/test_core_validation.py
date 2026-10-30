"""Validation tests for detection-core tasks 7.1-7.2 (Req 5, 7, 11, 12)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.admission import AdmissionManifestError, validate_report_schema  # noqa: E402
from openultrasast.core.consumer import PushRequest, consume_verdict  # noqa: E402
from openultrasast.core.verdict import Judgment, ProvenClaim  # noqa: E402
from openultrasast.semantic.obligations.abstract_domain import (  # noqa: E402
    AuthorityRef,
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    ResourceRef,
    WitnessMatch,
)
from openultrasast.semantic.obligations.trace import AbstractTraceState, Trace  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def test_committed_admission_report_satisfies_schema() -> None:
    report = json.loads((REPO / "benchmarks/measurements/2026-10-30-access-control-admission/report.json").read_text(encoding="utf-8"))
    validate_report_schema(report)


def test_schema_validator_refuses_incomplete_report() -> None:
    report = json.loads((REPO / "benchmarks/measurements/2026-10-30-access-control-admission/report.json").read_text(encoding="utf-8"))
    del report["precision"]
    try:
        validate_report_schema(report)
        raise AssertionError("report missing precision must be refused")
    except AdmissionManifestError:
        pass


def test_end_to_end_push_through_core_contracts() -> None:
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
    trace = Trace(
        entry_kind="route",
        boundary="request",
        access="public",
        parameters=("request",),
        hops=(),
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
    record = trace.to_core_record(entry="src/app.py::handler", digests={"input": "abc123"})
    claim = ProvenClaim(trace_id="t1", witness="fact:f", path="src/app.py", line=30, family="access_control")
    verdict = consume_verdict(PushRequest(base="b", head="h", budget_class="dev-pool"), record, (claim,), ())
    assert verdict.claims[0].witness == "fact:f"
    assert record.judgment is Judgment.UNGUARDED
    assert record.canonical() == record.canonical()
