"""Legacy test conformance after production adapters leave the v1 surface."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.trace import TraceRecord  # noqa: E402
from openultrasast.core.verdict import Judgment  # noqa: E402
from openultrasast.hunt.prover import Coverage, PairJudgmentCounts  # noqa: E402


def _legacy_record(*, judgment: Judgment = Judgment.UNGUARDED) -> TraceRecord:
    reasons = ("abstract_state_unset",) if judgment is Judgment.INDETERMINATE else ()
    return TraceRecord(
        entry="src/app.py::handler",
        hops=(),
        operation_kind="protected_read",
        resource="credentials",
        authority="admin",
        witnesses=(),
        guards=(),
        completeness_reasons=reasons,
        judgment=judgment,
        digests={"input": "abc123"},
    )


def test_legacy_trace_contract_remains_available_only_as_tested_compatibility() -> None:
    record = _legacy_record()

    assert isinstance(record, TraceRecord)
    assert record.entry == "src/app.py::handler"
    assert record.judgment is Judgment.UNGUARDED
    assert record.resource == "credentials"
    assert record.canonical() == _legacy_record().canonical()


def test_legacy_indeterminate_record_stays_explicit() -> None:
    record = _legacy_record(judgment=Judgment.INDETERMINATE)

    assert record.judgment is Judgment.INDETERMINATE
    assert record.completeness_reasons


def test_hunt_coverage_retires_its_legacy_core_projection() -> None:
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

    assert coverage.resolution_counts == {"complete_calls": 5, "incomplete_calls": 3, "unresolved_calls": 2}
    assert not hasattr(coverage, "to_core")
