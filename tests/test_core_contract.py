"""Core contract conformance tests for detection-core tasks 1.1-1.4 (Reqs 1, 2, 3, 5, 6, 9)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.coverage import Coverage, InstrumentFailure, check_reads  # noqa: E402
from openultrasast.core.provenance import ProvenanceMismatch, stamp, verify_stamp  # noqa: E402
from openultrasast.core.trace import Guard, Hop, TraceRecord, Witness  # noqa: E402
from openultrasast.core.verdict import BoundedSilence, Judgment, ProvenClaim, as_clean  # noqa: E402


def _trace() -> TraceRecord:
    return TraceRecord(
        entry="src/app.py::handler",
        hops=(Hop(function="handler", call_line=10, complete=True),),
        operation_kind="protected_read",
        resource="credentials",
        authority="admin",
        witnesses=(Witness(kind="guard", provenance="fact:checkPermission", relation="all_paths"),),
        guards=(Guard(kind="permission_check", effect="branches"),),
        completeness_reasons=(),
        judgment=Judgment.UNGUARDED,
        digests={"input": "abc123"},
    )


def test_trace_serializes_byte_identical_on_repeat() -> None:
    first = _trace().canonical()
    second = _trace().canonical()
    assert first == second
    assert isinstance(first, bytes)


def test_trace_record_pins_schema_fields() -> None:
    record = _trace().record()
    for field in (
        "entry",
        "hops",
        "operation_kind",
        "resource",
        "authority",
        "witnesses",
        "guards",
        "completeness_reasons",
        "judgment",
        "digests",
    ):
        assert field in record
    assert record["judgment"] == "unguarded"


def test_judgment_vocabulary_is_exactly_three_way() -> None:
    assert {j.value for j in Judgment} == {"unguarded", "discharged", "indeterminate"}


def test_indeterminate_never_converts_to_clean() -> None:
    assert as_clean(Judgment.DISCHARGED) == Judgment.DISCHARGED
    try:
        as_clean(Judgment.INDETERMINATE)
        raise AssertionError("indeterminate must never convert to clean")
    except ValueError:
        pass


def test_proven_claim_requires_witness_and_location() -> None:
    claim = ProvenClaim(trace_id="t1", witness="w1", path="src/app.py", line=10, family="access_control")
    assert claim.family == "access_control"
    silence = BoundedSilence(path="src/app.py", reason="unreached", coverage={"entry_points": 0})
    assert silence.reason == "unreached"


def test_coverage_requires_exactly_one_bucket_per_call() -> None:
    good = Coverage(entry_points=2, frameworks_recognised={"jenkins": 1}, calls=3, complete=1, incomplete=1, unresolved=1)
    good.validate()
    bad = Coverage(entry_points=1, frameworks_recognised={}, calls=3, complete=2, incomplete=1, unresolved=1)
    try:
        bad.validate()
        raise AssertionError("two buckets for one call must be refused")
    except ValueError:
        pass
    negative = Coverage(entry_points=1, frameworks_recognised={}, calls=3, complete=-1, incomplete=2, unresolved=2)
    try:
        negative.validate()
        raise AssertionError("negative bucket counts must be refused")
    except ValueError:
        pass


def test_verdict_contract_exposes_no_model_role_path() -> None:
    import openultrasast.core.verdict as verdict_module

    public = verdict_module.__all__
    assert not any("model" in name.lower() or "judge" in name.lower() for name in public), (
        "the verdict contract must expose no model/judge path; models judge residuals zero-shot over a trace only"
    )


def test_zero_byte_read_is_instrument_failure() -> None:
    try:
        check_reads({"src/app.py": 0, "src/lib.py": 12})
        raise AssertionError("zero-byte read must fail the run")
    except InstrumentFailure:
        pass
    check_reads({"src/app.py": 5})


def test_provenance_stamp_and_mismatch_refusal() -> None:
    record = stamp(
        analyzer_revision="d063167",
        fact_set_digest="3eb5bf699434",
        acquisition_record_digest="none",
        configuration_digest="095b5a4905ad",
        population_digest="c866c0e812c0",
        change_id="case-1",
    )
    assert set(record) == {
        "analyzer_revision",
        "fact_set_digest",
        "acquisition_record_digest",
        "configuration_digest",
        "population_digest",
        "input_digest",
    }
    verify_stamp(record, record.copy())
    tampered = {**record, "fact_set_digest": "ffffffffffff"}
    try:
        verify_stamp(tampered, record)
        raise AssertionError("mismatched digest must be refused")
    except ProvenanceMismatch:
        pass
