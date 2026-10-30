"""Fact-pack and consumer contract tests for detection-core tasks 6.1-6.2 (Req 9, 10, 11)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.consumer import PushRequest, consume_verdict  # noqa: E402
from openultrasast.core.factpack import FactPackError, admit_fact_pack, verify_fact_pack  # noqa: E402
from openultrasast.core.trace import TraceRecord  # noqa: E402
from openultrasast.core.verdict import BoundedSilence, Judgment, ProvenClaim  # noqa: E402

FACTS = ({"id": "obligation:protected_read", "language": "java"},)


def test_unreviewed_fact_pack_is_refused() -> None:
    try:
        admit_fact_pack("access_control", FACTS, review_digest="")
        raise AssertionError("unreviewed pack must be refused")
    except FactPackError:
        pass


def test_reviewed_fact_pack_stamps_provenance() -> None:
    pack = admit_fact_pack("access_control", FACTS, review_digest="review-2026-10-30")
    assert pack.family == "access_control"
    assert pack.review_digest == "review-2026-10-30"
    assert len(pack.fact_set_digest) == 12
    verify_fact_pack(pack, FACTS)
    try:
        verify_fact_pack(pack, FACTS + ({"id": "tampered"},))
        raise AssertionError("tampered facts must be refused")
    except FactPackError:
        pass


def _record() -> TraceRecord:
    return TraceRecord(
        entry="src/app.py::handler",
        hops=(),
        operation_kind="protected_read",
        resource="credentials",
        authority="admin",
        judgment=Judgment.UNGUARDED,
        digests={"input": "abc"},
    )


def test_consumer_accepts_witnessed_claim_and_reasoned_silence() -> None:
    claim = ProvenClaim(trace_id="t1", witness="w1", path="src/app.py", line=10, family="access_control")
    silence = BoundedSilence(path="src/other.py", reason="unreached", coverage={"entry_points": 0})
    verdict = consume_verdict(PushRequest(base="b", head="h", budget_class="dev-pool"), _record(), (claim,), (silence,))
    assert verdict.claims == (claim,)
    assert verdict.silence == (silence,)


def test_consumer_refuses_claim_without_witness_or_silence_without_reason() -> None:
    bad_claim = ProvenClaim(trace_id="t1", witness="", path="src/app.py", line=10, family="access_control")
    try:
        consume_verdict(PushRequest(base="b", head="h", budget_class="c"), _record(), (bad_claim,), ())
        raise AssertionError("witnessless claim must be refused")
    except ValueError:
        pass
    bad_silence = BoundedSilence(path="src/other.py", reason="", coverage={})
    try:
        consume_verdict(PushRequest(base="b", head="h", budget_class="c"), _record(), (), (bad_silence,))
        raise AssertionError("reasonless silence must be refused")
    except ValueError:
        pass
