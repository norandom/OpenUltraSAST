"""access-control-prover task 7.4: judgment, trace and coverage contracts with abstract state (offline).

Three-way pair judgments, completeness and evidence relations as contracts, and their canonical
serialization, per the design's "Abstract evidence domain" and "Witness matching and judgment"
sections and Req 7.1, 7.2, 7.5, 7.6, 9.1, 9.2, 9.6. Legacy trace and coverage shapes stay byte-stable
unless the caller opts into the abstract state.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

from openultrasast.semantic.ir import parse_python_ast
from openultrasast.semantic.obligations.dominance import OrderDominance
from openultrasast.semantic.obligations.facts import ObligationFacts, OperationFact
from openultrasast.semantic.obligations.operations import Operation
from openultrasast.semantic.obligations.paths import PathRecord
from openultrasast.semantic.obligations.trace import build_trace

if TYPE_CHECKING:
    from openultrasast.semantic.obligations.trace import AbstractTraceState, Trace

_LEGACY_TRACE_KEYS = {
    "entry_kind",
    "boundary",
    "access",
    "parameters",
    "hops",
    "operation_kind",
    "fact_id",
    "operation_line",
    "arguments",
    "guards_after",
    "requires",
    "dominating",
    "missing",
    "operation_context",
}


def _abstract_state() -> AbstractTraceState:
    from openultrasast.semantic.obligations.abstract_domain import (
        AuthorityRef,
        Completeness,
        EvidenceRelation,
        PairJudgment,
        PathJudgment,
        ResourceRef,
        WitnessMatch,
    )
    from openultrasast.semantic.obligations.trace import AbstractTraceState

    return AbstractTraceState(
        path_judgment=PathJudgment(
            judgment=PairJudgment.UNGUARDED,
            missing=("path_guard",),
            completeness=Completeness(
                False,
                ("resolution:ambiguous_call", "matching:unknown_resource", "matching:unknown_authority"),
            ),
            matches=(WitnessMatch(EvidenceRelation.MUST, EvidenceRelation.MAY, EvidenceRelation.NO, ("implication:admin_role",)),),
        ),
        resource=ResourceRef(kind="exact", values=("doc:1",)),
        authority=AuthorityRef(values=("admin",)),
        resource_relation=EvidenceRelation.MAY,
        authority_relation=EvidenceRelation.UNKNOWN,
    )


def _trace(abstract_state: AbstractTraceState | None = None) -> Trace:
    from openultrasast.semantic.obligations.trace import Trace

    return Trace(
        entry_kind="route",
        boundary="http_request",
        access="unknown",
        parameters=("item",),
        hops=(),
        operation_kind="protected_read",
        fact_id="read",
        operation_line=2,
        arguments=(("item", "request_input"),),
        guards_after=(),
        requires=("path_guard",),
        dominating=(),
        missing=None,
        abstract_state=abstract_state,
    )


def test_pair_judgment_is_exactly_the_three_way_vocabulary() -> None:
    # Req 4.1-4.3 vocabulary: a pair is unguarded, discharged or indeterminate (design, PairJudgment).
    from openultrasast.semantic.obligations.abstract_domain import PairJudgment

    assert [judgment.value for judgment in PairJudgment] == ["unguarded", "discharged", "indeterminate"]


def test_witness_match_and_path_judgment_carry_the_design_fields() -> None:
    from openultrasast.semantic.obligations.abstract_domain import (
        Completeness,
        EvidenceRelation,
        PairJudgment,
        PathJudgment,
        WitnessMatch,
    )

    match = WitnessMatch(EvidenceRelation.MUST, EvidenceRelation.NO, EvidenceRelation.MAY, ("witness:guard",))
    judgment = PathJudgment(PairJudgment.DISCHARGED, (), Completeness(True), (match,))
    assert (judgment.judgment, judgment.missing, judgment.matches) == (PairJudgment.DISCHARGED, (), (match,))
    assert judgment.completeness == Completeness(True)
    assert hash(judgment) == hash(PathJudgment(PairJudgment.DISCHARGED, (), Completeness(True), (match,)))


def test_count_pair_judgments_reports_each_way_separately() -> None:
    # Req 7.1, 7.6: unguarded, discharged and indeterminate pairs are counted separately; an
    # indeterminate pair is included in neither the unguarded nor the discharged count.
    from openultrasast.semantic.obligations.abstract_domain import PairJudgment, PairJudgmentCounts, count_pair_judgments

    counts = count_pair_judgments([PairJudgment.UNGUARDED, PairJudgment.INDETERMINATE, PairJudgment.INDETERMINATE, PairJudgment.DISCHARGED])
    assert counts == PairJudgmentCounts(unguarded=1, discharged=1, indeterminate=2)
    assert counts.examined() == 4
    assert count_pair_judgments([]) == PairJudgmentCounts()


def test_reason_counts_aggregates_every_reason_by_pair() -> None:
    # Req 7.2, 7.5: every incompleteness reason is preserved once per pair and aggregated in coverage.
    from openultrasast.semantic.obligations.abstract_domain import Completeness, reason_counts

    counts = reason_counts(
        [
            Completeness(False, ("resolution:ambiguous_call", "matching:unknown_resource")),
            Completeness(False, ("resolution:ambiguous_call", "dominance:cfg_unavailable")),
            Completeness(True),
        ]
    )
    assert counts == {"resolution:ambiguous_call": 2, "dominance:cfg_unavailable": 1, "matching:unknown_resource": 1}
    assert list(counts) == sorted(counts)


def test_legacy_trace_omits_abstract_state_from_record_and_text() -> None:
    record = _trace().record()
    assert "abstract_state" not in record
    assert set(record) == _LEGACY_TRACE_KEYS
    assert json.loads(json.dumps(record)) == record
    text = _trace().text()
    assert [line.split(" ", 1)[0] for line in text.splitlines()] == ["entry", "operation", "verdict"]
    assert _trace().record() == record and _trace().text() == text


def test_abstract_state_round_trips_all_fields_through_canonical_json() -> None:
    from openultrasast.semantic.obligations.trace import parse_abstract_state

    state = _abstract_state()
    record = _trace(abstract_state=state).record()
    assert json.loads(json.dumps(record)) == record
    assert parse_abstract_state(record["abstract_state"]) == state
    assert _trace(abstract_state=state).record() == record


def test_canonical_value_encoding_names_every_domain_value_stably() -> None:
    # EvidenceRelation and PairJudgment encode as their value strings; ResourceRef, AuthorityRef and
    # Completeness encode as sorted field dicts, so the canonical form is deterministic (Req 9.5).
    payload = _trace(abstract_state=_abstract_state()).record()["abstract_state"]
    assert list(payload) == sorted(payload)
    assert payload["path_judgment"]["judgment"] == "unguarded"
    assert payload["path_judgment"]["completeness"] == {
        "is_complete": False,
        "reasons": ["resolution:ambiguous_call", "matching:unknown_resource", "matching:unknown_authority"],
    }
    assert payload["path_judgment"]["matches"] == [
        {"authority_relation": "no", "evidence": ["implication:admin_role"], "relation": "must", "resource_relation": "may"}
    ]
    assert payload["resource"] == {"kind": "exact", "values": ["doc:1"]}
    assert payload["authority"] == {"is_unknown": False, "values": ["admin"]}
    assert payload["resource_relation"] == "may"
    assert payload["authority_relation"] == "unknown"


def test_abstract_text_appends_one_deterministic_abstract_component() -> None:
    legacy = _trace().text()
    extended = _trace(abstract_state=_abstract_state()).text()
    assert extended.startswith(legacy)
    lines = extended.splitlines()
    assert lines[-1].startswith("abstract ")
    assert json.loads(lines[-1][len("abstract ") :]) == _trace(abstract_state=_abstract_state()).record()["abstract_state"]
    assert extended == _trace(abstract_state=_abstract_state()).text()


def test_every_incompleteness_reason_survives_the_round_trip() -> None:
    # Req 7.2's reason vocabulary, including unknown resource and unknown authority, is preserved in
    # the trace (Req 7.5, 9.6) rather than folded into a quieter summary.
    from dataclasses import replace

    from openultrasast.semantic.obligations.abstract_domain import Completeness
    from openultrasast.semantic.obligations.trace import parse_abstract_state

    reasons = (
        "recognition:framework_unrecognised",
        "resolution:unresolved_call",
        "resolution:ambiguous_call",
        "summary:exploration_cutoff",
        "dominance:cfg_unavailable",
        "matching:unknown_resource",
        "matching:unknown_authority",
        "judgment:analysis_exception",
    )
    state = _abstract_state()
    state = replace(state, path_judgment=replace(state.path_judgment, completeness=Completeness(False, reasons)))
    parsed = parse_abstract_state(_trace(abstract_state=state).record()["abstract_state"])
    assert parsed.path_judgment.completeness.reasons == reasons
    assert parsed.path_judgment.completeness.is_complete is False


def test_parse_abstract_state_rejects_unknown_judgment_values() -> None:
    import pytest

    from openultrasast.semantic.obligations.trace import parse_abstract_state

    payload = _trace(abstract_state=_abstract_state()).record()["abstract_state"]
    payload["path_judgment"]["judgment"] = "probably_fine"
    with pytest.raises(ValueError):
        parse_abstract_state(payload)


def test_build_trace_carries_abstract_state_as_an_opt_in_argument() -> None:
    text = "def entry(item):\n    read(item)\n"
    ir = parse_python_ast("app.py", text)
    facts = ObligationFacts("1", (OperationFact("read", "protected_read", "python", ("read",), None, ("path_guard",), "high"),), ())
    result = build_trace(
        path=PathRecord((("app.py::entry", None),), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 2, "entry", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
        abstract_state=_abstract_state(),
    )
    assert result.abstract_state == _abstract_state()
    assert result.record()["abstract_state"]["path_judgment"]["judgment"] == "unguarded"


def test_coverage_counts_pair_judgments_without_changing_legacy_fields() -> None:
    # Req 7.1, 7.6: the coverage contract gains the three pair judgment counts additively; the
    # legacy constructor call and fields stay valid and the record stays pure JSON.
    from dataclasses import asdict

    from openultrasast.hunt.prover import Coverage
    from openultrasast.semantic.obligations.abstract_domain import PairJudgmentCounts

    coverage = Coverage({"python": 1}, {}, 1, 1, 0, 1, 1, {"parse_failed": 1})
    assert coverage.pair_judgments == PairJudgmentCounts()
    serialized = asdict(coverage)
    assert json.loads(json.dumps(serialized)) == serialized
    assert serialized["pair_judgments"] == {"unguarded": 0, "discharged": 0, "indeterminate": 0}
