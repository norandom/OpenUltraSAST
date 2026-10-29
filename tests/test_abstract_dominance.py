"""Strict abstract-dominance relations over the CFG (Task 10.1, Reqs 10.1-10.7)."""

import pytest

from openultrasast.semantic.cfg import FunctionCfg
from openultrasast.semantic.cst import parse_function_nodes
from openultrasast.semantic.extra import grammar_for
from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation
from openultrasast.semantic.obligations.cfg_dominance import CfgDominance, DominanceEvidence
from openultrasast.semantic.obligations.operations import Discharge, Operation

PATH = "src/C.java"

JAVA_GUARD = """class C {
    void handle(Request request) {
        if (!request.user.isAdmin()) { throw new IllegalStateException(); }
        request.store.deleteAll();
    }
}
"""

JAVA_VALUE_ONLY = """class C {
    void handle(Request request) {
        boolean admin = request.user.isAdmin();
        request.store.deleteAll();
    }
}
"""

JAVA_AFTER = """class C {
    void handle(Request request) {
        request.store.deleteAll();
        if (!request.user.isAdmin()) { throw new IllegalStateException(); }
    }
}
"""

JAVA_SOME_PATHS = """class C {
    void handle(Request request) {
        if (request.flag) {
            if (!request.user.isAdmin()) { throw new IllegalStateException(); }
        }
        request.store.deleteAll();
    }
}
"""


def _witness(line: int | None, *, kind: str = "path_guard", scope: str = "statement") -> Discharge:
    return Discharge(
        path=PATH,
        line=line,
        function="handle",
        kind=kind,
        fact_id="f:guard",
        provenance="call",
        scope=scope,
        detail="",
    )


def _operation(line: int) -> Operation:
    return Operation(
        path=PATH,
        line=line,
        function="handle",
        kind="protected_read",
        fact_id="f:op",
        resource="store",
        requires=("path_guard",),
    )


def _dominance(text: str) -> CfgDominance:
    if grammar_for("java") is None:
        pytest.skip("no Java grammar installed")
    nodes = parse_function_nodes(PATH, text, "java")
    assert nodes, "the parser read no function"
    cfg = FunctionCfg.from_cst(nodes[0], "java")
    return CfgDominance({PATH: text}, {(PATH, "handle"): cfg})


def _lines(text: str) -> dict[str, int]:
    file_lines = text.splitlines()
    return {
        "guard": next(number for number, line_text in enumerate(file_lines, start=1) if "isAdmin" in line_text),
        "operation": next(number for number, line_text in enumerate(file_lines, start=1) if "deleteAll" in line_text),
    }


def test_throwing_guard_on_all_paths_is_must() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    evidence = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.MUST
    assert evidence.guard_effect == "throws"


def test_value_only_guard_on_all_paths_is_no() -> None:
    dominance = _dominance(JAVA_VALUE_ONLY)
    lines = _lines(JAVA_VALUE_ONLY)
    evidence = dominance.evidence(_witness(lines["guard"], kind="ownership_check"), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.NO
    assert evidence.guard_effect == "value_only"


def test_guard_after_operation_is_no() -> None:
    dominance = _dominance(JAVA_AFTER)
    lines = _lines(JAVA_AFTER)
    evidence = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.NO


def test_branch_conditional_guard_is_may() -> None:
    dominance = _dominance(JAVA_SOME_PATHS)
    lines = _lines(JAVA_SOME_PATHS)
    evidence = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.MAY


def test_missing_graph_is_unknown_never_order_fallback() -> None:
    dominance = CfgDominance({PATH: JAVA_GUARD}, {})
    lines = _lines(JAVA_GUARD)
    evidence = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.UNKNOWN
    assert evidence.reason == "cfg_unavailable"


def test_line_without_graph_node_is_unknown() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    evidence = dominance.evidence(_witness(1), _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.UNKNOWN
    assert evidence.reason == "line_without_node"


def test_cross_function_witness_is_unknown_never_order() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    cross_function_witness = Discharge(
        path=PATH,
        line=lines["guard"],
        function="other",
        kind="path_guard",
        fact_id="f:guard",
        provenance="call",
        scope="hop",
        detail="",
    )
    evidence = dominance.evidence(cross_function_witness, _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.UNKNOWN
    assert evidence.reason == "dominance:cross_function"


def test_scoped_witness_dominates_whole_handler() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    scoped = _witness(None, scope="router")
    evidence = dominance.evidence(scoped, _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.MUST


def test_in_operation_witness_same_line_is_must() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    constraint = _witness(lines["operation"], kind="identity_constraint")
    evidence = dominance.evidence(constraint, _operation(lines["operation"]))
    assert evidence.relation is EvidenceRelation.MUST


def test_legacy_boolean_surface_unchanged() -> None:
    dominance = CfgDominance({PATH: JAVA_GUARD}, {})
    lines = _lines(JAVA_GUARD)
    assert dominance.dominates(_witness(lines["guard"]), _operation(lines["operation"]), ()) is True
    assert isinstance(dominance.relation(_witness(lines["guard"]), _operation(lines["operation"])), str)


def test_dominance_evidence_is_frozen() -> None:
    evidence = DominanceEvidence(relation=EvidenceRelation.MUST, guard_effect="throws", reason=None)
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises on assignment
        evidence.relation = EvidenceRelation.NO  # type: ignore[misc]


def test_evidence_is_deterministic() -> None:
    dominance = _dominance(JAVA_GUARD)
    lines = _lines(JAVA_GUARD)
    first = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    second = dominance.evidence(_witness(lines["guard"]), _operation(lines["operation"]))
    assert first == second
