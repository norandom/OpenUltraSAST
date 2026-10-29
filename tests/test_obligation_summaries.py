"""Task 9.1 -- local function summaries: determinism, no caller traversal."""

from __future__ import annotations

import inspect

import pytest

from openultrasast.semantic.cst import declaration_scopes
from openultrasast.semantic.ir import CallSite, FunctionIR
from openultrasast.semantic.obligations import summaries
from openultrasast.semantic.obligations.abstract_domain import Completeness
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.resolution import SymbolId, SymbolIndex
from openultrasast.semantic.obligations.summaries import FunctionSummary, local_summaries, monotone_summaries

PHP_CLASS = """<?php
class InvoiceController {
    public function preview($fields) {
        return $this->render($fields);
    }
}
"""

JAVA_ONE_CLASS = """public class Handler {
    public void handle() {
        this.run();
    }
    void run() {
    }
}
"""

JAVA_TWO_CLASSES = """public class Auditor {
    public boolean check() {
        return true;
    }
}
class Gate {
    public boolean check() {
        return false;
    }
}
"""

JAVA_SELF_LOOP = """public class Node {
    int walk() {
        return this.walk();
    }
}
"""

JAVA_MUTUAL = """public class C {
    void a() {
        this.b();
    }
    void b() {
        this.a();
    }
}
"""

JAVA_CHAIN = """public class Chain {
    void helper1() {
        this.helper2();
    }
    void helper2() {
    }
}
"""

JAVA_THREE_CYCLE = """public class Ring {
    void a() {
        this.b();
    }
    void b() {
        this.c();
    }
    void c() {
        this.a();
    }
}
"""


def _self_call(name: str, line: int, arity: int = 0) -> CallSite:
    return CallSite(name, line, (), (), (), False, 0, receiver="this", arity=arity)


def _named_operation(path: str, function_name: str, resource: str) -> Operation:
    return Operation(
        path=path,
        line=3,
        function=function_name,
        kind="protected_read",
        fact_id="java:protected-read",
        resource=resource,
        requires=("path_guard",),
    )


def _scope_functions(fixture: str, path: str, language: str) -> tuple[FunctionIR, ...]:
    scopes = declaration_scopes(path, fixture, language)
    assert scopes, f"fixture produced no declaration scopes: {path}"
    functions = []
    for scope in scopes:
        calls = (CallSite("render", 4, (), (), (), False, 0),) if scope.function_name == "preview" else ()
        functions.append(
            FunctionIR(
                name=scope.function_name,
                params=scope.params,
                start_line=scope.start_line,
                end_line=scope.start_line + 3,
                binds=(),
                calls=calls,
            )
        )
    return tuple(functions)


def _index(fixtures: tuple[tuple[str, str, str], ...]) -> SymbolIndex:
    return SymbolIndex.build(fixtures)


def _operation(function_name: str) -> Operation:
    return Operation(
        path="src/InvoiceController.php",
        line=3,
        function=function_name,
        kind="protected_read",
        fact_id="php:protected-read",
        resource="invoice",
        requires=("path_guard",),
    )


def _witness(function_name: str) -> Discharge:
    return Discharge(
        path="src/InvoiceController.php",
        line=2,
        function=function_name,
        kind="path_guard",
        fact_id="php:authorize",
        provenance="call",
        scope="statement",
        detail="authorize",
    )


def test_empty_function_produces_a_complete_empty_summary() -> None:
    index = _index((("src/Handler.java", JAVA_ONE_CLASS, "java"),))
    functions = {"src/Handler.java": (FunctionIR("run", (), 7, 8, (), ()),)}
    (summary,) = local_summaries(functions, index)
    assert summary.symbol.name == "run"
    assert summary.operations == ()
    assert summary.witnesses == ()
    assert summary.calls == ()
    assert summary.completeness == Completeness(is_complete=True)


def test_unresolved_call_leaves_local_completeness_incomplete() -> None:
    index = _index((("src/Handler.java", JAVA_ONE_CLASS, "java"),))
    calls = (CallSite("missing", 3, (), (), (), False, 0),)
    functions = {"src/Handler.java": (FunctionIR("handle", (), 2, 5, (), calls),)}
    (summary,) = local_summaries(functions, index)
    assert summary.completeness.is_complete is False
    assert "resolution:no_candidate" in summary.completeness.reasons


def test_variable_receiver_call_stays_incomplete() -> None:
    index = _index((("src/Auditor.java", JAVA_TWO_CLASSES, "java"),))
    calls = (CallSite("check", 2, (), (), (), False, 0, receiver="auditor", arity=0),)
    functions = {"src/Auditor.java": (FunctionIR("review", (), 2, 4, (), calls),)}
    (summary,) = local_summaries(functions, index)
    assert len(summary.calls[0].targets) == 2
    assert summary.completeness.is_complete is False
    assert "resolution:receiver_type_unknown" in summary.completeness.reasons


def test_exact_self_call_is_complete() -> None:
    index = _index((("src/Handler.java", JAVA_ONE_CLASS, "java"),))
    calls = (CallSite("run", 3, (), (), (), False, 0, receiver="this", arity=0),)
    functions = {"src/Handler.java": (FunctionIR("handle", (), 2, 5, (), calls),)}
    (summary,) = local_summaries(functions, index)
    assert len(summary.calls[0].targets) == 1
    assert summary.completeness == Completeness(is_complete=True)


def test_injected_operations_and_witnesses_are_preserved() -> None:
    index = _index((("src/InvoiceController.php", PHP_CLASS, "php"),))
    scopes = declaration_scopes("src/InvoiceController.php", PHP_CLASS, "php")
    preview_scope = scopes[0]
    functions = {"src/InvoiceController.php": (FunctionIR(preview_scope.function_name, preview_scope.params, 3, 5, (), ()),)}
    symbol = local_summaries(functions, index)[0].symbol
    operations = {symbol: (_operation(preview_scope.function_name),)}
    witnesses = {symbol: (_witness(preview_scope.function_name),)}
    (summary,) = local_summaries(functions, index, operations_by_symbol=operations, witnesses_by_symbol=witnesses)
    assert summary.operations == (_operation(preview_scope.function_name),)
    assert summary.witnesses == (_witness(preview_scope.function_name),)


def test_summary_symbol_carries_enclosing_type_and_signature() -> None:
    index = _index((("src/InvoiceController.php", PHP_CLASS, "php"),))
    functions = {"src/InvoiceController.php": (FunctionIR("preview", ("$fields",), 3, 5, (), ()),)}
    (summary,) = local_summaries(functions, index)
    assert summary.symbol.enclosing_type == "InvoiceController"
    assert summary.symbol.signature == ("$fields",)


def test_summaries_are_deterministic_across_builds() -> None:
    index = _index(
        (
            ("src/InvoiceController.php", PHP_CLASS, "php"),
            ("src/Handler.java", JAVA_ONE_CLASS, "java"),
        )
    )
    functions = {
        "src/Handler.java": (FunctionIR("handle", (), 2, 5, (), ()),),
        "src/InvoiceController.php": (FunctionIR("preview", ("$fields",), 3, 5, (), ()),),
    }
    assert local_summaries(functions, index) == local_summaries(functions, index)


def test_module_text_contains_no_target_names() -> None:
    module_source = inspect.getsource(summaries)
    for target_name in ("symfony", "laravel", "tornado", "wordpress", "stapler", "jetty", "rails", "spring"):
        assert target_name not in module_source.lower()


def test_function_summary_is_frozen() -> None:
    summary = FunctionSummary.__new__(FunctionSummary)
    with pytest.raises(Exception, match="cannot assign|frozen"):
        summary.symbol = None  # type: ignore[misc,assignment]


def _symbol_by_name(summaries: tuple[FunctionSummary, ...], name: str) -> SymbolId:
    for summary in summaries:
        if summary.symbol.name == name:
            return summary.symbol
    raise AssertionError(f"no summary named {name}")


def test_direct_recursion_terminates_with_stable_operations() -> None:
    index = _index((("src/Node.java", JAVA_SELF_LOOP, "java"),))
    walk = FunctionIR("walk", (), 2, 4, (), (_self_call("walk", 3),))
    functions = {"src/Node.java": (walk,)}
    local = local_summaries(functions, index)
    operations = {_symbol_by_name(local, "walk"): (_named_operation("src/Node.java", "walk", "node"),)}
    result = monotone_summaries(functions, index, operations_by_symbol=operations)
    assert len(result) == 1
    assert result[0].operations == (_named_operation("src/Node.java", "walk", "node"),)
    assert result[0].completeness == Completeness(is_complete=True)


def test_mutual_recursion_shares_accumulated_operations_and_witnesses() -> None:
    index = _index((("src/C.java", JAVA_MUTUAL, "java"),))
    function_a = FunctionIR("a", (), 2, 4, (), (_self_call("b", 3),))
    function_b = FunctionIR("b", (), 5, 7, (), (_self_call("a", 6),))
    functions = {"src/C.java": (function_a, function_b)}
    local = local_summaries(functions, index)
    symbol_b = _symbol_by_name(local, "b")
    operations = {symbol_b: (_named_operation("src/C.java", "b", "shared"),)}
    witnesses = {symbol_b: (_witness("b"),)}
    result = monotone_summaries(functions, index, operations_by_symbol=operations, witnesses_by_symbol=witnesses)
    shared = (_named_operation("src/C.java", "b", "shared"),)
    by_name = {summary.symbol.name: summary for summary in result}
    assert by_name["a"].operations == shared
    assert by_name["b"].operations == shared
    assert by_name["a"].witnesses == (_witness("b"),)


def test_chain_helper_propagates_operations_to_caller() -> None:
    index = _index((("src/Chain.java", JAVA_CHAIN, "java"),))
    helper1 = FunctionIR("helper1", (), 2, 4, (), (_self_call("helper2", 3),))
    helper2 = FunctionIR("helper2", (), 5, 6, (), ())
    functions = {"src/Chain.java": (helper1, helper2)}
    local = local_summaries(functions, index)
    operations = {_symbol_by_name(local, "helper2"): (_named_operation("src/Chain.java", "helper2", "chain"),)}
    result = monotone_summaries(functions, index, operations_by_symbol=operations)
    by_name = {summary.symbol.name: summary for summary in result}
    assert by_name["helper1"].operations == (_named_operation("src/Chain.java", "helper2", "chain"),)
    assert by_name["helper1"].completeness == Completeness(is_complete=True)


def test_candidate_edges_never_propagate_operations() -> None:
    index = _index((("src/Auditor.java", JAVA_TWO_CLASSES, "java"),))
    review_calls = (CallSite("check", 2, (), (), (), False, 0, receiver="auditor", arity=0),)
    review = FunctionIR("review", (), 2, 4, (), review_calls)
    check = FunctionIR("check", (), 2, 4, (), ())
    functions = {"src/Auditor.java": (review, check)}
    local = local_summaries(functions, index)
    auditor_symbol = next(symbol for symbol in (s.symbol for s in local) if symbol.enclosing_type == "Auditor")
    operations = {auditor_symbol: (_named_operation("src/Auditor.java", "check", "auditor"),)}
    result = monotone_summaries(functions, index, operations_by_symbol=operations)
    by_name = {(summary.symbol.enclosing_type, summary.symbol.name): summary for summary in result}
    assert by_name[(None, "review")].operations == ()
    assert by_name[("Auditor", "check")].operations == (_named_operation("src/Auditor.java", "check", "auditor"),)


def test_incomplete_callee_reason_propagates_to_caller() -> None:
    index = _index((("src/Chain.java", JAVA_CHAIN, "java"),))
    helper1 = FunctionIR("helper1", (), 2, 4, (), (_self_call("helper2", 3),))
    helper2 = FunctionIR("helper2", (), 5, 6, (), (CallSite("missing", 6, (), (), (), False, 0),))
    functions = {"src/Chain.java": (helper1, helper2)}
    result = monotone_summaries(functions, index)
    by_name = {summary.symbol.name: summary for summary in result}
    assert by_name["helper2"].completeness.is_complete is False
    assert by_name["helper1"].completeness.is_complete is False
    assert "resolution:no_candidate" in by_name["helper1"].completeness.reasons


def test_three_cycle_accumulates_all_operations() -> None:
    index = _index((("src/Ring.java", JAVA_THREE_CYCLE, "java"),))
    function_a = FunctionIR("a", (), 2, 4, (), (_self_call("b", 3),))
    function_b = FunctionIR("b", (), 5, 7, (), (_self_call("c", 6),))
    function_c = FunctionIR("c", (), 8, 10, (), (_self_call("a", 9),))
    functions = {"src/Ring.java": (function_a, function_b, function_c)}
    local = local_summaries(functions, index)
    operations = {
        _symbol_by_name(local, "a"): (_named_operation("src/Ring.java", "a", "ring-a"),),
        _symbol_by_name(local, "b"): (_named_operation("src/Ring.java", "b", "ring-b"),),
        _symbol_by_name(local, "c"): (_named_operation("src/Ring.java", "c", "ring-c"),),
    }
    result = monotone_summaries(functions, index, operations_by_symbol=operations)
    accumulated = (
        _named_operation("src/Ring.java", "a", "ring-a"),
        _named_operation("src/Ring.java", "b", "ring-b"),
        _named_operation("src/Ring.java", "c", "ring-c"),
    )
    for summary in result:
        assert summary.operations == accumulated


def test_monotone_summaries_are_deterministic() -> None:
    index = _index((("src/C.java", JAVA_MUTUAL, "java"),))
    function_a = FunctionIR("a", (), 2, 4, (), (_self_call("b", 3),))
    function_b = FunctionIR("b", (), 5, 7, (), (_self_call("a", 6),))
    functions = {"src/C.java": (function_a, function_b)}
    assert monotone_summaries(functions, index) == monotone_summaries(functions, index)


def test_monotone_output_order_matches_local_summaries() -> None:
    index = _index((("src/C.java", JAVA_MUTUAL, "java"),))
    function_a = FunctionIR("a", (), 2, 4, (), (_self_call("b", 3),))
    function_b = FunctionIR("b", (), 5, 7, (), (_self_call("a", 6),))
    functions = {"src/C.java": (function_a, function_b)}
    assert [summary.symbol for summary in monotone_summaries(functions, index)] == [
        summary.symbol for summary in local_summaries(functions, index)
    ]
