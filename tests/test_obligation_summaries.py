"""Task 9.1 -- local function summaries: determinism, no caller traversal."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from time import monotonic

import pytest

from openultrasast.semantic.cst import declaration_scopes
from openultrasast.semantic.ir import CallSite, FunctionIR
from openultrasast.semantic.obligations import summaries
from openultrasast.semantic.obligations.abstract_domain import Completeness
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.resolution import SymbolId, SymbolIndex
from openultrasast.semantic.obligations.summaries import (
    EvidencePath,
    ExplorationBudget,
    FunctionSummary,
    candidate_call_edges,
    exact_call_edges,
    exact_evidence_paths,
    local_summaries,
    monotone_summaries,
)

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


JAVA_FANOUT = """
class Fan {
    void helper1() { this.helper2(); this.helper3(); }
    void helper2() {}
    void helper3() {}
}
""".strip()


def _java_operation(name: str, line: int) -> Operation:
    return Operation(
        path="src/C.java",
        line=line,
        function=name,
        kind="protected_read",
        fact_id=f"java:{name}-op",
        resource=name,
        requires=("path_guard",),
    )


def _fanout_functions() -> dict[str, tuple[FunctionIR, ...]]:
    return {
        "src/C.java": (
            FunctionIR(
                "helper1",
                (),
                3,
                3,
                (),
                (_self_call("helper2", 3), _self_call("helper3", 3)),
            ),
            FunctionIR("helper2", (), 4, 4, (), ()),
            FunctionIR("helper3", (), 5, 5, (), ()),
        )
    }


def _mutual_functions() -> dict[str, tuple[FunctionIR, ...]]:
    return {
        "src/C.java": (
            FunctionIR("a", (), 2, 4, (), (_self_call("b", 3),)),
            FunctionIR("b", (), 5, 7, (), (_self_call("a", 6),)),
        )
    }


def _operations_injected(
    functions: dict[str, tuple[FunctionIR, ...]], index: SymbolIndex, injected: dict[str, Operation]
) -> dict[SymbolId, tuple[Operation, ...]]:
    operations_by_symbol: dict[SymbolId, tuple[Operation, ...]] = {}
    for summary in local_summaries(functions, index):
        operation = injected.get(summary.symbol.name)
        if operation is not None:
            operations_by_symbol[summary.symbol] = (operation,)
    return operations_by_symbol


def test_depth_cutoff_preserves_accumulated_evidence_and_reason() -> None:
    index = _index((("src/C.java", JAVA_MUTUAL, "java"),))
    functions = _mutual_functions()
    operations_by_symbol = _operations_injected(functions, index, {"b": _java_operation("b", 6)})
    summaries_with_cutoff = monotone_summaries(
        functions, index, operations_by_symbol=operations_by_symbol, budget=ExplorationBudget(depth=1)
    )
    summaries_unbounded = monotone_summaries(functions, index, operations_by_symbol=operations_by_symbol)
    by_name = {summary.symbol.name: summary for summary in summaries_with_cutoff}
    unbounded_by_name = {summary.symbol.name: summary for summary in summaries_unbounded}
    assert by_name["a"].operations == unbounded_by_name["a"].operations
    assert by_name["a"].operations == (_java_operation("b", 6),)
    assert "summaries:depth_cutoff" in by_name["a"].completeness.reasons
    assert "summaries:depth_cutoff" in by_name["b"].completeness.reasons
    assert not by_name["a"].completeness.is_complete


def test_deadline_cutoff_returns_local_evidence() -> None:
    index = _index((("src/C.java", JAVA_FANOUT, "java"),))
    functions = _fanout_functions()
    operations_by_symbol = _operations_injected(
        functions, index, {"helper2": _java_operation("helper2", 4), "helper3": _java_operation("helper3", 5)}
    )
    summaries_with_cutoff = monotone_summaries(
        functions, index, operations_by_symbol=operations_by_symbol, budget=ExplorationBudget(deadline=monotonic() - 1.0)
    )
    by_name = {summary.symbol.name: summary for summary in summaries_with_cutoff}
    assert by_name["helper1"].operations == ()
    assert "summaries:deadline_cutoff" in by_name["helper1"].completeness.reasons
    assert not by_name["helper1"].completeness.is_complete
    assert by_name["helper2"].completeness.is_complete
    assert by_name["helper2"].operations == (_java_operation("helper2", 4),)


def test_fan_out_cutoff_merges_sorted_prefix() -> None:
    index = _index((("src/C.java", JAVA_FANOUT, "java"),))
    functions = _fanout_functions()
    operations_by_symbol = _operations_injected(
        functions, index, {"helper2": _java_operation("helper2", 4), "helper3": _java_operation("helper3", 5)}
    )
    summaries_with_cutoff = monotone_summaries(
        functions, index, operations_by_symbol=operations_by_symbol, budget=ExplorationBudget(fan_out=1)
    )
    by_name = {summary.symbol.name: summary for summary in summaries_with_cutoff}
    assert by_name["helper1"].operations == (_java_operation("helper2", 4),)
    assert "summaries:fan_out_cutoff" in by_name["helper1"].completeness.reasons
    assert not by_name["helper1"].completeness.is_complete
    assert by_name["helper3"].completeness.is_complete


def test_all_none_budget_equals_default_behaviour() -> None:
    index = _index((("src/C.java", JAVA_MUTUAL, "java"),))
    functions = _mutual_functions()
    operations_by_symbol = _operations_injected(functions, index, {"b": _java_operation("b", 6)})
    with_default = monotone_summaries(functions, index, operations_by_symbol=operations_by_symbol)
    with_empty_budget = monotone_summaries(functions, index, operations_by_symbol=operations_by_symbol, budget=ExplorationBudget())
    assert with_default == with_empty_budget


def test_exploration_budget_is_frozen() -> None:
    budget = ExplorationBudget(depth=1)
    with pytest.raises(FrozenInstanceError):
        budget.depth = 2  # type: ignore[misc]


def test_cutoff_reasons_join_existing_incompleteness() -> None:
    index = _index((("src/C.java", JAVA_FANOUT, "java"),))
    functions = {
        "src/C.java": (
            FunctionIR(
                "helper1",
                (),
                3,
                3,
                (),
                (_self_call("helper2", 3), CallSite("missing", 3, (), (), (), False, 0)),
            ),
            FunctionIR("helper2", (), 4, 4, (), ()),
        )
    }
    summaries_with_cutoff = monotone_summaries(functions, index, budget=ExplorationBudget(deadline=monotonic() - 1.0))
    by_name = {summary.symbol.name: summary for summary in summaries_with_cutoff}
    reasons = by_name["helper1"].completeness.reasons
    assert "resolution:no_candidate" in reasons
    assert "summaries:deadline_cutoff" in reasons


# --- Task 9.4: exact evidence paths (Reqs 3.9, 3.10, 11.4, 11.5) ---

JAVA_ENTRY_CHAIN = """class Handler {
    public void handle() {
        this.run("job");
    }
    public void run(String command) {
        this.persist(command);
    }
    public void persist(String payload) {
    }
}
"""

JAVA_TWO_ROUTES = """class Gate {
    public void enter() {
        this.left();
        this.right();
    }
    public void left() {
        this.vault();
    }
    public void right() {
        this.vault();
    }
    public void vault() {
    }
}
"""


JAVA_AUDITOR = """class Auditor {
    public void check() {
    }
}
class Gate {
    public void check() {
    }
}
"""


def _chain_index() -> SymbolIndex:
    return SymbolIndex.build(
        (
            ("src/Handler.java", JAVA_ENTRY_CHAIN, "java"),
            ("src/Auditor.java", JAVA_AUDITOR, "java"),
        )
    )


def _routes_index() -> SymbolIndex:
    return SymbolIndex.build((("src/Gate.java", JAVA_TWO_ROUTES, "java"),))


def _chain_functions() -> dict[str, tuple[FunctionIR, ...]]:
    return {
        "src/Handler.java": (
            FunctionIR("handle", (), 2, 4, (), (CallSite("run", 3, (), (), (), False, 0, receiver="this", arity=1),)),
            FunctionIR("run", ("command",), 5, 7, (), (CallSite("persist", 6, (), (), (), False, 0, receiver="this", arity=1),)),
            FunctionIR("persist", ("payload",), 8, 9, (), ()),
        )
    }


def _routes_functions() -> dict[str, tuple[FunctionIR, ...]]:
    return {
        "src/Gate.java": (
            FunctionIR(
                "enter",
                (),
                2,
                5,
                (),
                (
                    CallSite("left", 3, (), (), (), False, 0, receiver="this"),
                    CallSite("right", 4, (), (), (), False, 0, receiver="this"),
                ),
            ),
            FunctionIR("left", (), 6, 8, (), (CallSite("vault", 7, (), (), (), False, 0, receiver="this"),)),
            FunctionIR("right", (), 9, 11, (), (CallSite("vault", 10, (), (), (), False, 0, receiver="this"),)),
            FunctionIR("vault", (), 12, 13, (), ()),
        )
    }


def _symbol(index: SymbolIndex, name: str) -> SymbolId:
    return next(symbol for symbol in index.by_name[name] if symbol.module == "src/Handler.java")


def _routes_symbol(index: SymbolIndex, name: str) -> SymbolId:
    return next(symbol for symbol in index.by_name[name] if symbol.module == "src/Gate.java")


def test_exact_edges_carry_call_site_lines() -> None:
    index = _chain_index()
    edges = exact_call_edges(_chain_functions(), index)
    pairs = {(edge.caller.name, edge.callee.name): edge.line for edge in edges}
    assert pairs[("handle", "run")] == 3
    assert pairs[("run", "persist")] == 6


def test_entry_chain_emits_hops_from_entry_to_operation() -> None:
    index = _chain_index()
    edges = exact_call_edges(_chain_functions(), index)
    persist_symbol = _symbol(index, "persist")
    paths = exact_evidence_paths(
        (_symbol(index, "handle"),),
        edges,
        operations_by_symbol={persist_symbol: (_java_operation("persist", 9),)},
    )
    assert len(paths) == 1
    assert paths[0].entry.name == "handle"
    assert paths[0].target.name == "persist"
    assert [hop.callee.name for hop in paths[0].hops] == ["run", "persist"]
    assert paths[0].hops[0].line == 3


def test_entry_itself_holding_an_operation_emits_a_zero_hop_path() -> None:
    index = _chain_index()
    edges = exact_call_edges(_chain_functions(), index)
    handle_symbol = _symbol(index, "handle")
    paths = exact_evidence_paths(
        (handle_symbol,),
        edges,
        operations_by_symbol={handle_symbol: (_java_operation("handle", 3),)},
    )
    assert paths == (EvidencePath(entry=handle_symbol, target=handle_symbol, hops=()),)


def test_two_complete_chains_to_one_operation_stay_independent() -> None:
    index = _routes_index()
    edges = exact_call_edges(_routes_functions(), index)
    enter = _routes_symbol(index, "enter")
    vault = _routes_symbol(index, "vault")
    paths = exact_evidence_paths(
        (enter,),
        edges,
        operations_by_symbol={vault: (_java_operation("vault", 12),)},
    )
    routes = sorted(tuple(hop.callee.name for hop in path.hops) for path in paths)
    assert routes == [("left", "vault"), ("right", "vault")]
    assert all(path.target == vault for path in paths)


def test_candidate_edges_never_complete_a_path() -> None:
    index = _chain_index()
    functions = {
        "src/Handler.java": (FunctionIR("handle", (), 2, 4, (), (CallSite("check", 3, (), (), (), False, 0, receiver="auditor"),)),)
        + _chain_functions()["src/Handler.java"][1:]
    }
    edges = exact_call_edges(functions, index)
    auditor = next(symbol for symbol in index.by_name["check"] if symbol.module == "src/Auditor.java")
    paths = exact_evidence_paths(
        (_symbol(index, "handle"),),
        edges,
        operations_by_symbol={auditor: (_java_operation("check", 1),)},
    )
    assert paths == ()
    diagnostics = candidate_call_edges(functions, index)
    assert len(diagnostics) == 1
    assert diagnostics[0].caller.name == "handle"
    assert diagnostics[0].reason == "resolution:receiver_type_unknown"
    assert any(candidate.enclosing_type == "Auditor" for candidate in diagnostics[0].candidates)


def test_exact_evidence_paths_are_deterministic() -> None:
    index = _routes_index()
    edges = exact_call_edges(_routes_functions(), index)
    enter = _routes_symbol(index, "enter")
    vault = _routes_symbol(index, "vault")
    operations = {vault: (_java_operation("vault", 12),)}
    assert exact_evidence_paths((enter,), edges, operations_by_symbol=operations) == exact_evidence_paths(
        (enter,), edges, operations_by_symbol=operations
    )
