"""Task 9.1 -- local function summaries: determinism, no caller traversal."""

from __future__ import annotations

import inspect

import pytest

from openultrasast.semantic.cst import declaration_scopes
from openultrasast.semantic.ir import CallSite, FunctionIR
from openultrasast.semantic.obligations import summaries
from openultrasast.semantic.obligations.abstract_domain import Completeness
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.resolution import SymbolIndex
from openultrasast.semantic.obligations.summaries import FunctionSummary, local_summaries

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
