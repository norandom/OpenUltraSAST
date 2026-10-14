"""Ordered traces preserve argument origins across a bounded caller chain."""

import json
from types import SimpleNamespace

from openultrasast.semantic.ir import parse_python_ast
from openultrasast.semantic.obligations.dominance import OrderDominance
from openultrasast.semantic.obligations.facts import DischargerFact, ObligationFacts, OperationFact
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.paths import PathRecord
from openultrasast.semantic.obligations.trace import build_trace


def fixture():
    text = """def entry(item):
    guard()
    middle(item)
def middle(value):
    alias = value
    final(alias)
def final(key):
    owner = request.user
    limit = 7
    mystery = unrecognised()
    read(key, owner, limit, mystery)
    guard()
"""
    ir = parse_python_ast("app.py", text)
    facts = ObligationFacts(
        "1",
        (OperationFact("read", "protected_read", "python", ("read",), None, ("path_guard",), "high"),),
        (
            DischargerFact(
                "identity", "identity_constraint", "python", identity_sources=("request.user",), request_sources=("request.args",)
            ),
        ),
    )
    return text, ir, facts


def trace():
    text, ir, facts = fixture()
    return build_trace(
        path=PathRecord((("app.py::entry", 3), ("app.py::middle", 6), ("app.py::final", None)), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 11, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(
            Discharge("app.py", 2, "entry", "path_guard", "guard", "authenticated_context", "statement"),
            Discharge("app.py", 12, "final", "path_guard", "guard", "authenticated_context", "statement"),
        ),
        dominance=OrderDominance({"app.py": text}),
        dominating=("path_guard",),
        missing=None,
    )


def test_four_origins_and_three_hop_order():
    result = trace()
    assert result.arguments == (("key", "request_input"), ("owner", "authenticated_context"), ("limit", "constant"), ("mystery", "unknown"))
    assert [hop.function for hop in result.hops] == ["entry", "middle", "final"]
    assert result.hops[0].forwarded == ("item",)
    assert result.hops[1].forwarded == ("alias",)
    assert result.hops[0].guards_before_call[0].line == 2
    assert result.guards_after[0].line == 12


def test_deterministic_text_and_canonical_json():
    result = trace()
    assert result.text() == trace().text()
    assert [line.split(" ", 1)[0] for line in result.text().splitlines()] == [
        "entry",
        "hop",
        "hop",
        "hop",
        "operation",
        "guard_after",
        "verdict",
    ]
    record = result.record()
    assert json.loads(json.dumps(record)) == record
    assert list(record) == sorted(record)
    assert record == trace().record()
    assert not {"language", "framework", "repository", "size", "count"} & record.keys()


def test_recent_bind_sources_and_unknown_composites():
    text, _, facts = fixture()
    text = text.replace(
        "    read(key, owner, limit, mystery)",
        """    key = request.args['id']
    owner = external
    limit = [mystery]
    read(key, owner, limit, mystery)""",
    )
    ir = parse_python_ast("app.py", text)
    result = build_trace(
        path=PathRecord((("app.py::final", None),), "app.py::final", True),
        entry=SimpleNamespace(kind="route", trust_boundary="internal", access_level="unknown"),
        operation=Operation("app.py", 14, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert result.arguments == (("key", "request_input"), ("owner", "unknown"), ("limit", "unknown"), ("mystery", "unknown"))


def test_call_text_fallback_balances_nested_arguments():
    from dataclasses import replace

    text, ir, facts = fixture()
    text = text.replace("read(key, owner, limit, mystery)", "read(key, nested(owner, limit), 'a,b', mystery)")
    parsed = parse_python_ast("app.py", text)
    functions = tuple(replace(fn, calls=tuple(replace(call, arg_texts=()) for call in fn.calls)) for fn in parsed.functions)
    ir = replace(ir, functions=functions)
    result = build_trace(
        path=PathRecord((("app.py::final", None),), "app.py::final", True),
        entry=SimpleNamespace(kind="route", trust_boundary="network_request", access_level="unknown"),
        operation=Operation("app.py", 11, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert result.arguments == (
        ("key", "request_input"),
        ("nested(owner, limit)", "unknown"),
        ("'a,b'", "constant"),
        ("mystery", "unknown"),
    )


def test_request_alias_and_member_access_across_methods():
    text, _, facts = fixture()
    text = (
        text.replace("def middle(value):", "def middle(self, value):")
        .replace("def final(key):", "def final(self, key):")
        .replace("read(key, owner, limit, mystery)", "read(key.id, owner, limit, mystery)")
    )
    ir = parse_python_ast("app.py", text)
    result = build_trace(
        path=PathRecord((("app.py::entry", 3), ("app.py::middle", 6), ("app.py::final", None)), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 11, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert result.arguments[0] == ("key.id", "request_input")


def test_source_name_suffix_is_unknown():
    text, _, facts = fixture()
    text = text.replace("owner = request.user", "owner = request.users")
    ir = parse_python_ast("app.py", text)
    result = build_trace(
        path=PathRecord((("app.py::final", None),), "app.py::final", True),
        entry=SimpleNamespace(kind="route", trust_boundary="internal", access_level="unknown"),
        operation=Operation("app.py", 11, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert result.arguments[1] == ("owner", "unknown")


def test_guards_after_follow_return_order():
    text, _, facts = fixture()
    text = text.replace("    middle(item)", "    middle(item)\n    guard()").replace("    final(alias)", "    final(alias)\n    guard()")
    ir = parse_python_ast("app.py", text)
    result = build_trace(
        path=PathRecord((("app.py::entry", 3), ("app.py::middle", 7), ("app.py::final", None)), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 13, "final", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(
            Discharge("app.py", 4, "entry", "path_guard", "entry-after", "authenticated_context", "statement"),
            Discharge("app.py", 8, "middle", "path_guard", "middle-after", "authenticated_context", "statement"),
            Discharge("app.py", 14, "final", "path_guard", "final-after", "authenticated_context", "statement"),
        ),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert [guard.fact_id for guard in result.guards_after] == ["final-after", "middle-after", "entry-after"]


def test_control_components_include_branch_guard_without_discharge():
    from openultrasast.semantic.cfg import FunctionCfg
    from openultrasast.semantic.cst import parse_function_nodes
    from openultrasast.semantic.obligations.cfg_dominance import CfgDominance

    text = "def entry(item):\n    if enabled:\n        guard()\n    read(item)\n"
    ir = parse_python_ast("app.py", text)
    facts = ObligationFacts("1", (OperationFact("read", "protected_read", "python", ("read",), None, ("path_guard",), "high"),), ())
    nodes = parse_function_nodes("app.py", text, "python")
    if not nodes:
        import pytest

        pytest.skip("no Python grammar installed")
    dominance = CfgDominance({"app.py": text}, {("app.py", "entry"): FunctionCfg.from_cst(nodes[0], "python")})
    result = build_trace(
        path=PathRecord((("app.py::entry", None),), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 4, "entry", "protected_read", "read", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(Discharge("app.py", 3, "entry", "path_guard", "guard", "authenticated_context", "statement"),),
        dominance=dominance,
        dominating=(),
        missing="path_guard",
    )
    guard = result.hops[0].guards_before_call[0]
    assert (guard.relation, guard.effect) == ("some_paths", "throws")
    assert result.operation_context.conditions == () and result.record()["operation_context"]["in_loop"] is False
    assert '"relation":"some_paths"' in result.text()
    assert '"operation_context":' in result.text().splitlines()[-2]


def test_order_dominance_trace_names_relation_and_effect():
    record = trace().record()
    assert record["hops"][0]["guards_before_call"][0]["relation"] == "all_paths"
    assert record["hops"][0]["guards_before_call"][0]["effect"] == "throws"
    assert record["guards_after"][0]["relation"] == "after"
    assert record["operation_context"] == {"catches": [], "conditions": [], "in_loop": False, "in_try": False, "on_exception_path": False}


def test_handler_operation_arguments_are_parameter_origins():
    text = "def entry(self, item):\n    return item\n"
    ir = parse_python_ast("app.py", text)
    facts = ObligationFacts(
        "1", (OperationFact("handler", "protected_read", "python", (), None, ("path_guard",), "high", handlers=("entry",)),), ()
    )
    result = build_trace(
        path=PathRecord((("app.py::entry", None),), "app.py::entry", True),
        entry=SimpleNamespace(kind="route", trust_boundary="http_request", access_level="unknown"),
        operation=Operation("app.py", 1, "entry", "protected_read", "handler", None, ("path_guard",)),
        irs={"app.py": (ir, text)},
        facts=facts,
        witnesses=(),
        dominance=OrderDominance({"app.py": text}),
        dominating=(),
        missing="path_guard",
    )
    assert result.arguments == (("item", "request_input"),)
