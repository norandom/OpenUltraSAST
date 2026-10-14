"""CfgDominance: a guard counts only when control flow keeps the operation from running after it fails."""

import pytest

from openultrasast.semantic.cfg import FunctionCfg
from openultrasast.semantic.cst import parse_function_nodes
from openultrasast.semantic.extra import grammar_for
from openultrasast.semantic.obligations.cfg_dominance import CfgDominance, describe, operation_context
from openultrasast.semantic.obligations.dominance import Dominance, OrderDominance
from openultrasast.semantic.obligations.operations import Discharge, Operation
from openultrasast.semantic.obligations.paths import PathRecord

PATH = "T.java"


def setup(body, kind="ownership_check", marker="can("):
    if grammar_for("java") is None:
        pytest.skip("no Java grammar installed")
    text = "class T {\n Object handle(Item item) {\n" + "".join(f"  {line}\n" for line in body) + " }\n}\n"
    assert len(text.encode()) > 0
    nodes = parse_function_nodes(PATH, text, "java")
    assert nodes, "the parser read no function"
    cfg = FunctionCfg.from_cst(nodes[0], "java")
    lines = text.splitlines()
    guard_line = next(number for number, line in enumerate(lines, 1) if marker in line)
    op_line = next(number for number, line in enumerate(lines, 1) if "read(" in line)
    witness = Discharge(PATH, guard_line, "handle", kind, "guard", "authenticated_context", "statement")
    operation = Operation(PATH, op_line, "handle", "protected_read", "read", None, ("path_guard", "ownership_check"))
    return CfgDominance({PATH: text}, {(PATH, "handle"): cfg}), witness, operation, text


def test_protocol():
    dominance, *_ = setup(["read(item);"], marker="read(")
    assert isinstance(dominance, Dominance)


def test_value_only_predicate_does_not_discharge():
    dominance, witness, operation, _ = setup(["boolean ok = can(item);", "return read(item);"])
    assert dominance.relation(witness, operation) == "all_paths"
    assert dominance.effect(witness, operation) == "value_only"
    assert not dominance.dominates(witness, operation, None)


def test_same_predicate_guarding_a_throw_discharges():
    dominance, witness, operation, _ = setup(["if (!can(item)) {", "  throw new AccessDeniedException();", "}", "return read(item);"])
    assert (dominance.relation(witness, operation), dominance.effect(witness, operation)) == ("all_paths", "throws")
    assert dominance.dominates(witness, operation, None)


def test_operation_only_inside_passing_branch_discharges():
    dominance, witness, operation, _ = setup(["if (can(item)) {", "  return read(item);", "}", "return null;"])
    assert dominance.effect(witness, operation) == "returns"
    assert dominance.dominates(witness, operation, None)
    dominance, witness, operation, _ = setup(["if (can(item)) {", "  read(item);", "}"])
    assert dominance.effect(witness, operation) == "branches"
    assert dominance.dominates(witness, operation, None)
    assert operation_context(dominance, operation).conditions == ("can(item)",)


def test_branch_only_guard_is_some_paths_and_no_discharge():
    dominance, witness, operation, text = setup(
        ["if (item.isShared()) {", "  checkPermission(ADMINISTER);", "}", "return read(item);"], kind="path_guard", marker="checkPermission"
    )
    assert dominance.relation(witness, operation) == "some_paths"
    assert dominance.effect(witness, operation) == "throws"
    assert not dominance.dominates(witness, operation, None)
    # The order-based default accepts the same guard: it reads only that the guard comes first.
    assert OrderDominance({PATH: text}).dominates(witness, operation, None)


def test_throwing_guard_in_swallowing_try_does_not_dominate():
    dominance, witness, operation, _ = setup(
        ["try {", "  checkPermission(ADMINISTER);", "} catch (AccessDeniedException e) {", "  log(e);", "}", "return read(item);"],
        kind="path_guard",
        marker="checkPermission",
    )
    assert not dominance.dominates(witness, operation, None)


def test_scopes_and_path_records_keep_their_semantics():
    dominance, witness, operation, _ = setup(["boolean ok = can(item);", "return read(item);"])
    for scope in ("decorator", "router"):
        scoped = Discharge(PATH, None, "handle", "path_guard", "guard", "authenticated_context", scope)
        assert dominance.dominates(scoped, operation, None)
        assert describe(dominance, scoped, operation, {}) == ("all_paths", "exits")
    caller = Discharge("Caller.java", 3, "entry", "path_guard", "guard", "authenticated_context", "statement")
    record = PathRecord((("Caller.java::entry", 4), (f"{PATH}::handle", None)), "Caller.java::entry", True)
    assert dominance.dominates(caller, operation, record)
    assert not dominance.dominates(caller, operation, None)
    later = PathRecord(((f"{PATH}::handle", 3), ("Caller.java::entry", None)), f"{PATH}::handle", True)
    assert not dominance.dominates(caller, operation, later)


def test_missing_graph_falls_back_to_order_and_is_recorded():
    text = "class T {\n Object handle(Item item) {\n  checkPermission(ADMINISTER);\n  return read(item);\n }\n}\n"
    witness = Discharge(PATH, 3, "handle", "path_guard", "guard", "authenticated_context", "statement")
    operation = Operation(PATH, 4, "handle", "protected_read", "read", None, ("path_guard",))
    dominance = CfgDominance({PATH: text}, {})
    assert dominance.dominates(witness, operation, None) == OrderDominance({PATH: text}).dominates(witness, operation, None)
    assert [(item["reason"], item["path"], item["function"]) for item in dominance.degradations] == [("cfg_unavailable", PATH, "handle")]
    unavailable = FunctionCfg(1, 6, False, "labelled_jump")
    dominance = CfgDominance({PATH: text}, {(PATH, "handle"): unavailable})
    assert dominance.dominates(witness, operation, None)
    assert dominance.degradations[0]["detail"] == "labelled_jump"
    assert not {"language", "framework", "repository"} & set(dominance.degradations[0])


def test_order_description_without_graph():
    text = "def f():\n    ok = can()\n    if not ok:\n        return\n    read()\n"
    witness = Discharge("a.py", 2, "f", "ownership_check", "guard", "authenticated_context", "statement")
    operation = Operation("a.py", 5, "f", "protected_read", "read", None, ("ownership_check",))
    assert describe(OrderDominance({"a.py": text}), witness, operation, {"a.py": text}) == ("all_paths", "returns")
    assert operation_context(OrderDominance({"a.py": text}), operation) == operation_context(OrderDominance({}), operation)
