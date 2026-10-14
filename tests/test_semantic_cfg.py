"""The structural control-flow graph decides dominance per language and reports a line's control context."""

import pytest

from openultrasast.semantic.cfg import FunctionCfg
from openultrasast.semantic.cst import parse_function_nodes
from openultrasast.semantic.extra import grammar_for

SOURCES = {
    "java": (
        "T.java",
        """class T {
 Object f(int x) {
  guardA();
  if (x > 0) {
   guardB();
  }
  for (int i = 0; i < x; i++) {
   guardC();
  }
  try {
   guardD();
  } catch (IOException e) {
   recoverE();
  }
  return opF();
 }
}
""",
        "x > 0",
        "IOException",
    ),
    "php": (
        "t.php",
        """<?php
function f($x) {
  guardA();
  if ($x > 0) {
    guardB();
  }
  for ($i = 0; $i < $x; $i++) {
    guardC();
  }
  try {
    guardD();
  } catch (IOException $e) {
    recoverE();
  }
  return opF();
}
""",
        "$x > 0",
        "IOException",
    ),
    "python": (
        "t.py",
        """def f(x):
    guardA()
    if x > 0:
        guardB()
    for i in range(x):
        guardC()
    try:
        guardD()
    except IOError:
        recoverE()
    return opF()
""",
        "x > 0",
        "IOError",
    ),
    "javascript": (
        "t.js",
        """function f(x) {
  guardA();
  if (x > 0) {
    guardB();
  }
  for (let i = 0; i < x; i++) {
    guardC();
  }
  try {
    guardD();
  } catch (e) {
    recoverE();
  }
  return opF();
}
""",
        "x > 0",
        "any",
    ),
    "typescript": (
        "t.ts",
        """function f(x: number): unknown {
  guardA();
  if (x > 0) {
    guardB();
  }
  for (let i = 0; i < x; i++) {
    guardC();
  }
  try {
    guardD();
  } catch (e) {
    recoverE();
  }
  return opF();
}
""",
        "x > 0",
        "any",
    ),
}


def _require(language):
    if grammar_for(language) is None:
        pytest.skip(f"no grammar installed for {language}")


def graph(language, path, text):
    _require(language)
    assert len(text.encode()) > 0
    nodes = parse_function_nodes(path, text, language)
    assert nodes, "the parser read no function"
    return FunctionCfg.from_cst(nodes[0], language)


def line_of(text, marker):
    return next(number for number, line in enumerate(text.splitlines(), 1) if marker in line)


@pytest.mark.parametrize("language", sorted(SOURCES))
def test_dominance_and_context_per_language(language):
    path, text, condition, caught = SOURCES[language]
    cfg = graph(language, path, text)
    assert cfg.available, cfg.reason
    at = {marker: line_of(text, marker) for marker in ("guardA", "guardB", "guardC", "guardD", "recoverE", "opF")}
    # A guard before the unconditional return dominates it.
    assert cfg.dominates(at["guardA"], at["opF"])
    assert cfg.relation(at["guardA"], at["opF"]) == "all_paths"
    # A guard inside an if-branch does not dominate a statement after the branch.
    assert not cfg.dominates(at["guardB"], at["opF"])
    assert cfg.relation(at["guardB"], at["opF"]) == "some_paths"
    # A guard inside a loop body does not dominate a statement after the loop.
    assert not cfg.dominates(at["guardC"], at["opF"])
    # A guard in a try whose catch falls through does not dominate a statement after the try.
    assert not cfg.dominates(at["guardD"], at["opF"])
    assert cfg.relation(at["opF"], at["guardA"]) == "after"
    assert cfg.context(at["guardB"]).conditions == (condition,)
    assert cfg.context(at["guardC"]).in_loop and not cfg.context(at["opF"]).in_loop
    try_context = cfg.context(at["guardD"])
    assert try_context.in_try and try_context.catches == (caught,) and not try_context.on_exception_path
    assert cfg.context(at["recoverE"]).on_exception_path
    assert any(node.kind == "catch" for node in cfg.nodes)
    assert cfg.context(at["opF"]) == type(try_context)()


def python_graph(body):
    text = "def f(x):\n" + "".join(f"    {line}\n" for line in body)
    return graph("python", "t.py", text), text


@pytest.mark.parametrize(
    "body,effect",
    [
        (["if not can(x):", "    raise Denied()", "op(x)"], "throws"),
        (["if not can(x):", "    return None", "op(x)"], "returns"),
        (["if can(x):", "    op(x)"], "branches"),
        (["if can(x):", "    op(x)", "else:", "    return None"], "returns"),
        (["for item in x:", "    if not can(item):", "        continue", "    op(item)"], "exits"),
        (["if not can(x):", "    sys.exit(1)", "op(x)"], "exits"),
        (["allowed = can(x)", "if not allowed:", "    return None", "op(x)"], "returns"),
        (["allowed = can(x)", "op(x)"], "value_only"),
        (["can(x)", "op(x)"], "value_only"),
        (["assert can(x)", "op(x)"], "throws"),
    ],
)
def test_failure_effect(body, effect):
    cfg, text = python_graph(body)
    assert cfg.available, cfg.reason
    assert cfg.effect(line_of(text, "can("), line_of(text, "op("), throwing=False) == effect


def test_throwing_call_and_both_arms_reaching():
    cfg, text = python_graph(["check_permission(x)", "op(x)"])
    assert cfg.effect(line_of(text, "check_permission"), line_of(text, "op("), throwing=True) == "throws"
    cfg, text = python_graph(["if can(x):", "    log()", "op(x)"])
    assert cfg.effect(line_of(text, "can("), line_of(text, "op("), throwing=False) == "value_only"


def test_switch_arms_and_back_edges():
    text = """class T {
 void f(int k) {
  switch (k) {
   case 1:
    guardA();
    break;
   default:
    other();
  }
  do {
   guardB();
  } while (k > 0);
  opC();
 }
}
"""
    cfg = graph("java", "T.java", text)
    assert cfg.available
    assert not cfg.dominates(line_of(text, "guardA"), line_of(text, "opC"))
    assert cfg.context(line_of(text, "guardA")).conditions == ("case 1 of k",)
    # A do body runs at least once, so its first statement dominates what follows the loop.
    assert cfg.dominates(line_of(text, "guardB"), line_of(text, "opC"))
    assert cfg.context(line_of(text, "guardB")).in_loop


@pytest.mark.parametrize(
    "language,path,text",
    [
        ("java", "T.java", "class T { void f() { outer: for (;;) { for (;;) { break outer; } } } }"),
        ("javascript", "t.js", "function f() { x = cond ? 1 : 2; outer: for (;;) { continue outer; } }"),
        ("php", "t.php", "<?php function f() { while (true) { while (true) { break 2; } } }"),
        ("php", "t.php", "<?php function f($x) { $y = $x ?? throw new Exception(); }"),
    ],
)
def test_unmodelled_construct_leaves_no_graph(language, path, text):
    cfg = graph(language, path, text)
    assert not cfg.available and cfg.reason
    assert cfg.node_at(1) is None and not cfg.dominates(1, 1)


def test_language_without_builder_is_unavailable():
    _require("c")
    nodes = parse_function_nodes("t.c", "int f(void) { return 1; }\n", "c")
    assert nodes
    assert FunctionCfg.from_cst(nodes[0], "c").reason == "no_control_flow_builder"


def test_line_after_function_names_exit():
    cfg, text = python_graph(["guard()", "if x:", "    return 1", "return 2"])
    assert cfg.node_at(cfg.end_line + 1) == FunctionCfg.EXIT
    assert cfg.dominates(line_of(text, "guard"), cfg.end_line + 1)
    assert not cfg.dominates(line_of(text, "return 2"), cfg.end_line + 1)
