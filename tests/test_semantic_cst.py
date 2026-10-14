"""Extra-on CST walker and overlay. Skips when wheels are absent."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.findings import quick_scan_findings
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets
from openultrasast.semantic import adjudicate, has_semantic_extra
from openultrasast.semantic.ir import parse_file

pytestmark = pytest.mark.semantic


def _require_extra() -> None:
    if not has_semantic_extra():
        pytest.skip("requires openultrasast[semantic]")


def test_javascript_eval_query_is_tree_sitter_call() -> None:
    _require_extra()
    ir = parse_file("app.js", "eval(req.query.x)\n", "javascript")
    assert ir.parse_ok is True
    assert ir.engine == "tree-sitter"
    calls = [call for function in ir.functions for call in function.calls]
    eval_calls = [call for call in calls if call.name == "eval"]
    assert eval_calls
    assert any("req.query" in arg for arg in eval_calls[0].arg_texts)


def test_broken_javascript_is_parse_failed() -> None:
    _require_extra()
    ir = parse_file("app.js", "eval(req.query.x\n", "javascript")
    assert ir.parse_ok is False
    assert ir.reason == "parse_failed"


def test_javascript_eval_promotes(tmp_path: Path) -> None:
    _require_extra()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.js").write_text("eval(req.query.x)\n")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings)
    eval_records = [record for record in records if "js-eval" in record.proposal_id]
    assert eval_records
    assert eval_records[0].disposition == "promote"
    assert eval_records[0].evidence_level == "static_corroboration"
    assert eval_records[0].engine == "tree-sitter"


def test_c_constant_system_demotes(tmp_path: Path) -> None:
    _require_extra()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "run.c").write_text('void f(void) { system("ls"); }\n')
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings)
    hits = [record for record in records if record.path == "run.c"]
    assert hits
    assert all(record.disposition != "unadjudicated" or record.reason != "language_unsupported" for record in hits)
    demoted = [record for record in hits if record.disposition == "demote"]
    assert demoted
    assert demoted[0].dominating_fact == "constant"
    assert demoted[0].evidence_level == "static_corroboration"


def test_php_functions_binds_calls_and_parameters(tmp_path: Path) -> None:
    _require_extra()
    from tree_sitter import Parser

    from openultrasast.semantic.cst import _KIND, _walk
    from openultrasast.semantic.extra import grammar_for

    text = """<p>Text mode</p>
<?php
class Example {
    public function run(?Thing $x, &$y, ...$rest) {
        $value = $this->g($y);
        $value .= "hello $x";
        $allowed = Gate::authorize('read', $x);
        $this?->g($y);
    }
}
function free_fn($x) { return consume($x); }
$closure = function ($z) { return consume($z); };
$arrow = fn($a) => consume($a);
"""
    path = tmp_path / "sample.php"
    path.write_text(text)
    data = path.read_bytes()
    assert len(data) == len(text.encode()) > 0
    tree = Parser(grammar_for("php")).parse(data)
    assert not tree.root_node.has_error
    seen = {node.type for node in _walk(tree.root_node)}
    # Exercise every registered kind against the installed grammar, including fn.
    assert set().union(*_KIND["php"].values()) <= seen
    ir = parse_file(path.name, data.decode(), "php")
    assert ir.parse_ok and ir.engine == "tree-sitter"
    assert [(fn.name, fn.start_line, fn.end_line, fn.params) for fn in ir.functions] == [
        ("<module>", 1, 14, ()),
        ("run", 4, 9, ("$x", "$y", "$rest")),
        ("free_fn", 11, 11, ("$x",)),
        ("<anon>", 12, 12, ("$z",)),
        ("<anon>", 13, 13, ("$a",)),
    ]
    module, method, free, closure, arrow = ir.functions
    assert module.calls == ()
    assert [b.name for b in module.binds] == ["$closure", "$arrow"]
    assert [(b.name, b.line, b.names, b.call_name) for b in method.binds] == [
        ("$value", 5, ("$this", "$y"), "g"),
        ("$value", 6, ("$value", "$x"), None),
        ("$allowed", 7, ("$x",), "authorize"),
    ]
    assert [(c.name, c.line, c.arg_texts, c.arg_names) for c in method.calls] == [
        ("g", 5, ("$y",), (("$y",),)),
        ("authorize", 7, ("'read'", "$x"), ((), ("$x",))),
        ("g", 8, ("$y",), (("$y",),)),
    ]
    assert method.calls[1].arg_is_constant == (True, False)
    for fn in (free, closure, arrow):
        assert [call.name for call in fn.calls] == ["consume"]
        assert fn.calls[0].arg_names == (fn.params,)


def test_php_interpolation_and_named_arguments() -> None:
    _require_extra()
    ir = parse_file("sample.php", '<?php function f($x) { $s = "hello $x"; consume(value: "hello", other: "$x"); }', "php")
    assert ir.parse_ok
    fn = ir.functions[1]
    assert fn.binds[0].names == ("$x",) and not fn.binds[0].is_constant
    assert fn.calls[0].arg_texts == ('"hello"', '"$x"')
    assert fn.calls[0].arg_names == ((), ("$x",))
    assert fn.calls[0].arg_is_constant == (True, False)
