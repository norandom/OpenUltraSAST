"""freeze.py resolves an advisory's file-only site to the function the fix changes (population v3, decision 2).

The resolver reads PHP text only; it must not be fooled by braces in strings, comments or inline HTML, and a line
outside every function is `<global>`."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("freeze", Path(__file__).resolve().parents[1] / "benchmarks" / "independent" / "freeze.py")
freeze = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(freeze)

PHP = """<html>{ not code }</html>
<?php
// a comment with { brace
class Box
{
    public function open($x)
    {
        $s = "}{ in a string";
        return function ($y) { return $y; };
    }

    abstract protected function shape();

    private static function &close() {
        /* } */
        return <<<EOT
        } heredoc {
        EOT;
    }
}
$top = 1;
?>
<div>{</div>
<?php function helper() { return '#{'; }
"""


def test_named_functions_and_their_lines() -> None:
    spans = {name: (first, last) for name, first, last in freeze.php_functions(PHP)}
    assert spans == {"open": (6, 10), "close": (14, 19), "helper": (24, 24)}


def test_a_line_resolves_to_its_innermost_named_function_or_global() -> None:
    spans = freeze.php_functions(PHP)
    assert freeze.enclosing(spans, 9) == "open"  # inside the closure: the named function owns it
    assert freeze.enclosing(spans, 17) == "close"
    assert freeze.enclosing(spans, 21) == "<global>"
    assert freeze.enclosing(spans, 1) == "<global>"


def test_an_insertion_after_a_closing_brace_is_outside_the_function() -> None:
    spans = freeze.php_functions(PHP)
    assert freeze.enclosing(spans, 10) == "open"  # a changed line on the closing brace
    assert freeze.enclosing(spans, 10, inserted=True) == "<global>"  # new code that follows it
    assert freeze.enclosing(spans, 8, inserted=True) == "open"
