"""Named function ranges shared by the scorer, the overlay, and the catalog generator.

Tree-sitter names an arrow function after its first bare parameter and gives
object or class methods, `exports.x = function`, and IIFEs ``<anon>``. Labels in
the pair catalogs name the declarator (``const h = ...``, ``exports.h = ...``,
``h(req, res) {``). Every consumer must therefore name ranges the same way, or
function-scoped matching silently fails (pair-corpus-honesty Req 1.2, design
§Scorer). This module is the single source of that naming. Stdlib plus ``.ir``
only; never imports ``overlay`` or ``pairs``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .ir import FileIR, parse_file

FunctionRange = tuple[str, int, int]
MODULE_FUNCTION = "<module>"
ANON_FUNCTION = "<anon>"
UNNAMED_FUNCTIONS = frozenset({MODULE_FUNCTION, ANON_FUNCTION})
# Keywords a parser or a regex fallback can mistake for a function name; never valid labels.
RESERVED_FUNCTION_LABELS = frozenset(
    {
        "function",
        "def",
        "return",
        "if",
        "else",
        "for",
        "while",
        "switch",
        "catch",
        "class",
        "async",
        "await",
        "lambda",
        "const",
        "let",
        "var",
        "export",
        "import",
        "module",
        "exports",
        "new",
        "this",
        "self",
        "anonymous",
        ANON_FUNCTION,
    }
)

_IDENT = r"[A-Za-z_$][\w$]*"
_ARROW_TAIL = r"(?:async\s*)?(?:\([^)]*\)|" + _IDENT + r")\s*=>"
_DECL = re.compile(
    # def name( / function name( / export async function name(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:def|function|sub)\s+(" + _IDENT + r")\s*[\({]|"
    # const name = [a.b.c =]* [async] (args) => | ident =>
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(" + _IDENT + r")\s*=\s*(?:" + _IDENT + r"(?:\." + _IDENT + r")*\s*=\s*)*" + _ARROW_TAIL + r"|"
    # exports.name = / module.exports.name = [async] function | (args) =>
    r"^\s*(?:module\.)?exports\.(" + _IDENT + r")\s*=\s*(?:async\s*)?(?:function\b|" + _ARROW_TAIL + r")|"
    # object property: name: [async] function | (args) =>
    r"^\s*(?:async\s+)?(" + _IDENT + r")\s*:\s*(?:async\s*)?(?:function\b|" + _ARROW_TAIL + r")|"
    # C / Java / JS method or shorthand: [type] name(args) {   (no call: the arg list carries no callback or literal)
    r"^\s*(?:[A-Za-z_][\w:<>\*\s,]*[\s\*])?(" + r"[A-Za-z_][\w:$]*" + r")\s*\(([^;{]*)\)\s*(?:const\s*)?\{?\s*$"
)
_CALLBACK_ARGS = re.compile(r"\bfunction\b|=>|['\"`]|^\s*\d")
# A statement keyword before `name(` means the line calls or controls, it does not declare.
_STATEMENT_PREFIX = re.compile(
    r"^\s*(?:return|print|yield|throw|await|new|else|case|delete|typeof|synchronized|with|elif|except|try|if|for|while|switch|catch|do)\b"
)
# Only these grammars name an arrow function after its bare parameter; elsewhere the parser name is trustworthy.
_PARAM_NAMED_ARROWS = frozenset({"javascript", "typescript"})


def declarator_name(line: str) -> str | None:
    """Function name declared on ``line``, or None when the line declares nothing (a call is not a declaration)."""
    match = _DECL.match(line)
    if not match:
        return None
    groups = match.groups()
    name = next((group for group in groups[:5] if group), None)
    if name is None:
        return None
    if groups[4] is not None:
        args = groups[5] or ""
        if _CALLBACK_ARGS.search(args):
            return None  # `exec('...', function (err) {` is a call, not a declaration
        if _STATEMENT_PREFIX.match(line) or name in {"if", "for", "while", "switch", "catch", "return", "elif", "with", "synchronized"}:
            return None
        name = name.rsplit("::", 1)[-1]  # `bool K::m(` declares `m`; catalog labels are unqualified
    return name if name not in RESERVED_FUNCTION_LABELS else None


def named_ranges_from_ir(ir: FileIR, text: str) -> tuple[FunctionRange, ...]:
    """Declarator-named function ranges from a parsed file; anonymous functions keep ``<anon>`` only when nothing names them."""
    lines = text.splitlines()
    ranges: list[FunctionRange] = []
    for fn in ir.functions:
        if fn.name == MODULE_FUNCTION:
            continue
        line = lines[fn.start_line - 1] if 0 < fn.start_line <= len(lines) else ""
        declared = declarator_name(line)
        name = declared or fn.name
        if name in RESERVED_FUNCTION_LABELS and name != ANON_FUNCTION:
            name = ANON_FUNCTION
        elif declared is None and name != ANON_FUNCTION and ir.language in _PARAM_NAMED_ARROWS and not _declares(line, name):
            name = ANON_FUNCTION  # tree-sitter named a bare-parameter arrow (`block => {`) after its parameter
        ranges.append((name, fn.start_line, fn.end_line))
    return tuple(ranges)


def _declares(line: str, name: str) -> bool:
    """True when ``line`` visibly declares ``name`` as a function (keyword form or ``name(``), not as a parameter."""
    escaped = re.escape(name)
    return bool(re.search(r"\b(?:function|def|sub)\s+" + escaped + r"\b|(?<![\w$.])" + escaped + r"\s*\(", line))


def named_function_ranges(path: str, text: str, language: str) -> tuple[FunctionRange, ...] | None:
    """Ranges for one file. None when the parser rejected the file; regex line scan only when no grammar exists."""
    ir = parse_file(path, text, language)
    if ir.parse_ok:
        return named_ranges_from_ir(ir, text)
    if ir.reason == "parse_failed":
        return None
    lines = text.splitlines()
    fallback: list[FunctionRange] = []
    for index, line in enumerate(lines, start=1):
        name = declarator_name(line)
        if name:
            fallback.append((name, index, len(lines)))
    return tuple(fallback)


def function_at(ranges: Sequence[FunctionRange], line: int | None) -> str | None:
    """Innermost *named* function whose range contains ``line``; None when unknown or only anonymous."""
    if line is None:
        return None
    best: FunctionRange | None = None
    for item in ranges:
        name, start, end = item
        if name in UNNAMED_FUNCTIONS or not (start <= line <= end):
            continue
        if best is None or (end - start) < (best[2] - best[1]):
            best = item
    return best[0] if best is not None else None


def spans_named(ranges: Sequence[FunctionRange], function: str) -> tuple[tuple[int, int], ...]:
    return tuple((start, end) for name, start, end in ranges if name == function)
