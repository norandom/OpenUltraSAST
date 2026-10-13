"""Facts about repository source text, shared by scans, learning and plane tasks."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NamedTuple

from .preprocess import IGNORED_DIRS, build_file_target, detect_language

if TYPE_CHECKING:
    from .mapping import EntryPointRecord
    from .semantic.ir import FileIR

LANGUAGE_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "c_cpp": "cpp",
        "c++": "cpp",
        "python_web": "python",
        "py": "python",
        "node": "javascript",
        "js": "javascript",
        "ts": "typescript",
    }
)


def module_function(name: str) -> str:
    """Map the legacy module-level sentinel in stored records to the one name the code uses."""
    return MODULE_FUNCTION if name == LEGACY_MODULE_FUNCTION else name


def canonical_language(name: str) -> str:
    """Return the language name used by source parsers."""
    name = name.strip().lower()
    return LANGUAGE_ALIASES.get(name, name)


MODULE_FUNCTION = "<module>"
LEGACY_MODULE_FUNCTION = "<global>"  # what frozen records before 2026-10-13 call module-level code
ANON_FUNCTION = "<anon>"
MAX_FILE_BYTES = 1_000_000
LANGUAGES = frozenset({"python", "php", "javascript", "typescript", "java", "go", "ruby"})  # the declared languages
_EXCLUDED_DIRS = frozenset(
    IGNORED_DIRS | {"vendor", "node_modules", "bower_components", "third_party", "third-party", "dist", "build", "out", "target"}
)
_NOT_PRODUCT = re.compile(
    r"(^|/)(tests?|__tests__|__mocks__|spec|specs|docs?|examples?|fixtures?|e2e|cypress|storybook|testdata)/"
    r"|\.(test|spec|stories|mock|e2e)\.[cm]?[jt]sx?$"
    r"|_test\.(py|go|rb)$|(^|/)test_[^/]*\.(py|rb)$|Test\.java$|Tests\.java$|_spec\.rb$"
    r"|\.min\.(js|css)$|\.bundle\.js$"
)

_JS_MODIFIERS = r"(?:(?:export|default|public|private|protected|static|async|readonly|override)\s+)*"
_JAVA_MODIFIERS = r"(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|strictfp)\s+)*"
DECLARATION: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    "php": re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)\s*\("),
    "javascript": re.compile(
        r"^\s*" + _JS_MODIFIERS + r"function\s*\*?\s*(\w+)\s*\("
        r"|^\s*" + _JS_MODIFIERS + r"(\w+)\s*\([^;]*\)\s*(?::[^{=]+)?\{\s*$"
        r"|^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)"
    ),
    "java": re.compile(
        r"^\s*" + _JAVA_MODIFIERS + r"(?:<[^>]*>\s+)?(?!return\b|new\b|throw\b)[\w<>\[\],.?]+\s+(\w+)\s*\([^;]*\)\s*"
        r"(?:throws\s+[\w.,\s]+)?\{?\s*$"
    ),
    "go": re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("),
    "ruby": re.compile(r"^\s*def\s+(?:self\.)?(\w+[?!=]?)"),
}
DECLARATION["typescript"] = DECLARATION["javascript"]
KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "function",
        "else",
        "do",
        "try",
        "with",
        "elif",
        "except",
        "new",
        "throw",
        "super",
        "constructor",
        "foreach",
        "match",
        "case",
        "unless",
        "until",
    }
)
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "*/", "--")


RESERVED_FUNCTION_LABELS = KEYWORDS | frozenset(
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

# KEYWORDS is the line engine's statement-word filter (a declaration named `class` or `self` is still a declaration
# for the parser engine, which uses RESERVED_FUNCTION_LABELS). The two sets differ on purpose; see the label diff gate.

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


def declarator_name(line: str, language: str = "") -> str | None:
    """Function name declared on ``line``, or None when the line declares nothing (a call is not a declaration)."""
    pattern = DECLARATION.get(canonical_language(language))
    if pattern is not None and (match := pattern.match(line)):
        name = next((group for group in match.groups() if group), "")
        if name and name not in RESERVED_FUNCTION_LABELS:
            return name
    if language in {"python", "ruby", "go", "php", "java"}:
        return None
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


class FunctionRange(NamedTuple):
    """A function's name and inclusive, one-based source lines."""

    name: str
    start: int
    end: int
    kind: str


class CallSite(NamedTuple):
    """A call's one-based line and the name it invokes."""

    line: int
    name: str


class SourceFacts(NamedTuple):
    """Repository evidence about one source location."""

    language: str
    function: str
    span: tuple[int, int] | None
    callers: tuple[tuple[str, int], ...]
    entry_points: tuple[EntryPointRecord, ...]


def product_files(root: Path) -> list[str]:
    """Return sorted repository-relative product paths, excluding tests and dependencies."""
    from .model.layout import is_test_path, is_vendored, layout_facts

    root = Path(root)
    facts = layout_facts()
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part.startswith(".") or part in _EXCLUDED_DIRS for part in relative.parts):
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root) or not path.is_file():
            continue
        posix = relative.as_posix()
        if _NOT_PRODUCT.search(posix) or is_vendored(posix, facts) or is_test_path(posix, facts):
            continue
        if detect_language(path) in LANGUAGES and path.stat().st_size <= MAX_FILE_BYTES:
            files.append(posix)
    return files


def ranges_from_ir(ir: FileIR, text: str) -> tuple[FunctionRange, ...]:
    """Use declarator names when a parser names a function after its parameter."""
    lines = text.splitlines()
    result = []
    for fn in ir.functions:
        if fn.name == MODULE_FUNCTION:
            continue
        line = lines[fn.start_line - 1] if 0 < fn.start_line <= len(lines) else ""
        declared = declarator_name(line, ir.language)
        name = declared or fn.name
        if (
            name in RESERVED_FUNCTION_LABELS
            and name != ANON_FUNCTION
            or declared is None
            and ir.language in _PARAM_NAMED_ARROWS
            and not _declares(line, name)
        ):
            name = ANON_FUNCTION
        result.append(FunctionRange(name, fn.start_line, fn.end_line, "anonymous" if name == ANON_FUNCTION else "function"))
    return tuple(result)


def _declares(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(re.search(r"\b(?:function|def|sub)\s+" + escaped + r"\b|(?<![\w$.])" + escaped + r"\s*\(", line))


def _code_lines(text: str) -> list[str]:
    """Blank comments and quoted strings before counting delimiters."""
    token = re.compile(r"/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
    return token.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), text).splitlines()


def _body_end(code: Sequence[str], start: int, column: int) -> int | None:
    """Find the end of a body after its declaration head, skipping prototypes and calls."""
    parens, depth, opened, arrow = 0, 0, False, False
    for row in range(start, len(code)):
        for col in range(column if row == start else 0, len(code[row])):
            char = code[row][col]
            if opened:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return row + 1
            elif char == "(":
                parens += 1
            elif char == ")":
                parens -= 1
                if parens < 0:
                    return None
            elif parens == 0:
                if code[row].startswith("=>", col):
                    arrow = True
                if char == "{":
                    opened, depth = True, 1
                elif char in ";}":
                    return row + 1 if arrow else None
                elif char == "," and arrow:
                    return row + 1
        if not opened and arrow:
            return row + 1
        if not opened and row - start >= 40:
            return None
    return len(code) if opened else None


_HEAD = re.compile(
    r"(?<![\w.$>])([A-Za-z_$][\w:$]*)\s*(?:<[^<>(){};]*>\s*)?(?=\()|^\s*sub\s+(\w+)\s*(?=\{)"
    r"|(?<![\w$])([A-Za-z_$][\w$]*)\s*[:=]\s*(?:[\w$.]+\s*=\s*)*(?:async\s*)?(?:function\b\s*[\w$]*\s*)?(?=\(|[\w$]+\s*=>)"
)


def _regex_ranges(text: str, language: str) -> tuple[FunctionRange, ...]:
    lines, code = text.splitlines(), _code_lines(text)
    result = []
    for index, line in enumerate(code):
        name = declarator_name(line, language)
        if language == "python":
            if not name:
                continue
            indent = len(line) - len(line.lstrip())
            end = index + 1
            for row in range(index + 1, len(code)):
                if code[row].strip() and len(code[row]) - len(code[row].lstrip()) <= indent:
                    break
                if code[row].strip():
                    end = row + 1
        elif language == "ruby":
            if not name:
                continue
            depth, end = 1, len(lines)
            for row in range(index + 1, len(code)):
                if re.match(r"\s*(?:def|class|module|if|unless|case|begin|while|until|for)\b", code[row]):
                    depth += 1
                if re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", code[row]):
                    depth += 1
                if re.match(r"\s*end\b", code[row]):
                    depth -= 1
                    if depth == 0:
                        end = row + 1
                        break
        else:
            if _STATEMENT_PREFIX.match(line):
                continue
            heads = list(_HEAD.finditer(line))
            if not heads:
                continue
            head = heads[0]
            candidate = next(group for group in head.groups() if group).rsplit("::", 1)[-1]
            name = name or candidate
            if name in RESERVED_FUNCTION_LABELS:
                continue
            end = _body_end(code, index, head.end())
            if end is None:
                continue
        result.append(FunctionRange(name, index + 1, end, "function"))
    return tuple(result)


def ranges(path: str, text: str, language: str) -> tuple[FunctionRange, ...]:
    """Return inclusive source ranges using tree-sitter, or a declaration scan without a grammar.

    A parser rejection raises ValueError so unreadable syntax cannot look like a file without functions; a language
    without a grammar uses the declaration scan.
    """
    from .semantic.cst import parse_with_cst

    language = canonical_language(language)
    ir = parse_with_cst(path, text, language)
    if ir is not None:
        if not ir.parse_ok and ir.reason != "language_unsupported":
            raise ValueError(f"{path}: source parse failed")
        named = ranges_from_ir(ir, text) if ir.parse_ok else _regex_ranges(text, language)
    else:
        named = _regex_ranges(text, language)
    module = (FunctionRange(MODULE_FUNCTION, 1, len(text.splitlines()), "module"),) if text.splitlines() else ()
    return module + named


def enclosing(ranges: Sequence[FunctionRange], line: int | None) -> str:
    """Return the innermost named function at a one-based line, or the module label."""
    found = [item for item in ranges if item.kind == "function" and line is not None and item.start <= line <= item.end]
    return min(found, key=lambda item: item.end - item.start).name if found else MODULE_FUNCTION


def bounds(ranges: Sequence[FunctionRange], name: str) -> tuple[int, int] | None:
    """Return the first matching function's inclusive, one-based bounds."""
    name = re.split(r"::|\.|->", name)[-1]
    return next(((item.start, item.end) for item in ranges if item.name == name), None)


def spans_named(ranges: Sequence[FunctionRange], name: str) -> tuple[tuple[int, int], ...]:
    """Return all ranges of a name, including repeated method declarations."""
    return tuple((item.start, item.end) for item in ranges if item.name == name)


def call_sites(text: str, names: Iterable[str]) -> tuple[CallSite, ...]:
    """Return calls in line order, excluding declarations and comments, once per name and line."""
    wanted = sorted(set(names) - RESERVED_FUNCTION_LABELS - {MODULE_FUNCTION}, key=lambda name: (-len(name), name))
    if not wanted:
        return ()
    token = re.compile(r"(?<![A-Za-z0-9_$])(" + "|".join(re.escape(name) for name in wanted) + r")\s*\(")
    result = []
    for number, line in enumerate(_code_lines(text), start=1):
        declared = {
            next((group for group in match.groups() if group), "") for pattern in DECLARATION.values() if (match := pattern.match(line))
        }
        if "{" in line or "=>" in line:
            declared.add(declarator_name(line))
        seen = set()
        for match in token.finditer(line):
            name = match.group(1)
            # A same-line body can call its own function after the declaration head.
            if name in seen or (name in declared and not any(char in line[: match.start()] for char in "{;")):
                continue
            seen.add(name)
            result.append(CallSite(number, name))
    return tuple(result)


def _read_source(root: Path, path: str) -> str:
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or any(part.startswith(".env") for part in Path(path).parts):
        raise ValueError(f"source path is outside the repository or private: {path}")
    return resolved.read_text(encoding="utf-8", errors="replace")


def callers_of(root: Path, name: str, *, files: Iterable[str]) -> tuple[tuple[str, int], ...]:
    """Return sorted call locations from the supplied repository-relative product files."""
    root = Path(root)
    return tuple((path, call.line) for path in sorted(set(files)) for call in call_sites(_read_source(root, path), (name,)))


def facts_for(root: Path, path: str, line: int, *, entry_points: Sequence[EntryPointRecord] | None = None) -> SourceFacts:
    """Compute repository facts at a line; supplied entry points avoid repeated mapping."""
    root = Path(root)
    text = _read_source(root, path)
    language = canonical_language(detect_language(root / path))
    spans = ranges(path, text, language)
    function = enclosing(spans, line)
    files = product_files(root)
    if entry_points is None:
        from .mapping import analyze_entry_points

        entry_points = analyze_entry_points(root, [build_file_target(root, root / file) for file in files])
    return SourceFacts(language, function, bounds(spans, function), callers_of(root, function, files=files), tuple(entry_points))


def _digest(names: Sequence[str]) -> str:
    """Identify a sorted set of function names for stored facts."""
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16]


# --- the line-pattern engine: declarations by regular expression, spans to the next declaration, brace matching -----
# This is what labels, features, roles, excerpts and the plane facts were built on. The parser-based `ranges` above
# serves the scorer and the overlay; both share DECLARATION, KEYWORDS, RESERVED_FUNCTION_LABELS and the sentinel.

HASH_COMMENTS = frozenset({"python", "php", "ruby", "shell", "perl", "yaml", "r"})

SLASH_COMMENTS = frozenset(
    {"c", "cpp", "java", "javascript", "typescript", "php", "go", "groovy", "csharp", "kotlin", "rust", "swift", "scala"}
)  # fmt: skip

def _comment_ranges(line: str, state: str | None, language: str) -> tuple[list[tuple[int, int]], str | None]:
    """The comment spans of one line and the block state carried to the next (``block`` inside ``/* */``, a triple
    quote inside a Python docstring). Strings are skipped so a ``#`` in a literal is not a comment."""
    hashes, slashes, python = language in HASH_COMMENTS, language in SLASH_COMMENTS, language == "python"
    ranges: list[tuple[int, int]] = []
    i, n, quote = 0, len(line), None
    if state is not None:
        close = "*/" if state == "block" else state
        j = line.find(close)
        if j < 0:
            return [(0, n)], state
        ranges.append((0, j + len(close)))
        i, state = j + len(close), None
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if python and line.startswith(('"""', "'''"), i) and not line[:i].strip():
            delim = line[i : i + 3]
            j = line.find(delim, i + 3)
            if j < 0:
                ranges.append((i, n))
                return ranges, delim
            ranges.append((i, j + 3))
            i = j + 3
            continue
        if c in "\"'`":
            quote = c
        elif (slashes and line.startswith("//", i)) or (hashes and c == "#"):
            ranges.append((i, n))
            break
        elif slashes and line.startswith("/*", i):
            j = line.find("*/", i + 2)
            if j < 0:
                ranges.append((i, n))
                return ranges, "block"
            ranges.append((i, j + 2))
            i = j + 2
            continue
        i += 1
    return ranges, state

_UNKNOWN_LANGUAGES = frozenset({"", "other", "unknown"})

_PERL_LINE = re.compile(r"^\s*(?:sub\s+\w+\s*[{(;]|use\s+strict\s*;|my\s+[$@%]\w+)")

_RUBY_DEF = re.compile(r"^\s*def\s+(?:self\.)?\w+[?!=]?(?:\s*\(|\s|$)")

_RUBY_END = re.compile(r"^\s*end\s*$")

_BODY_SCAN_LINES = 40  # how far past a declaration head the body's ``{`` (or a prototype's ``;``) may be

_STATEMENT_HEAD = re.compile(r"\s*(return|if|while|for|switch|else|case|throw|await|yield)\b")

_FUNCTION_EXPR = r"(?:async\s+)?(?:function\b\s*\*?\s*[\w$]*\s*)?(?=\(|[\w$]+\s*=>)"  # function (...) / (...) => / a =>

def resolve_language(lines: Sequence[str], language: str) -> str:
    """The alias-normalised language; a file given as unknown (``other``, the feature vocabulary's bucket for Go, Ruby,
    C#, Perl, ...) is sniffed for Perl (``sub name {``, ``use strict;``) and Ruby (``def`` ... ``end``), whose
    declaration forms a brace matcher never finds and whose ``#`` comments must be redacted."""
    language = canonical_language(language)
    if language in _UNKNOWN_LANGUAGES and lines:
        if any(_PERL_LINE.match(line) for line in lines):
            return "perl"
        if any(_RUBY_DEF.match(line) for line in lines) and any(_RUBY_END.match(line) for line in lines):
            return "ruby"
    return language

def _blank_comments(lines: Sequence[str], language: str) -> list[str]:
    style = language if language in SLASH_COMMENTS or language in HASH_COMMENTS else "c"
    code: list[str] = []
    state: str | None = None
    for line in lines:
        ranges, state = _comment_ranges(line, state, style)
        for start, end in reversed(ranges):
            line = line[:start] + " " * (end - start) + line[end:]
        code.append(line)
    return code

def _declaration_heads(name: str) -> re.Pattern[str]:
    """Where a brace language may declare ``name`` (the body follows): ``name(`` (a definition -- or a call, told
    apart by :func:`_body_start`); Perl ``sub name {``; an object-literal method ``name: function (`` /
    ``name: (a) =>``; an assignment ``x.y.name = function (`` / ``= (a) =>`` / ``const name = m.name = async a =>``
    (any chain). ``$`` is an identifier character (``Glance$serveRequest``)."""
    quoted = re.escape(name)
    return re.compile(
        rf"(?<![\w.>$]){quoted}\s*(?:<[^<>(){{}};]*>\s*)?(?=\()"
        rf"|^\s*sub\s+{quoted}\s*(?=[{{(;])"
        rf"|(?<![\w$]){quoted}\s*:\s*{_FUNCTION_EXPR}"
        rf"|(?<![\w$]){quoted}\s*=\s*(?:[\w$.\[\]'\"]+\s*=\s*)*{_FUNCTION_EXPR}"
    )

def _body_start(code: Sequence[str], line: int, column: int) -> tuple[str, int, int] | None:
    """Scan from a declaration head for its body: ``("brace", line, column)`` of the ``{`` at parenthesis depth 0,
    ``("expression", line, column)`` of the ``;`` or ``,`` ending an arrow function's expression body, ``None`` for a
    prototype (``;`` before any body), a call (a ``)`` closing an outer parenthesis, a ``}``) or no body within
    :data:`_BODY_SCAN_LINES`. Parentheses are tracked so ``f(a, function () {})`` is not a definition of ``f``."""
    depth, arrow = 0, False
    for j in range(line, min(line + _BODY_SCAN_LINES, len(code))):
        text = code[j]
        k = column if j == line else 0
        while k < len(text):
            c = text[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth < 0:
                    return None
            elif depth == 0:
                if c == "{":
                    return ("brace", j, k)
                if arrow and c in ";,":
                    return ("expression", j, k)
                if c in "};":  # a statement ends (a call, a prototype) before any body opened
                    return None
                if text.startswith("=>", k):
                    arrow = True
                    k += 1
            k += 1
    return None

def _brace_bounds(lines: Sequence[str], language: str, function: str) -> tuple[int, int] | None:
    """A brace language's definition of ``function`` (``Class::name`` and ``a.b`` reduced to the last name): the first
    declaration head (:func:`_declaration_heads`) whose body :func:`_body_start` finds, to the matching ``}`` (or the
    end of an expression body). Comments are blanked before anything is matched or counted."""
    name = re.split(r"::|\.|->", function)[-1]
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return None
    heads = _declaration_heads(name)
    code = _blank_comments(lines, language)
    for i, line in enumerate(code):
        if _STATEMENT_HEAD.match(line):
            continue
        for found in heads.finditer(line):
            body = _body_start(code, i, found.end())
            if body is None:
                continue
            kind, j, k = body
            if kind == "expression":
                return i, j + 1
            depth = 0
            for row in range(j, len(code)):
                for c in code[row][k:] if row == j else code[row]:
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            return i, row + 1
            return i, len(code)
    return None

def function_bounds(lines: Sequence[str], language: str, function: str) -> tuple[int, int] | None:
    """0-based ``[start, end)`` of the first declaration of ``function`` (the whole file for ``<global>``), or
    ``None`` when the file does not declare it. Languages without a repo-facts declaration pattern (C, C++, C#, Perl,
    ...) and brace languages whose pattern misses the name use the brace matcher; an unknown language is sniffed
    (:func:`resolve_language`)."""
    function = module_function(function)
    language = resolve_language(lines, language)
    if function == MODULE_FUNCTION:
        return (0, len(lines)) if lines else None
    pattern = DECLARATION.get(language)
    start = next((i for i, line in enumerate(lines) if _declared_name(pattern, line) == function), None) if pattern else None
    if start is None:
        return _brace_bounds(lines, language, function) if language in SLASH_COMMENTS or pattern is None else None
    span = function_span(lines, language, function)
    if not span:
        return None
    return start, min(start + span, len(lines))

def product_paths(workspace: Path) -> list[Path]:
    """Product source files of the supported languages, sorted; tests, vendored trees, build output, minified
    bundles and dot-directories are not product (the classification of `model_sinks.py` and the layout facts)."""
    from .model.layout import is_test_path, is_vendored, layout_facts

    facts = layout_facts()
    files: list[Path] = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(workspace)
        parts = relative.parts
        if any(part.startswith(".") or part in _EXCLUDED_DIRS for part in parts[:-1]) or parts[-1].startswith("."):
            continue
        posix = relative.as_posix()
        if _NOT_PRODUCT.search(posix) or is_vendored(posix, facts) or is_test_path(posix, facts):
            continue
        if detect_language(path) not in LANGUAGES or path.stat().st_size > MAX_FILE_BYTES:
            continue
        files.append(path)
    return files

def declared_functions(lines: Sequence[str], language: str) -> list[str]:
    """The function names a file declares, in source order, each once."""
    pattern = DECLARATION.get(language)
    if pattern is None:
        return []
    names: list[str] = []
    for line in lines:
        name = _declared_name(pattern, line)
        if name and name not in names:
            names.append(name)
    return names

def enclosing_at(lines: Sequence[str], index: int, language: str) -> str:
    """The nearest declaration at or above line ``index`` (0-based), `<global>` when there is none."""
    pattern = DECLARATION.get(language)
    if pattern is None:
        return MODULE_FUNCTION
    indent = _indent(lines[index]) if language == "python" else None
    for back in range(index, -1, -1):
        name = _declared_name(pattern, lines[back])
        if not name:
            continue
        if indent is None or back == index or _indent(lines[back]) < indent:
            return name
        indent = min(indent, _indent(lines[back]))  # a sibling or deeper def: keep looking for the one that encloses
    return MODULE_FUNCTION

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))

def call_sites_in(lines: Sequence[str], language: str, names: Iterable[str]) -> list[dict[str, Any]]:
    """Calls to any of ``names`` in one file: `{"function", "line", "enclosing"}`, one per name and line, in
    line order. A declaration line is not a call of the function it declares; comment lines are skipped."""
    wanted = sorted(set(names), key=lambda n: (-len(n), n))
    if not wanted:
        return []
    token = re.compile(r"(?<![A-Za-z0-9_$])(" + "|".join(re.escape(n) for n in wanted) + r")\s*\(")
    pattern = DECLARATION.get(language)
    found: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith(_COMMENT_PREFIXES):
            continue
        declared = _declared_name(pattern, line) if pattern is not None else ""
        seen: set[str] = set()
        for match in token.finditer(line):
            name = match.group(1)
            if name == declared or name in seen:
                continue
            seen.add(name)
            found.append({"function": name, "line": index + 1, "enclosing": enclosing_at(lines, index, language)})
    return found

def _declared_name(pattern: re.Pattern[str], line: str) -> str:
    match = pattern.match(line)
    if not match:
        return ""
    name = next((g for g in match.groups() if g), "")
    return "" if name in KEYWORDS else name

def function_span(lines: Sequence[str], language: str, function: str) -> int | None:
    """Lines of the first declaration of ``function`` up to the next declaration (Python: up to the next line indented
    no deeper), ``None`` when the file does not declare it. ``<global>`` counts the whole file."""
    function = module_function(function)
    if function == MODULE_FUNCTION:
        return len(lines)
    pattern = DECLARATION.get(language)
    if pattern is None:
        return None
    start = next((i for i, line in enumerate(lines) if _declared_name(pattern, line) == function), None)
    if start is None:
        return None
    indent = len(lines[start]) - len(lines[start].lstrip(" \t"))
    for end in range(start + 1, len(lines)):
        line = lines[end]
        if language == "python":
            if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip(" \t")) <= indent:
                return end - start
        elif _declared_name(pattern, line):
            return end - start
    return len(lines) - start


declared_name = _declared_name
