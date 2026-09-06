#!/usr/bin/env python3
"""Shared pair harvest library: extract one function from public parent/fix blobs.

Maintainer-only; CI stays offline (tests run the extractors on local strings).
Does not clone mozilla-central, gecko-dev, or Chromium. Advisory-only recipes
(no parent and commit) are rejected. FixFox is not a fetch source.

Modes (recipe ``mode``, default ``name``):
- ``name``        anchor on the declarator of ``function`` (comment and string mentions ignored)
- ``line_range``  copy ``line_start..line_end`` from the parent blob and
                  ``fix_line_start..fix_line_end`` (default: same) from the fix blob
- ``hunk``        take the function enclosing the first changed hunk on each side
- ``enclosing``   take the function enclosing ``line`` on the parent blob and
                  ``fix_line`` (default: same) on the fix blob; ``fix_path`` may differ

Languages: c, cpp, java, javascript, typescript (brace-balanced), python (indentation), perl (``sub``).
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "github.com",
    "phabricator.services.mozilla.com",
    "hg.mozilla.org",
    "hg-edge.mozilla.org",
}
BLOCKED_TOKENS = ("fixfox", "zenodo.org/record")
MODES = ("name", "line_range", "hunk", "enclosing", "handler_context")
_SUFFIX_LANGUAGE = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".pl": "perl",
    ".pm": "perl",
    ".yml": "yaml",
    ".yaml": "yaml",
}
_HASH_COMMENT = {"python", "perl", "yaml"}
_CONTEXT_LANGUAGES = {"yaml", "javascript", "typescript", "python"}
_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_CLASS_RE = re.compile(r"^(\s*)class\s+([A-Za-z_]\w*)\s*[(:]")
_COMMENTED_CODE = re.compile(r"^#\s*(?:@|(?:async\s+)?def\s|class\s|function\s)")
_CONTROL_HEAD = re.compile(r"^(?:else\s+)?(?:if|for|while|switch|catch|do|try|finally)\b")
_INDENTED = {"python", "yaml"}


class RecipeError(ValueError):
    """Invalid harvest recipe or extraction failure."""


# --- masking -----------------------------------------------------------------


def mask_comments_and_strings(source: str, language: str = "c") -> str:
    """Return ``source`` with comment and string-literal bodies replaced by spaces.

    Same length, newlines preserved, so indexes and line numbers line up with the
    original. Braces and identifiers inside comments or strings therefore never
    anchor an extraction.
    """
    out = list(source)
    n = len(source)
    i = 0
    hash_comments = language in _HASH_COMMENT
    slash_comments = not hash_comments
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if hash_comments and ch == "#":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if slash_comments and ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if slash_comments and ch == "/" and nxt == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            continue
        if language == "python" and ch in "\"'" and source.startswith(ch * 3, i):
            quote = ch * 3
            for k in range(i, min(i + 3, n)):
                out[k] = " "  # blank the delimiters too: a closing triple quote at column 0 is not a dedent
            i += 3
            while i < n and not source.startswith(quote, i):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            for k in range(i, min(i + 3, n)):
                out[k] = " "
            i += 3
            continue
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < n and source[i] != quote:
                if source[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if source[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if source[i] == "\n" and quote != "`":
                    break  # unterminated single-line literal; stop masking at EOL
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


# --- extraction --------------------------------------------------------------


def language_for(recipe: dict[str, Any]) -> str:
    language = str(recipe.get("language") or "").lower()
    if language:
        return {"c++": "cpp", "js": "javascript", "ts": "typescript"}.get(language, language)
    return _SUFFIX_LANGUAGE.get(Path(str(recipe.get("path", ""))).suffix.lower(), "c")


def extract_function(source: str, function_name: str, language: str = "c") -> str:
    """Copy the named function from its declarator through its balanced body."""
    if language == "python":
        return extract_python_block(source, function_name)
    masked = mask_comments_and_strings(source, language)
    needle = function_name
    idx = 0
    while True:
        found = masked.find(needle, idx)
        if found < 0:
            raise RecipeError(f"function not found: {function_name}")
        idx = found + len(needle)
        before = masked[found - 1] if found else " "
        if before.isalnum() or before == "_" or before == ".":
            continue
        rest = masked[idx:].lstrip()
        if not (rest.startswith("(") or rest.startswith("<") or rest.startswith("{")):
            continue
        brace = masked.find("{", found)
        semi = masked.find(";", found)
        if brace < 0 or (0 <= semi < brace):
            continue  # prototype / declaration, keep searching
        break
    start = _declarator_start(source, masked, found)
    end = _balanced_end(masked, brace)
    return source[start : end + 1].strip() + "\n"


def extract_python_block(source: str, function_name: str) -> str:
    lines = source.splitlines(keepends=True)
    masked = mask_comments_and_strings(source, "python").splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = _DEF_RE.match(line)
        if match is None or match.group(2) != function_name:
            continue
        indent = len(match.group(1))
        start = _decorator_start(lines, index, indent)
        end = _python_block_end(masked, index, indent)
        return "".join(lines[start:end]).rstrip("\n") + "\n"
    raise RecipeError(f"function not found: {function_name}")


def _decorator_start(lines: Sequence[str], index: int, indent: int) -> int:
    """First line of the decorator run above ``index``: multi-line decorators and comments included.

    A commented-out decorator is not noise: `#@token_required` above a handler is the whole bug in an absence row, and
    an excerpt that starts below it hides the only trace the guard ever existed. `@ns.doc(...)` routinely wraps over
    four lines, and stopping at its continuation drops the `@ns.route(...)` above it — the registration itself
    (learning-harness Req 10.2)."""
    first = index
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if not stripped:
            break
        if _indent(lines[cursor]) == indent and stripped.startswith("@"):
            first = cursor
            cursor -= 1
            continue
        if _indent(lines[cursor]) == indent and stripped.startswith("#"):
            if _COMMENTED_CODE.match(stripped):
                first = cursor  # `#@token_required` above the handler is the removed guard, not prose
            cursor -= 1
            continue
        anchor = _decorator_anchor(lines, cursor, indent)
        if anchor is None:
            break
        first = anchor
        cursor = anchor - 1
    return first


def _decorator_anchor(lines: Sequence[str], cursor: int, indent: int) -> int | None:
    """The `@` line of the multi-line decorator whose last line is ``cursor``, or None when ``cursor`` is not one."""
    for start in range(cursor, -1, -1):
        stripped = lines[start].strip()
        if _indent(lines[start]) == indent and stripped.startswith("@"):
            whole = " ".join(lines[position].strip() for position in range(start, cursor + 1))
            opened = " ".join(lines[position].strip() for position in range(start, cursor))
            balanced = whole.count("(") == whole.count(")") and opened.count("(") > opened.count(")")
            return start if balanced else None
        if stripped and _indent(lines[start]) <= indent:
            return None
    return None


def extract_handler_context(source: str, function_name: str, language: str = "c", *, line: int | None = None) -> str:
    """The named handler with everything that says it is reachable: its own decorators, the class its framework
    registers (a `Resource`/`MethodView` method carries its route on the class, not on the function), and every
    statement outside it that names the function as an identifier — `app.add_url_rule(..., view_func=fn)`,
    `router.get('/x', fn)`, `path('x', fn)`, `app.use(fn)`. Comment and string mentions never count (the masked text
    is searched). Pass ``line`` when the name repeats in the file: `def get` appears once per resource class, so the
    name alone cannot say which handler a row labels. One excerpt per side, so guards living in decorators, routers
    and middleware are visible to the teacher and the scorer (authorization-obligations Req 7.1, learning-harness
    Req 10.2)."""
    lines = source.splitlines()
    if line is not None:
        bounds = innermost_function_bounds(source, int(line), language)
        if bounds is None:
            raise RecipeError(f"line {line} is not inside a function")
        start, end = bounds[0] - 1, bounds[1]
        # function_bounds_at anchors on the declarator; the decorators above it are part of the handler
        start = _decorator_start(lines, start, _indent(lines[start]))
        body = "\n".join(lines[start:end]) + "\n"
    else:
        body = extract_function(source, function_name, language)
        start = _start_line_of(source, body) - 1
        end = start + len(body.splitlines())
    header = _python_class_header(lines, start) if language == "python" else ()
    masked_lines = mask_comments_and_strings(source, language).splitlines()
    mention = re.compile(rf"(?<![\w.]){re.escape(function_name)}(?!\w)")
    declaration = re.compile(rf"^\s*(?:async\s+)?(?:def|function|sub)\s+{re.escape(function_name)}\b")
    covered = set(range(start, end)) | set(header)
    registrations = [
        lines[index]
        for index, masked in enumerate(masked_lines)
        if index not in covered and index < len(lines) and mention.search(masked) and not declaration.match(masked)
    ]
    if header:
        body = "\n".join(lines[index] for index in header) + "\n" + body
    if not registrations:
        return body
    return body.rstrip("\n") + "\n\n" + "\n".join(line.strip() for line in registrations) + "\n"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _python_class_header(lines: list[str], start: int) -> tuple[int, ...]:
    """Line indexes of the class declaration enclosing the handler at ``start``, with its decorators.

    Flask-RESTX, Django REST framework and Flask's `MethodView` register the *class*: `@ns.route('/profile')` sits
    above `class UserProfile(Resource)`, and the method below it is the handler. An excerpt that starts at `def get`
    is both unreachable and unparsable (a bare indented block), so the class header travels with it."""
    if start >= len(lines) or _indent(lines[start]) == 0:
        return ()
    indent = _indent(lines[start])
    for index in range(start - 1, -1, -1):
        match = _CLASS_RE.match(lines[index])
        if match is None or len(match.group(1)) >= indent:
            continue
        return tuple(range(_decorator_start(lines, index, len(match.group(1))), index + 1))
    return ()


def innermost_function_bounds(source: str, line: int, language: str = "c") -> tuple[int, int] | None:
    """1-based inclusive bounds of the *innermost* function containing ``line``.

    `function_bounds_at` returns the outermost top-level brace group, which is right for C and wrong for the JavaScript
    and TypeScript the absence corpus is made of: a handler declared inside a React component or a route module comes
    back as the whole 6000-line component, and the excerpt starts mid-parameter-list. Only the handler-context mode
    uses this, so hunk and enclosing rows keep the bounds they were harvested with."""
    if language == "python":
        return function_bounds_at(source, line, language)
    masked = mask_comments_and_strings(source, language)
    offsets = _line_offsets(source)
    if line < 1 or line > len(offsets):
        return None
    target = offsets[line - 1]
    stack: list[int] = []
    best: tuple[int, int] | None = None
    for pos, ch in enumerate(masked):
        if ch == "{":
            stack.append(pos)
        elif ch == "}" and stack:
            open_at = stack.pop()
            if pos < target:
                continue
            start = _declarator_start(source, masked, open_at)
            if not (start <= target <= pos):
                continue  # the declarator line counts: `const f = async () => {` opens its brace after the anchor
            head = masked[start:open_at]
            if "(" not in head or ")" not in head or _CONTROL_HEAD.match(head.strip()):
                continue  # an object literal, a bare block, or `if (...) {` — not a callable
            if head.count("{") != head.count("}"):
                continue  # the declarator walk crossed an opening brace: this is a block inside the function, not the function
            span = (_line_of(offsets, start), _line_of(offsets, pos))
            if best is None or span[0] > best[0]:
                best = span
    return best


def extract_registration_context(source: str, function_name: str, language: str = "c") -> str:
    """The part of a *separate* document that registers ``function_name``, or "" when it names it nowhere.

    Some frameworks keep the route table out of the handler file: connexion registers by `operationId` in an OpenAPI
    document, an Express application registers in a router module. That statement carries the guard — the `security`
    block, the authorization middleware — so an absence row harvested without it cannot be judged at all. Comment and
    string mentions never count. Indented documents return the enclosing block with its ancestor headings; brace
    documents return the whole enclosing call, which is where the middleware list lives."""
    masked_lines = mask_comments_and_strings(source, language).splitlines()
    lines = source.splitlines()
    mention = re.compile(rf"(?<![\w.])(?:\w+\.)*{re.escape(function_name)}(?!\w)")
    hits = [index for index, masked in enumerate(masked_lines) if mention.search(masked)]
    if not hits:
        return ""
    if language in _INDENTED:
        return _indented_block(lines, hits[0])
    return _enclosing_call(source, masked_lines, lines, hits[0], function_name)


def _indented_block(lines: list[str], hit: int) -> str:
    """The innermost block containing ``hit``, prefixed by the heading line of every ancestor above it."""
    indent = _indent(lines[hit])
    ancestors: list[int] = []
    current = indent
    for index in range(hit - 1, -1, -1):
        if not lines[index].strip():
            continue
        if _indent(lines[index]) < current:
            ancestors.append(index)
            current = _indent(lines[index])
            if current == 0:
                break
    if not ancestors:
        return lines[hit] + "\n"
    inner = ancestors[0]
    end = inner + 1
    while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > _indent(lines[inner])):
        end += 1
    body = [*reversed(ancestors[1:]), *range(inner, end)]
    return "\n".join(lines[index] for index in body).rstrip("\n") + "\n"


def _enclosing_call(source: str, masked_lines: list[str], lines: list[str], hit: int, function_name: str) -> str:
    """The whole call statement around the mention: `webRouter.post(` … `)` spans four lines and three of them are the guard."""
    masked = "\n".join(masked_lines)
    offsets = _line_offsets(masked + "\n")
    at = masked.find(function_name, offsets[hit])
    if at < 0:
        return lines[hit] + "\n"
    depth = 0
    open_at = -1
    for pos in range(at - 1, -1, -1):
        ch = masked[pos]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                open_at = pos
                break
            depth -= 1
    if open_at < 0:
        return lines[hit] + "\n"
    depth = 0
    close_at = len(masked) - 1
    for pos in range(open_at, len(masked)):
        if masked[pos] == "(":
            depth += 1
        elif masked[pos] == ")":
            depth -= 1
            if depth == 0:
                close_at = pos
                break
    start = _line_of(offsets, open_at) - 1
    end = _line_of(offsets, close_at)
    return "\n".join(lines[start:end]).rstrip("\n") + "\n"


def extract_line_range(source: str, start: int, end: int) -> str:
    """Inclusive 1-based line range."""
    lines = source.splitlines(keepends=True)
    if start < 1 or end < start or end > len(lines):
        raise RecipeError(f"line range {start}..{end} outside 1..{len(lines)}")
    return "".join(lines[start - 1 : end]).rstrip("\n") + "\n"


def function_bounds_at(source: str, line: int, language: str = "c") -> tuple[int, int] | None:
    """1-based inclusive (start, end) of the function enclosing ``line``; None when not inside one."""
    lines = source.splitlines(keepends=True)
    if line < 1 or line > len(lines):
        return None
    if language == "python":
        return _python_bounds_at(lines, line)
    masked = mask_comments_and_strings(source, language)
    offsets = _line_offsets(source)
    target = offsets[line - 1]
    depth = 0
    open_at: int | None = None
    for pos, ch in enumerate(masked):
        if ch == "{":
            if depth == 0:
                open_at = pos
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and open_at is not None:
                if open_at <= target <= pos or _line_of(offsets, open_at) <= line <= _line_of(offsets, pos):
                    start = _declarator_start(source, masked, open_at)
                    return _line_of(offsets, start), _line_of(offsets, pos)
                open_at = None
    return None


WHOLE_FILE_MAX_LINES = 150


def extract_hunk(parent_source: str, fix_source: str, language: str = "c") -> tuple[str, str]:
    """Functions enclosing the first changed hunk that sits inside a function on both sides.

    Fallback for small modules (npm one-file packages, route files) whose change is at
    module level: when both blobs are at most ``WHOLE_FILE_MAX_LINES`` lines, the whole
    file is the excerpt. Larger module-level changes are a RecipeError.
    """
    parent_lines = parent_source.splitlines()
    fix_lines = fix_source.splitlines()
    matcher = difflib.SequenceMatcher(a=parent_lines, b=fix_lines, autojunk=False)
    changed = [(tag, i1, i2, j1, j2) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal"]
    if not changed:
        raise RecipeError("parent and fix blobs are identical")
    for _tag, i1, i2, j1, j2 in changed:
        parent_line = i1 + 1 if i2 > i1 else max(i1, 1)
        fix_line = j1 + 1 if j2 > j1 else max(j1, 1)
        parent_bounds = function_bounds_at(parent_source, parent_line, language)
        fix_bounds = function_bounds_at(fix_source, fix_line, language)
        if parent_bounds is not None and fix_bounds is not None:
            return (
                extract_line_range(parent_source, *parent_bounds),
                extract_line_range(fix_source, *fix_bounds),
            )
    if len(parent_lines) <= WHOLE_FILE_MAX_LINES and len(fix_lines) <= WHOLE_FILE_MAX_LINES:
        return parent_source.rstrip("\n") + "\n", fix_source.rstrip("\n") + "\n"
    raise RecipeError("no changed hunk is inside a function on both sides and the file is too large to vendor whole")


def _declarator_start(source: str, masked: str, anchor: int) -> int:
    """Start offset of the declarator statement that owns ``anchor`` (walk back to the previous ';', '}' or preprocessor line)."""
    pos = anchor - 1
    while pos >= 0:
        ch = masked[pos]
        if ch in ";}":
            break
        if ch == "\n":
            line_start = masked.rfind("\n", 0, pos) + 1
            if masked[line_start:pos].lstrip().startswith("#"):
                break
        pos -= 1
    start = pos + 1
    # Skip blank and comment-only lines between the boundary and the declarator.
    while True:
        line_end = source.find("\n", start)
        if line_end < 0:
            break
        if masked[start:line_end].strip():
            break
        start = line_end + 1
    return start


def _balanced_end(masked: str, brace: int) -> int:
    depth = 0
    for pos in range(brace, len(masked)):
        ch = masked[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return pos
    raise RecipeError("unbalanced braces")


def _line_offsets(source: str) -> list[int]:
    offsets = [0]
    for index, ch in enumerate(source):
        if ch == "\n":
            offsets.append(index + 1)
    return offsets


def _line_of(offsets: list[int], pos: int) -> int:
    low, high = 0, len(offsets) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if offsets[mid] <= pos:
            low = mid
        else:
            high = mid - 1
    return low + 1


def _python_block_end(lines: list[str], def_index: int, indent: int) -> int:
    """End index of the block starting at ``def_index``. Pass masked lines so the bodies of
    triple-quoted strings (blank after masking) never terminate the block."""
    end = def_index + 1
    last_code = def_index + 1
    while end < len(lines):
        line = lines[end]
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if len(line) - len(line.lstrip()) <= indent:
                break
            last_code = end + 1
        end += 1
    return last_code


def _python_bounds_at(lines: list[str], line: int) -> tuple[int, int] | None:
    index = line - 1
    masked = mask_comments_and_strings("".join(lines), "python").splitlines(keepends=True)
    for def_index in range(index, -1, -1):
        match = _DEF_RE.match(lines[def_index])
        if match is None:
            continue
        indent = len(match.group(1))
        end = _python_block_end(masked, def_index, indent)
        if def_index <= index < end:
            return def_index + 1, end
    return None


# --- recipes and IO ----------------------------------------------------------


def provenance_header(recipe: dict[str, Any], *, side: str, sha: str, upstream_start: int | None = None, relpath: str | None = None) -> str:
    lines = [
        f"Provenance: {recipe.get('repo', '')} {recipe.get('function', '')} ({side}).",
        f"repo: {recipe.get('repo', '')}",
        f"commit: {sha}",
        f"parent: {recipe.get('parent', '')}",
        f"commit_url: {recipe.get('commit_url', '')}",
        f"cve: {recipe.get('cve', '')}",
        f"license: {recipe.get('license', '')}",
        f"function: {recipe.get('function', '')}",
        f"relpath: {recipe.get('relpath', recipe.get('path', ''))}",
        f"provenance: {recipe.get('provenance', 'human')}",
        f"mechanism: {recipe.get('mechanism', 'other')}",
    ]
    if upstream_start is not None:
        lines.append(f"upstream_start: {upstream_start}")  # 1-based line of the excerpt body in the upstream file
    if relpath is not None:
        lines[8] = f"relpath: {relpath}"  # a context document names itself, not the handler file
    language = language_for(recipe) if relpath is None else _SUFFIX_LANGUAGE.get(Path(relpath).suffix.lower(), "c")
    if language in _HASH_COMMENT:
        return "\n".join(f"# {line}" for line in lines) + "\n"
    if language in {"cpp", "java", "javascript", "typescript"}:
        return "\n".join(f"// {line}" for line in lines) + "\n"
    return "/* " + "\n * ".join(lines) + "\n */\n"


def validate_recipe(recipe: dict[str, Any], *, require_license: bool = True) -> None:
    name = str(recipe.get("name", ""))
    if any(token in str(recipe).lower() for token in BLOCKED_TOKENS):
        raise RecipeError(f"{name}: embargoed or blocked dataset")
    if not recipe.get("parent") or not recipe.get("commit"):
        raise RecipeError(f"{name}: advisory-only recipe rejected; parent and commit required")
    mode = str(recipe.get("mode", "name"))
    if mode not in MODES:
        raise RecipeError(f"{name}: unknown mode {mode!r}; expected one of {MODES}")
    if not recipe.get("path"):
        raise RecipeError(f"{name}: path required")
    if mode in {"name", "handler_context"} and not recipe.get("function"):
        raise RecipeError(f"{name}: path and function required")
    if mode == "line_range" and not (isinstance(recipe.get("line_start"), int) and isinstance(recipe.get("line_end"), int)):
        raise RecipeError(f"{name}: line_range mode needs integer line_start and line_end")
    if mode == "enclosing" and not isinstance(recipe.get("line"), int):
        raise RecipeError(f"{name}: enclosing mode needs an integer line")
    if require_license and not recipe.get("license"):
        raise RecipeError(f"{name}: license required")
    for relpath in context_relpaths(recipe):
        suffix = Path(relpath).suffix.lower()
        if _SUFFIX_LANGUAGE.get(suffix) not in _CONTEXT_LANGUAGES:
            raise RecipeError(f"{name}: context document {relpath} has no supported registration reader")


def github_raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def excerpt_paths(recipe: dict[str, Any], root: Path) -> tuple[Path, Path]:
    name = str(recipe["name"])
    ext = Path(str(recipe.get("path", "a.c"))).suffix or ".c"
    folder = root / name
    return folder / f"vuln{ext}", folder / f"fixed{ext}"


def context_relpaths(recipe: dict[str, Any]) -> tuple[str, ...]:
    """Repo-relative documents that register the handler, fetched at the same two commits as the excerpt."""
    value = recipe.get("context") or ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def context_paths(recipe: dict[str, Any], root: Path) -> tuple[tuple[str, Path, Path], ...]:
    """`(relpath, vuln document, fixed document)` per context document. Each side keeps its own copy: the route table
    is part of the change often enough (a guard added to the router, not to the handler) that sharing one would hide
    the fix."""
    folder = root / str(recipe["name"]) / "context"
    return tuple((relpath, folder / "vuln" / relpath, folder / "fixed" / relpath) for relpath in context_relpaths(recipe))


_TOKEN_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "***REDACTED***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{12,}"), r"\1***REDACTED***"),
    (re.compile(r"\bsk-[A-Za-z0-9._\-]{16,}"), "***REDACTED***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***REDACTED***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "***REDACTED***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "***REDACTED***"),
    (re.compile(r"\bAIza[A-Za-z0-9_\-]{20,}"), "***REDACTED***"),
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)[^\s:/@]{3,}(@)"), r"\1***REDACTED***\2"),
    # Generic sensitive assignment: ONLY quoted literal values, so redaction never breaks code
    # (`password = request.form[...]` and `token = getToken()` are code, not secrets).
    (
        re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\b(\s*[=:]\s*)(['\"])[A-Za-z0-9/+_\-]{8,}\3"),
        r"\1\2\3***REDACTED***\3",
    ),
)


def redact(body: str) -> str:
    """Mask credential-shaped literals in an excerpt without changing code shape (mirrors openultrasast.redaction, quoted-only generic rule)."""
    for pattern, replacement in _TOKEN_PATTERNS:
        body = pattern.sub(replacement, body)
    return body


def write_excerpt(
    path: Path,
    recipe: dict[str, Any],
    *,
    side: str,
    sha: str,
    body: str,
    upstream_start: int | None = None,
    relpath: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = provenance_header(recipe, side=side, sha=sha, upstream_start=upstream_start, relpath=relpath)
    path.write_text(header + "\n" + redact(body), encoding="utf-8")


def extract_pair_with_lines(recipe: dict[str, Any], parent_src: str, fix_src: str) -> tuple[tuple[str, int], tuple[str, int]]:
    """Like ``extract_pair`` but also returns the 1-based upstream start line of each excerpt body."""
    language = language_for(recipe)
    mode = str(recipe.get("mode", "name"))
    if mode == "line_range":
        start, end = int(recipe["line_start"]), int(recipe["line_end"])
        fix_start = int(recipe.get("fix_line_start", start))
        fix_end = int(recipe.get("fix_line_end", end))
        return (extract_line_range(parent_src, start, end), start), (extract_line_range(fix_src, fix_start, fix_end), fix_start)
    if mode == "hunk":
        return _hunk_with_lines(parent_src, fix_src, language)
    if mode == "enclosing":
        line = int(recipe["line"])
        fix_line = int(recipe.get("fix_line", line))
        parent_bounds = function_bounds_at(parent_src, line, language)
        fix_bounds = function_bounds_at(fix_src, fix_line, language)
        if parent_bounds is None or fix_bounds is None:
            raise RecipeError(f"{recipe.get('name')}: line {line}/{fix_line} is not inside a function")
        return (extract_line_range(parent_src, *parent_bounds), parent_bounds[0]), (extract_line_range(fix_src, *fix_bounds), fix_bounds[0])
    function = str(recipe["function"])
    if mode == "handler_context":
        parent_text, fix_text = _handler_context_pair(recipe, parent_src, fix_src, language)
    else:
        parent_text, fix_text = extract_function(parent_src, function, language), extract_function(fix_src, function, language)
    return (parent_text, _start_line_of(parent_src, parent_text)), (fix_text, _start_line_of(fix_src, fix_text))


def _handler_context_pair(recipe: dict[str, Any], parent_src: str, fix_src: str, language: str) -> tuple[str, str]:
    """Both sides with their registration. ``line``/``fix_line`` anchor when the name repeats or when the fixed twin is
    a different, correctly guarded handler from the same snapshot (a Real-Vuln-Benchmark trap): then ``fix_function``
    names what the fixed side actually contains."""
    line = recipe.get("line")
    fix_line = recipe.get("fix_line", line)
    return (
        extract_handler_context(parent_src, str(recipe["function"]), language, line=int(line) if isinstance(line, int) else None),
        extract_handler_context(
            fix_src,
            str(recipe.get("fix_function") or recipe["function"]),
            language,
            line=int(fix_line) if isinstance(fix_line, int) else None,
        ),
    )


def _start_line_of(source: str, excerpt: str) -> int:
    first = excerpt.splitlines()[0] if excerpt.strip() else ""
    for index, line in enumerate(source.splitlines(), start=1):
        if line.rstrip() == first.rstrip():
            return index
    return 1


def _hunk_with_lines(parent_source: str, fix_source: str, language: str) -> tuple[tuple[str, int], tuple[str, int]]:
    parent_lines = parent_source.splitlines()
    fix_lines = fix_source.splitlines()
    matcher = difflib.SequenceMatcher(a=parent_lines, b=fix_lines, autojunk=False)
    changed = [(tag, i1, i2, j1, j2) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != "equal"]
    if not changed:
        raise RecipeError("parent and fix blobs are identical")
    for _tag, i1, i2, j1, j2 in changed:
        parent_line = i1 + 1 if i2 > i1 else max(i1, 1)
        fix_line = j1 + 1 if j2 > j1 else max(j1, 1)
        parent_bounds = function_bounds_at(parent_source, parent_line, language)
        fix_bounds = function_bounds_at(fix_source, fix_line, language)
        if parent_bounds is not None and fix_bounds is not None:
            return (extract_line_range(parent_source, *parent_bounds), parent_bounds[0]), (
                extract_line_range(fix_source, *fix_bounds),
                fix_bounds[0],
            )
    if len(parent_lines) <= WHOLE_FILE_MAX_LINES and len(fix_lines) <= WHOLE_FILE_MAX_LINES:
        return (parent_source.rstrip("\n") + "\n", 1), (fix_source.rstrip("\n") + "\n", 1)
    raise RecipeError("no changed hunk is inside a function on both sides and the file is too large to vendor whole")


def extract_pair(recipe: dict[str, Any], parent_src: str, fix_src: str) -> tuple[str, str]:
    """Apply the recipe's mode to two blobs. Pure; unit-tested offline."""
    language = language_for(recipe)
    mode = str(recipe.get("mode", "name"))
    if mode == "line_range":
        start, end = int(recipe["line_start"]), int(recipe["line_end"])
        fix_start = int(recipe.get("fix_line_start", start))
        fix_end = int(recipe.get("fix_line_end", end))
        return extract_line_range(parent_src, start, end), extract_line_range(fix_src, fix_start, fix_end)
    if mode == "hunk":
        return extract_hunk(parent_src, fix_src, language)
    if mode == "enclosing":
        line = int(recipe["line"])
        fix_line = int(recipe.get("fix_line", line))
        parent_bounds = function_bounds_at(parent_src, line, language)
        fix_bounds = function_bounds_at(fix_src, fix_line, language)
        if parent_bounds is None or fix_bounds is None:
            raise RecipeError(f"{recipe.get('name')}: line {line}/{fix_line} is not inside a function")
        return extract_line_range(parent_src, *parent_bounds), extract_line_range(fix_src, *fix_bounds)
    function = str(recipe["function"])
    if mode == "handler_context":
        return _handler_context_pair(recipe, parent_src, fix_src, language)
    return extract_function(parent_src, function, language), extract_function(fix_src, function, language)


def harvest_recipe(recipe: dict[str, Any], root: Path, *, require_license: bool = True) -> tuple[Path, Path]:
    """Fetch every blob the recipe names, extract, and only then write.

    Every fetch happens before the first write on purpose: a re-harvest that half succeeds would leave a reviewed
    excerpt truncated and its context document stale, and nothing downstream could tell that apart from a real
    upstream change (learning-harness Req 10.2)."""
    validate_recipe(recipe, require_license=require_license)
    if str(recipe.get("host", "github")) != "github":
        raise RecipeError(f"{recipe.get('name')}: live fetch currently implemented for host=github only")
    repo, parent, commit = str(recipe["repo"]), str(recipe["parent"]), str(recipe["commit"])
    fix_repo = str(recipe.get("fix_repo", repo))
    parent_src = fetch_url(github_raw_url(repo, parent, str(recipe["path"])))
    # fix_path lets a pair take its fixed side from another file of the same snapshot
    # (Real-Vuln-Benchmark false-positive traps are the fixed twins of vulnerable findings).
    fix_src = fetch_url(github_raw_url(fix_repo, commit, str(recipe.get("fix_path", recipe["path"]))))
    function = str(recipe.get("function", ""))
    fix_function = str(recipe.get("fix_function") or function)
    documents: list[tuple[Path, str, str, str, str]] = []
    for relpath, vuln_doc, fixed_doc in context_paths(recipe, root):
        language = _SUFFIX_LANGUAGE.get(Path(relpath).suffix.lower(), "c")
        for path, side, sha, wanted, source in (
            (vuln_doc, "vuln", parent, function, fetch_url(github_raw_url(repo, parent, relpath))),
            (fixed_doc, "fixed", commit, fix_function, fetch_url(github_raw_url(fix_repo, commit, relpath))),
        ):
            stanza = extract_registration_context(source, wanted, language)
            if not stanza.strip():
                raise RecipeError(f"{recipe.get('name')}: context document {relpath} never names {wanted}")
            documents.append((path, side, sha, stanza, relpath))
    (parent_fn, parent_start), (fix_fn, fix_start) = extract_pair_with_lines(recipe, parent_src, fix_src)
    vuln_path, fixed_path = excerpt_paths(recipe, root)
    write_excerpt(vuln_path, recipe, side="vuln", sha=parent, body=parent_fn, upstream_start=parent_start)
    write_excerpt(fixed_path, recipe, side="fixed", sha=commit, body=fix_fn, upstream_start=fix_start)
    for path, side, sha, stanza, relpath in documents:
        write_excerpt(path, recipe, side=side, sha=sha, body=stanza, relpath=relpath)
    return vuln_path, fixed_path


def materialize_pointer(recipe: dict[str, Any], cache_root: Path, *, slice_name: str) -> tuple[Path, Path]:
    """Harvest a non-vendored pair into ``cache_root/<slice>/<name>/`` (Req 10.2).

    The cache lives outside the repository; a missing upstream license is allowed here because nothing is redistributed,
    the excerpts stay on the operator's machine. Redaction applies as for vendored excerpts.
    """
    root = Path(cache_root) / slice_name
    vuln_path, fixed_path = excerpt_paths(recipe, root)
    if vuln_path.is_file() and fixed_path.is_file():
        return vuln_path, fixed_path
    return harvest_recipe(recipe, root, require_license=False)


def fetch_url(url: str, timeout: int = 60) -> str:
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise RecipeError(f"host not allowed: {host}")
    request = Request(url, headers={"User-Agent": "OpenUltraSAST-pair-harvest"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 — host allowlisted
        return response.read().decode("utf-8", "replace")


def merge_recipes(existing: list[dict[str, Any]], new: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Append ``new`` recipes whose name is not already present; existing rows are never rewritten (vendored labels stay put)."""
    names = {str(r["name"]) for r in existing}
    added = [r for r in new if str(r["name"]) not in names]
    return [*existing, *added], [str(r["name"]) for r in added]


def load_recipes(path: Path) -> tuple[dict[str, Any], ...]:
    payload = tomllib.loads(path.read_text())
    return tuple(dict(item) for item in payload.get("recipe", []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slice", default="vfc", help="slice directory under benchmarks/pairs (default: vfc)")
    parser.add_argument("--recipes", type=Path, default=None, help="recipes file (default: <slice>/recipes.toml)")
    parser.add_argument("--name", help="recipe name to harvest (omit with --all)")
    parser.add_argument("--all", action="store_true", help="process every recipe")
    parser.add_argument("--prefix", help="process every recipe whose name starts with this prefix")
    parser.add_argument("--fetch", action="store_true", help="HTTP-fetch and write excerpts; default is dry-run validate")
    parser.add_argument("--force", action="store_true", help="overwrite existing excerpts")
    parser.add_argument("--out", type=Path, default=None, help="excerpt root (default: <slice>/)")
    parser.add_argument("--report", type=Path, default=None, help="write a JSON row per recipe with its status and reason")
    args = parser.parse_args(argv)
    slice_root = ROOT / args.slice
    recipes_path = args.recipes or slice_root / "recipes.toml"
    out = args.out or slice_root
    loaded = load_recipes(recipes_path)
    recipes = {str(item["name"]): item for item in loaded}
    selected: list[dict[str, Any]]
    if args.all:
        selected = list(loaded)
    elif args.prefix:
        selected = [item for item in loaded if str(item["name"]).startswith(args.prefix)]
    elif args.name:
        if args.name not in recipes:
            print(f"unknown recipe: {args.name}", file=sys.stderr)
            return 2
        selected = [recipes[args.name]]
    else:
        print("pass --name RECIPE, --prefix PREFIX, or --all", file=sys.stderr)
        return 2
    failures = 0
    report: list[dict[str, str]] = []
    for recipe in selected:
        name = str(recipe["name"])
        try:
            validate_recipe(recipe)
        except RecipeError as exc:
            print(str(exc), file=sys.stderr)
            report.append({"name": name, "status": "failed", "reason": str(exc)})
            failures += 1
            continue
        if not args.fetch:
            print(f"ok {name} parent={recipe['parent']} commit={recipe['commit']} mode={recipe.get('mode', 'name')}")
            report.append({"name": name, "status": "validated", "reason": ""})
            continue
        vuln_path, fixed_path = excerpt_paths(recipe, out)
        if vuln_path.is_file() and fixed_path.is_file() and not args.force:
            print(f"skip {name} (exists)")
            report.append({"name": name, "status": "skipped", "reason": "excerpt already present"})
            continue
        try:
            harvest_recipe(recipe, out)
        except (RecipeError, OSError) as exc:
            # The excerpt on disk is the reviewed one; a fetch that failed leaves it exactly as it was and says why.
            print(f"{name}: {exc}", file=sys.stderr)
            report.append({"name": name, "status": "failed", "reason": str(exc)})
            failures += 1
            continue
        print(f"wrote {name} -> {vuln_path.parent}")
        report.append({"name": name, "status": "written", "reason": ""})
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
