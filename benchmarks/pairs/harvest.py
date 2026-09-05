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
import re
import sys
import tomllib
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
MODES = ("name", "line_range", "hunk", "enclosing")
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
}
_HASH_COMMENT = {"python", "perl"}
_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")


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
        start = index
        while (
            start > 0 and lines[start - 1].lstrip().startswith("@") and (len(lines[start - 1]) - len(lines[start - 1].lstrip())) == indent
        ):
            start -= 1  # decorators belong to the function
        end = _python_block_end(masked, index, indent)
        return "".join(lines[start:end]).rstrip("\n") + "\n"
    raise RecipeError(f"function not found: {function_name}")


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


def provenance_header(recipe: dict[str, Any], *, side: str, sha: str, upstream_start: int | None = None) -> str:
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
    language = language_for(recipe)
    if language in _HASH_COMMENT:
        return "\n".join(f"# {line}" for line in lines) + "\n"
    if language in {"cpp", "java", "javascript", "typescript"}:
        return "\n".join(f"// {line}" for line in lines) + "\n"
    return "/* " + "\n * ".join(lines) + "\n */\n"


def validate_recipe(recipe: dict[str, Any]) -> None:
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
    if mode == "name" and not recipe.get("function"):
        raise RecipeError(f"{name}: path and function required")
    if mode == "line_range" and not (isinstance(recipe.get("line_start"), int) and isinstance(recipe.get("line_end"), int)):
        raise RecipeError(f"{name}: line_range mode needs integer line_start and line_end")
    if mode == "enclosing" and not isinstance(recipe.get("line"), int):
        raise RecipeError(f"{name}: enclosing mode needs an integer line")
    if not recipe.get("license"):
        raise RecipeError(f"{name}: license required")


def github_raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def excerpt_paths(recipe: dict[str, Any], root: Path) -> tuple[Path, Path]:
    name = str(recipe["name"])
    ext = Path(str(recipe.get("path", "a.c"))).suffix or ".c"
    folder = root / name
    return folder / f"vuln{ext}", folder / f"fixed{ext}"


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


def write_excerpt(path: Path, recipe: dict[str, Any], *, side: str, sha: str, body: str, upstream_start: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = provenance_header(recipe, side=side, sha=sha, upstream_start=upstream_start)
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
    parent_text = extract_function(parent_src, function, language)
    fix_text = extract_function(fix_src, function, language)
    return (parent_text, _start_line_of(parent_src, parent_text)), (fix_text, _start_line_of(fix_src, fix_text))


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
    return extract_function(parent_src, function, language), extract_function(fix_src, function, language)


def harvest_recipe(recipe: dict[str, Any], root: Path) -> tuple[Path, Path]:
    validate_recipe(recipe)
    if str(recipe.get("host", "github")) != "github":
        raise RecipeError(f"{recipe.get('name')}: live fetch currently implemented for host=github only")
    parent_src = fetch_url(github_raw_url(str(recipe["repo"]), str(recipe["parent"]), str(recipe["path"])))
    # fix_path lets a pair take its fixed side from another file of the same snapshot
    # (Real-Vuln-Benchmark false-positive traps are the fixed twins of vulnerable findings).
    fix_src = fetch_url(
        github_raw_url(str(recipe.get("fix_repo", recipe["repo"])), str(recipe["commit"]), str(recipe.get("fix_path", recipe["path"])))
    )
    (parent_fn, parent_start), (fix_fn, fix_start) = extract_pair_with_lines(recipe, parent_src, fix_src)
    vuln_path, fixed_path = excerpt_paths(recipe, root)
    write_excerpt(vuln_path, recipe, side="vuln", sha=str(recipe["parent"]), body=parent_fn, upstream_start=parent_start)
    write_excerpt(fixed_path, recipe, side="fixed", sha=str(recipe["commit"]), body=fix_fn, upstream_start=fix_start)
    return vuln_path, fixed_path


def fetch_url(url: str, timeout: int = 60) -> str:
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise RecipeError(f"host not allowed: {host}")
    request = Request(url, headers={"User-Agent": "OpenUltraSAST-pair-harvest"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 — host allowlisted
        return response.read().decode("utf-8", "replace")


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
    for recipe in selected:
        name = str(recipe["name"])
        try:
            validate_recipe(recipe)
        except RecipeError as exc:
            print(str(exc), file=sys.stderr)
            failures += 1
            continue
        if not args.fetch:
            print(f"ok {name} parent={recipe['parent']} commit={recipe['commit']} mode={recipe.get('mode', 'name')}")
            continue
        vuln_path, fixed_path = excerpt_paths(recipe, out)
        if vuln_path.is_file() and fixed_path.is_file() and not args.force:
            print(f"skip {name} (exists)")
            continue
        try:
            harvest_recipe(recipe, out)
        except (RecipeError, OSError) as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"wrote {name} -> {vuln_path.parent}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
