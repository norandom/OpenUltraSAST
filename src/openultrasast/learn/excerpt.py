"""Code excerpts for the decision engine's prompts and memory (learned-decision-engine design section 4.2).

No model. An excerpt is the body of the labelled function at its pin, as numbered lines, bounded:

- candidates: at most 80 lines and 4,000 characters, centred on the changed lines of a delta or the hit line;
- memory examples: at most 40 lines and 2,000 characters.

What an excerpt never holds: the path, the repository or the commit (none is rendered; a caller may name identity
strings -- ``owner/name``, the owner, the path, commit ids -- that are replaced wherever the code repeats them).
What it hides: advisory ids (CVE, GHSA) anywhere, and **comments with security wording** (:func:`.labels.
security_reason`, multilingual), which a fixed side often carries ("prevent XSS", "CVE-2021-1234") and which would
otherwise tell the model the label. Both become ``<redacted>``. A delta unit adds the base->head diff of the function
(at most 40 lines), the change under test -- never the later fix.

The text is normalised (trailing blanks dropped, ``\\n`` endings, one final newline) before it is hashed, so the sha
names the content an embedding and a response cache key are of.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..plane.tasks.repo_facts import DECLARATION, GLOBAL, _declared_name
from .features import function_span
from .labels import _ADVISORY, security_reason

REDACTED = "<redacted>"
LANGUAGE_ALIASES = {"c_cpp": "cpp", "c++": "cpp", "js": "javascript", "ts": "typescript", "py": "python"}
HASH_COMMENTS = frozenset({"python", "php", "ruby", "shell", "perl", "yaml", "r"})
SLASH_COMMENTS = frozenset(
    {"c", "cpp", "java", "javascript", "typescript", "php", "go", "groovy", "csharp", "kotlin", "rust", "swift", "scala"}
)  # fmt: skip
MAX_LINE_CHARS = 240
_HEX = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)


@dataclass(frozen=True)
class Bounds:
    lines: int
    chars: int


CANDIDATE = Bounds(80, 4000)
EXAMPLE = Bounds(40, 2000)
DIFF_LINES = 40


@dataclass(frozen=True)
class Excerpt:
    """A rendered excerpt: ``text`` (numbered lines, then the diff for a delta), its ``sha``, the first and last
    source line shown (1-based), and whether the bounds cut the function."""

    text: str
    sha: str
    first: int
    last: int
    truncated: bool

    @property
    def line_numbers(self) -> range:
        return range(self.first, self.last + 1)


def normalise(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


def excerpt_sha(text: str) -> str:
    return hashlib.sha256(normalise(text).encode("utf-8")).hexdigest()


# --- comments ---------------------------------------------------------------------------------------------------------


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


_OPEN = ("/**", "/*", "//", "#", '"""', "'''", "*")
_CLOSE = ("*/", '"""', "'''")


def _redact_comment(text: str) -> str:
    if security_reason(text) is None:
        return _ADVISORY.sub(REDACTED, text)
    stripped = text.strip()
    opener = next((o for o in _OPEN if stripped.startswith(o)), "")
    closer = next((c for c in _CLOSE if stripped.endswith(c) and len(stripped) > len(opener)), "")
    lead = text[: len(text) - len(text.lstrip())]
    return lead + " ".join(p for p in (opener, REDACTED, closer) if p)


def redact(lines: Sequence[str], language: str, identities: Iterable[str] = ()) -> list[str]:
    """``lines`` with security wording in comments and advisory ids anywhere replaced by ``<redacted>``, and every
    identity string (case-insensitive, at least 4 characters) replaced too."""
    language = LANGUAGE_ALIASES.get(language, language)
    names = sorted({i for i in identities if len(i) >= 4}, key=len, reverse=True)
    identity = re.compile("|".join(re.escape(n) for n in names), re.IGNORECASE) if names else None
    out: list[str] = []
    state: str | None = None
    for line in lines:
        ranges, state = _comment_ranges(line, state, language)
        text = line
        for start, end in reversed(ranges):
            text = text[:start] + _redact_comment(text[start:end]) + text[end:]
        text = _ADVISORY.sub(REDACTED, text)
        if identity is not None:
            text = identity.sub(REDACTED, text)
        out.append(text)
    return out


def identities_of(repo: str = "", path: str = "", commits: Iterable[str] = ()) -> tuple[str, ...]:
    """The identity strings an excerpt must not repeat: ``owner/name``, the owner, the path, commit ids. The bare
    repository name is kept: it is usually the package name the code imports, which is code, not an identity."""
    from .labels import repo_name

    found: list[str] = []
    slug = repo_name(repo) if repo else ""
    if "/" in slug:
        found += [slug, slug.split("/", 1)[0]]
    if path and "/" in path:
        found.append(path)
    found += [c for c in commits if c and _HEX.fullmatch(c)]
    return tuple(found)


# --- spans and excerpts -----------------------------------------------------------------------------------------------


def _brace_bounds(lines: Sequence[str], language: str, function: str) -> tuple[int, int] | None:
    """A brace language's definition of ``function`` (``Class::name`` and ``a.b`` reduced to the last name): the first
    line naming it before ``(`` whose ``{`` comes before any ``;``, to the matching ``}``. Comments are blanked
    before braces are counted."""
    name = re.split(r"::|\.|->", function)[-1]
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    call = re.compile(r"(?<![\w.>$])" + re.escape(name) + r"\s*\(")
    code: list[str] = []
    state: str | None = None
    for line in lines:
        ranges, state = _comment_ranges(line, state, language if language in SLASH_COMMENTS else "c")
        for start, end in reversed(ranges):
            line = line[:start] + " " * (end - start) + line[end:]
        code.append(line)
    for i, line in enumerate(code):
        found = call.search(line)
        if found is None or re.match(r"\s*(return|if|while|for|switch|else)\b", line):
            continue
        tail = "\n".join([line[found.end() :], *code[i + 1 : i + 8]])
        brace, semi = tail.find("{"), tail.find(";")
        if brace < 0 or (0 <= semi < brace):
            continue
        depth, opened = 0, False
        for j in range(i, len(code)):
            for c in line[found.end() :] if j == i else code[j]:
                if c == "{":
                    depth, opened = depth + 1, True
                elif c == "}" and opened:
                    depth -= 1
                    if depth == 0:
                        return i, j + 1
        return i, len(code)
    return None


def function_bounds(lines: Sequence[str], language: str, function: str) -> tuple[int, int] | None:
    """0-based ``[start, end)`` of the first declaration of ``function`` (the whole file for ``<global>``), or
    ``None`` when the file does not declare it. Languages without a repo-facts declaration pattern (C, C++, ...) and
    brace languages whose pattern misses the name use the brace matcher."""
    language = LANGUAGE_ALIASES.get(language, language)
    if function == GLOBAL:
        return (0, len(lines)) if lines else None
    pattern = DECLARATION.get(language)
    start = next((i for i, line in enumerate(lines) if _declared_name(pattern, line) == function), None) if pattern else None
    if start is None:
        return _brace_bounds(lines, language, function) if language in SLASH_COMMENTS or pattern is None else None
    span = function_span(lines, language, function)
    if not span:
        return None
    return start, min(start + span, len(lines))


def _window(start: int, end: int, focus: Sequence[int], size: int) -> tuple[int, int]:
    if end - start <= size:
        return start, end
    inside = sorted(f - 1 for f in focus if start <= f - 1 < end)
    if not inside:
        return start, start + size
    centre = inside[len(inside) // 2]
    lo = max(start, min(centre - size // 2, end - size))
    return lo, lo + size


def _numbered(lines: Sequence[str], first: int) -> list[str]:
    out = []
    for offset, line in enumerate(lines):
        text = line if len(line) <= MAX_LINE_CHARS else line[: MAX_LINE_CHARS - 3] + "..."
        out.append(f"{first + offset:>5}  {text}")
    return out


def excerpt(
    lines: Sequence[str] | None,
    language: str,
    function: str,
    *,
    bounds: Bounds = CANDIDATE,
    focus: Sequence[int] = (),
    identities: Iterable[str] = (),
    diff: str | None = None,
) -> Excerpt | None:
    """The bounded, redacted, numbered excerpt of ``function``, or ``None`` when the file is unread or the function is
    not declared there (never an empty excerpt). ``focus`` are 1-based lines to centre on; ``diff`` (a delta's
    :func:`delta_diff`) is appended under a ``diff:`` line."""
    if not lines:
        return None
    span = function_bounds(lines, language, function)
    if span is None:
        return None
    start, end = span
    lo, hi = _window(start, end, focus, bounds.lines)
    shown = redact(lines[lo:hi], language, identities)
    rendered = _numbered(shown, lo + 1)
    centre = (len(rendered) - 1) // 2 if focus else 0
    truncated = (lo, hi) != (start, end)
    while len(rendered) > 1 and len("\n".join(rendered)) > bounds.chars:
        # drop the line farthest from the centre (the end when there is no focus), keeping the window contiguous
        if focus and centre > len(rendered) - 1 - centre:
            rendered.pop(0)
            lo += 1
            centre -= 1
        else:
            rendered.pop()
        hi = lo + len(rendered)
        truncated = True
    body = "\n".join(rendered)
    if diff:
        body += "\ndiff:\n" + diff
    text = normalise(body)
    if not text.strip():
        return None
    return Excerpt(text, excerpt_sha(text), lo + 1, hi, truncated)


def delta_diff(
    base: Sequence[str], head: Sequence[str], language: str, *, max_lines: int = DIFF_LINES, identities: Iterable[str] = ()
) -> str:
    """The base->head unified diff of a function (one line of context, no file headers), redacted, at most
    ``max_lines`` lines."""
    diff = [line for line in difflib.unified_diff(list(base), list(head), lineterm="", n=1)][2:]
    out: list[str] = []
    for line in diff:
        if line.startswith("@@"):
            out.append(line)
        else:
            out.append(line[:1] + redact([line[1:]], language, identities)[0])
    if len(out) > max_lines:
        out = out[: max_lines - 1] + [f"... ({len(out) - max_lines + 1} more diff lines)"]
    return "\n".join(out)


__all__ = [
    "CANDIDATE", "DIFF_LINES", "EXAMPLE", "REDACTED", "Bounds", "Excerpt", "delta_diff", "excerpt", "excerpt_sha",
    "function_bounds", "identities_of", "normalise", "redact",
]  # fmt: skip
