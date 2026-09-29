"""`repo-facts`: the memory layer of the service plane (ai-service-plane, Requirement 5.1 / 5.2).

Source text only, no model, no git. For every product file: the functions it defines; and for every candidate
function, the call sites in *other* product files (path, 1-based line, enclosing function), capped at 40 and
sorted. The unit of work is one file (Requirement 2.2): a row goes to `units.jsonl` as each file finishes and
a restart skips the rows already there. `facts.json` is assembled from the rows and is byte-identical across
runs over the same tree; `summary.json` is written last and says `done` only when every unit finished.

The declaration patterns follow `benchmarks/independent/sink_candidates.py`, extended to Java, Go and Ruby;
the product filter follows `model_sinks.py` plus the `[[layout]]` facts (`model.layout`) for the languages that
declare them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import traceback
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ...model.layout import is_test_path, is_vendored, layout_facts
from ...preprocess import IGNORED_DIRS, detect_language

CALLERS_CAP = 40
MAX_FILE_BYTES = 1_000_000
LANGUAGES = frozenset({"python", "php", "javascript", "typescript", "java", "go", "ruby"})
GLOBAL = "<global>"

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


class TaskFailed(RuntimeError):
    """A crash inside `run` that has already been recorded in `summary.json` (status `failed`, traceback)."""


def product_files(workspace: Path) -> list[Path]:
    """Product source files of the supported languages, sorted; tests, vendored trees, build output, minified
    bundles and dot-directories are not product (the classification of `model_sinks.py` and the layout facts)."""
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


def enclosing(lines: Sequence[str], index: int, language: str) -> str:
    """The nearest declaration at or above line ``index`` (0-based), `<global>` when there is none."""
    pattern = DECLARATION.get(language)
    if pattern is None:
        return GLOBAL
    indent = _indent(lines[index]) if language == "python" else None
    for back in range(index, -1, -1):
        name = _declared_name(pattern, lines[back])
        if not name:
            continue
        if indent is None or back == index or _indent(lines[back]) < indent:
            return name
        indent = min(indent, _indent(lines[back]))  # a sibling or deeper def: keep looking for the one that encloses
    return GLOBAL


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def call_sites(lines: Sequence[str], language: str, names: Iterable[str]) -> list[dict[str, Any]]:
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
            found.append({"function": name, "line": index + 1, "enclosing": enclosing(lines, index, language)})
    return found


def _declared_name(pattern: re.Pattern[str], line: str) -> str:
    match = pattern.match(line)
    if not match:
        return ""
    name = next((g for g in match.groups() if g), "")
    return "" if name in KEYWORDS else name


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _candidate_names(candidates: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({str(c["function"]) for c in candidates if c.get("function")})


def _digest(names: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16]


def _load_units(units_path: Path, digest: str) -> dict[str, dict[str, Any]]:
    """Rows already in `units.jsonl` that were computed for the same candidate set (Requirement 2.2)."""
    rows: dict[str, dict[str, Any]] = {}
    if not units_path.is_file():
        return rows
    for raw in units_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("digest") == digest and isinstance(row.get("path"), str):
            rows[row["path"]] = row
    return rows


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary(output_dir: Path, *, status: str, units_done: int, units_total: int, **extra: Any) -> dict[str, Any]:
    """The task contract's `summary.json`: `done` is refused unless every unit finished."""
    if status == "done" and units_done != units_total:
        status = "failed"
        extra.setdefault("reason", f"{units_done} of {units_total} units finished")
    summary: dict[str, Any] = {
        "status": status,
        "units_done": units_done,
        "units_total": units_total,
        "usd": None,
        "calls": 0,
        "usage": {},
        "model": None,
        **extra,
    }
    _write_json(output_dir / "summary.json", summary)
    return summary


def assemble_facts(
    rows: Mapping[str, Mapping[str, Any]], candidates: Sequence[Mapping[str, Any]], cap: int = CALLERS_CAP
) -> dict[str, Any]:
    """`facts.json` from the per-file rows: functions per file, and per candidate the callers in other files."""
    files = {path: {"functions": list(row.get("functions", ()))} for path, row in sorted(rows.items())}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for path, row in sorted(rows.items()):
        for call in row.get("calls", ()):
            by_name.setdefault(str(call["function"]), []).append(
                {"path": path, "line": int(call["line"]), "enclosing": str(call.get("enclosing", GLOBAL))}
            )
    callers: dict[str, list[dict[str, Any]]] = {}
    for candidate in sorted(candidates, key=lambda c: (str(c["path"]), str(c["function"]))):
        path, name = str(candidate["path"]), str(candidate["function"])
        sites = sorted(
            (site for site in by_name.get(name, ()) if site["path"] != path), key=lambda s: (s["path"], s["line"], s["enclosing"])
        )
        callers[f"{path}::{name}"] = sites[:cap]
    return {
        "files": files,
        "callers": callers,
        "counts": {
            "files": len(files),
            "functions": sum(len(f["functions"]) for f in files.values()),
            "candidates": len(callers),
            "callers": sum(len(v) for v in callers.values()),
        },
    }


def run(workspace: Path, output_dir: Path, candidates: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Compute the facts for ``workspace`` into ``output_dir``; returns the written summary.

    ``candidates`` rows are ``{"path", "function"}`` (workspace-relative POSIX path). ``None`` means every
    function every product file defines. A `units.jsonl` row from an earlier run over the same candidate set
    is reused, not recomputed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    units_path = output_dir / "units.jsonl"
    files = product_files(workspace)
    languages = {p: detect_language(p) for p in files}
    wanted: list[dict[str, Any]]
    if candidates is None:
        wanted = [
            {"path": p.relative_to(workspace).as_posix(), "function": name}
            for p in files
            for name in declared_functions(_read_lines(p), languages[p])
        ]
    else:
        wanted = [{"path": str(c["path"]), "function": str(c["function"])} for c in candidates]
    names = _candidate_names(wanted)
    digest = _digest(names)
    present = {p.relative_to(workspace).as_posix() for p in files}
    rows = {path: row for path, row in _load_units(units_path, digest).items() if path in present}
    try:
        with units_path.open("a", encoding="utf-8") as sink:
            for path in files:
                relative = path.relative_to(workspace).as_posix()
                if relative in rows:
                    continue
                lines = _read_lines(path)
                row: dict[str, Any] = {
                    "path": relative,
                    "language": languages[path],
                    "digest": digest,
                    "functions": declared_functions(lines, languages[path]),
                    "calls": call_sites(lines, languages[path], names),
                }
                sink.write(json.dumps(row, sort_keys=True) + "\n")
                sink.flush()
                rows[relative] = row
    except Exception as exc:
        write_summary(
            output_dir, status="failed", units_done=len(rows), units_total=len(files), reason=str(exc), traceback=traceback.format_exc()
        )
        raise TaskFailed(str(exc)) from exc
    facts = assemble_facts(rows, wanted)
    _write_json(output_dir / "facts.json", facts)
    return write_summary(output_dir, status="done", units_done=len(rows), units_total=len(files))


def _load_candidates(path: str | None) -> list[dict[str, Any]] | None:
    if not path:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("candidates", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError(f"{path}: candidates must be a list of {{path, function}} rows")
    return [{"path": str(row["path"]), "function": str(row["function"])} for row in rows]


def main(environ: Mapping[str, str] | None = None) -> int:
    """Entrypoint under the task contract: `OUSAST_WORKSPACE_DIR`, `OUSAST_OUTPUT_DIR`, optional
    `OUSAST_INPUT_CANDIDATES` (a JSON file). Exit 0 when done, 2 when failed; a crash still leaves a
    `summary.json` with the traceback."""
    env = environ if environ is not None else os.environ
    output_dir = Path(env.get("OUSAST_OUTPUT_DIR") or "")
    try:
        if not env.get("OUSAST_OUTPUT_DIR"):
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        workspace = Path(env.get("OUSAST_WORKSPACE_DIR") or "")
        if not env.get("OUSAST_WORKSPACE_DIR") or not workspace.is_dir():
            raise ValueError(f"OUSAST_WORKSPACE_DIR is not a directory: {workspace}")
        summary = run(workspace, output_dir, _load_candidates(env.get("OUSAST_INPUT_CANDIDATES")))
    except TaskFailed as exc:
        print(f"repo-facts failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if env.get("OUSAST_OUTPUT_DIR"):
            output_dir.mkdir(parents=True, exist_ok=True)
            write_summary(output_dir, status="failed", units_done=0, units_total=0, reason=str(exc), traceback=traceback.format_exc())
        print(f"repo-facts failed: {exc}", file=sys.stderr)
        return 2
    return 0 if summary["status"] == "done" else 2


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "CALLERS_CAP",
    "DECLARATION",
    "TaskFailed",
    "assemble_facts",
    "call_sites",
    "declared_functions",
    "enclosing",
    "main",
    "product_files",
    "run",
    "write_summary",
]
