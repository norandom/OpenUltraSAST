from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

from .preprocess import enumerate_source_files


class PathEscapesRepo(ValueError):
    """Raised when a resolved tool path is not under the scan root."""


def clamp_repo_path(root: Path, user_path: str) -> Path:
    resolved_root = root.resolve()
    candidate = Path(user_path)
    resolved = candidate.resolve() if candidate.is_absolute() else (resolved_root / candidate).resolve()
    try:
        common = os.path.commonpath([str(resolved_root), str(resolved)])
    except ValueError as exc:
        raise PathEscapesRepo(f"path {user_path!r} escapes scan root {resolved_root}") from exc
    if common != str(resolved_root):
        raise PathEscapesRepo(f"path {user_path!r} escapes scan root {resolved_root}")
    return resolved


def read_file(root: Path, path: str, *, max_chars: int) -> str:
    clamped = clamp_repo_path(root, path)
    if max_chars <= 0:
        return ""
    return clamped.read_text(errors="ignore")[:max_chars]


# A matched line is quoted, not returned whole: a minified bundle's single line can be megabytes.
_LINE_CHARS = 240
_Lines = tuple[tuple[str, tuple[str, ...]], ...]
_SOURCE_MEMO: dict[tuple[str, int], tuple[_Lines, tuple[tuple[Path, int], ...]]] = {}


def _source_lines(root: Path) -> _Lines:
    """Every product source file under `root` with its lines, read ONCE per root state.

    Each `grep_repo` and `find_refs` call re-enumerated the tree -- walk, ignore rules, vendored checks -- and
    re-read every file. On a 1,800-file repository a model verifying candidates spent its hours there, CPU-bound,
    not waiting on the model. Keyed by the root's path and modification time, and a hit is re-validated file by
    file -- an edit inside a subdirectory does not touch the root's mtime. The value is immutable.
    """
    resolved_root = root.resolve()
    key = (str(resolved_root), resolved_root.stat().st_mtime_ns)
    entry = _SOURCE_MEMO.get(key)
    if entry is not None and all(_mtime(path) == stamp for path, stamp in entry[1]):
        return entry[0]
    files = list(_iter_clamped_source_files(resolved_root))
    lines = tuple((relative, tuple(path.read_text(errors="ignore").splitlines())) for relative, path in files)
    if len(_SOURCE_MEMO) >= 4:
        _SOURCE_MEMO.pop(next(iter(_SOURCE_MEMO)))
    _SOURCE_MEMO[key] = (lines, tuple((path, _mtime(path)) for _, path in files))
    return lines


def _mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return -1


def grep_repo(root: Path, pattern: str, *, max_matches: int) -> list[dict[str, object]]:
    if max_matches <= 0:
        return []
    compiled = re.compile(pattern)
    matches: list[dict[str, object]] = []
    for relative, lines in _source_lines(root):
        for line_no, line in enumerate(lines, start=1):
            if compiled.search(line):
                matches.append({"path": relative, "line": line_no, "text": line[:_LINE_CHARS]})
                if len(matches) >= max_matches:
                    return matches
    return matches


def find_refs(root: Path, symbol: str) -> list[dict[str, object]]:
    resolved_root = root.resolve()
    refs: list[dict[str, object]] = []
    if symbol:
        compiled = re.compile(rf"\b{re.escape(symbol)}\b")
        for relative, lines in _source_lines(resolved_root):
            for line_no, line in enumerate(lines, start=1):
                if compiled.search(line):
                    refs.append({"path": relative, "name": symbol, "line": line_no, "text": line[:_LINE_CHARS], "source": "text"})
    return refs


def _iter_clamped_source_files(root: Path) -> Iterator[tuple[str, Path]]:
    resolved_root = root.resolve()
    for path in enumerate_source_files(resolved_root):
        relative = path.relative_to(resolved_root).as_posix()
        yield relative, clamp_repo_path(resolved_root, relative)
