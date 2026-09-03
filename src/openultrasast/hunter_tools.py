from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator, Mapping
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


def grep_repo(root: Path, pattern: str, *, max_matches: int) -> list[dict[str, object]]:
    if max_matches <= 0:
        return []
    compiled = re.compile(pattern)
    matches: list[dict[str, object]] = []
    for relative, path in _iter_clamped_source_files(root):
        for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
            if compiled.search(line):
                matches.append({"path": relative, "line": line_no, "text": line})
                if len(matches) >= max_matches:
                    return matches
    return matches


def find_refs(root: Path, symbol: str, mapping_index: object) -> list[dict[str, object]]:
    resolved_root = root.resolve()
    refs: list[dict[str, object]] = []
    for record in _iter_mapping_records(mapping_index):
        if not _record_matches_symbol(record, symbol):
            continue
        raw_path = _record_path(record)
        if raw_path is None:
            continue
        clamped = clamp_repo_path(resolved_root, raw_path)
        name = _record_value(record, "name", "function_name", "symbol")
        refs.append(
            {
                "path": clamped.relative_to(resolved_root).as_posix(),
                "name": str(name) if name is not None else symbol,
                "line": _as_line(_record_value(record, "line")),
                "source": "mapping",
            }
        )
    if symbol:
        compiled = re.compile(rf"\b{re.escape(symbol)}\b")
        for relative, path in _iter_clamped_source_files(resolved_root):
            for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
                if compiled.search(line):
                    refs.append({"path": relative, "name": symbol, "line": line_no, "text": line, "source": "text"})
    return refs


def _iter_clamped_source_files(root: Path) -> Iterator[tuple[str, Path]]:
    resolved_root = root.resolve()
    for path in enumerate_source_files(resolved_root):
        relative = path.relative_to(resolved_root).as_posix()
        yield relative, clamp_repo_path(resolved_root, relative)


def _iter_mapping_records(mapping_index: object) -> Iterable[object]:
    if mapping_index is None:
        return ()
    if isinstance(mapping_index, Mapping):
        return (mapping_index,)
    if isinstance(mapping_index, (str, bytes, bytearray)):
        return ()
    if isinstance(mapping_index, Iterable):
        return mapping_index
    return (mapping_index,)


def _record_matches_symbol(record: object, symbol: str) -> bool:
    for field in ("name", "function_name", "symbol"):
        value = _record_value(record, field)
        if value is not None and str(value) == symbol:
            return True
    return False


def _record_path(record: object) -> str | None:
    value = record.get("path") if isinstance(record, Mapping) else getattr(record, "path", None)
    if value is None:
        return None
    return str(value)


def _record_value(record: object, *names: str) -> object | None:
    for name in names:
        raw: object | None
        if isinstance(record, Mapping):
            if name not in record:
                continue
            raw = record[name]
        else:
            raw = getattr(record, name, None)
        if raw is not None:
            return raw
    return None


def _as_line(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    return None
