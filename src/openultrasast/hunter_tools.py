from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from .preprocess import FileTarget, enumerate_source_files


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


# --- curated structural tools (learning-harness, Req 6.4, 6.5) --------------------------------------
# A detector reads code with `read_file` and `read_definition`; the three list tools below answer with
# identifiers and line spans only, so they can never become a second way to dump the repository. Every
# path a caller supplies is clamped to the scan root first. No caching: a detector calls these a handful
# of times per region, and a stale view of a tree that a round may have rewritten is worse than a reparse.


def read_definition(root: Path, symbol: str, *, max_chars: int, path: str | None = None) -> dict[str, object] | None:
    """The definition of one named function: where it is, how far it runs, and its text. None when absent."""
    resolved_root = root.resolve()
    scope = clamp_repo_path(resolved_root, path) if path is not None else None
    for relative, target in _iter_clamped_source_files(resolved_root):
        if scope is not None and target != scope:
            continue
        text = target.read_text(errors="ignore")
        span = _named_span(relative, text, symbol)
        if span is None:
            continue
        lines = text.splitlines()
        start, end = span
        while start > 1 and lines[start - 2].lstrip().startswith("@"):
            start -= 1  # a handler's decorators are part of what the detector must see
        body = "\n".join(lines[start - 1 : end])
        return {"path": relative, "name": symbol, "start_line": start, "end_line": end, "text": body[: max(max_chars, 0)]}
    return None


def entry_points(root: Path, *, path: str | None = None) -> list[dict[str, object]]:
    """Handlers the mapper names, with their access classification and evidence. No source text."""
    from .mapping import analyze_entry_points

    resolved_root = root.resolve()
    relative = _relative_or_none(resolved_root, path)
    targets = _repo_targets(resolved_root)
    rows: list[dict[str, object]] = []
    for record in analyze_entry_points(resolved_root, targets):
        if relative is not None and record.path != relative:
            continue
        rows.append(
            {
                "path": record.path,
                "function": record.function_name,
                "name": record.name,
                "kind": record.kind,
                "line": record.line,
                "end_line": record.end_line,
                "access_level": record.access_level,
                "evidence": list(record.access_evidence),
            }
        )
    return rows


def flows(root: Path, *, path: str, function: str) -> list[dict[str, object]]:
    """Adjudicated source-to-sink records inside one function: which source, which sink, what the overlay said."""
    from .findings import quick_scan_findings
    from .rank import rank_targets
    from .semantic import adjudicate

    resolved_root = root.resolve()
    relative = _relative_or_none(resolved_root, path)
    targets = _repo_targets(resolved_root)
    span = _span_in(resolved_root, relative, function)
    if span is None:
        return []
    findings = [item for item in quick_scan_findings(resolved_root, targets, rank_targets(targets), None) if item.status != "shadow"]
    rows: list[dict[str, object]] = []
    for record in adjudicate(root=resolved_root, targets=targets, findings=findings):
        if record.path != relative or record.line is None or not span[0] <= record.line <= span[1]:
            continue
        rows.append(
            {
                "path": record.path,
                "function": function,
                "line": record.line,
                "sources": list(record.sources),
                "sinks": list(record.sinks),
                "disposition": record.disposition,
                "cwe": record.cwe,
            }
        )
    return rows


def obligations(root: Path, *, path: str, function: str) -> list[dict[str, object]]:
    """What one function owes and has not discharged: the operation, the missing discharger, why it is owed."""
    from .config import ObligationsConfig
    from .semantic.facts import FactLoadError, load_facts
    from .semantic.ir import parse_file
    from .semantic.obligations import check_obligations, load_obligation_facts
    from .semantic.obligations.dominance import OrderDominance

    resolved_root = root.resolve()
    relative = _relative_or_none(resolved_root, path)
    targets = _repo_targets(resolved_root)
    try:
        flow_facts = load_facts()
    except FactLoadError:
        return []
    irs: dict[str, tuple[object, str]] = {}
    texts: dict[str, str] = {}
    for target in targets:
        try:
            text = (resolved_root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        texts[target.path] = text
        irs[target.path] = (parse_file(target.path, text, target.language), text)
    from .mapping import analyze_entry_points

    result = check_obligations(
        irs=irs,  # type: ignore[arg-type]
        entries=analyze_entry_points(resolved_root, targets),
        facts=load_obligation_facts(),
        flow_facts=flow_facts,
        policy=None,
        paths=(),
        dominance=OrderDominance(texts=texts),
        store_shapes=(),
        min_siblings=ObligationsConfig().min_siblings,
    )
    return [
        {
            "path": finding.operation.path,
            "function": finding.operation.function,
            "line": finding.operation.line,
            "operation": finding.operation.kind,
            "resource": finding.operation.resource,
            "missing": finding.missing,
            "label": finding.label,
            "evidence": list(finding.evidence),
        }
        for finding in result.findings
        if (relative is None or finding.operation.path == relative) and finding.operation.function == function
    ]


def _repo_targets(root: Path) -> list[FileTarget]:
    from .preprocess import preprocess_repository

    _, targets = preprocess_repository(root)
    return list(targets)


def _relative_or_none(root: Path, path: str | None) -> str | None:
    if path is None:
        return None
    return clamp_repo_path(root, path).relative_to(root).as_posix()


def _named_span(relative: str, text: str, symbol: str) -> tuple[int, int] | None:
    from .preprocess import detect_language
    from .semantic.functions import named_function_ranges, spans_named

    ranges = named_function_ranges(relative, text, detect_language(Path(relative)))
    spans = spans_named(ranges or (), symbol)
    return spans[0] if spans else None


def _span_in(root: Path, relative: str | None, function: str) -> tuple[int, int] | None:
    if relative is None:
        return None
    try:
        text = (root / relative).read_text(errors="ignore")
    except OSError:
        return None
    return _named_span(relative, text, function)
