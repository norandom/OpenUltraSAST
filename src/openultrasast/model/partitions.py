"""Physical first-party frontend inputs and routing; selection remains in the scan ranker."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..cpg.backend import _DeadlineExpired, _remove_owned_tree
from ..preprocess import LANGUAGE_BY_EXTENSION
from .contracts import ExecutionBudget
from .layout import is_test_path, is_vendored, layout_facts

FRONTENDS = {
    "php": "php",
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "java": "java",
    "c": "c",
    "cpp": "c_cpp",
}


@dataclass(frozen=True)
class PartitionCoverage:
    language: str
    frontend: str | None
    paths: tuple[str, ...]
    source_bytes: int
    status: str
    boundaries: tuple[str, ...] = ()
    runtime: str = "unspecified"
    excluded_paths: tuple[str, ...] = ()
    unshipped_paths: tuple[str, ...] = ()


class PartitionGraph:
    """Routes existing requests without reordering or allocating another scan budget."""

    def __init__(self, budget: ExecutionBudget | None = None) -> None:
        self.budget = budget
        self.diagnostics: list[str] = []
        self.graphs: dict[str, Any] = {}
        self.roots: dict[str, Path] = {}
        self.path_languages: dict[str, str] = {}
        self.partitions: tuple[PartitionCoverage, ...] = ()
        self.boundaries: tuple[str, ...] = ()
        self.unparsed: tuple[str, ...] = ()
        self.cpg_path = Path("partitioned-cpg")

    def cleanup(self) -> None:
        try:
            for graph in self.graphs.values():
                cleanup = getattr(graph, "cleanup", None)
                if callable(cleanup):
                    cleanup()
        finally:
            for root in self.roots.values():
                deadline = self.budget.deadline_monotonic + self.budget.cancellation_allowance_seconds if self.budget else float("inf")
                try:
                    _remove_owned_tree(root, deadline)
                except (OSError, _DeadlineExpired):
                    self.diagnostics.append("scratch_cleanup_incomplete")

    def execution_diagnostics(self) -> tuple[str, ...]:
        reasons = list(self.diagnostics)
        for graph in self.graphs.values():
            read = getattr(graph, "execution_diagnostics", None)
            if callable(read):
                reasons.extend(read())
        return tuple(reasons)

    def _normalize(self, value: Any) -> Any:
        if isinstance(value, str):
            for root in self.roots.values():
                value = value.replace(str(root) + "/", "")
            return value
        if isinstance(value, list):
            return [self._normalize(v) for v in value]
        if isinstance(value, dict):
            return {k: self._normalize(v) for k, v in value.items()}
        return value

    def run(self, kind: str, params: Mapping[str, object]) -> list[object] | None:
        return self.run_batch(kind, {"one": params}).get("one")

    def run_batch(self, kind: str, requests: Mapping[str, Mapping[str, object]]) -> dict[str, list[object]]:
        answers: dict[str, list[object]] = {}
        languages = dict.fromkeys(self.path_languages.get(str(params.get("file", "")), "") for params in requests.values())
        for language in languages:
            graph = self.graphs.get(language)
            if graph is None:
                continue
            if self.budget is not None and time.monotonic() >= self.budget.deadline_monotonic:
                break
            selected = {rid: params for rid, params in requests.items() if self.path_languages.get(str(params.get("file", ""))) == language}
            if not selected:
                continue
            batch = getattr(graph, "run_batch", None)
            raw = batch(kind, selected) if callable(batch) else {rid: graph.run(kind, params) for rid, params in selected.items()}
            if not isinstance(raw, Mapping):
                continue
            for rid, rows in raw.items():
                if rid in selected and isinstance(rows, list):
                    answers[rid] = self._normalize(rows)
                elif rid == "__census__" and isinstance(rows, list):
                    expected = set(next(p.paths for p in self.partitions if p.language == language))
                    normalized = self._normalize(rows)
                    names = [r.get("file_names") for r in normalized if isinstance(r, Mapping)]
                    named = bool(names) and all(isinstance(n, list) and all(isinstance(p, str) for p in n) for n in names)
                    observed = {p.removeprefix("./") for n in names if isinstance(n, list) for p in n if isinstance(p, str)}
                    if not named or not expected <= observed:
                        self.diagnostics.append("partition_file_census_incomplete" if named else "partition_file_census_unavailable")
                        rows = [
                            {
                                "methods": 0,
                                "files": 0,
                                "shards": max((int(str(r.get("shards", 1))) for r in rows if isinstance(r, Mapping)), default=1),
                            }
                        ]
                    # Preserve any individual empty or sharded graph's degradation.
                    previous = answers.get(rid, [])
                    if not previous or any(
                        isinstance(r, Mapping) and (int(str(r.get("methods", 0))) == 0 or int(str(r.get("shards", 1))) > 1) for r in rows
                    ):
                        answers[rid] = rows
        return answers


def build_partitions(
    root: Path, build: Callable[[Path, str], Any], budget: ExecutionBudget | None, declared: Mapping[str, tuple[str, ...]] | None = None
) -> PartitionGraph:
    graph = PartitionGraph(budget)
    paths: dict[str, list[Path]] = {}
    boundaries: set[str] = set()
    excluded: set[str] = set()
    facts = layout_facts()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for directory, dirs, files, directory_fd in os.fwalk(
            ".", follow_symlinks=False, dir_fd=root_fd, onerror=lambda error: boundaries.add("source_unreadable")
        ):
            if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                boundaries.add("deadline_exhausted")
                break
            base = root / directory
            for name in list(dirs):
                if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                    boundaries.add("deadline_exhausted")
                    dirs.clear()
                    break
                path = base / name
                relative = path.relative_to(root).as_posix()
                if name in {".git", ".hg", ".svn", ".openultrasast", ".venv", "venv", "__pycache__"}:
                    excluded.add(relative + "/")
                    dirs.remove(name)
                    continue
                if path.is_symlink() or is_vendored(relative + "/", facts):
                    excluded.add(relative + "/")
                    boundaries.add("symlink_context_unresolved" if path.is_symlink() else "vendor_semantics_unresolved")
                    dirs.remove(name)
            for name in files:
                if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                    boundaries.add("deadline_exhausted")
                    break
                path = base / name
                relative = path.relative_to(root).as_posix()
                if is_vendored(relative, facts):
                    excluded.add(relative)
                    boundaries.add("vendor_semantics_unresolved")
                    continue
                if path.is_symlink() or not path.is_file():
                    excluded.add(relative)
                    boundaries.add("symlink_context_unresolved")
                    continue
                language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "unknown")
                if language == "unknown":
                    try:
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                        with os.fdopen(fd, "rb") as handle:
                            first = handle.readline(4096).lower()
                    except OSError:
                        boundaries.add("source_unreadable")
                        continue
                    if first.startswith(b"#!"):
                        language = "python" if b"python" in first else "javascript" if b"node" in first else "unknown"
                languages = (language,) if language != "unknown" else (declared or {}).get(relative, ())
                for item in languages:
                    paths.setdefault(item, []).append(path)
                if len(languages) == 1:
                    graph.path_languages[relative] = languages[0]
                elif languages:
                    boundaries.add("ambiguous_frontend_path")
        if len(paths) > 1:
            boundaries.add("cross_partition_semantics_unresolved")
        records: list[PartitionCoverage] = []
        for language, sources in sorted(paths.items()):
            relative_paths = tuple(sorted(p.relative_to(root).as_posix() for p in sources))
            frontend = FRONTENDS.get(language)
            if frontend is None:
                records.append(PartitionCoverage(language, None, relative_paths, 0, "unsupported", ("frontend_unsupported",)))
                boundaries.add("frontend_unsupported")
                continue
            scratch = Path(tempfile.mkdtemp(prefix="ousast-input-"))
            graph.roots[language] = scratch
            size = 0
            complete = True
            for source in sources:
                if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                    complete = False
                    break
                target = scratch / source.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                # A no-follow open prevents file symlink substitution between census and read.
                try:
                    fd = _open_source(root_fd, source.relative_to(root).parts)
                except OSError:
                    boundaries.add("source_unreadable")
                    complete = False
                    break
                with os.fdopen(fd, "rb") as handle, target.open("wb") as output:
                    while chunk := handle.read(1024 * 1024):
                        if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                            complete = False
                            break
                        output.write(chunk)
                        size += len(chunk)
                if not complete:
                    break
            built = build(scratch, frontend) if complete else None
            if built is not None:
                graph.graphs[language] = built
                graph.unparsed += tuple(graph._normalize(list(getattr(built, "unparsed", ()))))
            record_limits: tuple[str, ...] = ("runtime_unspecified",) if language in {"javascript", "typescript"} else ()
            if language == "typescript":
                record_limits += ("typescript_property_support_unvalidated",)
                boundaries.add("typescript_property_support_unvalidated")
            if language in {"c", "cpp"}:
                record_limits += ("c_bounds_arithmetic_unmodeled",)
            records.append(
                PartitionCoverage(language, frontend, relative_paths, size, "built" if built is not None else "build_failed", record_limits)
            )
        from dataclasses import replace

        graph.partitions = tuple(
            replace(
                record, excluded_paths=tuple(sorted(excluded)), unshipped_paths=tuple(p for p in record.paths if is_test_path(p, facts))
            )
            for record in records
        )
        graph.boundaries = tuple(sorted(boundaries))
        return graph
    except BaseException:
        graph.cleanup()
        raise
    finally:
        os.close(root_fd)


def _open_source(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise OSError("source is not a regular file")
        return result
    finally:
        os.close(descriptor)
