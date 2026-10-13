"""Four fixed annotations computed from head source and the tool's own facts."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

from .. import mapping, source
from ..model.taxonomy import DEFAULT_FAMILIES_PATH, load_families
from ..preprocess import build_file_target, detect_language
from ..semantic.facts import load_facts
from ..semantic.ir import FileIR, parse_file
from ..semantic.obligations import check_obligations, load_obligation_facts
from ..semantic.obligations.dominance import OrderDominance
from ..semantic.obligations.operations import covers, find_operations, valid_witness
from .labels import label_rows
from .table import FEATURE_NAMES

Change = Mapping[str, Any]


class _Absent(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    return result.stdout.decode("utf-8", errors="replace")


def _safe_path(root: Path, path: str) -> Path:
    relative = Path(path)
    resolved = (root / relative).resolve()
    if relative.is_absolute() or any(part.startswith(".env") or part == ".git" for part in relative.parts):
        raise ValueError("private or absolute source path")
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("source path is outside the repository")
    return resolved


@dataclass
class Context:
    """Cache work shared by every candidate of one checked-out change."""

    root: Path
    change: Change
    texts: dict[str, str] = field(default_factory=dict)
    spans: dict[str, tuple[source.FunctionRange, ...]] = field(default_factory=dict)
    range_errors: dict[str, str] = field(default_factory=dict)
    irs: dict[str, FileIR] = field(default_factory=dict)
    diff_bytes: int = 0

    @cached_property
    def head_verified(self) -> bool:
        """True once the checkout is proven to be at the change's head; absent otherwise."""
        if _git(self.root, "rev-parse", "HEAD").strip() != _git(self.root, "rev-parse", str(self.change["head"])).strip():
            raise _Absent("head_mismatch")
        return True

    def verify_head(self) -> None:
        if not self.head_verified:
            raise _Absent("head_mismatch")

    def read(self, path: str) -> str:
        safe = _safe_path(self.root, path)
        if path not in self.texts:
            self.verify_head()
            data = safe.read_bytes()
            if not data:
                raise _Absent("empty_source")
            self.texts[path] = data.decode("utf-8", errors="replace")
        return self.texts[path]

    def ranges(self, path: str) -> tuple[source.FunctionRange, ...]:
        if path not in self.spans:
            self.spans[path] = source.ranges(path, self.read(path), source.canonical_language(detect_language(self.root / path)))
        return self.spans[path]

    @cached_property
    def product_files(self) -> list[str]:
        return source.product_files(self.root)

    @cached_property
    def entry_points(self) -> list[mapping.EntryPointRecord]:
        for path in self.product_files:
            self.read(path)
        return mapping.analyze_entry_points(self.root, [build_file_target(self.root, self.root / path) for path in self.product_files])

    @cached_property
    def hunks(self) -> dict[str, list[list[int]]]:
        """Line ranges per file that the push changed or added, at head."""
        return self._patch[0]

    @cached_property
    def deletions(self) -> dict[str, list[int]]:
        """Per file, the head lines after which the push removed lines (0 when it removed the top of the file).

        A fix that adds a guard is a push that removes it when replayed base-to-head, and that push has no added
        line at head: without this column the diff features are blind to exactly that shape."""
        return self._patch[1]

    @cached_property
    def _patch(self) -> tuple[dict[str, list[list[int]]], dict[str, list[int]]]:
        self.verify_head()
        # Exclude private files before git opens the patch; only hunk coordinates become features.
        patch = _git(
            self.root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "-U0",
            f"{self.change['base']}..{self.change['head']}",
            "--",
            ".",
            ":(glob,exclude)**/.env*",
            ":(exclude).env*",
        )
        self.diff_bytes = len(patch.encode("utf-8"))
        result: dict[str, list[list[int]]] = {}
        removed: dict[str, list[int]] = {}
        path = None
        for text in patch.splitlines():
            if text.startswith("+++ "):
                token = text[4:]
                token = json.loads(token) if token.startswith('"') else token
                path = token[2:] if token.startswith("b/") else None
            elif path is not None and (match := re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", text)):
                start, count = int(match[1]), int(match[2] or "1")
                if count:
                    result.setdefault(path, []).append([start, start + count - 1])
                else:
                    removed.setdefault(path, []).append(start)
        return result, removed

    def ir(self, path: str) -> FileIR:
        if path not in self.irs:
            self.irs[path] = parse_file(path, self.read(path), source.canonical_language(detect_language(self.root / path)))
        return self.irs[path]


Compute = Callable[[Path, Change, str, int, Context], dict[str, object]]


@dataclass(frozen=True)
class Producer:
    """A versioned producer with a closed output column list and private failure handling."""

    name: str
    version: str
    columns: tuple[str, ...]
    compute: Compute


def _producer(name: str, compute: Compute, version: str = "1") -> Producer:
    columns = tuple(f"feature.{name}.{column}" for column in FEATURE_NAMES[name])
    provenance = tuple(f"provenance.{name}.{column}" for column in ("ok", "reason", "version", "bytes_read"))

    def guarded(root: Path, change: Change, path: str, line: int, ctx: Context) -> dict[str, object]:
        result: dict[str, object] = dict.fromkeys(columns)
        reason = None
        before = set(ctx.texts)
        try:
            values = compute(root, change, path, line, ctx)
            if set(values) != set(FEATURE_NAMES[name]):
                raise ValueError("producer output does not match its columns")
            result.update({f"feature.{name}.{key}": value for key, value in values.items()})
        except Exception as error:
            reason = error.reason if isinstance(error, _Absent) else type(error).__name__
        bytes_read = sum(len(text.encode("utf-8")) for key, text in ctx.texts.items() if key not in before or key == path)
        if name == "diff":
            bytes_read = ctx.diff_bytes
        elif name == "taxonomy" and reason is None:
            bytes_read = len(DEFAULT_FAMILIES_PATH.read_bytes())
        result.update(
            {
                f"provenance.{name}.ok": reason is None,
                f"provenance.{name}.reason": reason,
                f"provenance.{name}.version": version,
                f"provenance.{name}.bytes_read": bytes_read,
            }
        )
        return result

    return Producer(name, version, columns + provenance, guarded)


def _diff(root: Path, change: Change, path: str, line: int, ctx: Context) -> dict[str, object]:
    hunks = ctx.hunks.get(path, [])
    deletions = ctx.deletions.get(path, [])
    # A removal sits between head lines `after` and `after + 1`; both lines count as touched.
    ranges = hunks + [[max(after, 1), max(after, 1) + 1] for after in deletions]
    distance = min((max(start - line, 0, line - end) for start, end in ranges), default=None)
    return {"hunks": hunks, "deletions": deletions, "on_changed_line": distance == 0, "distance": distance}


def _source(root: Path, change: Change, path: str, line: int, ctx: Context) -> dict[str, object]:
    ctx.read(path)
    if path in ctx.range_errors:
        raise _Absent(ctx.range_errors[path])
    facts = source.facts_for(root, path, line, entry_points=ctx.entry_points)
    # Select the occurrence at this line when several methods share a name.
    spans = [r for r in ctx.ranges(path) if r.name == facts.function and r.start <= line <= r.end]
    span = min(spans, key=lambda r: r.end - r.start) if spans else None
    return {
        "function": facts.function,
        "span": [span.start, span.end] if span else None,
        "callers": [list(caller) for caller in facts.callers],
        "entry_points": [{"path": entry.path, "line": entry.line, "kind": entry.kind} for entry in facts.entry_points],
        "language": facts.language,
    }


def _roles(function: Any, facts: Any) -> dict[str, str]:
    names = set(function.params)
    names.update(call.name for call in function.calls)
    for bind in function.binds:
        names.update((bind.name, *bind.names))
        if bind.call_name:
            names.add(bind.call_name)
    for call in function.calls:
        for arguments in call.arg_names:
            names.update(arguments)
    roles = {}
    for role, entries, attribute in (
        ("source", facts.sources, "patterns"),
        ("sink", facts.sinks, "calls"),
        ("sanitizer", facts.sanitizers, "calls"),
    ):
        for fact in entries:
            for pattern in getattr(fact, attribute):
                token = pattern.rstrip("(")
                for name in sorted(names):
                    if name == token or name.endswith("." + token) or token.startswith(name + ".") and role == "source":
                        # A shared sink/sanitizer name remains a sink; parameterization needs more than a name.
                        roles.setdefault(name, role)
    return roles


def _obligations(path: str, ctx: Context) -> list[dict[str, object]]:
    ir, text = ctx.ir(path), ctx.read(path)
    facts, flow = load_obligation_facts(), load_facts()
    scoped = facts.for_language(ir.language)
    if not scoped.operations and not scoped.dischargers:
        raise _Absent("obligations_language_unsupported")
    dominance = OrderDominance({path: text})
    result = check_obligations(
        irs={path: (ir, text)},
        entries=ctx.entry_points,
        facts=facts,
        flow_facts=flow,
        policy=None,
        paths=(),
        dominance=dominance,
        store_shapes=(),
        min_siblings=3,
    )
    # No finding does not imply discharge: the checker also gates on entry-point reachability.
    return [
        {
            "operation": operation.kind,
            "line": operation.line,
            "discharged": any(
                valid_witness(witness) and covers(witness, operation) and dominance.dominates(witness, operation, None)
                for witness in result.discharges
            ),
        }
        for operation in find_operations(ir, scoped, text=text)
    ]


def _semantic(root: Path, change: Change, path: str, line: int, ctx: Context) -> dict[str, object]:
    ir = ctx.ir(path)
    if not ir.parse_ok:
        raise _Absent("language_unsupported" if ir.reason == "language_unsupported" else "parse_failed")
    functions = [fn for fn in ir.functions if fn.start_line <= line <= fn.end_line]
    if not functions:
        raise _Absent("function_unavailable")
    function = min(functions, key=lambda fn: fn.end_line - fn.start_line)
    return {
        "roles": _roles(function, load_facts().for_language(ir.language)),
        "def_use": {
            "binds": [{"line": b.line, "name": b.name, "names": list(b.names), "call_name": b.call_name} for b in function.binds],
            "calls": [{"line": c.line, "name": c.name, "names": [list(names) for names in c.arg_names]} for c in function.calls],
        },
        "obligations": _obligations(path, ctx),
    }


def _taxonomy(root: Path, change: Change, path: str, line: int, ctx: Context) -> dict[str, object]:
    return {"families": [{"id": f.id, "definition": " ".join(f.description.split())} for f in load_families().families]}


PRODUCERS = (
    _producer("diff", _diff, version="2"),
    _producer("source", _source),
    _producer("semantic", _semantic),
    _producer("taxonomy", _taxonomy),
)


def _candidates(root: Path, change: Change, ctx: Context) -> list[dict[str, Any]]:
    selected: set[tuple[str, int]] = set()
    files = list(change.get("files", []))
    if change.get("kind") == "vulnerability" and not any(f["path"] == change["path"] for f in files):
        files.append({"path": change["path"], "head_lines": []})
    for file in files:
        path = file["path"]
        _safe_path(root, path)
        try:
            ranges = ctx.ranges(path)
        except Exception as error:
            ctx.range_errors[path] = error.reason if isinstance(error, _Absent) else type(error).__name__
            line = next((start for start, _ in file.get("head_lines", [])), 1)
            selected.add((path, max(1, line)))
            continue
        touched = [
            r
            for r in ranges
            if r.kind == "function" and any(r.start <= end and start <= r.end for start, end in file.get("head_lines", []))
        ]
        selected.update((path, r.start) for r in touched)
        if not touched and file.get("head_lines") and ranges:
            selected.add((path, max(1, file["head_lines"][0][0])))
        if change.get("kind") == "vulnerability" and path == change["path"]:
            labelled = [
                r
                for r in ranges
                if r.name == change["function"] and r.start <= change["function_lines"][1] and change["function_lines"][0] <= r.end
            ]
            selected.update((path, r.start) for r in labelled)
            if not labelled:
                selected.add((path, change["function_lines"][0]))
    return [
        {
            "change_id": change.get("id", change.get("case_id")),
            "repo": change.get("repo", change.get("repository")),
            "head": change["head"],
            "path": path,
            "line": line,
            "kind": change["kind"],
            "fold": change.get("fold"),
        }
        for path, line in sorted(selected)
    ]


def candidate_rows(root: Path, change: Change) -> list[dict[str, Any]]:
    """Enumerate touched head functions and the positive fix site, retaining unreadable files."""
    root = Path(root)
    return _candidates(root, change, Context(root, change))


def compute_rows(root: Path, change: Change, producers: tuple[Producer, ...] = PRODUCERS) -> list[dict[str, Any]]:
    """Fill candidate rows, then join labels after every producer has finished."""
    root = Path(root)
    # Producers receive only revision coordinates; advisory and label fields never cross this boundary.
    coordinates = {key: change[key] for key in ("base", "head")}
    ctx = Context(root, coordinates)
    rows = _candidates(root, change, ctx)
    for row in rows:
        for producer in producers:
            row.update(producer.compute(root, coordinates, row["path"], row["line"], ctx))
    return label_rows(rows, change)
