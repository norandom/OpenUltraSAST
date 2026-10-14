"""Ordered security structure and bounded argument provenance for examined paths."""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any

from ..ir import FileIR, FunctionIR, trailing_name
from .dominance import Dominance
from .facts import ObligationFacts
from .operations import Discharge, Operation, valid_witness
from .paths import PathRecord
from .shapes import _call_matches


@dataclass(frozen=True)
class Guard:
    kind: str
    scope: str
    line: int | None
    provenance: str
    fact_id: str


@dataclass(frozen=True)
class Hop:
    function: str
    call_line: int | None
    guards_before_call: tuple[Guard, ...]
    forwarded: tuple[str, ...]


@dataclass(frozen=True)
class Trace:
    entry_kind: str
    boundary: str
    access: str
    parameters: tuple[str, ...]
    hops: tuple[Hop, ...]
    operation_kind: str
    fact_id: str
    operation_line: int
    arguments: tuple[tuple[str, str], ...]
    guards_after: tuple[Guard, ...]
    requires: tuple[str, ...]
    dominating: tuple[str, ...]
    missing: str | None

    def record(self) -> dict[str, Any]:
        """Return JSON values with keys sorted recursively, retaining sequence order."""
        result: dict[str, Any] = json.loads(json.dumps(asdict(self), sort_keys=True))
        return result

    def text(self) -> str:
        """Emit entry, hops, operation, later guards and verdict in that order."""
        record = self.record()
        components = [("entry", {key: record[key] for key in ("entry_kind", "boundary", "access", "parameters")})]
        components.extend(("hop", hop) for hop in record["hops"])
        components.append(("operation", {key: record[key] for key in ("operation_kind", "fact_id", "operation_line", "arguments")}))
        components.extend(("guard_after", guard) for guard in record["guards_after"])
        components.append(("verdict", {key: record[key] for key in ("requires", "dominating", "missing")}))
        return "\n".join(f"{label} {json.dumps(value, sort_keys=True, separators=(',', ':'))}" for label, value in components)


def _arguments(function: FunctionIR, line: int, names: Sequence[str], text: str) -> tuple[str, ...]:
    calls = [call for call in function.calls if call.line == line and any(_call_matches(call.name, name) for name in names)]
    if calls and calls[0].arg_texts:
        return calls[0].arg_texts
    # Some grammars omit arguments. Read only the selected call, balancing nested delimiters and strings.
    lines = text.splitlines()
    if not 0 < line <= len(lines):
        return ()
    source = "\n".join(lines[line - 1 : function.end_line])
    for name in names:
        match = re.search(rf"(?<![\w$]){re.escape(trailing_name(name))}\s*\(", source)
        if match is None:
            continue
        arguments: list[str] = []
        start = match.end()
        depth = 0
        quote = ""
        escaped = False
        for index in range(start, len(source)):
            char = source[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char in "\"'`":
                quote = char
            elif char in "([{":
                depth += 1
            elif char == ")" and depth == 0:
                value = source[start:index].strip()
                if value:
                    arguments.append(value)
                return tuple(arguments)
            elif char in ")]}":
                depth -= 1
            elif char == "," and depth == 0:
                arguments.append(source[start:index].strip())
                start = index + 1
    return ()


def _origin(value: str, function: FunctionIR, before: int, parameters: Mapping[str, str], facts: ObligationFacts) -> str:
    """Follow the most recent preceding assignment, never guessing an unresolved origin."""
    value = value.strip()
    while True:
        bind = next(
            (
                item
                for item in sorted(function.binds, key=lambda item: (item.line, item.order), reverse=True)
                if item.line < before and item.name == value
            ),
            None,
        )
        if bind is None:
            break
        value, before = bind.value_text.strip(), bind.line
    if value in {"true", "false", "null"}:
        return "constant"
    try:
        ast.literal_eval(value)
    except (ValueError, SyntaxError):
        pass
    else:
        return "constant"
    if any(_source_matches(value, source) for fact in facts.dischargers for source in fact.identity_sources):
        return "authenticated_context"
    if any(_source_matches(value, source) for fact in facts.dischargers for source in fact.request_sources):
        return "request_input"
    if value in parameters:
        return parameters[value]
    member = re.fullmatch(r"(\$?[A-Za-z_]\w*)(?:(?:\.|->)[A-Za-z_]\w*|\[[^\[\]]+\])+", value)
    if member is not None:
        return _origin(member.group(1), function, before, parameters, facts)
    return "unknown"


def _source_matches(value: str, source: str) -> bool:
    suffix = r"(?![\w$])" if source[-1:].isalnum() or source.endswith("_") else ""
    return bool(source and re.search(r"(?<![\w$])" + re.escape(source) + suffix, value))


def build_trace(
    *,
    path: PathRecord,
    entry: object,
    operation: Operation,
    irs: Mapping[str, tuple[FileIR, str]],
    facts: ObligationFacts,
    witnesses: Sequence[Discharge],
    dominance: Dominance,
    dominating: tuple[str, ...],
    missing: str | None,
    access: str | None = None,
) -> Trace:
    """Build one trace without changing the checker's verdict or coverage."""
    hops: list[Hop] = []
    after_by_hop: list[list[Guard]] = []
    incoming: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    arguments: tuple[tuple[str, str], ...] = ()
    boundary = str(getattr(entry, "trust_boundary", "unknown"))
    for index, (node, call_line) in enumerate(path.hops):
        file, _, name = node.rpartition("::")
        ir, text = irs[file]
        function = next(fn for fn in ir.functions if fn.name == name)
        scoped = facts.for_language(ir.language)
        if index == 0:
            parameters = function.params
            origins = {param: "request_input" if boundary in {"http_request", "network_request"} else "unknown" for param in parameters}
        else:
            origins = dict(zip(tuple(param for param in function.params if param not in {"self", "cls", "this"}), incoming, strict=False))
        final = index == len(path.hops) - 1
        line = operation.line if final else call_line
        measured = operation if final else replace(operation, path=file, function=name, line=line or function.end_line)
        before: list[Guard] = []
        after: list[Guard] = []
        after_by_hop.append(after)
        local = sorted(
            (w for w in witnesses if (w.path, w.function) == (file, name)),
            key=lambda w: (w.line or 0, w.kind, w.scope, w.provenance, w.fact_id),
        )
        for witness in local:
            guard = Guard(witness.kind, witness.scope, witness.line, witness.provenance, witness.fact_id)
            if valid_witness(witness) and dominance.dominates(witness, measured, None):
                before.append(guard)
            elif witness.line is not None and line is not None and witness.line > line:
                after.append(guard)
        if final:
            names = next(fact.calls for fact in scoped.operations if fact.id == operation.fact_id)
        else:
            names = (path.hops[index + 1][0].rpartition("::")[2],)
        values = _arguments(function, line, names, text) if line is not None and names else ()
        incoming = tuple(_origin(value, function, line or function.end_line + 1, origins, scoped) for value in values)
        if final:
            arguments = tuple(zip(values, incoming, strict=True))
        hops.append(
            Hop(
                name,
                call_line,
                tuple(before),
                tuple(value for value, origin in zip(values, incoming, strict=True) if not final and origin == "request_input"),
            )
        )
    return Trace(
        str(getattr(entry, "kind", "unknown")),
        boundary,
        access if access is not None else str(getattr(entry, "access_level", "unknown")),
        parameters,
        tuple(hops),
        operation.kind,
        operation.fact_id,
        operation.line,
        arguments,
        tuple(guard for later in reversed(after_by_hop) for guard in later),
        operation.requires,
        tuple(sorted(dominating)),
        missing,
    )
