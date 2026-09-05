"""Obligated operations and discharge witnesses in one parsed file (authorization-obligations, Req 3.1, 5.4).

An ``Operation`` is a call site matching an operation fact inside a named function. A ``Discharge`` is a witness that a
discharger fact is present: a decorator on the handler, a guard or check call before the operation, an identity
constraint keyword bound from the authenticated context, or a non-permissive setting. ``covers`` says whether one witness
discharges one operation: same function, a kind the operation requires, and, for identity constraints, a value bound from
the authenticated context (a constraint bound from the request or a constant discharges nothing).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..facts import SemanticFacts
from ..ir import FileIR, FunctionIR
from ..variants import trailing_name
from .facts import DischargerFact, ObligationFacts
from .shapes import _call_matches, _constraint_provenance, _is_literal, _operations, _permissive

SCOPES = ("decorator", "router", "statement", "hop")


@dataclass(frozen=True)
class Operation:
    path: str
    line: int
    function: str
    kind: str
    fact_id: str
    resource: str | None  # identifier token naming the resource (model or table), never text
    requires: tuple[str, ...]


@dataclass(frozen=True)
class Discharge:
    path: str
    line: int | None
    function: str
    kind: str
    fact_id: str
    provenance: str
    scope: str  # SCOPES
    detail: str = ""  # identifier only: the decorator or call name that witnessed the discharge


def find_operations(ir: FileIR, facts: ObligationFacts, *, text: str) -> tuple[Operation, ...]:
    """Every obligated operation in the file's named functions, in source order."""
    if not ir.parse_ok:
        return ()
    lines = text.splitlines()
    found: list[Operation] = []
    seen: set[tuple[str, int, str]] = set()
    for function in ir.functions:
        if function.name == "<module>":
            continue
        for site in _operations(function, facts, lines, kind=None):
            key = (function.name, site.call.line, site.fact.id)
            if key in seen:
                continue  # the walker records a chained `x.filter_by(...).first()` as two call sites on one line
            seen.add(key)
            found.append(
                Operation(
                    path=ir.path,
                    line=site.call.line,
                    function=function.name,
                    kind=site.fact.kind,
                    fact_id=site.fact.id,
                    resource=_resource_token(site.call.name, site.line_text, site.fact.resource_arg, site.call.arg_texts),
                    requires=site.fact.requires,
                )
            )
    return tuple(found)


def find_discharges(
    ir: FileIR,
    facts: ObligationFacts,
    flow_facts: SemanticFacts,
    *,
    text: str,
    entries: Sequence[object] = (),
) -> tuple[Discharge, ...]:
    """Every discharge witness in the file: decorators above each handler, guard and check calls, identity constraints."""
    if not ir.parse_ok:
        return ()
    lines = text.splitlines()
    evidence_by_function: dict[str, list[str]] = {}
    for entry in entries:
        name = getattr(entry, "function_name", None)
        if name:
            evidence_by_function.setdefault(str(name), []).extend(str(item) for item in getattr(entry, "access_evidence", []) or [])
    witnesses: list[Discharge] = []
    for function in ir.functions:
        if function.name == "<module>":
            continue
        decorators = _decorators_above(function, lines) + evidence_by_function.get(function.name, [])
        for fact in facts.dischargers:
            witnesses.extend(_decorator_witnesses(ir.path, function, fact, decorators))
            witnesses.extend(_call_witnesses(ir.path, function, fact))
            witnesses.extend(_constraint_witnesses(ir.path, function, fact, facts, flow_facts, lines))
    return tuple(_dedupe(witnesses))


def covers(witness: Discharge, operation: Operation) -> bool:
    """A witness discharges an operation when it sits in the same function, has a kind the operation requires, and, for an
    identity constraint, binds its value from the authenticated context. Ordering along the path is the Dominance protocol's
    job (task 2.4); this is the kind-and-provenance fit only."""
    if witness.path != operation.path or witness.function != operation.function:
        return False
    if witness.kind not in operation.requires:
        return False
    if witness.kind == "identity_constraint" and witness.provenance != "authenticated_context":
        return False
    return not (witness.kind == "non_permissive_value" and witness.line != operation.line)


def _decorators_above(function: FunctionIR, lines: Sequence[str]) -> list[str]:
    start = function.start_line
    found: list[str] = []
    index = start - 2
    while index >= 0 and lines[index].strip().startswith("@"):
        found.append(lines[index].strip())
        index -= 1
    return found


def _decorator_witnesses(path: str, function: FunctionIR, fact: DischargerFact, decorators: Sequence[str]) -> list[Discharge]:
    out: list[Discharge] = []
    for decorator in decorators:
        name = _decorator_name(decorator)
        if any(candidate == name or candidate in decorator for candidate in fact.decorators):
            out.append(
                Discharge(
                    path=path,
                    line=None,
                    function=function.name,
                    kind=fact.kind,
                    fact_id=fact.id,
                    provenance="authenticated_context" if fact.kind == "path_guard" else "unknown",
                    scope="decorator",
                    detail=name,
                )
            )
    return out


def _call_witnesses(path: str, function: FunctionIR, fact: DischargerFact) -> list[Discharge]:
    if fact.kind == "identity_constraint":
        return []
    out: list[Discharge] = []
    for call in function.calls:
        if any(_call_matches(call.name, name) for name in fact.calls):
            if fact.kind == "non_permissive_value":
                continue  # settings are judged per operation line in _constraint_witnesses
            out.append(
                Discharge(
                    path=path,
                    line=call.line,
                    function=function.name,
                    kind=fact.kind,
                    fact_id=fact.id,
                    provenance="authenticated_context" if fact.kind == "path_guard" else "unknown",
                    scope="statement",
                    detail=trailing_name(call.name),
                )
            )
    return out


def _constraint_witnesses(
    path: str,
    function: FunctionIR,
    fact: DischargerFact,
    facts: ObligationFacts,
    flow_facts: SemanticFacts,
    lines: Sequence[str],
) -> list[Discharge]:
    out: list[Discharge] = []
    if fact.kind == "identity_constraint":
        for site in _operations(function, facts, lines, kind=None):
            provenance = _constraint_provenance(site, fact, flow_facts)
            if provenance is not None:
                out.append(
                    Discharge(
                        path=path,
                        line=site.call.line,
                        function=function.name,
                        kind="identity_constraint",
                        fact_id=fact.id,
                        provenance=provenance,
                        scope="statement",
                        detail=trailing_name(site.call.name),
                    )
                )
    elif fact.kind == "non_permissive_value":
        for site in _operations(function, facts, lines, kind="security_setting"):
            if any(_call_matches(site.call.name, name) for name in fact.calls) and not _permissive(site, fact):
                out.append(
                    Discharge(
                        path=path,
                        line=site.call.line,
                        function=function.name,
                        kind="non_permissive_value",
                        fact_id=fact.id,
                        provenance="constant",
                        scope="statement",
                        detail=trailing_name(site.call.name),
                    )
                )
    return out


def _resource_token(callee: str, line_text: str, resource_arg: int | None, arg_texts: Sequence[str]) -> str | None:
    """The identifier that names the resource: the receiver's first segment (`Book.query...` -> `book`), a table name in a
    SQL literal, or the argument the fact points at. Never more than one identifier."""
    if resource_arg is not None and resource_arg < len(arg_texts):
        match = re.match(r"[A-Za-z_][\w]*", arg_texts[resource_arg].strip())
        return match.group(0).lower() if match else None
    head = callee.split(".")[0].split("(")[0]
    if (
        head
        and head not in {"self", "cls", "db", "session", "cursor", "conn", "connection", "c", "cur", "request", "req", "this"}
        and not _is_literal(head)
    ):
        return head.lower()
    table = re.search(r"\b(?:from|into|update|join)\s+([A-Za-z_][\w]*)", line_text, re.I)
    return table.group(1).lower() if table else None


def _decorator_name(decorator: str) -> str:
    body = decorator.lstrip("@").strip()
    return trailing_name(body.split("(", 1)[0])


def _dedupe(witnesses: Sequence[Discharge]) -> list[Discharge]:
    seen: set[tuple[object, ...]] = set()
    out: list[Discharge] = []
    for witness in witnesses:
        key = (witness.path, witness.line, witness.function, witness.kind, witness.provenance, witness.scope, witness.detail)
        if key not in seen:
            seen.add(key)
            out.append(witness)
    return out


__all__ = ["SCOPES", "Discharge", "Operation", "covers", "find_discharges", "find_operations"]
