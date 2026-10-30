"""Ordered security structure and bounded argument provenance for examined paths."""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any

from openultrasast.core.trace import Guard as CoreGuard
from openultrasast.core.trace import Hop as CoreHop
from openultrasast.core.trace import TraceRecord
from openultrasast.core.trace import Witness as CoreWitness
from openultrasast.core.verdict import Judgment as CoreJudgment

from ..cfg import ControlContext
from ..ir import FileIR, FunctionIR, trailing_name
from .abstract_domain import (
    AuthorityRef,
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    ResourceRef,
    WitnessMatch,
)
from .cfg_dominance import describe, operation_context
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
    relation: str  # all_paths, some_paths, none or after, relative to the hop's call or the operation
    effect: str  # throws, returns, exits, branches or value_only: what failing the guard does to the operation


@dataclass(frozen=True)
class Hop:
    function: str
    call_line: int | None
    guards_before_call: tuple[Guard, ...]
    forwarded: tuple[str, ...]


@dataclass(frozen=True)
class AbstractTraceState:
    """The abstract evidence a prover-mode trace carries beyond the legacy verdict (Req 9.1, 9.2, 9.6).

    ``path_judgment`` is the three-way judgment with its missing kinds, every incompleteness reason
    and the per-witness match relations; ``resource`` and ``authority`` are the operation's abstract
    values and ``resource_relation``/``authority_relation`` the pair-level compatibility relations.
    The state is absent from legacy traces, which stay byte-stable (task 7.4).
    """

    path_judgment: PathJudgment
    resource: ResourceRef
    authority: AuthorityRef
    resource_relation: EvidenceRelation
    authority_relation: EvidenceRelation


def _enum_json_value(value: Any) -> str:
    """The canonical JSON encoding of a relation or judgment: its value string."""
    if isinstance(value, Enum):
        return str(value.value)
    raise TypeError(f"not canonically serializable: {type(value).__name__}")


def _parse_path_judgment(payload: Mapping[str, Any]) -> PathJudgment:
    """Rebuild one ``PathJudgment`` from its canonical JSON (round-trip half of Req 9.5)."""
    completeness_payload = payload["completeness"]
    return PathJudgment(
        judgment=PairJudgment(payload["judgment"]),
        missing=tuple(payload["missing"]),
        completeness=Completeness(
            is_complete=bool(completeness_payload["is_complete"]),
            reasons=tuple(completeness_payload["reasons"]),
        ),
        matches=tuple(
            WitnessMatch(
                relation=EvidenceRelation(match["relation"]),
                resource_relation=EvidenceRelation(match["resource_relation"]),
                authority_relation=EvidenceRelation(match["authority_relation"]),
                evidence=tuple(match["evidence"]),
            )
            for match in payload["matches"]
        ),
    )


def parse_abstract_state(payload: Mapping[str, Any]) -> AbstractTraceState:
    """Rebuild the abstract trace state from its canonical JSON record.

    The inverse of the canonical encoding: value strings name relations and judgments again, field
    dicts become ``ResourceRef``/``AuthorityRef`` values and every incompleteness reason is kept.
    Anything outside the closed vocabularies fails loud rather than degrading to a quieter value.
    """
    resource_payload = payload["resource"]
    authority_payload = payload["authority"]
    return AbstractTraceState(
        path_judgment=_parse_path_judgment(payload["path_judgment"]),
        resource=ResourceRef(kind=resource_payload["kind"], values=tuple(resource_payload["values"])),
        authority=AuthorityRef(
            values=tuple(authority_payload["values"]),
            is_unknown=bool(authority_payload["is_unknown"]),
        ),
        resource_relation=EvidenceRelation(payload["resource_relation"]),
        authority_relation=EvidenceRelation(payload["authority_relation"]),
    )


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
    operation_context: ControlContext = ControlContext()
    # Opt-in abstract evidence (task 7.4): absent (None) in legacy mode, so legacy serialization is
    # byte-stable; set only by the prover's abstract judgment path (task 10.6).
    abstract_state: AbstractTraceState | None = None

    def record(self) -> dict[str, Any]:
        """Return JSON values with keys sorted recursively, retaining sequence order.

        The abstract state is omitted entirely when unset, so a legacy trace's record keeps its exact
        historical shape; when set, relations and judgments encode as their value strings.
        """
        payload = asdict(self)
        if payload["abstract_state"] is None:
            del payload["abstract_state"]
        record: dict[str, Any] = json.loads(json.dumps(payload, sort_keys=True, default=_enum_json_value))
        return record

    def to_core_record(self, *, entry: str, digests: Mapping[str, str], complete: bool = False) -> TraceRecord:
        """Native conformance to the detection-core trace contract (detection-core task 8.1).

        ``complete`` defaults to False: a Trace carries no per-hop completeness, so the
        record never asserts resolved call targets it did not see. Guards are mapped from
        every hop's before-call guards plus the operation-level guards.
        """
        state = self.abstract_state
        if state is None:
            judgment = CoreJudgment.INDETERMINATE
            reasons: tuple[str, ...] = ("abstract_state_unset",)
            witnesses: tuple[CoreWitness, ...] = ()
            resource = "unknown"
            authority = "unknown"
        else:
            judgment = CoreJudgment(state.path_judgment.judgment.value)
            completeness = state.path_judgment.completeness
            reasons = tuple(completeness.reasons) or (("incomplete",) if not completeness.is_complete else ())
            witnesses = tuple(
                CoreWitness(kind="witness", provenance=evidence, relation=match.relation.value)
                for match in state.path_judgment.matches
                for evidence in match.evidence
            )
            resource = ",".join(state.resource.values) or "unknown"
            authority = ",".join(state.authority.values) or "unknown"
        hops = tuple(CoreHop(function=hop.function, call_line=hop.call_line, complete=complete) for hop in self.hops)
        hop_guards = tuple(guard for hop in self.hops for guard in hop.guards_before_call)
        guards = tuple(CoreGuard(kind=guard.kind, effect=guard.effect) for guard in (*hop_guards, *self.guards_after))
        return TraceRecord(
            entry=entry,
            hops=hops,
            operation_kind=self.operation_kind,
            resource=resource,
            authority=authority,
            witnesses=witnesses,
            guards=guards,
            completeness_reasons=reasons,
            judgment=judgment,
            digests=dict(digests),
        )

    def text(self) -> str:
        """Emit entry, hops, operation, later guards, verdict and, when present, the abstract state."""
        record = self.record()
        components = [("entry", {key: record[key] for key in ("entry_kind", "boundary", "access", "parameters")})]
        components.extend(("hop", hop) for hop in record["hops"])
        operation_keys = ("operation_kind", "fact_id", "operation_line", "arguments", "operation_context")
        components.append(("operation", {key: record[key] for key in operation_keys}))
        components.extend(("guard_after", guard) for guard in record["guards_after"])
        components.append(("verdict", {key: record[key] for key in ("requires", "dominating", "missing")}))
        if "abstract_state" in record:
            components.append(("abstract", record["abstract_state"]))
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
    abstract_state: AbstractTraceState | None = None,
) -> Trace:
    """Build one trace without changing the checker's verdict or coverage."""
    texts = {file: text for file, (_, text) in irs.items()}
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
            relation, effect = describe(dominance, witness, measured, texts)
            guard = Guard(witness.kind, witness.scope, witness.line, witness.provenance, witness.fact_id, relation, effect)
            dominated = valid_witness(witness) and dominance.dominates(witness, measured, None)
            if dominated or (valid_witness(witness) and witness.line is not None and line is not None and witness.line < line):
                # A guard above the call that does not dominate it stays visible, with the relation that says why.
                before.append(guard)
            elif witness.line is not None and line is not None and witness.line > line:
                after.append(guard)
        handler = False
        if final:
            fact = next(fact for fact in scoped.operations if fact.id == operation.fact_id)
            names = fact.calls
            # A handler-named operation is the handler itself: its arguments are the handler's own parameters.
            handler = bool(fact.handlers) and not fact.calls
        else:
            names = (path.hops[index + 1][0].rpartition("::")[2],)
        values = _arguments(function, line, names, text) if line is not None and names else ()
        incoming = tuple(_origin(value, function, line or function.end_line + 1, origins, scoped) for value in values)
        if handler:
            own = tuple(param for param in function.params if param not in {"self", "cls", "this"})
            arguments = tuple((param, origins.get(param, "unknown")) for param in own)
        elif final:
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
        operation_context(dominance, operation),
        abstract_state,
    )
