"""Obligation shapes learned from trusted pairs (authorization-obligations, Req 2).

The lesson of an absence pair is not a flow: it is a discharger present on a discharged operation of the labeled kind
(an identity constraint bound from the authenticated context, a guard dominating the operation, a non-permissive value)
that the vulnerable operation lacks. Real-Vuln twins are often the same function with a flag, or an unrelated trap
function, so the discharged sibling operation may sit on either side; the derivation looks on the fixed side first and
then in the vulnerable function itself. Keyword constraints are not in ``FileIR`` call sites (positional arguments only),
so they are read from the call's own source line; nothing textual enters the shape. Stdlib plus ``..ir``, ``..facts``,
``..functions``, ``..variants`` (name tracing) and ``.facts`` only.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..facts import SemanticFacts
from ..functions import named_ranges_from_ir
from ..ir import CallSite, FileIR, FunctionIR
from ..variants import trailing_name
from .facts import DISCHARGER_KINDS, OPERATION_KINDS, PROVENANCE_KINDS, DischargerFact, ObligationFacts, OperationFact

FAMILY = "obligation"
# Closed vocabulary ids whose pairs describe an absence rather than a flow; such rows are exported as obligation shapes.
ABSENCE_MECHANISMS = frozenset(
    {
        "missing_auth_guard",
        "identity_from_request_body",
        "permissive_default",
        "validation_strength",
        "unconstrained_protected_read",
        "unconstrained_protected_write",
        "unguarded_privileged_action",
    }
)
RESOURCE_CLASSES = ("owned", "global", "setting")
_IDENT = re.compile(r"[A-Za-z_][\w.]*")


@dataclass(frozen=True)
class ObligationShape:
    language: str
    operation_kind: str  # OPERATION_KINDS
    discharger_kind: str  # DISCHARGER_KINDS
    provenance: str  # PROVENANCE_KINDS: what the discharger binds its value from
    resource_class: str  # RESOURCE_CLASSES
    mechanism: str  # closed vocabulary id from the label
    family: str = FAMILY

    def key(self) -> str:
        parts = (
            self.family,
            self.language,
            self.operation_kind,
            self.discharger_kind,
            self.provenance,
            self.resource_class,
            self.mechanism,
        )
        return "|".join(parts)

    def to_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "language": self.language,
            "operation_kind": self.operation_kind,
            "discharger_kind": self.discharger_kind,
            "provenance": self.provenance,
            "resource_class": self.resource_class,
            "mechanism": self.mechanism,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> ObligationShape:
        shape = cls(
            language=str(payload.get("language", "")),
            operation_kind=str(payload.get("operation_kind", "")),
            discharger_kind=str(payload.get("discharger_kind", "")),
            provenance=str(payload.get("provenance", "unknown")),
            resource_class=str(payload.get("resource_class", "global")),
            mechanism=str(payload.get("mechanism", "other")),
            family=str(payload.get("family", FAMILY)),
        )
        if shape.family != FAMILY:
            raise ValueError(f"not an obligation shape: family {shape.family!r}")
        for value, allowed, name in (
            (shape.operation_kind, OPERATION_KINDS, "operation_kind"),
            (shape.discharger_kind, DISCHARGER_KINDS, "discharger_kind"),
            (shape.provenance, PROVENANCE_KINDS, "provenance"),
            (shape.resource_class, RESOURCE_CLASSES, "resource_class"),
        ):
            if value not in allowed:
                raise ValueError(f"unknown {name} {value!r}")
        return shape


@dataclass(frozen=True)
class OperationSite:
    call: CallSite
    fact: OperationFact
    function: FunctionIR
    line_text: str


@dataclass(frozen=True)
class DischargeLesson:
    kind: str
    provenance: str


def derive_obligation(
    vuln: FileIR,
    fixed: FileIR,
    *,
    function: str,
    obligation: str | None,
    mechanism: str,
    facts: ObligationFacts,
    flow_facts: SemanticFacts,
    vuln_text: str,
    fixed_text: str,
) -> ObligationShape | None:
    """The shape of the labeled absence: the undischarged operation on the vulnerable side and the discharger a discharged
    sibling operation (fixed side first, then the vulnerable function) carries. None when nothing can be learned."""
    result = _analyze(
        vuln,
        fixed,
        function=function,
        obligation=obligation,
        mechanism=mechanism,
        facts=facts,
        flow_facts=flow_facts,
        vuln_text=vuln_text,
        fixed_text=fixed_text,
    )
    return result if isinstance(result, ObligationShape) else None


def explain_skip(
    vuln: FileIR,
    fixed: FileIR,
    *,
    function: str,
    vuln_text: str,
    fixed_text: str,
    obligation: str | None = None,
    facts: ObligationFacts | None = None,
    flow_facts: SemanticFacts | None = None,
) -> str:
    """The reason ``derive_obligation`` returns None for this pair (``ok`` when it would not)."""
    from ..facts import FactLoadError, load_facts
    from .facts import load_obligation_facts

    loaded = facts if facts is not None else load_obligation_facts()
    try:
        flow = flow_facts if flow_facts is not None else load_facts()
    except FactLoadError:
        flow = SemanticFacts(version="", sources=(), sinks=(), sanitizers=())
    result = _analyze(
        vuln,
        fixed,
        function=function,
        obligation=obligation,
        mechanism="other",
        facts=loaded,
        flow_facts=flow,
        vuln_text=vuln_text,
        fixed_text=fixed_text,
    )
    return "ok" if isinstance(result, ObligationShape) else result


def _analyze(
    vuln: FileIR,
    fixed: FileIR,
    *,
    function: str,
    obligation: str | None,
    mechanism: str,
    facts: ObligationFacts,
    flow_facts: SemanticFacts,
    vuln_text: str,
    fixed_text: str,
) -> ObligationShape | str:
    if not vuln.parse_ok or not fixed.parse_ok:
        return "parse_failed"
    scoped = facts.for_language(vuln.language)
    flow = flow_facts.for_language(vuln.language)
    vuln_fn = _function_named(vuln, function, vuln_text)
    if vuln_fn is None:
        return "no_labeled_function"
    vuln_lines = vuln_text.splitlines()
    operations = _operations(vuln_fn, scoped, vuln_lines, kind=obligation)
    if not operations and obligation is not None:
        # The walker names chained calls after their first segment (`filter_by(...).update(x)` is a `filter_by`), so the
        # labeled kind may not be visible; any obligated operation in the labeled function stands in, the label kind stays.
        operations = _operations(vuln_fn, scoped, vuln_lines, kind=None)
    if not operations:
        return "no_obligated_operation"
    undischarged = [op for op in operations if _discharge_of(op, scoped, flow, vuln_lines) is None]
    if not undischarged:
        return "no_undischarged_operation"
    target = undischarged[0]
    kind = obligation or target.fact.kind
    sibling_kind = target.fact.kind  # siblings are looked up by what the walker sees; the shape keeps the labeled kind
    # The lesson: a discharged operation of the same kind on the fixed side, else in the vulnerable function itself.
    lesson: DischargeLesson | None = None
    fixed_fn = _function_named(fixed, function, fixed_text) or _same_kind_function(fixed, sibling_kind, scoped, fixed_text.splitlines())
    if fixed_fn is not None:
        fixed_lines = fixed_text.splitlines()
        for op in _operations(fixed_fn, scoped, fixed_lines, kind=sibling_kind):
            lesson = _discharge_of(op, scoped, flow, fixed_lines)
            if lesson is not None:
                break
        if lesson is None and kind == "security_setting":
            lesson = _setting_lesson(target, fixed_fn, scoped, fixed_lines)
    if lesson is None:
        for op in _operations(vuln_fn, scoped, vuln_lines, kind=sibling_kind):
            if op is target:
                continue
            lesson = _discharge_of(op, scoped, flow, vuln_lines)
            if lesson is not None:
                break
    if lesson is None:
        return "no_discharger_added:" + "|".join(target.fact.requires)
    return ObligationShape(
        language=vuln.language,
        operation_kind=kind,
        discharger_kind=lesson.kind,
        provenance=lesson.provenance,
        resource_class=_resource_class(kind, lesson.kind),
        mechanism=mechanism,
    )


def _operations(function: FunctionIR, facts: ObligationFacts, lines: Sequence[str], *, kind: str | None) -> list[OperationSite]:
    sites: list[OperationSite] = []
    for call in function.calls:
        for fact in facts.operations:
            if kind is not None and fact.kind != kind:
                continue
            if any(_call_matches(call.name, name) for name in fact.calls):
                line_text = lines[call.line - 1] if 0 < call.line <= len(lines) else ""
                if _all_constant(call, line_text):
                    continue  # a constant-only operation is not an obligated access on user-controlled data
                sites.append(OperationSite(call=call, fact=fact, function=function, line_text=line_text))
                break
    return sites


def _discharge_of(site: OperationSite, facts: ObligationFacts, flow: SemanticFacts, lines: Sequence[str]) -> DischargeLesson | None:
    """The discharger that covers this operation, or None when it is undischarged."""
    for fact in facts.dischargers:
        if fact.kind not in site.fact.requires:
            continue
        if fact.kind == "identity_constraint":
            provenance = _constraint_provenance(site, fact, flow)
            if provenance == "authenticated_context":  # a constraint bound from the request or a constant discharges nothing
                return DischargeLesson(kind="identity_constraint", provenance=provenance)
        elif fact.kind in {"path_guard", "ownership_check", "validated_input"}:
            if _guarded_before(site, fact, lines):
                return DischargeLesson(kind=fact.kind, provenance="authenticated_context" if fact.kind == "path_guard" else "unknown")
        elif fact.kind == "non_permissive_value":
            if any(_call_matches(site.call.name, name) for name in fact.calls) and not _permissive(site, fact):
                return DischargeLesson(kind="non_permissive_value", provenance="constant")
    return None


def _constraint_provenance(site: OperationSite, fact: DischargerFact, flow: SemanticFacts) -> str | None:
    """A constraint keyword from the facts on the operation's line; the provenance of the value it binds."""
    for param in fact.constraint_params:
        match = re.search(rf"\b{re.escape(param)}\s*=\s*([^,)]+)", site.line_text)
        if not match:
            continue
        value = match.group(1).strip()
        return _provenance_of(value, site.function, site.call.line, fact, flow)
    return None


def _provenance_of(value: str, function: FunctionIR, before_line: int, fact: DischargerFact, flow: SemanticFacts, depth: int = 0) -> str:
    if depth > 8:
        return "unknown"
    if any(pattern in value for pattern in fact.identity_sources):
        return "authenticated_context"
    if _is_literal(value):
        return "constant"
    name_match = _IDENT.match(value)
    if name_match is None:
        return "unknown"
    name = name_match.group(0).split(".")[0]
    binds = [bind for bind in function.binds if bind.name == name and bind.line < before_line]
    if binds:
        bind = max(binds, key=lambda item: item.line)
        if any(pattern in bind.value_text for pattern in fact.identity_sources):
            return "authenticated_context"
        if _flow_source_in(bind.value_text, flow, fact):
            return "request_input"
        for inner in bind.names:
            if inner != name:
                found = _provenance_of(inner, function, bind.line, fact, flow, depth + 1)
                if found != "unknown":
                    return found
        return "constant" if bind.is_constant and not bind.names else "unknown"
    if name in function.params:
        return "request_input"  # handler parameters are route or body values
    if _flow_source_in(value, flow, fact):
        return "request_input"
    return "unknown"


def _guarded_before(site: OperationSite, fact: DischargerFact, lines: Sequence[str]) -> bool:
    start = site.function.start_line
    decorators = [line.strip() for line in lines[max(start - 8, 0) : start - 1] if line.strip().startswith("@")]
    if any(any(name in decorator for name in fact.decorators) for decorator in decorators):
        return True
    guard_lines = [
        call.line
        for call in site.function.calls
        if call.line < site.call.line and any(_call_matches(call.name, name) for name in fact.calls)
    ]
    if not guard_lines:
        return False
    if fact.kind != "path_guard":
        return True
    between = lines[min(guard_lines) : site.call.line - 1]
    return any(re.match(r"\s*(return|raise|abort\(|sys\.exit)", line) for line in between)


def _setting_lesson(target: OperationSite, fixed_fn: FunctionIR, facts: ObligationFacts, lines: Sequence[str]) -> DischargeLesson | None:
    setting_facts = [f for f in facts.dischargers if f.kind == "non_permissive_value"]
    for op in _operations(fixed_fn, facts, lines, kind="security_setting"):
        if (
            trailing_name(op.call.name) == trailing_name(target.call.name)
            and not any(_permissive(op, f) for f in setting_facts)
            and op.line_text.strip() != target.line_text.strip()
        ):
            return DischargeLesson(kind="non_permissive_value", provenance="constant")
    return None


def _permissive(site: OperationSite, fact: DischargerFact) -> bool:
    """The setting call carries one of the fact's permissive values (data, not a code-level list)."""
    return any(token in site.line_text for token in fact.permissive_values)


def _all_constant(call: CallSite, line_text: str) -> bool:
    keyword_values = re.findall(r"\b\w+\s*=\s*([^,)]+)", line_text)
    positional_constant = all(call.arg_is_constant) if call.arg_texts else True
    return (
        positional_constant
        and all(_is_literal(value.strip()) for value in keyword_values)
        and (bool(call.arg_texts) or bool(keyword_values))
    )


def _is_literal(value: str) -> bool:
    return bool(re.fullmatch(r"(['\"].*['\"]|\d+(\.\d+)?|True|False|None|\[.*\]|\{.*\})", value.strip()))


def _flow_source_in(text: str, flow: SemanticFacts, fact: DischargerFact | None = None) -> bool:
    """A flow-fact source pattern, or one of the discharger fact's request_sources (data), names request input."""
    if any(pattern and pattern in text for source in flow.sources for pattern in source.patterns):
        return True
    return fact is not None and any(pattern in text for pattern in fact.request_sources)


def _resource_class(operation_kind: str, discharger_kind: str) -> str:
    if operation_kind == "security_setting":
        return "setting"
    return "owned" if discharger_kind in {"identity_constraint", "ownership_check"} else "global"


def _call_matches(name: str, fact_call: str) -> bool:
    """Same rule as the taint walker: exact, dotted suffix, or a bare name equal to the fact's last segment."""
    if name == fact_call or name.endswith("." + fact_call):
        return True
    return "." not in name and name == fact_call.split(".")[-1]


def _function_named(ir: FileIR, function: str, text: str) -> FunctionIR | None:
    for item in ir.functions:
        if item.name == function:
            return item
    if text:
        for name, start, _end in named_ranges_from_ir(ir, text):
            if name == function:
                for item in ir.functions:
                    if item.start_line == start:
                        return item
    return None


def _same_kind_function(ir: FileIR, kind: str, facts: ObligationFacts, lines: Sequence[str]) -> FunctionIR | None:
    """When the fixed twin is a different function (a Real-Vuln trap), the first function with an operation of the labeled kind."""
    for item in ir.functions:
        if item.name != "<module>" and _operations(item, facts, lines, kind=kind):
            return item
    return None


def is_obligation_row(record: object) -> bool:
    shape = getattr(record, "shape", None)
    return isinstance(shape, dict) and shape.get("family") == FAMILY


def obligation_mechanisms(records: Sequence[object]) -> tuple[object, ...]:
    """Store rows that carry an obligation shape (corpus origin, family obligation)."""
    return tuple(record for record in records if getattr(record, "origin", "") == "corpus" and is_obligation_row(record))


__all__ = [
    "ABSENCE_MECHANISMS",
    "FAMILY",
    "RESOURCE_CLASSES",
    "ObligationShape",
    "derive_obligation",
    "explain_skip",
    "is_obligation_row",
    "obligation_mechanisms",
]
