"""Lexical JavaScript/TypeScript structure for reviewed Express facts."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openultrasast.core.semantics import SourceLocation
from openultrasast.semantic.extra import grammar_for

_LANGUAGES = frozenset({"javascript", "typescript"})
_SCOPES = frozenset({"program", "statement_block", "function_declaration", "function_expression", "arrow_function", "method_definition"})
_FUNCTION_VALUES = frozenset({"function_expression", "arrow_function"})
_HOISTED = frozenset({"express_import", "function", "parameter"})
_STRINGS = frozenset({"string", "template_string"})


class EntryStructureError(ValueError):
    """Repository structure was unavailable or unsafe to interpret."""


@dataclass(frozen=True)
class ResolvedHandler:
    identity: str
    symbol: str
    location: SourceLocation
    declaration_kind: str


@dataclass(frozen=True)
class _Declaration:
    name: str
    node: Any
    scope: Any
    kind: str
    value: Any | None


@dataclass(frozen=True)
class _Resolution:
    declarations: tuple[_Declaration, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class StructuralCandidate:
    node: Any
    target: str
    shape: str
    receiver: str | None
    arguments: Any


@dataclass(frozen=True)
class CandidateStructure:
    candidate: StructuralCandidate
    receiver_types: tuple[str, ...]
    argument_shapes: tuple[str, ...]
    binding_shapes: tuple[str, ...]
    resolved_handlers: tuple[ResolvedHandler, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SourceStructure:
    path: str
    data: bytes
    root: Any
    declarations: tuple[_Declaration, ...]
    writes: tuple[Any, ...]


def _walk(node: Any) -> Iterator[Any]:
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode("utf-8")


def _string_value(node: Any, data: bytes) -> str | None:
    if node is None or node.type != "string":
        return None
    raw = _text(node, data)
    if len(raw) < 2 or raw[0] not in {'"', "'"} or raw[-1] != raw[0]:
        return None
    return raw[1:-1]


def _member_target(node: Any, data: bytes) -> tuple[str, str] | None:
    if node is None or node.type != "member_expression":
        return None
    owner = node.child_by_field_name("object")
    member = node.child_by_field_name("property")
    if owner is None or member is None or owner.type != "identifier":
        return None
    return _text(owner, data), _text(member, data)


def _call_target(call: Any, data: bytes) -> str | None:
    function = call.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "identifier":
        return _text(function, data)
    member = _member_target(function, data)
    return ".".join(member) if member is not None else None


def _scope(node: Any) -> Any:
    parent = node.parent
    while parent is not None:
        if parent.type in _SCOPES:
            return parent
        parent = parent.parent
    raise EntryStructureError("repository source declaration has no lexical scope")


def _import_declarations(root: Any, data: bytes) -> list[_Declaration]:
    values: list[_Declaration] = []
    for node in root.named_children:
        if node.type != "import_statement" or _string_value(node.child_by_field_name("source"), data) != "express":
            continue
        clause = next((item for item in node.named_children if item.type == "import_clause"), None)
        if clause is None:
            continue
        for name in clause.named_children:
            if name.type == "identifier":
                values.append(_Declaration(_text(name, data), name, root, "express_import", None))
    return values


def _is_express_require(value: Any, data: bytes) -> bool:
    if value is None or value.type != "call_expression" or _call_target(value, data) != "require":
        return False
    arguments = value.child_by_field_name("arguments")
    return bool(arguments and len(arguments.named_children) == 1 and _string_value(arguments.named_children[0], data) == "express")


def _variable_declaration(node: Any, data: bytes) -> _Declaration | None:
    name = node.child_by_field_name("name")
    if name is None or name.type != "identifier":
        return None
    value = node.child_by_field_name("value")
    kind = "express_require" if _is_express_require(value, data) else "variable"
    if getattr(value, "type", None) in _FUNCTION_VALUES:
        kind = "handler_variable"
    return _Declaration(_text(name, data), name, _scope(node), kind, value)


def _parameter_declarations(node: Any, data: bytes) -> list[_Declaration]:
    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        return []
    values: list[_Declaration] = []
    for item in parameters.named_children:
        name = item if item.type == "identifier" else item.child_by_field_name("pattern")
        if name is not None and name.type == "identifier":
            values.append(_Declaration(_text(name, data), name, node, "parameter", None))
    return values


def _declarations(root: Any, data: bytes) -> tuple[_Declaration, ...]:
    values = _import_declarations(root, data)
    for node in _walk(root):
        if node.type == "variable_declarator":
            declaration = _variable_declaration(node, data)
            if declaration is not None:
                values.append(declaration)
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            if name is not None:
                values.append(_Declaration(_text(name, data), name, _scope(node), "function", node))
        if node.type in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
            values.extend(_parameter_declarations(node, data))
    return tuple(values)


def _writes(root: Any) -> tuple[Any, ...]:
    kinds = {"assignment_expression", "augmented_assignment_expression", "update_expression"}
    return tuple(node for node in _walk(root) if node.type in kinds)


def read_source_structure(repository_root: Path, relative_path: str, language: str) -> SourceStructure:
    if language not in _LANGUAGES:
        raise EntryStructureError("repository source language is unsupported")
    root_path = Path(repository_root).resolve()
    source_path = (root_path / relative_path).resolve()
    try:
        normalized = source_path.relative_to(root_path).as_posix()
        data = source_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise EntryStructureError("repository source is unreadable or outside its root") from exc
    if not data:
        raise EntryStructureError("repository source is empty")
    grammar = grammar_for(language)
    if grammar is None:
        raise EntryStructureError("repository source parser is unavailable")
    try:
        from tree_sitter import Parser

        tree = Parser(grammar).parse(data)
    except Exception as exc:
        raise EntryStructureError("repository source parse failed") from exc
    if tree.root_node.has_error:
        raise EntryStructureError("repository source parse failed")
    return SourceStructure(normalized, data, tree.root_node, _declarations(tree.root_node, data), _writes(tree.root_node))


def candidates(source: SourceStructure, target: str) -> tuple[StructuralCandidate, ...]:
    values: list[StructuralCandidate] = []
    for node in _walk(source.root):
        if node.type != "call_expression" or _call_target(node, source.data) != target:
            continue
        function = node.child_by_field_name("function")
        member = _member_target(function, source.data)
        values.append(
            StructuralCandidate(
                node,
                target,
                "member_call" if member is not None else "factory_call",
                member[0] if member is not None else None,
                node.child_by_field_name("arguments"),
            )
        )
    return tuple(values)


def _visible_scopes(node: Any) -> tuple[Any, ...]:
    scopes: list[Any] = []
    current = node.parent
    while current is not None:
        if current.type in _SCOPES:
            scopes.append(current)
        current = current.parent
    return tuple(scopes)


def _raw_resolution(source: SourceStructure, use: Any, name: str) -> tuple[_Declaration, ...]:
    for scope in _visible_scopes(use):
        matches = tuple(item for item in source.declarations if item.name == name and item.scope == scope)
        if matches:
            live = tuple(item for item in matches if item.kind in _HOISTED or item.node.start_byte < use.start_byte)
            return live or matches
    return ()


def _write_name(write: Any, data: bytes) -> str | None:
    target = write.child_by_field_name("left") or write.child_by_field_name("argument")
    return _text(target, data) if target is not None and target.type == "identifier" else None


def _is_reassigned(source: SourceStructure, use: Any, declaration: _Declaration) -> bool:
    for write in source.writes:
        if write.start_byte >= use.start_byte or _write_name(write, source.data) != declaration.name:
            continue
        resolved = _raw_resolution(source, write, declaration.name)
        if len(resolved) == 1 and resolved[0] == declaration:
            return True
    return False


def _resolve(source: SourceStructure, use: Any, name: str, role: str) -> _Resolution:
    nearest = _raw_resolution(source, use, name)
    reasons: list[str] = []
    if not nearest:
        reasons.append(f"{role}_binding_missing:{name}")
    if len(nearest) > 1:
        reasons.append(f"{role}_binding_ambiguous:{name}")
    if len(nearest) == 1 and nearest[0].kind not in _HOISTED and nearest[0].node.start_byte > use.start_byte:
        reasons.append(f"{role}_binding_not_live:{name}")
    if len(nearest) == 1 and _is_reassigned(source, use, nearest[0]):
        reasons.append(f"{role}_binding_reassigned:{name}")
    return _Resolution(nearest, tuple(sorted(set(reasons))))


def _express_binding(source: SourceStructure, use: Any, name: str) -> tuple[bool, tuple[str, ...]]:
    resolved = _resolve(source, use, name, "express")
    reasons = list(resolved.reasons)
    authoritative = len(resolved.declarations) == 1 and resolved.declarations[0].kind in {"express_import", "express_require"}
    if resolved.declarations and not authoritative:
        reasons.append(f"express_binding_not_authoritative:{name}")
    return authoritative and not reasons, tuple(sorted(set(reasons)))


def _receiver_kind(source: SourceStructure, declaration: _Declaration) -> tuple[str | None, tuple[str, ...]]:
    value = declaration.value
    if value is None or value.type != "call_expression":
        return None, (f"receiver_factory_not_authoritative:{declaration.name}",)
    arguments = value.child_by_field_name("arguments")
    if arguments is None or arguments.named_children:
        return None, (f"receiver_factory_not_authoritative:{declaration.name}",)
    target = _call_target(value, source.data)
    if target is None:
        return None, (f"receiver_factory_not_authoritative:{declaration.name}",)
    express_name = target.removesuffix(".Router") if target.endswith(".Router") else target
    authoritative, reasons = _express_binding(source, value, express_name)
    if not authoritative:
        return None, reasons
    return ("express_router" if target.endswith(".Router") else "express_application"), ()


def _receiver(source: SourceStructure, candidate: StructuralCandidate) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if candidate.receiver is None:
        return (), ()
    resolved = _resolve(source, candidate.node, candidate.receiver, "receiver")
    if any("reassigned" in item or "not_live" in item for item in resolved.reasons):
        return (), resolved.reasons
    kinds: list[str] = []
    reasons = list(resolved.reasons)
    for declaration in resolved.declarations:
        kind, extra = _receiver_kind(source, declaration)
        if kind is not None:
            kinds.append(kind)
        reasons.extend(extra)
    normalized = tuple(sorted(set(reasons)))
    return (tuple(kinds) if len(kinds) == len(resolved.declarations) else ()), normalized


def _handler(source: SourceStructure, node: Any) -> tuple[tuple[ResolvedHandler, ...], tuple[str, ...]]:
    if node.type in _FUNCTION_VALUES:
        location = SourceLocation(source.path, node.start_point.row + 1, node.start_point.column, "<inline>")
        identity = f"<inline>@{source.path}:{location.line}:{location.column}"
        return (ResolvedHandler(identity, "<inline>", location, node.type),), ()
    if node.type != "identifier":
        return (), ("handler_shape_unsupported",)
    name = _text(node, source.data)
    resolved = _resolve(source, node, name, "handler")
    if any("reassigned" in item or "not_live" in item for item in resolved.reasons):
        return (), resolved.reasons
    handlers: list[ResolvedHandler] = []
    reasons = list(resolved.reasons)
    for declaration in resolved.declarations:
        if declaration.kind not in {"function", "handler_variable"}:
            reasons.append(f"handler_binding_not_repository_defined:{name}")
            continue
        location = SourceLocation(
            source.path,
            declaration.node.start_point.row + 1,
            declaration.node.start_point.column,
            name,
        )
        identity = f"{name}@{source.path}:{location.line}:{location.column}"
        handlers.append(ResolvedHandler(identity, name, location, declaration.kind))
    normalized = tuple(sorted(set(reasons)))
    return (tuple(handlers) if len(handlers) == len(resolved.declarations) else ()), normalized


def _arguments(
    source: SourceStructure, candidate: StructuralCandidate
) -> tuple[tuple[str, ...], tuple[ResolvedHandler, ...], tuple[str, ...]]:
    arguments = candidate.arguments
    if arguments is None or len(arguments.named_children) < 2:
        return (), (), ("route_arguments_incomplete",)
    if arguments.named_children[0].type not in _STRINGS:
        return (), (), ("route_path_not_literal",)
    handlers, reasons = _handler(source, arguments.named_children[-1])
    return tuple("route_path_and_handler" for _ in handlers), handlers, reasons


def _binding(source: SourceStructure, candidate: StructuralCandidate) -> tuple[tuple[str, ...], tuple[str, ...]]:
    parent = candidate.node.parent
    if parent is None or parent.type != "variable_declarator" or parent.child_by_field_name("value") != candidate.node:
        return (), ("application_binding_missing",)
    if candidate.arguments is None or candidate.arguments.named_children:
        return (), ("application_factory_arguments_unsupported",)
    authoritative, reasons = _express_binding(source, candidate.node, candidate.target)
    return (("application_instance_binding",) if authoritative else ()), reasons


def analyze_candidate(source: SourceStructure, candidate: StructuralCandidate) -> CandidateStructure:
    receiver_types, receiver_reasons = _receiver(source, candidate)
    argument_shapes, handlers, argument_reasons = _arguments(source, candidate) if candidate.receiver else ((), (), ())
    binding_shapes, binding_reasons = _binding(source, candidate) if candidate.receiver is None else ((), ())
    reasons = tuple(sorted(set((*receiver_reasons, *argument_reasons, *binding_reasons))))
    return CandidateStructure(candidate, receiver_types, argument_shapes, binding_shapes, handlers, reasons)


__all__ = [
    "CandidateStructure",
    "EntryStructureError",
    "ResolvedHandler",
    "SourceStructure",
    "analyze_candidate",
    "candidates",
    "read_source_structure",
]
