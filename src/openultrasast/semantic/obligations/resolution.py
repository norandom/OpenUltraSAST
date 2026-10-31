"""Stable declaration identities for repository-defined symbols (task 8.2).

The symbol index gives every declaration an identity keyed by module, enclosing type, name, and -- when
the declaration carries them -- parameter names, so same-name targets never merge (Req 3.2) and base-type
declarations attach only through explicit descendant edges (Req 3.5). Engine purity: no framework or
product names appear here; target vocabulary arrives as data through the acquisition pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ..cst import DeclarationScope, class_bases, declaration_scopes
from ..ir import CallSite
from .abstract_domain import Completeness


@dataclass(frozen=True)
class SymbolId:
    """The stable identity of one declaration: module (repository path), enclosing type, name, signature."""

    module: str
    enclosing_type: str | None
    name: str
    signature: tuple[str, ...] | None

    @property
    def sort_key(self) -> tuple[str, str, str, tuple[str, ...]]:
        """A total-order key; a missing signature sorts before every present one."""
        return (self.module, self.enclosing_type or "", self.name, self.signature or ())

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SymbolId):
            return NotImplemented
        return self.sort_key < other.sort_key


@dataclass(frozen=True)
class SymbolIndex:
    """Repository-defined declarations and the inheritance edges between their types."""

    declarations: tuple[SymbolId, ...]
    base_types: Mapping[tuple[str, str], tuple[str, ...]]
    by_name: Mapping[str, tuple[SymbolId, ...]] = field(default_factory=dict)

    @classmethod
    def build(cls, files: Iterable[tuple[str, str, str]]) -> SymbolIndex:
        """Build the index from (path, text, language) triples; deterministic and deduplicated."""
        declarations: set[SymbolId] = set()
        base_types: dict[tuple[str, str], tuple[str, ...]] = {}
        for path, text, language in files:
            scopes = declaration_scopes(path, text, language)
            declarations.update(_symbol_id(path, scope) for scope in scopes)
            base_types.update(_inheritance_edges(path, scopes))
            for type_name, bases in class_bases(path, text, language):
                base_types[(path, type_name)] = bases
        by_name: dict[str, list[SymbolId]] = {}
        for declaration in sorted(declarations):
            by_name.setdefault(declaration.name, []).append(declaration)
        return cls(
            declarations=tuple(sorted(declarations)),
            base_types=dict(sorted(base_types.items())),
            by_name={name: tuple(symbols) for name, symbols in sorted(by_name.items())},
        )


def ancestors_of(index: SymbolIndex, module: str, type_name: str) -> tuple[str, ...]:
    """Repository-defined base types of one type, transitive, nearest first, cycle-safe."""
    bases: list[str] = []
    queue: list[str] = [type_name]
    while queue:
        current = queue.pop(0)
        for base in index.base_types.get((module, current), ()):
            if base in bases or base == type_name:
                continue
            bases.append(base)
            queue.append(base)
    return tuple(bases)


def descendants_of(index: SymbolIndex, base_name: str) -> tuple[tuple[str, str], ...]:
    """(module, type) pairs whose ancestry includes base_name; unrelated types never appear."""
    return tuple(
        sorted((module, type_name) for module, type_name in index.base_types if base_name in ancestors_of(index, module, type_name))
    )


def inherited_method(
    index: SymbolIndex,
    base_type: str,
    method_name: str,
    *,
    arity: int | None,
) -> CallTargetSet:
    """Resolve a method as declared on base_type; attachment flows only along descendant edges.

    A unique declaration resolves complete. Declarations of the same base name in
    several modules stay a candidate set with an ambiguity reason (Req 3.5). No
    same-name method on an unrelated class ever enters the target set.
    """
    same_name = index.by_name.get(method_name, ())
    declared = [symbol for symbol in same_name if symbol.enclosing_type == base_type]
    narrowed = _arity_narrow(tuple(declared), arity) if declared else ()
    if not narrowed:
        return CallTargetSet(targets=(), completeness=Completeness(is_complete=False, reasons=("resolution:no_candidate",)))
    if len(narrowed) == 1:
        return CallTargetSet(targets=(narrowed[0],), completeness=Completeness(is_complete=True))
    return CallTargetSet(
        targets=tuple(narrowed),
        completeness=Completeness(is_complete=False, reasons=("resolution:inheritance_ambiguous_across_modules",)),
    )


def _symbol_id(module: str, scope: DeclarationScope) -> SymbolId:
    """Parameter names are the signature when present; a declaration without them has none."""
    signature = tuple(scope.params) if scope.params else None
    return SymbolId(module=module, enclosing_type=scope.enclosing_type, name=scope.function_name, signature=signature)


def _inheritance_edges(module: str, scopes: Iterable[DeclarationScope]) -> dict[tuple[str, str], tuple[str, ...]]:
    """(module, type) -> the base names that type declares, from any method declared inside it."""
    edges: dict[tuple[str, str], tuple[str, ...]] = {}
    for scope in scopes:
        if scope.enclosing_type is not None:
            edges[(module, scope.enclosing_type)] = scope.enclosing_base_types
    return edges


@dataclass(frozen=True)
class CallTargetSet:
    """The outcome of resolving one call: complete exact targets, incomplete candidates, or unresolved."""

    targets: tuple[SymbolId, ...]
    completeness: Completeness


_SELF_RECEIVERS = frozenset({"self", "$this", "this", "cls", "static"})


@dataclass(frozen=True)
class CallerBinding:
    """One call site bound to a target declaration, with whether the binding is exact."""

    module: str
    function: str
    line: int
    exact: bool


@dataclass(frozen=True)
class CallBindings:
    """Forward and reverse views of every resolved call in one change."""

    call_targets: tuple[CallTargetSet, ...]
    exact_caller_index: Mapping[SymbolId, tuple[CallerBinding, ...]]
    counts: Mapping[str, int]
    resolutions: Mapping[tuple[str, str, int], tuple[CallTargetSet, ...]] = field(default_factory=dict)

    def exact_callers(self, target: SymbolId) -> tuple[CallerBinding, ...]:
        """Call sites whose resolution is complete and lands on this target."""
        return self.exact_caller_index.get(target, ())


def resolve_call(call: CallSite, *, module: str, index: SymbolIndex) -> CallTargetSet:
    """Resolve one call site against the repository symbol index.

    Exact receiver and full signature produce one complete target; partial information
    produces a finite candidate set with an incompleteness reason; nothing falls back to
    a global bare-name key (Reqs 3.3, 3.4, 11.1, 11.6).
    """
    same_name = index.by_name.get(call.name, ())
    receiver = (call.receiver or "").strip()
    if not receiver:
        return _module_scope_targets(same_name, module, call.arity)
    if receiver in _SELF_RECEIVERS:
        return _method_targets(same_name, module, call.arity, "receiver_self_shared_across_classes")
    if _is_declared_type(same_name, receiver):
        return _type_receiver_targets(same_name, receiver, call.arity)
    return _variable_receiver_targets(same_name, call.arity)


def bind_calls(*, functions_by_module: Mapping[str, Iterable], index: SymbolIndex) -> CallBindings:
    """Resolve every call in the given function IRs and index the exact caller edges."""
    call_targets: list[CallTargetSet] = []
    caller_index: dict[SymbolId, list[CallerBinding]] = {}
    resolutions: dict[tuple[str, str, int], list[CallTargetSet]] = {}
    counts = {"complete_calls": 0, "incomplete_calls": 0, "unresolved_calls": 0}
    for module, functions in functions_by_module.items():
        for function_ir in functions:
            for call in function_ir.calls:
                target_set = resolve_call(call, module=module, index=index)
                call_targets.append(target_set)
                resolutions.setdefault((module, function_ir.name, call.line), []).append(target_set)
                _count_target_set(target_set, counts)
                if not target_set.completeness.reasons and len(target_set.targets) == 1:
                    binding = CallerBinding(module=module, function=function_ir.name, line=call.line, exact=True)
                    bindings = caller_index.setdefault(target_set.targets[0], [])
                    if binding not in bindings:
                        bindings.append(binding)
    return CallBindings(
        call_targets=tuple(call_targets),
        exact_caller_index={target: tuple(bindings) for target, bindings in sorted(caller_index.items())},
        counts=dict(sorted(counts.items())),
        resolutions={key: tuple(sets) for key, sets in sorted(resolutions.items())},
    )


def _count_target_set(target_set: CallTargetSet, counts: dict[str, int]) -> None:
    if not target_set.targets:
        counts["unresolved_calls"] += 1
    elif target_set.completeness.reasons:
        counts["incomplete_calls"] += 1
    else:
        counts["complete_calls"] += 1


def _module_scope_targets(same_name: tuple[SymbolId, ...], module: str, arity: int | None) -> CallTargetSet:
    # A receiver-less call (implicit this in class languages, plain call in
    # module languages) resolves against every same-name declaration in the
    # calling module: module-level functions and class methods alike. Complete
    # only when exactly one candidate exists; a shared name stays a finite
    # candidate set with an incompleteness reason, never a bare-name merge.
    module_scope = tuple(symbol for symbol in same_name if symbol.module == module)
    narrowed = _arity_narrow(module_scope, arity)
    if module_scope and not narrowed:
        return CallTargetSet(targets=(), completeness=Completeness(is_complete=False, reasons=("resolution:arity_mismatch",)))
    return _finish(narrowed, shared_reason="name_shared_across_module_scopes")


def _method_targets(same_name: tuple[SymbolId, ...], module: str, arity: int | None, shared_reason: str) -> CallTargetSet:
    methods = tuple(symbol for symbol in same_name if symbol.enclosing_type is not None and symbol.module == module)
    return _narrowed_or_unresolved(methods, arity, shared_reason)


def _type_receiver_targets(same_name: tuple[SymbolId, ...], type_name: str, arity: int | None) -> CallTargetSet:
    methods = tuple(symbol for symbol in same_name if symbol.enclosing_type == type_name)
    return _narrowed_or_unresolved(methods, arity, "class_shared_across_modules" if len({s.module for s in methods}) > 1 else "")


def _variable_receiver_targets(same_name: tuple[SymbolId, ...], arity: int | None) -> CallTargetSet:
    # A variable receiver's type is unknown, but when exactly ONE method with the
    # called name exists repository-wide, no second repository-defined target can
    # exist, so the call binds complete (unique-declaration member-call binding).
    # Two or more same-name declarations are a collision: they stay a finite
    # candidate set, never a bare-name merge. A same-name module-level function is
    # not a member-call target, so it neither binds nor collides here.
    methods = tuple(symbol for symbol in same_name if symbol.enclosing_type is not None)
    if len(methods) == 1:
        return CallTargetSet(targets=methods, completeness=Completeness(is_complete=True))
    narrowed = _arity_narrow(methods, arity)
    if not narrowed:
        return CallTargetSet(targets=(), completeness=Completeness(is_complete=False, reasons=("resolution:no_candidate",)))
    return CallTargetSet(
        targets=narrowed,
        completeness=Completeness(is_complete=False, reasons=("resolution:receiver_type_unknown",)),
    )


def _narrowed_or_unresolved(methods: tuple[SymbolId, ...], arity: int | None, shared_reason: str) -> CallTargetSet:
    narrowed = _arity_narrow(methods, arity)
    if methods and not narrowed:
        return CallTargetSet(targets=(), completeness=Completeness(is_complete=False, reasons=("resolution:arity_mismatch",)))
    return _finish(narrowed, shared_reason=shared_reason)


def _is_declared_type(same_name: tuple[SymbolId, ...], receiver: str) -> bool:
    return any(symbol.enclosing_type == receiver for symbol in same_name)


def _arity_narrow(symbols: tuple[SymbolId, ...], arity: int | None) -> tuple[SymbolId, ...]:
    if arity is None:
        return symbols
    narrowed = tuple(symbol for symbol in symbols if len(symbol.signature or ()) == arity)
    return narrowed or symbols


def _finish(targets: tuple[SymbolId, ...], shared_reason: str) -> CallTargetSet:
    if not targets:
        return CallTargetSet(targets=(), completeness=Completeness(is_complete=False, reasons=("resolution:no_candidate",)))
    if len(targets) == 1:
        return CallTargetSet(targets=targets, completeness=Completeness(is_complete=True))
    return CallTargetSet(targets=targets, completeness=Completeness(is_complete=False, reasons=(f"resolution:{shared_reason}",)))
