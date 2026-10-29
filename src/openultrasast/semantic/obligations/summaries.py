"""Function summaries for the obligations abstract interpretation.

Task 9.1 (Reqs 3.1, 3.6, 11.7): each summary collects a function's protected
operations, local witnesses, resolved calls and local completeness WITHOUT
traversing callers. Task 9.2 (Reqs 3.7, 11.6): a monotone fixpoint over
strongly connected call components unions callee evidence into callers until
stable, so direct and mutual recursion terminate with the accumulated
evidence. Task 9.3 (Reqs 3.8, 6.2, 6.3, 7.2): an exploration budget bounds
the fixpoint; depth, fan-out and deadline cutoffs stop growth, record the
exact cutoff reason and leave the affected summaries incomplete while
preserving the evidence accumulated so far. Summaries are deterministic and
carry no target names beyond fact identifiers (Req 11.7).
"""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from time import monotonic

from ..ir import FunctionIR
from .abstract_domain import Completeness, join_completeness
from .operations import Discharge, Operation
from .resolution import CallTargetSet, SymbolId, SymbolIndex, resolve_call

_DEPTH_CUTOFF = "summaries:depth_cutoff"
_FAN_OUT_CUTOFF = "summaries:fan_out_cutoff"
_DEADLINE_CUTOFF = "summaries:deadline_cutoff"


@dataclass(frozen=True)
class FunctionSummary:
    """Local summary of one function: what it holds, whom it calls."""

    symbol: SymbolId
    operations: tuple[Operation, ...] = ()
    witnesses: tuple[Discharge, ...] = ()
    calls: tuple[CallTargetSet, ...] = ()
    completeness: Completeness = field(default_factory=lambda: Completeness(is_complete=True))


@dataclass(frozen=True)
class ExplorationBudget:
    """Work bounds for the summary fixpoint; ``None`` means unbounded.

    Req 3.8: every bound that truncates exploration records its exact cutoff
    reason and leaves affected summaries incomplete with the evidence
    accumulated so far.
    """

    depth: int | None = None
    fan_out: int | None = None
    deadline: float | None = None


def _enclosing_type(index: SymbolIndex, module: str, name: str) -> str | None:
    """Return the enclosing type of the function ``name`` declared in ``module``."""
    for symbol in index.by_name.get(name, ()):
        if symbol.module == module:
            return symbol.enclosing_type
    return None


def _function_symbol(index: SymbolIndex, module: str, function_ir: FunctionIR) -> SymbolId:
    """Build the stable identity of ``function_ir`` within ``module``."""
    enclosing_type = _enclosing_type(index, module, function_ir.name)
    signature = tuple(function_ir.params) if function_ir.params else None
    return SymbolId(module, enclosing_type, function_ir.name, signature)


def _joined_call_completeness(calls: tuple[CallTargetSet, ...]) -> Completeness:
    """Join the completeness of every resolved call into one local value."""
    completeness = Completeness(is_complete=True)
    for call in calls:
        completeness = join_completeness(completeness, call.completeness)
    return completeness


def _sorted_functions(functions: Iterable[FunctionIR]) -> tuple[FunctionIR, ...]:
    """Deterministic function order (name, start line)."""
    return tuple(sorted(functions, key=lambda fn: (fn.name, fn.start_line)))


def local_summaries(
    functions_by_module: Mapping[str, Iterable[FunctionIR]],
    index: SymbolIndex,
    *,
    operations_by_symbol: Mapping[SymbolId, tuple[Operation, ...]] | None = None,
    witnesses_by_symbol: Mapping[SymbolId, tuple[Discharge, ...]] | None = None,
) -> tuple[FunctionSummary, ...]:
    """Summarise every function locally: operations, witnesses, resolved calls.

    No caller traversal happens here (task 9.2 owns the monotone fixpoint);
    completeness joins only the resolution completeness of the function's own
    calls plus the injected operation/witness completeness, so an unresolved or
    ambiguous call leaves the summary incomplete with its reason preserved.
    """
    operations_by_symbol = operations_by_symbol or {}
    witnesses_by_symbol = witnesses_by_symbol or {}
    summaries: list[FunctionSummary] = []
    for module in sorted(functions_by_module):
        for function_ir in _sorted_functions(functions_by_module[module]):
            symbol = _function_symbol(index, module, function_ir)
            calls = tuple(resolve_call(call, module=module, index=index) for call in function_ir.calls)
            completeness = _joined_call_completeness(calls)
            summaries.append(
                FunctionSummary(
                    symbol=symbol,
                    operations=operations_by_symbol.get(symbol, ()),
                    witnesses=witnesses_by_symbol.get(symbol, ()),
                    calls=calls,
                    completeness=completeness,
                )
            )
    return tuple(summaries)


def _exact_caller_edges(
    summaries_by_symbol: Mapping[SymbolId, FunctionSummary],
) -> dict[SymbolId, tuple[SymbolId, ...]]:
    """Caller-to-callee edges over complete single-target call sets only."""
    edges: dict[SymbolId, tuple[SymbolId, ...]] = {}
    for symbol, summary in summaries_by_symbol.items():
        callees = {target for call in summary.calls if call.completeness.is_complete and len(call.targets) == 1 for target in call.targets}
        edges[symbol] = tuple(sorted(callees))
    return edges


def _sorted_scc_components(
    edges: Mapping[SymbolId, tuple[SymbolId, ...]],
    nodes: Iterable[SymbolId],
) -> tuple[tuple[SymbolId, ...], ...]:
    """Strongly connected components (members sorted, callee components first)."""
    return _tarjan_components(edges, set(nodes))


def _tarjan_components(edges: Mapping[SymbolId, tuple[SymbolId, ...]], known: set[SymbolId]) -> tuple[tuple[SymbolId, ...], ...]:
    visit_index: dict[SymbolId, int] = {}
    lowlink: dict[SymbolId, int] = {}
    on_component_stack: set[SymbolId] = set()
    component_stack: list[SymbolId] = []
    components: list[tuple[SymbolId, ...]] = []
    counter = 0
    for root in sorted(known):
        if root in visit_index:
            continue
        counter = _tarjan_visit(
            root,
            edges,
            known,
            visit_index,
            lowlink,
            on_component_stack,
            component_stack,
            components,
            counter,
        )
    return tuple(components)


def _tarjan_visit(
    root: SymbolId,
    edges: Mapping[SymbolId, tuple[SymbolId, ...]],
    known: set[SymbolId],
    visit_index: dict[SymbolId, int],
    lowlink: dict[SymbolId, int],
    on_component_stack: set[SymbolId],
    component_stack: list[SymbolId],
    components: list[tuple[SymbolId, ...]],
    counter: int,
) -> int:
    work: list[tuple[SymbolId, Iterator[SymbolId]]] = [(root, iter(edges.get(root, ())))]
    while work:
        node, children = work[-1]
        if node not in visit_index:
            visit_index[node] = counter
            lowlink[node] = counter
            counter += 1
            component_stack.append(node)
            on_component_stack.add(node)
        descended = False
        for child in children:
            if child not in known:
                continue
            if child not in visit_index:
                work.append((child, iter(edges.get(child, ()))))
                descended = True
                break
            if child in on_component_stack:
                lowlink[node] = min(lowlink[node], visit_index[child])
        if descended:
            continue
        work.pop()
        _tarjan_emit_component(node, lowlink, visit_index, on_component_stack, component_stack, components)
        if work:
            parent = work[-1][0]
            lowlink[parent] = min(lowlink[parent], lowlink[node])
    return counter


def _tarjan_emit_component(
    node: SymbolId,
    lowlink: dict[SymbolId, int],
    visit_index: dict[SymbolId, int],
    on_component_stack: set[SymbolId],
    component_stack: list[SymbolId],
    components: list[tuple[SymbolId, ...]],
) -> None:
    if lowlink[node] != visit_index[node]:
        return
    members: list[SymbolId] = []
    while True:
        member = component_stack.pop()
        on_component_stack.discard(member)
        members.append(member)
        if member == node:
            break
    components.append(tuple(sorted(members)))


def _merge_operations(left: tuple[Operation, ...], right: tuple[Operation, ...]) -> tuple[Operation, ...]:
    combined = set(left) | set(right)
    return tuple(sorted(combined, key=_operation_sort_key))


def _operation_sort_key(operation: Operation) -> tuple[str, int, str, str, str, tuple[str, ...]]:
    return (
        operation.path,
        operation.line,
        operation.function,
        operation.kind,
        operation.fact_id,
        operation.requires,
    )


def _merge_witnesses(left: tuple[Discharge, ...], right: tuple[Discharge, ...]) -> tuple[Discharge, ...]:
    combined = set(left) | set(right)
    return tuple(sorted(combined, key=_witness_sort_key))


def _witness_sort_key(discharge: Discharge) -> tuple[str, int, str, str, str, str, str]:
    return (
        discharge.path,
        discharge.line if discharge.line is not None else -1,
        discharge.function,
        discharge.kind,
        discharge.fact_id,
        discharge.provenance,
        discharge.scope,
    )


def _propagated(summary: FunctionSummary, callees: Iterable[FunctionSummary]) -> FunctionSummary:
    """Union every callee's accumulated evidence into ``summary``."""
    operations = summary.operations
    witnesses = summary.witnesses
    completeness = summary.completeness
    for callee in callees:
        operations = _merge_operations(operations, callee.operations)
        witnesses = _merge_witnesses(witnesses, callee.witnesses)
        completeness = join_completeness(completeness, callee.completeness)
    return FunctionSummary(
        symbol=summary.symbol,
        operations=operations,
        witnesses=witnesses,
        calls=summary.calls,
        completeness=completeness,
    )


def _callees_for(
    member_symbol: SymbolId,
    edges: Mapping[SymbolId, tuple[SymbolId, ...]],
    summaries_by_symbol: Mapping[SymbolId, FunctionSummary],
    fan_out: int | None,
) -> tuple[list[FunctionSummary], bool]:
    """Resolve a member's exact callees, truncated to ``fan_out`` when set."""
    callee_edges = [edge for edge in edges.get(member_symbol, ()) if edge in summaries_by_symbol]
    truncated = fan_out is not None and len(callee_edges) > fan_out
    if truncated:
        callee_edges = callee_edges[:fan_out]
    return [summaries_by_symbol[edge] for edge in callee_edges], truncated


def _propagate_round(
    members: tuple[FunctionSummary, ...],
    summaries_by_symbol: dict[SymbolId, FunctionSummary],
    edges: Mapping[SymbolId, tuple[SymbolId, ...]],
    budget: ExplorationBudget,
) -> bool:
    """One union round over the component; returns whether anything changed."""
    changed = False
    for member in members:
        current = summaries_by_symbol[member.symbol]
        callees, truncated = _callees_for(member.symbol, edges, summaries_by_symbol, budget.fan_out)
        propagated = _propagated(current, callees)
        if truncated:
            propagated = replace(
                propagated,
                completeness=join_completeness(
                    propagated.completeness,
                    Completeness(is_complete=False, reasons=(_FAN_OUT_CUTOFF,)),
                ),
            )
        if propagated != current:
            summaries_by_symbol[member.symbol] = propagated
            changed = True
    return changed


def _apply_cutoff_reason(
    members: tuple[FunctionSummary, ...],
    summaries_by_symbol: dict[SymbolId, FunctionSummary],
    reason: str,
) -> None:
    """Mark every member of a truncated component with the cutoff reason."""
    for member in members:
        current = summaries_by_symbol[member.symbol]
        summaries_by_symbol[member.symbol] = replace(
            current,
            completeness=join_completeness(current.completeness, Completeness(is_complete=False, reasons=(reason,))),
        )


def _stabilise_component(
    members: tuple[FunctionSummary, ...],
    summaries_by_symbol: dict[SymbolId, FunctionSummary],
    edges: Mapping[SymbolId, tuple[SymbolId, ...]],
    budget: ExplorationBudget,
) -> None:
    """Iterate a component's members until stable or a budget bound fires."""
    if not any(edges.get(member.symbol) for member in members):
        return
    rounds = 0
    while True:
        if budget.deadline is not None and monotonic() > budget.deadline:
            _apply_cutoff_reason(members, summaries_by_symbol, _DEADLINE_CUTOFF)
            return
        if not _propagate_round(members, summaries_by_symbol, edges, budget):
            return
        rounds += 1
        if budget.depth is not None and rounds >= budget.depth:
            _apply_cutoff_reason(members, summaries_by_symbol, _DEPTH_CUTOFF)
            return


def monotone_summaries(
    functions_by_module: Mapping[str, Iterable[FunctionIR]],
    index: SymbolIndex,
    *,
    operations_by_symbol: Mapping[SymbolId, tuple[Operation, ...]] | None = None,
    witnesses_by_symbol: Mapping[SymbolId, tuple[Discharge, ...]] | None = None,
    budget: ExplorationBudget | None = None,
) -> tuple[FunctionSummary, ...]:
    """Summaries after the monotone fixpoint over strongly connected components.

    Local summaries first; then every component (callee components first) is
    iterated until union-stable, so recursion terminates with the accumulated
    operations, witnesses and completeness reasons of its cycle. ``budget``
    bounds the exploration (Req 3.8): a depth, fan-out or deadline cutoff
    stops growth and leaves affected summaries incomplete with the exact
    cutoff reason. Output order matches :func:`local_summaries`.
    """
    bounded = budget if budget is not None else ExplorationBudget()
    local = local_summaries(
        functions_by_module,
        index,
        operations_by_symbol=operations_by_symbol,
        witnesses_by_symbol=witnesses_by_symbol,
    )
    summaries_by_symbol = {summary.symbol: summary for summary in local}
    edges = _exact_caller_edges(summaries_by_symbol)
    for component in _sorted_scc_components(edges, summaries_by_symbol):
        members = tuple(summaries_by_symbol[member] for member in component)
        _stabilise_component(members, summaries_by_symbol, edges, bounded)
    return tuple(summaries_by_symbol[summary.symbol] for summary in local)
