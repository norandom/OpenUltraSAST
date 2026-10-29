"""Local function summaries for the obligations abstract interpretation.

Task 9.1 (Reqs 3.1, 3.6, 11.7). Each summary collects a function's protected
operations, local witnesses, resolved calls and local completeness WITHOUT
traversing callers: the monotone fixpoint over strongly connected call
components is task 9.2. Summaries are deterministic and carry no target names
beyond fact identifiers (Req 11.7).
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ..ir import FunctionIR
from .abstract_domain import Completeness, join_completeness
from .operations import Discharge, Operation
from .resolution import CallTargetSet, SymbolId, SymbolIndex, resolve_call


@dataclass(frozen=True)
class FunctionSummary:
    """Local summary of one function: what it holds, whom it calls."""

    symbol: SymbolId
    operations: tuple[Operation, ...] = ()
    witnesses: tuple[Discharge, ...] = ()
    calls: tuple[CallTargetSet, ...] = ()
    completeness: Completeness = field(default_factory=lambda: Completeness(is_complete=True))


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
