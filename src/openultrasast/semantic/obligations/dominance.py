"""Does a discharge witness dominate an operation? (authorization-obligations, Req 5.1, 5.2)

`Dominance` is a protocol so the checker can run before `guard-dominance-regime` exists. `OrderDominance` is the
order-based default: decorator and router witnesses dominate the whole handler; a statement witness dominates when it
precedes the operation and the function exits early between them, or when it is itself a guard call (a guard exits on
failure by contract), or when it is a constraint on the operation itself; along a path record a witness on an earlier hop
dominates. Nesting-aware dominance replaces this implementation behind the same protocol.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from .operations import Discharge, Operation

_EXIT = re.compile(r"^\s*(return\b|raise\b|abort\(|sys\.exit\(|exit\(|throw\b|res\.status\(|response\.status\()")


@runtime_checkable
class Dominance(Protocol):
    def dominates(self, witness: Discharge, operation: Operation, path: object | None) -> bool: ...


class OrderDominance:
    """Order-based dominance over source text and, when present, a path record's hops."""

    def __init__(self, texts: Mapping[str, str]) -> None:
        self._texts = dict(texts)

    def dominates(self, witness: Discharge, operation: Operation, path: object | None) -> bool:
        if witness.scope == "hop" or (path is not None and (witness.path, witness.function) != (operation.path, operation.function)):
            return self._dominates_along(witness, operation, path)
        if (witness.path, witness.function) != (operation.path, operation.function):
            return False
        if witness.scope in {"decorator", "router"}:
            return True
        if witness.line is None:
            return False
        if witness.kind == "identity_constraint" or witness.kind == "non_permissive_value":
            return witness.line == operation.line
        if witness.line >= operation.line:
            return False
        if witness.kind == "path_guard":
            return True
        lines = self._texts.get(witness.path, "").splitlines()
        between = lines[witness.line : operation.line - 1]
        return any(_EXIT.match(line) for line in between)

    def _dominates_along(self, witness: Discharge, operation: Operation, path: object | None) -> bool:
        hops = getattr(path, "hops", None)
        if not hops:
            return False
        witness_index = _hop_index(hops, witness.path, witness.function)
        operation_index = _hop_index(hops, operation.path, operation.function)
        if witness_index is None or operation_index is None:
            return False
        return witness_index < operation_index


def _hop_index(hops: object, path: str, function: str) -> int | None:
    stem = Path(path).stem
    if not isinstance(hops, Sequence):
        return None
    for index, hop in enumerate(hops):
        node = str(hop[0]) if isinstance(hop, (tuple, list)) else str(hop)
        node_path, _, node_function = node.rpartition("::")
        if node_function == function and (not node_path or Path(node_path).stem == stem):
            return index
    return None


__all__ = ["Dominance", "OrderDominance"]
