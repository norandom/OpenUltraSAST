"""Control flow decides whether a discharge witness dominates an operation (access-control-prover, Req 10).

`CfgDominance` implements the `Dominance` protocol over each function's structural control-flow graph. A statement
witness dominates when its node dominates the operation's node and the operation cannot be reached once the guard
fails: the failing arm throws, returns or exits, or the operation lies only inside the passing branch. A permission
predicate whose value nothing consumes before the operation (`value_only`) never dominates. Router and decorator
witnesses dominate the handler as a whole, and along a path record a witness on an earlier hop dominates, exactly
as `OrderDominance` judges them. A function without a graph is judged by `OrderDominance`, and the fallback is
recorded as a `cfg_unavailable` degradation.

`relation`, `effect` and `context` describe a witness and an operation for the trace; `describe` gives the same
description for any `Dominance`, deriving it from order when the object has no graph.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..cfg import ControlContext, FunctionCfg
from .abstract_domain import EvidenceRelation
from .dominance import Dominance, OrderDominance
from .operations import Discharge, Operation

# Discharger kinds whose calls fail by throwing: `checkPermission`, `denyAccessUnlessGranted` and the like.
_THROWING = frozenset({"path_guard"})
_SCOPED = frozenset({"decorator", "router"})
_IN_OPERATION = frozenset({"identity_constraint", "non_permissive_value"})
_EXIT_LINE = re.compile(r"^\s*(?P<word>return\b|raise\b|throw\b|abort\(|sys\.exit\(|exit\(|res\.status\(|response\.status\()")

CfgEntry = FunctionCfg | Sequence[FunctionCfg] | None


@dataclass(frozen=True)
class DominanceEvidence:
    """The strict dominance answer for prover mode: a relation, the guard's failure effect, and a reason when unknown."""

    relation: EvidenceRelation
    guard_effect: str | None = None
    reason: str | None = None


class CfgDominance:
    """Dominance over control-flow graphs keyed by (path, function), with order as the recorded fallback."""

    def __init__(self, texts: Mapping[str, str], cfgs: Mapping[tuple[str, str], CfgEntry]) -> None:
        self.order = OrderDominance(texts)
        self._texts = texts
        self._cfgs = cfgs
        self._unavailable: dict[tuple[str, str], str] = {}

    @property
    def degradations(self) -> tuple[dict[str, object], ...]:
        """One record per function judged by order instead of control flow."""
        return tuple(
            {"stage": "dominance", "reason": "cfg_unavailable", "path": path, "function": function, "detail": detail}
            for (path, function), detail in sorted(self._unavailable.items())
        )

    def graph(self, path: str, function: str, line: int) -> FunctionCfg | None:
        """The function's graph covering `line`, or None (recorded) when it has none."""
        entry = self._cfgs.get((path, function))
        candidates: Sequence[FunctionCfg] = (entry,) if isinstance(entry, FunctionCfg) else tuple(entry or ())
        matching = [cfg for cfg in candidates if cfg.start_line <= line <= cfg.end_line + 1]
        cfg = min(matching, key=lambda item: item.end_line - item.start_line) if matching else None
        if cfg is None or not cfg.available:
            detail = "no_graph" if cfg is None else cfg.reason or "unmodelled_construct"
            self._unavailable.setdefault((path, function), detail)
            return None
        return cfg

    def dominates(self, witness: Discharge, operation: Operation, path: object | None) -> bool:
        if witness.scope == "hop" or (path is not None and (witness.path, witness.function) != (operation.path, operation.function)):
            return self.order.dominates(witness, operation, path)
        if (witness.path, witness.function) != (operation.path, operation.function):
            return False
        if witness.scope in _SCOPED:
            return True
        if witness.line is None:
            return False
        if witness.kind in _IN_OPERATION:
            return witness.line == operation.line
        if witness.line >= operation.line:
            return False
        cfg = self.graph(operation.path, operation.function, operation.line)
        relation = cfg.relation(witness.line, operation.line) if cfg is not None else None
        if cfg is None or relation is None:
            if cfg is not None:
                self._unavailable.setdefault((operation.path, operation.function), "line_without_node")
            return self.order.dominates(witness, operation, path)
        if relation != "all_paths":
            return False
        return cfg.effect(witness.line, operation.line, throwing=witness.kind in _THROWING) != "value_only"

    def evidence(self, witness: Discharge, operation: Operation) -> DominanceEvidence:
        """Strict abstract relation (task 10.1): never falls back to order dominance.

        Unavailable graphs, unmapped lines and cross-function witnesses return UNKNOWN with a
        reason; the legacy boolean surface keeps its order fallback for non-opt-in callers.
        """
        decided = _pre_graph_evidence(witness, operation)
        if decided is not None:
            return decided
        guard_line = witness.line
        if guard_line is None:  # decided above; kept for line-type narrowing
            return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "dominance:no_line")
        cfg = self.graph(operation.path, operation.function, operation.line)
        if cfg is None:
            return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "cfg_unavailable")
        found = cfg.relation(guard_line, operation.line)
        if found is None:
            return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "line_without_node")
        if found == "all_paths":
            effect = cfg.effect(guard_line, operation.line, throwing=witness.kind in _THROWING)
            if effect == "value_only":
                return DominanceEvidence(EvidenceRelation.NO, effect)
            return DominanceEvidence(EvidenceRelation.MUST, effect)
        if found == "some_paths":
            effect = cfg.effect(guard_line, operation.line, throwing=witness.kind in _THROWING)
            return DominanceEvidence(EvidenceRelation.MAY, effect)
        if found in ("none", "after"):
            return DominanceEvidence(EvidenceRelation.NO, None)
        return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "dominance:unmapped_relation")

    def relation(self, witness: Discharge, operation: Operation) -> str:
        cfg = self._local(witness, operation)
        found = cfg.relation(witness.line, operation.line) if cfg is not None and witness.line is not None else None
        return found if found is not None else _order_relation(self.order, witness, operation)

    def effect(self, witness: Discharge, operation: Operation) -> str:
        cfg = self._local(witness, operation)
        found = (
            cfg.effect(witness.line, operation.line, throwing=witness.kind in _THROWING)
            if cfg is not None and witness.line is not None
            else None
        )
        return found if found is not None else _order_effect(self._texts, witness, operation)

    def context(self, operation: Operation) -> ControlContext:
        cfg = self.graph(operation.path, operation.function, operation.line)
        return cfg.context(operation.line) if cfg is not None else ControlContext()

    def _local(self, witness: Discharge, operation: Operation) -> FunctionCfg | None:
        if (
            witness.scope in _SCOPED
            or witness.line is None
            or witness.kind in _IN_OPERATION
            or (witness.path, witness.function) != (operation.path, operation.function)
        ):
            return None
        return self.graph(operation.path, operation.function, operation.line)


def _pre_graph_evidence(witness: Discharge, operation: Operation) -> DominanceEvidence | None:
    """Relation facts that need no graph: scopes, in-operation kinds, cross-function witnesses, line order."""
    if witness.scope in _SCOPED:
        return DominanceEvidence(EvidenceRelation.MUST, "handler")
    if witness.scope == "hop" or (witness.path, witness.function) != (operation.path, operation.function):
        return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "dominance:cross_function")
    if witness.kind in _IN_OPERATION:
        if witness.line == operation.line:
            return DominanceEvidence(EvidenceRelation.MUST, "constrains")
        return DominanceEvidence(EvidenceRelation.NO, "constrains")
    if witness.line is None:
        return DominanceEvidence(EvidenceRelation.UNKNOWN, None, "dominance:no_line")
    if witness.line >= operation.line:
        return DominanceEvidence(EvidenceRelation.NO, None)
    return None


def describe(dominance: Dominance, witness: Discharge, operation: Operation, texts: Mapping[str, str]) -> tuple[str, str]:
    """A witness's relation to an operation and its failure effect, from the graph when the dominance has one."""
    relation = getattr(dominance, "relation", None)
    effect = getattr(dominance, "effect", None)
    if callable(relation) and callable(effect):
        return str(relation(witness, operation)), str(effect(witness, operation))
    return _order_relation(dominance, witness, operation), _order_effect(texts, witness, operation)


def operation_context(dominance: Dominance, operation: Operation) -> ControlContext:
    context = getattr(dominance, "context", None)
    found: Any = context(operation) if callable(context) else None
    return found if isinstance(found, ControlContext) else ControlContext()


def _order_relation(dominance: Dominance, witness: Discharge, operation: Operation) -> str:
    if dominance.dominates(witness, operation, None):
        return "all_paths"
    if witness.line is not None and witness.line > operation.line:
        return "after"
    return "none"


def _order_effect(texts: Mapping[str, str], witness: Discharge, operation: Operation) -> str:
    """Without a graph: scoped witnesses end the request, throwing guards throw, others need an exit line between."""
    if witness.scope in _SCOPED:
        return "exits"
    if witness.kind in _IN_OPERATION:
        return "constrains"
    if witness.kind in _THROWING:
        return "throws"
    if witness.line is None or witness.line >= operation.line:
        return "value_only"
    lines = texts.get(witness.path, "").splitlines()[witness.line : operation.line - 1]
    for line in lines:
        match = _EXIT_LINE.match(line)
        if match is not None:
            word = match.group("word")
            return "returns" if word.startswith("return") else "throws" if word.startswith(("raise", "throw")) else "exits"
    return "value_only"


__all__ = ["CfgDominance", "DominanceEvidence", "describe", "operation_context"]
