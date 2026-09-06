"""How hard a piece of code makes an absence bug to see (learning-harness, Req 10.4).

A unit fixture that is easier than the corpus is worse than no fixture: the checker passes on it, the number
looks like capability, and the corpus rows it claims to cover keep failing for reasons nobody is looking at. The
three dimensions below are the ones the corpus actually varies on, measured on the vulnerable side:

- ``binding_hops`` — how many assignments sit between the identity source and the constrained use. `filter_by(
  user_id=request.user.id)` is nothing to trace; `resp = token_validator(...)` then `User.query.filter_by(
  username=resp['sub'])` then `filter_by(user=user, ...)` is two.
- ``registration_distance`` — 0 when the route decorator sits on the handler, 1 when a statement elsewhere in the
  same file registers it, 2 when the registration lives in another document entirely (connexion's `operationId`,
  an express router). Two is where the entry-point mapper stops being able to name the handler at all.
- ``guard_distance`` — 0 when a decorator carries the guard, 1 when the guard is a call in the body, 2 when the
  handler carries no visible guard. A decorator is a pattern; a call in the body has to be understood.

Higher is harder on every axis, so "strictly easier" is: no dimension harder, at least one easier.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from dataclasses import dataclass

IDENTITY_SOURCES = ("current_user", "request.user", "session", "g.user", "auth", "token", "jwt", "claims", "sub", "principal")
GUARD_TOKENS = ("login_required", "token_required", "requires_auth", "authenticate", "authorize", "token_validator", "current_user")
_ROUTE_DECORATOR = re.compile(r"\.(route|get|post|put|patch|delete)\b")


@dataclass(frozen=True)
class DifficultyVector:
    """One handler's difficulty. Higher is harder on every axis."""

    function: str
    binding_hops: int
    registration_distance: int
    guard_distance: int

    def axes(self) -> tuple[int, int, int]:
        return (self.binding_hops, self.registration_distance, self.guard_distance)

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function,
            "binding_hops": self.binding_hops,
            "registration_distance": self.registration_distance,
            "guard_distance": self.guard_distance,
        }


def difficulty_of(source: str, function: str, *, context: Sequence[str] = ()) -> DifficultyVector:
    """The vector for one Python handler. ``context`` is any document that registers it from outside the file."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return DifficultyVector(function=function, binding_hops=0, registration_distance=2, guard_distance=2)
    node = _function(tree, function)
    if node is None:
        return DifficultyVector(function=function, binding_hops=0, registration_distance=2, guard_distance=2)
    decorators = [ast.unparse(item) for item in node.decorator_list] + _class_decorators(tree, node)
    return DifficultyVector(
        function=function,
        binding_hops=_binding_hops(node),
        registration_distance=_registration_distance(source, tree, function, decorators, context),
        guard_distance=_guard_distance(node, decorators),
    )


def hardest(vectors: Sequence[DifficultyVector]) -> tuple[int, int, int]:
    """The per-axis maximum over a set of handlers: what the set can be asked to cope with."""
    if not vectors:
        return (0, 0, 0)
    return tuple(max(row.axes()[index] for row in vectors) for index in range(3))  # type: ignore[return-value]


def strictly_easier(fixture: Sequence[DifficultyVector], corpus: Sequence[DifficultyVector]) -> bool:
    """True when the fixture set reaches no further than the corpus on any axis and falls short on at least one.

    Per axis and over the whole set, because a suite covers a bug shape with several handlers between them: one
    fixture handler may carry the long binding chain and another the missing guard. What must not happen is a suite
    whose hardest case on some axis is easier than the corpus rows its tests claim to cover."""
    if not corpus:
        return False
    limit, reach = hardest(corpus), hardest(fixture)
    return all(reach[index] <= limit[index] for index in range(3)) and any(reach[index] < limit[index] for index in range(3))


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _class_decorators(tree: ast.AST, node: ast.AST) -> list[str]:
    for klass in ast.walk(tree):
        if isinstance(klass, ast.ClassDef) and any(child is node for child in klass.body):
            return [ast.unparse(item) for item in klass.decorator_list]
    return []


def _binding_hops(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Assignments that carry the identity forward before it constrains anything."""
    tainted: set[str] = set()
    hops = 0
    for statement in ast.walk(node):
        if not isinstance(statement, ast.Assign):
            continue
        text = ast.unparse(statement.value)
        if any(token in text for token in IDENTITY_SOURCES) or any(name in text for name in tainted):
            hops += 1
            for target in statement.targets:
                tainted.update(part.id for part in ast.walk(target) if isinstance(part, ast.Name))
    return hops


def _registration_distance(source: str, tree: ast.AST, function: str, decorators: Sequence[str], context: Sequence[str]) -> int:
    if any(_ROUTE_DECORATOR.search(item) for item in decorators):
        return 0
    mention = re.compile(rf"(?<![\w.]){re.escape(function)}(?!\w)")
    body = _function(tree, function)
    span = range(getattr(body, "lineno", 0), getattr(body, "end_lineno", 0) + 1) if body is not None else range(0)
    for number, line in enumerate(source.splitlines(), start=1):
        if number not in span and mention.search(line) and not line.strip().startswith(("def ", "async def ", "#")):
            return 1
    if any(re.search(rf"(?<![\w]){re.escape(function)}(?!\w)", item) for item in context):
        return 2
    return 2  # nothing in reach registers it, which is at least as hard as a registration in another document


def _guard_distance(node: ast.FunctionDef | ast.AsyncFunctionDef, decorators: Sequence[str]) -> int:
    if any(token in item.lower() for item in decorators for token in GUARD_TOKENS):
        return 0
    body = ast.unparse(node).lower()
    return 1 if any(token in body for token in GUARD_TOKENS) else 2


__all__ = ["GUARD_TOKENS", "IDENTITY_SOURCES", "DifficultyVector", "difficulty_of", "hardest", "strictly_easier"]
