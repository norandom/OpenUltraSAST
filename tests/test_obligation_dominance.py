"""authorization-obligations task 2.4: the Dominance protocol and its order-based default (offline)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Path:  # stub of reachability's PathRecord: (node, call line) hops ending at the operation's node
    hops: tuple[tuple[str, int], ...]


def _op(path: str = "app.py", line: int = 9, function: str = "handler", kind: str = "protected_read"):
    from openultrasast.semantic.obligations.operations import Operation

    return Operation(
        path=path,
        line=line,
        function=function,
        kind=kind,
        fact_id="orm-read",
        resource="book",
        requires=("identity_constraint", "ownership_check"),
    )


def _wit(
    kind: str, line: int | None, scope: str, function: str = "handler", path: str = "app.py", provenance: str = "authenticated_context"
):
    from openultrasast.semantic.obligations.operations import Discharge

    return Discharge(path=path, line=line, function=function, kind=kind, fact_id="f", provenance=provenance, scope=scope)


SRC = (
    "def handler(book_id):\n    user = current_user()\n    if user is None:\n        return None\n"
    "    book = Book.query.filter_by(id=book_id).first()\n    check_owner(user, book)\n    return book\n"
)


def test_order_dominance_decorators_and_router_witnesses_dominate_the_handler() -> None:
    from openultrasast.semantic.obligations.dominance import Dominance, OrderDominance

    dom = OrderDominance(texts={"app.py": SRC})
    assert isinstance(dom, Dominance)
    assert dom.dominates(_wit("ownership_check", None, "decorator"), _op(line=5), None)
    assert dom.dominates(_wit("ownership_check", None, "router"), _op(line=5), None)
    assert not dom.dominates(_wit("ownership_check", None, "decorator", function="other"), _op(line=5), None)


def test_order_dominance_statement_witness_needs_to_precede_with_an_exit_or_be_a_guard_call() -> None:
    from openultrasast.semantic.obligations.dominance import OrderDominance

    dom = OrderDominance(texts={"app.py": SRC})
    assert dom.dominates(_wit("ownership_check", 2, "statement"), _op(line=5), None)  # before, with `return` between
    assert not dom.dominates(_wit("ownership_check", 6, "statement"), _op(line=5), None)  # after the operation
    no_exit = "def handler(book_id):\n    user = current_user()\n    book = Book.query.filter_by(id=book_id).first()\n    return book\n"
    dom2 = OrderDominance(texts={"app.py": no_exit})
    assert not dom2.dominates(_wit("ownership_check", 2, "statement"), _op(line=3), None)  # no early exit: not a dominating check
    assert dom2.dominates(_wit("path_guard", 2, "statement"), _op(line=3), None)  # a guard call itself is an early exit by contract
    assert dom2.dominates(_wit("identity_constraint", 3, "statement"), _op(line=3), None)  # a constraint sits on the operation itself


def test_order_dominance_along_a_path_uses_hop_order() -> None:
    from openultrasast.semantic.obligations.dominance import OrderDominance

    dom = OrderDominance(texts={})
    path = _Path(hops=(("api.py::route", 10), ("svc.py::load", 20), ("repo.py::read", 30)))
    assert dom.dominates(_wit("path_guard", 4, "hop", function="route", path="api.py"), _op(path="repo.py", line=31, function="read"), path)
    assert not dom.dominates(
        _wit("path_guard", 4, "hop", function="read", path="repo.py"), _op(path="api.py", line=9, function="route"), path
    )
    assert not dom.dominates(
        _wit("path_guard", 4, "hop", function="elsewhere", path="x.py"), _op(path="repo.py", line=31, function="read"), path
    )
