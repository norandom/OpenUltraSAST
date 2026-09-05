"""authorization-obligations task 2.1: operations and discharge witnesses in a parsed file (offline, stdlib ast)."""

from __future__ import annotations

from openultrasast.mapping import EntryPointRecord
from openultrasast.semantic.facts import load_facts
from openultrasast.semantic.ir import parse_file

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/mine/<title>')\ndef constrained(title):\n"
    "    user_id = request.user.id\n"
    "    return Book.query.filter_by(user_id=user_id, book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n\n\n"
    "@app.route('/health')\ndef health():\n    return 'ok'\n"
)


def _entry(function: str, line: int, end: int, access: str, evidence: list[str]) -> EntryPointRecord:
    return EntryPointRecord(
        path="app.py",
        line=line,
        end_line=end,
        function_name=function,
        name=function,
        kind="route",
        access_level=access,  # type: ignore[arg-type]
        trust_boundary="http_request",
        access_evidence=evidence,
        conditions=[],
        provenance="test",
        rationale="",
    )


ENTRIES = [
    _entry("guarded", 6, 7, "authenticated", ["@login_required"]),
    _entry("constrained", 11, 13, "public", []),
    _entry("leaky", 17, 19, "public", []),
    _entry("health", 23, 24, "public", []),
]


def test_find_operations_names_kind_fact_function_and_resource() -> None:
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.operations import find_operations

    ir = parse_file("app.py", APP, "python")
    ops = find_operations(ir, load_obligation_facts().for_language("python"), text=APP)
    assert [(op.function, op.kind, op.resource) for op in ops] == [
        ("guarded", "protected_read", "book"),
        ("constrained", "protected_read", "book"),
        ("leaky", "protected_read", "book"),
    ]
    assert all(op.path == "app.py" and op.fact_id == "orm-read" and op.line > 0 for op in ops)
    assert not [op for op in ops if op.function == "health"]  # a constant return is no operation


def test_find_discharges_reports_witness_kind_provenance_and_scope() -> None:
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.operations import find_discharges

    ir = parse_file("app.py", APP, "python")
    witnesses = find_discharges(
        ir, load_obligation_facts().for_language("python"), load_facts().for_language("python"), text=APP, entries=ENTRIES
    )
    by_function = {}
    for w in witnesses:
        by_function.setdefault(w.function, []).append((w.kind, w.provenance, w.scope))
    assert ("path_guard", "authenticated_context", "decorator") in by_function["guarded"]
    assert ("identity_constraint", "authenticated_context", "statement") in by_function["constrained"]
    assert ("identity_constraint", "request_input", "statement") in by_function["leaky"]  # present, but discharges nothing
    assert "health" not in by_function
    assert all(w.path == "app.py" and w.fact_id for w in witnesses)


def test_discharge_witness_covers_operation_only_when_kind_and_provenance_fit() -> None:
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.operations import covers, find_discharges, find_operations

    ir = parse_file("app.py", APP, "python")
    facts = load_obligation_facts().for_language("python")
    ops = {op.function: op for op in find_operations(ir, facts, text=APP)}
    witnesses = find_discharges(ir, facts, load_facts().for_language("python"), text=APP, entries=ENTRIES)
    covering = {op.function: [w.kind for w in witnesses if covers(w, op)] for op in ops.values()}
    assert covering["constrained"] == ["identity_constraint"]
    assert covering["leaky"] == []  # request-bound identity does not cover
    assert covering["guarded"] == []  # a path guard does not cover a protected read (only privileged actions)
