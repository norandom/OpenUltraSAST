"""authorization-obligations task 2.2: sibling handler sets and consistency anomalies (offline)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_obligation_operations import APP, ENTRIES  # noqa: E402

from openultrasast.semantic.facts import load_facts  # noqa: E402
from openultrasast.semantic.ir import parse_file  # noqa: E402


def _inputs():
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.operations import find_discharges, find_operations

    ir = parse_file("app.py", APP, "python")
    facts = load_obligation_facts().for_language("python")
    ops = find_operations(ir, facts, text=APP)
    wit = find_discharges(ir, facts, load_facts().for_language("python"), text=APP, entries=ENTRIES)
    return ops, wit


def test_sibling_sets_group_by_router_and_resource_and_record_who_discharges() -> None:
    from openultrasast.semantic.obligations.siblings import sibling_sets

    ops, wit = _inputs()
    sets = sibling_sets(ENTRIES, ops, wit)
    assert len(sets) == 1
    (books,) = sets
    assert books.key == ("app", "book")
    assert set(books.handlers) == {"app.py::guarded", "app.py::constrained", "app.py::constrained_too", "app.py::leaky"}
    assert books.discharging["identity_constraint"] == (
        "app.py::constrained",
        "app.py::constrained_too",
    )  # leaky's request-bound one does not count
    assert books.discharging["path_guard"] == ("app.py::constrained", "app.py::guarded")
    assert books.operation_kinds == ("protected_read",)


def test_consistency_anomalies_respect_the_minimum_and_name_the_siblings() -> None:
    from openultrasast.semantic.obligations.siblings import consistency_anomalies, sibling_sets

    ops, wit = _inputs()
    sets = sibling_sets(ENTRIES, ops, wit)
    anomalies, under = consistency_anomalies(sets, min_siblings=2)
    by_handler = {(a.handler, a.missing): a for a in anomalies}
    # tasks.md observable: two siblings constrain by owner -> one anomaly per unconstrained handler naming both siblings
    assert by_handler[("app.py::leaky", "identity_constraint")].siblings == ("app.py::constrained", "app.py::constrained_too")
    assert by_handler[("app.py::guarded", "identity_constraint")].siblings == ("app.py::constrained", "app.py::constrained_too")
    assert by_handler[("app.py::leaky", "identity_constraint")].operation_kind == "protected_read"
    assert ("app.py::constrained", "identity_constraint") not in by_handler
    assert under == ()
    # Req 3.2: the configured minimum applies to how many siblings discharge, not to one sibling setting the norm
    anomalies_three, _ = consistency_anomalies(sets, min_siblings=3)
    assert not [a for a in anomalies_three if a.missing == "identity_constraint"]  # only two discharge
    anomalies_strict, under_strict = consistency_anomalies(sets, min_siblings=5)
    assert anomalies_strict == () and under_strict == (("app", "book"),)  # Req 3.3: under-populated, never reported


def test_public_route_among_authenticated_siblings_is_a_missing_path_guard_with_access_evidence() -> None:
    from openultrasast.semantic.obligations.siblings import consistency_anomalies, sibling_sets

    ops, wit = _inputs()
    sets = sibling_sets(ENTRIES, ops, wit)
    anomalies, _ = consistency_anomalies(sets, min_siblings=2)
    guard_anomalies = [a for a in anomalies if a.missing == "path_guard"]
    assert {a.handler for a in guard_anomalies} == {"app.py::constrained_too", "app.py::leaky"}
    assert all(a.access_level == "public" and "authenticated" in " ".join(a.evidence) for a in guard_anomalies)
    assert all(a.siblings == ("app.py::constrained", "app.py::guarded") for a in guard_anomalies)


def test_same_named_files_in_different_modules_are_not_siblings() -> None:
    """Round-2 finding: the key must be the module path, not the file's basename."""
    from openultrasast.mapping import EntryPointRecord
    from openultrasast.semantic.obligations.operations import Operation
    from openultrasast.semantic.obligations.siblings import sibling_sets

    def entry(path: str, function: str) -> EntryPointRecord:
        return EntryPointRecord(
            path=path,
            line=1,
            end_line=2,
            function_name=function,
            name=function,
            kind="route",
            access_level="public",
            trust_boundary="http_request",
            access_evidence=[],
            conditions=[],
            provenance="t",
            rationale="",
        )  # type: ignore[arg-type]

    def op(path: str, function: str) -> Operation:
        return Operation(
            path=path,
            line=2,
            function=function,
            kind="protected_read",
            fact_id="orm-read",
            resource="book",
            requires=("identity_constraint",),
        )

    entries = [entry("api/v1/books.py", "list_a"), entry("admin/legacy/books.py", "list_b")]
    sets = sibling_sets(entries, [op("api/v1/books.py", "list_a"), op("admin/legacy/books.py", "list_b")], [])
    assert {group.key for group in sets} == {("api/v1/books", "book"), ("admin/legacy/books", "book")}
    assert all(len(group.handlers) == 1 for group in sets)
