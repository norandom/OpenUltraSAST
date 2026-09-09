"""model-grounded-detection task 4.1: guard dominance, the arbiter for bugs that never crash (Req 6.2).

An access-control bug is the *absence* of a guard, so there is no flow to follow and no crash to reproduce.
What the model can establish is a consistency violation: an obligated operation that no discharging guard
dominates, in a file where its siblings are dominated by one. That asymmetry is the evidence.

This replaces the line-order heuristic in `semantic/obligations/dominance.py` ("the guard's line is before the
operation's line, with an early exit between") with real control-flow dominance over the CFG.
"""

from __future__ import annotations

from pathlib import Path


def _spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import DominanceSpec

    return DominanceSpec(
        family="access_control",
        language="python",
        operations=("filter_by", "query.get", "session.delete"),
        dischargers=("login_required", "current_user", "check_permission"),
    )


def _cpg(rows):  # type: ignore[no-untyped-def]
    from openultrasast.cpg.backend import CpgResult

    return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: rows)


def _op(method: str, guards: list[str], line: int = 10) -> dict[str, object]:
    return {"operation": "Note.query.filter_by(id=nid)", "opLine": str(line), "opMethod": method, "dominatingGuards": guards}


def test_an_unguarded_operation_among_guarded_siblings_is_entailed() -> None:
    """The consistency violation: every sibling checks the owner, this one does not."""
    from openultrasast.model.dominance import verdict
    from openultrasast.model.ladder import Rung

    rows = [_op("leaky", []), _op("list_notes", ["current_user"]), _op("edit_note", ["current_user"])]
    answer = verdict(_cpg(rows), _spec(), function="leaky")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert answer.family == "access_control"
    assert "leaky" in answer.witness and "2 sibling" in answer.witness, "the witness names the operation and its siblings"


def test_a_method_with_two_operations_counts_once_as_a_sibling() -> None:
    """One handler holding two obligated operations is one piece of corroboration, not two."""
    from openultrasast.model.dominance import verdict

    rows = [_op("leaky", []), _op("listing", ["current_user"], line=3), _op("listing", ["current_user"], line=4)]
    answer = verdict(_cpg(rows), _spec(), function="leaky")
    assert answer is not None and "1 sibling" in answer.witness
    assert answer.witness.count("listing") == 1


def test_a_guarded_operation_yields_no_finding() -> None:
    from openultrasast.model.dominance import verdict

    rows = [_op("safe", ["current_user"]), _op("other", ["current_user"])]
    assert verdict(_cpg(rows), _spec(), function="safe") is None


def test_an_unguarded_operation_with_no_guarded_sibling_is_only_corroborated() -> None:
    """Nothing to be inconsistent with: the whole module may be unauthenticated by design, and saying
    `entailed` there would assert a policy the model cannot see."""
    from openultrasast.model.dominance import verdict
    from openultrasast.model.ladder import Rung

    rows = [_op("a", []), _op("b", [])]
    answer = verdict(_cpg(rows), _spec(), function="a")
    assert answer is not None and answer.rung is Rung.CORROBORATED


def test_no_obligated_operation_yields_no_verdict() -> None:
    from openultrasast.model.dominance import verdict

    assert verdict(_cpg([]), _spec(), function="whatever") is None


def test_a_failed_query_is_not_read_as_an_absence_of_operations() -> None:
    """`None` from the engine means "could not decide", never "there is nothing here"."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict

    broken = CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: None)
    assert verdict(broken, _spec(), function="a") is None


def test_the_verdict_is_deterministic_over_one_cpg() -> None:
    """Req 6.4, for the absence arbiter as well as the flow one."""
    from openultrasast.model.dominance import verdict

    rows = [_op("leaky", []), _op("z", ["current_user"]), _op("a", ["check_permission"])]
    cpg = _cpg(rows)
    assert verdict(cpg, _spec(), function="leaky") == verdict(cpg, _spec(), function="leaky")


def test_the_spec_drives_the_query_parameters() -> None:
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict

    seen: dict[str, object] = {}

    def run(query: str, params: dict[str, object]) -> object:
        seen["query"] = query
        seen.update(params)
        return []

    verdict(CpgResult(cpg_path=Path("c.bin"), run=run), _spec(), function="f")
    assert seen["query"] == "dominance"
    assert seen["operations"] == ("filter_by", "query.get", "session.delete")
    assert seen["dischargers"] == ("login_required", "current_user", "check_permission")
    assert seen["function"] == "f"


def test_an_access_control_finding_names_a_line_a_contributor_can_open() -> None:
    """contributor-scan 2.7. Taint and config verdicts always carried a location; dominance did not, so every
    access-control finding arrived as `api_views/users.py:?:update_password` -- the right file by accident,
    because the region was asked about that file, and no line at all."""
    from pathlib import Path

    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict
    from openultrasast.model.specs import dominance_specs

    rows = [
        {
            "operation": "User.query.filter_by(username = username)",
            "opLine": "187",
            "opMethod": "update_password",
            "opFile": "api_views/users.py",
            "dominatingGuards": [],
        },
        {
            "operation": "User.query.filter_by(username = resp['sub'])",
            "opLine": "33",
            "opMethod": "me",
            "opFile": "api_views/users.py",
            "dominatingGuards": ["resp['sub']"],
        },
    ]
    spec = dominance_specs(language="python")["access_control"]

    answer = verdict(CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: rows), spec, function="update_password")

    assert answer is not None
    assert answer.location == "api_views/users.py:187:update_password"


def test_a_verdict_without_a_reported_file_carries_no_location() -> None:
    """An engine that could not report the file must not have a location invented for it."""
    from pathlib import Path

    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict
    from openultrasast.model.specs import dominance_specs

    rows = [{"operation": "q.filter_by(x)", "opLine": "-1", "opMethod": "handler", "opFile": "", "dominatingGuards": []}]
    spec = dominance_specs(language="python")["access_control"]

    answer = verdict(CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: rows), spec, function="handler")

    assert answer is not None and answer.location == ""
