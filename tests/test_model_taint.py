"""model-grounded-detection task 2.2: the taint verdict, and what separates entailed from corroborated.

An `ENTAILED` verdict is the static analogue of a reproduced crash: the CPG establishes the flow on its own and
the LLM's assertion is no longer load-bearing. `CORROBORATED` means a path exists but a sanitizer may break it,
so the judgement of sufficiency is the LLM's residual — checked against the graph, never averaged over runs.
"""

from __future__ import annotations

from pathlib import Path


def _cpg(rows: list[dict[str, object]]):  # type: ignore[no-untyped-def]
    from openultrasast.cpg.backend import CpgResult

    return CpgResult(cpg_path=Path("cpg.bin"), run=lambda query, params: rows)


def _spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import TaintSpec

    return TaintSpec(
        family="injection",
        language="python",
        sources=("request.args",),
        sinks=("os.system", "execute"),
        sanitizers=("escape", "quote"),
    )


def test_an_unsanitized_source_to_sink_path_is_entailed() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['x']", "sanitized": False, "length": 3}
    ]
    answer = verdict(_cpg(rows), _spec(), function="run")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert answer.family == "injection"
    assert "request.args" in answer.witness and "os.system" in answer.witness, "the witness names the flow it found"


def test_a_path_through_a_sanitizer_is_corroborated_not_entailed() -> None:
    """The model saw the flow but cannot judge whether the sanitizer is sufficient. That residual is the LLM's."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [{"sink": "execute(q)", "sinkLine": "9", "sinkMethod": "run", "source": "request.args['q']", "sanitized": True, "length": 4}]
    answer = verdict(_cpg(rows), _spec(), function="run")
    assert answer is not None and answer.rung is Rung.CORROBORATED


def test_no_path_yields_no_verdict_so_the_caller_reports_suspicion() -> None:
    from openultrasast.model.taint import verdict

    assert verdict(_cpg([]), _spec(), function="run") is None


def test_a_query_that_failed_is_not_read_as_an_absence_of_flow() -> None:
    """`None` from the engine means "could not decide", which is not the same as "no path" — Req 4.3."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.taint import verdict

    broken = CpgResult(cpg_path=Path("cpg.bin"), run=lambda query, params: None)
    assert verdict(broken, _spec(), function="run") is None


def test_the_verdict_is_restricted_to_the_labeled_function() -> None:
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "os.system(x)", "sinkLine": "40", "sinkMethod": "elsewhere",
            "source": "request.args['x']", "sanitized": False, "length": 2,
        }
    ]
    assert verdict(_cpg(rows), _spec(), function="run") is None, "a flow in another function does not judge this one"


def test_the_shortest_unsanitized_flow_wins_and_the_sequence_is_deterministic() -> None:
    """Req 6.4: two runs over one CPG give an identical verdict sequence, so there is nothing to average."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {"sink": "os.system(a)", "sinkLine": "7", "sinkMethod": "run", "source": "request.args['b']", "sanitized": True, "length": 9},
        {"sink": "os.system(a)", "sinkLine": "7", "sinkMethod": "run", "source": "request.args['a']", "sanitized": False, "length": 2},
    ]
    first = verdict(_cpg(rows), _spec(), function="run")
    second = verdict(_cpg(rows), _spec(), function="run")
    assert first == second
    assert first is not None and first.rung is Rung.ENTAILED and "request.args['a']" in first.witness


def test_the_spec_drives_the_query_parameters() -> None:
    """The security modelling is ours; the traversal is the engine's. The spec is what crosses the seam."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.taint import verdict

    seen: dict[str, object] = {}

    def run(query: str, params: dict[str, object]) -> object:
        seen["query"] = query
        seen.update(params)
        return []

    verdict(CpgResult(cpg_path=Path("cpg.bin"), run=run), _spec(), function="run")
    assert seen["query"] == "taint"
    assert seen["sources"] == ("request.args",)
    assert seen["sinks"] == ("os.system", "execute")
    assert seen["sanitizers"] == ("escape", "quote")
    assert seen["function"] == "run"
