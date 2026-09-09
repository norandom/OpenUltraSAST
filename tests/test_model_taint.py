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
            "sink": "os.system(x)",
            "sinkLine": "40",
            "sinkMethod": "elsewhere",
            "source": "request.args['x']",
            "sanitized": False,
            "length": 2,
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


# --- the safe-shape test (task 2.3 finding) ------------------------------------------------------------
#
# Taint reachability alone does not distinguish a parameterised fix from an interpolated bug: the flow
# `request.args["name"] -> name -> execute` exists on BOTH sides of the canonical SQL pair.
#
#     vuln   db.execute("select ... '" + name + "'")      one argument, interpolated
#     fixed  db.execute("select ... = %s", (name,))       two arguments, bound
#
# What separates them is the SHAPE of the sink call, which is exactly what `TaintSpec.safe_shape_sinks`
# preserves. Without this test the model entails both sides and arbitrates nothing.


def _shape_spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import TaintSpec

    return TaintSpec(
        family="injection",
        language="python",
        sources=("request.args",),
        sinks=("execute",),
        sanitizers=(),
        safe_shape_sinks=("execute",),
    )


def test_a_parameterised_sink_call_is_not_a_vulnerability_even_though_the_flow_reaches_it() -> None:
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": 'db.execute("select ... = %s", (name,))',
            "sinkLine": "5",
            "sinkMethod": "run",
            "source": "request.args['name']",
            "sanitized": False,
            "length": 4,
            "sinkArity": 2,
            "sinkArg0Literal": True,
        }
    ]
    assert verdict(_cpg(rows), _shape_spec(), function="run") is None, "a bound query is the fix, not the bug"


def test_an_interpolated_sink_call_of_the_same_name_is_entailed() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": 'db.execute("select ... \'" + name + "\'")',
            "sinkLine": "5",
            "sinkMethod": "run",
            "source": "request.args['name']",
            "sanitized": False,
            "length": 4,
            "sinkArity": 1,
            "sinkArg0Literal": False,
        }
    ]
    answer = verdict(_cpg(rows), _shape_spec(), function="run")
    assert answer is not None and answer.rung is Rung.ENTAILED


def test_the_shape_test_only_applies_to_sinks_declared_safe_in_that_shape() -> None:
    """`os.system(x)` with one argument is not "safe because it has one argument" -- the rule is per sink."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "os.system(full)",
            "sinkLine": "7",
            "sinkMethod": "run",
            "source": "request.args['cmd']",
            "sanitized": False,
            "length": 5,
            "sinkArity": 1,
            "sinkArg0Literal": False,
        }
    ]
    answer = verdict(_cpg(rows), _spec(), function="run")  # os.system is not in safe_shape_sinks
    assert answer is not None and answer.rung is Rung.ENTAILED


def test_a_row_without_shape_fields_is_judged_on_the_flow_alone() -> None:
    """Older rows, or an engine that could not report arity, must not be silently treated as safe."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [{"sink": "db.execute(q)", "sinkLine": "5", "sinkMethod": "run", "source": "request.args['n']", "sanitized": False, "length": 3}]
    answer = verdict(_cpg(rows), _shape_spec(), function="run")
    assert answer is not None and answer.rung is Rung.ENTAILED


def test_parameter_sources_are_opt_in_and_reach_the_query() -> None:
    """A function-level pair's parameters are its trust boundary; a whole repository's are not.

    39 of the 50 injection pairs carry no framework source token at all — their untrusted input arrives as a
    function parameter — and the flat-IR baseline this feature is measured against counted those as sources.
    So the flag must exist and must default to off.
    """
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.taint import verdict

    seen: dict[str, object] = {}

    def run(query: str, params: dict[str, object]) -> object:
        seen.update(params)
        return []

    verdict(CpgResult(cpg_path=Path("c.bin"), run=run), _spec(), function="run")
    assert seen["parameterSources"] == "false", "treating every parameter as untrusted is not the default"
    verdict(CpgResult(cpg_path=Path("c.bin"), run=run), _spec(), function="run", parameter_sources=True)
    assert seen["parameterSources"] == "true"


# --- closure scoping (group 4 finding) -----------------------------------------------------------------
#
# JavaScript is callback-heavy, so the method containing a sink routinely is not the labeled function:
#
#     function requestListener(req, res) {          // labeled
#         fs.stat(possibleFilename, function(err, stats) {
#             fs.readFileSync(possibleFilename)     // sink, enclosing method is <lambda>0
#         })
#     }
#
# Filtering on `sinkMethod == function` dropped every such sink -- the whole `path` family measured 0/8.
# The query now decides scope by line-range containment and reports it; the Python side trusts that flag and
# keeps the name comparison only as a fallback for rows that carry no flag.


def test_a_sink_in_a_nested_closure_is_in_scope_when_the_query_says_so() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "fs.readFileSync(possibleFilename)",
            "sinkLine": "6",
            "sinkMethod": "<lambda>0",
            "source": "req",
            "sanitized": False,
            "length": 4,
            "inLabeledScope": True,
        }
    ]
    answer = verdict(_cpg(rows), _spec(), function="requestListener")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert "<lambda>0" not in answer.witness, "the witness names the flow, not the synthetic closure name"


def test_a_sink_in_an_unrelated_function_stays_out_of_scope() -> None:
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "fs.readFileSync('/etc/' + name)",
            "sinkLine": "11",
            "sinkMethod": "unrelated",
            "source": "name",
            "sanitized": False,
            "length": 2,
            "inLabeledScope": False,
        }
    ]
    assert verdict(_cpg(rows), _spec(), function="requestListener") is None


def test_rows_without_the_scope_flag_fall_back_to_the_method_name() -> None:
    """A row from an engine that cannot report scope must not silently become in-scope."""
    from openultrasast.model.taint import verdict

    rows = [
        {"sink": "os.system(x)", "sinkLine": "9", "sinkMethod": "<lambda>0", "source": "request.args['x']", "sanitized": False, "length": 2}
    ]
    assert verdict(_cpg(rows), _spec(), function="run") is None


def test_a_flow_from_a_real_source_outranks_a_shorter_one_from_a_bare_parameter() -> None:
    """Shortest-wins alone picks the wrong witness once closures are in scope.

    In the angular-http-server shape the closure yields three unsanitized flows to one sink:
    `req.url.split('?')[0]` (11 steps, the actual vulnerability), `res` (3 steps) and `this` (7). Shortest
    would report `res -> fs.readFileSync(...)`, which names no attacker input and is simply untrue. A flow
    whose source matches the spec's source model outranks one from a bare captured name; shortest still
    breaks ties, so the order stays total and the verdict deterministic.
    """
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "fs.readFileSync(p)",
            "sinkLine": "6",
            "sinkMethod": "<lambda>0",
            "source": "res",
            "sanitized": False,
            "length": 3,
            "inLabeledScope": True,
        },
        {
            "sink": "fs.readFileSync(p)",
            "sinkLine": "6",
            "sinkMethod": "<lambda>0",
            "source": "this",
            "sanitized": False,
            "length": 7,
            "inLabeledScope": True,
        },
        {
            "sink": "fs.readFileSync(p)",
            "sinkLine": "6",
            "sinkMethod": "<lambda>0",
            "source": "request.args['f']",
            "sanitized": False,
            "length": 11,
            "inLabeledScope": True,
        },
    ]
    answer = verdict(_cpg(rows), _spec(), function="requestListener")
    assert answer is not None and answer.rung is Rung.ENTAILED
    assert "request.args['f']" in answer.witness, f"witness named no real source: {answer.witness}"
    assert verdict(_cpg(rows), _spec(), function="requestListener") == answer  # still deterministic


def test_a_modelled_source_flow_decides_even_when_a_parameter_flow_is_unsanitized() -> None:
    """Parameter sources are a fallback, never an override.

    On the fixed angular-http-server side the real flow `req.url -> ... -> readFileSync` IS sanitized by
    path.normalize, but the captured `res` parameter also reaches the sink unsanitized. Judging on the union
    reports the fix as still vulnerable, on the strength of a flow that names no attacker input. When any
    modelled source reaches the sink, those flows are the evidence and the bare-parameter ones are ignored.
    """
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "fs.readFileSync(safe)",
            "sinkLine": "41",
            "sinkMethod": "<lambda>0",
            "source": "res",
            "sanitized": False,
            "length": 3,
            "inLabeledScope": True,
        },
        {
            "sink": "fs.readFileSync(safe)",
            "sinkLine": "41",
            "sinkMethod": "<lambda>0",
            "source": "request.args['f']",
            "sanitized": True,
            "length": 22,
            "inLabeledScope": True,
        },
    ]
    answer = verdict(_cpg(rows), _spec(), function="requestListener")
    assert answer is not None and answer.rung is Rung.CORROBORATED, "a sanitized real flow is not an entailment"
    assert "request.args['f']" in answer.witness


def test_parameter_flows_still_decide_when_no_modelled_source_reaches_the_sink() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.taint import verdict

    rows = [
        {
            "sink": "os.system(cmd)",
            "sinkLine": "4",
            "sinkMethod": "run",
            "source": "username",
            "sanitized": False,
            "length": 2,
            "inLabeledScope": True,
        }
    ]
    answer = verdict(_cpg(rows), _spec(), function="run")
    assert answer is not None and answer.rung is Rung.ENTAILED


def test_a_region_scopes_its_question_to_its_own_file() -> None:
    """A region with no enclosing function must not be answered with the whole repository.

    Sending `function=""` unscoped matched every hit in the tree and the driver attributed all of it to
    whichever region asked: one permissive literal in app.py became eight identical entailed findings in
    eight files that do not contain it.
    """
    from openultrasast.model.config_value import request_params as config_params
    from openultrasast.model.specs import config_specs, taint_specs
    from openultrasast.model.taint import request_params as taint_params

    taint = taint_params(taint_specs(language="python")["injection"], function="", file="models/user_model.py")
    config = config_params(config_specs(language="python")["config_secrets"], function="", file="config.py")

    assert taint["file"] == "models/user_model.py"
    assert config["file"] == "config.py"
    # The pair path stays unscoped, so the committed pair measurements remain reproducible.
    assert taint_params(taint_specs(language="python")["injection"], function="run")["file"] == ""


def _bounded_rows(bounded: bool):  # type: ignore[no-untyped-def]
    return [
        {
            "sink": 'strcpy(outname+len, ".png")',
            "sinkLine": "374",
            "sinkMethod": "main",
            "sinkFile": "contrib/gregbook/wpng.c",
            "source": "*argv",
            "sanitized": False,
            "length": 6,
            "sinkArity": 2,
            "sinkArg0Literal": False,
            "inLabeledScope": True,
            "bounded": bounded,
            "bound": "(len = strlen(inname)) > 250" if bounded else "",
        }
    ]


def test_a_bound_that_governs_the_sink_lowers_the_rung() -> None:
    """contributor-scan 2.12. libpng's `strcpy(outname+len, ".png")` is governed by `len > 250` against a
    char[256]. Entailing it is a claim the code contradicts -- but a bound is not proof either, since
    off-by-one is how they fail, so the judge is asked rather than the site silenced."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.ladder import Rung
    from openultrasast.model.specs import taint_specs
    from openultrasast.model.taint import verdict

    spec = taint_specs(language="c")["memory"]
    assert "strcpy" in spec.bounded_sinks, "a CWE-121 sink is dischargeable by a bound"

    governed = verdict(CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: _bounded_rows(True)), spec, function="main")
    ungoverned = verdict(CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: _bounded_rows(False)), spec, function="main")

    assert governed is not None and governed.rung is Rung.CORROBORATED
    assert "governed by" in governed.witness, "the witness names the bound it found"
    assert ungoverned is not None and ungoverned.rung is Rung.ENTAILED, "an unguarded copy is still the finding"


def test_only_a_length_sink_can_be_discharged_by_a_bound() -> None:
    """A `len > 10` check does not make an SQL injection safe. The CWE decides, and CWE-121 is C-only."""
    from openultrasast.model.specs import taint_specs

    assert not taint_specs(language="python")["injection"].bounded_sinks
    assert not taint_specs(language="c")["injection"].bounded_sinks
    assert taint_specs(language="c")["memory"].bounded_sinks
