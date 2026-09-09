"""Taint reachability over the CPG: the arbiter for the flow families (Req 6.1).

The verdict is the static analogue of a reproduced crash. An unsanitized source→sink path is `ENTAILED` — the
graph establishes it and the LLM's claim is no longer load-bearing. A path a sanitizer may break is
`CORROBORATED`: the flow is real, but whether the sanitizer is *sufficient* is a semantic judgement the model
cannot make, and that residual is the LLM's — checked against this verdict rather than averaged over runs.

No path at all yields `None`, not a negative verdict: the caller reports `suspicion`. And a query that failed
yields `None` too, because "the engine could not decide" is not "there is no flow" — conflating them is how a
missing engine would silently become a clean bill of health.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..cpg.backend import CpgResult
from .ladder import Rung, Verdict
from .specs import TaintSpec


def request_params(
    spec: TaintSpec, *, function: str = "", file: str = "", parameter_sources: bool = False, call_depth: int = 0
) -> dict[str, object]:
    """The query parameters this arbiter sends. Shared with the batcher so there is one definition, not two.

    Two copies of a parameter dict is precisely the duplication that produced five bugs of one shape in the
    predecessor: a change made in one place and not its sibling.

    ``file`` scopes the answer to one source file. A region with no enclosing function sends ``function=""``,
    which without this matches the whole repository and gets that answer attributed to it -- one permissive
    literal in `app.py` became eight identical entailed findings in eight files that do not contain it. Empty
    means unscoped, which is what the single-region pair path still uses.
    """
    return {
        "sources": spec.sources,
        "sinks": spec.sinks,
        "sanitizers": spec.sanitizers,
        "function": function,
        "file": file,
        "parameterSources": "true" if parameter_sources else "false",
        "callDepth": str(call_depth),
        "boundedSinks": spec.bounded_sinks,
    }


def verdict(
    cpg: CpgResult, spec: TaintSpec, *, function: str = "", file: str = "", parameter_sources: bool = False, call_depth: int = 0
) -> Verdict | None:
    """The strongest verdict the taint query supports for ``spec`` in ``function``, or ``None`` to stay at suspicion.

    ``parameter_sources`` additionally treats the labeled function's own parameters as untrusted. That is right
    for a function-level pair, where the function boundary *is* the trust boundary, and wrong for a whole
    repository, where most parameters carry internal values — so it is off by default and the caller opts in.
    An ENTRY POINT is the case where both are true at once: its parameters are attacker input by definition,
    which is what the driver uses to decide.

    ``call_depth`` admits sinks that many call-graph levels below the labeled method. Zero keeps the old
    function-local question; above zero is what lets a handler's parameter reach a sink in another module,
    which is the shape VAmPI's SQL injection has and the shape a function-scoped question cannot see.
    """
    considered = _usable_flows(cpg, spec, function=function, file=file, parameter_sources=parameter_sources, call_depth=call_depth)
    if not considered:
        return None
    # A flow the graph cannot see a discharge for is the finding; a sanitized or BOUNDED one is a question.
    # libpng bounds `strcpy(outname+len, ".png")` with `(len = strlen(inname)) > 250` against a char[256],
    # and entailing it is a claim the code contradicts. But the bound reaches the sink through an `error`
    # flag rather than by dominating it, so the graph has not shown the copy is guarded either -- and a
    # bound is no proof of safety in any case, off-by-one being the classic way they fail. Corroborated is
    # the honest rung: the model cannot assert this, so the judge is asked instead of the site being
    # silenced.
    open_flows = [flow for flow in considered if not flow["sanitized"] and not flow["bounded"]]
    # Deterministic by construction: a total order, then take the first. Nothing depends on engine ordering.
    chosen = min(open_flows or considered, key=lambda flow: _rank(flow, spec))
    return _verdict_for(chosen, spec)


def _usable_flows(
    cpg: CpgResult,
    spec: TaintSpec,
    *,
    function: str,
    file: str,
    parameter_sources: bool,
    call_depth: int,
) -> list[dict[str, object]]:
    """The flows both entry points reason over, so neither can drift from the other.

    A sink whose *shape* is safe is the fix, not the bug: `execute(sql, params)` binds rather than
    interpolates and `printf("literal", x)` has a constant format string, so a flow reaching them is not a
    vulnerability even though its taint path is identical to the vulnerable twin's. Dropping those is what
    lets the model distinguish a pair at all -- measured on the injection slice, taint reachability alone
    entailed both sides of the canonical SQL pair and arbitrated nothing.

    Parameter sources are then a FALLBACK, never an override. When a modelled source reaches the sink those
    flows are the evidence, so a captured `res` parameter also reaching it unsanitized cannot report a fix as
    still vulnerable on the strength of a flow that names no attacker input.
    """
    rows = cpg.run(
        "taint",
        request_params(spec, function=function, file=file, parameter_sources=parameter_sources, call_depth=call_depth),
    )
    flows = [flow for flow in _flows(rows, function=function) if not _has_safe_shape(flow, spec)]
    modelled = [flow for flow in flows if _from_modelled_source(flow, spec)]
    return modelled or flows


def verdicts(
    cpg: CpgResult,
    spec: TaintSpec,
    *,
    function: str = "",
    file: str = "",
    parameter_sources: bool = False,
    call_depth: int = 0,
) -> list[Verdict]:
    """One verdict per distinct SINK SITE, strongest first.

    ``verdict`` answers "what is the strongest thing to say about this region", which is the right question
    for a pair: one labelled function, one bug, one answer. It is the wrong question for a region that spans
    a file. A PHP file with an SQL injection on line 6 and a command injection on line 13 got ONE injection
    verdict, and `system` won it on flow length -- so the SQL injection went unreported, by construction
    rather than by any failure of the analysis.

    The first element is exactly what ``verdict`` returns, so the pair path and the committed measurements
    that rest on it are unchanged.
    """
    flows = _usable_flows(cpg, spec, function=function, file=file, parameter_sources=parameter_sources, call_depth=call_depth)
    if not flows:
        return []
    by_site: dict[str, list[Mapping[str, object]]] = {}
    for flow in flows:
        by_site.setdefault(_location(flow) or str(flow.get("sink", "")), []).append(flow)

    chosen: list[Mapping[str, object]] = []
    for site_flows in by_site.values():
        open_flows = [flow for flow in site_flows if not flow["sanitized"] and not flow["bounded"]]
        chosen.append(min(open_flows or site_flows, key=lambda flow: _rank(flow, spec)))
    # Same total order the single-verdict path uses, so `verdicts(...)[0] == verdict(...)`.
    chosen.sort(key=lambda flow: (bool(flow["sanitized"]) or bool(flow["bounded"]), _rank(flow, spec)))
    return [_verdict_for(flow, spec) for flow in chosen]


def _verdict_for(flow: Mapping[str, object], spec: TaintSpec) -> Verdict:
    settled = bool(flow["sanitized"]) or bool(flow["bounded"])
    rung = Rung.CORROBORATED if settled else Rung.ENTAILED
    return Verdict(rung=rung, family=spec.family, witness=_witness(flow), location=_location(flow))


def _flows(rows: object, *, function: str) -> list[dict[str, object]]:
    """The query's rows, filtered to the labeled function. A non-list (a failure) yields nothing."""
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    kept: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if function and not _in_scope(row, function):
            continue
        kept.append(
            {
                "sink": str(row.get("sink", "")),
                "sinkArity": row.get("sinkArity"),
                "sinkArg0Literal": row.get("sinkArg0Literal"),
                "inLabeledScope": row.get("inLabeledScope"),
                "sinkLine": str(row.get("sinkLine", "")),
                "sinkMethod": str(row.get("sinkMethod", "")),
                "sinkFile": str(row.get("sinkFile", "")),
                "bounded": bool(row.get("bounded", False)),
                "bound": str(row.get("bound", "")),
                "source": str(row.get("source", "")),
                "sanitized": bool(row.get("sanitized", False)),
                "length": _as_int(row.get("length")),
            }
        )
    return kept


def _has_safe_shape(flow: Mapping[str, object], spec: TaintSpec) -> bool:
    """Does this flow end at a sink call written in the form the spec declares safe?

    Only sinks named in ``safe_shape_sinks`` are subject to the test -- ``os.system(x)`` is not safe merely
    because it takes one argument. A row that carries no shape fields (an engine that could not report arity)
    is judged on the flow alone: unknown shape must never be read as a safe one.
    """
    if not spec.safe_shape_sinks:
        return False
    sink = str(flow.get("sink", ""))
    if not any(name in sink for name in spec.safe_shape_sinks):
        return False
    arity = flow.get("sinkArity")
    literal = flow.get("sinkArg0Literal")
    if arity is None and literal is None:
        return False  # shape unknown -> judge on the flow, never assume safety
    bound = isinstance(arity, int | float) and int(arity) >= 2
    constant_format = literal is True
    return bound or constant_format


def _as_int(value: object) -> int:
    return int(value) if isinstance(value, int | float) else 0


def _in_scope(row: Mapping[str, object], function: str) -> bool:
    """Is this sink inside the labeled function, counting closures nested within it?

    JavaScript is callback-heavy, so the method containing a sink routinely is not the labeled function --
    `fs.readFileSync` inside the callback passed to `fs.stat` has enclosing method `<lambda>0`. The query
    decides containment by line range and reports it here; a row that carries no flag falls back to the name
    comparison, because an engine that cannot report scope must not have its sinks silently treated as scoped.
    """
    flag = row.get("inLabeledScope")
    if isinstance(flag, bool):
        return flag
    return str(row.get("sinkMethod", "")) == function


def _from_modelled_source(flow: Mapping[str, object], spec: TaintSpec) -> bool:
    """Does this flow start at something the source model names, rather than a bare captured parameter?"""
    source = str(flow["source"])
    return any(pattern in source for pattern in spec.sources)


def _rank(flow: Mapping[str, object], spec: TaintSpec) -> tuple[int, int, str, str]:
    """A flow from a modelled source first, then shortest, then lexicographic — a total order.

    Shortest alone picks the wrong witness once closures are in scope: a captured `res` reaches the sink in
    three steps while the actual `req.url -> ... -> possibleFilename` path takes eleven, and reporting the
    former names no attacker input at all. Naming a real source is what makes a witness evidence rather than
    an assertion, so it outranks brevity.
    """
    source = str(flow["source"])
    rank_modelled = 0 if _from_modelled_source(flow, spec) else 1
    return (rank_modelled, _as_int(flow["length"]), source, str(flow["sink"]))


def _witness(flow: Mapping[str, object]) -> str:
    line = flow.get("sinkLine") or "?"
    where = str(flow.get("sinkFile") or "")
    at = f" in {where}" if where else ""
    bound = str(flow.get("bound") or "")
    governed = f", governed by `{bound}`" if flow.get("bounded") and bound else ""
    return f"{flow['source']} -> {flow['sink']}{at} (line {line}, {flow['length']} steps{governed})"


def _location(flow: Mapping[str, object]) -> str:
    """``path:line:function`` of the SINK, when the engine reported a file. Empty leaves the region's own.

    All three parts come from the sink, not from the region that asked. A flow that crosses modules ends in
    a different file AND a different function, and naming the entry point beside the sink's line describes a
    place that does not exist -- `models/user_model.py:73:get_by_username`, where line 73 is inside
    `get_user`.
    """
    where = str(flow.get("sinkFile") or "")
    line = str(flow.get("sinkLine") or "")
    if not where or not line.lstrip("-").isdigit() or int(line) < 0:
        return ""
    return f"{where}:{line}:{flow.get('sinkMethod') or '?'}"


__all__ = ["request_params", "verdict"]
