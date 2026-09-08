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


def verdict(cpg: CpgResult, spec: TaintSpec, *, function: str = "", parameter_sources: bool = False) -> Verdict | None:
    """The strongest verdict the taint query supports for ``spec`` in ``function``, or ``None`` to stay at suspicion.

    ``parameter_sources`` additionally treats the labeled function's own parameters as untrusted. That is right
    for a function-level pair, where the function boundary *is* the trust boundary, and wrong for a whole
    repository, where most parameters carry internal values — so it is off by default and the caller opts in.
    """
    rows = cpg.run(
        "taint",
        {
            "sources": spec.sources,
            "sinks": spec.sinks,
            "sanitizers": spec.sanitizers,
            "function": function,
            "parameterSources": "true" if parameter_sources else "false",
        },
    )
    flows = _flows(rows, function=function)
    # A sink whose *shape* is safe is the fix, not the bug. `execute(sql, params)` binds rather than
    # interpolates and `printf("literal", x)` has a constant format string, so the flow that reaches them is
    # not a vulnerability -- even though the taint path is identical to the vulnerable twin's. Dropping these
    # is what lets the model distinguish a pair at all: measured on the injection slice, taint reachability
    # alone entailed both sides of the canonical SQL pair and therefore arbitrated nothing.
    flows = [flow for flow in flows if not _has_safe_shape(flow, spec)]
    if not flows:
        return None
    # Parameter sources are a FALLBACK, never an override. When a modelled source reaches the sink, those
    # flows are the evidence: a captured `res` parameter also reaching it unsanitized must not report a fix as
    # still vulnerable on the strength of a flow that names no attacker input.
    modelled = [flow for flow in flows if _from_modelled_source(flow, spec)]
    considered = modelled or flows
    unsanitized = [flow for flow in considered if not flow["sanitized"]]
    # Deterministic by construction: a total order, then take the first. Nothing depends on engine ordering.
    chosen = min(unsanitized or considered, key=lambda flow: _rank(flow, spec))
    rung = Rung.ENTAILED if not chosen["sanitized"] else Rung.CORROBORATED
    return Verdict(rung=rung, family=spec.family, witness=_witness(chosen))


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
    return f"{flow['source']} -> {flow['sink']} (line {line}, {flow['length']} steps)"


__all__ = ["verdict"]
