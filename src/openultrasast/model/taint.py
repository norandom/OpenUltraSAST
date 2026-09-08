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


def verdict(cpg: CpgResult, spec: TaintSpec, *, function: str = "") -> Verdict | None:
    """The strongest verdict the taint query supports for ``spec`` in ``function``, or ``None`` to stay at suspicion."""
    rows = cpg.run(
        "taint",
        {"sources": spec.sources, "sinks": spec.sinks, "sanitizers": spec.sanitizers, "function": function},
    )
    flows = _flows(rows, function=function)
    if not flows:
        return None
    unsanitized = [flow for flow in flows if not flow["sanitized"]]
    # Deterministic by construction: sort, then take the first. Nothing here depends on engine ordering.
    chosen = min(unsanitized or flows, key=_rank)
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
        if function and str(row.get("sinkMethod", "")) != function:
            continue
        kept.append({
            "sink": str(row.get("sink", "")),
            "sinkLine": str(row.get("sinkLine", "")),
            "sinkMethod": str(row.get("sinkMethod", "")),
            "source": str(row.get("source", "")),
            "sanitized": bool(row.get("sanitized", False)),
            "length": _as_int(row.get("length")),
        })
    return kept


def _as_int(value: object) -> int:
    return int(value) if isinstance(value, int | float) else 0


def _rank(flow: Mapping[str, object]) -> tuple[int, str, str]:
    """Shortest flow first, then lexicographic — a total order, so two runs cannot disagree."""
    return (_as_int(flow["length"]), str(flow["source"]), str(flow["sink"]))


def _witness(flow: Mapping[str, object]) -> str:
    line = flow.get("sinkLine") or "?"
    return f"{flow['source']} -> {flow['sink']} (line {line}, {flow['length']} steps)"


__all__ = ["verdict"]
