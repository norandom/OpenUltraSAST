"""Guard dominance: the arbiter for the bugs that never crash (model-grounded-detection, Req 6.2).

An access-control bug is the *absence* of a guard. There is no flow to follow and no crash to reproduce, so
neither taint reachability nor an execution oracle reaches this class at all — which is precisely the gap
Clearwing's crash ladder leaves open and this project exists to close.

What the model *can* establish is a consistency violation: an obligated operation that no discharging guard
governs, in a file where its siblings are governed by one. That asymmetry is the evidence, and it is
deterministic — no model call, and the same verdict on every run over one CPG.

The rungs are deliberately asymmetric:

    ENTAILED      unguarded here, guarded on a sibling — the file contradicts itself, and the model can say so
    CORROBORATED  unguarded here, and no sibling is guarded either — the obligation is real but there is
                  nothing to be inconsistent *with*. A whole module may be unauthenticated by design, and
                  calling that entailed would assert a policy the model cannot see.
    (none)        guarded, or no obligated operation at all
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from ..cpg.backend import CpgResult
from .ladder import Rung, Verdict
from .specs import DominanceSpec


def request_params(spec: DominanceSpec, *, function: str = "", file: str = "") -> dict[str, object]:
    """The query parameters this arbiter sends. Shared with the batcher; see the note in `taint.request_params`.

    ``operationRequires`` and ``dischargersByKind`` carry the facts' own relation as JSON, so the engine can
    ask whether a guard discharges THIS obligation rather than whether it discharges anything. ``file`` scopes
    the rows: the sibling comparison is a claim about one file contradicting itself, and two functions of the
    same name in different modules were otherwise pooled into one region's answer.
    """
    return {
        "operations": spec.operations,
        "dischargers": spec.dischargers,
        "function": function,
        "file": file,
        "operationRequires": json.dumps({k: list(v) for k, v in spec.requirements.items()}, sort_keys=True) if spec.requirements else "",
        "dischargersByKind": json.dumps({k: list(v) for k, v in spec.dischargers_by_kind.items()}, sort_keys=True)
        if spec.dischargers_by_kind
        else "",
    }


def verdict(cpg: CpgResult, spec: DominanceSpec, *, function: str = "", file: str = "") -> Verdict | None:
    """The verdict for the obligated operation in ``function``, or ``None`` when there is nothing to say."""
    rows = cpg.run("dominance", request_params(spec, function=function, file=file))
    operations = _operations(rows)
    if not operations:
        return None

    here = [row for row in operations if not function or row["opMethod"] == function]
    if not here:
        return None
    unguarded = [row for row in here if not row["guards"]]
    if not unguarded:
        return None  # every operation in this function is governed; nothing to report

    # Siblings are the obligated operations *elsewhere* in the graph. Sorted so the witness is stable.
    siblings = sorted(
        (row for row in operations if row["opMethod"] not in {r["opMethod"] for r in here}),
        key=lambda row: (row["opMethod"], row["opLine"]),
    )
    # Count guarded sibling *methods*, not rows: one method can hold several obligated operations, and
    # naming it twice makes the witness read as more corroboration than the file actually contains.
    guarded_methods = sorted({str(row["opMethod"]) for row in siblings if row["guards"]})
    target = min(unguarded, key=lambda row: (row["opMethod"], row["opLine"]))

    if guarded_methods:
        witness = (
            f"{target['opMethod']} line {target['opLine']}: no discharging guard, "
            f"while {len(guarded_methods)} sibling handler(s) are guarded "
            f"({', '.join(guarded_methods[:3])})"
        )
        return Verdict(rung=Rung.ENTAILED, family=spec.family, witness=witness)

    witness = f"{target['opMethod']} line {target['opLine']}: obligated operation with no discharging guard, and no guarded sibling"
    return Verdict(rung=Rung.CORROBORATED, family=spec.family, witness=witness)


def _operations(rows: object) -> list[dict[str, object]]:
    """The query's rows. A non-list (an engine failure) yields nothing, never a false absence."""
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    kept: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        guards = row.get("dominatingGuards")
        kept.append(
            {
                "operation": str(row.get("operation", "")),
                "opLine": str(row.get("opLine", "")),
                "opMethod": str(row.get("opMethod", "")),
                "guards": [str(g) for g in guards] if isinstance(guards, Sequence) and not isinstance(guards, str) else [],
            }
        )
    return kept


__all__ = ["request_params", "verdict"]
