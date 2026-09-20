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
        # The calls whose obligation depends on the argument's shape rather than on the name alone.
        "documentShape": ",".join(spec.document_shape),
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

    where = _where(target)
    # A carried obligation does not ENTAIL, however clean the asymmetry looks.
    #
    # The rung's justification is that one FILE contradicts itself: same file, same trust context, so an
    # unguarded operation beside a guarded one is evidence. Once the obligation is carried across a module
    # boundary, the operations being compared live in a data-access module that handlers of DIFFERENT trust
    # contexts share, and a route file mixing public with authenticated handlers is the normal shape -- so the
    # asymmetry stops implying inconsistency.
    #
    # Measured on NodeGoat, where this was not hypothetical: `handleSignup` looks a user up by name to check
    # the name is free, which is public by design, and two authenticated siblings in the same file pass
    # `req.session.userId` into the same module. The asymmetry is real and the defect is not. That question --
    # does this operation require a check, or is the route legitimately public? -- is exactly what the
    # corroborated band's residual asks, so a carried row is capped there and the judge decides it.
    if guarded_methods and not target.get("viaLine"):
        witness = (
            f"{where}: no discharging guard, while {len(guarded_methods)} sibling handler(s) are guarded ({', '.join(guarded_methods[:3])})"
        )
        return Verdict(rung=Rung.ENTAILED, family=spec.family, witness=witness, location=_location(target))

    if guarded_methods:
        witness = (
            f"{where}: no discharging guard, while {len(guarded_methods)} sibling handler(s) reaching the same "
            f"module are guarded ({', '.join(guarded_methods[:3])}); the obligation was carried across a module "
            f"boundary, so those siblings need not share this route's trust context"
        )
        return Verdict(rung=Rung.CORROBORATED, family=spec.family, witness=witness, location=_location(target))

    witness = f"{where}: obligated operation with no discharging guard, and no guarded sibling"
    return Verdict(rung=Rung.CORROBORATED, family=spec.family, witness=witness, location=_location(target))


def _where(row: Mapping[str, object]) -> str:
    """The sites a reader has to open. Two of them when the obligation crossed a module boundary.

    An application that puts its route in one file and its query in another raised no obligation at all until
    the query followed the call, and a witness that named only the operation would send a contributor to a
    data-access module that is not where the decision was made. Naming only the handler would hide what the
    claim is about. So a carried row names both, in the order a reader needs them.
    """
    method = str(row["opMethod"])
    via_line = str(row.get("viaLine") or "")
    if not via_line:
        return f"{method} line {row['opLine']}"
    call = str(row.get("viaCall") or "").strip()
    return f"{method} line {via_line} calls {call}, whose operation at {row.get('opFile')}:{row['opLine']}"


def _location(row: Mapping[str, object]) -> str:
    """``path:line:function`` of the obligated operation, when the engine reported a file.

    Taint and config verdicts have always carried this; dominance did not, so every access-control finding
    reached a contributor as `api_views/users.py:?:update_password` -- the right file by accident, because
    the region was asked about that file, and no line at all.
    """
    # A carried obligation is located at the CALL, not at the operation: that is the line the contributor
    # changed and the line an admission decision has to be attributable to. The operation's own site travels
    # in the witness.
    carried_line = str(row.get("viaLine") or "")
    if carried_line.lstrip("-").isdigit() and int(carried_line) >= 0 and row.get("viaFile"):
        return f"{row['viaFile']}:{carried_line}:{row.get('opMethod') or '?'}"
    where = str(row.get("opFile") or "")
    line = str(row.get("opLine") or "")
    if not where or not line.lstrip("-").isdigit() or int(line) < 0:
        return ""
    return f"{where}:{line}:{row.get('opMethod') or '?'}"


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
                "opFile": str(row.get("opFile", "")),
                "viaCall": str(row.get("viaCall", "")),
                "viaLine": str(row.get("viaLine", "")),
                "viaFile": str(row.get("viaFile", "")),
                "guards": [str(g) for g in guards] if isinstance(guards, Sequence) and not isinstance(guards, str) else [],
            }
        )
    return kept


__all__ = ["request_params", "verdict"]
