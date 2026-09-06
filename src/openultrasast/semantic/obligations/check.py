"""The obligation checker (authorization-obligations, Req 3–6).

An obligated operation is reported when it is reached (a path record ends at it, or, without path records, its function is
an entry point) and none of the dischargers it accepts dominates it. The label says why the obligation exists: a declared
policy clause (``declared_policy_violation``), the practice of sibling handlers (``consistency_violation``), or, in the
degraded mode without path records, the operation fact alone (``function_local``). With path records and neither a clause
nor a sibling norm, nothing justifies the obligation and nothing is reported (design gating 3). Findings are ``suspicion``;
the obligation, the missing discharger, the evidence and the known fix travel as data.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ...findings import StaticFinding
from ..facts import SemanticFacts
from ..ir import FileIR
from .dominance import Dominance
from .facts import ObligationFacts
from .operations import Discharge, Operation, find_discharges, find_operations, valid_witness
from .policy import DeclaredPolicy
from .siblings import Anomaly, SiblingSet, consistency_anomalies, sibling_sets

LABELS = ("declared_policy_violation", "consistency_violation", "function_local")
_ROUTE_LITERAL = re.compile(r"@\w[\w.]*\.(?:route|get|post|put|delete|patch|api_route|websocket)\(\s*['\"]([^'\"]+)['\"]")


@dataclass(frozen=True)
class ObligationFinding:
    operation: Operation
    missing: str  # discharger kind
    provenance: str | None  # when a discharger of that kind exists but binds the wrong provenance
    label: str  # LABELS
    evidence: tuple[str, ...]  # sibling handler ids or the policy clause
    known_fix: str | None  # mechanism record id whose obligation shape matches
    sensitivity: str
    route: str | None = None
    intent: str | None = None  # hunter adjudication (task 3.3): public | protected | unknown
    intent_rationale: str | None = None


@dataclass(frozen=True)
class ObligationResult:
    findings: tuple[ObligationFinding, ...]
    discharges: tuple[Discharge, ...]
    sibling_sets: tuple[SiblingSet, ...]
    under_populated: tuple[tuple[str, str], ...] = ()
    operations: int = 0
    degradations: tuple[dict[str, object], ...] = field(default=())
    policy_version: str | None = None


def check_obligations(
    *,
    irs: Mapping[str, tuple[FileIR, str]],
    entries: Sequence[object],
    facts: ObligationFacts,
    flow_facts: SemanticFacts,
    policy: DeclaredPolicy | None,
    paths: Sequence[object],
    dominance: Dominance,
    store_shapes: Sequence[object],
    min_siblings: int,
    extra_witnesses: Sequence[Discharge] = (),
) -> ObligationResult:
    operations: list[Operation] = []
    witnesses: list[Discharge] = list(extra_witnesses)
    texts: dict[str, str] = {}
    degradations: list[dict[str, object]] = []
    unsupported: set[str] = set()
    for path, (ir, text) in irs.items():
        texts[path] = text
        if not ir.parse_ok:
            if ir.reason == "language_unsupported" and ir.language not in unsupported:
                unsupported.add(ir.language)
                degradations.append({"stage": "obligations", "reason": "obligations_language_unsupported", "language": ir.language})
            continue
        scoped = facts.for_language(ir.language)
        flow = flow_facts.for_language(ir.language)
        operations.extend(find_operations(ir, scoped, text=text))
        witnesses.extend(find_discharges(ir, scoped, flow, text=text, entries=entries))
    sets = sibling_sets(entries, operations, witnesses)
    anomalies, under = consistency_anomalies(sets, min_siblings=min_siblings)
    anomaly_index: dict[tuple[str, str], Anomaly] = {(a.handler, a.missing): a for a in anomalies}
    entry_handlers = {f"{getattr(e, 'path', '')}::{getattr(e, 'function_name', '')}" for e in entries}
    reached = _reached(operations, paths, entry_handlers)
    if not paths and operations:
        for language in sorted({irs[op.path][0].language for op in operations if op.path in irs}):
            degradations.append(
                {
                    "stage": "obligations",
                    "reason": "obligations_function_local",
                    "language": language,
                    "files": sorted({op.path for op in operations if op.path in irs and irs[op.path][0].language == language}),
                    "detail": "no path records; obligations evaluated within entry-point handlers only",
                }
            )
    findings: list[ObligationFinding] = []
    invalid_rows = tuple(sorted(str(getattr(row, "id", "")) for row in store_shapes if not _usable_shape(row)))
    if invalid_rows:
        degradations.append({"stage": "obligations", "reason": "obligations_store_row_invalid", "records": list(invalid_rows)})
    for operation, path_record in reached:
        handler = f"{operation.path}::{operation.function}"
        route = _route_path(operation, texts.get(operation.path, ""))
        declared_access = policy.route_access(route) if policy is not None and route else None
        same = [w for w in witnesses if _relevant(w, operation)]
        dominated_kinds = {w.kind for w in same if valid_witness(w) and dominance.dominates(w, operation, path_record)}
        # (a) the operation's own obligation: discharged when any accepted discharger dominates. A declared public route
        # waives the path guard here too (Req 4.4), so the operation falls through to the next kind it accepts.
        required = [kind for kind in operation.requires if not (kind == "path_guard" and declared_access == "public")]
        if required and not (set(required) & dominated_kinds):
            missing = next(
                (kind for kind in required if (handler, kind) in anomaly_index),
                required[0],
            )
            finding = _finding(
                operation, missing, same, anomaly_index.get((handler, missing)), policy, route, declared_access, store_shapes, paths, facts
            )
            if finding is not None:
                findings.append(finding)
        # (b) consistency anomalies on kinds the siblings practice beyond the operation's own requirement (a path guard, say)
        for kind in sorted({a.missing for (h, _), a in anomaly_index.items() if h == handler} - set(operation.requires)):
            if kind in dominated_kinds:
                continue
            if kind == "path_guard" and declared_access == "public":
                continue  # declared public: the guard obligation is waived, the identity one is not
            finding = _finding(
                operation, kind, same, anomaly_index[(handler, kind)], policy, route, declared_access, store_shapes, paths, facts
            )
            if finding is not None:
                findings.append(finding)
    return ObligationResult(
        findings=tuple(_dedupe(findings)),
        discharges=tuple(witnesses),
        sibling_sets=sets,
        under_populated=under,
        operations=len(operations),
        degradations=tuple(degradations),
        policy_version=policy.version_hash if policy is not None else None,
    )


def findings_to_static(result: ObligationResult) -> list[StaticFinding]:
    statics: list[StaticFinding] = []
    for finding in result.findings:
        op = finding.operation
        tags = [f"obligation:{op.kind}", f"discharger:{finding.missing}", f"obligation_evidence:{finding.label}"]
        if op.resource:
            tags.append(f"resource:{op.resource}")
        if finding.known_fix:
            tags.append(f"mechanism:{finding.known_fix}")
        why = "; ".join(finding.evidence) if finding.evidence else "the operation fact alone (function-local mode)"
        resource = op.resource or "a resource"
        provenance = f" (a {finding.missing} is present but bound from {finding.provenance})" if finding.provenance else ""
        statics.append(
            StaticFinding(
                finding_id=f"obligation:{op.kind}:{op.path}:{op.line}:{finding.missing}",
                path=op.path,
                title=f"Obligation not discharged: {op.kind} on {resource} without {finding.missing}",
                severity={"high": "high", "medium": "medium", "low": "low"}.get(finding.sensitivity, "medium"),
                confidence="low",
                evidence_level="suspicion",
                rationale=(
                    f"{op.kind} on {resource} in {op.function} is reached without a dominating {finding.missing}{provenance}. "
                    f"Why the obligation exists: {why}. Label: {finding.label}."
                    + (f" Known fix learned from the corpus: {finding.known_fix}." if finding.known_fix else "")
                ),
                line=op.line,
                function_name=op.function,
                reachability_status="unknown",
                reachability_evidence=[],
                reachability_conditions=[],
                tags=tags,
                ranking_priority=0.0,
            )
        )
    return statics


def _finding(
    operation: Operation,
    missing: str,
    same: Sequence[Discharge],
    anomaly: Anomaly | None,
    policy: DeclaredPolicy | None,
    route: str | None,
    declared_access: str | None,
    store_shapes: Sequence[object],
    paths: Sequence[object],
    facts: ObligationFacts,
) -> ObligationFinding | None:
    wrong = next((w for w in same if w.kind == missing and not valid_witness(w)), None)
    declared = policy.resources.get(operation.resource or "") if policy is not None else None
    # A declared clause covers the obligation it speaks about: a protected resource covers identity and ownership
    # dischargers; a route declared authenticated or role-restricted covers the path guard.
    resource_clause = declared is not None and missing in {"identity_constraint", "ownership_check"}
    route_clause = missing == "path_guard" and declared_access in {"authenticated", "role"}
    if resource_clause and declared is not None:
        label = "declared_policy_violation"
        clause = f"resource {declared.name} declared sensitivity {declared.sensitivity}"
        if declared.identity_field:
            clause += f", identity field {declared.identity_field}"
        evidence: tuple[str, ...] = (clause,)
        if anomaly is not None:
            evidence = evidence + anomaly.siblings
    elif route_clause:
        label = "declared_policy_violation"
        evidence = (f"route {route} declared {declared_access}",) + (anomaly.siblings if anomaly is not None else ())
    elif anomaly is not None:
        label = "consistency_violation"
        evidence = anomaly.siblings + anomaly.evidence[len(anomaly.siblings) :]
    elif paths:
        return None  # path-aware mode: without a clause or a sibling norm, nothing justifies the obligation (gating 3)
    else:
        label = "function_local"  # degraded mode: the operation fact alone, recorded as a degradation
        evidence = ()
    sensitivity = (declared.sensitivity if declared is not None else None) or _fact_sensitivity(operation, facts)
    return ObligationFinding(
        operation=operation,
        missing=missing,
        provenance=wrong.provenance if wrong is not None else None,
        label=label,
        evidence=evidence,
        known_fix=_known_fix(operation, missing, store_shapes),
        sensitivity=sensitivity,
        route=route,
    )


def _reached(operations: Sequence[Operation], paths: Sequence[object], entry_handlers: set[str]) -> list[tuple[Operation, object | None]]:
    if not paths:
        return [(op, None) for op in operations if f"{op.path}::{op.function}" in entry_handlers]
    reached: list[tuple[Operation, object | None]] = []
    for op in operations:
        for record in paths:
            hops = getattr(record, "hops", None) or ()
            if not hops:
                continue
            last = hops[-1][0] if isinstance(hops[-1], (tuple, list)) else str(hops[-1])
            if str(last) == f"{op.path}::{op.function}":
                reached.append((op, record))
                break
    return reached


def _relevant(witness: Discharge, operation: Operation) -> bool:
    return witness.scope == "hop" or (witness.path, witness.function) == (operation.path, operation.function)


def _usable_shape(record: object) -> bool:
    """A store row is usable when its shape dict names both an operation kind and a discharger kind."""
    shape = getattr(record, "shape", None)
    return isinstance(shape, dict) and bool(shape.get("operation_kind")) and bool(shape.get("discharger_kind"))


def _known_fix(operation: Operation, missing: str, store_shapes: Sequence[object]) -> str | None:
    for record in store_shapes:
        if not _usable_shape(record):
            continue
        shape = getattr(record, "shape", None) or {}
        if isinstance(shape, dict) and shape.get("operation_kind") == operation.kind and shape.get("discharger_kind") == missing:
            return str(getattr(record, "id", "")) or None
    return None


def _fact_sensitivity(operation: Operation, facts: ObligationFacts) -> str:
    for fact in facts.operations:
        if fact.id == operation.fact_id:
            return fact.sensitivity
    return "medium"


def _route_path(operation: Operation, text: str) -> str | None:
    lines = text.splitlines()
    index = _def_index(lines, operation.function)
    if index is None:
        return None
    cursor = index - 1
    while cursor >= 0 and lines[cursor].strip().startswith("@"):
        match = _ROUTE_LITERAL.search(lines[cursor].strip())
        if match:
            return match.group(1)
        cursor -= 1
    return None


def _def_index(lines: Sequence[str], function: str) -> int | None:
    pattern = re.compile(rf"^\s*(?:async\s+)?(?:def|function)\s+{re.escape(function)}\b")
    for index, line in enumerate(lines):
        if pattern.match(line):
            return index
    return None


def _dedupe(findings: Sequence[ObligationFinding]) -> list[ObligationFinding]:
    seen: set[tuple[str, int, str, str]] = set()
    out: list[ObligationFinding] = []
    for finding in findings:
        key = (finding.operation.path, finding.operation.line, finding.operation.kind, finding.missing)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out


__all__ = ["LABELS", "ObligationFinding", "ObligationResult", "check_obligations", "findings_to_static"]
