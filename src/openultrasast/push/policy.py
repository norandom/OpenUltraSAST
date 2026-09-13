"""Compare immutable revision evidence and apply evaluated capability admission."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from string import Formatter
from typing import Any, Literal

from openultrasast.config import PushConfig
from openultrasast.contracts import Contract
from openultrasast.cpg.backend import CpgResult
from openultrasast.model.contracts import ChangeContext, ExecutionBudget, QuestionIdentity
from openultrasast.model.ladder import Rung
from openultrasast.model.pipeline import ModelFinding, _arbitrate_all
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ModelScanResult, ScanBudget, _prefetched, _spec_for, scan_repository
from openultrasast.model.specs import ConfigSpec, DominanceSpec, TaintSpec
from openultrasast.push.cache import ArtifactCache, SemanticKeys
from openultrasast.push.contracts import ComparisonAnalysis, PushComparison, PushResult


@dataclass(frozen=True)
class EvidenceOperation(Contract):
    question: QuestionIdentity
    mechanism: Literal["taint", "dominance", "config"]
    path: str
    line: int
    operation: str
    source: str
    discharged: bool
    detail: str


@dataclass(frozen=True)
class CandidateDelta(Contract):
    family: str
    site: str
    rung: str
    witness: str | None
    defect_id: str
    novelty: Literal["new", "worsened", "unchanged", "unknown"]
    reason: str
    head_operation: EvidenceOperation | None
    base_operations: tuple[EvidenceOperation, ...]
    change_evidence: tuple[str, ...]
    base_revision: str | None = None
    head_revision: str | None = None
    semantics: str | None = None


@dataclass(frozen=True)
class DeltaComparison:
    candidates: tuple[CandidateDelta, ...]
    base_scan: ModelScanResult | None
    semantics: str
    coverage_reasons: tuple[str, ...]


def semantics_digest(*, engine_identity: str, options: dict[str, object]) -> str:
    """Fingerprint shipped semantics plus caller-owned engine/options provenance.

    Include frontend adaptation, declaration/exclusion policy and scan options in options.
    This is an identity, never evidence of engine liveness or input readability.
    """
    root = Path(__file__).resolve().parents[1]
    files = sorted([*(root / "cpg" / "queries").glob("*.sc"), *(root / "ruleset").rglob("*.toml"), *(root / "model").glob("*.py")])
    payload = {
        "engine": engine_identity,
        "options": options,
        "files": [(str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest()) for p in files],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _operations(scan: ModelScanResult, budget: ExecutionBudget | None = None) -> tuple[EvidenceOperation, ...]:
    result = []
    for answer in scan.question_outcomes:
        if budget is not None and time.monotonic() >= budget.deadline_monotonic:
            break
        if answer.status != "completed" or answer.raw_rows_json is None:
            continue
        spec = _spec_for(answer.identity.family, answer.identity.language)
        expected = (
            "taint"
            if isinstance(spec, TaintSpec)
            else "dominance"
            if isinstance(spec, DominanceSpec)
            else "config"
            if isinstance(spec, ConfigSpec)
            else None
        )
        for row in json.loads(answer.raw_rows_json):
            if budget is not None and time.monotonic() >= budget.deadline_monotonic:
                break
            kind: Literal["taint", "dominance", "config"]
            if not isinstance(row, dict):
                continue
            if "sink" in row:
                kind, path, line, op = "taint", row.get("sinkFile"), row.get("sinkLine"), row.get("sink")
                if not isinstance(row.get("source"), str) or not row["source"].strip():
                    continue
                if type(row.get("sanitized")) is not bool or type(row.get("bounded")) is not bool:
                    continue
                source = json.dumps([row.get("sourceKind", "unknown"), row.get("source")], separators=(",", ":"))
                discharged = row["sanitized"] or row["bounded"]
            elif "operation" in row:
                kind, path, line, op = "dominance", row.get("opFile"), row.get("opLine"), row.get("operation")
                source = "obligation"
                if not isinstance(row.get("dominatingGuards"), list) or not all(isinstance(g, str) for g in row["dominatingGuards"]):
                    continue
                discharged = bool(row["dominatingGuards"])
            elif "setting" in row:
                kind, path, line, op = "config", row.get("file"), row.get("line"), row.get("setting")
                source = "configuration"
                discharged = False
            else:
                continue
            if (
                kind != expected
                or not isinstance(path, str)
                or not path
                or not isinstance(op, str)
                or not op.strip()
                or not str(line).isdigit()
                or int(str(line)) < 1
            ):
                continue
            result.append(
                EvidenceOperation(answer.identity, kind, path, int(str(line)), str(op), source, discharged, json.dumps(row, sort_keys=True))
            )
    return tuple(result)


def _base_location(op: EvidenceOperation, context: ChangeContext) -> tuple[str, int] | None:
    matches = []
    for anchor in context.line_correspondences:
        size = anchor.base_end_line - anchor.base_start_line
        if context.decode_path(anchor.head_path) == op.path and anchor.head_start_line <= op.line <= anchor.head_start_line + size:
            matches.append((context.decode_path(anchor.base_path), anchor.base_start_line + op.line - anchor.head_start_line))
    if matches:
        return matches[0] if len(set(matches)) == 1 else None
    changed = {context.decode_path(p) for p in context.changed_paths}
    if op.path not in changed:
        return op.path, op.line
    return None


def _change_evidence(op: EvidenceOperation, context: ChangeContext) -> tuple[str, ...]:
    paths = {op.path, op.question.path}
    for relation in context.relationships:
        if relation.target == op.question and relation.evidence:
            paths.add(relation.source.path)
    paths.update(context.decode_path(r.base_path) for r in context.renames if context.decode_path(r.head_path) in paths)
    return tuple(
        f"{span.side}:{context.decode_path(span.path)}:{span.start_line}-{span.end_line}"
        for span in context.spans
        if context.decode_path(span.path) in paths
    )


def _candidate(
    finding: ModelFinding,
    op: EvidenceOperation | None,
    bases: tuple[EvidenceOperation, ...],
    novelty: Literal["new", "worsened", "unchanged", "unknown"],
    reason: str,
    change: tuple[str, ...],
    context: ChangeContext,
) -> CandidateDelta:
    location = _base_location(op, context) if op else None
    identity = [
        finding.family,
        op.mechanism if op else "unknown",
        location or ((op.path, op.line) if op else finding.site),
        op.operation if op else finding.site,
        op.source if op else "unknown",
        op.question.function if op else None,
    ]
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return CandidateDelta(
        finding.family, finding.site, finding.rung.value, finding.witness or None, key, novelty, reason, op, bases, change
    )


def _valid_answer(scan: ModelScanResult, question: QuestionIdentity, operations: tuple[EvidenceOperation, ...]) -> bool:
    answer = next((q for q in scan.question_outcomes if q.identity == question), None)
    if answer is None or answer.raw_rows_json is None:
        return False
    rows = json.loads(answer.raw_rows_json)
    # Query bodies are operation rows. An unrecognized/malformed row is not an empty answer.
    return len(rows) == sum(op.question == question for op in operations)


def _context_boundaries(scan: ModelScanResult, question: QuestionIdentity | None = None) -> tuple[str, ...]:
    # Aggregate coverage keeps every gap. A candidate may ignore only a recognized
    # question-owned boundary attached to a different, recorded question. Unknown
    # ownership and graph/declaration gaps remain global.
    if scan.scope is None:
        return ("scope_missing",)
    owned_prefixes = (
        "context_projection_unavailable:contributor-scan:",
        "context_scope_empty:contributor-scan:",
        "dynamic_external_or_depth_context_unresolved:contributor-scan:",
    )
    others = {q.identity.question_id for q in scan.scope.selected if q.identity != question}
    others.update(q.identity.question_id for q in scan.scope.deferred if q.identity != question)
    return tuple(
        boundary
        for boundary in scan.scope.unresolved_boundaries
        if not boundary.startswith("evidence_unknown:")
        and not (question is not None and boundary.startswith(owned_prefixes) and boundary.rsplit(":", 1)[-1] in others)
    )


def _counterpart(question: QuestionIdentity, context: ChangeContext) -> QuestionIdentity:
    renamed = {context.decode_path(r.head_path): context.decode_path(r.base_path) for r in context.renames}
    return replace(question, path=renamed.get(question.path, question.path))


def _proven_finding(finding: ModelFinding, op: EvidenceOperation, head: ModelScanResult) -> bool:
    """Match the existing arbiter's exact witness, not just a coincident line number."""
    answer = next((q for q in head.question_outcomes if q.identity == op.question), None)
    spec = _spec_for(op.question.family, op.question.language)
    if answer is None or answer.raw_rows_json is None or spec is None:
        return False
    rows = json.loads(answer.raw_rows_json)
    verdicts = _arbitrate_all(
        CpgResult(Path("prefetched"), _prefetched(rows)),
        spec,
        path=op.question.path,
        function=op.question.function or "",
        parameter_sources=False,
        call_depth=0,
    )
    return any(v.witness == finding.witness and v.rung == finding.rung for v in verdicts)


def compare_evidence(
    head: ModelScanResult,
    base: ModelScanResult | None,
    *,
    context: ChangeContext,
    head_semantics: str,
    base_semantics: str,
    execution_budget: ExecutionBudget | None = None,
    cache: ArtifactCache | None = None,
    cache_semantics: SemanticKeys | None = None,
) -> tuple[CandidateDelta, ...]:
    """Reuse completed comparison evidence; alert eligibility is always applied later."""

    def complete(scan: ModelScanResult | None) -> bool:
        return bool(
            scan
            and scan.scope
            and scan.scope.population_complete
            and not scan.degradations
            and not scan.scope.unresolved_boundaries
            and all(item.reason == "tier_zero" for item in scan.scope.deferred)
            and all(item.status == "completed" for item in scan.question_outcomes)
            and {item.identity for item in scan.scope.selected} == {item.identity for item in scan.question_outcomes}
        )

    key = None
    if (
        cache is not None
        and cache_semantics is not None
        and execution_budget is not None
        and time.monotonic() < execution_budget.deadline_monotonic
        and context.base_revision is not None
        and not context.unresolved_boundaries
        and head_semantics == base_semantics
        and complete(head)
        and complete(base)
    ):
        from openultrasast.cpg.artifact import read_bytes

        def evidence(scan: ModelScanResult) -> dict[str, object]:
            return {
                name: value
                for name, value in asdict(scan).items()
                if name not in {"seconds", "build_seconds", "query_seconds", "query_seconds_by_kind"}
            }

        assert base is not None
        try:
            key = cache_semantics.comparison(
                base=context.base_revision,
                head=context.head_revision,
                context=context.to_payload(),
                evidence={
                    "head": evidence(head),
                    "base": evidence(base),
                    "semantics": head_semantics,
                    "policy": hashlib.sha256(read_bytes(Path(__file__), execution_budget.deadline_monotonic)).hexdigest(),
                },
            )
            raw = cache.get_json(key, kind="comparison", budget=execution_budget)
            if isinstance(raw, list):
                decoded = tuple(CandidateDelta.from_payload(item) for item in raw)
                if time.monotonic() < execution_budget.deadline_monotonic and all(
                    item.novelty != "unknown"
                    and item.base_revision == context.base_revision
                    and item.head_revision == context.head_revision
                    and item.semantics == head_semantics
                    for item in decoded
                ):
                    return decoded
        except (OSError, ValueError, TimeoutError):
            key = None
    result = _compare_evidence(
        head, base, context=context, head_semantics=head_semantics, base_semantics=base_semantics, execution_budget=execution_budget
    )
    if key is not None and cache is not None and execution_budget is not None:
        cache.put_json(
            key,
            [item.to_payload() for item in result],
            kind="comparison",
            budget=execution_budget,
            complete=all(item.novelty != "unknown" for item in result),
        )
    return result


def _compare_evidence(
    head: ModelScanResult,
    base: ModelScanResult | None,
    *,
    context: ChangeContext,
    head_semantics: str,
    base_semantics: str,
    execution_budget: ExecutionBudget | None = None,
) -> tuple[CandidateDelta, ...]:
    """Absence counts only in completed comparable scope, never from scan silence."""
    head_ops, base_ops = _operations(head, execution_budget), _operations(base, execution_budget) if base else ()
    results = []
    for finding in head.findings:
        if execution_budget is not None and time.monotonic() >= execution_budget.deadline_monotonic:
            results.append(_candidate(finding, None, (), "unknown", "deadline_exhausted", (), context))
            continue
        matching = [
            op
            for op in head_ops
            if op.question.family == finding.family
            and finding.site.startswith(f"{op.path}:{op.line}:")
            and _proven_finding(finding, op, head)
        ]
        if len(matching) > 1:
            matching = [
                op
                for op in matching
                if op.mechanism != "taint" or finding.witness.startswith(str(json.loads(op.detail).get("source")) + " -> ")
            ]
        op = matching[0] if len(matching) == 1 else None
        novelty: Literal["new", "worsened", "unchanged", "unknown"] = "unknown"
        reason = "witness_identity_unresolved"
        old: tuple[EvidenceOperation, ...] = ()
        change: tuple[str, ...] = ()
        if op is not None:
            location = _base_location(op, context)
            counterpart = _counterpart(op.question, context)
            contextual = tuple(b for b in base_ops if b.question == counterpart and b.mechanism == op.mechanism)
            old = tuple(b for b in contextual if (b.path, b.line) == location and b.operation == op.operation)
            change = _change_evidence(op, context)
            reason = "base_incomplete"
            complete = bool(
                base
                and base.scope
                and base.scope.population_complete
                and all(question.reason == "tier_zero" for question in base.scope.deferred)
                and not _context_boundaries(base)
                and not base.degradations
                and _valid_answer(base, counterpart, base_ops)
                and counterpart in {q.identity for q in base.scope.selected}
                and counterpart in {q.identity for q in base.question_outcomes if q.status == "completed"}
                and {q.identity for q in base.scope.selected} == {q.identity for q in base.question_outcomes}
                and all(q.status == "completed" for q in base.question_outcomes)
            )
            if head_semantics != base_semantics:
                reason = "semantics_mismatch"
            elif context.base_revision is None:
                reason = "base_unavailable"
            elif context.unresolved_boundaries:
                reason = "change_context_unresolved"
            elif (
                not head.scope
                or _context_boundaries(head, op.question)
                or head.degradations
                or not _valid_answer(head, op.question, head_ops)
                or op.question not in {q.identity for q in head.scope.selected}
            ):
                reason = "head_context_incomplete"
            elif execution_budget is not None and time.monotonic() >= execution_budget.deadline_monotonic:
                reason = "deadline_exhausted"
            elif complete:
                same = tuple(b for b in old if b.source == op.source)
                reason = "operation_correspondence_unresolved"
                if any(
                    b.discharged == op.discharged
                    and (op.mechanism != "config" or json.loads(b.detail).get("literalArgs") == json.loads(op.detail).get("literalArgs"))
                    for b in same
                ):
                    novelty, reason = "unchanged", "same_supported_mechanism"
                elif old and change and finding.rung == Rung.ENTAILED and not op.discharged:
                    if same and all(b.discharged for b in same):
                        novelty, reason = "worsened", "discharge_removed"
                    elif not same and op.mechanism == "taint":
                        reason = "source_correspondence_unresolved"
                elif (
                    location is not None
                    and not old
                    and change
                    and op.mechanism == "taint"
                    and finding.rung == Rung.ENTAILED
                    and not op.discharged
                ):
                    novelty, reason = "new", "source_connection_absent_from_comparable_base"
        results.append(_candidate(finding, op, old, novelty, reason, change, context))
    return tuple(
        replace(
            candidate,
            base_revision=context.base_revision,
            head_revision=context.head_revision,
            semantics=head_semantics if head_semantics == base_semantics else None,
        )
        for candidate in results
    )


def compare_targeted_base(
    base_root: Path,
    *,
    head: ModelScanResult,
    head_regions: Sequence[ScanRegion],
    base_regions: Sequence[ScanRegion],
    context: ChangeContext,
    backend: Any,
    execution_budget: ExecutionBudget,
    scan_budget: ScanBudget,
    head_semantics: str,
    base_semantics: str,
    cache: ArtifactCache | None = None,
    cache_semantics: SemanticKeys | None = None,
) -> DeltaComparison:
    """Re-run counterparts of the ranker's selected head questions through the existing driver.

    The caller supplies immutable base regions, not a different selector. Unknown function
    correspondence is left unknown rather than widening to every function in the file.
    """
    selected = {q.identity for q in head.scope.selected} if head.scope else set()
    renames = {context.decode_path(r.head_path): context.decode_path(r.base_path) for r in context.renames}
    wanted = {(renames.get(q.path, q.path), q.function, q.family) for q in selected}
    targets = tuple(
        replace(r, families=tuple(f for f in r.families if (r.path, r.function, f) in wanted))
        for r in base_regions
        if any((r.path, r.function, family) in wanted for family in r.families)
    )
    # Preserve source/entry-point contracts and family depth; mismatches are not comparable.
    source_contract = {(renames.get(r.path, r.path), r.function): r.source for r in head_regions}
    compatible = all(source_contract.get((r.path, r.function)) == r.source for r in targets)
    reasons = []
    base = None
    if context.base_revision is None:
        reasons.append("base_unavailable")
    elif head_semantics != base_semantics or not compatible:
        reasons.append("semantics_mismatch")
    elif time.monotonic() >= execution_budget.deadline_monotonic:
        reasons.append("deadline_exhausted")
    elif not targets:
        reasons.append("base_counterpart_unresolved")
    else:
        try:
            base = scan_repository(
                base_root,
                targets,
                backend=backend,
                budget=scan_budget,
                execution_budget=execution_budget,
                ranking_mode=head.scope.ranking_mode if head.scope else "static",
                unit=next(iter(selected)).unit,
                population_complete=True,
            )
        except Exception as error:  # noqa: BLE001 -- comparison failure is coverage, not a new defect
            reasons.append(f"base_scan_failed:{type(error).__name__}")
    candidates = compare_evidence(
        head,
        base,
        context=context,
        head_semantics=head_semantics,
        base_semantics=base_semantics,
        execution_budget=execution_budget,
        cache=cache,
        cache_semantics=cache_semantics,
    )
    reasons.extend(c.reason for c in candidates if c.novelty == "unknown")
    return DeltaComparison(candidates, base, head_semantics, tuple(dict.fromkeys(reasons)))


@dataclass(frozen=True)
class CapabilityKey(Contract):
    language: str
    runtime: str
    framework: str
    family: str
    mechanism: Literal["taint", "dominance", "config"]
    context: str
    semantics: str


@dataclass(frozen=True)
class CapabilityAdmission(Contract):
    """Evaluated declaration supplied by the eligibility loader (task 8.3).

    This contract is not an evaluator or a signature verifier. No shipped declaration
    is enabled; synthetic policy tests cannot qualify a real capability.
    Templates belong to the evaluated declaration, never to model-generated prose.
    """

    key: CapabilityKey
    evaluation_id: str
    evaluation_artifact: str
    verdict: Literal["PASS", "NO-GO", "experimental"]
    consequence_template: str
    repair_template: str
    enabled: bool = False
    positive_controls: int = 0
    reviewed_alerts: int = 0
    calibration_artifact: str | None = None
    untouched_workload: str | None = None
    # Exact operation symbols covered by this evaluated semantic context. Receiver
    # spelling is preserved; unresolved/dynamic forms do not acquire eligibility.
    operation_symbols: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdmissionCandidate(Contract):
    delta: CandidateDelta
    capability: CapabilityKey
    comparison: PushComparison
    dependency_gaps: tuple[str, ...] = ()
    # Semantic contexts of sanitizer facts used in interpreting this witness. A
    # name alone is not evidence that an HTML escape discharges a SQL obligation.
    sanitizer_contexts: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateDisposition(Contract):
    candidate: AdmissionCandidate
    admitted: bool
    reasons: tuple[str, ...]
    evaluation_id: str | None
    capability_evaluations: tuple[CapabilityAdmission, ...]


@dataclass(frozen=True)
class ActionableDefect(Contract):
    defect_id: str
    family: str
    witnesses: tuple[str, ...]
    locations: tuple[tuple[str, int], ...]
    comparisons: tuple[PushComparison, ...]
    refs: tuple[str, ...]
    change_evidence: tuple[str, ...]
    consequences: tuple[str, ...]
    repairs: tuple[str, ...]
    evaluation_ids: tuple[str, ...]


@dataclass(frozen=True)
class AdmissionResult(Contract):
    defects: tuple[ActionableDefect, ...]
    dispositions: tuple[CandidateDisposition, ...]
    coverage_reasons: tuple[str, ...]


def _grounded_template(template: str, operation: EvidenceOperation, context: str) -> str | None:
    try:
        parts = tuple(Formatter().parse(template))
        if {field for _, field, _, _ in parts if field is not None} != {"operation", "context"}:
            return None
        if any(spec or conversion for _, _, spec, conversion in parts):
            return None
        return template.format(operation=operation.operation, context=context)
    except (ValueError, KeyError, IndexError):
        return None


def admit_candidates(candidates: Sequence[AdmissionCandidate], *, capabilities: Sequence[CapabilityAdmission] = ()) -> AdmissionResult:
    """Apply one origin-agnostic evidence bar for both advisory and blocking.

    Capabilities are trusted evaluated declarations, not user/model assertions.
    Task 8.3 owns their generation/loading; the default registry is deliberately empty.
    Unknown legacy delta provenance cannot acquire eligibility by being wrapped here.
    """
    defects: dict[str, ActionableDefect] = {}
    dispositions = []
    gaps: list[str] = []
    for candidate in candidates:
        delta, key, op = candidate.delta, candidate.capability, candidate.delta.head_operation
        reasons = []
        matching = [cap for cap in capabilities if cap.key == key]
        cap = matching[0] if len(matching) == 1 else None
        if not matching:
            reasons.append("capability_unavailable")
        elif len(matching) > 1:
            reasons.append("capability_ambiguous")
        elif cap is not None:
            if not cap.enabled:
                reasons.append("capability_disabled")
            if (
                cap.verdict != "PASS"
                or cap.positive_controls < 1
                or cap.reviewed_alerts < 1
                or cap.calibration_artifact is None
                or cap.untouched_workload is None
            ):
                reasons.append("capability_unevaluated")
        if (
            delta.base_revision is None
            or delta.head_revision is None
            or delta.semantics is None
            or delta.base_revision != candidate.comparison.base_oid
            or delta.head_revision != candidate.comparison.head_oid
            or delta.semantics != key.semantics
        ):
            reasons.append("comparison_provenance_mismatch")
        if delta.rung != Rung.ENTAILED.value:
            # No production execution-confirmed producer exists. Do not accept a label
            # in anticipation of one; a future producer needs an explicit protocol.
            reasons.append("insufficient_rung")
        if delta.novelty == "unknown":
            reasons.append("comparison_unknown")
        elif delta.novelty == "unchanged":
            reasons.append("unchanged")
        elif not delta.change_evidence or (delta.novelty, delta.reason) not in (
            ("new", "source_connection_absent_from_comparable_base"),
            ("worsened", "discharge_removed"),
        ):
            reasons.append("change_unsupported")
        if op is None or delta.witness is None:
            reasons.append("witness_unresolved")
        consequence = repair = None
        if op is not None:
            path = PurePosixPath(op.path)
            if op.line < 1 or path.is_absolute() or ".." in path.parts or not delta.site.startswith(f"{op.path}:{op.line}:"):
                reasons.append("location_unresolved")
            if (op.question.language, op.question.family, op.mechanism) != (
                key.language,
                key.family,
                key.mechanism,
            ) or delta.family != key.family:
                reasons.append("family_semantics_mismatch")
            if op.discharged:
                reasons.append("claim_discharged")
            if cap is not None:
                # These are existing graph operation spellings, not source scanning.
                # A declaration may narrow an entailed claim; it cannot create one.
                symbol = op.operation.partition("(")[0].strip()
                if symbol not in cap.operation_symbols:
                    reasons.append("operation_semantics_mismatch")
                consequence = _grounded_template(cap.consequence_template, op, key.context)
                repair = _grounded_template(cap.repair_template, op, key.context)
                if consequence is None:
                    reasons.append("consequence_unsupported")
                if repair is None:
                    reasons.append("repair_unsupported")
        if candidate.dependency_gaps:
            reasons.append("dependency_unresolved")
        if any(context != key.context for context in candidate.sanitizer_contexts):
            reasons.append("sanitizer_semantics_mismatch")
        previous = defects.get(delta.defect_id)
        if previous is not None and previous.family != delta.family:
            reasons.append("defect_identity_collision")
        dispositions.append(
            CandidateDisposition(candidate, not reasons, tuple(reasons), cap.evaluation_id if cap else None, tuple(matching))
        )
        gaps.extend(reason for reason in reasons if reason not in ("unchanged", "insufficient_rung", "claim_discharged"))
        if reasons:
            continue
        assert op is not None and delta.witness is not None and consequence is not None and repair is not None and cap is not None
        repair = f"{op.path}:{op.line}: {repair}"
        if previous is None:
            defects[delta.defect_id] = ActionableDefect(
                delta.defect_id,
                delta.family,
                (delta.witness,),
                ((op.path, op.line),),
                (candidate.comparison,),
                candidate.comparison.refs,
                delta.change_evidence,
                (consequence,),
                (repair,),
                (cap.evaluation_id,),
            )
        else:
            defects[delta.defect_id] = replace(
                previous,
                witnesses=tuple(dict.fromkeys((*previous.witnesses, delta.witness))),
                locations=tuple(dict.fromkeys((*previous.locations, (op.path, op.line)))),
                comparisons=tuple(dict.fromkeys((*previous.comparisons, candidate.comparison))),
                refs=tuple(dict.fromkeys((*previous.refs, *candidate.comparison.refs))),
                change_evidence=tuple(dict.fromkeys((*previous.change_evidence, *delta.change_evidence))),
                consequences=tuple(dict.fromkeys((*previous.consequences, consequence))),
                repairs=tuple(dict.fromkeys((*previous.repairs, repair))),
                evaluation_ids=tuple(dict.fromkeys((*previous.evaluation_ids, cap.evaluation_id))),
            )
    return AdmissionResult(tuple(defects.values()), tuple(dispositions), tuple(dict.fromkeys(gaps)))


def admission_push_result(
    admission: AdmissionResult, analyses: tuple[ComparisonAnalysis, ...], *, config: PushConfig | None = None
) -> PushResult:
    """Finding admission and coverage remain independent of push enforcement."""
    config = config or PushConfig()
    comparisons = {analysis.comparison for analysis in analyses}
    if any(comparison not in comparisons for defect in admission.defects for comparison in defect.comparisons):
        raise ValueError("admitted defect requires its exact comparison analysis")
    coverage: Literal["complete_within_scope", "incomplete", "unavailable", "not_applicable"]
    if not analyses or all(analysis.coverage_status == "unavailable" for analysis in analyses):
        coverage = "unavailable"
    elif admission.coverage_reasons or any(analysis.coverage_status != "complete_within_scope" for analysis in analyses):
        coverage = "incomplete"
    else:
        coverage = "complete_within_scope"
    ids = tuple(defect.defect_id for defect in admission.defects)
    block = config.mode == "blocking" and (
        bool(ids) or (coverage in ("incomplete", "unavailable") and config.incomplete_coverage_policy == "block")
    )
    return PushResult(analyses, "actionable" if ids else "none", coverage, "block" if block else "allow", ids)
