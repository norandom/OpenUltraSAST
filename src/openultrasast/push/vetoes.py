"""Experimental recorded-veto evaluation for release milestone M1a.

Record every comparison and admission veto per raw finding instead of applying it, so
a maintainer can see which vetoes discard a detection the arbiter already reported.

This module never admits a defect, enables a capability or changes the production
result. The production comparison and admission have already run on the applied path.
Here the same policy functions run again over a *lifted* view of the same evidence in
which recognized completeness vetoes are removed and recorded. Failures are never
lifted: deadline exhaustion, unanswered queries, unreadable input, empty graphs and
unparsed files stay applied, because silence from failure is not a quiet fixed twin.
Every payload produced here carries an experimental label.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from openultrasast.contracts import Contract
from openultrasast.model.contracts import ChangeContext, ExecutionBudget, QuestionIdentity
from openultrasast.model.scan import ModelScanResult
from openultrasast.push.contracts import PushComparison
from openultrasast.push.policy import (
    AdmissionCandidate,
    CandidateDelta,
    CapabilityAdmission,
    CapabilityKey,
    EvidenceOperation,
    _base_location,
    _compare_evidence,
    _context_boundaries,
    _counterpart,
    _grounded_template,
    admit_candidates,
    operation_provenance,
)

FLAG = "--experimental-record-vetoes"
LABEL = (
    "EXPERIMENTAL recorded-veto evaluation (release milestone M1a). Listed vetoes were recorded, not applied. "
    "Nothing in this section is an alert, an admitted defect, a capability or a comparison result; the production "
    "result and admission above remain authoritative."
)

# Outcome reasons that scan.py applies to an *answered* question after the fact. Lifting them
# restores the answered rows; an unanswered or not-arbitrated question is never lifted.
LIFTED_OUTCOME_REASONS = frozenset({"change_context_incomplete", "graph_incomplete"})
# Physical vendor exclusion is retained; only its global completion veto is recorded here.
LIFTED_DEGRADATION_REASONS = frozenset({"vendor_semantics_unresolved"})
# Boundary kinds diagnosed in release-remediation-research.md as completeness vetoes rather
# than input failures. The kind is one colon-separated segment of a boundary string.
LIFTED_BOUNDARY_KINDS = frozenset(
    {
        "vendor_semantics_unresolved",
        "ambiguous_line_correspondence",
        "context_projection_unavailable",
        "context_scope_empty",
        "dynamic_external_or_depth_context_unresolved",
        "context_location_unavailable",
        "configuration_dependency_projection_unavailable",
        "deleted_dependency_projection_unavailable",
    }
)
# Admission reasons that this flag can never remove; they are recorded with that explanation.
_EXPECTED_ADMISSION = {
    "capability_unavailable": "no evaluated capability is enabled; the recorded-veto flag cannot enable one",
    "capability_disabled": "capability declared but not enabled; the recorded-veto flag cannot enable one",
    "capability_unevaluated": "capability not qualified; the recorded-veto flag cannot qualify one",
}


@dataclass(frozen=True)
class RecordedVeto(Contract):
    stage: str
    veto: str
    detail: str
    lifted: bool


@dataclass(frozen=True)
class QuestionReceipt(Contract):
    identity: QuestionIdentity
    status: str
    reason: str
    rows: int | None
    lifted: bool


@dataclass(frozen=True)
class OutcomeCount(Contract):
    status: str
    reason: str
    count: int


@dataclass(frozen=True)
class ScanSummary(Contract):
    findings: int
    outcomes: tuple[OutcomeCount, ...]
    lifted: tuple[OutcomeCount, ...]
    degradations: tuple[str, ...]
    lifted_degradations: tuple[str, ...]
    boundaries_by_kind: tuple[OutcomeCount, ...]
    changed_path_questions: tuple[QuestionReceipt, ...]


@dataclass(frozen=True)
class RecordedFinding(Contract):
    family: str
    site: str
    rung: str
    witness: str | None
    question: QuestionIdentity | None
    operation: EvidenceOperation | None
    operation_method: str | None
    base_location: str | None
    production_novelty: str
    production_reason: str
    production_admission: tuple[str, ...]
    recorded_novelty: str
    recorded_reason: str
    recorded_admission: tuple[str, ...]
    vetoes: tuple[RecordedVeto, ...]


@dataclass(frozen=True)
class BaseOnlyFinding(Contract):
    family: str
    site: str
    rung: str
    witness: str | None
    head_counterparts: tuple[QuestionReceipt, ...]


@dataclass(frozen=True)
class EvaluationFinding(Contract):
    """A developer-readable rendering of one evaluation finding, for reading, never for alerting.

    Consequence and repair come from a supplied declaration's templates through the same
    grounded-template path the admitted case uses, so no prose is invented here. When no
    declaration matches, both are absent with the reason stated. This record is produced outside
    admission and cannot become an alert.
    """

    family: str
    path: str
    line: int
    novelty: str
    reason: str
    witness: str
    change_evidence: str
    provenance: str
    question_function: str | None
    engine_method: str | None
    operation: str
    operation_symbol: str
    consequence: str | None
    repair: str | None
    unavailable: tuple[str, ...]
    declaration: str | None
    declaration_verdict: str | None
    declaration_enabled: bool


@dataclass(frozen=True)
class RecordedVetoReport(Contract):
    label: str
    flag: str
    lifted_kinds: tuple[str, ...]
    head: ScanSummary
    base: ScanSummary | None
    findings: tuple[RecordedFinding, ...]
    base_only_findings: tuple[BaseOnlyFinding, ...]
    lifted_coverage_reasons: tuple[str, ...]
    remaining_coverage_reasons: tuple[str, ...]
    evaluation: tuple[EvaluationFinding, ...] = ()


def boundary_kind(boundary: str) -> str | None:
    """Return the recognized lifted kind inside a boundary string, if any."""
    return next((segment for segment in boundary.split(":") if segment in LIFTED_BOUNDARY_KINDS), None)


def _lift_scan(scan: ModelScanResult) -> tuple[ModelScanResult, Counter[str]]:
    lifted: Counter[str] = Counter()
    outcomes = []
    for outcome in scan.question_outcomes:
        if outcome.status == "unresolved" and outcome.reason in LIFTED_OUTCOME_REASONS and outcome.raw_rows_json is not None:
            lifted["question:" + outcome.reason] += 1
            outcomes.append(replace(outcome, status="completed", reason="recorded_veto:" + outcome.reason))
        else:
            outcomes.append(outcome)
    degradations = []
    for degradation in scan.degradations:
        if str(degradation.get("reason")) in LIFTED_DEGRADATION_REASONS:
            lifted["degradation:" + str(degradation.get("reason"))] += 1
        else:
            degradations.append(degradation)
    scope = scan.scope
    if scope is not None:
        kept = []
        for boundary in scope.unresolved_boundaries:
            kind = boundary_kind(boundary)
            if kind is None:
                kept.append(boundary)
            else:
                lifted["boundary:" + kind] += 1
        scope = replace(scope, unresolved_boundaries=tuple(kept))
    return replace(scan, question_outcomes=tuple(outcomes), degradations=tuple(degradations), scope=scope), lifted


def _lift_context(context: ChangeContext) -> tuple[ChangeContext, tuple[str, ...]]:
    lifted = tuple(b for b in context.unresolved_boundaries if boundary_kind(b) is not None)
    kept = tuple(b for b in context.unresolved_boundaries if boundary_kind(b) is None)
    return replace(context, unresolved_boundaries=kept), lifted


def _rows(raw: str | None) -> int | None:
    if raw is None:
        return None
    rows = json.loads(raw)
    return len(rows) if isinstance(rows, list) else None


def _receipt(scan: ModelScanResult, lifted: ModelScanResult, identity: QuestionIdentity) -> QuestionReceipt | None:
    original = next((o for o in scan.question_outcomes if o.identity == identity), None)
    if original is None:
        return None
    after = next((o for o in lifted.question_outcomes if o.identity == identity), original)
    return QuestionReceipt(identity, original.status, original.reason, _rows(original.raw_rows_json), after.status != original.status)


def _summary(scan: ModelScanResult, lifted: ModelScanResult, counts: Counter[str], context: ChangeContext) -> ScanSummary:
    outcomes = Counter((o.status, o.reason) for o in scan.question_outcomes)
    boundaries = Counter(boundary_kind(b) or b.split(":")[0] for b in (scan.scope.unresolved_boundaries if scan.scope else ()))
    changed = {context.decode_path(p) for p in context.changed_paths}
    receipts = tuple(
        receipt
        for o in scan.question_outcomes
        if o.identity.path in changed
        for receipt in (_receipt(scan, lifted, o.identity),)
        if receipt is not None
    )
    return ScanSummary(
        len(scan.findings),
        tuple(OutcomeCount(status, reason, count) for (status, reason), count in sorted(outcomes.items())),
        tuple(
            OutcomeCount(key.split(":", 1)[0], key.split(":", 1)[1], count)
            for key, count in sorted(counts.items())
            if not key.startswith("boundary:")
        ),
        tuple(dict.fromkeys(str(d.get("reason")) for d in scan.degradations)),
        tuple(key.split(":", 1)[1] for key in sorted(counts) if key.startswith("degradation:")),
        tuple(OutcomeCount("boundary", kind, count) for kind, count in sorted(boundaries.items())),
        receipts,
    )


def _method(op: EvidenceOperation) -> str | None:
    return op.method


def _boundary_vetoes(stage: str, boundaries: Sequence[str]) -> list[RecordedVeto]:
    return [RecordedVeto(stage, boundary_kind(b) or b, b, boundary_kind(b) is not None) for b in boundaries]


def _degradation_vetoes(stage: str, scan: ModelScanResult) -> list[RecordedVeto]:
    return [
        RecordedVeto(
            stage,
            "degradation:" + str(d.get("reason")),
            json.dumps(dict(d), sort_keys=True, default=str),
            str(d.get("reason")) in LIFTED_DEGRADATION_REASONS,
        )
        for d in scan.degradations
    ]


def _question_veto(stage: str, receipt: QuestionReceipt | None, identity: QuestionIdentity) -> list[RecordedVeto]:
    if receipt is None:
        return [RecordedVeto(stage, "question_missing", identity.question_id, False)]
    if receipt.status == "completed":
        return []
    detail = f"{identity.question_id} status={receipt.status} rows={receipt.rows}"
    return [RecordedVeto(stage, receipt.reason, detail, receipt.lifted)]


def _finding_vetoes(
    op: EvidenceOperation | None,
    *,
    head: ModelScanResult,
    lifted_head: ModelScanResult,
    base: ModelScanResult | None,
    lifted_base: ModelScanResult | None,
    context: ChangeContext,
    recorded: CandidateDelta,
    admission: Sequence[str],
) -> tuple[RecordedVeto, ...]:
    vetoes: list[RecordedVeto] = []
    if op is None:
        vetoes.append(RecordedVeto("comparison", recorded.reason, "no completed head operation matches this finding after lifting", False))
    else:
        question = op.question
        vetoes.extend(_question_veto("head_question", _receipt(head, lifted_head, question), question))
        vetoes.extend(_boundary_vetoes("head_scan", _context_boundaries(head, question)))
        vetoes.extend(_degradation_vetoes("head_scan", head))
        method = _method(op)
        provenance = operation_provenance(op)
        if provenance != "exact":
            vetoes.append(
                RecordedVeto(
                    "identity",
                    "query_identity_differs_from_witness",
                    f"provenance={provenance}; question function={question.function!r}; engine method={method!r}",
                    False,
                )
            )
        if base is None or lifted_base is None:
            vetoes.append(RecordedVeto("base_scan", "base_unavailable", "no base scan was produced", False))
        else:
            counterpart = _counterpart(question, context)
            vetoes.extend(_question_veto("base_question", _receipt(base, lifted_base, counterpart), counterpart))
            vetoes.extend(_boundary_vetoes("base_scan", _context_boundaries(base)))
            vetoes.extend(_degradation_vetoes("base_scan", base))
            if base.scope is not None:
                if not base.scope.population_complete:
                    vetoes.append(RecordedVeto("base_scan", "population_incomplete", "base census not asserted complete", False))
                for deferred in base.scope.deferred:
                    if deferred.reason != "tier_zero":
                        vetoes.append(RecordedVeto("base_scan", "deferred:" + deferred.reason, deferred.identity.question_id, False))
            pending = [o for o in lifted_base.question_outcomes if o.status != "completed"]
            if pending:
                detail = f"{len(pending)} of {len(lifted_base.question_outcomes)} base questions not completed after lifting"
                vetoes.append(RecordedVeto("base_scan", "questions_not_completed", detail, False))
    vetoes.extend(_boundary_vetoes("change_context", context.unresolved_boundaries))
    if op is not None and recorded.novelty == "unknown":
        location = _base_location(op, context)
        where = f"{location[0]}:{location[1]}" if location else "unresolved (operation on a changed line or ambiguous)"
        vetoes.append(RecordedVeto("comparison", recorded.reason, "base location " + where, False))
    for reason in admission:
        explanation = _EXPECTED_ADMISSION.get(reason, "production admission reason on the lifted candidate")
        vetoes.append(RecordedVeto("admission", reason, explanation, False))
    return tuple(vetoes)


def load_declarations(path: Path) -> tuple[CapabilityAdmission, ...]:
    """Read experimental declarations for the evaluation rendering only.

    These never reach admission. The installed registry remains the sole source of eligibility,
    so a declaration read here cannot enable a capability or emit an alert however it is written.
    """
    content = path.read_bytes()[: 1024**2 + 1]
    if len(content) > 1024**2:
        raise ValueError("declaration_size_limit")
    payload = json.loads(content)
    if not isinstance(payload, list):
        raise ValueError("declarations must be a list")
    return tuple(CapabilityAdmission.from_payload(item) for item in payload)


def _evaluation(delta: CandidateDelta, declarations: Sequence[CapabilityAdmission], semantics: str) -> EvaluationFinding | None:
    """Render one established finding. Returns None for anything not attributed to the change."""
    op = delta.head_operation
    if op is None or delta.novelty not in ("new", "worsened") or delta.witness is None or not delta.change_evidence:
        return None
    key = CapabilityKey(op.question.language, "unspecified", "unspecified", delta.family, op.mechanism, "unreviewed", semantics)
    matching = [declaration for declaration in declarations if declaration.key == key]
    symbol = op.operation.partition("(")[0].strip()
    unavailable: list[str] = []
    consequence = repair = None
    declaration = matching[0] if len(matching) == 1 else None
    if not matching:
        unavailable.append("no_matching_declaration")
    elif len(matching) > 1:
        unavailable.append("ambiguous_declaration")
    if declaration is not None:
        consequence = _grounded_template(declaration.consequence_template, op, key.context)
        repair = _grounded_template(declaration.repair_template, op, key.context)
        if consequence is None:
            unavailable.append("consequence_template_ungrounded")
        if repair is None:
            unavailable.append("repair_template_ungrounded")
        if symbol not in declaration.operation_symbols:
            unavailable.append("declaration_does_not_cover_operation_symbol")
    return EvaluationFinding(
        delta.family,
        op.path,
        op.line,
        delta.novelty,
        delta.reason,
        delta.witness,
        delta.change_evidence[0],
        operation_provenance(op),
        op.question.function,
        op.method,
        op.operation,
        symbol,
        consequence,
        repair,
        tuple(unavailable),
        declaration.evaluation_id if declaration else None,
        declaration.verdict if declaration else None,
        bool(declaration.enabled) if declaration else False,
    )


def record_vetoes(
    *,
    head: ModelScanResult,
    base: ModelScanResult | None,
    context: ChangeContext,
    comparison: PushComparison,
    semantics: str,
    production: Sequence[CandidateDelta],
    production_admission: dict[str, tuple[str, ...]],
    coverage_reasons: Sequence[str],
    capabilities: Sequence[CapabilityAdmission] = (),
    declarations: Sequence[CapabilityAdmission] = (),
    execution_budget: ExecutionBudget | None = None,
) -> RecordedVetoReport:
    """Re-run the production comparison and admission over lifted evidence and list what was lifted.

    `production` and `production_admission` (keyed by delta.defect_id) are the applied results the
    runner already produced; they are retained beside the recorded outcome for every finding.
    """
    lifted_head, head_counts = _lift_scan(head)
    lifted_base, base_counts = _lift_scan(base) if base is not None else (None, Counter())
    lifted_context, lifted_boundaries = _lift_context(context)
    lifted_reasons = tuple(r for r in coverage_reasons if boundary_kind(r) is not None or r in LIFTED_OUTCOME_REASONS)
    remaining = tuple(r for r in coverage_reasons if r not in lifted_reasons)
    recorded = _compare_evidence(
        lifted_head,
        lifted_base,
        context=lifted_context,
        head_semantics=semantics,
        base_semantics=semantics,
        execution_budget=execution_budget,
    )
    candidates = tuple(
        AdmissionCandidate(
            delta,
            CapabilityKey(
                delta.head_operation.question.language if delta.head_operation else "unknown",
                "unspecified",
                "unspecified",
                delta.family,
                delta.head_operation.mechanism if delta.head_operation else "taint",
                "unreviewed",
                semantics,
            ),
            comparison,
            remaining,
        )
        for delta in recorded
    )
    # Only the per-candidate reasons are retained. Any defect the lifted path would admit is
    # deliberately dropped here: this section is a diagnostic record, never an alert channel.
    admitted = admit_candidates(candidates, capabilities=capabilities)
    recorded_admission = {d.candidate.delta.defect_id: d.reasons for d in admitted.dispositions}
    applied = {(c.family, c.site, c.witness): c for c in production}
    findings = []
    for finding, delta in zip(head.findings, recorded, strict=True):
        before = applied.get((finding.family, finding.site, finding.witness or None))
        op = delta.head_operation
        location = _base_location(op, context) if op else None
        admission = recorded_admission.get(delta.defect_id, ())
        findings.append(
            RecordedFinding(
                finding.family,
                finding.site,
                finding.rung.value,
                finding.witness or None,
                op.question if op else None,
                op,
                _method(op) if op else None,
                f"{location[0]}:{location[1]}" if location else None,
                before.novelty if before else "unknown",
                before.reason if before else "production_candidate_missing",
                production_admission.get(before.defect_id, ()) if before else (),
                delta.novelty,
                delta.reason,
                admission,
                _finding_vetoes(
                    op,
                    head=head,
                    lifted_head=lifted_head,
                    base=base,
                    lifted_base=lifted_base,
                    context=context,
                    recorded=delta,
                    admission=admission,
                ),
            )
        )
    base_only = []
    if base is not None and lifted_base is not None:
        head_sites = {(f.family, f.site) for f in head.findings}
        for finding in base.findings:
            if (finding.family, finding.site) in head_sites:
                continue
            path = finding.site.split(":", 1)[0]
            counterparts = tuple(
                receipt
                for o in head.question_outcomes
                if o.identity.path == path and o.identity.family == finding.family
                for receipt in (_receipt(head, lifted_head, o.identity),)
                if receipt is not None
            )
            base_only.append(BaseOnlyFinding(finding.family, finding.site, finding.rung.value, finding.witness or None, counterparts))
    kinds = (
        *("question:" + r for r in LIFTED_OUTCOME_REASONS),
        *("degradation:" + r for r in LIFTED_DEGRADATION_REASONS),
        *("boundary:" + k for k in LIFTED_BOUNDARY_KINDS),
    )
    return RecordedVetoReport(
        LABEL,
        FLAG,
        tuple(sorted(kinds)),
        _summary(head, lifted_head, head_counts, context),
        _summary(base, lifted_base, base_counts, context) if base is not None and lifted_base is not None else None,
        tuple(findings),
        tuple(base_only),
        tuple(dict.fromkeys((*lifted_reasons, *lifted_boundaries))),
        remaining,
        # Rendered from the PRODUCTION comparison, so the demonstration shows what the production
        # rules established, not what the lifted view would have.
        tuple(item for delta in production for item in (_evaluation(delta, declarations, semantics),) if item is not None),
    )
