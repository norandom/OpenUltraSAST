"""Adjudicate inventory proposals: promote, demote, unadjudicated, coverage."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from ..findings import SEVERITY_LABEL, StaticFinding
from ..policy import load_policy, resolve_severity
from ..preprocess import FileTarget
from .engines import joern_available, joern_flow
from .facts import FactLoadError, SemanticFacts, load_facts
from .functions import FunctionRange, function_at, named_ranges_from_ir
from .ir import parse_file
from .taint import Demotion, FileFlow, TaintPath, UnadjudicatedFlow, analyze_ir, merge_joern_paths

DISPOSITIONS = frozenset({"promote", "demote", "unadjudicated", "coverage"})
UNADJUDICATED_REASONS = frozenset({"parse_failed", "language_unsupported", "flow_incomplete", "facts_unavailable"})
ALLOWED_EVIDENCE = frozenset({"static_corroboration", "suspicion"})
__all__ = ["OverlayRecord", "adjudicate", "function_at", "FunctionRange", "write_overlay", "finding_from_coverage"]

FORBIDDEN_EVIDENCE = frozenset({"crash_reproduced", "exploit_demonstrated", "patch_validated", "root_cause_explained"})


class OverlayError(ValueError):
    """Raised when an overlay record violates fail-closed invariants."""


@dataclass(frozen=True)
class OverlayRecord:
    proposal_id: str
    path: str
    line: int | None
    disposition: str
    reason: str
    cwe: str
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    sanitizers: tuple[str, ...]
    evidence_level: str
    dominating_fact: str | None = None
    origin: str = "inventory"
    engine: str = "none"
    language: str = ""
    function: str | None = None  # enclosing function when the file parsed (additive; pair-corpus-honesty)
    mechanism_id: str | None = None  # known mechanism whose shape matches this call site (additive; corpus-seeded-mechanisms)

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise OverlayError(f"invalid disposition: {self.disposition}")
        if self.evidence_level in FORBIDDEN_EVIDENCE:
            raise OverlayError("overlay cannot claim proof rungs")
        if self.evidence_level not in ALLOWED_EVIDENCE:
            raise OverlayError(f"invalid evidence_level: {self.evidence_level}")
        if self.disposition == "demote" and not self.dominating_fact and not self.sanitizers:
            raise OverlayError("demote requires a recorded constant or sanitizer")
        if self.disposition == "unadjudicated" and self.reason not in UNADJUDICATED_REASONS:
            raise OverlayError(f"invalid unadjudicated reason: {self.reason}")
        if self.disposition in {"promote", "coverage"} and self.evidence_level not in ALLOWED_EVIDENCE:
            raise OverlayError("promote and coverage must stay at static_corroboration or below")


def adjudicate(
    *,
    root: Path,
    targets: Sequence[FileTarget],
    findings: Sequence[StaticFinding],
    facts: SemanticFacts | FactLoadError | None = None,
    joern_extra: Sequence[TaintPath] | None = None,
) -> list[OverlayRecord]:
    loaded = facts if facts is not None else _try_facts()
    language_by_path = {target.path: target.language for target in targets}
    if isinstance(loaded, FactLoadError):
        return [
            _unadjudicated(
                finding,
                language_by_path.get(finding.path, ""),
                "facts_unavailable",
                "none",
            )
            for finding in findings
        ]
    flows, ranges = _flows_for(root, targets, loaded, joern_extra)
    records: list[OverlayRecord] = []
    claimed: set[tuple[str, int | None, str]] = set()
    for finding in findings:
        language = language_by_path.get(finding.path, "")
        flow = flows.get(finding.path)
        record = _record_for_finding(finding, language, flow, function_at(ranges.get(finding.path, ()), finding.line))
        records.append(record)
        claimed.add((finding.path, finding.line, _sink_hint(finding)))
    for path, flow in flows.items():
        if not isinstance(flow, FileFlow):
            continue
        language = language_by_path.get(path, flow.language)
        for taint in flow.taint_paths:
            key = (taint.path, taint.sink_line, taint.sink)
            if (taint.path, taint.sink_line, taint.sink) in claimed or any(
                item.path == taint.path and item.line == taint.sink_line for item in findings
            ):
                continue
            records.append(
                OverlayRecord(
                    proposal_id=f"overlay-coverage:{taint.path}:{taint.sink_line}:{taint.sink}",
                    path=taint.path,
                    line=taint.sink_line,
                    disposition="coverage",
                    reason=f"uninventoried sink {taint.sink} reached from {taint.source}",
                    cwe=taint.cwe,
                    sources=(taint.source,),
                    sinks=(taint.sink,),
                    sanitizers=(),
                    evidence_level="static_corroboration",
                    origin="overlay",
                    engine=flow.engine,
                    language=language,
                    function=function_at(ranges.get(path, ()), taint.sink_line),
                )
            )
            claimed.add(key)
    return records


def write_overlay(records: Sequence[OverlayRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"records": [asdict(record) for record in records]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def finding_from_coverage(record: OverlayRecord) -> StaticFinding:
    policy = load_policy()
    severity = SEVERITY_LABEL.get(resolve_severity(policy, record.cwe), "info") if record.cwe else "info"
    sink = record.sinks[0] if record.sinks else "sink"
    return StaticFinding(
        finding_id=record.proposal_id,
        path=record.path,
        title=f"Overlay coverage: {sink}",
        severity=severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale=record.reason,
        line=record.line,
        function_name=None,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["overlay-originated"],
        ranking_priority=0.0,
    )


def _try_facts() -> SemanticFacts | FactLoadError:
    try:
        return load_facts()
    except FactLoadError as exc:
        return exc


def _flows_for(
    root: Path,
    targets: Sequence[FileTarget],
    facts: SemanticFacts,
    joern_extra: Sequence[TaintPath] | None,
) -> tuple[dict[str, FileFlow | UnadjudicatedFlow], dict[str, tuple[FunctionRange, ...]]]:
    flows: dict[str, FileFlow | UnadjudicatedFlow] = {}
    ranges: dict[str, tuple[FunctionRange, ...]] = {}
    for target in targets:
        text = _read_text(root / target.path)
        ir = parse_file(target.path, text, target.language)
        if not ir.parse_ok:
            flows[target.path] = UnadjudicatedFlow(path=target.path, reason=ir.reason or "parse_failed", engine=ir.engine)
            continue
        ranges[target.path] = named_ranges_from_ir(ir, text)
        analyzed: FileFlow | UnadjudicatedFlow = analyze_ir(ir, facts.for_language(target.language))
        if isinstance(analyzed, FileFlow):
            extra = tuple(joern_extra) if joern_extra is not None else _joern_paths(target.path, text, target.language)
            if extra:
                analyzed = FileFlow(
                    path=analyzed.path,
                    language=analyzed.language,
                    engine=analyzed.engine,
                    taint_paths=merge_joern_paths(analyzed.taint_paths, extra),
                    demotions=analyzed.demotions,
                    incomplete=analyzed.incomplete,
                )
        flows[target.path] = analyzed
    return flows, ranges


def _joern_paths(path: str, text: str, language: str) -> tuple[TaintPath, ...]:
    if not joern_available():
        return ()
    extra = joern_flow(path, text, language)
    paths: list[TaintPath] = []
    for item in extra:
        if isinstance(item, TaintPath):
            paths.append(item)
    return tuple(paths)


def _record_for_finding(
    finding: StaticFinding,
    language: str,
    flow: FileFlow | UnadjudicatedFlow | None,
    function: str | None = None,
) -> OverlayRecord:
    if flow is None:
        return _unadjudicated(finding, language, "flow_incomplete", "none")
    if isinstance(flow, UnadjudicatedFlow):
        reason = flow.reason if flow.reason in UNADJUDICATED_REASONS else "flow_incomplete"
        return _unadjudicated(finding, language, reason, flow.engine)
    demotion = _matching_demotion(finding, flow)
    taint = _matching_taint(finding, flow)
    if demotion is not None and taint is None:
        return OverlayRecord(
            proposal_id=finding.finding_id,
            path=finding.path,
            line=finding.line,
            disposition="demote",
            reason=f"{demotion.sink} dominated by {demotion.dominating_fact}",
            cwe=demotion.cwe or _cwe_of(finding),
            sources=(),
            sinks=(demotion.sink,),
            sanitizers=demotion.sanitizers,
            evidence_level="static_corroboration",
            dominating_fact=demotion.dominating_fact,
            engine=flow.engine,
            language=language,
            function=function,
        )
    if taint is not None and (demotion is None or not demotion.sanitizers):
        # Sanitizer on the same path would have produced a demotion with sanitizers.
        return OverlayRecord(
            proposal_id=finding.finding_id,
            path=finding.path,
            line=finding.line,
            disposition="promote",
            reason=f"{taint.source} reaches {taint.sink} without a dominating sanitizer",
            cwe=taint.cwe or _cwe_of(finding),
            sources=(taint.source,),
            sinks=(taint.sink,),
            sanitizers=(),
            evidence_level="static_corroboration",
            engine=flow.engine,
            language=language,
            function=function,
        )
    if demotion is not None:
        return OverlayRecord(
            proposal_id=finding.finding_id,
            path=finding.path,
            line=finding.line,
            disposition="demote",
            reason=f"{demotion.sink} dominated by {demotion.dominating_fact}",
            cwe=demotion.cwe or _cwe_of(finding),
            sources=(),
            sinks=(demotion.sink,),
            sanitizers=demotion.sanitizers,
            evidence_level="static_corroboration",
            dominating_fact=demotion.dominating_fact,
            engine=flow.engine,
            language=language,
            function=function,
        )
    return _unadjudicated(finding, language, "flow_incomplete", flow.engine, function)


def _matching_taint(finding: StaticFinding, flow: FileFlow) -> TaintPath | None:
    for item in flow.taint_paths:
        if item.path == finding.path and _line_matches(finding.line, item.sink_line) and _sink_matches(finding, item.sink):
            return item
    for item in flow.taint_paths:
        if item.path == finding.path and _line_matches(finding.line, item.sink_line):
            return item
    return None


def _matching_demotion(finding: StaticFinding, flow: FileFlow) -> Demotion | None:
    for item in flow.demotions:
        if item.path == finding.path and _line_matches(finding.line, item.sink_line) and _sink_matches(finding, item.sink):
            return item
    for item in flow.demotions:
        if item.path == finding.path and _line_matches(finding.line, item.sink_line):
            return item
    return None


def _line_matches(finding_line: int | None, sink_line: int) -> bool:
    return finding_line is None or finding_line == sink_line


def _sink_matches(finding: StaticFinding, sink: str) -> bool:
    haystack = f"{finding.finding_id} {finding.title} {finding.rationale} {sink}".lower()
    return sink.lower() in haystack or finding.finding_id.split(":", 1)[0].lower() in sink.lower()


def _sink_hint(finding: StaticFinding) -> str:
    return finding.finding_id.split(":", 1)[0]


def _cwe_of(finding: StaticFinding) -> str:
    for token in finding.rationale.replace("(", " ").replace(")", " ").split():
        if token.startswith("CWE-"):
            return token.rstrip(".,;")
    return ""


def _unadjudicated(finding: StaticFinding, language: str, reason: str, engine: str, function: str | None = None) -> OverlayRecord:
    return OverlayRecord(
        proposal_id=finding.finding_id,
        path=finding.path,
        line=finding.line,
        disposition="unadjudicated",
        reason=reason,
        cwe=_cwe_of(finding),
        sources=(),
        sinks=(),
        sanitizers=(),
        evidence_level="static_corroboration",
        engine=engine,
        language=language,
        function=function,
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""
