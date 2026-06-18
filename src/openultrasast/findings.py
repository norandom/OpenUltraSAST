from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .preprocess import FileTarget
from .rank import RankingScore


@dataclass(frozen=True)
class StaticFinding:
    finding_id: str
    path: str
    title: str
    severity: str
    confidence: str
    evidence_level: str
    rationale: str
    line: int | None
    function_name: str | None
    reachability_status: str
    reachability_evidence: list[dict[str, object]]
    reachability_conditions: list[str]
    tags: list[str]
    ranking_priority: float


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    severity: str
    tags: tuple[str, ...]
    pattern: re.Pattern[str]


PATTERN_RULES = (
    PatternRule(
        rule_id="c-unsafe-copy",
        title="Unsafe C string or input function needs review",
        severity="high",
        tags=("memory_unsafe",),
        pattern=re.compile(r"\b(gets|strcpy|strcat|sprintf)\s*\("),
    ),
    PatternRule(
        rule_id="python-unsafe-eval",
        title="Dynamic Python execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(eval|exec)\s*\("),
    ),
    PatternRule(
        rule_id="python-unsafe-deserialization",
        title="Unsafe Python deserialization needs review",
        severity="high",
        tags=("deserialization",),
        pattern=re.compile(r"\b(pickle\.loads|yaml\.load)\s*\("),
    ),
    PatternRule(
        rule_id="python-shell-true",
        title="Subprocess shell execution needs review",
        severity="medium",
        tags=("syscall_entry",),
        pattern=re.compile(r"subprocess\.[a-zA-Z_]+\s*\([^\n]*shell\s*=\s*True"),
    ),
)


def quick_scan_findings(root: Path, targets: list[FileTarget], rankings: list[RankingScore]) -> list[StaticFinding]:
    ranking_by_path = {ranking.path: ranking for ranking in rankings}
    findings: list[StaticFinding] = []
    for target in targets:
        text = _read_text(root / target.path)
        for rule in PATTERN_RULES:
            ranking = ranking_by_path.get(target.path)
            for match in rule.pattern.finditer(text):
                findings.append(_finding_from_match(target, rule, text, match.start(), ranking))
    return sorted(findings, key=lambda item: (_severity_sort(item.severity), -item.ranking_priority, item.path))


def build_quick_hunter_prompt(target: FileTarget, source_excerpt: str) -> str:
    return (
        "Review this file for security-relevant issues. Return structured findings only when evidence exists.\n"
        f"Path: {target.path}\n"
        f"Language: {target.language}\n"
        f"Tags: {', '.join(target.tags) or 'none'}\n"
        "Source excerpt:\n"
        f"{source_excerpt[:4000]}"
    )


def write_findings(findings: list[StaticFinding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"findings": [asdict(finding) for finding in findings]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _finding_from_match(
    target: FileTarget,
    rule: PatternRule,
    text: str,
    offset: int,
    ranking: RankingScore | None,
) -> StaticFinding:
    line = text.count("\n", 0, offset) + 1
    reachability_status, function_name, reachability_evidence = _reachability_for_line(target, line)
    priority = ranking.priority if ranking is not None else 1.0
    return StaticFinding(
        finding_id=f"{rule.rule_id}:{target.path}:{line}",
        path=target.path,
        title=rule.title,
        severity=rule.severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale=f"Static pattern {rule.rule_id} matched line {line}; manual verification still required.",
        line=line,
        function_name=function_name,
        reachability_status=reachability_status,
        reachability_evidence=reachability_evidence,
        reachability_conditions=_reachability_conditions(reachability_evidence),
        tags=sorted(set(target.tags) | set(rule.tags)),
        ranking_priority=_finding_priority(priority, reachability_status),
    )


def _reachability_for_line(target: FileTarget, line: int) -> tuple[str, str | None, list[dict[str, object]]]:
    hints = target.reachability_hints
    concrete = [hint for hint in hints if isinstance(hint.get("line"), int)]
    matching = [hint for hint in concrete if _line_in_hint(line, hint)]
    if matching:
        return "reachable", _function_name(matching), matching
    if concrete:
        return "unknown", None, []
    inferred = [hint for hint in hints if hint.get("line") is None]
    if inferred:
        return "inferred-file-surface", None, inferred
    return "unknown", None, []


def _line_in_hint(line: int, hint: dict[str, object]) -> bool:
    start = hint.get("line")
    end = hint.get("end_line")
    if not isinstance(start, int):
        return False
    if not isinstance(end, int):
        end = start
    return start <= line <= end


def _function_name(hints: list[dict[str, object]]) -> str | None:
    for hint in hints:
        function_name = hint.get("function_name")
        if isinstance(function_name, str) and function_name:
            return function_name
    return None


def _reachability_conditions(hints: list[dict[str, object]]) -> list[str]:
    conditions: list[str] = []
    for hint in hints:
        value = hint.get("conditions")
        if isinstance(value, list):
            conditions.extend(str(item) for item in value if item)
    return sorted(set(conditions))


def _finding_priority(priority: float, reachability_status: str) -> float:
    if reachability_status == "unknown":
        return min(priority, 1.5)
    return priority


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _severity_sort(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)
