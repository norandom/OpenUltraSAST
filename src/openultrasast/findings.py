from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .policy import CwePolicy, load_policy, resolve_severity
from .preprocess import FileTarget
from .rank import RankingScore
from .ruleset import DEFAULT_RULESET_DIR, PatternRule, load_ruleset


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
    status: str = "enabled"


SEVERITY_LABEL = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low", 0: "info"}

# Default ruleset loaded from versioned TOML data (rules-as-data).
PATTERN_RULES = load_ruleset(DEFAULT_RULESET_DIR)


def quick_scan_findings(
    root: Path,
    targets: list[FileTarget],
    rankings: list[RankingScore],
    ruleset: tuple[PatternRule, ...] | None = None,
    policy: dict[str, CwePolicy] | None = None,
    *,
    min_emit_priority: float = 0.0,
    min_emit_precision: float = 0.0,
) -> list[StaticFinding]:
    ruleset = PATTERN_RULES if ruleset is None else ruleset
    policy = load_policy() if policy is None else policy
    ranking_by_path = {ranking.path: ranking for ranking in rankings}
    # Compile once; disabled rules and rules below the precision floor never fire.
    compiled = [
        (rule, re.compile(rule.pattern)) for rule in ruleset if rule.status != "disabled" and rule.precision_estimate >= min_emit_precision
    ]
    findings: list[StaticFinding] = []
    for target in targets:
        text = _read_text(root / target.path)
        for rule, pattern in compiled:
            if rule.languages and target.language not in rule.languages:
                continue
            ranking = ranking_by_path.get(target.path)
            for match in pattern.finditer(text):
                if _match_is_in_comment(text, match.start(), target.language):
                    continue
                finding = _finding_from_match(target, rule, text, match, ranking, policy)
                if finding.ranking_priority >= min_emit_priority:
                    findings.append(finding)
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
    match: re.Match[str],
    ranking: RankingScore | None,
    policy: dict[str, CwePolicy],
) -> StaticFinding:
    offset = match.start()
    line = text.count("\n", 0, offset) + 1
    reachability_status, function_name, reachability_evidence = _reachability_for_line(target, line)
    priority = ranking.priority if ranking is not None else 1.0
    matched_token = match.group(1) if match.groups() else match.group(0).split("(", 1)[0].strip()
    severity = SEVERITY_LABEL.get(resolve_severity(policy, rule.cwe), "info")
    return StaticFinding(
        finding_id=f"{rule.rule_id}:{target.path}:{line}",
        path=target.path,
        title=rule.title,
        severity=severity,
        confidence="medium",
        evidence_level="static_corroboration",
        rationale=(
            f"Static pattern {rule.rule_id} ({rule.cwe}) matched {matched_token} on line {line}; manual verification still required."
        ),
        line=line,
        function_name=function_name,
        reachability_status=reachability_status,
        reachability_evidence=reachability_evidence,
        reachability_conditions=_reachability_conditions(reachability_evidence),
        tags=sorted(set(target.tags) | set(rule.tags)),
        ranking_priority=_finding_priority(priority, reachability_status),
        status=rule.status,
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


HASH_COMMENT_LANGUAGES = {"python", "ruby", "shell", "yaml"}


def _match_is_in_comment(text: str, offset: int, language: str = "") -> bool:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    column = offset - line_start
    stripped = line.lstrip()
    if language in HASH_COMMENT_LANGUAGES:
        if stripped.startswith("#"):
            return True
        comment_column = line.find("#")
        return comment_column != -1 and comment_column < column
    if stripped.startswith(("//", "/*", "*")):
        return True
    comment_column = line.find("//")
    return comment_column != -1 and comment_column < column


def _severity_sort(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)
