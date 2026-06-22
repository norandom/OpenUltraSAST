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
    cwe: str
    languages: tuple[str, ...]


C_LANGUAGES = ("c", "cpp")
PYTHON_LANGUAGES = ("python",)
JS_LANGUAGES = ("javascript", "typescript")
JAVA_LANGUAGES = ("java",)
GROOVY_LANGUAGES = ("groovy",)

PATTERN_RULES = (
    # --- C / C++ -----------------------------------------------------------------
    PatternRule(
        rule_id="c-unsafe-copy",
        title="Unsafe C string copy needs review",
        severity="high",
        tags=("memory_unsafe",),
        pattern=re.compile(r"\b(gets|strcpy|strcat|sprintf)\s*\("),
        cwe="CWE-121",
        languages=C_LANGUAGES,
    ),
    PatternRule(
        rule_id="c-unsafe-memory-copy",
        title="Unsafe C memory copy needs review",
        severity="high",
        tags=("memory_unsafe",),
        pattern=re.compile(r"\b(memcpy|memmove|bcopy)\s*\("),
        cwe="CWE-121",
        languages=C_LANGUAGES,
    ),
    PatternRule(
        rule_id="c-unsafe-format",
        title="Unsafe C format string needs review",
        severity="high",
        tags=("memory_unsafe",),
        # Flag format functions that receive a variable format string.
        # Calls with string literals, such as printf("..."), are ignored.
        pattern=re.compile(r"\b(printf|vprintf|vsprintf|vsnprintf|vfprintf|syslog)\s*\(\s*[A-Za-z_]"),
        cwe="CWE-134",
        languages=C_LANGUAGES,
    ),
    PatternRule(
        rule_id="c-unsafe-scanf",
        title="Unbounded C scanf needs review",
        severity="high",
        tags=("memory_unsafe",),
        pattern=re.compile(r"\b(scanf|fscanf|sscanf)\s*\([^\n]*%s"),
        cwe="CWE-121",
        languages=C_LANGUAGES,
    ),
    PatternRule(
        rule_id="c-shell-exec",
        title="C shell execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(system|popen)\s*\("),
        cwe="CWE-78",
        languages=C_LANGUAGES,
    ),
    PatternRule(
        rule_id="c-exec-family",
        title="C exec command execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(execl|execlp|execle|execv|execvp|execvpe)\s*\("),
        cwe="CWE-78",
        languages=C_LANGUAGES,
    ),
    # --- Python ------------------------------------------------------------------
    PatternRule(
        rule_id="python-unsafe-eval",
        title="Dynamic Python execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        cwe="CWE-95",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-os-command",
        title="Python OS command execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(os\.system|os\.popen|os\.execl|os\.execlp|os\.execv|os\.execvp)\s*\("),
        cwe="CWE-78",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-shell-true",
        title="Subprocess shell execution needs review",
        severity="medium",
        tags=("syscall_entry",),
        pattern=re.compile(r"subprocess\.[a-zA-Z_]+\s*\([^\n]*shell\s*=\s*True"),
        cwe="CWE-78",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-unsafe-deserialization",
        title="Unsafe Python deserialization needs review",
        severity="high",
        tags=("deserialization",),
        pattern=re.compile(r"\b(pickle\.loads|pickle\.load|cPickle\.loads|yaml\.load|marshal\.loads)\s*\("),
        cwe="CWE-502",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-sql-injection",
        title="Python SQL string composition needs review",
        severity="high",
        tags=("injection",),
        # Flag .execute(...) calls built with %-formatting, .format(), string
        # concatenation, or an f-string. Parameterised %s placeholders pass.
        pattern=re.compile(r"(\.execute)\s*\(\s*[^\n]*(?:[\"']\s*%\s*[(A-Za-z_]|\.format\s*\(|[\"']\s*\+|\bf[\"'])"),
        cwe="CWE-89",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-path-traversal",
        title="Python file open with external input needs review",
        severity="medium",
        tags=("filesystem_entry",),
        pattern=re.compile(r"\b(open)\s*\(\s*[^\n]*(?:request\.|req\.|argv|input\s*\(|params\[|GET\[|POST\[)"),
        cwe="CWE-22",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-ssrf",
        title="Python outbound request with external input needs review",
        severity="medium",
        tags=("network_entry",),
        pattern=re.compile(
            r"\b(requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|urlopen)\s*\(\s*[^\n]*(?:request\.|req\.|argv|input\s*\()"
        ),
        cwe="CWE-918",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-weak-hash",
        title="Python weak hash needs review",
        severity="low",
        tags=("crypto",),
        pattern=re.compile(r"\bhashlib\.(md5|sha1)\s*\("),
        cwe="CWE-327",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-ssti",
        title="Python server-side template injection needs review",
        severity="high",
        tags=("injection",),
        pattern=re.compile(r"\b(render_template_string)\s*\("),
        cwe="CWE-94",
        languages=PYTHON_LANGUAGES,
    ),
    PatternRule(
        rule_id="python-flask-debug",
        title="Flask debug mode enabled needs review",
        severity="low",
        tags=("insecure_default",),
        pattern=re.compile(r"\.run\s*\([^\n]*(debug)\s*=\s*True"),
        cwe="CWE-489",
        languages=PYTHON_LANGUAGES,
    ),
    # --- JavaScript / TypeScript -------------------------------------------------
    PatternRule(
        rule_id="js-command-exec",
        title="Node child_process command execution needs review",
        severity="high",
        tags=("syscall_entry",),
        # exec and execSync invoke a shell. execFile and spawn with an argv array
        # do not, so this rule leaves them alone.
        pattern=re.compile(r"\b(exec|execSync)\s*\("),
        cwe="CWE-78",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-spawn-shell",
        title="Node spawn with shell needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(spawn|spawnSync)\s*\([^\n]*shell\s*:\s*true"),
        cwe="CWE-78",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-eval",
        title="Dynamic JavaScript evaluation needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(eval)\s*\("),
        cwe="CWE-95",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-function-constructor",
        title="JavaScript Function constructor needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"new\s+(Function)\s*\("),
        cwe="CWE-95",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-xss-response",
        title="Unsanitized HTTP response reflection needs review",
        severity="high",
        tags=("injection",),
        pattern=re.compile(r"\.(send|write|end)\s*\(\s*[^\n]*\b(?:req|request)\.(?:query|params|body)"),
        cwe="CWE-79",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-dom-xss",
        title="DOM sink with untrusted input needs review",
        severity="high",
        tags=("injection",),
        pattern=re.compile(r"\.(innerHTML|outerHTML)\s*=\s*[^\n]*\b(?:req|request|location|document\.location)"),
        cwe="CWE-79",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-sql-injection",
        title="JavaScript SQL string composition needs review",
        severity="high",
        tags=("injection",),
        pattern=re.compile(r"\.(query|execute)\s*\(\s*[^\n]*(?:\$\{|\+\s*[A-Za-z_$])"),
        cwe="CWE-89",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-path-traversal",
        title="Node filesystem access with external input needs review",
        severity="medium",
        tags=("filesystem_entry",),
        pattern=re.compile(
            r"\bfs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|unlinkSync)\s*\(\s*[^\n]*\b(?:req|request)\."
        ),
        cwe="CWE-22",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-ssrf",
        title="JavaScript outbound request with external input needs review",
        severity="medium",
        tags=("network_entry",),
        pattern=re.compile(r"\b(axios|fetch|got)\s*[.(][^\n]*\b(?:req|request)\."),
        cwe="CWE-918",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-weak-hash",
        title="JavaScript weak hash needs review",
        severity="low",
        tags=("crypto",),
        pattern=re.compile(r"createHash\s*\(\s*[\"'](md5|sha1)[\"']"),
        cwe="CWE-327",
        languages=JS_LANGUAGES,
    ),
    PatternRule(
        rule_id="js-deserialize",
        title="JavaScript unsafe deserialization needs review",
        severity="high",
        tags=("deserialization",),
        pattern=re.compile(r"\b(unserialize)\s*\("),
        cwe="CWE-502",
        languages=JS_LANGUAGES,
    ),
    # --- Java --------------------------------------------------------------------
    PatternRule(
        rule_id="java-command-exec",
        title="Java runtime command execution needs review",
        severity="high",
        tags=("syscall_entry",),
        pattern=re.compile(r"\b(exec)\s*\("),
        cwe="CWE-78",
        languages=JAVA_LANGUAGES,
    ),
    PatternRule(
        rule_id="java-sql-injection",
        title="Java SQL string composition needs review",
        severity="high",
        tags=("injection",),
        # Flag SQL strings that start with a statement keyword and then concatenate
        # more data. Parameterised queries with placeholders are ignored.
        pattern=re.compile(r"(?i)\"\s*(select|insert|update|delete)\b[^\"]*\"\s*\+"),
        cwe="CWE-89",
        languages=JAVA_LANGUAGES,
    ),
    PatternRule(
        rule_id="java-weak-hash",
        title="Java weak hash needs review",
        severity="low",
        tags=("crypto",),
        pattern=re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1)\""),
        cwe="CWE-327",
        languages=JAVA_LANGUAGES,
    ),
    PatternRule(
        rule_id="java-deserialization",
        title="Java unsafe deserialization needs review",
        severity="high",
        tags=("deserialization",),
        pattern=re.compile(r"\.(readObject)\s*\("),
        cwe="CWE-502",
        languages=JAVA_LANGUAGES,
    ),
    # --- Groovy server-side templates -------------------------------------------
    PatternRule(
        rule_id="groovy-xss-unescaped",
        title="Groovy template unescaped output needs review",
        severity="high",
        tags=("injection",),
        # Flag unescaped bound variables. String literals are ignored.
        pattern=re.compile(r"(yieldUnescaped)\s+[A-Za-z_]"),
        cwe="CWE-79",
        languages=GROOVY_LANGUAGES,
    ),
)


def quick_scan_findings(root: Path, targets: list[FileTarget], rankings: list[RankingScore]) -> list[StaticFinding]:
    ranking_by_path = {ranking.path: ranking for ranking in rankings}
    findings: list[StaticFinding] = []
    for target in targets:
        text = _read_text(root / target.path)
        for rule in PATTERN_RULES:
            if rule.languages and target.language not in rule.languages:
                continue
            ranking = ranking_by_path.get(target.path)
            for match in rule.pattern.finditer(text):
                if _match_is_in_comment(text, match.start(), target.language):
                    continue
                findings.append(_finding_from_match(target, rule, text, match, ranking))
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
) -> StaticFinding:
    offset = match.start()
    line = text.count("\n", 0, offset) + 1
    reachability_status, function_name, reachability_evidence = _reachability_for_line(target, line)
    priority = ranking.priority if ranking is not None else 1.0
    matched_token = match.group(1) if match.groups() else match.group(0).split("(", 1)[0].strip()
    return StaticFinding(
        finding_id=f"{rule.rule_id}:{target.path}:{line}",
        path=target.path,
        title=rule.title,
        severity=rule.severity,
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
