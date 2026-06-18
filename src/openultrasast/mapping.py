from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal

from .preprocess import FileTarget

MappingKind = Literal["semgrep", "codeql", "differential", "sharp_edge"]
AccessLevel = Literal[
    "public",
    "authenticated",
    "role-restricted",
    "contract-only/callback",
    "local-only",
    "review-required",
]


@dataclass(frozen=True)
class StaticHint:
    analyzer: str
    rule_id: str
    title: str
    severity: str
    path: str
    start_line: int | None
    message: str
    fingerprint: str | None
    provenance: str
    evidence_candidate: bool = True


@dataclass(frozen=True)
class MappingTaskRecord:
    kind: MappingKind
    path: str
    rule_id: str
    task: str
    rationale: str


@dataclass(frozen=True)
class DifferentialMappingRecord:
    path: str
    change_kind: str
    trust_boundary: str | None
    rationale: str


@dataclass(frozen=True)
class SharpEdgeRecord:
    path: str
    category: str
    surface: str
    rationale: str


@dataclass(frozen=True)
class EntryPointRecord:
    path: str
    line: int | None
    end_line: int | None
    function_name: str | None
    name: str
    kind: str
    access_level: AccessLevel
    trust_boundary: str
    access_evidence: list[str]
    conditions: list[str]
    provenance: str
    rationale: str


def ingest_sarif(path: Path) -> list[StaticHint]:
    payload = json.loads(path.read_text())
    hints: list[StaticHint] = []
    for run in _items(payload.get("runs")):
        tool = run.get("tool") if isinstance(run, dict) else {}
        driver = tool.get("driver") if isinstance(tool, dict) else {}
        analyzer = _normalise_analyzer(str(driver.get("name", "sarif"))) if isinstance(driver, dict) else "sarif"
        rules = _rules_by_id(driver.get("rules", []) if isinstance(driver, dict) else [])
        for result in _items(run.get("results") if isinstance(run, dict) else []):
            hint = _hint_from_result(result, analyzer, rules)
            if hint is not None:
                hints.append(hint)
    return sorted(hints, key=lambda item: (item.path, item.start_line or 0, item.rule_id))


def attach_static_hints(targets: list[FileTarget], hints: list[StaticHint]) -> list[FileTarget]:
    hints_by_path: dict[str, list[dict[str, object]]] = {}
    for hint in hints:
        hints_by_path.setdefault(hint.path, []).append(asdict(hint))
    return [replace(target, static_hints=hints_by_path.get(target.path, target.static_hints)) for target in targets]


def analyze_entry_points(root: Path, targets: list[FileTarget]) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    for target in targets:
        path = root / target.path
        text = path.read_text(errors="ignore")
        records.extend(_language_entry_points(target, text))
        records.extend(_tag_entry_points(target))
    return sorted(records, key=lambda item: (item.path, item.line is None, item.line or 0, item.name))


def attach_reachability_hints(targets: list[FileTarget], entry_points: list[EntryPointRecord]) -> list[FileTarget]:
    hints_by_path: dict[str, list[dict[str, object]]] = {}
    for entry_point in entry_points:
        hints_by_path.setdefault(entry_point.path, []).append(asdict(entry_point))
    return [replace(target, reachability_hints=hints_by_path.get(target.path, target.reachability_hints)) for target in targets]


def verifier_evidence_candidates(hints: list[StaticHint], *, path: str | None = None) -> list[dict[str, object]]:
    selected = [hint for hint in hints if hint.evidence_candidate and (path is None or hint.path == path)]
    return [
        {
            "source": hint.analyzer,
            "rule_id": hint.rule_id,
            "path": hint.path,
            "line": hint.start_line,
            "severity": hint.severity,
            "message": hint.message,
            "provenance": hint.provenance,
        }
        for hint in selected
    ]


def semgrep_mapping_tasks(hints: list[StaticHint]) -> list[MappingTaskRecord]:
    return [
        MappingTaskRecord(
            kind="semgrep",
            path=hint.path,
            rule_id=hint.rule_id,
            task="pattern_variant_review",
            rationale="Use Semgrep evidence to check variants and rule precision before verifier promotion.",
        )
        for hint in hints
        if hint.analyzer == "semgrep"
    ]


def codeql_mapping_tasks(hints: list[StaticHint]) -> list[MappingTaskRecord]:
    return [
        MappingTaskRecord(
            kind="codeql",
            path=hint.path,
            rule_id=hint.rule_id,
            task="source_sink_sanitizer_path_review",
            rationale="Use CodeQL evidence to inspect source, sink, sanitizer, and path explanation.",
        )
        for hint in hints
        if hint.analyzer == "codeql"
    ]


def differential_mapping_record(path: str, *, change_kind: str, trust_boundary: str | None, rationale: str) -> DifferentialMappingRecord:
    return DifferentialMappingRecord(path=path, change_kind=change_kind, trust_boundary=trust_boundary, rationale=rationale)


def sharp_edge_record(path: str, *, category: str, surface: str, rationale: str) -> SharpEdgeRecord:
    return SharpEdgeRecord(path=path, category=category, surface=surface, rationale=rationale)


def write_static_hints(hints: list[StaticHint], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"static_hints": [asdict(hint) for hint in hints]}, indent=2, sort_keys=True) + "\n")


def write_entry_points(entry_points: list[EntryPointRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"entry_points": [asdict(entry_point) for entry_point in entry_points]}, indent=2, sort_keys=True) + "\n")


def _language_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    if target.language == "python":
        return _python_entry_points(target, text)
    if target.language in {"javascript", "typescript"}:
        return _js_entry_points(target, text)
    if target.language in {"c", "cpp"}:
        return _c_entry_points(target, text)
    if target.language == "solidity":
        return _solidity_entry_points(target, text)
    return []


def _python_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = [_safe_unparse(decorator) for decorator in node.decorator_list]
                route = next((decorator for decorator in decorators if _looks_like_route_decorator(decorator)), None)
                if route is not None:
                    access, evidence = _python_route_access(decorators)
                    conditions = _python_conditions(node, decorators)
                    records.append(
                        _entry(
                            target,
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            node.name,
                            node.name,
                            "route",
                            access,
                            "http_request",
                            evidence or [route],
                            conditions,
                        )
                    )
                if any("click.command" in decorator or ".command" in decorator for decorator in decorators):
                    records.append(
                        _entry(
                            target,
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            node.name,
                            node.name,
                            "cli",
                            "local-only",
                            "process_invocation",
                            decorators,
                            _python_conditions(node, decorators),
                        )
                    )
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("if __name__") and "__main__" in stripped:
            records.append(_entry(target, number, number, "__main__", "__main__", "cli", "local-only", "process_invocation", [stripped], []))
        if "argparse." in stripped or "click.command" in stripped:
            records.append(_entry(target, number, number, None, "cli_parser", "cli", "local-only", "process_invocation", [stripped], []))
    return records


def _js_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    route_tokens = (".get(", ".post(", ".put(", ".delete(", ".patch(", ".use(")
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if any(token in stripped for token in route_tokens) and any(prefix in stripped for prefix in ("app", "router", "server")):
            records.append(_entry(target, number, number, _js_handler_name(stripped), "http_handler", "route", "public", "http_request", [stripped], _line_conditions(stripped)))
        if "process.argv" in stripped:
            records.append(_entry(target, number, number, None, "process.argv", "cli", "local-only", "process_invocation", [stripped], _line_conditions(stripped)))
    return records


def _c_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if " main(" in f" {stripped}" or stripped.startswith("main("):
            records.append(_entry(target, number, number, "main", "main", "cli", "local-only", "process_invocation", [stripped], _line_conditions(stripped)))
        if "LLVMFuzzerTestOneInput" in stripped:
            records.append(_entry(target, number, number, "LLVMFuzzerTestOneInput", "LLVMFuzzerTestOneInput", "fuzz", "public", "fuzzer_input", [stripped], _line_conditions(stripped)))
    return records


def _solidity_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("function ") or not any(token in stripped for token in (" public", " external")):
            continue
        if " view" in stripped or " pure" in stripped:
            continue
        evidence = [token for token in ("onlyOwner", "onlyRole", "requiresAuth") if token in stripped]
        conditions = [token for token in ("whenNotPaused", "whenPaused", "featureEnabled") if token in stripped]
        access = "role-restricted" if evidence else "public"
        name = stripped.removeprefix("function ").split("(", 1)[0]
        if "callback" in name.lower() or name.startswith("onERC"):
            access = "contract-only/callback"
            evidence.append("callback naming convention")
        records.append(_entry(target, number, number, name, name, "smart_contract_state_change", access, "contract_call", evidence or ["external/public function"], conditions))
    return records


def _tag_entry_points(target: FileTarget) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    tags = set(target.tags)
    if "parser" in tags or "deserialization" in tags:
        records.append(_entry(target, None, None, None, "parser_input", "parser", "public", "attacker_controlled_input", ["parser/deserialization file tag"], []))
    if "network_entry" in tags:
        records.append(_entry(target, None, None, None, "network_surface", "route", "public", "network_request", ["network entry file tag"], []))
    if "auth_boundary" in tags:
        records.append(_entry(target, None, None, None, "auth_boundary", "privileged_surface", "authenticated", "identity_boundary", ["auth boundary file tag"], []))
    if "syscall_entry" in tags or "filesystem_entry" in tags:
        records.append(_entry(target, None, None, None, "local_privileged_boundary", "privileged_surface", "local-only", "local_process", ["syscall/filesystem file tag"], []))
    return records


def _entry(
    target: FileTarget,
    line: int | None,
    end_line: int | None,
    function_name: str | None,
    name: str,
    kind: str,
    access_level: AccessLevel,
    trust_boundary: str,
    access_evidence: list[str],
    conditions: list[str],
) -> EntryPointRecord:
    return EntryPointRecord(
        path=target.path,
        line=line,
        end_line=end_line,
        function_name=function_name,
        name=name,
        kind=kind,
        access_level=access_level,
        trust_boundary=trust_boundary,
        access_evidence=access_evidence,
        conditions=conditions,
        provenance=f"entrypoint:{kind}:{access_level}",
        rationale=f"{kind} surface classified as {access_level} at {trust_boundary}",
    )


def _looks_like_route_decorator(line: str) -> bool:
    return any(token in line for token in ("route", ".get", ".post", ".put", ".delete", ".patch"))


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


def _python_route_access(decorators: list[str]) -> tuple[AccessLevel, list[str]]:
    role_tokens = ("role", "permission", "admin", "owner")
    auth_tokens = ("login_required", "authenticated", "auth", "jwt_required")
    access_decorators = [decorator for decorator in decorators if not _looks_like_route_decorator(decorator)]
    evidence = [decorator for decorator in access_decorators if any(token in decorator.lower() for token in role_tokens + auth_tokens)]
    lowered = "\n".join(evidence).lower()
    if any(token in lowered for token in role_tokens):
        return "role-restricted", evidence
    if any(token in lowered for token in auth_tokens):
        return "authenticated", evidence
    return "public", evidence


def _python_conditions(node: ast.FunctionDef | ast.AsyncFunctionDef, decorators: list[str]) -> list[str]:
    conditions = [decorator for decorator in decorators if _looks_conditional(decorator)]
    for child in ast.walk(node):
        if isinstance(child, ast.If):
            test = _safe_unparse(child.test)
            if _looks_conditional(test):
                conditions.append(test)
    return sorted(set(conditions))


def _line_conditions(line: str) -> list[str]:
    return [line] if _looks_conditional(line) else []


def _looks_conditional(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("feature", "flag", "toggle", "enabled", "disabled", "experiment", "beta", "rollout", "paused"))


def _js_handler_name(line: str) -> str | None:
    if "function " in line:
        return line.split("function ", 1)[1].split("(", 1)[0].strip() or None
    if "=>" in line:
        return "arrow_handler"
    return None


def _hint_from_result(result: object, analyzer: str, rules: dict[str, dict[str, object]]) -> StaticHint | None:
    if not isinstance(result, dict):
        return None
    rule_id = str(result.get("ruleId", "unknown"))
    location = _primary_location(result)
    if location is None:
        return None
    artifact = location.get("physicalLocation", {}).get("artifactLocation", {})
    region = location.get("physicalLocation", {}).get("region", {})
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri:
        return None
    rule = rules.get(rule_id, {})
    message = result.get("message", {})
    message_text = message.get("text") if isinstance(message, dict) else None
    return StaticHint(
        analyzer=analyzer,
        rule_id=rule_id,
        title=str(rule.get("name") or rule.get("shortDescription") or rule_id),
        severity=_severity(result, rule),
        path=uri.lstrip("./"),
        start_line=region.get("startLine") if isinstance(region.get("startLine"), int) else None,
        message=message_text if isinstance(message_text, str) else rule_id,
        fingerprint=_fingerprint(result),
        provenance=f"sarif:{analyzer}:{rule_id}",
    )


def _primary_location(result: dict[str, object]) -> dict[str, Any] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    return locations[0]


def _rules_by_id(rules: object) -> dict[str, dict[str, object]]:
    by_id: dict[str, dict[str, object]] = {}
    for rule in _items(rules):
        rule_id = rule.get("id") if isinstance(rule, dict) else None
        if isinstance(rule_id, str):
            by_id[rule_id] = rule
    return by_id


def _severity(result: dict[str, object], rule: dict[str, object]) -> str:
    level = result.get("level")
    if level == "error":
        return "high"
    if level == "warning":
        return "medium"
    properties = rule.get("properties")
    if isinstance(properties, dict) and "security-severity" in properties:
        try:
            return "high" if float(properties["security-severity"]) >= 7.0 else "medium"
        except (TypeError, ValueError):
            return "medium"
    return "low"


def _fingerprint(result: dict[str, object]) -> str | None:
    for key in ("partialFingerprints", "fingerprints"):
        value = result.get(key)
        if isinstance(value, dict) and value:
            first = next(iter(value.values()))
            return str(first)
    return None


def _normalise_analyzer(name: str) -> str:
    lowered = name.lower()
    if "semgrep" in lowered:
        return "semgrep"
    if "codeql" in lowered:
        return "codeql"
    return lowered.replace(" ", "_") or "sarif"


def _items(value: object) -> list[object]:
    return value if isinstance(value, list) else []
