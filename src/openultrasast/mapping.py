from __future__ import annotations

import ast
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal, cast

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
    # Did the access level come from a DECLARATION, or from the absence of one?
    #
    # The distinction decides whether "public" can be trusted. An OpenAPI operation with no `security` block
    # is declared open, because the spec is a complete contract; a WordPress `wp_ajax_nopriv_` hook is
    # WordPress saying logged-out callers reach this. But a Flask handler with no `@login_required` is
    # "public" only because nothing was found -- which is precisely the bug the access-control family exists
    # to report, so treating it as a declaration would silence the detector on its primary case.
    access_declared: bool = False


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
    records.extend(_route_manifest_entry_points(root, targets))
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
    if target.language == "php":
        return _php_entry_points(target, text)
    return []


# WordPress registers handlers rather than decorating them, and the hook name states the access level:
# `wp_ajax_nopriv_*` is admin-ajax for logged-OUT users and is therefore declared public, while `wp_ajax_*`
# fires only for logged-in ones. That is a DECLARED access level, not a guess from an absent decorator, which
# is the distinction task 2.8 turns on.
# A callback is a bare string OR an array callable. `array( $this, 'method' )` is the normal form in a
# class-based plugin -- Paid Memberships Pro registers every REST route that way -- and matching only the
# string form left its handlers ranked as plain functions, below the budget, so the entry point that carries
# CVE-2023-23488's source was never asked about.
_PHP_CALLABLE = (
    r"""(?:['"](?P<handler>[A-Za-z_][A-Za-z0-9_]*)['"]|(?:array\s*\(|\[)\s*\$this\s*,\s*['"](?P<method>[A-Za-z_][A-Za-z0-9_]*)['"])"""
)
_PHP_REGISTRATION = re.compile(
    r"""\b(?P<call>add_action|add_filter|add_shortcode)\s*\(\s*['"](?P<hook>[^'"]+)['"]\s*,\s*""" + _PHP_CALLABLE,
    re.VERBOSE,
)
_PHP_REST_ROUTE = re.compile(r"\bregister_rest_route\s*\(")
_PHP_CALLBACK = re.compile(r"""['"]callback['"]\s*=>\s*""" + _PHP_CALLABLE)
_PHP_PERMISSION = re.compile(r"""['"]permission_callback['"]\s*=>\s*(?P<value>[^,\)]+)""")
# A method carries visibility and modifiers before `function`, and modern PHP always writes them. Matching
# only a bare `function` made every class-based plugin ONE file-level region: MW WP Form's
# `protected function _delete_files()` was invisible, while Paid Memberships Pro's methods happened to
# work because that file omits the modifiers.
_PHP_FUNCTION = re.compile(
    r"^\s*(?:(?:final|abstract|public|protected|private|static)\s+)*function\s+&?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)


def _php_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    """WordPress's registration model, plus every top-level function as a region of its own.

    The functions matter as much as the hooks. Without them a PHP file is ONE file-level region, and a region
    that spans a file attributes every finding to the file rather than to the function that holds it.
    """
    records: list[EntryPointRecord] = []
    lines = text.splitlines()
    bounds = _php_function_bounds(lines)

    for number, line in enumerate(lines, start=1):
        for match in _PHP_REGISTRATION.finditer(line):
            hook = match.group("hook")
            handler = match.group("handler") or match.group("method")
            if not handler:
                continue
            access, evidence = _wordpress_hook_access(match.group("call"), hook)
            start, end = bounds.get(handler, (number, number))
            records.append(
                _entry(target, start, end, handler, f"wp:{hook}", "route", access, "http_request", evidence, [], access_declared=True)
            )
        if _PHP_REST_ROUTE.search(line):
            window = "\n".join(lines[number - 1 : number + 12])
            callback = _PHP_CALLBACK.search(window)
            if callback is not None:
                handler = callback.group("handler") or callback.group("method")
                if not handler:
                    continue
                permission = _PHP_PERMISSION.search(window)
                access, evidence = _rest_route_access(permission.group("value").strip() if permission else None)
                start, end = bounds.get(handler, (number, number))
                records.append(
                    _entry(
                        target, start, end, handler, "wp:rest_route", "route", access, "http_request", evidence, [], access_declared=True
                    )
                )

    registered = {record.function_name for record in records}
    for name, (start, end) in sorted(bounds.items()):
        if name not in registered:
            records.append(
                _entry(target, start, end, name, f"php:{name}", "function", "review-required", "call", ["php function declaration"], [])
            )
    return records


def _wordpress_hook_access(call: str, hook: str) -> tuple[AccessLevel, list[str]]:
    """The hook name is the declaration. `nopriv` is WordPress saying "logged-out callers reach this"."""
    if hook.startswith("wp_ajax_nopriv_"):
        return "public", [f"{call}('{hook}') is admin-ajax for logged-out callers"]
    if hook.startswith("wp_ajax_"):
        return "authenticated", [f"{call}('{hook}') fires only for logged-in callers"]
    if call == "add_shortcode":
        return "public", [f"add_shortcode('{hook}') renders in page content"]
    return "review-required", [f"{call}('{hook}')"]


def _rest_route_access(permission: str | None) -> tuple[AccessLevel, list[str]]:
    """`permission_callback` is the REST contract. `__return_true` declares the route open."""
    if permission is None:
        return "review-required", ["register_rest_route with no permission_callback"]
    if "__return_true" in permission:
        return "public", ["permission_callback => __return_true declares the route public"]
    return "authenticated", [f"permission_callback => {permission[:60]}"]


def _php_function_bounds(lines: Sequence[str]) -> dict[str, tuple[int, int]]:
    """Line ranges of top-level PHP functions, by brace depth. Good enough to scope a region."""
    bounds: dict[str, tuple[int, int]] = {}
    name: str | None = None
    start = 0
    depth = 0
    for number, line in enumerate(lines, start=1):
        if name is None:
            match = _PHP_FUNCTION.match(line)
            if match is not None:
                name, start, depth = match.group("name"), number, 0
        if name is not None:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "{" in "".join(lines[start - 1 : number]):
                bounds[name] = (start, number)
                name = None
    return bounds


def _python_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        records.extend(_python_registered_routes(target, tree))
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
            records.append(
                _entry(target, number, number, "__main__", "__main__", "cli", "local-only", "process_invocation", [stripped], [])
            )
        if "argparse." in stripped or "click.command" in stripped:
            records.append(_entry(target, number, number, None, "cli_parser", "cli", "local-only", "process_invocation", [stripped], []))
    return records


def _js_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    route_tokens = (".get(", ".post(", ".put(", ".delete(", ".patch(", ".use(")
    lines = text.splitlines()
    bounds = _js_function_bounds(lines)
    for number, stripped in _js_statements(lines):
        if any(token in stripped for token in route_tokens) and any(prefix in stripped.lower() for prefix in ("app", "router", "server")):
            handler, middleware = _js_registration(stripped, bounds)
            access, evidence = _js_route_access(middleware, stripped)
            start, end = bounds.get(handler or "", (number, number))
            records.append(
                _entry(
                    target,
                    start,
                    end,
                    handler or _js_handler_name(stripped),
                    "http_handler",
                    "route",
                    access,
                    "http_request",
                    evidence,
                    _line_conditions(stripped),
                )
            )
        if "process.argv" in stripped:
            records.append(
                _entry(
                    target,
                    number,
                    number,
                    None,
                    "process.argv",
                    "cli",
                    "local-only",
                    "process_invocation",
                    [stripped],
                    _line_conditions(stripped),
                )
            )
    records.extend(_js_route_module(target, lines, bounds))
    return records


_OPERATION_ID = re.compile(r"""^\s*(?:-\s*)?["']?operationId["']?\s*:\s*["']?([\w.]+)["']?,?\s*$""")
_MANIFEST_SUFFIXES = (".yml", ".yaml", ".json")
_MANIFEST_MAX_BYTES = 2_000_000


def _route_manifest_entry_points(root: Path, targets: Sequence[FileTarget]) -> list[EntryPointRecord]:
    """Handlers a *document* registers: an OpenAPI `operationId` names the function connexion, FastAPI-from-spec or an
    API gateway will call, and the `security` block beside it is the guard.

    Frameworks that keep the route table out of the handler file leave every handler looking like a plain function, so
    an absence bug on one is unreachable and unjudgeable. The document itself is not a source file — it never becomes a
    file target — so the record is attributed to the module the operation id points at when that module is present
    (learning-harness Req 10.2)."""
    modules = {target.path for target in targets}
    records: list[EntryPointRecord] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _MANIFEST_SUFFIXES:
            continue
        try:
            if path.stat().st_size > _MANIFEST_MAX_BYTES:
                continue
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        for index, line in enumerate(lines):
            match = _OPERATION_ID.match(line)
            if match is None:
                continue
            operation = match.group(1)
            handler = operation.rsplit(".", 1)[-1]
            owner = _operation_module(operation, modules)
            access, evidence = _manifest_access(lines, index)
            records.append(
                EntryPointRecord(
                    path=owner or relative,
                    line=None if owner else index + 1,
                    end_line=None if owner else index + 1,
                    function_name=handler,
                    name=operation,
                    kind="route",
                    access_level=access,
                    trust_boundary="http_request",
                    access_evidence=evidence,
                    conditions=[],
                    provenance=f"entrypoint:route:{access}",
                    rationale=f"registered by operationId {operation} in {relative}",
                    # A route manifest is a complete contract: an operation with no `security` block is
                    # declared open, not merely undecorated.
                    access_declared=True,
                )
            )
    return records


def _operation_module(operation: str, modules: set[str]) -> str | None:
    """`api_views.books.get_by_title` -> `api_views/books.py` when that file is in the snapshot."""
    parts = operation.split(".")
    if len(parts) < 2:
        return None
    for depth in range(len(parts) - 1, 0, -1):
        candidate = "/".join(parts[:depth]) + ".py"
        if candidate in modules:
            return candidate
    return None


def _manifest_access(lines: Sequence[str], hit: int) -> tuple[AccessLevel, list[str]]:
    """The operation's own `security` block decides. `security: []` is an explicit opt-out and stays public."""
    indent = len(lines[hit]) - len(lines[hit].lstrip())
    start = hit
    while start > 0 and (not lines[start - 1].strip() or len(lines[start - 1]) - len(lines[start - 1].lstrip()) >= indent):
        start -= 1
    end = hit + 1
    while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) >= indent):
        end += 1
    for index in range(start, end):
        stripped = lines[index].strip()
        if not stripped.startswith("security"):
            continue
        if stripped.replace(" ", "") in {"security:[]", '"security":[]', "security:[],", '"security":[],'}:
            return "public", [f"{stripped} declares the operation public"]
        return "authenticated", [f"security block at {lines[index].strip()}"]
    return "public", ["operation declares no security requirement"]


_RESOURCE_BASES = ("resource", "methodview", "apiview", "viewset", "modelviewset", "httpendpoint")
_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")


def _python_registered_routes(target: FileTarget, tree: ast.AST) -> list[EntryPointRecord]:
    """Handlers whose route is registered by a call or by convention, not by a decorator on the function itself
    (authorization-obligations 2.6): `add_url_rule(path, view_func=fn)`, `api.add_resource(Cls, path)`, and the HTTP-verb
    methods of a `Resource`/`MethodView`/`APIView`/`ViewSet` subclass. Without these, projects that register their routes
    elsewhere have no named entry point and every obligation on them is unreachable."""
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    classes: dict[str, ast.ClassDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            classes.setdefault(node.name, node)
    registered_functions: set[str] = set()
    registered_classes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _safe_unparse(node.func)
        trailing = callee.rsplit(".", 1)[-1]
        if trailing == "add_url_rule":
            for keyword in node.keywords:
                if keyword.arg == "view_func":
                    registered_functions.add(_safe_unparse(keyword.value).split(".")[0])
            registered_functions.update(_safe_unparse(arg) for arg in node.args[1:2] if isinstance(arg, ast.Name))
        elif trailing in {"add_resource", "register_blueprint", "include_router"} or trailing == "add_view":
            registered_classes.update(_safe_unparse(arg) for arg in node.args if isinstance(arg, ast.Name))
            registered_functions.update(_safe_unparse(arg) for arg in node.args if isinstance(arg, ast.Name))
    records: list[EntryPointRecord] = []
    for name in sorted(registered_functions):
        handler = functions.get(name)
        if handler is None or _has_route_decorator(handler):
            continue
        decorators = [_safe_unparse(decorator) for decorator in handler.decorator_list]
        access, evidence = _python_route_access(decorators)
        records.append(
            _entry(
                target,
                handler.lineno,
                getattr(handler, "end_lineno", handler.lineno),
                handler.name,
                handler.name,
                "route",
                access,
                "http_request",
                evidence or [f"registered handler {handler.name}"],
                _python_conditions(handler, decorators),
            )
        )
    for name, klass in sorted(classes.items()):
        bases = [_safe_unparse(base).rsplit(".", 1)[-1].lower() for base in klass.bases]
        if name not in registered_classes and not any(base in _RESOURCE_BASES for base in bases):
            continue
        class_decorators = [_safe_unparse(decorator) for decorator in klass.decorator_list]
        for child in klass.body:
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) or child.name.lower() not in _HTTP_VERBS:
                continue
            decorators = class_decorators + [_safe_unparse(decorator) for decorator in child.decorator_list]
            access, evidence = _python_route_access(decorators)
            records.append(
                _entry(
                    target,
                    child.lineno,
                    getattr(child, "end_lineno", child.lineno),
                    child.name,
                    f"{name}.{child.name}",
                    "route",
                    access,
                    "http_request",
                    evidence or [f"{name} handler method {child.name}"],
                    _python_conditions(child, decorators),
                )
            )
    return records


def _has_route_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_looks_like_route_decorator(_safe_unparse(decorator)) for decorator in node.decorator_list)


def _c_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if " main(" in f" {stripped}" or stripped.startswith("main("):
            records.append(
                _entry(
                    target,
                    number,
                    number,
                    "main",
                    "main",
                    "cli",
                    "local-only",
                    "process_invocation",
                    [stripped],
                    _line_conditions(stripped),
                )
            )
        if "LLVMFuzzerTestOneInput" in stripped:
            records.append(
                _entry(
                    target,
                    number,
                    number,
                    "LLVMFuzzerTestOneInput",
                    "LLVMFuzzerTestOneInput",
                    "fuzz",
                    "public",
                    "fuzzer_input",
                    [stripped],
                    _line_conditions(stripped),
                )
            )
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
        access: AccessLevel = "role-restricted" if evidence else "public"
        name = stripped.removeprefix("function ").split("(", 1)[0]
        if "callback" in name.lower() or name.startswith("onERC"):
            access = "contract-only/callback"
            evidence.append("callback naming convention")
        records.append(
            _entry(
                target,
                number,
                number,
                name,
                name,
                "smart_contract_state_change",
                access,
                "contract_call",
                evidence or ["external/public function"],
                conditions,
            )
        )
    return records


def _tag_entry_points(target: FileTarget) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    tags = set(target.tags)
    if "parser" in tags or "deserialization" in tags:
        records.append(
            _entry(
                target,
                None,
                None,
                None,
                "parser_input",
                "parser",
                "public",
                "attacker_controlled_input",
                ["parser/deserialization file tag"],
                [],
            )
        )
    if "network_entry" in tags:
        records.append(
            _entry(target, None, None, None, "network_surface", "route", "public", "network_request", ["network entry file tag"], [])
        )
    if "auth_boundary" in tags:
        records.append(
            _entry(
                target,
                None,
                None,
                None,
                "auth_boundary",
                "privileged_surface",
                "authenticated",
                "identity_boundary",
                ["auth boundary file tag"],
                [],
            )
        )
    if "syscall_entry" in tags or "filesystem_entry" in tags:
        records.append(
            _entry(
                target,
                None,
                None,
                None,
                "local_privileged_boundary",
                "privileged_surface",
                "local-only",
                "local_process",
                ["syscall/filesystem file tag"],
                [],
            )
        )
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
    access_declared: bool = False,
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
        access_declared=access_declared,
    )


def _looks_like_route_decorator(line: str) -> bool:
    return any(token in line for token in ("route", ".get", ".post", ".put", ".delete", ".patch"))


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


_STRING_LITERAL = re.compile(r"""(['"]).*?\1""", re.DOTALL)


def _python_route_access(decorators: list[str]) -> tuple[AccessLevel, list[str]]:
    """The guard is the decorator's *name*, never its prose.

    `@ns.doc(description='... without proper authorization checks')` documents the bug; matching "authorization"
    inside it reads an unguarded endpoint as guarded and silences every obligation on it, which is exactly the
    absence the corpus exists to catch (learning-harness Req 10.2)."""
    role_tokens = ("role", "permission", "admin", "owner")
    auth_tokens = ("login_required", "authenticated", "auth", "jwt_required", "token_required", "require_token")
    access_decorators = [decorator for decorator in decorators if not _looks_like_route_decorator(decorator)]
    named = {decorator: _STRING_LITERAL.sub("", decorator).lower() for decorator in access_decorators}
    evidence = [decorator for decorator in access_decorators if any(token in named[decorator] for token in role_tokens + auth_tokens)]
    lowered = "\n".join(named[decorator] for decorator in evidence)
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
    return any(
        token in lowered for token in ("feature", "flag", "toggle", "enabled", "disabled", "experiment", "beta", "rollout", "paused")
    )


_JS_FUNCTION = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")
_JS_EXPORTED_VERB = re.compile(r"^\s*export\s+(?:async\s+)?(?:function\s+([A-Z]+)|const\s+([A-Z]+)\s*=)")
_JS_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$.]*$")
_JS_AUTH_TOKENS = ("auth", "login", "session", "jwt", "token", "protect", "guard", "require")
_JS_ROLE_TOKENS = ("role", "permission", "admin", "owner")


def _js_function_bounds(lines: Sequence[str]) -> dict[str, tuple[int, int]]:
    """Declared function names to their 1-based line span, by brace balance from the declaration."""
    bounds: dict[str, tuple[int, int]] = {}
    for index, line in enumerate(lines):
        match = _JS_FUNCTION.match(line)
        if match is None:
            continue
        depth = 0
        end = index
        for cursor in range(index, len(lines)):
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            end = cursor
            if depth <= 0 and "{" in "".join(lines[index : cursor + 1]):
                break
        bounds.setdefault(match.group(1), (index + 1, end + 1))
    return bounds


def _js_statements(lines: Sequence[str]) -> list[tuple[int, str]]:
    """One entry per statement, with the line its first token sits on.

    An express route is often written over several lines, one middleware per line, and the guard is exactly what
    those middle lines say. Read line by line, `webRouter.post(` carries no handler and no middleware at all, so the
    route reads as public and the handler is never named (learning-harness Req 10.2)."""
    statements: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        joined, span = stripped, 1
        while joined.count("(") > joined.count(")") and span < _MAX_STATEMENT_LINES and index + span < len(lines):
            joined = f"{joined} {lines[index + span].strip()}"
            span += 1
        if span > 1 and joined.count("(") <= joined.count(")"):
            statements.append((index + 1, joined))
            index += span
            continue
        statements.append((index + 1, stripped))
        index += 1
    return statements


_MAX_STATEMENT_LINES = 12


def _js_registration(line: str, bounds: Mapping[str, tuple[int, int]]) -> tuple[str | None, list[str]]:
    """`router.get('/books', requireAuth, listBooks)` -> the handler identifier and the middleware identifiers before it."""
    body = line[line.find("(") + 1 : line.rfind(")")] if "(" in line and line.rfind(")") > line.find("(") else ""
    parts = [part.strip() for part in body.split(",") if part.strip()]
    identifiers = [part for part in parts[1:] if _JS_IDENTIFIER.match(part)]
    if not identifiers:
        return None, [line]
    handler = next((name for name in reversed(identifiers) if name in bounds or name.rsplit(".", 1)[-1] in bounds), identifiers[-1])
    middleware = [name for name in identifiers if name != handler]
    return handler.rsplit(".", 1)[-1], middleware  # `ExportsController.exportProject` is registered; `exportProject` is defined


def _js_route_access(middleware: Sequence[str], line: str) -> tuple[AccessLevel, list[str]]:
    lowered = " ".join(middleware).lower()
    evidence = [f"middleware {name}" for name in middleware] or [line]
    if any(token in lowered for token in _JS_ROLE_TOKENS):
        return "role-restricted", evidence
    if any(token in lowered for token in _JS_AUTH_TOKENS):
        return "authenticated", evidence
    return "public", evidence


def _js_route_module(target: FileTarget, lines: Sequence[str], bounds: Mapping[str, tuple[int, int]]) -> list[EntryPointRecord]:
    """Next.js App Router convention: exported HTTP-verb functions in a `route.<ext>` module are the handlers."""
    if Path(target.path).stem != "route":
        return []
    verbs = {verb.upper() for verb in _HTTP_VERBS}
    records: list[EntryPointRecord] = []
    for index, line in enumerate(lines, start=1):
        match = _JS_EXPORTED_VERB.match(line)
        name = (match.group(1) or match.group(2)) if match else None
        if name is None or name not in verbs:
            continue
        start, end = bounds.get(name, (index, index))
        records.append(
            _entry(target, start, end, name, f"route.{name}", "route", "public", "http_request", [f"route module export {name}"], [])
        )
    return records


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
            by_id[rule_id] = cast("dict[str, object]", rule)
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
