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
    "unknown",
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
    # Does the file this record belongs to actually DEFINE the handler it names?
    #
    # A route-registration module registers handlers that live elsewhere: NodeGoat's `index.js`
    # requires seven handler modules and defines none. The record still names the handler, because
    # the authorization question is about which middleware guards which handler and that is
    # inherently cross-file. But a REGION scoped to a function its file does not hold is a question
    # the graph cannot answer, and 138 questions across six families were unresolvable for exactly
    # that reason on one repository. The region builder uses this to scope such an entry to the file.
    defines_handler: bool = True
    # Did the access level come from a DECLARATION, or from the absence of one?
    #
    # The distinction decides whether "public" can be trusted. An OpenAPI operation with no `security` block
    # is declared open, because the spec is a complete contract; a WordPress `wp_ajax_nopriv_` hook is
    # WordPress saying logged-out callers reach this. But a Flask handler with no `@login_required` is
    # "public" only because nothing was found -- which is precisely the bug the access-control family exists
    # to report, so treating it as a declaration would silence the detector on its primary case.
    access_declared: bool = False
    # The registry call that made this function an entry, when a string-keyed registry did (`add_action`,
    # `add_filter`, `add_shortcode`). Such a callback is handed its arguments BY THE REGISTRY -- whatever the
    # matching `do_action`/`apply_filters` passes -- not by the request, which is what the scan's parameter
    # rule needs to know. Empty for every entry that did not come from a registration.
    registered_by: str = ""


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


def analyze_entry_points(
    root: Path, targets: list[FileTarget], *, texts: Mapping[str, str] | None = None, include_manifests: bool = True
) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    source_texts = dict(texts) if texts is not None else {t.path: (root / t.path).read_text(errors="ignore") for t in targets}
    if texts is None:
        for config in framework_config_paths(root):
            source_texts[config] = (root / config).read_text(errors="ignore")
    for target in targets:
        text = source_texts[target.path]
        records.extend(_language_entry_points(target, text))
        if target.language == "php":
            framework_entries = _php_framework_entries(target, text, source_texts)
            names = {e.function_name for e in framework_entries}
            records = [e for e in records if not (e.path == target.path and e.kind == "function" and e.function_name in names)]
            records.extend(framework_entries)
        records.extend(_tag_entry_points(target))
    if include_manifests:
        records.extend(_route_manifest_entry_points(root, targets))
    return sorted(records, key=lambda item: (item.path, item.line is None, item.line or 0, item.name))


def php_hook_callbacks(root: Path, targets: list[FileTarget], register_calls: Sequence[str] | None = None) -> dict[str, tuple[str, ...]]:
    """WordPress's hook registry, read out of the source text because the graph does not carry it.

    `php2cpg` 4.0.623 drops the callback argument of a registration entirely. What the CPG holds is

        add_filter("wp_statistics_current_page", )

    with an empty second argument, so the link between a hook and its handler cannot be recovered from the
    graph at any price. It can be recovered from the source, where both ends are string literals -- and that
    is the same place, and the same regex, the entry-point mapper already reads them from.

    This is the link table for the hook half of the two-stage join (task 5.11). It is deliberately a plain
    name-to-names mapping with no inference in it: a hook whose name is computed (`"save_post_" . $type`)
    simply does not appear, rather than being guessed at.

    ``register_calls`` comes from the semantic fact tables and defaults to whatever they declare for PHP.
    Nothing here knows what WordPress is: the registry shape is general -- Django signals, jQuery events, a
    plugin system's event bus -- and a second framework is a row in a TOML, not a change to this function.
    """
    if register_calls is None:
        from .semantic.facts import load_facts

        register_calls = tuple(sorted({call for fact in load_facts().for_language("php").dispatches for call in fact.register}))
    if not register_calls:
        return {}
    pattern = re.compile(
        r"""\b(?P<call>"""
        + "|".join(re.escape(name) for name in register_calls)
        + r""")\s*\(\s*['"](?P<hook>[^'"]+)['"]\s*,\s*"""
        + _PHP_CALLABLE,
        re.VERBOSE,
    )
    table: dict[str, set[str]] = {}
    for target in targets:
        if target.language != "php":
            continue
        try:
            text = (root / target.path).read_text(errors="ignore")
        except OSError:
            continue
        for match in pattern.finditer(text):
            handler = match.group("handler") or match.group("method")
            if handler:
                table.setdefault(match.group("hook"), set()).add(handler)
    return {hook: tuple(sorted(names)) for hook, names in sorted(table.items())}


def attach_reachability_hints(targets: list[FileTarget], entry_points: list[EntryPointRecord]) -> list[FileTarget]:
    hints_by_path: dict[str, list[dict[str, object]]] = {}
    for entry_point in entry_points:
        hints_by_path.setdefault(entry_point.path, []).append(asdict(entry_point))
    return [replace(target, reachability_hints=hints_by_path.get(target.path, target.reachability_hints)) for target in targets]


def write_static_hints(hints: list[StaticHint], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"static_hints": [asdict(hint) for hint in hints]}, indent=2, sort_keys=True) + "\n")


def write_entry_points(entry_points: list[EntryPointRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"entry_points": [asdict(entry_point) for entry_point in entry_points]}, indent=2, sort_keys=True) + "\n")


def _language_entry_points(target: FileTarget, text: str) -> list[EntryPointRecord]:
    if target.language == "java":
        return _stapler_entries(target, text) + _jetty_entries(target, text)
    if target.language == "python":
        return _python_entry_points(target, text) + _tornado_entries(target, text)
    if target.language in {"javascript", "typescript"}:
        return _js_entry_points(target, text) + _remix_exports(target, text)
    if target.language in {"c", "cpp"}:
        return _c_entry_points(target, text)
    if target.language == "solidity":
        return _solidity_entry_points(target, text)
    if target.language == "php":
        return _php_entry_points(target, text)
    return []


def framework_config_paths(root: Path) -> list[str]:
    """Small, declared configuration locations outside the product source census."""
    candidates = [
        root / "config" / name for name in ("routes.yaml", "routes.yml", "routes.xml", "packages/security.yaml", "packages/security.yml")
    ]
    candidates.extend((root / "config/routes").glob("*.yaml"))
    candidates.extend((root / "config/routes").glob("*.yml"))
    return sorted(path.relative_to(root).as_posix() for path in candidates if path.is_file() and not path.is_symlink())


@dataclass(frozen=True)
class _PhpMethod:
    owner: str
    owner_header: str
    owner_attributes: str
    name: str
    line: int
    end_line: int
    header: str
    body: str


def _php_methods(text: str) -> list[_PhpMethod]:
    """CST class and method boundaries, including the method's own attributes and docblock."""
    from .semantic.extra import grammar_for

    grammar = grammar_for("php")
    if grammar is None:
        return []
    from tree_sitter import Parser

    data = text.encode()
    parser = Parser(grammar)
    tree = parser.parse(data)
    if tree.root_node.has_error:
        return []
    result: list[_PhpMethod] = []

    def value(node: Any) -> str:
        return data[node.start_byte : node.end_byte].decode()

    def walk(node: Any, owner: str = "", header: str = "", attributes: str = "", prior_comment: str = "") -> None:
        if node.type == "class_declaration":
            name, body = node.child_by_field_name("name"), node.child_by_field_name("body")
            owner = value(name) if name is not None else ""
            header = data[node.start_byte : body.start_byte if body else node.end_byte].decode()
            attributes = header + prior_comment
        if node.type == "method_declaration" and owner:
            name, body = node.child_by_field_name("name"), node.child_by_field_name("body")
            if name is not None and body is not None:
                own_header = data[node.start_byte : body.start_byte].decode()
                declaration = re.search(r"\bfunction\b", own_header)
                line = data[: node.start_byte].count(b"\n") + 1 + own_header[: declaration.start() if declaration else 0].count("\n")
                own_header = prior_comment + own_header
                result.append(
                    _PhpMethod(
                        owner, header, attributes, value(name), line, data[: node.end_byte].count(b"\n") + 1, own_header, value(body)
                    )
                )
            return
        previous_comment = ""
        for child in node.named_children:
            walk(child, owner, header, attributes, previous_comment)
            previous_comment = value(child) if child.type == "comment" else ""

    walk(tree.root_node)
    return result


@dataclass(frozen=True)
class _PhpRoute:
    source: str
    owner: str
    method: str
    path: str
    statement: str


def _php_routes(texts: Mapping[str, str]) -> list[_PhpRoute]:
    """Resolve literal Laravel array and Controller@method registrations without name-only joins."""
    routes: list[_PhpRoute] = []
    pattern = re.compile(r"\bRoute::(?:get|post|put|patch|delete|any|match)\s*\([^;]+;", re.S)
    for source, text in texts.items():
        if not source.endswith(".php"):
            continue
        # Comments cannot register a route. Preserve strings, which carry the route arguments.
        clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
        for match in pattern.finditer(clean):
            statement = match.group()
            target = re.search(r"\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", statement)
            if target is None:
                target = re.search(r"['\"]([\w\\]+)@(\w+)['\"]", statement)
            path = re.search(r"\(\s*['\"]([^'\"]+)['\"]", statement)
            if target:
                routes.append(_PhpRoute(source, target[1].split("\\")[-1], target[2], path[1] if path else "", statement))
    return routes


def _php_framework_entries(target: FileTarget, text: str, texts: Mapping[str, str]) -> list[EntryPointRecord]:
    records: list[EntryPointRecord] = []
    routes = _php_routes(texts)
    for method in _php_methods(text):
        if re.search(r"\b(private|protected)\b", method.header) or method.name.startswith("_"):
            continue
        route_attribute = re.search(r"(?:#\[|@)(?:[\w\\]+\\)?Route\s*\(\s*(?:path\s*[:=]\s*)?['\"]([^'\"]+)['\"]", method.header)
        configured: list[tuple[str, str]] = []
        if re.search(r"extends\s+(?:[\w\\]+\\)?AbstractController\b", method.owner_header):
            for source, config in texts.items():
                if "route" not in source or not source.endswith((".yaml", ".yml", ".xml", ".php")):
                    continue
                if re.search(r"\b" + re.escape(method.owner) + r"::" + re.escape(method.name) + r"\b", config):
                    configured.append((source, method.name))
        if route_attribute or configured:
            route_name = route_attribute[1] if route_attribute else configured[0][1]
            class_route = re.search(r"(?:#\[|@)(?:[\w\\]+\\)?Route\s*\(\s*(?:path\s*[:=]\s*)?['\"]([^'\"]+)['\"]", method.owner_attributes)
            if class_route and route_attribute:
                route_name = class_route[1].rstrip("/") + "/" + route_name.lstrip("/")
            evidence = [f"Symfony Route {route_name}"] + [f"Symfony controller registration in {source}" for source, _ in configured]
            records.append(
                _entry(target, method.line, method.end_line, method.name, route_name, "route", "unknown", "http_request", evidence, [])
            )
            continue
        component = re.search(r"extends\s+(?:Livewire\\)?Component\b", method.owner_header)
        if component and ("Livewire\\" in text or "Livewire\\" in method.owner_header):
            bindings = [
                source
                for source, body in texts.items()
                if re.search(r"wire:[\w.:-]+\s*=\s*['\"]" + re.escape(method.name) + r"(?:\(|['\"])", body)
            ]
            records.append(
                _entry(
                    target,
                    method.line,
                    method.end_line,
                    method.name,
                    method.name,
                    "route",
                    "unknown",
                    "http_request",
                    [f"Livewire Component {method.owner}"] + [f"Livewire wire binding in {source}" for source in bindings],
                    [],
                )
            )
            continue
        for route in routes:
            if (route.owner, route.method) != (method.owner, method.name):
                continue
            access: AccessLevel = "unknown" if "middleware" in route.statement else "public"
            records.append(
                _entry(
                    target,
                    method.line,
                    method.end_line,
                    method.name,
                    route.path or method.name,
                    "route",
                    access,
                    "http_request",
                    [f"Laravel Route registration in {route.source}: {route.path}"],
                    [],
                    access_declared=access == "public",
                )
            )
    return records


def _tornado_entries(target: FileTarget, text: str) -> list[EntryPointRecord]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    records: list[EntryPointRecord] = []
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    bases = {"RequestHandler", "WebSocketHandler"}
    for _ in classes:
        for node in classes:
            if any(_safe_unparse(base).split(".")[-1] in bases for base in node.bases):
                bases.add(node.name)
    for node in classes:
        direct = any(_safe_unparse(base).split(".")[-1] in bases for base in node.bases)
        # The pool's terminal socket inherits through terminado and explicitly invokes Tornado's base method.
        explicit_super = any(_safe_unparse(base) == "terminado.TermSocket" for base in node.bases) and any(
            isinstance(call, ast.Call) and _safe_unparse(call.func).startswith("tornado.websocket.WebSocketHandler.")
            for call in ast.walk(node)
        )
        if not direct and not explicit_super:
            continue
        for method in node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) or method.name not in {
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "head",
                "options",
                "open",
            }:
                continue
            records.append(
                _entry(
                    target,
                    method.lineno,
                    method.end_lineno,
                    method.name,
                    method.name,
                    "route",
                    "unknown",
                    "http_request",
                    [f"Tornado {node.name}.{method.name}", *[_safe_unparse(d) for d in method.decorator_list]],
                    [],
                )
            )
    return records


def _remix_exports(target: FileTarget, text: str) -> list[EntryPointRecord]:
    if "app/routes/" not in "/" + target.path:
        return []
    from .semantic.extra import grammar_for

    grammar = grammar_for("tsx" if Path(target.path).suffix == ".tsx" else target.language)
    if grammar is None:
        return []
    from tree_sitter import Parser

    data = text.encode()
    parser = Parser(grammar)
    tree = parser.parse(data)
    if tree.root_node.has_error:
        return []
    records: list[EntryPointRecord] = []

    def walk(node: Any) -> None:
        if node.type == "export_statement":
            for declaration in node.named_children:
                candidates = (
                    declaration.named_children if declaration.type in {"lexical_declaration", "variable_declaration"} else [declaration]
                )
                for candidate in candidates:
                    name_node = candidate.child_by_field_name("name")
                    if name_node is None:
                        continue
                    name = data[name_node.start_byte : name_node.end_byte].decode()
                    if name not in {"action", "loader"}:
                        continue
                    function = candidate.child_by_field_name("value") if candidate.type == "variable_declarator" else candidate
                    if function is None or function.type not in {"function_declaration", "arrow_function", "function_expression"}:
                        continue
                    records.append(
                        _entry(
                            target,
                            data[: function.start_byte].count(b"\n") + 1,
                            data[: function.end_byte].count(b"\n") + 1,
                            name,
                            name,
                            "route",
                            "unknown",
                            "http_request",
                            [f"Remix route export {name}"],
                            [],
                        )
                    )
            return
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return records


def entry_framework(entry: object) -> str | None:
    """The recogniser id recorded in a handler entry's evidence."""
    evidence = " ".join(getattr(entry, "access_evidence", ()))
    for name, identifier in (
        ("Stapler", "stapler"),
        ("Jetty", "jetty"),
        ("Servlet", "servlet"),
        ("JAX-RS", "jaxrs"),
        ("Symfony", "symfony"),
        ("Livewire", "livewire"),
        ("Laravel", "laravel"),
        ("Remix", "remix"),
        ("Tornado", "tornado"),
    ):
        if name in evidence:
            return identifier
    return None


def _java_methods(target: FileTarget, text: str) -> list[tuple[object, str, str]]:
    """Use the CST to keep class declarations, parameters and method bodies separate."""
    from .semantic.extra import grammar_for

    grammar = grammar_for("java")
    if grammar is None:
        return []
    from tree_sitter import Parser

    data = text.encode("utf-8")
    tree = Parser(grammar).parse(data)
    if tree.root_node.has_error:
        return []
    methods: list[tuple[object, str, str]] = []

    def walk(node: Any, owner: str = "") -> None:
        if node.type in {"class_declaration", "interface_declaration"}:
            body = node.child_by_field_name("body")
            owner = data[node.start_byte : body.start_byte if body else node.end_byte].decode("utf-8")
        if node.type == "method_declaration":
            body = node.child_by_field_name("body")
            if body is not None:
                header = data[node.start_byte : body.start_byte].decode("utf-8")
                methods.append((node, owner, header))
            return
        for child in node.named_children:
            walk(child, owner)

    walk(tree.root_node)
    return methods


def _stapler_entries(target: FileTarget, text: str) -> list[EntryPointRecord]:
    exposed = re.compile(
        r"\b(?:extends|implements)\b[^\{]*\b(?:Descriptor|Action|RootAction|Plugin|UnprotectedRootAction|AbstractDescribableImpl)\b"
    )
    parameters = re.compile(r"\b(?:StaplerRequest2?|StaplerResponse2?)\b|@(?:QueryParameter|AncestorInPath)\b")
    records = []
    for raw_node, owner, header in _java_methods(target, text):
        node = cast(Any, raw_node)
        name_node = node.child_by_field_name("name")
        name = name_node.text.decode("utf-8")
        params = node.child_by_field_name("parameters").text.decode("utf-8")
        class_match = exposed.search(owner)
        param_match = parameters.search(params)
        if not re.search(r"\bpublic\b", header) or not re.match(r"^do[A-Z]", name) or not (class_match or param_match):
            continue
        public = bool(re.search(r"\bimplements\b[^\{]*\bUnprotectedRootAction\b", owner))
        evidence = ["Stapler public do method"]
        if class_match:
            evidence.append(class_match.group())
        if param_match:
            evidence.append("Stapler parameter: " + param_match.group())
        records.append(
            _entry(
                target,
                node.start_point[0] + 1,
                node.end_point[0] + 1,
                name,
                name,
                "route",
                "public" if public else "unknown",
                "http_request",
                evidence,
                [],
                access_declared=public,
            )
        )
    return records


def _jetty_entries(target: FileTarget, text: str) -> list[EntryPointRecord]:
    records = []
    for raw_node, owner, header in _java_methods(target, text):
        node = cast(Any, raw_node)
        name = node.child_by_field_name("name").text.decode("utf-8")
        evidence = []
        if re.search(r"\bextends\s+(?:[\w.]+\.)?AbstractHandler\b", owner) and name == "handle":
            evidence.append("Jetty AbstractHandler.handle")
        if re.search(r"\bextends\s+(?:[\w.]+\.)?(?:HttpServlet|GenericServlet|Servlet)\b", owner) and name in {
            "service",
            "doGet",
            "doPost",
            "doPut",
            "doDelete",
            "doPatch",
            "doHead",
            "doOptions",
        }:
            evidence.append("Servlet request method: " + name)
        if re.search(r"@(?:[\w.]+\.)?(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Path)\b", header):
            evidence.append("JAX-RS request annotation")
        if evidence and not re.search(r"\bprivate\b", header):
            records.append(
                _entry(target, node.start_point[0] + 1, node.end_point[0] + 1, name, name, "route", "unknown", "http_request", evidence, [])
            )
    return records


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


def _call_arguments(lines: list[str], number: int, opener: re.Pattern[str], *, limit: int = 120) -> str:
    """The text of one call's argument list, from the line that opens it to its balancing parenthesis."""
    text = "\n".join(lines[number - 1 : number - 1 + limit])
    start = opener.search(text)
    if start is None:
        return text
    depth = 0
    for position in range(start.end() - 1, len(text)):
        character = text[position]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[start.start() : position + 1]
    return text


def _own_permission(
    callback: re.Match[str], previous: re.Match[str] | None, following: re.Match[str] | None, permissions: list[re.Match[str]]
) -> re.Match[str] | None:
    """The permission callback of the same endpoint: the first after this callback and before the next one,
    else the last after the previous callback and before this one -- endpoints write them in either order."""
    after = [p for p in permissions if p.start() > callback.end() and (following is None or p.start() < following.start())]
    if after:
        return after[0]
    before = [p for p in permissions if p.start() < callback.start() and (previous is None or p.start() > previous.end())]
    return before[-1] if before else None


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
                _entry(
                    target,
                    start,
                    end,
                    handler,
                    f"wp:{hook}",
                    "route",
                    access,
                    "http_request",
                    evidence,
                    [],
                    access_declared=True,
                    registered_by=match.group("call"),
                )
            )
        if _PHP_REST_ROUTE.search(line):
            # EVERY callback of the registration, not the first. One `register_rest_route` commonly carries
            # an array of endpoints -- PMPro's `/discount_code` has a GET and a POST handler -- and taking the
            # first recorded the reader as a route and left the writer an ordinary function, whose `$request`
            # then was no source: the REST path that injects SQL through the discount-code `save()` vanished.
            window = _call_arguments(lines, number, _PHP_REST_ROUTE)
            callbacks = list(_PHP_CALLBACK.finditer(window))
            permissions = list(_PHP_PERMISSION.finditer(window))
            for index, callback in enumerate(callbacks):
                handler = callback.group("handler") or callback.group("method")
                if not handler:
                    continue
                permission = _own_permission(
                    callback,
                    callbacks[index - 1] if index else None,
                    callbacks[index + 1] if index + 1 < len(callbacks) else None,
                    permissions,
                )
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
            named = handler or _js_handler_name(stripped)
            records.append(
                _entry(
                    target,
                    start,
                    end,
                    named,
                    "http_handler",
                    "route",
                    access,
                    "http_request",
                    evidence,
                    _line_conditions(stripped),
                    defines_handler=bool(named) and named in bounds,
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
    defines_handler: bool = True,
    registered_by: str = "",
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
        defines_handler=defines_handler,
        conditions=conditions,
        provenance=f"entrypoint:{kind}:{access_level}",
        rationale=f"{kind} surface classified as {access_level} at {trust_boundary}",
        access_declared=access_declared,
        registered_by=registered_by,
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
