"""Framework enforcement outside a handler, resolved from cached source and route declarations."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from ...mapping import EntryPointRecord, _php_methods, _php_routes, entry_framework
from .operations import Discharge

_MIDDLEWARE = re.compile(r"['\"](auth(?::[^'\"]+)?|can:[^'\"]+|role(?::[^'\"]+)?|permission(?::[^'\"]+)?)['\"]")


def witnesses(*, root: Path, texts: Mapping[str, str], entries: Sequence[EntryPointRecord], language: str) -> list[Discharge]:
    """One scoped path guard per enforcement source and covered handler; unrelated declarations discharge nothing.

    Texts are supplied by the caller's cache. Root names the checkout; this function never rereads source files.
    """
    del root
    found: list[Discharge] = []
    routes = _php_routes(texts) if language == "php" else []
    security = _security_rules(texts) if language == "php" else []
    methods_by_path = {path: _php_methods(text) for path, text in texts.items() if language == "php" and path.endswith(".php")}
    for entry in entries:
        if not entry.function_name or entry.line is None or not entry.defines_handler:
            continue
        framework = entry_framework(entry)
        sources: list[tuple[str, str]] = []
        if language == "python" and framework == "tornado":
            tree = ast.parse(texts.get(entry.path, ""))
            for py_method in ast.walk(tree):
                if isinstance(py_method, (ast.FunctionDef, ast.AsyncFunctionDef)) and py_method.lineno == entry.line:
                    for decorator in py_method.decorator_list:
                        name = ast.unparse(decorator)
                        if name in {"authenticated", "tornado.web.authenticated"}:
                            sources.append(("decorator", f"Tornado {name} in {entry.path}"))
        if language == "php" and framework in {"symfony", "laravel", "livewire"}:
            methods = methods_by_path.get(entry.path, [])
            method = next((m for m in methods if m.name == entry.function_name and m.line == entry.line), None)
            if method is None:
                continue
            if framework == "symfony":
                for header in (method.header, method.owner_attributes):
                    if re.search(r"(?:#\[|@)(?:[\w\\]+\\)?(?:IsGranted|Security)\s*\(", header):
                        sources.append(("decorator", f"Symfony IsGranted/Security in {entry.path}"))
                # Symfony evaluates access_control in order: a public match cannot be skipped for a later role.
                for source, path, roles in security:
                    if re.search(path, entry.name):
                        if roles and not any(role in {"PUBLIC_ACCESS", "IS_AUTHENTICATED_ANONYMOUSLY"} for role in roles):
                            sources.append(("router", f"Symfony access_control in {source}"))
                        break
            if framework in {"laravel", "livewire"}:
                for route in routes:
                    if (route.owner, route.method) == (method.owner, method.name):
                        middleware = re.search(r"->middleware\s*\((.*?)\)", route.statement, re.S)
                        if middleware and _MIDDLEWARE.search(middleware[1]):
                            sources.append(("router", f"Laravel route middleware in {route.source}"))
                for constructor in methods:
                    if constructor.owner != method.owner or constructor.name != "__construct":
                        continue
                    for match in re.finditer(r"\$this->(?:middleware|authorizeResource)\s*\([^;]+;", constructor.body, re.S):
                        statement = match.group()
                        only = re.search(r"->only\s*\((.*?)\)", statement, re.S)
                        exclude = re.search(r"->except\s*\((.*?)\)", statement, re.S)
                        if only and not re.search(r"['\"]" + re.escape(method.name) + r"['\"]", only[1]):
                            continue
                        if exclude and re.search(r"['\"]" + re.escape(method.name) + r"['\"]", exclude[1]):
                            continue
                        if "authorizeResource" in statement or _MIDDLEWARE.search(statement):
                            sources.append(("router", f"Laravel constructor enforcement in {entry.path}"))
        for scope, detail in dict.fromkeys(sources):
            found.append(
                Discharge(
                    entry.path, None, entry.function_name, "path_guard", f"{framework}-enforcement", "authenticated_context", scope, detail
                )
            )
    return list(dict.fromkeys(found))


def _security_rules(texts: Mapping[str, str]) -> list[tuple[str, str, tuple[str, ...]]]:
    result: list[tuple[str, str, tuple[str, ...]]] = []
    for source, text in texts.items():
        if not source.endswith(("config/packages/security.yaml", "config/packages/security.yml")):
            continue
        payload = yaml.safe_load(text)
        if not isinstance(payload, dict) or not isinstance(payload.get("security"), dict):
            continue
        rules = payload["security"].get("access_control", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("path"), str):
                continue
            roles = rule.get("roles", ())
            if isinstance(roles, str):
                roles = (roles,)
            if not isinstance(roles, (list, tuple)):
                continue
            result.append((source, rule["path"], tuple(str(role) for role in roles)))
    return result
