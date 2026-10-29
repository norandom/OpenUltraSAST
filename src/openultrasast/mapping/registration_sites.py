"""Generic call-site registration adapter (task 11.2).

Resolves handlers registered at call sites through the same-file stable
symbols: a registration call whose argument names a class declared in the
file yields one entry per declared method of that class, with the
registration site and the resolved handler identity as evidence. A
registration whose argument names no declared class yields no entry and is
reported as unresolved coverage. The registration vocabulary is data
supplied to the strategy; this module names no target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..semantic.cst import declaration_scopes

if TYPE_CHECKING:
    from .legacy import EntryPointRecord


@dataclass
class RegistrationSiteStrategy:
    """Recognise handlers registered at call sites named by vocabulary."""

    identifier: str
    languages: tuple[str, ...]
    vocabulary: tuple[str, ...] = ()
    _matchers: tuple[tuple[str, re.Pattern[str]], ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._matchers = tuple((name, re.compile(rf"(?<!\w){re.escape(name)}\s*\(")) for name in self.vocabulary)

    def recognize(self, target: Any, text: str) -> list[EntryPointRecord]:
        records: list[EntryPointRecord] = []
        declared_classes = _declared_classes(target.path, text, target.language)
        for name, matcher in self._matchers:
            for line_number, line_text in enumerate(text.splitlines(), start=1):
                if not matcher.search(line_text):
                    continue
                handler = _resolve_handler(line_text, declared_classes)
                if handler is None:
                    continue
                records.extend(
                    _handler_entries(
                        path=target.path,
                        handler=handler,
                        call_name=name,
                        call_line=line_number,
                        text=text,
                        language=target.language,
                    )
                )
        return records

    def registration_coverage(self, target: Any, text: str) -> dict[str, int]:
        declared_classes = _declared_classes(target.path, text, target.language)
        unresolved = 0
        for _, matcher in self._matchers:
            for line_text in text.splitlines():
                if not matcher.search(line_text):
                    continue
                if _resolve_handler(line_text, declared_classes) is None:
                    unresolved += 1
        return {"registration_unresolved": unresolved} if unresolved else {}


def _declared_classes(path: str, text: str, language: str) -> frozenset[str]:
    classes = {scope.enclosing_type for scope in declaration_scopes(path, text, language) if scope.enclosing_type is not None}
    return frozenset(classes)


def _resolve_handler(line_text: str, declared_classes: frozenset[str]) -> str | None:
    for class_name in sorted(declared_classes):
        if re.search(rf"\b{re.escape(class_name)}\b", line_text):
            return class_name
    return None


def _handler_entries(
    *,
    path: str,
    handler: str,
    call_name: str,
    call_line: int,
    text: str,
    language: str,
) -> list[EntryPointRecord]:
    from .legacy import EntryPointRecord

    entries = []
    for scope in declaration_scopes(path, text, language):
        if scope.enclosing_type != handler:
            continue
        entries.append(
            EntryPointRecord(
                path=path,
                line=scope.start_line,
                end_line=scope.start_line,
                function_name=scope.function_name,
                name=scope.function_name,
                kind="route",
                access_level="unknown",
                trust_boundary="external",
                access_evidence=[
                    f"registration site {path}:{call_line}",
                    f"registered handler {handler}",
                ],
                conditions=[],
                provenance="",
                rationale="registered handler request method",
                defines_handler=True,
                registered_by=call_name,
            )
        )
    return entries


__all__ = ["RegistrationSiteStrategy"]
