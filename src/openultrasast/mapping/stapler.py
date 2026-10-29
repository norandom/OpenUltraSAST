"""Task 11.6: the Stapler entry recogniser as a registered strategy.

This is a target-named strategy module: Stapler vocabulary is legitimate here
(the engine never imports this module; only the registry dispatches it). The
recognition body moved verbatim from ``mapping/legacy.py`` so existing entries
stay byte-identical; the legacy inline dispatch no longer matches this family.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, cast

from .legacy import _entry, _java_methods
from .registry import register

if TYPE_CHECKING:
    from .legacy import EntryPointRecord


class StaplerStrategy:
    """Recognise Jenkins Stapler ``do*`` handler methods on exposed types."""

    identifier = "stapler"
    languages: tuple[str, ...] = ("java",)

    def recognize(self, target: object, text: str) -> list[EntryPointRecord]:
        exposed = re.compile(
            r"\b(?:extends|implements)\b[^\{]*\b(?:Descriptor|Action|RootAction|Plugin|UnprotectedRootAction|AbstractDescribableImpl)\b"
        )
        parameters = re.compile(r"\b(?:StaplerRequest2?|StaplerResponse2?)\b|@(?:QueryParameter|AncestorInPath)\b")
        records: list[EntryPointRecord] = []
        for raw_node, owner, header in _java_methods(target, text):  # type: ignore[arg-type]
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
                    target,  # type: ignore[arg-type]
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


register(StaplerStrategy())

__all__ = ["StaplerStrategy"]
