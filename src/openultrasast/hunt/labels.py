"""Attach benchmark fix-site labels without exposing them to feature producers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any


def label_rows(rows: Sequence[Mapping[str, Any]], change: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Label verified sites, leave other positive rows unknown and label ordinary rows zero."""
    kind = change.get("kind")
    if kind not in ("vulnerability", "ordinary"):
        raise ValueError("change kind must be vulnerability or ordinary")
    if not change.get("case_id"):
        raise ValueError("a label needs a traceable case_id")
    if kind == "vulnerability" and not all(change.get(k) for k in ("path", "function", "function_lines", "family")):
        raise ValueError("a vulnerability label needs its path, function, span and family")
    result = []
    for row in rows:
        data = deepcopy(dict(row))
        span = change.get("function_lines")
        function = row.get("function", row.get("feature.source.function"))
        site = (
            kind == "vulnerability"
            and row.get("path") == change["path"]
            and (function == change["function"] or (span[0] <= row.get("line", 0) <= span[1]))
        )
        data.update(
            label=1 if site else 0 if kind == "ordinary" else None,
            family=change["family"] if site else None,
            fix_span=list(span) if site else None,
            label_ref=change["case_id"] if site or kind == "ordinary" else None,
            verification=None,
        )
        result.append(data)
    return result
