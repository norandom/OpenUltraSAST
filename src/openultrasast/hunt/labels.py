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
    # Every verified site of the change is a positive: the primary one and, when several accepted
    # locations share the fix commit, each entry of ``targets``.
    sites = []
    if kind == "vulnerability":
        sites.append((change["path"], change["function"], list(change["function_lines"]), change["case_id"]))
        for target in change.get("targets", []):
            sites.append((target["path"], target["function"], list(target["function_lines"]), target.get("case_id", change["case_id"])))
    result = []
    for row in rows:
        data = deepcopy(dict(row))
        function = row.get("function", row.get("feature.source.function"))
        matched = next(
            (
                site
                for site in sites
                if row.get("path") == site[0] and (function == site[1] or (site[2][0] <= row.get("line", 0) <= site[2][1]))
            ),
            None,
        )
        data.update(
            label=1 if matched else 0 if kind == "ordinary" else None,
            family=change["family"] if matched else None,
            fix_span=matched[2] if matched else None,
            label_ref=matched[3] if matched else change["case_id"] if kind == "ordinary" else None,
            verification=None,
        )
        result.append(data)
    return result
