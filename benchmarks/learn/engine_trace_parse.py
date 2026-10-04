"""Lossless parsing of the optional shortest-path trace, with explicit evidence limits."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_STEP = re.compile(r"^(.*):(-?\d+) \[([^\]]+)\] ([\s\S]*)$")


def parse_trace(row: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve row-level discharge evidence; never guess which node sanitized a path.

    The query emits basename-only files and truncated code. A bound can be off-path;
    it remains in ``guard`` even when no trace step exactly matches it. Invalid steps
    raise instead of turning an unreadable trace into an empty path.
    """
    raw = row.get("trace", [])
    if not isinstance(raw, list):
        raise ValueError("trace must be an array")
    steps = []
    bound = str(row.get("bound") or "")
    for index, text in enumerate(raw):
        match = _STEP.fullmatch(text) if isinstance(text, str) else None
        if match is None:
            raise ValueError(f"invalid trace step: {text!r}")
        location, line, node_label, code = match.groups()
        file, separator, method = location.partition(":")
        roles = ["source"] if index == 0 else ["step"]
        if index == len(raw) - 1:
            roles = ["source", "sink"] if index == 0 else ["sink"]
        if bound and code == bound:
            roles.append("guard")
        steps.append(
            {
                "file": file,
                "method": method if separator else "?",
                "line": int(line),
                "node_label": node_label,
                "code": code,
                "roles": roles,
                "raw": text,
            }
        )
    return {
        "steps": steps,
        "sanitized": bool(row.get("sanitized", False)),
        "sanitizer": {"on_path": bool(row.get("sanitized", False)), "step": None},
        "guard": {"text": bound, "bounded": bool(row.get("bounded", False))},
    }
