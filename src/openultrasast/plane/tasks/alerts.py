"""`alerts` (harnessx-removal Requirement 6.3, design section 6): what the deterministic rules say about a case.

No model, budget ``{usd: 0, calls: 0}``, one per case in a ``--loop`` Run, serialized like ``repo-facts`` (a full-tree
scan per pin). It runs the quick-mode scan -- ``preprocess_repository``, the entry-point reachability hints,
``rank_targets`` and ``quick_scan_findings`` over the image's bundled ruleset, enabled and shadow rules alike, exactly
what ``ousast scan --mode quick`` runs -- on the case's vulnerable pin and on its fixed pin, and writes one row per
(rule, file, line, pin) to ``alerts.jsonl``:

    rule_id, rule_status (enabled | shadow), path, line, function, pin_role (vulnerable | fixed), pin, in_fix_range

``function`` is the enclosing declaration by the patterns ``repo-facts`` uses (so an alert joins the verify
candidates' ``path::function``; ``<global>`` outside any function); a language those patterns do not cover keeps the
scan's own reachability attribution. ``in_fix_range`` says whether the line lies inside the fix: the old-side ranges
of ``case.json`` on the vulnerable pin, the new-side ``fixed_ranges`` on the fixed pin (null when ``case.json`` has
none). A fixed-pin alert inside the fix is a false alert on code the fix wrote: rule M1 of ``improve/memory.py``
counts it.

Env: ``OUSAST_OUTPUT_DIR``, ``OUSAST_WORKSPACE_DIR`` (vulnerable checkout), ``OUSAST_FIXED_DIR`` (fixed checkout),
``OUSAST_INPUT_CASE`` (``case.json``), ``OUSAST_VULNERABLE_PIN``, ``OUSAST_FIXED_PIN``. A pin whose checkout yields no
source file fails the task: an unread tree and a silent one are indistinguishable afterwards. Exit 0 done, 2 failed.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...findings import quick_scan_findings
from ...mapping import analyze_entry_points, attach_reachability_hints
from ...preprocess import detect_language, preprocess_repository
from ...rank import rank_targets
from .repo_facts import DECLARATION, GLOBAL, enclosing

ROLES = ("vulnerable", "fixed")
DIRS = ("OUSAST_WORKSPACE_DIR", "OUSAST_FIXED_DIR")
PINS = ("OUSAST_VULNERABLE_PIN", "OUSAST_FIXED_PIN")
Ranges = Mapping[str, Sequence[Sequence[int]]]


def _lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def in_range(ranges: Ranges | None, path: str, line: int | None) -> bool | None:
    if ranges is None:
        return None
    return line is not None and any(int(lo) <= line <= int(hi) for lo, hi in ranges.get(path, []))


def scan(root: Path, role: str, pin: str, ranges: Ranges | None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """(rows, what was read) of one pin: the quick-mode findings as alert rows, one per rule, file, line."""
    _, targets = preprocess_repository(root)
    targets = attach_reachability_hints(targets, analyze_entry_points(root, targets))
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    read = {"files": len(targets), "bytes": sum((root / t.path).stat().st_size for t in targets if (root / t.path).is_file())}
    cache: dict[str, list[str]] = {}
    rows: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    for finding in findings:
        rule_id = finding.finding_id.split(":", 1)[0]
        lines = cache.setdefault(finding.path, _lines(root / finding.path))
        language = detect_language(root / finding.path)
        if language in DECLARATION and finding.line and 0 < finding.line <= len(lines):
            function = enclosing(lines, finding.line - 1, language)
        else:
            function = finding.function_name or GLOBAL
        row = {
            "rule_id": rule_id, "rule_status": finding.status, "path": finding.path, "line": finding.line, "function": function,
            "pin_role": role, "pin": pin, "in_fix_range": in_range(ranges, finding.path, finding.line),
        }  # fmt: skip
        rows.setdefault((rule_id, finding.path, finding.line), row)
    ordered = sorted(rows.values(), key=lambda r: (r["path"], r["line"] or 0, r["rule_id"]))
    return ordered, read


def _summary(output_dir: Path, summary: Mapping[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(environ: Mapping[str, str] | None = None) -> int:
    env = environ if environ is not None else os.environ
    output = Path(env["OUSAST_OUTPUT_DIR"]) if env.get("OUSAST_OUTPUT_DIR") else None
    summary: dict[str, Any] = {"status": "failed", "units_done": 0, "units_total": 2, "usd": 0, "calls": 0, "usage": {}, "model": None}
    try:
        if output is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        output.mkdir(parents=True, exist_ok=True)
        case = json.loads(Path(env["OUSAST_INPUT_CASE"]).read_text(encoding="utf-8")) if env.get("OUSAST_INPUT_CASE") else {}
        ranges = {"vulnerable": case.get("ranges"), "fixed": case.get("fixed_ranges")}
        rows: list[dict[str, Any]] = []
        for role, directory, pin in zip(ROLES, DIRS, PINS, strict=True):
            root = Path(env.get(directory) or "")
            if not env.get(directory) or not root.is_dir():
                raise ValueError(f"{directory} is not a directory: {root}")
            found, read = scan(root, role, str(env.get(pin) or ""), ranges[role])
            if read["files"] == 0:
                raise ValueError(f"the {role} checkout {root} has no source file the scan reads: an unread tree is not a clean one")
            summary.setdefault("read", {})[role] = read
            summary.setdefault("alerts", {})[role] = len(found)
            rows.extend(found)
            summary["units_done"] += 1
        (output / "alerts.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
        summary["status"] = "done"
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback
        summary["reason"] = traceback.format_exc()[-2000:]
    if output is not None:
        _summary(output, summary)
    print(json.dumps({k: summary.get(k) for k in ("status", "alerts", "read")}), file=sys.stderr)
    return 0 if summary["status"] == "done" else 2


__all__ = ["in_range", "main", "scan"]


if __name__ == "__main__":
    raise SystemExit(main())
