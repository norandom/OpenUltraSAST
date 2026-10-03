"""The quick-rule tier of pre-push: the fast first look (task 17.3, Requirement 9.3).

The shipped pattern rules run over the head side of the files a push changes, before the engine and
inside the same deadline, and keep the matches that fall on a changed line or inside a changed
function. They are pattern matches: shown as advisory, labeled apart from admitted alerts, never
admitted and never blocking. Requirement 3.2 still governs every engine candidate.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from openultrasast.model.contracts import ChangeContext

Basis = Literal["comparison", "last_commit"]


@dataclass(frozen=True)
class QuickTierResult:
    status: Literal["completed", "not_run", "failed"]
    basis: Basis
    files: tuple[str, ...] = ()
    bytes_read: int = 0
    findings: tuple[Mapping[str, object], ...] = ()
    reason: str | None = None
    seconds: float = 0.0
    basis_commit: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "label": "quick rules: pattern matches on changed lines; advisory, not admitted, never blocking",
            "status": self.status,
            "basis": self.basis,
            "basis_commit": self.basis_commit,
            "files": list(self.files),
            "bytes_read": self.bytes_read,
            "findings": [dict(item) for item in self.findings],
            "reason": self.reason,
            "seconds": self.seconds,
        }


def head_spans(context: ChangeContext) -> dict[str, list[tuple[int, int]]]:
    """Changed head lines per decoded path, for every changed file that still exists in head."""
    deleted = set(context.deleted_paths)
    spans: dict[str, list[tuple[int, int]]] = {}
    for path in context.changed_paths:
        if path not in deleted:
            spans.setdefault(context.decode_path(path), [])
    for span in context.spans:
        if span.side == "head":
            spans.setdefault(context.decode_path(span.path), []).append((span.start_line, span.end_line))
    return spans


def run_quick_tier(
    root: Path, spans: Mapping[str, Sequence[tuple[int, int]]], *, basis: Basis = "comparison", basis_commit: str | None = None
) -> QuickTierResult:
    """Pattern rules over the changed head files of a materialized snapshot at `root`.

    Pure and bounded by its caller: it reads only the named files, runs no project code and calls no
    model. `files`/`bytes_read` prove what it read, so a zero is never an unread input.
    """
    from openultrasast.findings import PATTERN_RULES, quick_scan_findings
    from openultrasast.mapping import analyze_entry_points, attach_reachability_hints
    from openultrasast.policy import load_policy
    from openultrasast.preprocess import build_file_target, detect_language
    from openultrasast.rank import rank_targets

    started = time.monotonic()
    resolved = root.resolve()
    paths = []
    read = 0
    for name in sorted(spans):
        path = resolved / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(resolved):
            continue
        if detect_language(path) == "unknown":
            continue
        paths.append(path)
        read += path.stat().st_size
    targets = [build_file_target(resolved, path) for path in paths]
    targets = attach_reachability_hints(targets, analyze_entry_points(resolved, targets))
    rules = {rule.rule_id: rule for rule in PATTERN_RULES}
    kept: list[Mapping[str, object]] = []
    for finding in quick_scan_findings(resolved, targets, rank_targets(targets), PATTERN_RULES, load_policy()):
        if finding.status == "shadow" or finding.line is None:
            continue
        changed = spans.get(finding.path, ())
        where = _changed_scope(finding.line, changed, finding.reachability_evidence)
        if where is None:
            continue
        rule_id = finding.finding_id.split(":", 1)[0]
        rule = rules.get(rule_id)
        kept.append(
            {
                "rule": rule_id,
                "title": finding.title,
                "cwe": rule.cwe if rule is not None else None,
                "severity": finding.severity,
                "path": finding.path,
                "line": finding.line,
                "function": finding.function_name,
                "scope": where,
            }
        )
    return QuickTierResult(
        "completed",
        basis,
        tuple(target.path for target in targets),
        read,
        tuple(kept),
        seconds=time.monotonic() - started,
        basis_commit=basis_commit,
    )


def _changed_scope(line: int, changed: Sequence[tuple[int, int]], hints: Sequence[Mapping[str, object]]) -> str | None:
    if any(start <= line <= end for start, end in changed):
        return "changed_line"
    for hint in hints:
        start, end = hint.get("line"), hint.get("end_line")
        inside = isinstance(start, int) and isinstance(end, int) and start <= line <= end
        if inside and any(a <= end and start <= b for a, b in changed):  # type: ignore[operator]
            return "changed_function"
    return None
