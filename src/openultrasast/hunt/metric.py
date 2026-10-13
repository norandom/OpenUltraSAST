"""Search outcomes using the frozen benchmark's location and family rules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Outcome:
    hit: bool
    suspicions: int
    on_diff: int
    feedback: str


def _location_match(change: Mapping[str, Any], finding: Mapping[str, Any], tolerance: int) -> bool:
    """Mirror unseen.score.location_match, including its config-secret exception."""
    for file in change.get("files", []):
        if finding.get("path") != file["path"]:
            continue
        line = finding.get("line", 0) or 0
        if any(start - tolerance <= line <= end + tolerance for start, end in file.get("head_lines", [])):
            return True
        if change.get("family") != "config_secrets" and file["path"] == change.get("path", file["path"]):
            function = change.get("function")
            if function and function != "<global>" and finding.get("function") == function:
                return True
            span = change.get("function_lines") or file.get("function_lines")
            if span and span[0] <= line <= span[1]:
                return True
    return False


def _on_diff(change: Mapping[str, Any], finding: Mapping[str, Any], tolerance: int) -> bool:
    return any(finding.get("path") == file["path"] and
               any(start - tolerance <= (finding.get("line", 0) or 0) <= end + tolerance
                   for start, end in file.get("head_lines", [])) for file in change.get("files", []))


def search_outcome(change: Mapping[str, Any], findings: Sequence[Mapping[str, Any]], *, tolerance: int = 10) -> Outcome:
    """Count all suspicions and record whether one catches a positive site."""
    if change.get("kind") not in ("vulnerability", "ordinary"):
        raise ValueError("change kind must be vulnerability or ordinary")
    if tolerance < 0:
        raise ValueError("location tolerance cannot be negative")
    hit = change["kind"] == "vulnerability" and any(
        finding.get("family") == change.get("family") and _location_match(change, finding, tolerance) for finding in findings
    )
    on_diff = sum(_on_diff(change, finding, tolerance) for finding in findings)
    feedback = []
    if change["kind"] == "vulnerability" and not hit:
        span = change.get("function_lines") or [next((start for f in change.get("files", [])
                                                    for start, _ in f.get("head_lines", [])), 0)]
        feedback.append(f"missed {change.get('path', '')}:{span[0]} {change.get('function', '')} family {change.get('family', '')}")
    off_diff = [f"{f.get('path', '')}:{f.get('line', 0)} family {f.get('family', '')}"
                for f in findings if not _on_diff(change, f, tolerance)]
    if off_diff:
        feedback.append("off-diff suspicions: " + ", ".join(off_diff))
    return Outcome(hit, len(findings), on_diff, "; ".join(feedback))


def _field(value: object, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def search_metric(example: object, pred: object, trace: object = None) -> float:
    """Provide DSPy's metric signature while keeping this module dependency free."""
    change = _field(example, "change", example)
    outcome = search_outcome(change, _field(pred, "findings", []))
    return float(outcome.hit) if change["kind"] == "vulnerability" else 1 - min(1, outcome.suspicions / 5)
