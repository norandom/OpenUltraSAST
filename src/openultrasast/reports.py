from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .findings import StaticFinding
from .run import ScanRun
from .verification import VerificationResult


def write_markdown_report(
    findings: list[StaticFinding],
    path: Path,
    verifications: list[VerificationResult] | None = None,
    *,
    redact: bool = True,
    complexity_map: object | None = None,
    verdicts: Sequence[object] | None = None,
    overlay: Sequence[object] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications or [])
    overlay_by_id = _overlay_by_id(overlay or [])
    lines = ["# OpenUltraSAST Report", "", f"Findings: {len(findings)}", "", "## Inventory", ""]
    if not findings:
        lines.append("No quick-mode findings were emitted.")
        lines.append("")
    for finding in findings:
        verification = verification_by_id.get(finding.finding_id)
        disposition = overlay_by_id.get(finding.finding_id)
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Path: `{finding.path}`",
                f"- Line: `{finding.line}`",
                f"- Function: `{finding.function_name or 'unknown'}`",
                f"- Severity: `{finding.severity}`",
                f"- Confidence: `{finding.confidence}`",
                f"- Evidence level: `{finding.evidence_level}`",
                f"- Verification: `{verification.status if verification else 'not_run'}`",
                f"- Reachability: `{finding.reachability_status}`",
                f"- Conditions: `{', '.join(finding.reachability_conditions) or 'none'}`",
                f"- Ranking priority: `{finding.ranking_priority}`",
                f"- Tags: `{', '.join(finding.tags)}`",
            ]
        )
        if disposition is not None:
            lines.append(f"- Disposition: `{getattr(disposition, 'disposition', '')}`")
            lines.append(f"- Overlay reason: `{getattr(disposition, 'reason', '')}`")
        lines.extend(["", finding.rationale, ""])
    if overlay:
        _append_overlay(lines, overlay)
    if complexity_map is not None:
        _append_complexity_map(lines, complexity_map)
    if verdicts is not None:
        _append_worth_fixing(lines, verdicts)
    report = "\n".join(lines).rstrip() + "\n"
    if redact:
        from .redaction import redact_secrets

        report = redact_secrets(report)
    path.write_text(report)


def _append_complexity_map(lines: list[str], complexity_map: object) -> None:
    hotspots = tuple(getattr(complexity_map, "hotspots", ()) or ())
    heuristic_only = getattr(complexity_map, "heuristic_only", None)
    summary = f"Hotspots: {len(hotspots)}"
    if heuristic_only is not None:
        summary += f" (heuristic_only={str(bool(heuristic_only)).lower()})"
    lines.extend(["## Complexity map", "", summary, ""])
    if not hotspots:
        lines.extend(["No complexity hotspots were emitted.", ""])
        return
    for hotspot in hotspots:
        identity = _report_identity(getattr(hotspot, "path", ""), getattr(hotspot, "function_name", None))
        lines.extend(
            [
                f"### `{identity}`",
                "",
                f"- Score: `{getattr(hotspot, 'score', '')}`",
                f"- Band: `{getattr(hotspot, 'band', '')}`",
            ]
        )
        hint = getattr(hotspot, "test_hint", None)
        if hint is not None:
            lines.append(f"- Gap: `{getattr(hint, 'gap', '')}`")
            kind = getattr(hint, "test_kind", None)
            if kind:
                lines.append(f"- Recommended test: `{kind}`")
            reason = getattr(hint, "reason", "")
            if reason:
                lines.append(f"- Hint: {reason}")
        inventory_ids = tuple(getattr(hotspot, "inventory_finding_ids", ()) or ())
        if inventory_ids:
            lines.append(f"- Inventory: `{', '.join(str(item) for item in inventory_ids)}`")
        rationale = str(getattr(hotspot, "rationale", "") or "")
        lines.extend(["", rationale, ""] if rationale else [""])


def _append_worth_fixing(lines: list[str], verdicts: Sequence[object]) -> None:
    worth = [item for item in verdicts if getattr(item, "worth_fixing", False)]
    lines.extend(["## Worth fixing", "", f"Count: {len(worth)}", ""])
    if not worth:
        lines.extend(["No worth-fixing verdicts were produced.", ""])
        return
    for item in worth:
        identity = _report_identity(getattr(item, "path", ""), getattr(item, "function_name", None))
        lines.extend(
            [
                f"### `{identity}`",
                "",
                f"- Verdict: `{getattr(item, 'verdict', '')}`",
                f"- Reason: `{getattr(item, 'reason', '')}`",
                "",
            ]
        )


def _report_identity(path: object, function_name: object) -> str:
    path_text = str(path or "")
    if function_name:
        return f"{path_text}::{function_name}"
    return path_text


def write_sarif_report(
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    path: Path,
    overlay: Sequence[object] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications)
    overlay_by_id = _overlay_by_id(overlay or [])
    rules = _sarif_rules(findings)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenUltraSAST",
                        "informationUri": "https://github.com/norandom/OpenUltraSAST",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    _sarif_result(finding, verification_by_id.get(finding.finding_id), overlay_by_id.get(finding.finding_id))
                    for finding in findings
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_manifest(
    *,
    run: ScanRun,
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    artifact_paths: dict[str, Path],
    path: Path,
    score: dict[str, object] | None = None,
    degradations: list[dict[str, object]] | None = None,
    fusion: list[dict[str, object]] | None = None,
    stages: dict[str, object] | None = None,
    complexity: dict[str, object] | None = None,
    worth_fixing: dict[str, object] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications)
    payload: dict[str, object] = {
        "scan_id": run.scan_id,
        "target": str(run.target),
        "artifacts": {name: _relative_artifact(run.root, artifact) for name, artifact in sorted(artifact_paths.items())},
        "findings": [
            {
                "finding_id": finding.finding_id,
                "path": finding.path,
                "line": finding.line,
                "severity": finding.severity,
                "evidence_level": finding.evidence_level,
                "verification_status": verification_by_id[finding.finding_id].status
                if finding.finding_id in verification_by_id
                else "not_run",
                "artifact_refs": _artifact_refs(run.root, artifact_paths),
            }
            for finding in findings
        ],
    }
    if score is not None:
        payload["score"] = score
    if degradations is not None:
        payload["degradations"] = degradations
    if fusion is not None:
        payload["fusion"] = fusion
    if stages is not None:
        payload["stages"] = stages
    if complexity is not None:
        payload["complexity"] = complexity
    if worth_fixing is not None:
        payload["worth_fixing"] = worth_fixing
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def scan_exit_code(
    findings: list[StaticFinding],
    verifications: list[VerificationResult],
    policy: str,
    worth_fixing_verdicts: Sequence[object] | None = None,
) -> int:
    if policy == "never":
        return 0
    if policy == "findings":
        return 1 if findings else 0
    if policy == "verified":
        return 1 if any(result.verified for result in verifications) else 0
    if policy == "worth-fixing":
        return 1 if any(getattr(verdict, "worth_fixing", False) for verdict in worth_fixing_verdicts or ()) else 0
    raise ValueError(f"unknown fail policy: {policy}")


def _sarif_rules(findings: list[StaticFinding]) -> dict[str, dict[str, object]]:
    rules: dict[str, dict[str, object]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "properties": {"tags": finding.tags},
            },
        )
    return rules


def _sarif_result(finding: StaticFinding, verification: VerificationResult | None, overlay: object | None = None) -> dict[str, object]:
    properties: dict[str, object] = {
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence_level": finding.evidence_level,
        "verification": asdict(verification) if verification else None,
        "reachability_status": finding.reachability_status,
        "reachability_conditions": finding.reachability_conditions,
        "ranking_priority": finding.ranking_priority,
    }
    if overlay is not None:
        properties["disposition"] = getattr(overlay, "disposition", "")
        properties["overlay_reason"] = getattr(overlay, "reason", "")
    return {
        "ruleId": _rule_id(finding),
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.rationale},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": finding.line or 1},
                }
            }
        ],
        "partialFingerprints": {"openultrasastFindingId": finding.finding_id},
        "properties": properties,
    }


def _rule_id(finding: StaticFinding) -> str:
    return finding.finding_id.split(":", 1)[0]


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _verification_by_id(verifications: list[VerificationResult]) -> dict[str, VerificationResult]:
    return {result.finding_id: result for result in verifications}


def _overlay_by_id(records: Sequence[object]) -> dict[str, object]:
    mapped: dict[str, object] = {}
    for record in records:
        proposal_id = getattr(record, "proposal_id", None)
        if isinstance(proposal_id, str) and proposal_id:
            mapped[proposal_id] = record
    return mapped


def _append_overlay(lines: list[str], records: Sequence[object]) -> None:
    lines.extend(["## Overlay", "", f"Records: {len(records)}", ""])
    labels = ("promoted", "demoted", "unadjudicated", "coverage")
    counts = {label: 0 for label in labels}
    for record in records:
        disposition = str(getattr(record, "disposition", ""))
        if disposition == "promote":
            counts["promoted"] += 1
        elif disposition == "demote":
            counts["demoted"] += 1
        elif disposition == "unadjudicated":
            counts["unadjudicated"] += 1
        elif disposition == "coverage":
            counts["coverage"] += 1
    lines.append("- Labels: " + ", ".join(f"{label}={counts[label]}" for label in labels))
    lines.append("")
    for record in records:
        disposition = str(getattr(record, "disposition", ""))
        proposal_id = str(getattr(record, "proposal_id", ""))
        reason = str(getattr(record, "reason", ""))
        lines.extend(
            [
                f"### `{disposition}` `{proposal_id}`",
                "",
                f"- Path: `{getattr(record, 'path', '')}`",
                f"- Line: `{getattr(record, 'line', None)}`",
                f"- Reason: `{reason}`",
                "",
            ]
        )


def _artifact_refs(root: Path, artifact_paths: dict[str, Path]) -> dict[str, str]:
    refs = {
        "findings_json": _relative_artifact(root, artifact_paths["findings"]),
        "verification_json": _relative_artifact(root, artifact_paths["verification"]),
        "markdown": _relative_artifact(root, artifact_paths["markdown"]),
        "sarif": _relative_artifact(root, artifact_paths["sarif"]),
    }
    if "trajectories" in artifact_paths:
        refs["trajectories_jsonl"] = _relative_artifact(root, artifact_paths["trajectories"])
    return refs


def _relative_artifact(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
