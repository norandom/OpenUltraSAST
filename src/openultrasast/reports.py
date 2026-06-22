from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .findings import StaticFinding
from .run import ScanRun
from .verification import VerificationResult


def write_markdown_report(findings: list[StaticFinding], path: Path, verifications: list[VerificationResult] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications or [])
    lines = ["# OpenUltraSAST Report", "", f"Findings: {len(findings)}", ""]
    if not findings:
        lines.append("No quick-mode findings were emitted.")
    for finding in findings:
        verification = verification_by_id.get(finding.finding_id)
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
                "",
                finding.rationale,
                "",
            ]
        )
    path.write_text("\n".join(lines).rstrip() + "\n")


def write_sarif_report(findings: list[StaticFinding], verifications: list[VerificationResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications)
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
                "results": [_sarif_result(finding, verification_by_id.get(finding.finding_id)) for finding in findings],
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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def scan_exit_code(findings: list[StaticFinding], verifications: list[VerificationResult], policy: str) -> int:
    if policy == "never":
        return 0
    if policy == "findings":
        return 1 if findings else 0
    if policy == "verified":
        return 1 if any(result.verified for result in verifications) else 0
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


def _sarif_result(finding: StaticFinding, verification: VerificationResult | None) -> dict[str, object]:
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
        "properties": {
            "finding_id": finding.finding_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "evidence_level": finding.evidence_level,
            "verification": asdict(verification) if verification else None,
            "reachability_status": finding.reachability_status,
            "reachability_conditions": finding.reachability_conditions,
            "ranking_priority": finding.ranking_priority,
        },
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
