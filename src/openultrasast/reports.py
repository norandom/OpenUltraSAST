from __future__ import annotations

from pathlib import Path

from .findings import StaticFinding


def write_markdown_report(findings: list[StaticFinding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# OpenUltraSAST Report", "", f"Findings: {len(findings)}", ""]
    if not findings:
        lines.append("No quick-mode findings were emitted.")
    for finding in findings:
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Path: `{finding.path}`",
                f"- Line: `{finding.line}`",
                f"- Severity: `{finding.severity}`",
                f"- Confidence: `{finding.confidence}`",
                f"- Evidence level: `{finding.evidence_level}`",
                f"- Ranking priority: `{finding.ranking_priority}`",
                f"- Tags: `{', '.join(finding.tags)}`",
                "",
                finding.rationale,
                "",
            ]
        )
    path.write_text("\n".join(lines).rstrip() + "\n")
