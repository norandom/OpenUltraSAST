from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
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
    mechanisms: Mapping[str, Mapping[str, object]] | None = None,
    obligations: Mapping[str, Mapping[str, object]] | None = None,
    obligations_summary: Mapping[str, object] | None = None,
    coverage: Sequence[Mapping[str, object]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verification_by_id = _verification_by_id(verifications or [])
    overlay_by_id = _overlay_by_id(overlay or [])
    cited: dict[str, Mapping[str, object]] = {}
    cited_obligations: dict[str, Mapping[str, object]] = {}
    # THE RULE (contributor-scan 2.11): a report is proportionate to what the engine can say.
    #
    # A finding whose only evidence is a text pattern -- `evidence_level == "static_corroboration"`, nothing
    # corroborating it beyond the match -- is grouped by rule instead of given a section each. libpng emitted
    # 198 sections of which 163 were exactly that, asserting `memcpy` and `strcpy` are PRESENT in a library
    # that uses them correctly throughout. That is the noise developers have learned to skip in every other
    # tool, and shipping it costs the findings beside it their credibility.
    #
    # Grouped, never dropped, and proportionate rather than hidden. A rule with a handful of sites keeps its
    # full sections -- one `python-flask-debug` is a finding a contributor can act on and must not be
    # summarised away. A rule with fifty-four is a property of the codebase. Anything a proposer actually
    # reasoned about -- the model layer, the obligations checker -- keeps its section whatever its rung,
    # because an undecided CLAIM about a site is not an observation that an API exists.
    patterned = _crowded_pattern_rules(findings)
    crowded = {id(item) for item in patterned}
    reasoned = [item for item in findings if id(item) not in crowded]

    lines = ["# OpenUltraSAST Report", "", f"Findings: {len(findings)}", "", "## Inventory", ""]
    if not findings:
        lines.append("No quick-mode findings were emitted.")
        lines.append("")
    for finding in reasoned:
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
                f"- Rung: `{finding.rung}`",
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
        mechanism_id = _mechanism_id_for(finding, disposition)
        if mechanism_id and mechanisms is not None and mechanism_id in mechanisms:
            info = mechanisms[mechanism_id]
            cited[mechanism_id] = info
            lines.append(f"- Mechanism: `{mechanism_id}` — {info.get('summary', '')}")
            lines.append(f"- Known fix guard: `{info.get('guard', 'none')}`")
            lines.append(f"- Learned from pairs: `{', '.join(_pairs_of(info))}`")
        info_o = (obligations or {}).get(finding.finding_id)
        if info_o is not None:
            cited_obligations[finding.finding_id] = info_o
            _append_obligation_lines(lines, info_o, (mechanisms or {}).get(str(info_o.get("known_fix") or "")))
        lines.extend(["", finding.rationale, ""])
    if coverage:
        _append_coverage(lines, coverage)
    if patterned:
        _append_pattern_matches(lines, patterned)
    if cited:
        _append_mechanisms(lines, cited)
    if cited_obligations:
        _append_obligations(lines, cited_obligations, obligations_summary)
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
    mechanisms: Mapping[str, Mapping[str, object]] | None = None,
    obligations: Mapping[str, Mapping[str, object]] | None = None,
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
                    _sarif_result(
                        finding,
                        verification_by_id.get(finding.finding_id),
                        overlay_by_id.get(finding.finding_id),
                        mechanisms=mechanisms,
                        obligation=(obligations or {}).get(finding.finding_id),
                    )
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
    provenance: dict[str, object] | None = None,
    variants: dict[str, object] | None = None,
    obligations: dict[str, object] | None = None,
    model: dict[str, object] | None = None,
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
                "rung": finding.rung,
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
    if provenance is not None:
        payload["provenance"] = provenance
    if variants is not None:
        payload["variants"] = variants
    if obligations is not None:
        payload["obligations"] = obligations
    if model is not None:
        payload["model"] = model
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


def _sarif_result(
    finding: StaticFinding,
    verification: VerificationResult | None,
    overlay: object | None = None,
    *,
    mechanisms: Mapping[str, Mapping[str, object]] | None = None,
    obligation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    properties: dict[str, object] = {
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence_level": finding.evidence_level,
        "rung": finding.rung,
        "verification": asdict(verification) if verification else None,
        "reachability_status": finding.reachability_status,
        "reachability_conditions": finding.reachability_conditions,
        "ranking_priority": finding.ranking_priority,
    }
    if overlay is not None:
        properties["disposition"] = getattr(overlay, "disposition", "")
        properties["overlay_reason"] = getattr(overlay, "reason", "")
    mechanism_id = _mechanism_id_for(finding, overlay)
    if mechanism_id:
        properties["mechanism_id"] = mechanism_id
        info = (mechanisms or {}).get(mechanism_id)
        if info is not None:
            properties["mechanism_summary"] = str(info.get("summary", ""))
            properties["mechanism_guard"] = str(info.get("guard", "none"))
            properties["mechanism_pairs"] = _pairs_of(info)
    if obligation is not None:
        properties["obligation_kind"] = str(obligation.get("obligation", ""))
        properties["obligation_resource"] = obligation.get("resource")
        properties["obligation_missing"] = str(obligation.get("missing", ""))
        properties["obligation_provenance"] = obligation.get("provenance")
        properties["obligation_label"] = str(obligation.get("label", ""))
        properties["obligation_evidence"] = _strings_of(obligation, "evidence")
        properties["obligation_known_fix"] = obligation.get("known_fix")
        properties["obligation_intent"] = obligation.get("intent")
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


# How many sites a pattern rule may have before it is summarised instead of listed in full. A rule at or
# under this keeps the behaviour it always had; over it, the report stops repeating itself.
_PATTERN_DETAIL_LIMIT = 3


def _crowded_pattern_rules(findings: Sequence[StaticFinding]) -> list[StaticFinding]:
    """Pattern-only findings belonging to a rule that matched more sites than are worth listing."""
    counts: dict[str, int] = {}
    for finding in findings:
        if _is_pattern_only(finding):
            rule = str(finding.finding_id).split(":", 1)[0]
            counts[rule] = counts.get(rule, 0) + 1
    return [
        finding
        for finding in findings
        if _is_pattern_only(finding) and counts.get(str(finding.finding_id).split(":", 1)[0], 0) > _PATTERN_DETAIL_LIMIT
    ]


def _append_coverage(lines: list[str], coverage: Sequence[Mapping[str, object]]) -> None:
    """What was looked for, and what could not be decided (Req 5.6).

    A scan that reports nothing has established that nothing it MODELS was found. That is not the same as
    finding nothing, and the difference is the whole reason this section exists: a silent report read as a
    clean bill of health is worse than a noisy one, because the reader acts on it.
    """
    lines.extend(
        [
            "## What was analysed",
            "",
            "Each family below was offered to at least one region. **A family that reported nothing has "
            "established only that nothing it models was found** — silence here means no fact table covered "
            "the code, not that the code is safe.",
            "",
            "| language | family | regions | operations modelled |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in coverage:
        lines.append(f"| {row.get('language')} | `{row.get('family')}` | {row.get('regions')} | {row.get('modelled')} |")
    lines.append("")

    stated = [row for row in coverage if str(row.get("limits") or "")]
    if stated:
        lines.extend(["### Stated limits", ""])
        for row in stated:
            lines.extend([f"**`{row.get('family')}` ({row.get('language')})** — {row.get('limits')}", ""])


def _is_pattern_only(finding: StaticFinding) -> bool:
    """Is a text match the only thing behind this finding?

    `static_corroboration` is what the static layer emits when a pattern matched and nothing else spoke. A
    proposer that reasoned about the site -- the model layer, the obligations checker -- carries `suspicion`
    here even when its rung is also suspicion, and that is the distinction: an undecided CLAIM is not the
    same as an observation that an API is present.
    """
    return str(finding.evidence_level) == "static_corroboration" and str(finding.rung) == "suspicion"


def _append_pattern_matches(lines: list[str], patterned: Sequence[StaticFinding]) -> None:
    """Pattern matches, grouped by rule. Proportionate: few sites are named, many are counted."""
    by_rule: dict[str, list[StaticFinding]] = {}
    for finding in patterned:
        by_rule.setdefault(str(finding.finding_id).split(":", 1)[0], []).append(finding)

    lines.extend(
        [
            "## Pattern matches",
            "",
            f"{len(patterned)} site(s) matched a static pattern with nothing corroborating them. A match says "
            "an API is present, not that it is misused; the model reached none of these, and silence from the "
            "model means no fact table covered the site rather than that it is safe. All of them are in "
            "`findings.json`.",
            "",
        ]
    )
    for rule, items in sorted(by_rule.items(), key=lambda entry: (-len(entry[1]), entry[0])):
        by_file: dict[str, int] = {}
        for finding in items:
            by_file[str(finding.path)] = by_file.get(str(finding.path), 0) + 1
        top = sorted(by_file.items(), key=lambda entry: (-entry[1], entry[0]))[:3]
        where = ", ".join(f"`{name}` ({count})" for name, count in top)
        more = f", and {len(by_file) - len(top)} more file(s)" if len(by_file) > len(top) else ""
        lines.append(f"- `{rule}` — {len(items)} site(s) across {len(by_file)} file(s): {where}{more}")
    lines.append("")


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


def _mechanism_id_for(finding: StaticFinding, overlay: object | None) -> str | None:
    """Mechanism cited by a finding: a `mechanism:<id>` tag on a variant finding, or the merged overlay record's id."""
    for tag in finding.tags:
        if tag.startswith("mechanism:"):
            return tag.split(":", 1)[1]
    merged = getattr(overlay, "mechanism_id", None)
    return str(merged) if merged else None


def _append_mechanisms(lines: list[str], cited: Mapping[str, Mapping[str, object]]) -> None:
    lines.extend(
        ["## Mechanisms", "", "Known mechanisms this report cites (corpus-seeded; variant findings stay suspicions until verified).", ""]
    )
    for mechanism_id, info in sorted(cited.items()):
        pairs = ", ".join(_pairs_of(info)) or "unknown"
        lines.append(
            f"- `{mechanism_id}`: {info.get('summary', '')}; known fix guard `{info.get('guard', 'none')}`; learned from `{pairs}`"
        )
    lines.append("")


def _pairs_of(info: Mapping[str, object]) -> list[str]:
    pairs = info.get("pairs")
    return [str(p) for p in pairs] if isinstance(pairs, list | tuple) else []


def _append_obligation_lines(lines: list[str], info: Mapping[str, object], mechanism: Mapping[str, object] | None) -> None:
    resource = info.get("resource") or "a resource"
    provenance = f" (`{info.get('provenance')}`)" if info.get("provenance") else ""
    evidence = ", ".join(_strings_of(info, "evidence")) or "the operation fact alone"
    lines.append(f"- Obligation: `{info.get('obligation')}` on `{resource}`")
    lines.append(f"- Missing discharger: `{info.get('missing')}`{provenance}")
    lines.append(f"- Evidence: `{info.get('label')}` — {evidence}")
    if info.get("known_fix"):
        guard = mechanism.get("guard") if mechanism else info.get("missing")
        pairs = ", ".join(_pairs_of(mechanism)) if mechanism else "the mechanism store"
        lines.append(f"- Known fix: `{guard}` learned from `{pairs}` ({info.get('known_fix')})")
    if info.get("intent"):
        lines.append(f"- Intent: `{info.get('intent')}`")


def _append_obligations(lines: list[str], cited: Mapping[str, Mapping[str, object]], summary: Mapping[str, object] | None = None) -> None:
    lines.extend(
        ["## Obligations", "", "Operations reached without a dominating discharger; suspicions labeled by why the obligation exists.", ""]
    )
    if summary is not None:
        version = summary.get("policy_version")
        lines.append(f"Sibling sets evaluated: {summary.get('sibling_sets', 0)} (under-populated: {summary.get('under_populated', 0)})")
        lines.append(f"Policy version: {f'`{version}`' if version else 'none'}")
        lines.append("")
        sets = summary.get("sets")
        if isinstance(sets, list | tuple):
            for group in sets:
                if isinstance(group, Mapping):
                    lines.append(f"- `{group.get('module')}` / `{group.get('resource')}`: {group.get('handlers')} handlers")
            lines.append("")
    for finding_id, info in sorted(cited.items()):
        resource = info.get("resource") or "a resource"
        lines.append(f"- `{finding_id}`: `{info.get('obligation')}` on `{resource}` without `{info.get('missing')}` ({info.get('label')})")
    lines.append("")


def _strings_of(info: Mapping[str, object], key: str) -> list[str]:
    value = info.get(key)
    return [str(item) for item in value] if isinstance(value, list | tuple) else []
