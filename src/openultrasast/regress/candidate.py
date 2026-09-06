"""Candidate selection and safety-gated regression execution."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from ..complexity.ledger import hotspot_key, select_forced_candidates
from ..complexity.map import Hotspot
from ..config import SandboxConfig
from ..findings import StaticFinding
from ..preprocess import LANGUAGE_BY_EXTENSION
from ..sandbox import SandboxJob, SandboxResult, SandboxRunner
from ..sandbox.runner import WORKSPACE_MOUNT
from .recipes import recipe_for
from .safety import UnsafeSnippetError, check_snippet_safety
from .verdict import (
    INCONCLUSIVE,
    MISSING_RECIPE,
    NOT_TRIGGERABLE,
    SAFETY_REJECTED,
    TRIGGERABLE,
    RegressionVerdict,
    is_worth_fixing,
    verdict_from_result,
)

DEFAULT_IMAGES = {
    "python": "python:3.12-alpine",
    "javascript": "node:22-alpine",
    "c": "gcc:13",
}

__all__ = [
    "INCONCLUSIVE",
    "MISSING_RECIPE",
    "NOT_TRIGGERABLE",
    "SAFETY_REJECTED",
    "TRIGGERABLE",
    "CandidateVerdict",
    "RegressionRunner",
    "RegressionVerdict",
    "run_regression",
    "select_candidates",
    "snippet_for",
    "write_verdicts",
]


@dataclass(frozen=True)
class CandidateVerdict:
    path: str
    function_name: str | None
    language: str
    verdict: str
    reason: str
    inventory_finding_ids: tuple[str, ...]
    worth_fixing: bool = False


def select_candidates(
    hotspots: Sequence[Hotspot],
    findings: Sequence[StaticFinding],
    *,
    max_candidates: int,
    policy_severity_by_id: Mapping[str, object] | None = None,
    rule_cwe: Mapping[str, str] | None = None,
) -> tuple[Hotspot, ...]:
    """Select min(max_candidates, ranked hotspots) ∪ sev-5 reachable inventory.

    The cap applies to the ranked hotspot slice. Forced policy-severity-5
    reachable (or inferred-file-surface) inventory stays in the set even when a
    ledger overlay demoted its hotspot out of that slice.
    """
    ranked = tuple(sorted(hotspots, key=lambda item: (-item.score, item.path, item.function_name or "")))
    selected = list(ranked[: max(max_candidates, 0)])
    seen = {hotspot_key(item.path, item.function_name) for item in selected}
    extras: list[Hotspot] = []
    for finding in select_forced_candidates(findings, policy_severity_by_id or {}, rule_cwe=rule_cwe):
        hotspot = _hotspot_for_finding(finding, ranked) or _hotspot_from_forced_finding(finding)
        key = hotspot_key(hotspot.path, hotspot.function_name)
        if key in seen:
            continue
        seen.add(key)
        extras.append(hotspot)
    return tuple(selected + extras)


def _hotspot_for_finding(finding: StaticFinding, hotspots: Sequence[Hotspot]) -> Hotspot | None:
    for hotspot in hotspots:
        if finding.finding_id in hotspot.inventory_finding_ids:
            return hotspot
    key = hotspot_key(finding.path, finding.function_name)
    for hotspot in hotspots:
        if hotspot_key(hotspot.path, hotspot.function_name) == key:
            return hotspot
    return None


def hotspot_from_finding(finding: StaticFinding, *, rationale: str) -> Hotspot:
    """A zero-score hotspot wrapping one finding: forced sev-5 inventory or a variant of a known mechanism."""
    return Hotspot(
        path=finding.path,
        function_name=finding.function_name,
        score=0.0,
        band="low",
        signals={},
        rationale=rationale,
        test_hint=None,
        inventory_finding_ids=(finding.finding_id,),
    )


def _hotspot_from_forced_finding(finding: StaticFinding) -> Hotspot:
    return hotspot_from_finding(finding, rationale="forced reachable severity-5 inventory")


class RegressionRunner:
    """Run a snippet in the sandbox only after the structural safety check passes."""

    def __init__(self, sandbox: SandboxRunner) -> None:
        self._sandbox = sandbox

    def run_recipe(
        self,
        language: str,
        snippet: str,
        image: str,
        sandbox_limits: SandboxConfig,
        *,
        repo_root: Path,
        oracle: Callable[[SandboxResult], bool] | None = None,
    ) -> RegressionVerdict:
        job = recipe_for(language, snippet, image, sandbox_limits, repo_root=repo_root)
        if job is None:
            return verdict_from_result(recipe_missing=True)
        return self.run_snippet(snippet, job, oracle=oracle)

    def run_snippet(
        self, snippet: str, job: SandboxJob | None, *, oracle: Callable[[SandboxResult], bool] | None = None
    ) -> RegressionVerdict:
        if job is None:
            return verdict_from_result(recipe_missing=True)
        try:
            check_snippet_safety(snippet)
        except UnsafeSnippetError:
            return verdict_from_result(safety_rejected=True)
        return verdict_from_result(self._sandbox.run(job), oracle=oracle)


def snippet_for(language: str, path: str, function_name: str | None) -> str:
    """Render a scratch snippet that loads the candidate source inside the sandbox."""
    relative = path.replace("\\", "/")
    workspace_path = f"{WORKSPACE_MOUNT}/{relative}"
    identity = function_name or relative
    if language == "python":
        return (
            f"# candidate {identity}\n"
            "from pathlib import Path\n"
            f"source = Path({workspace_path!r}).read_text()\n"
            f"compile(source, {relative!r}, 'exec')\n"
        )
    if language == "javascript":
        return (
            f"// candidate {identity}\n"
            "const fs = require('fs');\n"
            f"const source = fs.readFileSync({workspace_path!r}, 'utf8');\n"
            "if (!source.length) { process.exit(1); }\n"
        )
    if language == "c":
        return f"/* candidate {identity} */\nint main(void) {{ return 0; }}\n"
    return ""


def run_regression(
    hotspots: Sequence[Hotspot],
    findings: Sequence[StaticFinding],
    *,
    max_candidates: int,
    policy: Mapping[str, object],
    rule_cwe: Mapping[str, str],
    languages_by_path: Mapping[str, str],
    repo_root: Path,
    sandbox: SandboxRunner,
    sandbox_limits: SandboxConfig,
    images: Mapping[str, str],
) -> tuple[CandidateVerdict, ...]:
    """Select candidates under the cap, run recipes in the sandbox, and return verdicts."""
    selected = select_candidates(
        hotspots,
        findings,
        max_candidates=max_candidates,
        policy_severity_by_id=policy,
        rule_cwe=rule_cwe,
    )
    runner = RegressionRunner(sandbox)
    findings_by_id = {finding.finding_id: finding for finding in findings}
    records: list[CandidateVerdict] = []
    for hotspot in selected:
        language = _language_for(hotspot.path, languages_by_path)
        snippet = _proposed_snippet(hotspot, findings) or snippet_for(language, hotspot.path, hotspot.function_name)
        image = images.get(language) or DEFAULT_IMAGES.get(language, "ousast-missing-image")
        mapped = runner.run_recipe(language, snippet, image, sandbox_limits, repo_root=repo_root)
        reachability = _reachability_for(hotspot, findings_by_id)
        mapped = replace(mapped, worth_fixing=is_worth_fixing(mapped.verdict, reachability))
        records.append(
            CandidateVerdict(
                path=hotspot.path,
                function_name=hotspot.function_name,
                language=language,
                verdict=mapped.verdict,
                reason=mapped.reason,
                inventory_finding_ids=hotspot.inventory_finding_ids,
                worth_fixing=mapped.worth_fixing,
            )
        )
    return tuple(records)


def write_verdicts(verdicts: Sequence[CandidateVerdict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"verdicts": [asdict(item) for item in verdicts]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _proposed_snippet(hotspot: Hotspot, findings: Sequence[StaticFinding]) -> str | None:
    for finding in findings:
        snippet = finding.proposed_snippet
        if not snippet:
            continue
        if finding.path == hotspot.path or finding.finding_id in hotspot.inventory_finding_ids:
            return snippet
    return None


def _language_for(path: str, languages_by_path: Mapping[str, str]) -> str:
    if path in languages_by_path:
        return languages_by_path[path]
    return LANGUAGE_BY_EXTENSION.get(Path(path).suffix.lower(), "unknown")


def _reachability_for(hotspot: Hotspot, findings_by_id: Mapping[str, StaticFinding]) -> str:
    statuses = [
        findings_by_id[finding_id].reachability_status for finding_id in hotspot.inventory_finding_ids if finding_id in findings_by_id
    ]
    for status in statuses:
        if is_worth_fixing(TRIGGERABLE, status):
            return status
    return statuses[0] if statuses else "unknown"
