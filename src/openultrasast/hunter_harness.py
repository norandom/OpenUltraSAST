"""HarnessX-backed hunter pool — a real LLM agent loop per ranked target.

A drop-in for :func:`hunter.run_hunter_pool` (same call shape, returns the same
:class:`hunter.HunterPoolResult`) that runs the optional HarnessX agentic plane. It
is lazy/guarded: importing this module never imports ``harnessx``; the extra is only
touched once :meth:`HxScanOrchestrator.run_pool` runs. The agent ``.run()`` path makes
LLM API calls and is therefore exercised only with the extra + credentials present;
the default scan keeps using the deterministic :func:`hunter.run_hunter_pool`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .findings import SEVERITY_LABEL, StaticFinding, _reachability_conditions, _reachability_for_line
from .harness_ext import build_provider, build_sast, require_harnessx
from .hunter import (
    HunterPoolResult,
    HunterTask,
    HunterTrajectory,
    build_retrieval_context_by_path,
    schedule_hunter_tasks,
)
from .policy import CwePolicy, load_policy, resolve_severity
from .preprocess import FileTarget
from .rank import RankingScore
from .ruleset import PatternRule

# The hunter agent is asked to emit findings as a JSON array of these objects.
_FINDINGS_JSON = re.compile(r"\[\s*\{.*\}\s*\]", re.DOTALL)


@dataclass(frozen=True)
class ScanTask:
    """Thin description of one bounded hunter task (wraps, not subclasses, BaseTask)."""

    description: str
    success_criteria: str
    max_steps: int
    token_budget: int | None
    max_cost_usd: float | None


class HxScanOrchestrator:
    """Runs the hunter pool on a real HarnessX agent loop, one bounded task per target."""

    def __init__(
        self,
        *,
        provider_model: str,
        provider: str = "anthropic",
        max_cost_usd: float = 2.0,
        token_threshold: int = 120_000,
    ) -> None:
        require_harnessx()
        self._provider_model = provider_model
        self._provider = provider
        self._max_cost_usd = max_cost_usd
        self._token_threshold = token_threshold
        self._agent: Any = None

    def _build_agent(self) -> Any:
        from harnessx.core.model_config import ModelConfig

        config = build_sast(max_cost_usd=self._max_cost_usd, token_threshold=self._token_threshold)
        return ModelConfig(main=build_provider(self._provider_model, self._provider)).agentic(config)

    def run_pool(
        self,
        root: Path,
        targets: list[FileTarget],
        rankings: list[RankingScore],
        *,
        scan_id: str,
        ruleset: tuple[PatternRule, ...] | None = None,
        policy: dict[str, CwePolicy] | None = None,
        emit: Callable[..., None] | None = None,
    ) -> HunterPoolResult:
        import asyncio

        tasks = schedule_hunter_tasks(targets, rankings, retrieval_context_by_path=build_retrieval_context_by_path(root, targets))
        resolved_policy = policy if policy is not None else load_policy()
        self._agent = self._agent or self._build_agent()
        return asyncio.run(self._run_all(scan_id, tasks, resolved_policy, emit))

    async def _run_all(
        self,
        scan_id: str,
        tasks: list[HunterTask],
        policy: dict[str, CwePolicy],
        emit: Callable[..., None] | None,
    ) -> HunterPoolResult:
        from harnessx.core.harness import BaseTask

        findings: list[StaticFinding] = []
        trajectories: list[HunterTrajectory] = []
        agent = self._agent
        for task in tasks:
            base_task = BaseTask(
                description=self._describe(task),
                success_criteria="Enumerate each reachable tainted sink with file:line and a one-line rationale.",
                max_steps=task.budget.max_findings_per_target,
                token_budget=task.budget.retrieval_budget_chars * 4,
                max_cost_usd=self._max_cost_usd,
            )
            result = await agent.run(base_task, session_id=scan_id)
            task_findings = self._findings_from_result(task, result, policy)
            findings.extend(task_findings)
            trajectories.append(self._trajectory_from_result(scan_id, task, result, task_findings))
            if emit is not None:
                emit(
                    "stage_end",
                    f"hunter_pool:{task.target.path}",
                    {
                        "exit_reason": getattr(result, "exit_reason", "unknown"),
                        "total_steps": getattr(result, "total_steps", 0),
                        "total_cost_usd": getattr(result, "total_cost_usd", 0.0),
                    },
                )
        await agent.cleanup()
        return HunterPoolResult(findings=sorted(findings, key=lambda item: item.finding_id), trajectories=trajectories)

    def _describe(self, task: HunterTask) -> str:
        from .skills import select_skill_context

        context = task.retrieval_context or f"[repo_code] {task.target.path}"
        skills = select_skill_context(task.target, stage="hunt", budget_chars=task.budget.skill_budget_chars)
        skill_block = f"\n\nRelevant security skills:\n{skills}" if skills else ""
        return (
            f"Audit `{task.target.path}` ({task.target.language}) for security-relevant vulnerabilities. "
            f"Report ONLY evidence-backed findings as a JSON array, each object: "
            f'{{"line": <int>, "title": <str>, "cwe": "CWE-NN" (optional), "rationale": <str>}}. '
            f"Emit `[]` if none.{skill_block}\n\nSource context:\n{context}"
        )

    def _findings_from_result(self, task: HunterTask, result: object, policy: dict[str, CwePolicy]) -> list[StaticFinding]:
        items = _extract_findings(getattr(result, "final_output", "") or "")
        findings: list[StaticFinding] = []
        for item in items:
            line = item.get("line")
            line = int(line) if isinstance(line, int) else None
            reachability_status, function_name, reachability_evidence = (
                _reachability_for_line(task.target, line) if line is not None else ("unknown", None, [])
            )
            cwe = str(item.get("cwe", "")) or None
            severity = SEVERITY_LABEL.get(resolve_severity(policy, cwe), "medium") if cwe else "medium"
            line_part = line if line is not None else 0
            findings.append(
                StaticFinding(
                    finding_id=f"hx-hunter:{task.target.path}:{line_part}",
                    path=task.target.path,
                    title=str(item.get("title", "HarnessX hunter finding")),
                    severity=severity,
                    confidence="medium",
                    evidence_level="static_corroboration",
                    rationale=str(item.get("rationale", "Reported by the HarnessX hunter; manual verification required.")),
                    line=line,
                    function_name=function_name,
                    reachability_status=reachability_status,
                    reachability_evidence=reachability_evidence,
                    reachability_conditions=_reachability_conditions(reachability_evidence),
                    tags=sorted(set(task.target.tags)),
                    ranking_priority=task.ranking.priority,
                )
            )
        return findings

    def _trajectory_from_result(
        self, scan_id: str, task: HunterTask, result: object, task_findings: list[StaticFinding]
    ) -> HunterTrajectory:
        return HunterTrajectory(
            scan_id=scan_id,
            target_path=task.target.path,
            tier=task.tier,
            priority=task.ranking.priority,
            selected_skills=task.selected_skills,
            retrieval_context_chars=len(task.retrieval_context),
            findings=[finding.finding_id for finding in task_findings],
            status=str(getattr(result, "exit_reason", "completed")),
        )


def _extract_findings(text: str) -> list[dict[str, object]]:
    """Best-effort extraction of the findings JSON array from the agent's final output."""
    match = _FINDINGS_JSON.search(text)
    if match is None:
        return []
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
