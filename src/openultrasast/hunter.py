from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from .findings import StaticFinding, quick_scan_findings
from .preprocess import FileTarget
from .rank import RankingScore

HunterTier = Literal["A", "B", "C"]


@dataclass(frozen=True)
class HunterBudget:
    tier: HunterTier
    max_targets: int
    max_findings_per_target: int
    retrieval_budget_chars: int
    skill_budget_chars: int


@dataclass(frozen=True)
class HunterTask:
    target: FileTarget
    ranking: RankingScore
    tier: HunterTier
    budget: HunterBudget
    selected_skills: list[str]
    retrieval_context: str


@dataclass(frozen=True)
class HunterTrajectory:
    scan_id: str
    target_path: str
    tier: HunterTier
    priority: float
    selected_skills: list[str]
    retrieval_context_chars: int
    findings: list[str]
    status: str


@dataclass(frozen=True)
class HunterPoolResult:
    findings: list[StaticFinding]
    trajectories: list[HunterTrajectory]


DEFAULT_BUDGETS = {
    "A": HunterBudget(tier="A", max_targets=20, max_findings_per_target=20, retrieval_budget_chars=6000, skill_budget_chars=2500),
    "B": HunterBudget(tier="B", max_targets=40, max_findings_per_target=10, retrieval_budget_chars=4000, skill_budget_chars=1500),
    "C": HunterBudget(tier="C", max_targets=80, max_findings_per_target=5, retrieval_budget_chars=2000, skill_budget_chars=800),
}


def assign_tier(priority: float) -> HunterTier:
    if priority >= 3:
        return "A"
    if priority >= 2:
        return "B"
    return "C"


def schedule_hunter_tasks(
    targets: list[FileTarget],
    rankings: list[RankingScore],
    *,
    retrieval_context_by_path: dict[str, str] | None = None,
) -> list[HunterTask]:
    target_by_path = {target.path: target for target in targets}
    retrieval_context_by_path = retrieval_context_by_path or {}
    scheduled: list[HunterTask] = []
    per_tier_counts: dict[HunterTier, int] = {"A": 0, "B": 0, "C": 0}

    for ranking in sorted(rankings, key=lambda item: (-item.priority, item.path)):
        target = target_by_path.get(ranking.path)
        if target is None:
            continue
        tier = assign_tier(ranking.priority)
        budget = DEFAULT_BUDGETS[tier]
        if per_tier_counts[tier] >= budget.max_targets:
            continue
        per_tier_counts[tier] += 1
        scheduled.append(
            HunterTask(
                target=target,
                ranking=ranking,
                tier=tier,
                budget=budget,
                selected_skills=select_skill_snippets(target),
                retrieval_context=retrieval_context_by_path.get(target.path, "")[: budget.retrieval_budget_chars],
            )
        )
    return scheduled


def run_hunter_pool(root: Path, targets: list[FileTarget], rankings: list[RankingScore], *, scan_id: str) -> HunterPoolResult:
    tasks = schedule_hunter_tasks(targets, rankings, retrieval_context_by_path=build_retrieval_context_by_path(root, targets))
    findings: list[StaticFinding] = []
    trajectories: list[HunterTrajectory] = []
    max_workers = min(8, max(1, len(tasks)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for task_findings, trajectory in executor.map(lambda task: _run_hunter_task(root, scan_id, task), tasks):
            findings.extend(task_findings)
            trajectories.append(trajectory)
    return HunterPoolResult(findings=sorted(findings, key=lambda item: item.finding_id), trajectories=trajectories)


def write_hunter_trajectories(trajectories: list[HunterTrajectory], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(asdict(trajectory), sort_keys=True) + "\n" for trajectory in trajectories))


def build_retrieval_context_by_path(root: Path, targets: list[FileTarget], *, max_chars: int = 6000) -> dict[str, str]:
    contexts: dict[str, str] = {}
    for target in targets:
        source = _read_source(root / target.path, max_chars=max_chars)
        if source:
            contexts[target.path] = f"[repo_code] {target.path}\n{source}"
    return contexts


def select_skill_snippets(target: FileTarget, *, max_snippets: int = 4) -> list[str]:
    tags = set(target.tags)
    snippets: list[str] = []
    if target.language in {"c", "cpp", "c++"} or "memory_unsafe" in tags:
        snippets.extend(["address-sanitizer", "libfuzzer", "harness-writing"])
    if "parser" in tags or "fuzzable" in tags:
        snippets.extend(["fuzzing-dictionary", "fuzzing-obstacles"])
    if "crypto" in tags:
        snippets.extend(["constant-time-analysis", "wycheproof"])
    if "auth_boundary" in tags or "network_entry" in tags:
        snippets.extend(["sharp-edges", "insecure-defaults"])
    if "deserialization" in tags:
        snippets.append("semgrep-rule-creator")
    return sorted(dict.fromkeys(snippets))[:max_snippets]


def _run_hunter_task(root: Path, scan_id: str, task: HunterTask) -> tuple[list[StaticFinding], HunterTrajectory]:
    findings = quick_scan_findings(root, [task.target], [task.ranking])[: task.budget.max_findings_per_target]
    return findings, HunterTrajectory(
        scan_id=scan_id,
        target_path=task.target.path,
        tier=task.tier,
        priority=task.ranking.priority,
        selected_skills=task.selected_skills,
        retrieval_context_chars=len(task.retrieval_context),
        findings=[finding.finding_id for finding in findings],
        status="completed",
    )


def _read_source(path: Path, *, max_chars: int) -> str:
    try:
        return path.read_text(errors="ignore")[:max_chars]
    except OSError:
        return ""
