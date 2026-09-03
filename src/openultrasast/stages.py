from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class Stage(StrEnum):
    STATIC = "static"
    MAP = "map"
    REGRESS = "regress"


MODE_STAGES: dict[str, tuple[Stage, ...]] = {
    "quick": (Stage.STATIC,),
    "standard": (Stage.STATIC, Stage.MAP),
    "deep": (Stage.STATIC, Stage.MAP, Stage.REGRESS),
}


@dataclass(frozen=True)
class StagePlan:
    mode: str
    requested: tuple[Stage, ...]
    completed: tuple[Stage, ...]
    skipped: tuple[dict[str, str], ...]  # stage, reason


def plan_for_mode(mode: str) -> StagePlan:
    return StagePlan(mode=mode, requested=MODE_STAGES[mode], completed=(), skipped=())


def skip_as_degradation(stage: Stage, reason: str) -> dict[str, str]:
    return {"stage": str(stage), "reason": reason}


def record_skip(plan: StagePlan, stage: Stage, reason: str) -> StagePlan:
    return replace(plan, skipped=plan.skipped + (skip_as_degradation(stage, reason),))
