from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Protocol
from pathlib import Path

from .preprocess import FileTarget


class RankingError(ValueError):
    """Raised when ranker output does not match the expected schema."""


@dataclass(frozen=True)
class RankingScore:
    path: str
    surface: int
    influence: int
    reachability: int
    priority: float
    rationale: str
    model_id: str | None
    static_boosts: list[str]


class RankerClient(Protocol):
    def complete_json(self, *, model: str, messages: list[dict[str, str]], timeout_seconds: int = 60) -> object:
        raise NotImplementedError


def rank_targets(targets: list[FileTarget], model_rankings: object | None = None, model_id: str | None = None) -> list[RankingScore]:
    model_by_path = parse_ranker_response(model_rankings, model_id) if model_rankings is not None else {}
    rankings: list[RankingScore] = []
    for target in targets:
        heuristic = heuristic_rank(target)
        override = model_by_path.get(target.path)
        rankings.append(_merge_rankings(heuristic, override) if override is not None else heuristic)
    return sorted(rankings, key=lambda item: (-item.priority, item.path))


def rank_targets_with_model(
    targets: list[FileTarget],
    *,
    client: RankerClient,
    model: str,
    chunk_size: int = 150,
    timeout_seconds: int = 60,
) -> list[RankingScore]:
    if chunk_size < 1:
        raise RankingError("chunk_size must be at least 1")
    model_rankings: list[dict[str, object]] = []
    for start in range(0, len(targets), chunk_size):
        chunk = targets[start : start + chunk_size]
        response = client.complete_json(
            model=model,
            messages=[
                {"role": "system", "content": _ranker_system_prompt()},
                {"role": "user", "content": json.dumps([_target_prompt_payload(target) for target in chunk], sort_keys=True)},
            ],
            timeout_seconds=timeout_seconds,
        )
        for ranking in parse_ranker_response(response, model).values():
            model_rankings.append(asdict(ranking))
    return rank_targets(targets, {"rankings": model_rankings}, model_id=model)


def write_rankings(rankings: list[RankingScore], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"rankings": [asdict(ranking) for ranking in rankings]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def heuristic_rank(target: FileTarget) -> RankingScore:
    tags = set(target.tags)
    surface = 1
    influence = 1
    reachability = 1
    boosts: list[str] = []

    if "memory_unsafe" in tags:
        surface = max(surface, 3)
        boosts.append("memory_unsafe")
    if "parser" in tags or "deserialization" in tags:
        surface = max(surface, 4)
        reachability = max(reachability, 3)
        boosts.append("input_parser")
    if "network_entry" in tags:
        reachability = max(reachability, 4)
        boosts.append("network_entry")
    if "auth_boundary" in tags:
        surface = max(surface, 3)
        reachability = max(reachability, 3)
        boosts.append("auth_boundary")
    if "crypto" in tags:
        influence = max(influence, 4)
        boosts.append("crypto")
    if "syscall_entry" in tags or "filesystem_entry" in tags:
        surface = max(surface, 3)
        boosts.append("privileged_boundary")
    if target.has_fuzz_entry_point or "fuzzable" in tags:
        surface = max(surface, 5)
        reachability = max(reachability, 4)
        boosts.append("fuzzable")
    if target.loc >= 500:
        influence = max(influence, 3)
        boosts.append("large_file")
    reachability_boost = _reachability_from_hints(target.reachability_hints)
    if reachability_boost:
        reachability = max(reachability, reachability_boost)
        boosts.append("entry_point_reachable")

    return RankingScore(
        path=target.path,
        surface=surface,
        influence=influence,
        reachability=reachability,
        priority=composite_priority(surface, influence, reachability),
        rationale=_heuristic_rationale(target, boosts),
        model_id=None,
        static_boosts=sorted(set(boosts)),
    )


def composite_priority(surface: int, influence: int, reachability: int) -> float:
    return round(_clamp_score(surface) * 0.5 + _clamp_score(influence) * 0.2 + _clamp_score(reachability) * 0.3, 2)


def parse_ranker_response(payload: object, model_id: str | None) -> dict[str, RankingScore]:
    items = _ranking_items(payload)
    rankings: dict[str, RankingScore] = {}
    for item in items:
        if not isinstance(item, dict):
            raise RankingError("each ranking item must be an object")
        path = item.get("path")
        rationale = item.get("rationale", "model ranking")
        if not isinstance(path, str) or not path:
            raise RankingError("ranking item requires non-empty path")
        if not isinstance(rationale, str) or not rationale:
            raise RankingError(f"ranking item for {path} requires rationale")
        surface = _required_score(item, "surface", path)
        influence = _required_score(item, "influence", path)
        reachability = _required_score(item, "reachability", path)
        static_boosts = item.get("static_boosts", [])
        if not isinstance(static_boosts, list):
            raise RankingError(f"ranking item for {path} has invalid static_boosts")
        rankings[path] = RankingScore(
            path=path,
            surface=surface,
            influence=influence,
            reachability=reachability,
            priority=composite_priority(surface, influence, reachability),
            rationale=rationale,
            model_id=model_id,
            static_boosts=sorted(str(boost) for boost in static_boosts),
        )
    return rankings


def _ranking_items(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        rankings = payload.get("rankings")
        if isinstance(rankings, list):
            return rankings
    raise RankingError("ranker response must be a list or object with rankings list")


def _required_score(item: dict[str, object], field: str, path: str) -> int:
    value = item.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 5:
        raise RankingError(f"ranking item for {path} requires integer {field} from 1 to 5")
    return value


def _merge_rankings(heuristic: RankingScore, model: RankingScore) -> RankingScore:
    return RankingScore(
        path=heuristic.path,
        surface=max(heuristic.surface, model.surface),
        influence=max(heuristic.influence, model.influence),
        reachability=max(heuristic.reachability, model.reachability),
        priority=composite_priority(
            max(heuristic.surface, model.surface),
            max(heuristic.influence, model.influence),
            max(heuristic.reachability, model.reachability),
        ),
        rationale=model.rationale,
        model_id=model.model_id,
        static_boosts=sorted(set(heuristic.static_boosts) | set(model.static_boosts)),
    )


def _heuristic_rationale(target: FileTarget, boosts: list[str]) -> str:
    if boosts:
        return f"heuristic rank from tags: {', '.join(sorted(set(boosts)))}"
    return f"baseline rank for {target.language} file"


def _clamp_score(value: int) -> int:
    return min(5, max(1, value))


def _ranker_system_prompt() -> str:
    return (
        "Score each file for security review priority. Return JSON only with a rankings array. "
        "Each item must include path, surface, influence, reachability, rationale, and optional static_boosts. "
        "Scores must be integers from 1 to 5."
    )


def _target_prompt_payload(target: FileTarget) -> dict[str, object]:
    return {
        "path": target.path,
        "language": target.language,
        "loc": target.loc,
        "tags": target.tags,
        "has_fuzz_entry_point": target.has_fuzz_entry_point,
        "reachability_hints": target.reachability_hints,
    }


def _reachability_from_hints(hints: list[dict[str, object]]) -> int:
    score = 0
    for hint in hints:
        access_level = hint.get("access_level")
        kind = hint.get("kind")
        if access_level == "public":
            score = max(score, 5 if kind in {"route", "parser", "fuzz"} else 4)
        elif access_level in {"authenticated", "contract-only/callback"}:
            score = max(score, 4)
        elif access_level == "role-restricted":
            score = max(score, 3)
        elif access_level == "review-required":
            score = max(score, 2)
        elif access_level == "local-only":
            score = max(score, 2)
    return score
