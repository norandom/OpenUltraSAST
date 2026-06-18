import json
from pathlib import Path

import pytest

from openultrasast.preprocess import FileTarget
from openultrasast.provider.openrouter import OpenRouterError, parse_json_content
from openultrasast.rank import (
    RankingError,
    composite_priority,
    parse_ranker_response,
    rank_targets,
    rank_targets_with_model,
    write_rankings,
)


class FakeRankerClient:
    def __init__(self) -> None:
        self.calls = 0

    def complete_json(self, *, model: str, messages: list[dict[str, str]], timeout_seconds: int = 60) -> object:
        self.calls += 1
        assert model == "openrouter/test-ranker"
        return {
            "rankings": [
                {
                    "path": "a.py" if self.calls == 1 else "b.py",
                    "surface": 2,
                    "influence": 3,
                    "reachability": 4,
                    "rationale": "model rationale",
                    "static_boosts": ["model"],
                }
            ]
        }


def test_composite_priority_uses_spec_formula() -> None:
    assert composite_priority(surface=5, influence=4, reachability=3) == 4.2


def test_heuristic_ranking_prioritizes_fuzzable_parser() -> None:
    targets = [
        FileTarget(
            path="parser.c",
            absolute_path="/repo/parser.c",
            language="c",
            loc=10,
            tags=["memory_unsafe", "parser", "fuzzable"],
            has_fuzz_entry_point=True,
        ),
        FileTarget(
            path="util.py",
            absolute_path="/repo/util.py",
            language="python",
            loc=5,
            tags=[],
            has_fuzz_entry_point=False,
        ),
    ]

    rankings = rank_targets(targets)

    assert rankings[0].path == "parser.c"
    assert rankings[0].surface == 5
    assert rankings[0].reachability == 4


def test_parse_ranker_response_rejects_malformed_scores() -> None:
    with pytest.raises(RankingError):
        parse_ranker_response({"rankings": [{"path": "a.py", "surface": 9, "influence": 1, "reachability": 1}]}, "model")


def test_rank_targets_with_model_chunks_requests() -> None:
    targets = [
        FileTarget(path="a.py", absolute_path="/repo/a.py", language="python", loc=1, tags=[], has_fuzz_entry_point=False),
        FileTarget(path="b.py", absolute_path="/repo/b.py", language="python", loc=1, tags=[], has_fuzz_entry_point=False),
    ]
    client = FakeRankerClient()

    rankings = rank_targets_with_model(targets, client=client, model="openrouter/test-ranker", chunk_size=1)

    assert client.calls == 2
    assert {ranking.model_id for ranking in rankings} == {"openrouter/test-ranker"}


def test_parse_json_content_accepts_fenced_json() -> None:
    assert parse_json_content('```json\n{"rankings": []}\n```') == {"rankings": []}


def test_parse_json_content_rejects_non_json() -> None:
    with pytest.raises(OpenRouterError):
        parse_json_content("not json")


def test_write_rankings_emits_artifact(tmp_path: Path) -> None:
    target = FileTarget(
        path="auth.py",
        absolute_path="/repo/auth.py",
        language="python",
        loc=5,
        tags=["auth_boundary"],
        has_fuzz_entry_point=False,
    )
    output = tmp_path / "rank" / "ranking.json"

    write_rankings(rank_targets([target]), output)

    payload = json.loads(output.read_text())
    assert payload["rankings"][0]["path"] == "auth.py"
    assert payload["rankings"][0]["priority"] >= 1


def test_reachability_hints_raise_ranking_priority() -> None:
    target = FileTarget(
        path="routes.py",
        absolute_path="/repo/routes.py",
        language="python",
        loc=5,
        tags=[],
        has_fuzz_entry_point=False,
        reachability_hints=[
            {
                "kind": "route",
                "access_level": "public",
                "trust_boundary": "http_request",
            }
        ],
    )

    ranking = rank_targets([target])[0]

    assert ranking.reachability == 5
    assert "entry_point_reachable" in ranking.static_boosts
