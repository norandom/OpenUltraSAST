"""Rule cache filling uses scripted clients and an isolated local store; no provider is contacted."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from learn_fixtures import ScriptedChat, default_answer
from test_learn_experiments import CODE, EXAMPLES, PRICES, excerpt_text, paid
from test_learn_rules import prepared, write_rule_manifest

from openultrasast.cli import main
from openultrasast.learn import experiments as ex
from openultrasast.learn.fill import fill_rule
from openultrasast.learn.program import Candidate, Program, Prompt
from openultrasast.learn.retrieve import Target
from openultrasast.plane.memory import FileStore


def snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def seed_one(store: FileStore, manifest: ex.Manifest, unit: ex.Unit) -> int:
    chat, caller = paid()
    caller.store = store
    example = next(e for e in EXAMPLES if e.id == unit.unit)
    folds = {f.name: f for f in ex.program_folds(EXAMPLES, manifest)[0]}
    program = Program(ex.arm_spec(manifest, manifest.arms["A"], unit.family, store), EXAMPLES, excerpt_text)
    program.decide(Candidate(Target.of(example), CODE[example.excerpt_sha], "python"), folds[unit.fold], caller, seed=0)
    return len(chat.calls)


def total(report: dict[str, Any], key: str) -> int:
    return sum(f[key] for f in report["families"].values())


def test_dry_run_makes_zero_calls_and_writes_nothing(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path)
    cached = seed_one(store, manifest, units[0])
    chat = ScriptedChat()
    before = snapshot(tmp_path)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, dry_run=True)
    assert report["status"] == "dry_run" and report["client_calls"] == 0 and report["usd"] == 0
    assert not chat.calls and snapshot(tmp_path) == before
    assert total(report, "units") == len(units)
    assert total(report, "requests") == 2 * len(units)
    assert total(report, "cached") == cached
    assert total(report, "missing") == 2 * len(units) - cached
    assert total(report, "filled") == 0
    assert all(f["estimated_usd"] > 0 for f in report["families"].values() if f["missing"])


def test_fill_only_missing_requests_then_replay_is_complete(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path)
    cached = seed_one(store, manifest, units[0])
    chat = ScriptedChat()
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=1.0)
    assert report["status"] == "done" and total(report, "still_missing") == 0
    assert total(report, "filled") == report["client_calls"] == len(chat.calls) == 2 * len(units) - cached
    assert 0 < report["usd"] < 1.0
    before = snapshot(tmp_path)
    again = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=1.0)
    assert again["client_calls"] == 0 and total(again, "filled") == 0 and snapshot(tmp_path) == before
    caller, meter = ex.zero_cost_caller("deepseek-flash", PRICES, store)
    replay = ex.run_rule(store, manifest, EXAMPLES, caller, meter, excerpt_text)
    assert replay.decided == {"score": len(units)} and replay.skipped["replay_miss"] == 0
    assert meter.calls == 0 and meter.usd == 0


@pytest.mark.parametrize("explicit_miss", [False, True])
def test_dry_run_uses_mean_billed_cached_usage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit_miss: bool) -> None:
    store, manifest, units = prepared(tmp_path)
    assert seed_one(store, manifest, units[0]) == 2
    paths = sorted((tmp_path / "memory" / "responses").rglob("*"))
    responses = [p for p in paths if p.is_file()]
    assert len(responses) == 2
    for i, path in enumerate(responses, 1):
        entry = json.loads(path.read_bytes())
        entry["usage"] = {"prompt_cache_hit_tokens": 9000 * i, "completion_tokens": 100 * i}
        entry["usage"]["prompt_cache_miss_tokens" if explicit_miss else "prompt_tokens"] = (1000 if explicit_miss else 10000) * i
        path.write_text(json.dumps(entry))
    monkeypatch.setattr(Prompt, "estimated_tokens", property(lambda self: 1_000_000))
    before = snapshot(tmp_path)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, dry_run=True)
    family = report["families"][units[0].family]
    mean_cost = 1.5 * (9000 * 0.014 + 1000 * 0.44 + 100 * 1.32) / 1_000_000
    assert family["missing"] > 0 and family["estimate_method"] == "measured"
    assert family["estimated_usd"] == pytest.approx(family["missing"] * mean_cost)
    other = next(f for name, f in report["families"].items() if name != units[0].family)
    assert other["estimate_method"] == "estimated"
    assert report["client_calls"] == 0 and snapshot(tmp_path) == before


@pytest.mark.parametrize("usage", [None, {}])
def test_dry_run_falls_back_without_cached_usage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, usage: dict[str, int] | None) -> None:
    store, manifest, units = prepared(tmp_path)
    assert seed_one(store, manifest, units[0]) == 2
    for path in (tmp_path / "memory" / "responses").rglob("*"):
        if path.is_file():
            entry = json.loads(path.read_bytes())
            entry.pop("usage")
            if usage is not None:
                entry["usage"] = usage
            path.write_text(json.dumps(entry))
    monkeypatch.setattr(Prompt, "estimated_tokens", property(lambda self: 1000))
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, dry_run=True)
    for family in report["families"].values():
        assert family["estimate_method"] == "estimated"
        assert family["estimated_output_tokens"] == 300
        assert family["estimated_usd"] == pytest.approx(family["missing"] * (1000 * 0.44 + 300 * 1.32) / 1_000_000)


class FixedCostChat(ScriptedChat):
    def complete(self, **kwargs: Any) -> Any:
        response = super().complete(**kwargs)
        self.usage[-1] = {"prompt_tokens": 0, "completion_tokens": 6_000}
        return response


def test_hard_ceiling_stops_before_a_non_multiple_budget_is_exceeded(tmp_path: Path) -> None:
    store, manifest, _ = prepared(tmp_path)
    chat = FixedCostChat()
    prices = {"cache_hit_per_m": 0.0, "input_per_m": 0.0, "output_per_m": 1.0}
    report = fill_rule(store, manifest, EXAMPLES, prices, excerpt_text, client=chat, budget_usd=0.025)
    assert report["status"] == "unfinished"
    assert 0 < report["usd"] <= 0.025
    assert report["usd"] == pytest.approx(len(chat.calls) * 0.006)
    assert report["client_calls"] == total(report, "filled") == len(chat.calls)
    assert total(report, "still_missing") > 0
    assert total(report, "filled") + total(report, "still_missing") == total(report, "missing")


def test_smoke_failure_stops_before_any_fill_and_redacts_provider_error(tmp_path: Path) -> None:
    store, manifest, _ = prepared(tmp_path)

    def fail(*args: Any) -> str:
        raise RuntimeError("provider unavailable SECRET_DO_NOT_PRINT")

    chat = ScriptedChat(fail)
    before = snapshot(tmp_path)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=1.0)
    assert report["status"] == "failed" and report["client_calls"] == len(chat.calls) == 1
    assert total(report, "filled") == 0 and total(report, "still_missing") == total(report, "missing")
    assert snapshot(tmp_path) == before
    assert "SECRET_DO_NOT_PRINT" not in json.dumps(report)


def test_pending_units_refuse_before_calls_or_writes(tmp_path: Path) -> None:
    store, original, _ = prepared(tmp_path)
    path = write_rule_manifest(tmp_path, original.programs["injection"], "exp-902-pending")
    manifest = ex.load_manifest(path)
    ex.register(store, manifest, commit_of=lambda _: "c" * 40)
    chat = ScriptedChat()
    before = snapshot(tmp_path)
    with pytest.raises(ex.ExperimentError, match="pending|frozen|units"):
        fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=1.0)
    assert not chat.calls and snapshot(tmp_path) == before


@pytest.mark.parametrize("budget", [None, -1.0, float("nan"), float("inf")])
def test_paid_fill_requires_a_finite_nonnegative_budget(tmp_path: Path, budget: float | None) -> None:
    store, manifest, _ = prepared(tmp_path)
    chat = ScriptedChat()
    before = snapshot(tmp_path)
    with pytest.raises(ex.ExperimentError, match="budget-usd"):
        fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=budget)
    assert not chat.calls and snapshot(tmp_path) == before


def test_zero_budget_stops_before_smoke(tmp_path: Path) -> None:
    store, manifest, _ = prepared(tmp_path)
    chat = ScriptedChat()
    before = snapshot(tmp_path)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=0.0)
    assert report["status"] == "unfinished" and report["client_calls"] == 0 and report["usd"] == 0
    assert not chat.calls and snapshot(tmp_path) == before


def test_parse_retry_requests_are_cached_for_identical_replay(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path)
    answers = 0

    def first_invalid(messages: Any, temperature: Any) -> str:
        nonlocal answers
        answers += 1
        return "invalid json" if answers == 1 else default_answer(messages, temperature)

    chat = ScriptedChat(first_invalid)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, client=chat, budget_usd=1.0)
    assert report["status"] == "done" and total(report, "still_missing") == 0
    assert len(chat.calls) == 2 * len(units) + 1
    caller, meter = ex.zero_cost_caller("deepseek-flash", PRICES, store)
    replay = ex.run_rule(store, manifest, EXAMPLES, caller, meter, excerpt_text)
    assert replay.decided == {"score": len(units)} and replay.skipped["replay_miss"] == 0
    assert meter.calls == 0


def test_cli_dry_run_needs_no_endpoint_and_does_not_write_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import openultrasast.learn.examples as examples
    import openultrasast.model.endpoint as endpoint

    _, manifest, _ = prepared(tmp_path)
    real_get_blob = FileStore.get_blob

    def get_blob(self: FileStore, kind: str, sha: str, **kwargs: Any) -> bytes | None:
        if kind == "excerpts":
            text = CODE.get(sha)
            return text.encode() if text is not None else None
        return real_get_blob(self, kind, sha, **kwargs)

    monkeypatch.setattr(FileStore, "get_blob", get_blob)
    monkeypatch.setattr(examples, "load_examples", lambda *_: EXAMPLES)
    monkeypatch.setattr(endpoint, "resolve_chat_endpoint", lambda *_: pytest.fail("dry run resolved an endpoint"))
    out = tmp_path / "report.json"
    before = snapshot(tmp_path)
    code = main(
        ["learn", "experiment", "fill", str(manifest.path), "--dry-run", "--memory", f"file://{tmp_path / 'memory'}", "--out", str(out)]
    )
    assert code == 0 and not out.exists() and snapshot(tmp_path) == before
    report = json.loads(capsys.readouterr().out)
    assert report["client_calls"] == 0 and report["status"] == "dry_run"
    assert all(f["estimate_method"] == "estimated" for f in report["families"].values())


def test_growing_call_costs_stay_inside_the_initial_reserve(tmp_path: Path) -> None:
    store, manifest, _ = prepared(tmp_path)

    class GrowingCostChat(ScriptedChat):
        def complete(self, **kwargs: Any) -> Any:
            response = super().complete(**kwargs)
            self.usage[-1] = {"prompt_tokens": 0, "completion_tokens": min(len(self.calls), 9) * 1_000}
            return response

    chat = GrowingCostChat()
    prices = {"cache_hit_per_m": 0.0, "input_per_m": 0.0, "output_per_m": 1.0}
    report = fill_rule(store, manifest, EXAMPLES, prices, excerpt_text, client=chat, budget_usd=0.025)
    assert report["status"] == "unfinished" and 0 < report["usd"] <= 0.025
    assert report["usd"] == pytest.approx(sum(int(row["completion_tokens"]) for row in chat.usage) / 1_000_000)
    assert total(report, "filled") == len(chat.calls) and total(report, "still_missing") > 0


def test_dry_run_prices_prompt_tokens_with_empty_cache(tmp_path: Path) -> None:
    from openultrasast.learn.fill import DEFAULT_OUTPUT_TOKENS

    store, manifest, units = prepared(tmp_path)
    report = fill_rule(store, manifest, EXAMPLES, PRICES, excerpt_text, dry_run=True)
    folds = {f.name: f for f in ex.program_folds(EXAMPLES, manifest)[0]}
    index = {e.id: e for e in EXAMPLES}
    expected = dict.fromkeys(manifest.families, 0.0)
    for unit in units:
        example = index[unit.unit]
        program = Program(ex.arm_spec(manifest, manifest.arms["A"], unit.family, store), EXAMPLES, excerpt_text)
        prompt, _ = program.prepare(Candidate(Target.of(example), CODE[example.excerpt_sha], "python"), folds[unit.fold], seed=0)
        output_tokens = DEFAULT_OUTPUT_TOKENS
        expected[unit.family] += (
            program.spec.k * (prompt.estimated_tokens * PRICES["input_per_m"] + output_tokens * PRICES["output_per_m"]) / 1_000_000
        )
    for family, amount in expected.items():
        assert report["families"][family]["estimated_usd"] == pytest.approx(amount)


def test_bounded_provider_caps_output_and_disables_unmetered_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.model.endpoint import DeepSeekChatClient
    from openultrasast.provider.openrouter import OpenRouterChatClient

    raw_calls: list[dict[str, Any]] = []

    def raw(self: OpenRouterChatClient, **kwargs: Any) -> dict[str, object]:
        raw_calls.append(kwargs)
        assert self.max_attempts == 1
        return {"choices": [{"message": {"role": "assistant", "content": ""}}], "usage": {"prompt_tokens": 20, "completion_tokens": 3}}

    monkeypatch.setattr(OpenRouterChatClient, "complete_chat_raw", raw)
    transport = OpenRouterChatClient(api_key="test-placeholder", max_attempts=3)
    original = DeepSeekChatClient(transport, disable_thinking=True)  # the default: config.models.thinking is False
    bounded = original.bounded(300)
    response = bounded.complete(model="deepseek-flash", messages=[{"role": "user", "content": "JSON"}], tools=[], json_object=True)
    assert response.content == "" and len(raw_calls) == 1
    assert raw_calls[0]["extra_body"]["max_tokens"] == 300
    # The bounded copy keeps the configured client's thinking setting, so a fill answers as the run would.
    assert raw_calls[0]["extra_body"]["thinking"] == {"type": "disabled"}
    thinking_on = DeepSeekChatClient(transport, disable_thinking=False).bounded(300)
    thinking_on.complete(model="deepseek-flash", messages=[{"role": "user", "content": "JSON"}], tools=[], json_object=True)
    assert "thinking" not in raw_calls[-1]["extra_body"]
    assert bounded.usage == [{"prompt_tokens": 20, "completion_tokens": 3}]
    assert original.usage == [] and transport.max_attempts == 3
