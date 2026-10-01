"""The program (learned-decision-engine design 4.1, task 6.4): rendering without label or identity fields, the
byte-identical prefix, answer parsing, the vote, ``unsure`` never blocks, the metered client's temperature and
ceiling, and the response cache's replay. Every client is scripted."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from learn_fixtures import ScriptedChat, by_id, corpus, x_record

from openultrasast.learn import program as program_module
from openultrasast.learn.folds import outer_folds
from openultrasast.learn.program import (
    PARSE_FAILED,
    Answer,
    Caller,
    Candidate,
    Demo,
    Program,
    ProgramSpec,
    ReplayMiss,
    aggregate,
    classify,
    line_numbers,
    parse_answer,
    render,
    request_key,
)
from openultrasast.learn.retrieve import BoundaryViolation, Retrieval, Target
from openultrasast.learn.schema import EXCLUDED_FIELDS, FeatureRecordError
from openultrasast.model.endpoint import DeepSeekChatClient
from openultrasast.plane.budget import BudgetExhausted, MeteredClient
from openultrasast.plane.memory import FileStore

PRICES = {"cache_hit_per_m": 0.014, "input_per_m": 0.44, "output_per_m": 1.32}
EXAMPLES = corpus(groups=10)
INDEX = by_id(EXAMPLES)
CODE = {
    e.excerpt_sha: f"   10  def f{i}(q):\n   11      return {'execute(q)' if e.label else 'escape(q)'}\n" for i, e in enumerate(EXAMPLES)
}


def excerpt_text(sha: str) -> str | None:
    return CODE.get(sha)


def candidate(code: str = "   40  def view(q):\n   41      return execute(q)\n", group: str = "cand/repo", **kw: object) -> Candidate:
    rec = x_record(**kw)  # type: ignore[arg-type]
    return Candidate(Target(group, "injection", "static", rec["x"], rec["instruments"]), code, "python")


def program(**spec: object) -> Program:
    return Program(ProgramSpec(**spec), EXAMPLES, excerpt_text)  # type: ignore[arg-type]


FOLD = replace(outer_folds(EXAMPLES, k=5)[0], eval_groups=frozenset({"cand/repo"}))


def test_prompts_hold_no_excluded_field_and_no_candidate_label() -> None:
    prompt, got = program().prepare(candidate(), FOLD)
    text = "\n".join(str(m["content"]) for m in prompt.messages)
    for name in EXCLUDED_FIELDS:
        assert not re.search(rf"^{re.escape(name)}\s*[:=]", text, re.MULTILINE), name
    candidate_part = text.rsplit("Candidate:\n", 1)[1]
    assert "label" not in candidate_part and "vulnerable" not in candidate_part
    assert len(got.examples) == 6 and text.count("(label: ") == 6
    leaky = candidate()
    x = {**leaky.target.x, "site_match": True}
    with pytest.raises(FeatureRecordError, match="site_match"):
        render(ProgramSpec(), replace(leaky, target=replace(leaky.target, x=x)), [], [], INDEX, excerpt_text)


def test_missing_instruments_are_said_in_words() -> None:
    prompt, _ = program().prepare(candidate(engine="none"), FOLD)
    tail = str(prompt.messages[-1]["content"]).rsplit("Candidate:\n", 1)[1]
    assert "engine: no coverage" in tail and "delta: not applicable" in tail and "eng.findings" not in tail


def test_the_prefix_is_byte_identical_across_candidates() -> None:
    demo_example = EXAMPLES[0]
    demo = Demo(demo_example.id, demo_example.excerpt_sha, 0, "injection", "not_vulnerable", 0.8, "Line 11 escapes q.", (11,))
    prog = program(demos=(demo,))
    a, _ = prog.prepare(candidate(), FOLD)
    b, _ = prog.prepare(candidate("    7  def other(x):\n    8      return x\n", hits=3), FOLD)
    assert a.messages[0] == b.messages[0] and a.prefix.encode() == b.prefix.encode()
    assert "Demonstration 1:" in a.prefix and a.messages[1] != b.messages[1]


def test_parsing_valid_invalid_and_out_of_range_citations() -> None:
    lines = frozenset({40, 41})
    ok = parse_answer(
        '{"verdict": "vulnerable", "family": "injection", "confidence": 0.9, "rationale": "r", "cited_lines": [41, 99]}', lines
    )
    assert ok == Answer("vulnerable", "injection", 0.9, "r", (41,))
    fenced = '```json\n{"verdict": "unsure", "family": "x", "confidence": 0.5, "rationale": "r", "cited_lines": [40]}\n```'
    assert parse_answer(fenced, lines, families=("injection",)) == Answer("unsure", "none", 0.5, "r", (40,))
    for bad in (
        "not json", '["vulnerable"]', '{"verdict": "maybe", "confidence": 0.5, "rationale": "r", "cited_lines": [40]}',
        '{"verdict": "vulnerable", "confidence": 1.5, "rationale": "r", "cited_lines": [40]}',
        '{"verdict": "vulnerable", "confidence": 0.5, "rationale": "", "cited_lines": [40]}',
        '{"verdict": "vulnerable", "confidence": 0.5, "rationale": "r", "cited_lines": [99]}', "",
    ):  # fmt: skip
        assert parse_answer(bad, lines) is None, bad
    assert line_numbers("   40  a\n   41  b\ndiff:\n@@ -1 +1 @@\n 42 not a line") == {40, 41}


def test_unparsable_answers_are_retried_once_then_unsure_never_not_vulnerable() -> None:
    chat = ScriptedChat(lambda messages, t: "I think it is fine.")
    caller = Caller(MeteredClient(chat, prices=PRICES), "deepseek-flash", PRICES)
    prompt, _ = program().prepare(candidate(), FOLD)
    decision = classify(prompt, caller, 1)
    assert len(chat.calls) == 2 and [c["temperature"] for c in chat.calls] == [0.0, 0.0]
    assert decision.verdict == "unsure" and decision.parse_failed == 1 and decision.s == 0.5 and not decision.blockable


def test_vote_score_and_unsure_never_blocks() -> None:
    v = Answer("vulnerable", "injection", 0.9, "r", (1,))
    n = Answer("not_vulnerable", "injection", 0.8, "r", (1,))
    u = Answer("unsure", "none", 0.4, "r", (1,))
    d = aggregate([v, v, v, n, u, PARSE_FAILED])
    assert d.verdict == "vulnerable" and d.s == pytest.approx((0.9 * 3 + 0.2 + 0.5 + 0.5) / 6) and d.blockable
    assert d.votes == {"vulnerable": 3, "not_vulnerable": 1, "unsure": 2} and d.parse_failed == 1
    assert aggregate([v, v, u, PARSE_FAILED]).verdict == "unsure"  # parse failures vote unsure: a tie is unsure
    tie = aggregate([v, n])
    assert tie.verdict == "unsure" and not tie.blockable
    unsure = aggregate([u, u, v])
    assert unsure.verdict == "unsure" and not unsure.blockable


def test_metered_client_receives_temperature_and_stops_at_its_ceiling() -> None:
    chat = ScriptedChat()
    caller = Caller(MeteredClient(chat, prices=PRICES, budget_usd=10.0), "deepseek-flash", PRICES)
    decision = program(k=3).decide(candidate(), FOLD, caller)
    assert [c["temperature"] for c in chat.calls] == [0.0, 0.7, 0.7] and all(c["json_object"] for c in chat.calls)
    assert decision.verdict == "vulnerable" and decision.votes["vulnerable"] == 3 and decision.retrieval == "signals_only"
    assert decision.neighbours["label"] == {"0": 3, "1": 3}
    capped = Caller(MeteredClient(ScriptedChat(), prices=PRICES, budget_calls=2), "deepseek-flash", PRICES)
    with pytest.raises(BudgetExhausted):
        program(k=3).decide(candidate(), FOLD, capped)


def test_deepseek_client_forwards_temperature() -> None:
    seen: list[dict] = []

    class Raw:
        def complete_chat_raw(self, **kw: object) -> dict:
            seen.append(dict(kw["extra_body"]))  # type: ignore[arg-type]
            return {"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 3}}

    client = DeepSeekChatClient(Raw())  # type: ignore[arg-type]
    MeteredClient(client).complete(model="m", messages=[], tools=[], json_object=True, temperature=0.7)
    assert seen[0]["temperature"] == 0.7 and seen[0]["thinking"] == {"type": "disabled"}
    client.complete(model="m", messages=[], tools=[])
    assert "temperature" not in seen[1]


def test_response_cache_replays_at_zero_cost(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    chat = ScriptedChat()
    first = Caller(MeteredClient(chat, prices=PRICES), "deepseek-flash", PRICES, store=store)
    one = program(k=2).decide(candidate(), FOLD, first)
    assert first.calls == 2 and len(store.blob_names("responses")) == 2
    replay = Caller(None, "deepseek-flash", PRICES, store=store)
    two = program(k=2).decide(candidate(), FOLD, replay)
    assert replay.calls == 0 and replay.replayed == 2 and one == two and replay.usd() == first.usd() and first.usd()
    assert replay.cache_digest() == first.cache_digest()
    with pytest.raises(ReplayMiss):
        program(k=2).decide(candidate("    1  def z():\n    2      return 0\n"), FOLD, replay)
    key = request_key("deepseek-flash", first.params_digest, [{"role": "user", "content": "x"}], 0.0, "0", True)
    assert key != request_key("deepseek-flash", first.params_digest, [{"role": "user", "content": "x"}], 0.7, "0", True)
    stored = json.loads(store.get_blob("responses", store.blob_names("responses")[0], verify=False) or b"{}")
    assert set(stored) == {"content", "model", "usage"}


def test_the_boundary_is_asserted_before_any_call(monkeypatch: pytest.MonkeyPatch) -> None:
    sibling = next(e for e in EXAMPLES if e.group == EXAMPLES[0].group and e.id != EXAMPLES[0].id)
    target_group = EXAMPLES[0].group

    def leaky(*args: object, **kw: object) -> Retrieval:
        return Retrieval((sibling,), "signals_only", "short", 0, 1, 0)

    monkeypatch.setattr(program_module, "retrieve", leaky)
    chat = ScriptedChat()
    with pytest.raises(BoundaryViolation):
        program().decide(candidate(group=target_group), FOLD, Caller(MeteredClient(chat), "deepseek-flash"))
    assert chat.calls == []
