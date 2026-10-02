"""Compilation (learned-decision-engine design 4.3 and 5, task 6.5): bootstrap few-shot keeps only right, confident,
identity-free demonstrations; instruction search on the pre-registered metric; the compile split stays out of every
evaluation fold; a ceiling ends the compile unfinished; a rerun from the response cache reproduces the artifact
byte for byte at $0 (``test_reproducible_from_cache``); the permissive-licence filter for packaged programs."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest
from learn_fixtures import ScriptedChat, by_id, corpus, default_answer, example
from test_plane_memory import FakeObjects, _real_s3

from openultrasast.learn import compile as compile_module
from openultrasast.learn.compile import (
    DEFAULT_SPEC,
    CompileError,
    Scored,
    balanced_brier,
    best,
    canonical,
    compile_program,
    draw_demo_sets,
    identity_hits,
    load_program,
    load_spec,
    packageable,
    permissive,
    program_id,
)
from openultrasast.learn.examples import Example
from openultrasast.learn.folds import Fold, FoldError
from openultrasast.learn.program import Caller, Demo
from openultrasast.plane.budget import MeteredClient
from openultrasast.plane.memory import FileStore, MemoryStore, S3Store

PRICES = {"cache_hit_per_m": 0.014, "input_per_m": 0.44, "output_per_m": 1.32}
MEMORY = corpus(groups=24, per_group=4)
CODE = {e.excerpt_sha: f"   10  def f(q):\n   11      return {'execute(q)' if e.label else 'escape(q)'}\n" for e in MEMORY}
SPEC = load_spec(DEFAULT_SPEC)
PROPOSALS = [f"Instruction {i}: be careful with the signals." if i == 3 else f"Instruction {i}." for i in range(1, 7)]


def excerpt_text(sha: str) -> str | None:
    return CODE.get(sha)


def answer(messages: Sequence[Mapping[str, object]], temperature: float | None) -> str:
    """Proposals on request; a better calibrated confidence under the 'careful' instruction, so the search moves."""
    system = str(messages[0]["content"])
    if system.startswith("Propose instructions"):
        return json.dumps({"instructions": PROPOSALS})
    data = json.loads(default_answer(messages, temperature))
    if "careful" in system:
        data["confidence"] = 0.95
    return json.dumps(data)


@pytest.fixture(params=["file", "fake-s3-select", "s3"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryStore]:
    if request.param == "file":
        yield FileStore(tmp_path / "memory")
    elif request.param == "s3":
        yield from _real_s3()
    else:
        yield S3Store(FakeObjects("works"), "bucket", "p")


def _caller(chat: ScriptedChat, store: MemoryStore | None = None, **budget: object) -> Caller:
    return Caller(MeteredClient(chat, prices=PRICES, **budget), "deepseek-flash", PRICES, store=store)  # type: ignore[arg-type]


def _compile(caller: Caller, store: MemoryStore | None = None, memory: Sequence = MEMORY) -> compile_module.CompileResult:
    return compile_program(memory, caller, excerpt_text, spec=SPEC, store=store, created="2026-10-01", code_commit="test")


def test_reproducible_from_cache(store: MemoryStore) -> None:
    first_chat = ScriptedChat(answer)
    first = _compile(_caller(first_chat, store), store)
    assert first.status == "done" and first.calls > 0 and first.calls == len(first_chat.calls)
    second_chat = ScriptedChat(answer)
    second = _compile(_caller(second_chat, store), store)
    assert second.calls == 0 and second_chat.calls == [] and second.replayed > 0
    assert first.artifact is not None and second.artifact is not None
    assert canonical(first.artifact) == canonical(second.artifact) and first.program_id == second.program_id
    assert load_program(store, str(first.program_id)) == first.artifact
    assert first.artifact["compile"]["usd"] == second.artifact["compile"]["usd"] > 0


def test_the_search_picks_a_better_instruction_and_records_every_configuration() -> None:
    result = _compile(_caller(ScriptedChat(answer)))
    artifact = result.artifact
    assert artifact is not None and artifact["instruction_source"] == "proposed:3" and "careful" in artifact["instruction"]
    configurations = artifact["compile"]["configurations"]
    assert len(configurations) == 7 + 3  # 7 instructions with demo set 1, then the best with sets 2-4
    baseline = configurations[0]["score"]
    assert min(c["score"] for c in configurations) < baseline
    assert artifact["compile"]["spec_sha256"] == SPEC.sha256 and artifact["program_id"] == program_id(artifact)
    assert artifact["data"]["folds_digest"] and len(artifact["demos"]) == 3


def test_bootstrap_keeps_only_right_confident_identity_free_rationales() -> None:
    def naming(messages: Sequence[Mapping[str, object]], temperature: float | None) -> str:
        if str(messages[0]["content"]).startswith("Propose"):
            return json.dumps({"instructions": []})
        data = json.loads(default_answer(messages, temperature))
        tail = str(messages[-1]["content"]).rsplit("Candidate:", 1)[1]
        if "execute" in tail:
            data["rationale"] = "As in CVE-2021-1234 and app/views.py, the value reaches execute."
        return json.dumps(data)

    def timid(messages: Sequence[Mapping[str, object]], temperature: float | None) -> str:
        return json.dumps({**json.loads(default_answer(messages, temperature)), "confidence": 0.5})

    with pytest.raises(CompileError, match="kept no demonstration"):
        _compile(_caller(ScriptedChat(timid)))
    result = _compile(_caller(ScriptedChat(naming)))
    assert result.artifact is not None
    rejected = result.artifact["compile"]["bootstrap"]["rejected"]
    assert rejected.get("rationale names an identity", 0) > 0
    for demo in result.artifact["demos"]:
        assert identity_hits(demo["rationale"]) == [] and demo["label"] == 0  # every positive named an identity


def test_identity_scan() -> None:
    assert identity_hits("See CVE-2020-0001 here.") == ["CVE-2020-0001"]
    assert identity_hits("Line 4 of views.py passes q.") == ["views.py"]
    assert identity_hits("the acme helper", ("acme/webapp", "acme")) == ["acme"]
    assert identity_hits("Line 11 passes the parameter to the query.", ("acme/webapp", "acme")) == []


def test_the_compile_split_never_meets_an_evaluation_fold(monkeypatch: pytest.MonkeyPatch) -> None:
    real = compile_module.outer_folds

    def leaking(examples, **kw):  # type: ignore[no-untyped-def]
        folds = real(examples, **kw)
        return [*folds, Fold("outer", "leak", frozenset({e.group for e in examples}))]

    monkeypatch.setattr(compile_module, "outer_folds", leaking)
    with pytest.raises(FoldError):
        _compile(_caller(ScriptedChat(answer)))


def test_a_ceiling_ends_the_compile_unfinished_with_no_artifact(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    result = _compile(_caller(ScriptedChat(answer), store, budget_calls=5), store)
    assert result.status == "unfinished" and result.artifact is None and result.program_id is None
    assert "calls budget exhausted" in str(result.reason) and store.blob_names("programs") == []


def test_balanced_brier_weights_cells_and_caps_repositories() -> None:
    rows = [("a", 1, "g1", 1.0)] * 10 + [("a", 1, "g2", 0.0)] + [("a", 0, "g3", 0.0)]
    # cell (a, 1): g1 has 10 rows of error 0 (capped to weight 0.5 each = 5), g2 one row of error 1 -> 1/6
    assert balanced_brier(rows, repository_cap=5) == pytest.approx((1 / 6 + 0.0) / 2)
    assert balanced_brier([]) is None


def test_ties_go_to_fewer_prompt_tokens() -> None:
    a = Scored(0, 0, 0.100, {}, 900)
    b = Scored(1, 0, 0.103, {}, 500)
    c = Scored(2, 0, 0.090, {}, 2000)
    assert best([a, b], 0.005) == b and best([a, b, c], 0.005) == c


def test_demo_sets_mix_labels_and_carry_framework_alternates() -> None:
    examples = [example(f"d{i}", group=f"g{i}/r", label=i % 2, family=("injection", "path")[i % 3 == 0],
                        frameworks=("flask",) if i < 4 else ()) for i in range(12)]  # fmt: skip
    pool = [Demo(e.id, e.excerpt_sha, e.label, e.family, "x", 0.9, "r", (1,)) for e in examples]
    sets = draw_demo_sets(pool, by_id(examples), sets=4, size=3, seed=1)
    assert len(sets) == 4 and draw_demo_sets(pool, by_id(examples), sets=4, size=3, seed=1) == sets
    index = by_id(examples)
    for chosen in sets:
        assert {d.label for d in chosen[:2]} == {0, 1} and len(chosen) == 3
        for demo in chosen:
            if demo.alternate is not None:
                assert demo.alternate.label == demo.label
                assert not set(index[demo.example_id].frameworks) & set(index[demo.alternate.example_id].frameworks)


def test_only_permissively_licensed_demonstrations_are_packaged() -> None:
    assert all(permissive(x) for x in ("MIT", "BSD-3-Clause", "Apache-2.0", "ISC", "Zlib", "mit license"))
    assert not any(permissive(x) for x in ("GPL-3.0", "AGPL-3.0", "LGPL-2.1", "unlicensed", "", "proprietary", "MPL-2.0"))
    mit, gpl, unknown, apache = (example(n, group=f"{n}/r", label=1, license=lic) for n, lic in
                                 (("mit", "MIT"), ("gpl", "GPL-3.0"), ("unk", ""), ("apache", "Apache-2.0")))  # fmt: skip
    demo = lambda e, alt=None: {"example_id": e.id, "excerpt_sha": e.excerpt_sha, "label": 1, "rationale": "r", "alternate": alt}  # noqa: E731
    artifact = {"program_id": "x", "demos": [demo(mit), demo(gpl, demo(apache)), demo(unknown, demo(gpl))], "instruction": "i"}
    artifact["program_id"] = program_id(artifact)
    packaged, tally = packageable(artifact, by_id([mit, gpl, unknown, apache]))
    assert tally == {"kept": 1, "swapped": 1, "dropped": 1}
    assert [d["example_id"] for d in packaged["demos"]] == [mit.id, apache.id]
    assert packaged["program_id"] == program_id(packaged) != artifact["program_id"]
    assert packaged["packaged"]["from"] == artifact["program_id"]


def test_a_one_family_compile_asks_only_that_family(monkeypatch: pytest.MonkeyPatch) -> None:
    """``candidate_families`` limits the bootstrap and validation candidates; the compile memory keeps every family
    (retrieval's contrast examples), so the artifact's data counts are those of the whole pool."""
    asked: dict[str, set[str]] = {}
    real = compile_module._order

    def spy(items: Iterable[Example], seed: int, salt: str) -> list[Example]:
        items = list(items)
        asked.setdefault(salt, set()).update(e.family for e in items)
        return real(items, seed, salt)

    monkeypatch.setattr(compile_module, "_order", spy)
    result = compile_program(MEMORY, _caller(ScriptedChat(answer)), excerpt_text, spec=SPEC, candidate_families=("injection",))
    assert result.status == "done" and result.artifact is not None
    assert asked["boot"] == asked["val"] == {"injection"}
    assert result.artifact["data"]["examples"] == len(MEMORY)
    with pytest.raises(CompileError, match="compile split too small"):
        compile_program(MEMORY, _caller(ScriptedChat(answer)), excerpt_text, spec=SPEC, candidate_families=("memory",))
