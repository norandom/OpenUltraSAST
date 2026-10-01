"""Retrieval and the evaluation boundary (learned-decision-engine design 4.2, task 6.3): Gower distance with explicit
missing, the embedding re-rank, the balance rule, and ``test_boundary``."""

from __future__ import annotations

from dataclasses import replace

import pytest
from learn_fixtures import by_id, corpus, example, x_record

from openultrasast.learn.folds import compile_split, leave_one_framework_out, leave_one_source_out, outer_folds
from openultrasast.learn.retrieve import (
    BoundaryViolation,
    Target,
    assert_boundary,
    balance,
    demonstrations_for,
    deployment_fold,
    eligible,
    gower,
    retrieve,
    seed_memory,
)
from openultrasast.learn.schema import features_for, instruments_for

BLOCKS = len(instruments_for("static"))
ENGINE = [s for s in features_for("static") if s.instrument == "engine"]
QUICK_NO_PRIOR = [s for s in features_for("static") if s.instrument == "quick" and not s.prior]
QUICK_ALL = [s for s in features_for("static") if s.instrument == "quick"]


def _d(a: dict, b: dict, **kw: str) -> float:
    """The full distance (every block, the engine included): the definition. v1 withholds the engine (below)."""
    kw.setdefault("inputs", "full")
    return gower(a["x"], a["instruments"], b["x"], b["instruments"], "static", **kw)


def test_gower_on_hand_computed_fixtures() -> None:
    base = x_record(hits=2, findings=1)
    assert _d(base, base) == 0.0
    assert _d(base, x_record(hits=2, engine="none")) == pytest.approx(1 / BLOCKS)  # ran vs none: the block is 1
    assert _d(x_record(engine="none"), x_record(engine="none")) == 0.0  # the same non-ran state is 0
    assert _d(x_record(engine="failed"), x_record(engine="none")) == pytest.approx(1 / BLOCKS)  # failed vs none differ
    # 0 vs 10 enabled hits of cap 20 is 0.5; the mechanism bucket `other` (unknown rules) moves 10 of cap 10
    expected = (10 / 20 + 10 / 10) / len(QUICK_NO_PRIOR) / BLOCKS
    assert _d(x_record(hits=0), x_record(hits=10)) == pytest.approx(expected)
    # null in one, a value in the other: rung_max is null without findings, `suspicion` with one
    zero, one = x_record(findings=0), x_record(findings=1)
    assert _d(zero, one) == pytest.approx((1 / 10 + 1) / len(ENGINE) / BLOCKS)  # findings 0 vs 1 (cap 10), rung null vs set


def test_prior_features_are_dropped_with_priors_off() -> None:
    plain, prior = x_record(prior_hits=0), x_record(prior_hits=5)
    assert _d(plain, prior) == 0.0
    assert _d(plain, prior, priors="on") == pytest.approx(5 / 10 / len(QUICK_ALL) / BLOCKS)


def test_v1_distance_contains_no_engine_field() -> None:
    """v1 (the default) withholds the engine: neither its state nor its values move the distance, so neighbours cannot
    carry it; every other block still counts, over one block fewer."""
    ran, failed, none = x_record(findings=3), x_record(engine="failed"), x_record(engine="none")
    for a, b in ((ran, failed), (ran, none), (failed, none), (x_record(findings=0), ran)):
        assert gower(a["x"], a["instruments"], b["x"], b["instruments"], "static") == 0.0
        assert _d(a, b) > 0.0
    hits = x_record(hits=10, engine="failed")
    expected = (10 / 20 + 10 / 10) / len(QUICK_NO_PRIOR) / (BLOCKS - 1)
    assert gower(ran["x"], ran["instruments"], hits["x"], hits["instruments"], "static") == pytest.approx(expected)
    same, other = example("same-engine", group="g1", label=0, engine="failed"), example("other-engine", group="g2", label=1, findings=4)
    v1 = [gower(failed["x"], failed["instruments"], e.x, e.instruments, "static") for e in (same, other)]
    full = [gower(failed["x"], failed["instruments"], e.x, e.instruments, "static", inputs="full") for e in (same, other)]
    assert v1[0] == v1[1] and full[0] < full[1]  # the engine state ranked them; in v1 it cannot


def _target(**kw: object) -> Target:
    rec = x_record(**kw)  # type: ignore[arg-type]
    return Target("target/repo", "injection", "static", rec["x"], rec["instruments"])


def test_rerank_by_embeddings_with_lam_and_signals_only_without_vectors() -> None:
    near_signal = example("near-signal", group="a/a", label=1, hits=0)
    near_code = example("near-code", group="b/b", label=0, hits=8)
    vectors = {near_signal.excerpt_sha: [0.0, 1.0], near_code.excerpt_sha: [1.0, 0.5]}
    fold = outer_folds([near_signal, near_code], k=1)[0]
    fold = replace(fold, eval_groups=frozenset())
    target = replace(_target(hits=0), vector=[1.0, 0.0])
    by_code = retrieve(target, [near_signal, near_code], fold, vectors=vectors, lam=0.0, k=2)
    assert [e.id for e in by_code.examples][0] == near_code.id and by_code.mode == "signals+embeddings"
    by_signal = retrieve(replace(target, vector=None), [near_signal, near_code], fold, vectors=vectors, lam=0.5, k=2)
    assert by_signal.mode == "signals_only" and by_signal.examples[0].id == near_signal.id
    mixed = retrieve(target, [near_signal, near_code], fold, vectors=vectors, lam=0.5, k=2)
    assert mixed.mode == "signals+embeddings" and {e.id for e in mixed.examples} == {near_signal.id, near_code.id}


def test_balance_caps_labels_groups_and_other_families() -> None:
    same = [example(f"s{i}", group=f"g{i % 2}/r", label=1) for i in range(6)]
    taken, state = balance(same, "injection", 6)
    assert len(taken) == 3 and state == "short"  # <= k/2 positives, and no negatives in the pool
    mixed = [example(f"m{i}", group=f"g{i}/r", label=i % 2, family="path" if i < 4 else "injection") for i in range(12)]
    taken, state = balance(mixed, "injection", 6)
    assert sum(e.family != "injection" for e in taken) <= 2 and state == "ok"
    assert sum(e.label for e in taken) == 3
    crowded = [example(f"c{i}", group="one/repo", label=i % 2) for i in range(10)]
    taken, state = balance(crowded, "injection", 6)
    assert len(taken) == 2 and state == "short"  # at most 2 per repository group


def test_near_duplicates_drop_in_evaluation_and_stay_in_deployment() -> None:
    twin = example("twin", group="fork/repo", label=1)
    other = example("other", group="x/y", label=0)
    vectors = {twin.excerpt_sha: [1.0, 0.0], other.excerpt_sha: [0.0, 1.0]}
    target = replace(_target(), vector=[1.0, 0.0])
    evaluation = replace(outer_folds([twin], k=1)[0], eval_groups=frozenset())
    got = retrieve(target, [twin, other], evaluation, vectors=vectors, k=2)
    assert got.near_duplicates == 1 and [e.id for e in got.examples] == [other.id]
    deployed, _ = deployment_fold("https://github.com/someone/else", ["fork/repo"])
    kept = retrieve(target, [twin, other], deployed, vectors=vectors, k=2)
    assert kept.near_duplicates == 0 and twin.id in {e.id for e in kept.examples}


def test_deployment_excludes_the_scanned_repository_when_it_is_a_corpus_group() -> None:
    own = example("own", group="acme/webapp", label=1)
    fold, note = deployment_fold("https://github.com/Acme/WebApp.git", ["acme/webapp", "x/y"])
    assert note == "repository is in the corpus: its own cases excluded"
    assert not eligible(own, Target("someone/else", "injection", "static", own.x, own.instruments), fold)
    assert deployment_fold("https://github.com/new/repo", ["acme/webapp"])[1] is None


def _all_folds(examples: list) -> list:
    split = compile_split(examples, seed=3)
    return [
        *outer_folds(examples, seed=3, exclude=split.groups),
        *leave_one_source_out(examples, exclude=split.groups),
        *[f for f in leave_one_framework_out(examples, exclude=split.groups, min_groups=2) if f.status == "ok"],
    ]


def test_boundary() -> None:
    """For outer, leave-one-source-out and leave-one-framework-out folds, every retrieved example and every
    demonstration that reaches a prompt is eligible; ``seed_memory`` writes no example of the case's group."""
    examples = corpus(groups=16)
    index = by_id(examples)
    split = compile_split(examples, seed=3)
    demos = [
        {"example_id": e.id, "label": e.label, "alternate": {"example_id": alt.id, "label": alt.label}}
        for e, alt in zip(
            [e for e in examples if e.group in split.boot and e.frameworks][:3],
            [e for e in examples if e.group in split.boot and not e.frameworks][:3],
            strict=False,
        )
    ]
    folds = _all_folds(examples)
    assert {f.kind for f in folds} == {"outer", "leave_one_source_out", "leave_one_framework_out"}
    checked = 0
    for fold in folds:
        for target_example in [e for e in examples if e.group in fold.eval_groups]:
            target = Target.of(target_example)
            got = retrieve(target, examples, fold, k=6)
            usable = demonstrations_for(demos, index, target, fold)
            rendered = [e.id for e in got.examples] + [str(d["example_id"]) for d in usable]
            assert_boundary(rendered, index, target, fold)
            for example_id in rendered:
                chosen = index[example_id]
                assert chosen.group != target.group and chosen.group not in fold.eval_groups
                assert fold.held_source is None or chosen.source != fold.held_source
                assert fold.held_framework is None or fold.held_framework not in chosen.frameworks
                checked += 1
    assert checked > 100
    for group in {e.group for e in examples}:
        assert all(e.group != group for e in seed_memory(examples, group))


def test_a_demonstration_of_the_held_out_framework_is_swapped_for_its_alternate() -> None:
    flask = example("demo-flask", group="d/flask", label=1, frameworks=("flask",))
    alt = example("demo-plain", group="d/plain", label=1)
    target_example = example("t", group="t/t", label=0, frameworks=("flask",))
    target = Target.of(target_example)
    fold = leave_one_framework_out([flask, target_example], min_groups=1)[0]
    assert fold.held_framework == "flask" and target_example.group in fold.eval_groups
    demos = [{"example_id": flask.id, "alternate": {"example_id": alt.id}}]
    usable = demonstrations_for(demos, by_id([flask, alt]), target, fold)
    assert [d["example_id"] for d in usable] == [alt.id]
    assert demonstrations_for([{"example_id": flask.id, "alternate": None}], by_id([flask]), target, fold) == []


def test_assert_boundary_catches_an_ineligible_rendered_id() -> None:
    examples = corpus(groups=6)
    fold = outer_folds(examples, k=3)[0]
    target_example = next(e for e in examples if e.group in fold.eval_groups)
    sibling = next(e for e in examples if e.group == target_example.group and e.id != target_example.id)
    with pytest.raises(BoundaryViolation, match="target group"):
        assert_boundary([sibling.id], by_id(examples), Target.of(target_example), fold)
    with pytest.raises(BoundaryViolation, match="not in the memory"):
        assert_boundary(["0" * 64], by_id(examples), Target.of(target_example), fold)
