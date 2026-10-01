"""Folds by repository group (learned-decision-engine design 4.3-4.4, task 6.3)."""

from __future__ import annotations

import pytest
from learn_fixtures import corpus

from openultrasast.learn.folds import (
    INSUFFICIENT,
    Fold,
    FoldError,
    assert_disjoint,
    compile_split,
    folds_digest,
    leave_one_framework_out,
    leave_one_source_out,
    outer_folds,
)


def test_compile_split_is_a_quarter_of_groups_and_disjoint_from_every_evaluation_fold() -> None:
    examples = corpus(groups=20)
    split = compile_split(examples, seed=1)
    groups = {e.group for e in examples}
    assert len(split.groups) == 6 and split.groups <= groups  # 25% of each family's 10 groups, rounded: 3 + 3
    assert split.boot | split.val == split.groups and not split.boot & split.val and len(split.boot) == 4
    folds = [
        *outer_folds(examples, seed=1, exclude=split.groups),
        *leave_one_source_out(examples, exclude=split.groups),
        *leave_one_framework_out(examples, exclude=split.groups, min_groups=2),
    ]
    assert_disjoint(split, folds)
    for fold in folds:
        assert not fold.eval_groups & split.groups


def test_outer_folds_partition_the_remaining_groups_stratified() -> None:
    examples = corpus(groups=20)
    split = compile_split(examples, seed=1)
    folds = outer_folds(examples, seed=1, exclude=split.groups)
    assert len(folds) == 5
    union = set().union(*(f.eval_groups for f in folds))
    assert union == {e.group for e in examples} - split.groups and sum(len(f.eval_groups) for f in folds) == len(union)
    assert max(len(f.eval_groups) for f in folds) - min(len(f.eval_groups) for f in folds) <= 1


def test_folds_are_deterministic_by_seed() -> None:
    examples = corpus(groups=20)
    a, b = compile_split(examples, seed=7), compile_split(examples, seed=7)
    assert a == b and outer_folds(examples, seed=7) == outer_folds(examples, seed=7)
    assert folds_digest(a, outer_folds(examples, seed=7)) == folds_digest(b, outer_folds(examples, seed=7))
    assert any(compile_split(examples, seed=s).groups != a.groups for s in range(1, 6))


def test_leave_one_source_and_framework_out() -> None:
    examples = corpus(groups=12)
    sources = leave_one_source_out(examples)
    assert {f.held_source for f in sources} == {"pairs", "population-v1", "population-v2"}
    for fold in sources:
        assert fold.eval_groups == {e.group for e in examples if e.source == fold.held_source}
    frameworks = {f.held_framework: f for f in leave_one_framework_out(examples)}
    assert set(frameworks) == {"flask", "django"}
    assert all(f.status == INSUFFICIENT and not f.eval_groups for f in frameworks.values())  # 3 groups each < 10
    enough = {f.held_framework: f for f in leave_one_framework_out(examples, min_groups=3)}
    assert enough["flask"].status == "ok" and enough["flask"].eval_groups == {e.group for e in examples if "flask" in e.frameworks}


def test_a_shared_group_is_refused() -> None:
    examples = corpus(groups=8)
    split = compile_split(examples, seed=0)
    leaked = Fold("outer", "outer-x", frozenset({next(iter(split.groups))}))
    with pytest.raises(FoldError, match="compile split"):
        assert_disjoint(split, [leaked])
    twice = [Fold("outer", "a", frozenset({"g"})), Fold("outer", "b", frozenset({"g"}))]
    with pytest.raises(FoldError, match="in a and b"):
        assert_disjoint(split, twice)
