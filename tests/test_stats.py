"""The shared statistics against the formulas the benchmark and the learn harness used."""

from __future__ import annotations

import math

import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("statsmodels")
pytest.importorskip("sklearn")

from openultrasast import stats  # noqa: E402


def test_wilson_matches_the_benchmark_scorer_to_three_decimals():
    from benchmarks.unseen.score import wilson as scorer_wilson

    for successes, n in ((6, 12), (5, 12), (130, 239), (1, 149), (0, 12), (221, 239)):
        low, high = stats.wilson(successes, n)
        old_low, old_high = scorer_wilson(successes, n)
        assert abs(low - old_low) < 1e-3 and abs(high - old_high) < 1e-3, (successes, n)
    assert stats.wilson(0, 0) is None
    low, high = stats.wilson(6, 12)
    assert round(low, 3) == 0.254 and round(high, 3) == 0.746  # the pilot's hunter recall interval


def test_exact_mcnemar_matches_the_learn_harness():
    import random

    from openultrasast.learn.experiments import exact_mcnemar

    rng = random.Random(1)
    for _ in range(20):
        n = rng.randint(1, 40)
        a = [rng.random() < 0.5 for _ in range(n)]
        b = [rng.random() < 0.5 for _ in range(n)]
        ours = stats.mcnemar_exact(a, b)
        theirs = exact_mcnemar(list(zip(a, b, strict=True)))
        assert (ours.b, ours.c, ours.concordant) == (theirs.b, theirs.c, theirs.concordant)
        assert math.isclose(ours.p_value, theirs.p_value, abs_tol=1e-9), (a, b)
    assert stats.mcnemar_exact([True, False], [True, False]).p_value == 1.0
    with pytest.raises(ValueError):
        stats.mcnemar_exact([True], [True, False])


def _frame(seed=0, groups=8, per=6):
    import numpy as np

    rng = np.random.default_rng(seed)
    rows = []
    for g in range(groups):
        for _ in range(per):
            a = rng.random() < 0.4
            rows.append({"repo": f"r{g}", "a": int(a), "b": int(a or rng.random() < 0.3), "label": int(rng.random() < 0.5)})
    return pd.DataFrame(rows)


def test_cluster_bootstrap_is_seeded_and_brackets_the_estimate():
    frame = _frame()
    stat = lambda f: float(f["a"].mean())  # noqa: E731
    first = stats.cluster_bootstrap(frame, "repo", stat, resamples=300, seed=3)
    second = stats.cluster_bootstrap(frame, "repo", stat, resamples=300, seed=3)
    assert first == second and first[0] <= stat(frame) <= first[1]
    assert stats.cluster_bootstrap(frame.iloc[0:0], "repo", stat) is None


def test_paired_bootstrap_reports_b_minus_a_with_an_interval():
    frame = _frame()
    estimate = stats.paired_bootstrap(frame, "repo", "a", "b", resamples=300, seed=1)
    assert estimate.diff == pytest.approx(frame["b"].mean() - frame["a"].mean())
    assert estimate.ci is not None and estimate.ci[0] <= estimate.diff <= estimate.ci[1]
    assert estimate.units == len(frame) and estimate.groups == 8 and estimate.resamples == 300
    assert estimate.se is not None and estimate.se > 0


def test_group_folds_never_split_a_repository():
    frame = _frame(groups=10)
    folds = stats.group_folds(frame, "repo", k=5, seed=0)
    assert len(folds) == 5
    for train, test in folds:
        assert not set(frame.iloc[train]["repo"]) & set(frame.iloc[test]["repo"])
        assert sorted(train + test) == list(range(len(frame)))
    assert len(stats.leave_one_group_out(frame, "repo")) == 10
    with pytest.raises(ValueError):
        stats.group_folds(_frame(groups=3), "repo", k=5)


def test_separation_scores_each_column_alone():
    frame = pd.DataFrame(
        {
            "label": [1, 1, 1, 0, 0, 0, None],
            "perfect": [5, 6, 7, 1, 2, 3, 9],
            "noise": [1, 1, 1, 1, 1, 1, 1],
            "inverse": [1, 2, 3, 5, 6, 7, 0],
            "sparse": [None, None, None, None, None, None, 1],
        }
    )
    out = stats.separation(frame, "label", ["perfect", "noise", "inverse", "sparse", "missing"]).set_index("column")
    assert out.loc["perfect", "auc"] == 1.0 and out.loc["perfect", "n"] == 6
    assert out.loc["inverse", "auc"] == 0.0
    assert out.loc["noise", "auc"] == 0.5 and out.loc["noise", "note"] == "constant"
    assert out.loc["sparse", "auc"] is None or pd.isna(out.loc["sparse", "auc"])
    assert out.loc["missing", "note"] == "missing"
