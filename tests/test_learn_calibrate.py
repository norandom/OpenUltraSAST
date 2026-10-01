"""Calibration (learned-decision-engine design 4.4, task 6.5): Platt on a known miscalibration, cross-fitting (fold
j's map never saw fold j), the slope/intercept/ECE check, and the ADVISORY-only downgrade."""

from __future__ import annotations

import random

import pytest

from openultrasast.learn.calibrate import Row, check, cross_fit, fit_map, fit_platt, logit, offered, sigmoid


def _sample(n: int, a: float, b: float, seed: int = 0) -> tuple[list[float], list[int]]:
    """Scores whose true probability is ``sigmoid(a logit(s) + b)``: a known miscalibration of ``s``."""
    rng = random.Random(seed)
    scores = [rng.uniform(0.02, 0.98) for _ in range(n)]
    labels = [1 if rng.random() < sigmoid(a * logit(s) + b) else 0 for s in scores]
    return scores, labels


def test_platt_recovers_a_known_miscalibration() -> None:
    scores, labels = _sample(6000, 2.0, -0.5)
    a, b = fit_platt(scores, labels)
    assert a == pytest.approx(2.0, abs=0.15) and b == pytest.approx(-0.5, abs=0.15)


def _rows(n_groups: int, a: float, b: float, *, family: str = "injection", folds: int = 5, seed: int = 0) -> list[Row]:
    scores, labels = _sample(n_groups * 10, a, b, seed)
    return [Row(f"f{(i // 10) % folds}", family, f"g{i // 10}", y, s) for i, (s, y) in enumerate(zip(scores, labels, strict=True))]


def test_cross_fitting_never_fits_a_fold_on_itself() -> None:
    rows = _rows(100, 2.0, 0.0)
    ps, maps = cross_fit(rows, per_family_floor=10, pooled_floor=5)
    assert all(p is not None for p in ps)
    for fold, mapping in maps.items():
        expected = fit_map([r for r in rows if r.fold != fold], per_family_floor=10, pooled_floor=5)
        assert mapping == expected
    # moving fold f0's labels changes every map except f0's own
    flipped = [Row(r.fold, r.family, r.group, 1 - r.label if r.fold == "f0" else r.label, r.s) for r in rows]
    _, flipped_maps = cross_fit(flipped, per_family_floor=10, pooled_floor=5)
    assert flipped_maps["f0"] == maps["f0"] and flipped_maps["f1"] != maps["f1"]


def test_floors_per_family_pooled_and_insufficient() -> None:
    rows = _rows(60, 1.0, 0.0, family="injection") + _rows(12, 1.0, 0.3, family="path", seed=1) + _rows(3, 1.0, 0, family="memory", seed=2)
    mapping = fit_map(rows, per_family_floor=20, pooled_floor=5)
    assert set(mapping.per_family) == {"injection"} and set(mapping.intercepts) == {"path"} and mapping.insufficient == ("memory",)
    assert mapping.apply("memory", 0.7) is None and mapping.apply("path", 0.7) is not None


def test_the_check_holds_on_calibrated_scores_and_fails_otherwise() -> None:
    scores, labels = _sample(1500, 1.0, 0.0, seed=3)
    groups = [f"g{i // 10}" for i in range(len(scores))]
    good = check(scores, labels, groups, resamples=40)
    assert good.holds and good.ece <= 0.05 and good.slope_ci[0] <= 1 <= good.slope_ci[1]
    assert offered(good) == {"block": {"offered": True, "reason": None}, "advisory": {"offered": True, "reason": None}}
    overconfident = [min(0.99, max(0.01, 0.5 + 2.5 * (s - 0.5))) for s in scores]
    bad = check(overconfident, labels, groups, resamples=40)
    assert not bad.holds and bad.slope < 1
    assert offered(bad)["block"] == {"offered": False, "reason": "calibration"} and offered(bad)["advisory"]["offered"]
    assert len(good.reliability) == 5 and sum(b["n"] for b in good.reliability) == 1500
