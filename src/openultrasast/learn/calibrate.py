"""Calibration of the program's score on held-out repositories (learned-decision-engine design 4.4, Req 3.5, 7.4).

Pure Python, no fitted classifier: the raw score ``s`` (the vote mean) is mapped by **Platt scaling** on
``logit(clip(s, 0.01, 0.99))``, a two-parameter logistic fitted by Newton's method with Platt's smoothed targets.

- **Cross-fitted**: the map applied to fold j is fitted on the out-of-fold predictions of the other folds only
  (:func:`cross_fit`), so no map is checked on the fold it was fitted on.
- Per family when the family reaches the per-family floor of positive and negative repository groups; pooled with
  a per-family intercept between the floors; otherwise ``insufficient data`` (no calibrated probability).
- **The check** (:func:`check`): a reliability table (5 quantile bins), the calibration slope and intercept (a
  logistic regression of the label on ``logit(p)``) with repository-bootstrap 95% intervals, and the expected
  calibration error. It holds when the slope interval contains 1, the intercept interval contains 0 and ECE <= 0.05;
  otherwise only ADVISORY is offered (``block.offered = false, reason = "calibration"``).
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .labels import PER_FAMILY_FLOOR, POOLED_FLOOR

CLIP = 0.01
ECE_LIMIT = 0.05
BINS = 5


def logit(p: float) -> float:
    q = min(max(p, CLIP), 1 - CLIP)
    return math.log(q / (1 - q))


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1 / (1 + math.exp(-z))
    e = math.exp(z)
    return e / (1 + e)


def _solve(a: list[list[float]], b: list[float]) -> list[float]:
    """Gaussian elimination with partial pivoting (the systems here are 2 to ~10 wide)."""
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        m[col], m[pivot] = m[pivot], m[col]
        if abs(m[col][col]) < 1e-12:
            continue
        for r in range(n):
            if r != col:
                f = m[r][col] / m[col][col]
                for c in range(col, n + 1):
                    m[r][c] -= f * m[col][c]
    return [m[i][n] / m[i][i] if abs(m[i][i]) >= 1e-12 else 0.0 for i in range(n)]


def fit_logistic(xs: Sequence[Sequence[float]], ys: Sequence[float], *, l2: float = 1e-3, iterations: int = 100) -> list[float]:
    """Weights of ``y ~ sigmoid(w . x)`` by Newton's method with a small ridge (separable data stays finite)."""
    d = len(xs[0]) if xs else 0
    w = [0.0] * d
    for _ in range(iterations):
        grad = [-l2 * wi for wi in w]
        hess = [[(l2 if i == j else 0.0) for j in range(d)] for i in range(d)]
        for x, y in zip(xs, ys, strict=True):
            p = sigmoid(sum(wi * xi for wi, xi in zip(w, x, strict=True)))
            for i in range(d):
                grad[i] += (y - p) * x[i]
                for j in range(d):
                    hess[i][j] += p * (1 - p) * x[i] * x[j]
        step = _solve(hess, grad)
        w = [wi + si for wi, si in zip(w, step, strict=True)]
        if max((abs(s) for s in step), default=0.0) < 1e-9:
            break
    return w


def platt_targets(ys: Sequence[int]) -> list[float]:
    pos = sum(1 for y in ys if y == 1)
    neg = len(ys) - pos
    hi, lo = (pos + 1) / (pos + 2), 1 / (neg + 2)
    return [hi if y == 1 else lo for y in ys]


def fit_platt(scores: Sequence[float], labels: Sequence[int]) -> tuple[float, float]:
    """(a, b) of ``p = sigmoid(a logit(s) + b)``."""
    a, b = fit_logistic([[logit(s), 1.0] for s in scores], platt_targets(labels))
    return a, b


@dataclass(frozen=True)
class Row:
    """One out-of-fold prediction: its fold, family, repository group, label and raw score."""

    fold: str
    family: str
    group: str
    label: int
    s: float


@dataclass(frozen=True)
class CalibrationMap:
    per_family: Mapping[str, tuple[float, float]] = field(default_factory=dict)
    pooled: tuple[float, float] | None = None  # slope and baseline intercept of the pooled map
    intercepts: Mapping[str, float] = field(default_factory=dict)  # per-family intercept shift of the pooled map
    insufficient: tuple[str, ...] = ()

    def apply(self, family: str, s: float) -> float | None:
        if family in self.per_family:
            a, b = self.per_family[family]
            return sigmoid(a * logit(s) + b)
        if self.pooled is not None and family in self.intercepts:
            a, b = self.pooled
            return sigmoid(a * logit(s) + b + self.intercepts[family])
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "per_family": {f: list(v) for f, v in sorted(self.per_family.items())}, "pooled": list(self.pooled) if self.pooled else None,
            "intercepts": dict(sorted(self.intercepts.items())), "insufficient": list(self.insufficient),
        }  # fmt: skip


def _groups(rows: Sequence[Row], family: str, label: int) -> int:
    return len({r.group for r in rows if r.family == family and r.label == label})


def fit_map(rows: Sequence[Row], *, per_family_floor: int = PER_FAMILY_FLOOR, pooled_floor: int = POOLED_FLOOR) -> CalibrationMap:
    families = sorted({r.family for r in rows})
    level = {f: min(_groups(rows, f, 1), _groups(rows, f, 0)) for f in families}
    own = [f for f in families if level[f] >= per_family_floor]
    pooled = [f for f in families if pooled_floor <= level[f] < per_family_floor]
    per_family = {f: fit_platt([r.s for r in rows if r.family == f], [r.label for r in rows if r.family == f]) for f in own}
    pooled_map: tuple[float, float] | None = None
    intercepts: dict[str, float] = {}
    if pooled:
        chosen = [r for r in rows if r.family in pooled]
        xs = [[logit(r.s), 1.0] + [1.0 if r.family == f else 0.0 for f in pooled[1:]] for r in chosen]
        w = fit_logistic(xs, platt_targets([r.label for r in chosen]))
        pooled_map = (w[0], w[1])
        intercepts = {f: (w[2 + i - 1] if i else 0.0) for i, f in enumerate(pooled)}
    return CalibrationMap(per_family, pooled_map, intercepts, tuple(f for f in families if level[f] < pooled_floor))


def cross_fit(rows: Sequence[Row], **floors: int) -> tuple[list[float | None], dict[str, CalibrationMap]]:
    """Calibrated ``p`` per row, each from a map fitted on the other folds' rows only; and the map per fold."""
    maps = {fold: fit_map([r for r in rows if r.fold != fold], **floors) for fold in sorted({r.fold for r in rows})}
    return [maps[r.fold].apply(r.family, r.s) for r in rows], maps


@dataclass(frozen=True)
class Check:
    reliability: tuple[Mapping[str, float], ...]
    slope: float
    slope_ci: tuple[float, float]
    intercept: float
    intercept_ci: tuple[float, float]
    ece: float
    holds: bool
    n: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "reliability": [dict(b) for b in self.reliability], "slope": round(self.slope, 4),
            "slope_ci": [round(v, 4) for v in self.slope_ci], "intercept": round(self.intercept, 4),
            "intercept_ci": [round(v, 4) for v in self.intercept_ci], "ece": round(self.ece, 4), "holds": self.holds, "n": self.n,
        }  # fmt: skip


def _slope_intercept(ps: Sequence[float], ys: Sequence[int]) -> tuple[float, float]:
    a, b = fit_logistic([[logit(p), 1.0] for p in ps], [float(y) for y in ys])
    return a, b


def reliability(ps: Sequence[float], ys: Sequence[int], bins: int = BINS) -> tuple[list[dict[str, float]], float]:
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    table, ece = [], 0.0
    for b in range(bins):
        idx = order[b * len(order) // bins : (b + 1) * len(order) // bins]
        if not idx:
            continue
        mean_p = sum(ps[i] for i in idx) / len(idx)
        rate = sum(ys[i] for i in idx) / len(idx)
        table.append({"n": len(idx), "mean_p": round(mean_p, 4), "positive_rate": round(rate, 4)})
        ece += len(idx) / len(ps) * abs(mean_p - rate)
    return table, ece


def _percentile(values: Sequence[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))]


def check(ps: Sequence[float], ys: Sequence[int], groups: Sequence[str], *, resamples: int = 200, seed: int = 0) -> Check:
    """The calibration check on held-out predictions, with repository-cluster bootstrap intervals."""
    table, ece = reliability(ps, ys)
    slope, intercept = _slope_intercept(ps, ys)
    by_group: dict[str, list[int]] = {}
    for i, g in enumerate(groups):
        by_group.setdefault(g, []).append(i)
    names = sorted(by_group)
    rng = random.Random(seed)
    slopes, intercepts = [], []
    for _ in range(resamples):
        idx = [i for g in (rng.choice(names) for _ in names) for i in by_group[g]]
        sample_y = [ys[i] for i in idx]
        if len(set(sample_y)) < 2:
            continue
        a, b = _slope_intercept([ps[i] for i in idx], sample_y)
        slopes.append(a)
        intercepts.append(b)
    slope_ci = (_percentile(slopes, 0.025), _percentile(slopes, 0.975)) if slopes else (math.nan, math.nan)
    intercept_ci = (_percentile(intercepts, 0.025), _percentile(intercepts, 0.975)) if intercepts else (math.nan, math.nan)
    holds = bool(slopes) and slope_ci[0] <= 1 <= slope_ci[1] and intercept_ci[0] <= 0 <= intercept_ci[1] and ece <= ECE_LIMIT
    return Check(tuple(table), slope, slope_ci, intercept, intercept_ci, ece, holds, len(ps))


def offered(result: Check) -> dict[str, dict[str, Any]]:
    """What a family is offered: ADVISORY always; BLOCK only when calibration holds."""
    block = {"offered": True, "reason": None} if result.holds else {"offered": False, "reason": "calibration"}
    return {"block": block, "advisory": {"offered": True, "reason": None}}


__all__ = [
    "ECE_LIMIT", "CalibrationMap", "Check", "Row", "check", "cross_fit", "fit_logistic", "fit_map", "fit_platt", "logit", "offered",
    "reliability", "sigmoid",
]  # fmt: skip
