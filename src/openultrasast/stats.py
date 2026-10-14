"""Statistics the research side reports with: intervals, paired comparisons, grouped folds, feature separation.

One place, one convention. Wilson intervals come from statsmodels, exact McNemar from statsmodels, the bootstrap
is a repository-clustered percentile bootstrap with linear-interpolation quantiles, folds come from scikit-learn's
grouped splitters, and separation is the area under the ROC curve of one column against the label. The libraries
are imported inside the functions so the core install (PyYAML only) never pays for them; the `[hunt]` extra does.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

RESAMPLES = 2000
ALPHA = 0.05


def wilson(successes: int, n: int, *, alpha: float = ALPHA) -> tuple[float, float] | None:
    """The Wilson score interval of a proportion; None when there is no denominator."""
    if n <= 0:
        return None
    from statsmodels.stats.proportion import proportion_confint

    low, high = proportion_confint(successes, n, alpha=alpha, method="wilson")
    return float(low), float(high)


@dataclass(frozen=True)
class McNemar:
    """Exact McNemar on paired binary outcomes: `b` units where only A succeeds, `c` where only B does."""

    b: int
    c: int
    concordant: int
    p_value: float


def mcnemar_exact(a: Sequence[bool], b: Sequence[bool]) -> McNemar:
    """Two-sided exact McNemar (binomial on the discordant pairs); p = 1 when nothing is discordant."""
    if len(a) != len(b):
        raise ValueError("paired outcomes must have the same length")
    only_a = sum(1 for x, y in zip(a, b, strict=True) if x and not y)
    only_b = sum(1 for x, y in zip(a, b, strict=True) if y and not x)
    concordant = len(a) - only_a - only_b
    if only_a + only_b == 0:
        return McNemar(only_a, only_b, concordant, 1.0)
    from statsmodels.stats.contingency_tables import mcnemar

    result = mcnemar([[concordant, only_a], [only_b, 0]], exact=True)
    return McNemar(only_a, only_b, concordant, float(min(1.0, result.pvalue)))


def cluster_resample(groups: Sequence[str], rng: Any) -> list[tuple[int, int]]:
    """Draw groups with replacement; return (draw, row index) pairs so a repeated group keeps its own identity."""
    names = sorted(set(groups))
    members: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        members.setdefault(group, []).append(index)
    out: list[tuple[int, int]] = []
    for draw, name in enumerate(rng.choice(names, size=len(names), replace=True)):
        out.extend((draw, index) for index in members[name])
    return out


def _quantiles(values: Sequence[float], alpha: float) -> tuple[float, float]:
    import numpy as np

    low, high = np.quantile(np.asarray(values, dtype=float), [alpha / 2, 1 - alpha / 2])
    return float(low), float(high)


def cluster_bootstrap(
    frame: Any, group: str, stat: Callable[[Any], float | None], *, resamples: int = RESAMPLES, seed: int = 0, alpha: float = ALPHA
) -> tuple[float, float] | None:
    """Percentile interval of `stat(frame)` under a bootstrap that resamples whole groups (repositories)."""
    import numpy as np

    if len(frame) == 0:
        return None
    rng = np.random.default_rng(seed)
    groups = list(frame[group].astype(str))
    values = []
    for _ in range(resamples):
        rows = cluster_resample(groups, rng)
        sample = frame.iloc[[index for _, index in rows]].copy()
        sample[group] = [f"{draw}:{groups[index]}" for draw, index in rows]
        value = stat(sample)
        if value is not None:
            values.append(float(value))
    return _quantiles(values, alpha) if len(values) >= 2 else None


@dataclass(frozen=True)
class Estimate:
    """A paired comparison B minus A over units, with its clustered-bootstrap interval."""

    a: float | None
    b: float | None
    diff: float | None
    ci: tuple[float, float] | None
    se: float | None
    units: int
    groups: int
    resamples: int


def paired_bootstrap(
    frame: Any,
    group: str,
    a: str,
    b: str,
    *,
    stat: Callable[[Any], float | None] | None = None,
    resamples: int = RESAMPLES,
    seed: int = 0,
    alpha: float = ALPHA,
) -> Estimate:
    """B minus A where columns `a` and `b` hold each unit's outcome in both arms; `stat` reduces a column
    (mean by default) and may return None when a resample cannot be scored."""
    import numpy as np

    def mean(column: Any) -> float | None:
        return None if len(column) == 0 else float(column.mean())

    reduce = stat or mean
    a_all, b_all = reduce(frame[a]), reduce(frame[b])
    diff = None if a_all is None or b_all is None else b_all - a_all
    groups = list(frame[group].astype(str))
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(resamples if groups else 0):
        rows = [index for _, index in cluster_resample(groups, rng)]
        sample = frame.iloc[rows]
        x, y = reduce(sample[a]), reduce(sample[b])
        if x is not None and y is not None:
            values.append(y - x)
    ci = se = None
    if len(values) >= 2:
        ci = _quantiles(values, alpha)
        se = float(np.std(values, ddof=1))
    return Estimate(a_all, b_all, diff, ci, se, len(frame), len(set(groups)), len(values))


def group_folds(frame: Any, group: str, *, k: int = 5, seed: int = 0) -> list[tuple[list[int], list[int]]]:
    """K folds that never split a group across train and test (scikit-learn's GroupKFold, shuffled)."""
    from sklearn.model_selection import GroupKFold

    groups = list(frame[group].astype(str))
    if len(set(groups)) < k:
        raise ValueError(f"{len(set(groups))} groups cannot make {k} folds")
    splitter = GroupKFold(n_splits=k, shuffle=True, random_state=seed)
    return [(list(map(int, train)), list(map(int, test))) for train, test in splitter.split(frame, groups=groups)]


def leave_one_group_out(frame: Any, group: str) -> list[tuple[list[int], list[int]]]:
    from sklearn.model_selection import LeaveOneGroupOut

    groups = list(frame[group].astype(str))
    return [(list(map(int, train)), list(map(int, test))) for train, test in LeaveOneGroupOut().split(frame, groups=groups)]


def separation(frame: Any, label: str, columns: Iterable[str]) -> Any:
    """How well each numeric column alone separates label 1 from label 0: area under the ROC curve, the number
    of rows it was computed on, and a note when it could not be. 0.5 is no signal; near 0 or 1 is a leak or a
    strong feature, which the caller decides."""
    import pandas as pd
    from sklearn.metrics import roc_auc_score

    rows: list[dict[str, str | float | None]] = []
    labelled = frame[frame[label].isin([0, 1])]
    for column in columns:
        series = pd.to_numeric(labelled[column], errors="coerce") if column in labelled else None
        if series is None:
            rows.append({"column": column, "auc": None, "n": 0, "note": "missing"})
            continue
        mask = series.notna()
        y = labelled.loc[mask, label].astype(int)
        if mask.sum() == 0 or y.nunique() < 2:
            rows.append({"column": column, "auc": None, "n": int(mask.sum()), "note": "one class or empty"})
            continue
        if series[mask].nunique() < 2:
            rows.append({"column": column, "auc": 0.5, "n": int(mask.sum()), "note": "constant"})
            continue
        rows.append({"column": column, "auc": float(roc_auc_score(y, series[mask])), "n": int(mask.sum()), "note": ""})
    return pd.DataFrame(rows, columns=["column", "auc", "n", "note"])
