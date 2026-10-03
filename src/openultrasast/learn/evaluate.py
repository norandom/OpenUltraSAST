"""Evaluation of a compiled program on repositories it never saw (learned-decision-engine design 4.4-4.5, Req 5.2,
7.3, 7.4).

For each evaluation fold the program decides every candidate of the fold's groups with memory and demonstrations
filtered by the fold's boundary. The raw scores are then **cross-fitted** (:mod:`.calibrate`), and the operating
points are chosen on the *other* folds' calibrated predictions (nested), never on the fold reported:

- **BLOCK**: the lowest threshold whose precision has a Wilson 95% lower bound >= 0.95 (delta units when the data
  has them), counting only candidates whose majority verdict is not ``unsure``; none -> ``precision_unreachable``;
- **ADVISORY**: the highest threshold whose recall is >= 0.90; its precision is reported, not assumed;
- **DROP** below ADVISORY.

Metrics carry repository-cluster bootstrap 95% intervals. A family or language below the pooled floor of positive
and negative repository groups is reported as ``insufficient data``, never as a number. More than 5% parse failures
make the run an instrument failure, not a result.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from .calibrate import Row, check, cross_fit, offered
from .examples import Example
from .folds import Fold
from .labels import PER_FAMILY_FLOOR, POOLED_FLOOR
from .program import Caller, Candidate, Program
from .retrieve import Target
from .schema import BY_NAME, SCHEMA_VERSION, feature_set_digest

TARGET_PRECISION = 0.95
TARGET_RECALL = 0.90
PARSE_FAILURE_LIMIT = 0.05
BOOTSTRAP = 2000
_SIGNAL = re.compile(r"\b[a-z]+(?:\.[a-z_]+)+\b")


@dataclass(frozen=True)
class Prediction:
    fold: str
    family: str
    group: str
    label: int
    s: float
    verdict: str
    unit: str = "pin"
    language: str = "other"
    source: str = ""
    parse_failed: int = 0
    p: float | None = None
    point: str | None = None  # BLOCK | ADVISORY | DROP, from points chosen on the other folds
    pair: str = ""  # the two sides of one candidate share it; "" when only one side is present

    @property
    def blockable(self) -> bool:
        return self.verdict != "unsure"


def wilson_lower(successes: int, n: int, z: float = 1.959964) -> float:
    if n == 0:
        return 0.0
    phat = successes / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return (centre - margin) / (1 + z * z / n)


@dataclass(frozen=True)
class Points:
    block: float | None
    block_offered: bool
    block_reason: str | None
    advisory: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "block": {
                "threshold": self.block,
                "offered": self.block_offered,
                "reason": self.block_reason,
                "target_precision": TARGET_PRECISION,
            },
            "advisory": {"threshold": self.advisory, "target_recall": TARGET_RECALL},
        }


def choose_points(preds: Sequence[Prediction], *, precision: float = TARGET_PRECISION, recall: float = TARGET_RECALL) -> Points:
    """Operating points on calibrated predictions (``p`` set); rows without ``p`` are not decided."""
    rows = [r for r in preds if r.p is not None]
    thresholds = sorted({float(r.p) for r in rows if r.p is not None})
    deltas = [r for r in rows if r.unit == "delta"]
    blockable = [r for r in (deltas or rows) if r.blockable]
    block = None
    for t in thresholds:
        chosen = [r for r in blockable if (r.p or 0.0) >= t]
        if chosen and wilson_lower(sum(r.label for r in chosen), len(chosen)) >= precision:
            block = t
            break
    positives = sum(r.label for r in rows)
    advisory = None
    for t in reversed(thresholds):
        if positives and sum(r.label for r in rows if (r.p or 0.0) >= t) / positives >= recall:
            advisory = t
            break
    return Points(block, block is not None, None if block is not None else "precision_unreachable", advisory)


def nested_points(preds: Sequence[Prediction]) -> tuple[list[Prediction], dict[str, Points]]:
    """Each fold's rows decided with the points chosen on the other folds' calibrated predictions."""
    points = {fold: choose_points([r for r in preds if r.fold != fold]) for fold in sorted({r.fold for r in preds})}
    out = []
    for r in preds:
        pts = points[r.fold]
        if r.p is None:
            out.append(r)
            continue
        if pts.block is not None and r.blockable and r.p >= pts.block:
            point = "BLOCK"
        elif pts.advisory is not None and r.p >= pts.advisory:
            point = "ADVISORY"
        else:
            point = "DROP"
        out.append(replace(r, point=point))
    return out, points


BOUNDS = ("wilson", "point")


def precision_threshold(
    rows: Sequence[Prediction], *, precision: float = TARGET_PRECISION, bound: str = "wilson", min_flagged: int = 1
) -> float | None:
    """The lowest raw-score threshold ``t`` at which the blockable rows with ``s >= t`` reach ``precision``: their
    Wilson 95% lower bound (``bound="wilson"``) or their point precision over at least ``min_flagged`` rows
    (``bound="point"``). Candidate thresholds are the rows' own scores; ``None`` when no threshold qualifies."""
    if bound not in BOUNDS:
        raise ValueError(f"bound {bound!r} (one of {', '.join(BOUNDS)})")
    blockable = [r for r in rows if r.blockable]
    for t in sorted({r.s for r in blockable}):
        chosen = [r for r in blockable if r.s >= t]
        hits = sum(r.label for r in chosen)
        if len(chosen) < max(1, min_flagged):
            continue
        level = wilson_lower(hits, len(chosen)) if bound == "wilson" else hits / len(chosen)
        if level >= precision:
            return t
    return None


def nested_precision_block(
    preds: Sequence[Prediction],
    *,
    eligible: Callable[[Prediction], bool] | None = None,
    precision: float = TARGET_PRECISION,
    bound: str = "wilson",
    min_flagged: int = 1,
) -> tuple[list[Prediction], dict[str, dict[str, float | None]]]:
    """Selective blocking on the raw score, per family: the threshold for outer fold j is chosen on the *other* folds'
    rows of the family only (and, with ``eligible``, only those rows); the held-out fold's labels never enter it.
    Every row of fold j is then decided with that threshold: ``BLOCK`` when blockable and ``s >= t``, else ``DROP``.
    A family whose training folds reach no threshold offers no BLOCK on that fold. Returns the decided rows and the
    thresholds by family and fold."""
    thresholds: dict[str, dict[str, float | None]] = {}
    for family in sorted({r.family for r in preds}):
        rows = [r for r in preds if r.family == family]
        thresholds[family] = {
            fold: precision_threshold(
                [r for r in rows if r.fold != fold and (eligible is None or eligible(r))],
                precision=precision, bound=bound, min_flagged=min_flagged,
            )
            for fold in sorted({r.fold for r in rows})
        }  # fmt: skip
    out = []
    for r in preds:
        t = thresholds[r.family][r.fold]
        out.append(replace(r, point="BLOCK" if t is not None and r.blockable and r.s >= t else "DROP"))
    return out, thresholds


def calibrated_block(preds: Sequence[Prediction], *, seed: int = 0, **floors: int) -> tuple[list[Prediction], dict[str, Any]]:
    """Today's BLOCK rule, per family as the slice-2 evaluation applied it: the Platt map cross-fitted on the other
    folds, the calibration check on the family's held-out calibrated predictions, the BLOCK point chosen on the other
    folds' calibrated predictions (nested); a row is ``BLOCK`` only when the family's calibration holds. Returns the
    decided rows and, per family, the check and the calibrated thresholds by fold."""
    out: list[Prediction] = []
    info: dict[str, Any] = {}
    for family in sorted({r.family for r in preds}):
        rows = [r for r in preds if r.family == family]
        ps, _ = cross_fit([Row(r.fold, r.family, r.group, r.label, r.s) for r in rows], **floors)
        calibrated = [replace(r, p=p) for r, p in zip(rows, ps, strict=True)]
        decided = [r for r in calibrated if r.p is not None]
        checked = (
            check([float(r.p) for r in decided if r.p is not None], [r.label for r in decided], [r.group for r in decided], seed=seed)
            if len({r.label for r in decided}) == 2
            else None
        )
        holds = bool(checked and checked.holds)
        nested, points = nested_points(calibrated)
        out += [replace(r, point="BLOCK" if holds and r.point == "BLOCK" else "DROP") for r in nested]
        info[family] = {
            "calibration_holds": holds, "ece": None if checked is None else round(checked.ece, 4),
            "thresholds_by_fold": {f: p.block for f, p in points.items()},
            "reason_by_fold": {f: ("calibration" if not holds else p.block_reason) for f, p in points.items()},
        }  # fmt: skip
    return out, info


def _at(rows: Sequence[Prediction], level: str) -> dict[str, float | None]:
    flagged = [r for r in rows if r.point in (("BLOCK",) if level == "block" else ("BLOCK", "ADVISORY"))]
    positives = sum(r.label for r in rows)
    benign = [r for r in rows if r.label == 0 and r.unit == "delta"]
    return {
        "recall": sum(r.label for r in flagged) / positives if positives else None,
        "precision": sum(r.label for r in flagged) / len(flagged) if flagged else None,
        "false_per_100_benign_deltas": 100 * sum(1 for r in benign if r.point == "BLOCK") / len(benign)
        if benign and level == "block"
        else None,
    }


def cluster_bootstrap(
    rows: Sequence[Prediction], stat: Callable[[Sequence[Prediction]], float | None], *, resamples: int = BOOTSTRAP, seed: int = 0
) -> tuple[float, float] | None:
    by_group: dict[str, list[Prediction]] = {}
    for r in rows:
        by_group.setdefault(r.group, []).append(r)
    names = sorted(by_group)
    if not names:
        return None
    rng = random.Random(seed)
    values = []
    for _ in range(resamples):
        sample = [r for g in (rng.choice(names) for _ in names) for r in by_group[g]]
        value = stat(sample)
        if value is not None:
            values.append(value)
    if not values:
        return None
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def summary(rows: Sequence[Prediction], *, resamples: int = BOOTSTRAP, seed: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {"candidates": len(rows), "groups": len({r.group for r in rows})}

    def statistic(level: str, name: str) -> Callable[[Sequence[Prediction]], float | None]:
        return lambda sample: _at(sample, level)[name]

    for level in ("block", "advisory"):
        point = _at(rows, level)
        out[level] = {
            name: {"value": value, "ci": cluster_bootstrap(rows, statistic(level, name), resamples=resamples, seed=seed)}
            for name, value in point.items()
            if value is not None
        }
    return out


def floor_status(rows: Sequence[Prediction]) -> str:
    pos = len({r.group for r in rows if r.label == 1})
    neg = len({r.group for r in rows if r.label == 0})
    level = min(pos, neg)
    return "per_family" if level >= PER_FAMILY_FLOOR else "pooled" if level >= POOLED_FLOOR else "insufficient data"


def strata(rows: Sequence[Prediction], key: Callable[[Prediction], str], **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in sorted({key(r) for r in rows}):
        part = [r for r in rows if key(r) == name]
        status = floor_status(part)
        out[name] = {"status": status} if status == "insufficient data" else {"status": status, **summary(part, **kw)}
    return out


def explain(rationale: str, x: Mapping[str, Any]) -> list[str]:
    """The signals the rationale names that the record holds (a name it invents is dropped)."""
    named = dict.fromkeys(m.group(0) for m in _SIGNAL.finditer(rationale))
    return [n for n in named if n in BY_NAME and n in x and x[n] is not None]


def incompatible(artifact: Mapping[str, Any], record: Mapping[str, Any], signature_digest: str) -> str | None:
    """Why a program may not decide a record (the caller falls back to today's behaviour and says so)."""
    if artifact.get("schema_version") != SCHEMA_VERSION or record.get("schema_version") != SCHEMA_VERSION:
        return "schema version differs"
    if artifact.get("feature_set_digest") != feature_set_digest() or record.get("feature_set_digest") != feature_set_digest():
        return "feature set differs"
    if (artifact.get("signature") or {}).get("digest") != signature_digest:
        return "signature differs"
    if artifact.get("profile") != record.get("profile"):
        return "profile differs"
    return None


def targets(folds: Sequence[Fold], examples: Sequence[Example], *, skip: Iterable[str] = ()) -> list[tuple[Example, Fold]]:
    """(example, fold) for every example of every usable fold's evaluated groups; ``skip`` families are never asked
    (the families below the floor: no money is spent on them)."""
    skipped = set(skip)
    return [(e, f) for f in folds if f.status == "ok" for e in examples if e.group in f.eval_groups and e.family not in skipped]


def predict(
    program: Program,
    folds: Sequence[Fold],
    caller: Caller,
    candidate_of: Callable[[Any], Candidate | None],
    *,
    seed: int = 0,
    pairs: Sequence[tuple[Example, Fold]] | None = None,
) -> list[Prediction]:
    """Decide every example of every fold's evaluated groups (or the given ``pairs``), each under its own fold."""
    out: list[Prediction] = []
    for example, fold in pairs if pairs is not None else targets(folds, program.memory):
        candidate = candidate_of(example)
        if candidate is None:
            continue
        decision = program.decide(candidate, fold, caller, seed=seed)
        out.append(
            Prediction(
                fold.name, example.family, example.group, example.label, decision.s, decision.verdict, example.unit, example.language,
                example.source, decision.parse_failed,
            )
        )  # fmt: skip
    return out


def unevaluable_families(examples: Sequence[Example], *, floor: int = POOLED_FLOOR) -> list[str]:
    """Families below the pooled floor of positive and negative repository groups: reported, never evaluated."""
    out = []
    for family in sorted({e.family for e in examples}):
        pos = len({e.group for e in examples if e.family == family and e.label == 1})
        neg = len({e.group for e in examples if e.family == family and e.label == 0})
        if min(pos, neg) < floor:
            out.append(family)
    return out


def learning_curve(
    program: Program,
    pairs: Sequence[tuple[Example, Fold]],
    caller: Caller,
    candidate_of: Callable[[Any], Candidate | None],
    *,
    fractions: Sequence[float] = (0.0, 0.25, 0.5, 1.0),
    seed: int = 0,
) -> list[dict[str, Any]]:
    """The metric as a function of memory size: a seeded share of the memory's groups, the same fixed candidates."""
    from .compile import balanced_brier

    groups = sorted({e.group for e in program.memory}, key=lambda g: hashlib.sha256(f"{seed}\x00curve\x00{g}".encode()).hexdigest())
    points = []
    for fraction in fractions:
        kept = set(groups[: int(len(groups) * fraction + 0.5)])
        sub = replace(program, memory=[e for e in program.memory if e.group in kept])
        preds = predict(sub, [], caller, candidate_of, seed=seed, pairs=pairs)
        brier = balanced_brier([(p.family, p.label, p.group, p.s) for p in preds])
        points.append({"memory_fraction": fraction, "memory_groups": len(kept), "candidates": len(preds), "balanced_brier": brier})
    return points


def evaluate(preds: Sequence[Prediction], *, resamples: int = BOOTSTRAP, seed: int = 0, **floors: int) -> dict[str, Any]:
    """Cross-fitted calibration, its check, nested operating points and the report (counts and intervals only)."""
    failed = sum(r.parse_failed for r in preds)
    answers = len(preds) or 1
    rows = [Row(r.fold, r.family, r.group, r.label, r.s) for r in preds]
    ps, maps = cross_fit(rows, **floors)
    calibrated = [replace(r, p=p) for r, p in zip(preds, ps, strict=True)]
    decided = [r for r in calibrated if r.p is not None]
    checked = (
        check([float(r.p) for r in decided if r.p is not None], [r.label for r in decided], [r.group for r in decided], seed=seed)
        if decided
        else None
    )
    nested, points = nested_points(calibrated)
    report: dict[str, Any] = {
        "status": "instrument failure" if failed / answers > PARSE_FAILURE_LIMIT else "ok",
        "parse_failed_share": round(failed / answers, 4),
        "calibration": checked.as_dict() if checked else None,
        "offered": offered(checked) if checked else {"block": {"offered": False, "reason": "insufficient data"}},
        "points_by_fold": {f: p.as_dict() for f, p in points.items()},
        "maps_by_fold": {f: m.as_dict() for f, m in maps.items()},
        "overall": summary([r for r in nested if r.p is not None], resamples=resamples, seed=seed),
        "by_family": strata(nested, lambda r: r.family, resamples=resamples, seed=seed),
        "by_language": strata(nested, lambda r: r.language, resamples=resamples, seed=seed),
        "undecided": sum(1 for r in nested if r.p is None),
    }
    if checked is not None and not checked.holds:
        report["overall"]["block"] = {"offered": False, "reason": "calibration"}
    return report


def candidate_from_example(
    excerpt_text: Callable[[str], str | None], vectors: Mapping[str, Sequence[float]] | None = None
) -> Callable[[Any], Candidate | None]:
    """An evaluation candidate from a memory example: its record and stored excerpt (a 40-line example excerpt)."""

    def make(example: Any) -> Candidate | None:
        code = excerpt_text(example.excerpt_sha)
        if not code:
            return None
        return Candidate(Target.of(example, (vectors or {}).get(example.excerpt_sha)), code, example.language, tuple(example.roles))

    return make


__all__ = [
    "BOUNDS", "PARSE_FAILURE_LIMIT", "TARGET_PRECISION", "TARGET_RECALL", "Points", "Prediction", "calibrated_block",
    "candidate_from_example", "choose_points", "cluster_bootstrap", "evaluate", "explain", "floor_status", "incompatible",
    "learning_curve", "nested_points", "nested_precision_block", "precision_threshold", "predict", "strata", "summary", "targets",
    "unevaluable_families",
    "wilson_lower",
]  # fmt: skip
