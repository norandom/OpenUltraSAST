"""Offline, nested repository-held-out classifiers. No clients and no input profiles.

The frozen experiment units define outer boundaries. Inner screens, encoders,
scalers and hyperparameters see only inner training repositories. Scores are
experimental development evidence, not permission to BLOCK a push.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .embeddings import DEFAULT_DIMENSIONS, EmbeddingCache
from .evaluate import Prediction, family_floor, pooled_block_gate, pooled_threshold, wilson_lower
from .examples import Example, load_examples
from .experiments import ArmUnit, Metric, Unit, arm_units, auc, load_outcomes, paired_bootstrap, read_units, within_pair_auc
from .folds import outer_folds
from .leaks import THRESHOLD, Pair, separation, signals
from .schema import FEATURES, STATES

MODELS = ("logistic", "hist_gradient_boosting")
RECORD = Path("benchmarks/measurements/2026-10-04-trained-classifier/record.json")


@dataclass(frozen=True)
class Scored:
    unit: Unit
    model: str
    s: float
    verdict: str = "scored"
    point: str | None = None

    def arm(self) -> ArmUnit:
        u = self.unit
        return ArmUnit(u.unit, u.group, u.family, u.label, u.pair, self.s, self.verdict, None, None)

    def prediction(self) -> Prediction:
        u = self.unit
        return Prediction(u.fold, u.family, u.group, u.label, self.s, self.verdict, p=self.s, pair=u.pair, point=self.point)


def screen(examples: Sequence[Example], pairs: Mapping[str, str]) -> list[str]:
    """Reuse the audit's metric, including instrument states and family strata.

    No minimum pair floor: even a small training split must drop a perfect leak.
    Removing a feature also removes its missingness indicator.
    """
    sides: dict[tuple[str, str, str], dict[int, list[Example]]] = {}
    for e in examples:
        if pairs.get(e.id):
            sides.setdefault((e.group, e.family, pairs[e.id]), {}).setdefault(e.label, []).append(e)
    paired = []
    for (_, family, _), members in sides.items():
        if len(members.get(0, [])) == len(members.get(1, [])) == 1:
            records = [{"x": members[label][0].x, "instruments": members[label][0].instruments} for label in (1, 0)]
            paired.append(Pair(family, records[0], records[1]))
    scopes = [paired] + [[p for p in paired if p.family == f] for f in sorted({p.family for p in paired})]
    return sorted(s.name for s in signals("plane") if any(separation(s, scope)["separation"] >= THRESHOLD for scope in scopes if scope))


def _deps() -> tuple[Any, Any, Any, Any]:
    try:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError("learn train requires the optional train extra: uv sync --extra train") from exc
    return np, HistGradientBoostingClassifier, LogisticRegression, StandardScaler


class Matrix:
    """Fixed schema vocabularies, training-only means/scales; null has its own bit."""

    def __init__(self, examples: Sequence[Example], vectors: Mapping[str, Sequence[float]], dropped: Sequence[str], pooled: bool):
        np, _, _, scaler = _deps()
        self.specs = [s for s in FEATURES if s.name not in dropped]
        self.states = sorted({s.instrument for s in FEATURES} - {n.removeprefix("state.") for n in dropped if n.startswith("state.")})
        self.families = sorted({e.family for e in examples}) if pooled else []
        self.scaler = scaler()
        raw = self.raw(examples, vectors)
        self.scaler.fit(np.asarray(raw, dtype=float))

    def raw(self, examples: Sequence[Example], vectors: Mapping[str, Sequence[float]]) -> list[list[float]]:
        rows = []
        for e in examples:
            vector = vectors.get(e.excerpt_sha)
            if vector is None or len(vector) != DEFAULT_DIMENSIONS or not all(math.isfinite(v) for v in vector):
                raise ValueError("missing, nonfinite or wrong-dimension stored embedding; no embedding calls are permitted")
            row = list(vector)
            for s in self.specs:
                value = e.x.get(s.name) if e.instruments.get(s.instrument, {}).get("state") == "ran" else None
                row.append(float(value is None))
                if s.type == "enum":
                    row.extend(float(value == v) for v in s.vocabulary)
                else:
                    row.append(float(value) if value is not None else 0.0)
            for instrument in self.states:
                state = e.instruments.get(instrument, {}).get("state")
                row.extend(float(state == v) for v in STATES)
                row.append(float(state is None))
            row.extend(float(e.family == f) for f in self.families)
            rows.append(row)
        return rows

    def transform(self, examples: Sequence[Example], vectors: Mapping[str, Sequence[float]]) -> Any:
        return self.scaler.transform(self.raw(examples, vectors))


def _fit(
    train: Sequence[Example], vectors: Mapping[str, Sequence[float]], pairs: Mapping[str, str], model: str, parameter: float, pooled: bool
) -> tuple[Matrix, Any, list[str]]:
    np, tree, logistic, _ = _deps()
    dropped = screen(train, pairs)
    matrix = Matrix(train, vectors, dropped, pooled)
    x = matrix.transform(train, vectors)
    y = np.asarray([e.label for e in train])
    if len(set(y)) != 2:
        raise ValueError("training split needs both labels")
    if model == "logistic":
        estimator = logistic(C=parameter, class_weight="balanced", solver="liblinear", max_iter=2000, random_state=0)
        estimator.fit(x, y)
    elif model == "hist_gradient_boosting":
        # Disable sklearn's row-random early stopping: it would split repositories.
        estimator = tree(l2_regularization=parameter, max_iter=100, max_leaf_nodes=15, early_stopping=False, random_state=0)
        weights = np.asarray([len(y) / (2 * int(sum(y == label))) for label in y])
        estimator.fit(x, y, sample_weight=weights)
    else:
        raise ValueError("unknown trained model")
    return matrix, estimator, dropped


def fit_fold(
    examples: Sequence[Example],
    units: Sequence[Unit],
    vectors: Mapping[str, Sequence[float]],
    fold: str,
    model: str,
    scope: str,
    *,
    pairs: Mapping[str, str] | None = None,
) -> tuple[list[Scored], dict[str, Any]]:
    """Fit one outer boundary, tuning on three fresh repository-grouped inner folds."""
    by_id = {e.id: e for e in examples}
    held_units = [u for u in units if u.fold == fold]
    held_groups = {u.group for u in held_units}
    train = [e for e in examples if e.group not in held_groups and (scope == "pooled" or e.family == scope)]
    held_units = [u for u in held_units if scope == "pooled" or u.family == scope]
    counts = [len({e.group for e in train if e.label == label}) for label in (0, 1)]
    if not held_units or min(counts, default=0) < (2 if scope == "pooled" else 20):
        return [], {"status": "insufficient data", "training_repositories_by_label": counts}
    pair_map = pairs if pairs is not None else {u.unit: u.pair for u in units}
    candidates = (0.01, 0.1, 1.0) if model == "logistic" else (0.0, 1.0, 10.0)
    inner = outer_folds(train, k=3, seed=0)
    trials = []
    inner_scores: dict[float, list[Scored]] = {}
    for parameter in candidates:
        scored: list[Scored] = []
        for boundary in inner:
            subtrain = [e for e in train if e.group not in boundary.eval_groups]
            valid = [e for e in train if e.group in boundary.eval_groups]
            if not valid or len({e.label for e in subtrain}) < 2:
                continue
            matrix, estimator, _ = _fit(subtrain, vectors, pair_map, model, parameter, scope == "pooled")
            ps = estimator.predict_proba(matrix.transform(valid, vectors))[:, 1]
            scored.extend(
                Scored(Unit(e.id, e.group, e.family, e.label, boundary.name, pair_map.get(e.id, "")), model, float(p))
                for e, p in zip(valid, ps, strict=True)
            )
        inner_scores[parameter] = scored
        value = auc([r.arm() for r in scored])
        trials.append({"parameter": parameter, "inner_pooled_auc": value})
    usable = [t for t in trials if t["inner_pooled_auc"] is not None]
    if not usable:
        raise ValueError("no evaluable inner repository folds")
    best = max(usable, key=lambda t: float(t["inner_pooled_auc"] or 0))
    parameter = float(best["parameter"] or 0)
    matrix, estimator, dropped = _fit(train, vectors, pair_map, model, parameter, scope == "pooled")
    scores = estimator.predict_proba(matrix.transform([by_id[u.unit] for u in held_units], vectors))[:, 1]
    # Digest is an isolation-test witness, never a serialization of population identities.
    witness = matrix.transform(train, vectors).tobytes() + matrix.scaler.mean_.tobytes() + matrix.scaler.scale_.tobytes()
    witness += estimator.predict_proba(matrix.transform(train, vectors)).tobytes()
    record = {
        "status": "ok",
        "training_examples": len(train),
        "training_repositories_by_label": counts,
        "dropped_signals": dropped,
        "parameter": parameter,
        "inner_trials": trials,
        "fit_digest": hashlib.sha256(witness).hexdigest(),
    }
    held_rows = [Scored(u, f"{model}:{scope}", float(s)) for u, s in zip(held_units, scores, strict=True)]
    # Inner predictions were fitted without any outer-held repository. Rename
    # their folds to avoid collision with the frozen outer fold name.
    inner_preds = [replace(r.prediction(), fold="inner:" + r.unit.fold) for r in inner_scores[parameter]]
    decided, gates = pooled_block_gate(inner_preds + [r.prediction() for r in held_rows], eligible=lambda r: bool(r.pair))
    record["pooled_gate"] = gates[fold]
    held_decisions = decided[len(inner_preds) :]
    return [replace(r, point=p.point) for r, p in zip(held_rows, held_decisions, strict=True)], record


def metrics(rows: Sequence[Scored]) -> dict[str, Any]:
    arms = [r.arm() for r in rows]
    ranked = sorted(rows, key=lambda r: (-r.s, r.unit.unit))
    threshold = pooled_threshold([r.prediction() for r in rows])
    flagged = [r for r in rows if threshold is not None and r.s >= threshold and r.verdict != "unsure"]
    held_flags = [r for r in rows if r.point == "BLOCK"]
    return {
        "held_out_block_flags": len(held_flags),
        "held_out_block_wilson_lower": wilson_lower(sum(r.unit.label for r in held_flags), len(held_flags)),
        "family_floor": family_floor([r.prediction() for r in rows]),
        "examples": len(rows),
        "repositories": len({r.unit.group for r in rows}),
        "within_pair_auc": within_pair_auc(arms),
        "pooled_auc": auc(arms),
        "top_k_precision": {str(k): sum(r.unit.label for r in ranked[:k]) / k if len(rows) >= k else None for k in (10, 30, 73)},
        "wilson_threshold": threshold,
        "wilson_flagged": len(flagged),
        "wilson_lower": wilson_lower(sum(r.unit.label for r in flagged), len(flagged)),
        "threshold_check": "descriptive held-out capacity only; not an adopted operating point",
    }


def write_scores(path: Path, rows: Sequence[Scored]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps({**r.unit.as_dict(), "model": r.model, "s": r.s, "out_of_fold": True}, sort_keys=True, allow_nan=False) + "\n"
            for r in rows
        ),
        encoding="utf-8",
    )


def fit_eval(
    examples: Sequence[Example],
    units: Sequence[Unit],
    vectors: Mapping[str, Sequence[float]],
    llm: Mapping[str, ArmUnit],
    *,
    pairs: Mapping[str, str] | None = None,
    resamples: int = 2000,
) -> tuple[dict[str, Any], list[Scored]]:
    if not examples or not units:
        raise ValueError("empty input: no evaluation is possible")
    ids = {e.id: e for e in examples}
    if len(ids) != len(examples) or len({u.unit for u in units}) != len(units):
        raise ValueError("duplicate example or unit IDs")
    groups: dict[str, str] = {}
    for u in units:
        e, a = ids.get(u.unit), llm.get(u.unit)
        if e is None or a is None or a.s is None or not math.isfinite(a.s):
            raise ValueError("every frozen unit needs an example and a finite exp-005 arm-A score")
        if (e.group, e.family, e.label) != (u.group, u.family, u.label) or (a.group, a.family, a.label, a.pair) != (
            u.group,
            u.family,
            u.label,
            u.pair,
        ):
            raise ValueError("unit/example/LLM metadata mismatch")
        if not u.fold or groups.setdefault(u.group, u.fold) != u.fold:
            raise ValueError("repository crosses outer folds")
    reference = [Scored(u, "exp-005:A", float(llm[u.unit].s or 0), llm[u.unit].verdict) for u in units]
    llm_decided, llm_gates = pooled_block_gate([r.prediction() for r in reference], eligible=lambda r: bool(r.pair))
    reference = [replace(r, point=p.point) for r, p in zip(reference, llm_decided, strict=True)]
    report: dict[str, Any] = {
        "status": "evaluated",
        "counts": {"memory": len(examples), "units": len(units)},
        "llm": {"overall": metrics(reference), "folds": {}, "pooled_gates": llm_gates},
        "models": {},
    }
    scores = []
    for fold in sorted({u.fold for u in units}):
        report["llm"]["folds"][fold] = metrics([r for r in reference if r.unit.fold == fold])
    for model in MODELS:
        for scope in ["pooled", *sorted({u.family for u in units})]:
            name = f"{model}:{scope}"
            rows: list[Scored] = []
            folds = {}
            for fold in sorted({u.fold for u in units}):
                held, info = fit_fold(examples, units, vectors, fold, model, scope, pairs=pairs)
                rows.extend(held)
                folds[fold] = {**info, "metrics": metrics(held)}
            matched = [(llm[r.unit.unit], r.arm()) for r in rows]
            baseline = [r for r in reference if r.unit.unit in {s.unit.unit for s in rows}]
            report["models"][name] = {
                "folds": folds,
                "overall": metrics(rows),
                "llm_same_units": metrics(baseline),
                "trained_minus_llm": paired_bootstrap(matched, Metric("within_pair_auc"), resamples=resamples, seed=0).as_dict(),
            }
            scores.extend(rows)
    return report, scores


def run(args: argparse.Namespace) -> int:
    """Train from cached embeddings in the configured store; never call an embedding service."""
    import sys

    from ..config import load_dotenv
    from ..plane.memory import open_store

    try:
        load_dotenv()
        _deps()
        store = open_store(args.memory)
        examples = load_examples(store, args.profile)
        units = read_units(args.units)
        print(f"read units: {args.units.stat().st_size} bytes; {len(units)} units; {len(examples)} examples", file=sys.stderr)
        cache = EmbeddingCache(store)
        vectors = {}
        missing = set()
        exclusions = {
            family: {"excluded_missing_embedding": 0, "excluded_paired_units": 0, "excluded_missing_partner": 0}
            for family in sorted({e.family for e in examples} | {u.family for u in units})
        }
        for e in examples:
            vector = cache.get(e.excerpt_sha)
            if vector is None:
                missing.add(e.id)
                exclusions[e.family]["excluded_missing_embedding"] += 1
            else:
                vectors[e.excerpt_sha] = vector
        broken_pairs = {(u.group, u.family, u.pair) for u in units if u.unit in missing and u.pair}
        for u in units:
            if (u.group, u.family, u.pair) in broken_pairs:
                exclusions[u.family]["excluded_paired_units"] += 1
                if u.unit not in missing:
                    exclusions[u.family]["excluded_missing_partner"] += 1
        for family, counts in exclusions.items():
            print(f"{family}: " + "; ".join(f"{key}={value}" for key, value in counts.items()), file=sys.stderr)
        if len(missing) * 10 > len(examples):
            message = f"missing cached embeddings exclude {len(missing)}/{len(examples)} examples (>10%); training refused"
            args.record.parent.mkdir(parents=True, exist_ok=True)
            args.record.write_text(
                json.dumps({"status": "failed", "error": message, "exclusions": exclusions}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            raise ValueError(message)
        examples = [e for e in examples if e.id not in missing]
        # Keep cached partners for pooled metrics, but remove their paired eligibility in both arms.
        units = [replace(u, pair="") if (u.group, u.family, u.pair) in broken_pairs else u for u in units if u.unit not in missing]
        # Same candidate identity used by experiments.freeze_units, without regenerating frozen outer folds.
        pairs = {}
        pair_labels: dict[str, list[int]] = {}
        for record in store.rows(kind="example", where={"profile": args.profile}):
            row = record.row
            candidate = str(row.get("candidate") or "")
            if candidate:
                identity = "\x00".join(str(row.get(k, "")) for k in ("repo", "candidate", "family"))
                pair = hashlib.sha256(identity.encode()).hexdigest()[:16]
                pairs[str(row["id"])] = pair
                pair_labels.setdefault(pair, []).append(int(row["label"]))
        pairs = {uid: pair for uid, pair in pairs.items() if sorted(pair_labels[pair]) == [0, 1]}
        pairs.update({u.unit: u.pair for u in units})
        llm = arm_units(load_outcomes(store, "exp-005-graph-slice"), "A")
        llm = {uid: replace(a, pair="") if (a.group, a.family, a.pair) in broken_pairs else a for uid, a in llm.items()}
        report, scores = fit_eval(examples, units, vectors, llm, pairs=pairs, resamples=args.resamples)
        report["exclusions"] = exclusions
        report["units_sha256"] = hashlib.sha256(args.units.read_bytes()).hexdigest()
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        if args.train_command == "score":
            write_scores(args.out, scores)
        print("model\twithin-pair AUC\tpooled AUC\ttop-10\ttop-30\ttop-73")
        table = {"exp-005:A": report["llm"], **report["models"]}
        for name, result in table.items():
            m = result["overall"]
            print("\t".join(map(str, [name, m["within_pair_auc"], m["pooled_auc"], *m["top_k_precision"].values()])))
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"learn train: {exc}", file=sys.stderr)
        return 2
