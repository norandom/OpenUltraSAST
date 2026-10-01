"""Operating points and the evaluation report (learned-decision-engine design 4.4-4.5, task 6.5): points read from
calibrated, cross-fitted predictions of the other folds; ``unsure`` never BLOCKs; explanation fields; version
mismatch falls back; ``insufficient data``; parse failures are an instrument failure. Every client is scripted."""

from __future__ import annotations

import json
import random

import pytest
from learn_fixtures import ScriptedChat, corpus

from openultrasast.learn.evaluate import (
    Prediction,
    candidate_from_example,
    choose_points,
    evaluate,
    explain,
    incompatible,
    learning_curve,
    nested_points,
    predict,
    strata,
    targets,
    unevaluable_families,
    wilson_lower,
)
from openultrasast.learn.folds import compile_split, outer_folds
from openultrasast.learn.program import SIGNATURE, Caller, Program, ProgramSpec
from openultrasast.learn.schema import SCHEMA_VERSION, feature_set_digest
from openultrasast.plane.budget import MeteredClient


def _preds(n: int = 300, *, folds: int = 3, seed: int = 0, unsure_every: int = 0) -> list[Prediction]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        label = int(rng.random() < 0.4)
        p = min(0.99, max(0.01, rng.gauss(0.8 if label else 0.25, 0.12)))
        verdict = "unsure" if unsure_every and i % unsure_every == 0 else ("vulnerable" if p > 0.5 else "not_vulnerable")
        out.append(Prediction(f"f{i % folds}", "injection", f"g{i // 3}", label, p, verdict, "delta", "python", p=p))
    return out


def test_wilson_lower_bound() -> None:
    assert wilson_lower(0, 0) == 0.0 and wilson_lower(10, 10) == pytest.approx(0.722, abs=0.001)
    assert wilson_lower(95, 100) == pytest.approx(0.888, abs=0.001)


def test_points_come_from_the_other_folds_only() -> None:
    preds = _preds()
    decided, points = nested_points(preds)
    for fold, pts in points.items():
        assert pts == choose_points([r for r in preds if r.fold != fold])
    perturbed = [Prediction(**{**r.__dict__, "label": 1 - r.label}) if r.fold == "f0" else r for r in preds]
    _, again = nested_points(perturbed)
    assert again["f0"] == points["f0"] and again["f1"] != points["f1"]
    assert {r.point for r in decided} <= {"BLOCK", "ADVISORY", "DROP"}


def test_block_needs_the_wilson_bound_and_advisory_the_recall() -> None:
    pts = choose_points(_preds(600))
    assert pts.advisory is not None
    rows = _preds(600)
    positives = sum(r.label for r in rows)
    assert sum(r.label for r in rows if (r.p or 0) >= pts.advisory) / positives >= 0.90
    if pts.block is not None:
        chosen = [r for r in rows if (r.p or 0) >= pts.block and r.blockable]
        assert wilson_lower(sum(r.label for r in chosen), len(chosen)) >= 0.95
    noisy = [Prediction("f0", "injection", f"g{i}", i % 2, 0.6, "vulnerable", p=0.6) for i in range(50)]
    unreachable = choose_points(noisy)
    assert unreachable.block is None and not unreachable.block_offered and unreachable.block_reason == "precision_unreachable"


def test_a_majority_unsure_never_blocks() -> None:
    preds = [Prediction(f"f{i % 2}", "injection", f"g{i}", 1, 0.99, "unsure", "delta", p=0.99) for i in range(40)]
    preds += [Prediction(f"f{i % 2}", "injection", f"n{i}", 0, 0.01, "not_vulnerable", "delta", p=0.01) for i in range(40)]
    decided, _ = nested_points(preds)
    assert not any(r.point == "BLOCK" for r in decided)
    assert all(r.point == "ADVISORY" for r in decided if r.label == 1)


def test_explanations_keep_only_signals_the_record_holds() -> None:
    x = {"qr.enabled_hits": 2, "eng.findings": 0, "eng.rung_max": None}
    assert explain("qr.enabled_hits and eng.findings agree; eng.rung_max and made.up say otherwise", x) == [
        "qr.enabled_hits",
        "eng.findings",
    ]


def test_a_version_mismatch_falls_back_with_the_reason() -> None:
    artifact = {"schema_version": SCHEMA_VERSION, "feature_set_digest": feature_set_digest(), "signature": {"digest": SIGNATURE.digest},
                "profile": "static"}  # fmt: skip
    record = {"schema_version": SCHEMA_VERSION, "feature_set_digest": feature_set_digest(), "profile": "static"}
    assert incompatible(artifact, record, SIGNATURE.digest) is None
    assert incompatible({**artifact, "feature_set_digest": "old"}, record, SIGNATURE.digest) == "feature set differs"
    assert incompatible(artifact, {**record, "schema_version": 0}, SIGNATURE.digest) == "schema version differs"
    assert incompatible({**artifact, "signature": {"digest": "x"}}, record, SIGNATURE.digest) == "signature differs"
    assert incompatible(artifact, {**record, "profile": "plane"}, SIGNATURE.digest) == "profile differs"


def test_a_family_below_the_floor_is_insufficient_data_never_a_number() -> None:
    preds = _preds(90)
    few = [Prediction("f0", "memory", "openssl/openssl", i % 2, 0.5, "unsure", p=0.5) for i in range(20)]
    report = strata([*preds, *few], lambda r: r.family, resamples=50)
    assert report["memory"] == {"status": "insufficient data"}
    assert report["injection"]["status"] in ("per_family", "pooled") and "advisory" in report["injection"]


def _code(sha: str) -> str:
    return f"   10  def f(q):\n   11      return {'execute(q)' if int(sha, 16) % 2 else 'escape(q)'}\n"


def test_the_evaluation_runs_end_to_end_on_scripted_answers() -> None:
    memory = corpus(groups=30, per_group=4)
    codes = {e.excerpt_sha: f"   10  def f(q):\n   11      return {'execute(q)' if e.label else 'escape(q)'}\n" for e in memory}
    split = compile_split(memory)
    folds = outer_folds(memory, exclude=split.groups)
    pairs = targets(folds, memory, skip=unevaluable_families(memory, floor=3))
    assert pairs and all(e.group in f.eval_groups for e, f in pairs)
    program = Program(ProgramSpec(), memory, codes.get)
    chat = ScriptedChat()
    caller = Caller(MeteredClient(chat), "deepseek-flash")
    preds = predict(program, folds, caller, candidate_from_example(codes.get), pairs=pairs)
    assert len(preds) == len(pairs) == caller.calls + caller.replayed and caller.calls == len(chat.calls)  # identical prompts replay
    report = evaluate(preds, resamples=50, per_family_floor=10, pooled_floor=3)
    assert report["status"] == "ok" and report["parse_failed_share"] == 0 and report["calibration"] is not None
    assert set(report["points_by_fold"]) == {f.name for f in folds if f.eval_groups}
    curve = learning_curve(program, pairs[:20], caller, candidate_from_example(codes.get), fractions=(0.0, 1.0))
    assert [p["memory_fraction"] for p in curve] == [0.0, 1.0] and curve[0]["memory_groups"] == 0


def test_more_than_five_percent_parse_failures_is_an_instrument_failure() -> None:
    preds = [Prediction(f"f{i % 3}", "injection", f"g{i}", i % 2, 0.5, "unsure", parse_failed=int(i % 10 == 0)) for i in range(60)]
    assert evaluate(preds, resamples=20, per_family_floor=5, pooled_floor=2)["status"] == "instrument failure"
    assert json.dumps(evaluate(preds[1:10], resamples=5, per_family_floor=5, pooled_floor=2), default=str)
