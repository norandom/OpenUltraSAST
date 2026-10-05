"""Offline trained-arm contracts; model tests need the optional train extra."""

import argparse
import hashlib
import json
from dataclasses import asdict, replace

import pytest
from test_plane_memory import FakeObjects, row

from openultrasast.learn import trained
from openultrasast.learn.examples import Example
from openultrasast.learn.experiments import Unit, auc, within_pair_auc


@pytest.mark.parametrize("from_env", [False, True])
@pytest.mark.parametrize("missing_count", [0, 1, 2, 3])
def test_run_cached_s3(tmp_path, monkeypatch, capsys, from_env, missing_count):
    from openultrasast import config
    from openultrasast.learn.experiments import Outcome, outcome_row, write_units
    from openultrasast.plane import memory
    from openultrasast.plane.budget import MeteredEmbeddingClient
    from openultrasast.provider.openrouter import OpenRouterEmbeddingClient

    def forbidden_embedding(*args, **kwargs):
        pytest.fail("training must never call an embedding service")

    monkeypatch.setattr(MeteredEmbeddingClient, "embed", forbidden_embedding)
    monkeypatch.setattr(OpenRouterEmbeddingClient, "embed", forbidden_embedding)

    objects = FakeObjects("works")
    store = memory.S3Store(objects, "bucket", "p")
    examples, units, vectors = population(10)
    examples = [replace(e, excerpt_sha=hashlib.sha256(e.id.encode()).hexdigest()) for e in examples]
    # A second family makes per-family accounting observable, including zero exclusions.
    examples = [replace(e, family="path") if e.group == "9" else e for e in examples]
    units = [replace(u, family="path") if u.group == "9" else u for u in units]
    missing = {f"{g}-0" for g in range(missing_count)}
    cache = trained.EmbeddingCache(store)
    for e in examples:
        store.put_row({**row("example", e.id), **asdict(e)})
        if e.id not in missing:
            cache.put(e.excerpt_sha, vectors[e.id], tokens=0, created="2026-10-04")
    for u in units:
        outcome = Outcome(u.unit, u.group, u.family, u.label, u.pair, "A", 0, float(u.label), "scored", 0.0, 0, 0)
        store.put_row(outcome_row("exp-005-graph-slice", "a" * 40, outcome))
    location = "s3://bucket/p"
    loaded = []

    def dotenv():
        loaded.append(True)
        monkeypatch.setenv("OUSAST_MEMORY", location if from_env else "s3://wrong/override")
        monkeypatch.setenv("S3_ENDPOINT", "https://fake.invalid")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")

    def client(**kwargs):
        assert loaded and kwargs["bucket"] == "bucket"
        assert kwargs["access_key"] == kwargs["secret_key"] == "fake"
        return objects

    monkeypatch.setattr(config, "load_dotenv", dotenv)
    monkeypatch.setattr(memory, "S3Client", client)
    monkeypatch.setattr(trained, "_deps", lambda: None)
    seen = []

    def fit(examples, units, vectors, fold, model, scope, *, pairs):
        seen.append(True)
        assert not missing.intersection(e.id for e in examples)
        assert all(e.excerpt_sha in vectors for e in examples)
        for g in range(missing_count):
            partner = next(u for u in units if u.unit == f"{g}-1")
            assert partner.pair == pairs[partner.unit] == ""
        return [trained.Scored(u, model, float(u.label)) for u in units if u.fold == fold and (scope == "pooled" or u.family == scope)], {
            "status": "ok"
        }

    monkeypatch.setattr(trained, "fit_fold", fit)
    args = argparse.Namespace(
        memory=None if from_env else location,
        profile="static",
        units=tmp_path / "units.jsonl",
        record=tmp_path / "record.json",
        train_command="score",
        out=tmp_path / "scores.jsonl",
        resamples=5,
    )
    write_units(args.units, units)
    assert trained.run(args) == (2 if missing_count > 2 else 0)
    record = json.loads(args.record.read_text())
    expected = {
        "excluded_missing_embedding": missing_count,
        "excluded_paired_units": 2 * missing_count,
        "excluded_missing_partner": missing_count,
    }
    assert record["exclusions"]["injection"] == expected
    assert record["exclusions"]["path"] == dict.fromkeys(expected, 0)
    stderr = capsys.readouterr().err
    assert f"excluded_missing_embedding={missing_count}" in stderr
    assert f"excluded_paired_units={2 * missing_count}" in stderr
    if missing_count > 2:
        assert ">10%" in stderr and record["status"] == "failed"
        assert not seen and not args.out.exists()
    else:
        assert seen
        assert record["counts"] == {"memory": 20 - missing_count, "units": 20 - missing_count}
        assert record["llm"]["overall"]["within_pair_auc"] == 1.0
        scores = [json.loads(line) for line in args.out.read_text().splitlines()]
        assert not missing.intersection(s["unit"] for s in scores)
        assert sum(s["pair"] != "" for s in scores if s["model"] == "logistic") == 2 * (20 - 2 * missing_count)


def population(n=30):
    examples, units, vectors = [], [], {}
    for g in range(n):
        for label in (0, 1):
            uid = f"{g}-{label}"
            examples.append(
                Example(
                    uid,
                    str(g),
                    "synthetic",
                    (),
                    "injection",
                    label,
                    "python",
                    "static",
                    "pin",
                    {"eng.findings": label, "facts.callers": g % 3},
                    {"engine": {"state": "ran"}, "facts": {"state": "ran"}},
                    (),
                    uid,
                )
            )
            units.append(Unit(uid, str(g), "injection", label, f"outer-{g % 3}", str(g)))
            vectors[uid] = [float(label)] + [0.0] * 1535
    return examples, units, vectors


def test_per_fold_screen():
    examples, units, _ = population()
    for fold in {u.fold for u in units}:
        rows = [e for e in examples if next(u for u in units if u.unit == e.id).fold != fold]
        assert "eng.findings" in trained.screen(rows, {u.unit: u.pair for u in units})


def test_metrics_and_scores(tmp_path):
    _, units, _ = population(4)
    rows = [trained.Scored(u, "logistic:pooled", float(u.label)) for u in units]
    metrics = trained.metrics(rows)
    arms = [r.arm() for r in rows]
    assert metrics["within_pair_auc"] == within_pair_auc(arms)
    assert metrics["pooled_auc"] == auc(arms)
    assert metrics["top_k_precision"]["10"] is None
    assert metrics["wilson_threshold"] is None
    path = tmp_path / "scores.jsonl"
    trained.write_scores(path, rows)
    data = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(data) == 8
    assert set(data[0]) == {"unit", "group", "family", "label", "fold", "pair", "model", "s", "out_of_fold"}
    assert all(r["out_of_fold"] for r in data)


def test_outer_isolation():
    pytest.importorskip("sklearn", reason="optional train extra (scikit-learn and numpy) is not installed")
    examples, units, vectors = population()
    held = {u.group for u in units if u.fold == "outer-0"}
    first = trained.fit_fold(examples, units, vectors, "outer-0", "logistic", "pooled")
    changed = [replace(e, label=1 - e.label, x={"eng.findings": 999, "facts.callers": 1e9}) if e.group in held else e for e in examples]
    changed_vectors = {e.excerpt_sha: ([1e6] * 1536 if e.group in held else vectors[e.excerpt_sha]) for e in examples}
    second = trained.fit_fold(changed, units, changed_vectors, "outer-0", "logistic", "pooled")
    assert first[1] == second[1]  # includes fitted matrix/scaler/weight digests and inner choices
    assert len(first[0]) == len(second[0])


@pytest.mark.parametrize("model", ["logistic", "hist_gradient_boosting"])
def test_models(model):
    pytest.importorskip("sklearn", reason="optional train extra (scikit-learn and numpy) is not installed")
    examples, units, vectors = population()
    scores, record = trained.fit_fold(examples, units, vectors, "outer-0", model, "pooled")
    assert len(scores) == 20
    assert all(0 <= r.s <= 1 for r in scores)
    assert "eng.findings" in record["dropped_signals"]


def test_wilson_matches_helper():
    from openultrasast.learn.evaluate import pooled_threshold, wilson_lower

    _, units, _ = population(80)
    rows = [trained.Scored(u, "toy", float(u.label)) for u in units]
    result = trained.metrics(rows)
    assert result["wilson_threshold"] == pooled_threshold([r.prediction() for r in rows]) == 1.0
    assert result["wilson_lower"] == wilson_lower(80, 80)
    assert result["top_k_precision"] == {"10": 1.0, "30": 1.0, "73": 1.0}


def test_missing_is_distinct_from_zero():
    pytest.importorskip("sklearn", reason="optional train extra (scikit-learn and numpy) is not installed")
    examples, _, vectors = population(2)
    zero = examples[0]
    missing = replace(zero, x={**zero.x, "facts.callers": None})
    matrix = trained.Matrix([zero, missing], vectors, [], True)
    assert matrix.raw([zero], vectors) != matrix.raw([missing], vectors)
    assert len(matrix.raw([zero], vectors)[0]) > 1536


def test_cli_surface():
    import argparse

    from openultrasast.learn.cli import add_commands

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    learn = sub.add_parser("learn")
    add_commands(learn.add_subparsers(dest="learn_command"))
    args = parser.parse_args(["learn", "train", "score", "--out", "/tmp/scores.jsonl"])
    assert args.train_command == "score"
