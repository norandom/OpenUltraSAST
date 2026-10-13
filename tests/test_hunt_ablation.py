"""A registered ablation on readable git changes, with deterministic model answers."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace

import pytest

dspy = pytest.importorskip("dspy")
pd = pytest.importorskip("pandas")
pytest.importorskip("statsmodels")
pytest.importorskip("sklearn")
from dspy.utils import DummyLM  # noqa: E402

from openultrasast.hunt import ablation as ab  # noqa: E402
from openultrasast.hunt import program as hp  # noqa: E402
from openultrasast.hunt import runner  # noqa: E402
from openultrasast.hunt.features import ENGINEERED  # noqa: E402
from openultrasast.hunt.table import FeatureTable  # noqa: E402


@pytest.fixture
def population(tmp_path):
    repos, changes, rows = {}, [], []
    for number in range(3):
        root = tmp_path / f"repo-{number}"
        root.mkdir()

        def git(*args, root=root):
            return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        (root / "app.py").write_text("def run():\n    return input()\n")
        git("add", "app.py")
        git("commit", "-qm", "initial")
        base = git("rev-parse", "HEAD")
        (root / "app.py").write_text("def run():\n    return eval(input())\n")
        git("add", "app.py")
        git("commit", "-qm", "change")
        head = git("rev-parse", "HEAD")
        repo = f"fixture/repo-{number}"
        repos[repo] = str(root)
        for item in range(2):
            positive = number < 2 and item == 0
            change = {
                "id": f"c{number}-{item}",
                "repo": repo,
                "base": base,
                "head": head,
                "kind": "vulnerability" if positive else "ordinary",
                "case_id": f"case-{number}-{item}",
                "path": "app.py",
                "function": "run",
                "function_lines": [1, 2],
                "family": "injection",
                "files": [{"path": "app.py", "head_lines": [[2, 2]]}],
            }
            changes.append(change)
            for line in (1, 2):
                rows.append(
                    {
                        "change_id": change["id"],
                        "repo": repo,
                        "head": head,
                        "path": "app.py",
                        "line": line,
                        "kind": change["kind"],
                        "label": int(positive),
                        "feature.diff.distance": number,
                        "provenance.diff.ok": True,
                        "provenance.diff.reason": None,
                        "provenance.diff.version": 1,
                        "provenance.diff.bytes_read": 36,
                    }
                )
    table = ab.assign_folds(FeatureTable(rows), k=3, seed=13)
    folds = {row["change_id"]: row["fold"] for row in table.rows}
    changes = [{**change, "fold": folds[change["id"]]} for change in changes]
    pool = tmp_path / "pool-fixture.toml"
    pool.write_text("status = 'fixture'\n")
    manifest = ab.Manifest(
        table_digest=table.digest(),
        arms={"full": [], "without-roles": ["roles"]},
        compile_folds=[],
        holdout_folds=[0, 1, 2],
        metric="hunt.metric.search_outcome(tolerance=10)",
        sample={"changes": [c["id"] for c in changes], "repeats": 2},
        budget={"usd": 1.0, "calls": 100},
        rule={"version": "keep-drop-v1", "resamples": 100, "needs": {}},
        seed=13,
        program_id="fixture-program",
    )
    return pool, repos, changes, table, manifest


def test_folds_and_audit_keep_every_row_and_column(population):
    _, _, _, table, _ = population
    frame = table.to_pandas()
    assert frame.groupby("repo")["fold"].nunique().eq(1).all()
    assert frame.groupby("change_id")["fold"].nunique().eq(1).all()
    assert set(frame.fold) == {0, 1, 2}
    assert ab.assign_folds(table, k=3, seed=13).digest() == table.digest()
    audit = ab.leak_audit(table)
    assert set(audit.column) == set(ENGINEERED)
    assert audit.set_index("column").loc["diff.distance", "n"] == 12
    missing = audit.set_index("column").loc["semantic.sources"]
    assert pd.isna(missing.auc) and missing.n == 0 and missing.note
    assert dict(zip(audit.column, audit.annotation, strict=True)) == {key: value[1] for key, value in ENGINEERED.items()}
    assert len(ab.leak_audit(FeatureTable([]))) == len(ENGINEERED)


def finding(confidence=0.9, family="injection"):
    return {"path": "app.py", "line": 2, "family": family, "confidence": confidence, "rationale": "eval", "cited_lines": [2]}


def model(answers):
    return DummyLM([{"findings": json.dumps(answer)} for answer in answers])


def test_registration_paired_runs_statistics_and_curve(population, tmp_path):
    pool, repos, changes, table, manifest = population
    out = tmp_path / "ablation"
    # Each arm has its own deterministic sequence, but uses the same model class and sampling.
    models = {"full": model([[finding()]] * 12), "without-roles": model([[]] * 12)}
    kwargs = dict(program_factory=hp.HuntProgram, lm=models, repeats=2, table=table, load_changes=lambda m, s: changes)
    with pytest.raises(ValueError, match="registration"):
        ab.run(manifest, pool, repos, out, **kwargs)
    ab.register(manifest, out)
    registration = json.loads((out / "ablation.json").read_text())
    assert registration["manifest_id"] == ab.manifest_id(manifest)
    with pytest.raises(ValueError, match="registration"):
        ab.run(replace(manifest, seed=22), pool, repos, out, **kwargs)
    ab.run(manifest, pool, repos, out, **kwargs)
    for arm in manifest.arms:
        for repeat in range(2):
            records = [json.loads(runner.record_path(out / f"{arm}-{repeat}", c["id"]).read_text()) for c in changes]
            assert {r["id"] for r in records} == {c["id"] for c in changes}
            assert all(r["instrument"]["hook_bytes_read"] > 0 and r["instrument"]["head_verified"] for r in records)
            assert all(("roles" in r["inputs_present"]) == (arm == "full") for r in records)
    analysis = ab.analyse(out, manifest, changes)
    pooled = analysis["heldout"]["comparisons"]["without-roles"]["pooled"]
    assert pooled["recall"]["diff"] == -1 and pooled["recall"]["ci"] == (-1, -1)
    assert pooled["recall"]["units"] == 4 and pooled["recall"]["groups"] == 2
    assert pooled["suspicions_per_push"]["diff"] == -1 and pooled["suspicions_per_push"]["units"] == 8
    assert pooled["mcnemar"]["b"] == 4 and pooled["mcnemar"]["c"] == 0
    assert "injection" in analysis["heldout"]["comparisons"]["without-roles"]["families"]
    assert analysis["heldout"]["arms"]["full"]["curve"] == [
        {"confidence": 0.9, "recall": 1.0, "suspicions_per_push": 1.0, "positive_units": 4, "ordinary_units": 8}
    ]
    assert json.loads((out / "decisions.json").read_text())["roles"]["decision"] == "keep"
    # The saved registration also protects against changed folds and repeat counts.
    with pytest.raises(ValueError, match="repeats"):
        ab.run(manifest, pool, repos, out, **{**kwargs, "repeats": 1})
    with pytest.raises(ValueError, match="digest"):
        ab.run(manifest, pool, repos, out, **{**kwargs, "table": FeatureTable(table.rows[:-1])})


def test_parse_and_instrument_failures_stay_in_denominator(population, tmp_path):
    pool, repos, changes, table, original = population
    manifest = replace(original, sample={**original.sample, "repeats": 1})
    out = tmp_path / "failed"
    ab.register(manifest, out)
    # ChatAdapter retries a malformed answer through JSONAdapter once.
    bad = DummyLM([{"findings": "not json"}] * 2 + [{"findings": "[]"}] * 5)
    ab.run(
        manifest,
        pool,
        repos,
        out,
        program_factory=hp.HuntProgram,
        lm={"full": bad, "without-roles": model([[]] * 6)},
        repeats=1,
        table=table,
        load_changes=lambda m, s: changes,
    )
    record = json.loads(runner.record_path(out / "full-0", changes[0]["id"]).read_text())
    assert record["parse_failed"] and record["instrument"]["hook_bytes_read"] > 0
    # An absent record is also a miss, not a reason to shrink the paired population.
    runner.record_path(out / "without-roles-0", changes[2]["id"]).unlink()
    analysis = ab.analyse(out, manifest, changes)
    full = analysis["heldout"]["arms"]["full"]
    assert full["parse_failures"] == 1 and full["positive_units"] == 2 and full["recall"] == 0
    assert analysis["heldout"]["arms"]["without-roles"]["missing_records"] == 1
    assert analysis["heldout"]["comparisons"]["without-roles"]["pooled"]["recall"]["units"] == 2


def effect(diff, ci):
    return {"diff": diff, "ci": ci, "units": 12, "groups": 3}


def test_importance_and_decisions_use_heldout_effects_and_dependencies(tmp_path):
    neutral = {"recall": effect(0, (-0.1, 0.1)), "suspicions_per_push": effect(0, (-0.1, 0.1))}
    helpful = {**neutral, "recall": effect(-0.5, (-0.8, -0.2))}
    noisy = {**neutral, "suspicions_per_push": effect(-1, (-2, -0.5))}
    comparisons = {
        f"without-{name}": {"pooled": value}
        for name, value in (("roles", helpful), ("callers", noisy), ("def_use", neutral), ("obligations", neutral))
    }
    analysis = {
        "out_dir": str(tmp_path),
        "heldout": {"comparisons": comparisons, "additions": {"with-roles": {"pooled": {**neutral, "recall": effect(0.5, (0.2, 0.8))}}}},
        "compile": {"comparisons": {"without-callers": {"pooled": helpful}}},
    }
    table = ab.importance(analysis, annotations=["roles", "callers", "def_use", "obligations", "families"])
    assert len(table) == 5
    roles = table.set_index("annotation").loc["roles"]
    assert roles.remove_recall == -0.5 and roles.add_recall == 0.5 and roles.remove_recall_units == 12
    assert pd.isna(table.set_index("annotation").loc["families", "remove_recall"])
    decisions = ab.decide(table, needs={"roles": {"def_use"}, "def_use": {"obligations"}})
    assert decisions["roles"]["decision"] == "keep"
    assert decisions["callers"] == {"decision": "drop", "reason": "raises suspicions without recall"}
    assert decisions["def_use"]["decision"] == decisions["obligations"]["decision"] == "keep"
    assert ab.decide(table, needs={})["def_use"] == {"decision": "drop", "reason": "no measurable effect"}
    assert json.loads((tmp_path / "decisions.json").read_text())["def_use"]["decision"] == "drop"


@pytest.mark.parametrize("mask", [["label"], ["verification"], ["advisory"], ["provenance.source.ok"]])
def test_registration_rejects_non_feature_masks(population, tmp_path, mask):
    manifest = replace(population[-1], arms={"full": [], "bad": mask})
    with pytest.raises(ValueError, match="mask"):
        ab.register(manifest, tmp_path / "bad")


def write_records(out, manifest, changes, answers):
    """Save runner-shaped records to isolate analysis of fixed, known outcomes."""
    ab.register(manifest, out)
    for arm, per_change in answers.items():
        directory = out / f"{arm}-0"
        directory.mkdir()
        for change, findings in zip(changes, per_change, strict=True):
            record = {
                "id": change["id"],
                "done": True,
                "status": "hunt_covered",
                "program_id": manifest.program_id,
                "mask": manifest.arms[arm],
                "input_digest": runner.input_digest(change, manifest.program_id, manifest.arms[arm]),
                "push": {
                    "admission": {
                        "defects": [runner.defect_from(f, program_id=manifest.program_id, mask=tuple(manifest.arms[arm])) for f in findings]
                    }
                },
            }
            runner.record_path(directory, change["id"]).write_text(json.dumps(record))


def test_curve_counts_ties_all_suspicions_and_families(population, tmp_path):
    _, _, changes, _, original = population
    manifest = replace(original, sample={**original.sample, "repeats": 1})
    out = tmp_path / "curve"
    full = [[finding(0.9)], [finding(0.9), finding(0.4, "path")], [finding(0.4)], [], [], []]
    write_records(out, manifest, changes, {"full": full, "without-roles": [[]] * 6})
    result = ab.analyse(out, manifest, changes)
    arm = result["all"]["arms"]["full"]
    assert arm["curve"] == [
        {"confidence": 0.9, "recall": 0.5, "suspicions_per_push": 0.25, "positive_units": 2, "ordinary_units": 4},
        {"confidence": 0.4, "recall": 1.0, "suspicions_per_push": 0.5, "positive_units": 2, "ordinary_units": 4},
    ]
    families = result["all"]["comparisons"]["without-roles"]["families"]
    assert families["injection"]["recall"]["diff"] == -1
    assert families["path"]["recall"]["units"] == 0 and families["path"]["recall"]["ci"] is None
    for family in ("injection", "path"):
        assert families[family]["suspicions_per_push"]["diff"] == -0.25
        assert families[family]["suspicions_per_push"]["units"] == 4
    # A flagged failure with stale findings must be a miss in both the summary and the curve.
    path = runner.record_path(out / "full-0", changes[0]["id"])
    record = json.loads(path.read_text())
    record["status"] = "instrument_failure"
    path.write_text(json.dumps(record))
    failed = ab.analyse(out, manifest, changes)["all"]["arms"]["full"]
    assert failed["instrument_failures"] == 1 and failed["positive_units"] == 2 and failed["recall"] == 0.5
    assert failed["curve"][0]["recall"] == 0


def test_holdout_and_baseline_addition_are_separate(population, tmp_path):
    _, _, changes, _, original = population
    compile_fold = changes[0]["fold"]
    manifest = replace(
        original,
        sample={**original.sample, "repeats": 1},
        compile_folds=[compile_fold],
        holdout_folds=[f for f in original.holdout_folds if f != compile_fold],
        arms={"full": [], "without-roles": ["roles"], "baseline": ["roles", "callers"], "with-roles": ["callers"]},
    )
    out = tmp_path / "split"
    write_records(
        out,
        manifest,
        changes,
        {
            "full": [[], [], [finding()], [], [], []],
            "without-roles": [[finding()], [], [], [], [], []],
            "baseline": [[]] * 6,
            "with-roles": [[], [], [finding()], [], [], []],
        },
    )
    result = ab.analyse(out, manifest, changes)
    assert result["compile"]["comparisons"]["without-roles"]["pooled"]["recall"]["diff"] == 1
    assert result["heldout"]["comparisons"]["without-roles"]["pooled"]["recall"]["diff"] == -1
    importance = ab.importance(result, annotations=["roles"])
    assert importance.iloc[0].add_recall == 1 and importance.iloc[0].remove_recall == -1
    assert ab.decide(importance, needs={})["roles"]["decision"] == "keep"
    assert result["annotations_removed"]["without-roles"] == ["roles"]


def test_decisions_keep_suspicion_benefits_but_not_neutral_cycles():
    neutral = {"recall": effect(0, (0, 0)), "suspicions_per_push": effect(0, (0, 0))}
    effects = {"roles": {**neutral, "suspicions_per_push": effect(1, (0.5, 2))}, "callers": neutral, "def_use": neutral}
    table = ab.importance(
        {"heldout": {"comparisons": {f"without-{name}": {"pooled": value} for name, value in effects.items()}}}, annotations=list(effects)
    )
    decisions = ab.decide(table, needs={"callers": {"def_use"}, "def_use": {"callers"}})
    assert decisions["roles"] == {"decision": "keep", "reason": "removal raises suspicions"}
    assert decisions["callers"]["decision"] == decisions["def_use"]["decision"] == "drop"
    table.attrs["scope"] = "compile"
    with pytest.raises(ValueError, match="held-out"):
        ab.decide(table, needs={})


def test_registration_cannot_be_rewritten_or_have_its_contents_changed(population, tmp_path):
    manifest = population[-1]
    out = tmp_path / "registered"
    ab.register(manifest, out)
    assert ab.manifest_id(replace(manifest, arms=dict(reversed(list(manifest.arms.items()))))) == ab.manifest_id(manifest)
    with pytest.raises(ValueError, match="registration"):
        ab.register(replace(manifest, seed=99), out)
    payload = json.loads((out / "ablation.json").read_text())
    payload["manifest"]["seed"] = 99
    (out / "ablation.json").write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="registration"):
        ab.analyse(out, manifest, population[2])
