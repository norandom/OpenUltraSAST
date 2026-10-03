"""Decision-rule experiments (kind: rule): selective blocking on the raw score, chosen on training folds only, against
today's calibrated BLOCK rule, scored once from the response cache at zero cost (exp-003)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_learn_experiments import CODE, EXAMPLES, PRICES, _json_shape, artifact, committed, example_rows, excerpt_text, paid, put_program

from openultrasast.learn import experiments as ex
from openultrasast.learn.evaluate import Prediction, calibrated_block, nested_precision_block, precision_threshold, wilson_lower
from openultrasast.learn.program import Candidate, Program
from openultrasast.learn.retrieve import Target
from openultrasast.plane.memory import FileStore

ROOT = Path(__file__).resolve().parents[1]

RULE_MANIFEST = """
id: {id}
hypothesis: selective blocking beats the calibrated rule
kind: rule
programs: {{injection: {pid}, path: {pid}}}
arms:
  A: {{label: today, rule: {{name: calibrated_block}}}}
  B: {{label: bound, rule: {{name: precision_bound_block, bound: wilson, precision: 0.95, select_on: paired}}}}
  C: {{label: point, rule: {{name: precision_bound_block, bound: point, precision: 0.95, min_flagged: 2, select_on: paired}}}}
populations: {{primary: paired, secondary: [pooled]}}
decision: {{arm: B, target_precision: 0.95}}
metric:
  primary: [{{name: flagged_precision_lb, target: 0.95}}]
  secondary: [flagged_precision, coverage, flagged]
test: {{resamples: 50}}
budget_usd: {{total: 0}}
families: [injection, path]
folds: {{k: 5, seed: 0, compile_fraction: 0.25}}
units_file: {units}
"""


def write_rule_manifest(tmp_path: Path, pid: str, name: str = "exp-901-rule") -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(RULE_MANIFEST.format(id=name, pid=pid, units=tmp_path / f"{name}.units.jsonl"))
    return path


def pred(fold: int, label: int, s: float, *, family: str = "injection", group: str = "", verdict: str = "", pair: str = "p") -> Prediction:
    verdict = verdict or ("vulnerable" if s >= 0.5 else "not_vulnerable")
    return Prediction(f"outer-{fold}", family, group or f"org/r{fold}", label, s, verdict, pair=pair)


# --- the threshold ---------------------------------------------------------------------------------------------------------


def test_the_wilson_bound_needs_73_clean_flags_at_095() -> None:
    assert ex.min_flagged_for_bound(0.95) == 73
    assert wilson_lower(72, 72) < 0.95 <= wilson_lower(73, 73)
    clean = [pred(0, 1, 0.9) for _ in range(73)] + [pred(0, 0, 0.2) for _ in range(10)]
    assert precision_threshold(clean) == 0.9
    assert precision_threshold(clean[1:]) is None  # 72 clean flags never reach the bound
    assert precision_threshold(clean[1:], bound="point", min_flagged=10) == 0.9
    assert precision_threshold(clean[:5], bound="point", min_flagged=10) is None


def test_the_lowest_qualifying_threshold_and_unsure_never_blocks() -> None:
    rows = [pred(0, 1, 0.9) for _ in range(80)] + [pred(0, 1, 0.4) for _ in range(5)]
    assert precision_threshold(rows) == 0.4  # 85 clean flags at 0.4: the lowest threshold that qualifies
    assert precision_threshold([*rows, pred(0, 0, 0.6)]) == 0.9  # one false flag at 0.6: 85 of 86 and 80 of 81 do not
    unsure = [pred(0, 1, 0.95, verdict="unsure") for _ in range(100)]
    assert precision_threshold(unsure) is None
    decided, _ = nested_precision_block([*unsure[:3], *(pred(1, 1, 0.95) for _ in range(80))])
    assert all(r.point == "DROP" for r in decided if r.verdict == "unsure")


def leaky_threshold(preds: list[Prediction], fold: str) -> float | None:
    """What a rule that peeked at the held-out fold would choose: every fold's rows, the reported fold included."""
    return precision_threshold([r for r in preds if r.family == "injection"])


def test_no_threshold_is_chosen_with_outer_fold_labels() -> None:
    """Fold outer-0 holds 80 high-scoring positives; the other folds alone never reach the bound. A rule that used
    outer-0's labels would block on outer-0; the nested rule must not, and flipping outer-0's labels must not move
    outer-0's threshold."""
    held = [pred(0, 1, 0.9, group=f"org/h{i}") for i in range(80)]
    train = [pred(f, lab, 0.9 if lab else 0.3, group=f"org/t{f}-{i}") for f in range(1, 5) for i, lab in enumerate((1, 1, 1, 0, 0))]
    preds = held + train
    assert leaky_threshold(preds, "outer-0") is not None  # the test has teeth: the outer labels would qualify
    decided, thresholds = nested_precision_block(preds)
    assert thresholds["injection"]["outer-0"] is None
    assert all(r.point == "DROP" for r in decided if r.fold == "outer-0")
    flipped = [Prediction(r.fold, r.family, r.group, 1 - r.label, r.s, r.verdict, pair=r.pair) if r.fold == "outer-0" else r for r in preds]
    _, again = nested_precision_block(flipped)
    assert again["injection"]["outer-0"] == thresholds["injection"]["outer-0"]
    # and the other folds' thresholds do see outer-0 (it is their training data)
    assert all(thresholds["injection"][f"outer-{f}"] == 0.9 for f in range(1, 5))
    assert all(again["injection"][f"outer-{f}"] is None for f in range(1, 5))


def test_select_on_paired_ignores_unpaired_training_rows() -> None:
    unpaired = [pred(1, 1, 0.9, pair="", group=f"org/u{i}") for i in range(80)]
    paired = [pred(1, lab, 0.9 if lab else 0.1, group=f"org/p{i}") for i, lab in enumerate((1, 0) * 3)]
    held = [pred(0, 1, 0.9), pred(0, 0, 0.1)]
    _, everyone = nested_precision_block([*unpaired, *paired, *held])
    _, only_paired = nested_precision_block([*unpaired, *paired, *held], eligible=lambda r: bool(r.pair))
    assert everyone["injection"]["outer-0"] == 0.9 and only_paired["injection"]["outer-0"] is None


def test_the_calibrated_rule_blocks_only_where_calibration_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [pred(f, 1 if i < 30 else 0, 0.9 if i < 30 else 0.1, group=f"org/g{f}-{i}") for f in range(5) for i in range(40)]
    import openultrasast.learn.evaluate as ev

    real = ev.check
    for holds in (False, True):
        monkeypatch.setattr(ev, "check", lambda *a, _h=holds, **k: ev.replace(real(*a, **k), holds=_h))
        decided, info = calibrated_block(rows)
        assert info["injection"]["calibration_holds"] is holds
        blocked = [r for r in decided if r.point == "BLOCK"]
        assert bool(blocked) is holds and all(r.label == 1 for r in blocked)


# --- the manifest ------------------------------------------------------------------------------------------------------------


def test_rule_manifests_cost_nothing_and_change_only_the_rule(tmp_path: Path) -> None:
    path = write_rule_manifest(tmp_path, "0" * 64)
    manifest = ex.load_manifest(path)
    assert manifest.kind == "rule" and manifest.arms["B"].rule["bound"] == "wilson" and manifest.budget_total_usd == 0
    text = path.read_text()
    for bad, why in (
        (text.replace("budget_usd: {total: 0}", "budget_usd: {total: 1}"), "budget_usd must be 0"),
        (text.replace("A: {label: today, ", "A: {label: today, spec: {sampling: retrieval_ensemble}, "), "BLOCK rule only"),
        (text.replace("name: calibrated_block", "name: magic"), "rule.name"),
        (text.replace("bound: wilson", "bound: hope"), "bound in"),
        (text.replace("primary: paired", "primary: all"), "populations"),
        (text.replace("arm: B,", "arm: Z,"), "decision"),
        (text.replace("flagged_precision_lb", "auc"), "metric"),
        (text.replace("programs: {injection: " + "0" * 64 + ", path: ", "programs: {path: "), "program for every family"),
    ):
        path.write_text(bad)
        with pytest.raises(ex.ExperimentError, match=why):
            ex.load_manifest(path)


# --- the zero-cost run ------------------------------------------------------------------------------------------------------


def prepared(tmp_path: Path) -> tuple[FileStore, ex.Manifest, list[ex.Unit]]:
    store = FileStore(tmp_path / "memory")
    store.put_rows(example_rows())
    pid = put_program(store, artifact())
    manifest = ex.load_manifest(write_rule_manifest(tmp_path, pid))
    units = ex.freeze_units(store, manifest, EXAMPLES)
    ex.write_units(manifest.units_file, units)
    ex.register(store, manifest, commit_of=committed)
    return store, manifest, units


def test_the_run_replays_the_cache_excludes_misses_and_proves_zero_spend(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path)
    chat, caller = paid()
    caller.store = store
    folds = {f.name: f for f in ex.program_folds(EXAMPLES, manifest)[0]}
    index = {e.id: e for e in EXAMPLES}
    cached = units[: len(units) - 3]  # the incumbent's evaluation answered all but three units
    for u in cached:
        e = index[u.unit]
        program = Program(ex.arm_spec(manifest, manifest.arms["A"], u.family, store), EXAMPLES, excerpt_text)
        program.decide(Candidate(Target.of(e), CODE[e.excerpt_sha], "python"), folds[u.fold], caller, seed=0)
    paid_calls = len(chat.calls)
    with pytest.raises(ex.ZeroCostViolation):  # a paid caller is refused before anything is decided
        ex.run_rule(store, manifest, EXAMPLES, caller, caller.client, excerpt_text)
    zero, meter = ex.zero_cost_caller("deepseek-flash", PRICES, store)
    summary = ex.run_rule(store, manifest, EXAMPLES, zero, meter, excerpt_text)
    assert len(chat.calls) == paid_calls and meter.calls == 0 and meter.usd == 0.0 and zero.calls == 0
    assert summary.decided == {"score": len(cached)} and summary.skipped == {"already": 0, "replay_miss": 3}
    assert summary.spend["score"]["client_calls"] == 0 and summary.spend["score"]["usd"] == 0.0
    outcomes = ex.load_outcomes(store, manifest.id)
    assert sum(o.verdict == ex.MISS_VERDICT and o.s is None for o in outcomes) == 3
    report = ex.analyse_rule(manifest, outcomes, units, resamples=20, provenance={"code_commit": "c" * 40})
    assert report["units"]["excluded_replay_miss"] == 3 and report["units"]["evaluated"] == len(cached)
    assert report["spend_usd"] == {"score": 0.0} and report["decision"] in ex.VERDICTS
    assert set(report["families"]["injection"]) == {"A", "B", "C", "capacity"} and report["min_flagged_for_bound"] == 73
    text = json.dumps(report)
    assert "org0/repo0" not in text and units[0].unit not in text  # counts only
    store.put_row(ex.rule_result_row(manifest, "c" * 40, report))
    shapes: dict[str, set[str]] = {}  # one JSON type per column across the experiment's rows (S3 Select, see test_learn_experiments)
    for record in store.rows(repo=ex.experiment_repo(manifest.id)):
        for name, value in record.row.items():
            if value is not None:
                shapes.setdefault(name, set()).add(_json_shape(value))
    assert {name: sorted(s) for name, s in shapes.items() if len(s) > 1} == {}
    again = ex.run_rule(store, manifest, EXAMPLES, *ex.zero_cost_caller("deepseek-flash", PRICES, store), excerpt_text)
    assert again.decided == {"score": 0} and again.skipped["already"] == len(units)
    with pytest.raises(ex.ExperimentError, match="zero cost"):
        ex.run(store, manifest, EXAMPLES, {}, excerpt_text)


def test_a_call_past_the_meter_voids_the_run() -> None:
    caller, meter = ex.zero_cost_caller("deepseek-flash", PRICES, None)
    with pytest.raises(ex.ZeroCostViolation):
        meter.inner.complete(model="deepseek-flash", messages=[], tools=[])


# --- the analysis --------------------------------------------------------------------------------------------------------------


def crafted(tmp_path: Path, *, b_clean: bool) -> tuple[ex.Manifest, list[ex.Outcome], list[ex.Unit]]:
    """Five folds of 20 candidate pairs each: positives at s 0.9; negatives at 0.1, except four per fold at 0.9 unless
    ``b_clean``."""
    manifest = ex.load_manifest(write_rule_manifest(tmp_path, "0" * 64))
    units, outcomes = [], []
    for f in range(5):
        for i in range(40):
            label = 1 if i < 20 else 0
            high = label == 1 or (not b_clean and i >= 36)
            u = ex.Unit(f"u{f}-{i}", f"org/r{f}-{i % 20}", "injection", label, f"outer-{f}", f"p{f}-{i % 20}")
            units.append(u)
            s = 0.9 if high else 0.1
            outcomes.append(ex.Outcome(u.unit, u.group, u.family, label, u.pair, ex.SCORE_ARM, 0, s,
                                       "vulnerable" if high else "not_vulnerable", 0.0))  # fmt: skip
    return manifest, outcomes, units


def test_the_verdict_follows_the_registered_rule(tmp_path: Path) -> None:
    manifest, outcomes, units = crafted(tmp_path, b_clean=True)
    report = ex.analyse_rule(manifest, outcomes, units, resamples=20)
    cell = report["families"]["injection"]["B"]["paired"]
    assert cell["flagged"] == 100 and cell["flagged_precision"] == 1.0 and cell["coverage"] == 1.0 and cell["meets_target_lb"]
    assert report["decision"] == "adopt"
    assert report["families"]["path"]["B"]["paired"]["flagged"] == 0  # a family without units flags nothing
    manifest, outcomes, units = crafted(tmp_path, b_clean=False)
    report = ex.analyse_rule(manifest, outcomes, units, resamples=20)
    assert report["families"]["injection"]["B"]["paired"]["flagged"] == 0 and report["decision"] == "inconclusive"
    assert report["families"]["injection"]["C"]["paired"]["flagged"] == 0  # 80/96 point precision never reaches 0.95 either
    row = ex.rule_result_row(manifest, "c" * 40, report)
    assert row["kind"] == "experiment_result" and row["tests"]["injection"]["B"]["flagged"] == 0 and row["looks_taken"] == []


def test_the_registered_exp003_manifest_loads() -> None:
    path = ROOT / "plane/experiments/exp-003-precision-bound-blocking.yaml"
    if not path.exists():
        pytest.skip("exp-003 is not written yet")
    manifest = ex.load_manifest(path)
    assert manifest.kind == "rule" and manifest.budget_total_usd == 0 and manifest.raw["populations"]["primary"] == "paired"
    assert manifest.arms["A"].rule == {"name": "calibrated_block"} and manifest.arms["B"].rule["bound"] == "wilson"
    assert len(manifest.families) == 6 and set(manifest.programs) == set(manifest.families)
