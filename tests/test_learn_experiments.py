"""A/B experiments (learned-decision-engine design section 6, task 7): manifest digest refusal, frozen units and
pairing, the paired repository bootstrap, exact McNemar on a known table, the two-look boundary, the adoption rule,
arm A replaying at zero client calls, and the retrieval-ensemble sampling variant. Every client is scripted; stores
are ``FileStore`` under ``tmp_path``."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from learn_fixtures import ScriptedChat, corpus, x_record

from openultrasast.cli import main
from openultrasast.learn import experiments as ex
from openultrasast.learn.compile import canonical, program_id
from openultrasast.learn.program import TEMPERATURES, Caller, Candidate, Program, ProgramSpec
from openultrasast.learn.retrieve import Target
from openultrasast.plane.budget import MeteredClient
from openultrasast.plane.memory import FileStore

ROOT = Path(__file__).resolve().parents[1]
PRICES = {"cache_hit_per_m": 0.014, "input_per_m": 0.44, "output_per_m": 1.32}
EXAMPLES = corpus(groups=12)
CODE = {
    e.excerpt_sha: f"   10  def f{i}(q):\n   11      return {'execute(q)' if e.label else 'escape(q)'}\n" for i, e in enumerate(EXAMPLES)
}
COMMIT = "c" * 40
PIN = "a" * 40


def excerpt_text(sha: str) -> str | None:
    return CODE.get(sha)


def artifact(**classify: object) -> dict[str, object]:
    return {
        "kind": "llm-program", "instruction": "Judge the candidate.", "demos": [], "profile": "static",
        "retrieval": {"k": 4, "lam": 0.5, "n1": 40, "priors": "off"},
        "classify": {"model": "deepseek-flash", "k": 2, "inputs": "v1", "max_output_tokens": 300, **classify},
    }  # fmt: skip


def put_program(store: FileStore, art: dict[str, object]) -> str:
    pid = program_id(art)
    store.put_blob("programs", canonical(art), name=pid)
    return pid


def example_rows() -> list[dict[str, object]]:
    """Example rows as the memory build writes them (repo, candidate): the two sides of g0-e0/g0-e1 share a candidate."""
    rows = []
    for i, e in enumerate(EXAMPLES):
        candidate = "a.py::f" if e.group == "org0/repo0" and i < 2 else f"a.py::f{i}"
        rows.append({
            "id": e.id, "kind": "example", "repo": e.group, "pin": PIN, "run": "learn-memory", "task": "build", "population": "pairs",
            "split": "pairs", "image": "host", "candidate": candidate, "family": e.family, "label": e.label, "profile": "static",
        })  # fmt: skip
    return rows


MANIFEST = """
id: {id}
hypothesis: the variant changes the score
kind: program
programs: {{injection: {pid}, path: {pid}}}
arms:
  A: {{spec: {{}}, replay_only: {replay}, repeats: {repeats}, budget_usd: 1.0}}
  B: {{spec: {{sampling: retrieval_ensemble}}, repeats: {repeats}, budget_usd: 2.0}}
order: {{seed: 3}}
metric:
  primary: [{{name: canary_agreement, target: 0.9}}, within_pair_auc]
  secondary: [usd_per_candidate, auc, advisory_recall]
test: {{alpha: 0.05, resamples: 200}}
mde: 0.1
stopping: {{looks: [0.5, 1.0], boundary: obrien_fleming}}
budget_usd: {{total: 3}}
families: [injection, path]
folds: {{k: 5, seed: 0, compile_fraction: 0.25}}
units_file: {units}
"""


def write_manifest(tmp_path: Path, pid: str, *, name: str = "exp-900-test", replay: str = "true", repeats: int = 1) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(MANIFEST.format(id=name, pid=pid, replay=replay, repeats=repeats, units=tmp_path / f"{name}.units.jsonl"))
    return path


def committed(_: Path) -> str | None:
    return COMMIT


def unit(name: str, group: str, label: int, pair: str = "") -> ex.Unit:
    return ex.Unit(name, group, "injection", label, "outer-0", pair)


def outcome(u: ex.Unit, arm: str, s: float, verdict: str, *, replicate: int = 0, usd: float = 0.001) -> ex.Outcome:
    return ex.Outcome(u.unit, u.group, u.family, u.label, u.pair, arm, replicate, s, verdict, usd)


def crafted(groups: int = 8, per_group: int = 4, *, b_better: bool, a_period: int = 2) -> list[ex.Outcome]:
    """Paired outcomes over ``groups`` repositories: A flags the positives of every ``a_period``-th repository only,
    B flags every positive when ``b_better`` (else it is A's copy); neither flags a negative."""
    out = []
    for g in range(groups):
        for i in range(per_group):
            u = unit(f"u{g}-{i}", f"org/repo{g}", i % 2, pair=f"p{g}-{i // 2}")
            a_flag = u.label == 1 and g % a_period == 0
            out.append(outcome(u, "A", 0.8 if a_flag else 0.2, "vulnerable" if a_flag else "not_vulnerable"))
            b_flag = bool(u.label) if b_better else a_flag
            out.append(outcome(u, "B", 0.9 if b_flag else 0.1, "vulnerable" if b_flag else "not_vulnerable"))
    return out


# --- manifests and registration -------------------------------------------------------------------------------------------


def test_the_registered_manifests_load_as_declared() -> None:
    exp1 = ex.load_manifest(ROOT / "plane/experiments/exp-001-known-callers.yaml")
    exp2 = ex.load_manifest(ROOT / "plane/experiments/exp-002-retrieval-ensemble.yaml")
    assert exp1.kind == "plane" and exp1.arms["B"].task_env == {"OUSAST_VERIFY_CALLERS": "off"} and exp1.arms["A"].task_env == {}
    assert exp1.primary[0].as_dict() == {"name": "flag_rate", "label": 1} and exp1.budget_total_usd == 15 and exp1.mde == 0.15
    assert exp2.kind == "program" and exp2.arms["B"].spec == {"sampling": "retrieval_ensemble"} and exp2.arms["A"].spec == {}
    assert [m.name for m in exp2.primary] == ["canary_agreement", "within_pair_auc"] and exp2.primary[0].target == 0.9
    assert exp2.budget_total_usd == 4 and exp2.families == ("injection", "access_control") and exp2.arms["B"].repeats == 2
    assert exp1.boundaries == exp2.boundaries == (2.797, 1.977) and exp2.looks == (0.5, 1.0)
    assert set(exp2.programs) == {"injection", "access_control"}


def test_manifest_refusals(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "0" * 64)
    text = path.read_text()
    for bad, why in (
        (text.replace("sampling: retrieval_ensemble", "temperature: 0.1"), "ProgramSpec fields"),
        (text.replace("looks: [0.5, 1.0]", "looks: [0.3, 1.0]"), "tabulated"),
        (text.replace("budget_usd: {total: 3}", "budget_usd: {total: 2}"), "exceed"),
        (text.replace("  B: {spec", "  C: {spec"), "arms A and B"),
        (text.replace("advisory_recall", "f1"), "metric"),
    ):
        path.write_text(bad)
        with pytest.raises(ex.ExperimentError, match=why):
            ex.load_manifest(path)
    (tmp_path / "other.yaml").write_text(text)
    with pytest.raises(ex.ExperimentError, match="file stem"):
        ex.load_manifest(tmp_path / "other.yaml")


def test_register_refuses_uncommitted_and_modified_manifests(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    path = write_manifest(tmp_path, "0" * 64)
    manifest = ex.load_manifest(path)
    with pytest.raises(ex.ExperimentError, match="not committed"):
        ex.register(store, manifest, commit_of=lambda _: None)
    with pytest.raises(ex.ExperimentError, match="not registered"):
        ex.check_registered(store, manifest, need_units=False)
    row = ex.register(store, manifest, commit_of=committed, created="2026-10-02")
    assert row["pin"] == COMMIT and row["units_status"] == "pending" and row["manifest_digest"] == manifest.digest
    assert ex.check_registered(store, manifest, need_units=False)["id"] == row["id"]
    with pytest.raises(ex.ExperimentError, match="freeze the units"):
        ex.check_registered(store, manifest)  # the units are not frozen: it cannot run
    ex.register(store, manifest, commit_of=committed)  # the same file again is idempotent
    path.write_text(path.read_text().replace("mde: 0.1", "mde: 0.2"))
    changed = ex.load_manifest(path)
    with pytest.raises(ex.ExperimentError, match="new experiment"):
        ex.register(store, changed, commit_of=committed)
    with pytest.raises(ex.ExperimentError, match="differs from the registered"):
        ex.check_registered(store, changed, need_units=False)
    assert len(store.rows(kind="experiment")) == 1


def test_frozen_units_cover_the_evaluated_groups_and_pair_the_sides(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    store.put_rows(example_rows())
    manifest = ex.load_manifest(write_manifest(tmp_path, "0" * 64))
    units = ex.freeze_units(store, manifest, EXAMPLES)
    folds, _ = ex.program_folds(EXAMPLES, manifest)
    evaluated = {g for f in folds for g in f.eval_groups}
    assert units and {u.group for u in units} == evaluated and {u.family for u in units} <= {"injection", "path"}
    assert all(u.fold.startswith("outer-") for u in units)
    paired = [u for u in units if u.pair]
    assert {u.unit for u in paired} == {EXAMPLES[0].id, EXAMPLES[1].id} or not paired  # the one shared candidate, if evaluated
    digest = ex.write_units(manifest.units_file, units)
    assert ex.read_units(manifest.units_file) == units
    row = ex.register(store, manifest, commit_of=committed)
    assert row["units_status"] == "frozen" and row["units_digest"] == digest
    manifest.units_file.write_text(manifest.units_file.read_text() + json.dumps(unit("x", "org9/repo9", 1).as_dict()) + "\n")
    with pytest.raises(ex.ExperimentError, match="units"):
        ex.check_registered(store, manifest)


# --- statistics -------------------------------------------------------------------------------------------------------------


def test_metrics_on_crafted_rows() -> None:
    rows = [
        ex.ArmUnit("a", "g", "injection", 1, "p1", 0.9, "vulnerable", 0.002, True),
        ex.ArmUnit("b", "g", "injection", 0, "p1", 0.4, "not_vulnerable", 0.004, False),
        ex.ArmUnit("c", "h", "injection", 1, "p2", 0.5, "unsure", None, None),
        ex.ArmUnit("d", "h", "injection", 0, "p2", 0.5, "vulnerable", None, True),
    ]
    assert ex.metric_value(ex.Metric("auc"), rows) == pytest.approx((1 + 1 + 1 + 0.5) / 4)
    assert ex.metric_value(ex.Metric("within_pair_auc"), rows) == pytest.approx(0.75)
    assert ex.metric_value(ex.Metric("advisory_recall"), rows) == 0.5 and ex.metric_value(ex.Metric("advisory_precision"), rows) == 0.5
    assert ex.metric_value(ex.Metric("canary_agreement"), rows) == pytest.approx(2 / 3)
    assert ex.metric_value(ex.Metric("usd_per_candidate"), rows) == pytest.approx(0.003)
    assert ex.metric_value(ex.Metric("flag_rate", label=0), rows) == 0.5
    assert ex.metric_value(ex.Metric("auc"), rows[:1]) is None and ex.metric_value(ex.Metric("within_pair_auc"), rows[:1]) is None
    assert ex.Metric.parse("flag_rate[label=1]") == ex.Metric("flag_rate", 1) and ex.Metric("usd_per_candidate").direction == -1


def test_paired_bootstrap_over_repositories() -> None:
    better = ex.paired_units(crafted(b_better=True))
    est = ex.paired_bootstrap(better, ex.Metric("advisory_recall"), resamples=300, seed=1)
    assert est.a == 0.5 and est.b == 1.0 and est.diff == 0.5 and est.groups == 8 and est.units == 32
    assert est.ci is not None and est.ci[0] > 0 and ex.excludes_zero(est.ci, 1) == "favour" and ex.excludes_zero(est.ci, -1) == "against"
    same = ex.paired_units(crafted(b_better=False))
    est = ex.paired_bootstrap(same, ex.Metric("flag_rate"), resamples=100, seed=1)
    assert est.diff == 0 and est.ci == (0.0, 0.0) and est.se == 0 and ex.excludes_zero(est.ci, 1) == "spans"
    assert ex.paired_bootstrap([], ex.Metric("auc"), resamples=10).ci is None
    # the bootstrap resamples repositories, not units: a repository's units move together
    only_a = ex.paired_bootstrap(better[:4], ex.Metric("advisory_recall"), resamples=50, seed=0)
    assert only_a.groups == 1 and only_a.ci == (only_a.diff, only_a.diff)


def test_exact_mcnemar_on_a_known_table() -> None:
    table = [(True, False)] * 2 + [(False, True)] * 10 + [(True, True)] * 5 + [(False, False)] * 3
    mc = ex.exact_mcnemar(table)
    assert (mc.b, mc.c, mc.concordant) == (2, 10, 8)
    assert mc.p_value == pytest.approx(2 * (1 + 12 + 66) / 2**12)  # 0.0386
    assert ex.exact_mcnemar([(True, False)] * 3 + [(False, True)] * 3).p_value == 1.0
    assert ex.exact_mcnemar([(True, True)]).p_value == 1.0
    pairs = ex.paired_units(crafted(b_better=True))
    assert ex.mcnemar_for(pairs, ex.Metric("auc")) is None  # not a per-unit binary outcome
    recall = ex.mcnemar_for(pairs, ex.Metric("advisory_recall"))
    assert recall is not None and recall.b == 0 and recall.c == 8 and recall.p_value == pytest.approx(2 / 256)


def test_two_looks_with_obrien_fleming_boundaries(tmp_path: Path) -> None:
    manifest = ex.load_manifest(write_manifest(tmp_path, "0" * 64))
    recall = ex.Metric("advisory_recall")
    strong = ex.sequential_looks(ex.paired_units(crafted(groups=12, b_better=True, a_period=6)), recall, manifest, resamples=200)
    assert len(strong) == 1 and strong[0].crossed and strong[0].fraction == 0.5 and strong[0].boundary == 2.797 and strong[0].groups == 6
    assert strong[0].z is None or strong[0].z >= 2.797  # None: every first-look repository moved the same way (no variance)
    late = ex.sequential_looks(ex.paired_units(crafted(groups=12, b_better=True, a_period=2)), recall, manifest, resamples=200)
    assert [look.crossed for look in late] == [False, True] and late[1].z is not None and late[1].z >= 1.977
    none = ex.sequential_looks(ex.paired_units(crafted(groups=12, b_better=False)), recall, manifest, resamples=50)
    assert [look.fraction for look in none] == [0.5, 1.0] and not any(look.crossed for look in none)
    assert [look.boundary for look in none] == [2.797, 1.977] and none[1].groups == 12
    assert ex.look_order(["b", "a", "c"], 3) == ex.look_order(["c", "a", "b"], 3)  # the pre-shuffled order is seeded


def estimate(name: str, lo: float, hi: float) -> ex.Estimate:
    return ex.Estimate(name, 0.5, 0.5 + (lo + hi) / 2, (lo + hi) / 2, (lo, hi), 0.1, 10, 5, 100)


def test_the_adoption_rule(tmp_path: Path) -> None:
    manifest = ex.load_manifest(write_manifest(tmp_path, "0" * 64))  # primaries: canary_agreement, within_pair_auc
    favour, against, spans = (
        estimate("canary_agreement", 0.02, 0.2),
        estimate("within_pair_auc", -0.3, -0.1),
        estimate("within_pair_auc", -0.1, 0.1),
    )
    assert ex.decide(manifest, {"canary_agreement": favour, "within_pair_auc": spans}, None, None)[0] == "adopt"
    assert ex.decide(manifest, {"canary_agreement": favour, "within_pair_auc": against}, None, None)[0] == "reject"
    assert ex.decide(manifest, {"canary_agreement": spans, "within_pair_auc": spans}, None, None)[0] == "inconclusive"
    assert (
        ex.decide(manifest, {"canary_agreement": estimate("canary_agreement", -0.2, -0.02), "within_pair_auc": spans}, None, None)[0]
        == "reject"
    )
    cost_only = ex.Manifest(**{**manifest.__dict__, "cost_only": True})
    saving, no_saving = estimate("usd_per_candidate", -0.002, -0.001), estimate("usd_per_candidate", -0.001, 0.001)
    tost_in, tost_out = estimate("canary_agreement", -0.03, 0.02), estimate("canary_agreement", -0.08, 0.02)
    finals = {"canary_agreement": spans, "within_pair_auc": spans}
    assert ex.decide(cost_only, finals, saving, tost_in)[0] == "equivalent"
    assert ex.decide(cost_only, finals, no_saving, tost_in)[0] == "inconclusive"
    assert ex.decide(cost_only, finals, saving, tost_out)[0] == "inconclusive"
    assert ex.decide(manifest, finals, saving, tost_in)[0] == "inconclusive"  # not declared cost-only: no equivalence


def test_analyse_reports_counts_and_intervals_only(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    manifest = ex.load_manifest(write_manifest(tmp_path, "0" * 64))
    outcomes = crafted(groups=10, b_better=True)
    for o in outcomes:
        store.put_row(ex.outcome_row(manifest.id, COMMIT, o))
    loaded = ex.load_outcomes(store, manifest.id)
    assert sorted(loaded, key=lambda o: (o.unit, o.arm)) == sorted(outcomes, key=lambda o: (o.unit, o.arm))
    report = ex.analyse(manifest, loaded, resamples=100, provenance={"code_commit": COMMIT})
    assert report["units"] == {"paired": 40, "groups": 10, "outcomes": 80, "by_label": {"0": 20, "1": 20}}
    assert report["tests"]["canary_agreement"]["estimate"]["diff"] is None  # one replicate: no canary
    assert report["tests"]["advisory_recall"]["estimate"]["diff"] == 0.5 and report["tests"]["advisory_recall"]["mcnemar"]["c"] == 10
    assert report["tests"]["within_pair_auc"]["ci_vs_zero"] == "favour" and report["decision"] == "inconclusive"  # the first primary spans
    assert report["code_commit"] == COMMIT and report["manifest_digest"] == manifest.digest
    text = json.dumps(report)
    assert "org/repo" not in text and "u3-1" not in text  # no identities
    store.put_row(ex.result_row(manifest, COMMIT, report))
    assert store.rows(kind="experiment_result")[0].row["decision"] == "inconclusive"


# --- run --------------------------------------------------------------------------------------------------------------------


def paid(answer: ScriptedChat | None = None, budget: float = 5.0) -> tuple[ScriptedChat, Caller]:
    chat = answer or ScriptedChat()
    return chat, Caller(MeteredClient(chat, prices=PRICES, budget_usd=budget), "deepseek-flash", PRICES)


def prepared(tmp_path: Path, *, replay: str = "true", repeats: int = 1) -> tuple[FileStore, ex.Manifest, list[ex.Unit]]:
    store = FileStore(tmp_path / "memory")
    store.put_rows(example_rows())
    pid = put_program(store, artifact())
    manifest = ex.load_manifest(write_manifest(tmp_path, pid, replay=replay, repeats=repeats))
    units = ex.freeze_units(store, manifest, EXAMPLES)[:12]
    ex.write_units(manifest.units_file, units)
    ex.register(store, manifest, commit_of=committed)
    return store, manifest, units


def test_arm_a_replays_the_evaluation_at_zero_client_calls(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path)
    # the incumbent's evaluation: every unit decided once, responses in the cache
    chat, caller = paid()
    caller.store = store
    program = Program(ex.arm_spec(manifest, manifest.arms["A"], "injection", store), EXAMPLES, excerpt_text)
    folds = {f.name: f for f in ex.program_folds(EXAMPLES, manifest)[0]}
    index = {e.id: e for e in EXAMPLES}
    for u in units:
        e = index[u.unit]
        program.decide(Candidate(Target.of(e), CODE[e.excerpt_sha], "python"), folds[u.fold], caller, seed=0)
    evaluation_calls = len(chat.calls)
    assert evaluation_calls == 2 * len(units)
    b_chat, b_caller = paid()
    b_caller.store = store
    seen: list[tuple[str, str]] = []
    summary = ex.run(store, manifest, EXAMPLES, {"A": Caller(None, "deepseek-flash", PRICES, store=store), "B": b_caller}, excerpt_text,
                     on_decision=lambda o, d: seen.append((o.arm, o.verdict)), resamples=20)  # fmt: skip
    assert summary.status == "done" and summary.decided == {"A": len(units), "B": len(units)} and summary.skipped == {"A": 0, "B": 0}
    assert len(chat.calls) == evaluation_calls  # arm A made no client call
    assert summary.spend["A"]["client_calls"] == 0 and summary.spend["A"]["replayed"] == 2 * len(units)
    # B's first sample renders the same prompt as A's temperature-0 sample: the cache answers it; the second set is new
    assert summary.spend["B"]["client_calls"] == len(units) and summary.spend["B"]["replayed"] == len(units)
    assert len(b_chat.calls) == len(units)
    assert all(call["temperature"] == 0.0 for call in b_chat.calls)  # the ensemble arm samples at temperature 0
    rows = ex.load_outcomes(store, manifest.id)
    assert len(rows) == 2 * len(units) and {o.arm for o in rows} == {"A", "B"} and all(o.usd is not None and o.usd > 0 for o in rows)
    assert {o.order for o in rows if o.arm == "A"} == {0, 1}  # the seeded coin put A first for some units and second for others
    # a rerun decides nothing again and spends nothing
    again = ex.run(store, manifest, EXAMPLES, {"A": Caller(None, "deepseek-flash", PRICES, store=store), "B": paid()[1]}, excerpt_text)
    assert again.decided == {"A": 0, "B": 0} and again.skipped == {"A": len(units), "B": len(units)}
    report = ex.analyse(manifest, ex.load_outcomes(store, manifest.id), resamples=50)
    assert report["units"]["paired"] == len(units) and report["decision"] in ex.VERDICTS
    assert store.rows(kind="experiment", where=None)[-1].row["task"] in ("register", "run")


def test_run_refuses_an_unregistered_or_modified_manifest_and_a_missing_cache(tmp_path: Path) -> None:
    store, manifest, _ = prepared(tmp_path)
    manifest.path.write_text(manifest.path.read_text().replace("mde: 0.1", "mde: 0.15"))
    changed = ex.load_manifest(manifest.path)
    callers = {"A": Caller(None, "deepseek-flash", PRICES, store=store), "B": paid()[1]}
    with pytest.raises(ex.ExperimentError, match="differs"):
        ex.run(store, changed, EXAMPLES, callers, excerpt_text)
    with pytest.raises(ex.ExperimentError, match="not registered"):
        ex.run(FileStore(tmp_path / "other"), manifest, EXAMPLES, callers, excerpt_text)
    from openultrasast.learn.program import ReplayMiss

    with pytest.raises(ReplayMiss):  # arm A replay-only without the evaluation's cache: loud, never a silent zero
        ex.run(store, manifest, EXAMPLES, callers, excerpt_text)
    assert ex.load_outcomes(store, manifest.id) == []


def test_canary_replicates_use_a_fresh_cache_key_and_a_ceiling_leaves_the_run_resumable(tmp_path: Path) -> None:
    store, manifest, units = prepared(tmp_path, replay="false", repeats=2)
    a_chat, a_caller = paid(budget=0.0005)
    a_caller.store = store
    b_chat, b_caller = paid()
    b_caller.store = store
    summary = ex.run(store, manifest, EXAMPLES, {"A": a_caller, "B": b_caller}, excerpt_text, stop_early=False)
    assert summary.status == "unfinished" and "ceiling" in summary.reason.lower() or "budget" in summary.reason.lower()
    partial = ex.load_outcomes(store, manifest.id)
    assert partial and len(partial) < 4 * len(units)
    assert a_caller.salt == "" and b_caller.salt == ""
    a2_chat, a2_caller = paid()
    a2_caller.store = store
    done = ex.run(store, manifest, EXAMPLES, {"A": a2_caller, "B": b_caller}, excerpt_text, stop_early=False)
    assert done.status == "done" and done.skipped["A"] + done.decided["A"] == 2 * len(units)
    rows = ex.load_outcomes(store, manifest.id)
    assert len(rows) == 4 * len(units) and {o.replicate for o in rows} == {0, 1}
    by_arm = ex.arm_units(rows, "A")
    assert all(u.agree is not None for u in by_arm.values())
    report = ex.analyse(manifest, rows, resamples=50)
    assert (
        report["tests"]["canary_agreement"]["estimate"]["a"] is not None and report["tests"]["canary_agreement"]["target"]["level"] == 0.9
    )
    # replicate 1 asked the client again (a fresh key), it did not replay replicate 0
    assert len(a_chat.calls) + len(a2_chat.calls) >= 2 * len(units) + 1


def test_plane_experiments_do_not_run_here(tmp_path: Path) -> None:
    manifest = ex.load_manifest(ROOT / "plane/experiments/exp-001-known-callers.yaml")
    store = FileStore(tmp_path / "memory")
    with pytest.raises(ex.ExperimentError, match="plane"):
        ex.freeze_units(store, manifest, EXAMPLES)
    with pytest.raises(ex.ExperimentError, match="plane"):
        ex.run(store, manifest, EXAMPLES, {}, excerpt_text)


def test_cli_register_and_analyse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pid = "0" * 64
    path = write_manifest(tmp_path, pid)
    memory = f"file://{tmp_path / 'memory'}"
    monkeypatch.setattr(ex, "committed_at_head", lambda _p, cwd=None: None)
    assert main(["learn", "experiment", "register", str(path), "--memory", memory]) == 2  # not committed
    monkeypatch.setattr(ex, "committed_at_head", lambda _p, cwd=None: COMMIT)
    assert main(["learn", "experiment", "register", str(path), "--memory", memory]) == 0
    assert (
        main(["learn", "experiment", "analyse", str(path), "--memory", memory, "--resamples", "10", "--out", str(tmp_path / "r.json")]) == 0
    )
    report = json.loads((tmp_path / "r.json").read_text())
    assert report["decision"] == "inconclusive" and report["reason"] == "no paired units"
    path.write_text(path.read_text().replace("mde: 0.1", "mde: 0.3"))
    assert main(["learn", "experiment", "analyse", str(path), "--memory", memory]) == 2


# --- the retrieval-ensemble variant --------------------------------------------------------------------------------------


def candidate() -> Candidate:
    rec = x_record(hits=2)
    return Candidate(
        Target("cand/repo", "injection", "static", rec["x"], rec["instruments"]),
        "   40  def view(q):\n   41      return execute(q)\n",
        "python",
    )


def test_retrieval_ensemble_draws_disjoint_example_sets_and_the_default_is_unchanged() -> None:
    from openultrasast.learn.folds import outer_folds

    fold = outer_folds(EXAMPLES, seed=0)[0]
    ensemble = Program(ProgramSpec(k=3, k_ret=4, sampling="retrieval_ensemble"), EXAMPLES, excerpt_text)
    prepared_sets = ensemble.prepare_ensemble(candidate(), fold)
    ids = [set(p.example_ids) for p, _ in prepared_sets]
    assert len(ids) == 3 and all(ids) and not (ids[0] & ids[1]) and not (ids[0] & ids[2]) and not (ids[1] & ids[2])
    assert len({p.prefix for p, _ in prepared_sets}) == 1  # the same instruction and demonstrations: the prefix cache still hits
    chat, caller = paid()
    decision = ensemble.decide(candidate(), fold, caller)
    assert len(chat.calls) == 3 and all(c["temperature"] == 0.0 for c in chat.calls)
    assert (
        len({json.dumps(c["messages"]) for c in chat.calls}) == 3 and decision.verdict == "vulnerable" and sum(decision.votes.values()) == 3
    )
    # the default: one example set, temperatures 0 then 0.7, byte-identical messages
    chat, caller = paid()
    default = Program(ProgramSpec(k=3, k_ret=4), EXAMPLES, excerpt_text)
    default.decide(candidate(), fold, caller)
    assert [c["temperature"] for c in chat.calls] == [TEMPERATURES[0], TEMPERATURES[1], TEMPERATURES[1]]
    assert len({json.dumps(c["messages"]) for c in chat.calls}) == 1
    assert ProgramSpec().sampling == "temperature"
    with pytest.raises(ValueError, match="sampling"):
        Program(ProgramSpec(sampling="dice"), EXAMPLES, excerpt_text).decide(candidate(), fold, paid()[1])


def test_a_salted_caller_never_replays_the_unsalted_response(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    chat, caller = paid(ScriptedChat(lambda m, t: json.dumps({"verdict": "vulnerable", "confidence": 0.9, "cited_lines": [1]})))
    caller.store = store
    messages: list[dict[str, object]] = [{"role": "user", "content": "   1  execute(q)"}]
    caller.ask(messages, temperature=0.0, sample="0")
    caller.ask(messages, temperature=0.0, sample="0")
    assert caller.calls == 1 and caller.replayed == 1
    caller.salt = "r1:"
    caller.ask(messages, temperature=0.0, sample="0")
    assert caller.calls == 2 and len(store.blob_names("responses")) == 2
    assert math.isclose(caller.usd() or 0, caller.usd() or 0)


def test_verify_callers_line_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.plane.tasks import verify

    facts = {"callers": {"app.py::run": [{"path": "web.py", "line": 12, "enclosing": "handler"}]}}
    group = [("app.py::run", "run", 2)]
    assert "Known callers: web.py:12 in handler()" in verify.hunt_prompt("app.py", group, "injection", facts)
    monkeypatch.setenv("OUSAST_VERIFY_CALLERS", "off")
    assert "Known callers" not in verify.hunt_prompt("app.py", group, "injection", facts)


def _json_shape(value: object) -> str:
    """The JSON type of a value, with an array's element types: what an S3 Select schema inference sees."""
    if isinstance(value, list):
        return "array<" + ",".join(sorted({_json_shape(v) for v in value})) + ">"
    return type(value).__name__


def test_experiment_rows_share_one_json_type_per_column(tmp_path: Path) -> None:
    """The register, run and result rows of one experiment land in one object with its outcome rows; RustFS's S3
    Select infers one schema per object and fails the whole object on a column with two types (ops/ax/README.md).
    exp-002's result row carried ``units`` as an object beside the run row's integer, and no row of the experiment
    could be read afterwards (2026-10-02)."""
    manifest = ex.load_manifest(write_manifest(tmp_path, "0" * 64))
    outcomes = crafted(groups=4, b_better=True)
    report = ex.analyse(manifest, outcomes, resamples=20, provenance={"code_commit": COMMIT})
    store = FileStore(tmp_path / "memory")
    registration = ex.register(store, manifest, commit_of=lambda _p: COMMIT, created="2026-10-02")
    run_row = {
        **registration, "id": "run-row", "task": ex.RUN_TASK,
        **ex.RunSummary(manifest.id, "done", 4, {"A": 4, "B": 4}, {"A": 0, "B": 0}, {}, "f" * 64).as_dict(),
    }  # fmt: skip
    rows = [registration, run_row, ex.result_row(manifest, COMMIT, report), *(ex.outcome_row(manifest.id, COMMIT, o) for o in outcomes)]
    shapes: dict[str, set[str]] = {}
    for row in rows:
        for name, value in row.items():
            if value is not None:
                shapes.setdefault(name, set()).add(_json_shape(value))
    assert {name: sorted(s) for name, s in shapes.items() if len(s) > 1} == {}
