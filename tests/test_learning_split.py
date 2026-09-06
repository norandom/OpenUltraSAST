"""learning-harness task 3.1: one teacher rule across every learning path (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_slice, select_vendored


def _case(tmp_path: Path, name: str, *, split: str = "train", tier: str = "seeded", unscorable: str | None = None) -> PairCase:
    (tmp_path / f"{name}.py").write_text(f"# {name}\nx = 1\n")
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}.py",
        fixed_file=tmp_path / f"{name}.py",
        relpath="app.py",
        expected=(ExpectedFinding(cwe="CWE-89", vulnerability_class="x", path="app.py", evidence="", function="f", mechanism="other"),),
        min_recall=1.0,
        fix_policy="silent",
        split=split,
        review_tier=tier,
        reviewer="m" if tier == "reviewed" else "",
        unscorable=unscorable,
    )


def test_only_vendored_trusted_scorable_train_pairs_may_teach(tmp_path: Path) -> None:
    from openultrasast.learning.split import teachers

    cases = [
        _case(tmp_path, "train-seeded"),
        _case(tmp_path, "train-reviewed", tier="reviewed"),
        _case(tmp_path, "holdout-seeded", split="holdout"),
        _case(tmp_path, "train-untrusted", tier="title"),
        _case(tmp_path, "train-twin", unscorable="identical_twin"),
    ]
    assert [case.name for case in teachers(cases)] == ["train-seeded", "train-reviewed"]


def test_a_candidate_taught_by_a_holdout_pair_is_refused_by_name(tmp_path: Path) -> None:
    from openultrasast.learning.split import refuse_if_holdout

    cases = [_case(tmp_path, "train-one"), _case(tmp_path, "holdout-one", split="holdout")]
    assert refuse_if_holdout(["train-one"], cases) is None
    refusal = refuse_if_holdout(["train-one", "holdout-one"], cases)
    assert refusal is not None and refusal.pairs == ("holdout-one",)
    assert refusal.reason == "holdout_pair_refused"
    degradation = refusal.degradation()
    assert degradation["stage"] == "learning" and degradation["pairs"] == ["holdout-one"]
    assert "holdout-one" in str(degradation["detail"])


def test_the_exporter_seeds_from_train_pairs_only(tmp_path: Path) -> None:
    from openultrasast.semantic.mechanisms import MechanismStore, corpus_mechanisms
    from openultrasast.semantic.seed import export_mechanisms

    cases = select_vendored(select_slice(load_pair_catalog(DEFAULT_CATALOG), "vibe-py"))
    holdout = {case.name for case in cases if case.split == "holdout"}
    store = MechanismStore(tmp_path / "candidates.jsonl")
    report = export_mechanisms(cases, store)
    taught_by_holdout = [record.id for record in corpus_mechanisms(store.load()) if set(record.pairs) & holdout]
    assert taught_by_holdout == []
    assert report.records > 0 and any(reason.startswith("split:") for _pair, reason in report.skipped)


def test_leave_one_out_teaches_from_train_pairs_only(tmp_path: Path) -> None:
    from openultrasast.semantic.loo import evaluate_loo

    cases = [_case(tmp_path, "train-one"), _case(tmp_path, "holdout-one", split="holdout")]
    result = evaluate_loo(cases)
    assert {outcome.pair for outcome in result.outcomes} == {"train-one", "holdout-one"}  # every pair is still scored
    assert result.teaching_pairs <= 1  # only the train pair could ever have taught


def test_the_mechanism_lever_refuses_a_candidate_a_holdout_pair_taught(tmp_path: Path) -> None:
    from openultrasast.improve.evolve import propose_mechanism_edits
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.variants import Shape

    shape = Shape(
        language="python",
        sink_name="system",
        arity=1,
        source_positions=(0,),
        source_kinds=("request",),
        guard="none",
        mechanism="source_reaches_sink",
    )
    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    append_from_pair(candidates, shape, summary="s", cwe="CWE-78", pair="holdout-one", provenance="human", tier="seeded")
    cases = [_case(tmp_path, "train-one"), _case(tmp_path, "holdout-one", split="holdout")]
    edits = propose_mechanism_edits(cases, candidates, tmp_path / "scan.jsonl")
    assert [edit.mechanism_id for edit in edits if edit.action == "admit"] == []


def test_the_corrected_lever_number_is_measured_and_committed() -> None:
    report = Path("benchmarks/measurements/2026-09-06-mechanism-lever-split.json")
    assert report.is_file()
    payload = json.loads(report.read_text())
    assert payload["slice"] == "vibe-py" and payload["holdout_pairs"] > 0
    assert set(payload["before"]) >= {"detected", "silent", "youden", "shapes"}
    assert set(payload["after"]) >= {"detected", "silent", "youden", "shapes"}
    assert payload["after"]["shapes"] < payload["before"]["shapes"]  # holdout pairs no longer teach
    assert payload["after"]["youden"] <= payload["before"]["youden"]
