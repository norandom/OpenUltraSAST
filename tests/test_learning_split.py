"""learning-harness task 3.1: one teacher rule across every learning path (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_slice, select_vendored

VULN = "import os\nfrom flask import request\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "import subprocess\nfrom flask import request\n\n\ndef run():\n    subprocess.run(['echo'], check=False)\n"


def _teaching_case(tmp_path: Path, name: str, *, split: str = "train") -> PairCase:
    """A pair that really carries a mechanism shape.

    The trivial `x = 1` fixture below teaches nothing whatever the split says, so a teacher-rule assertion made
    against it passes with the rule deleted. This one is the difference between measuring the rule and measuring
    an empty corpus."""
    (tmp_path / f"{name}-v.py").write_text(VULN)
    (tmp_path / f"{name}-f.py").write_text(FIXED)
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(ExpectedFinding(cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other"),),
        min_recall=1.0,
        fix_policy="silent",
        split=split,
        review_tier="seeded",
    )


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
    """Both arms, because `teaching_pairs <= 1` on a two-pair corpus is satisfied by a rule that does nothing.

    The same two excerpts teach twice when both are on the train split and once when one is held out, and the run
    names the pair it refused (Req 5.1, 5.2)."""
    from openultrasast.semantic.loo import evaluate_loo

    both_train = evaluate_loo([_teaching_case(tmp_path, "train-one"), _teaching_case(tmp_path, "train-two")])
    assert both_train.teaching_pairs == 2 and both_train.degradations == ()
    result = evaluate_loo([_teaching_case(tmp_path, "train-one"), _teaching_case(tmp_path, "holdout-one", split="holdout")])
    assert {outcome.pair for outcome in result.outcomes} == {"train-one", "holdout-one"}  # every pair is still scored
    assert result.teaching_pairs == 1
    refusals = [item for item in result.degradations if item.get("reason") == "holdout_pair_refused"]
    assert [item["pairs"] for item in refusals] == [["holdout-one"]]


def test_the_mechanism_lever_refuses_a_candidate_a_holdout_pair_taught(tmp_path: Path) -> None:
    """Both arms. The shape is the one the corpus really teaches, taken from the pair itself.

    Asserting only the refusal would pass against a lever that admits nothing at all, and a hand-written shape that
    matches no excerpt can never be admitted either, so neither would measure the split rule (Req 5.2)."""
    from openultrasast.improve.evolve import propose_mechanism_edits
    from openultrasast.semantic.loo import _facts
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.seed import pair_lessons

    cases = [_teaching_case(tmp_path, "train-one"), _teaching_case(tmp_path, "holdout-one", split="holdout")]
    (lesson,) = pair_lessons(cases[0], _facts())

    def store(name: str, pair: str) -> MechanismStore:
        path = MechanismStore(tmp_path / name)
        append_from_pair(path, lesson.shape, summary=lesson.summary, cwe=lesson.cwe, pair=pair, provenance="human", tier="seeded")
        return path

    reasons: list[dict[str, object]] = []
    refused = propose_mechanism_edits(cases, store("refused.jsonl", "holdout-one"), tmp_path / "scan.jsonl", degradations=reasons)
    assert [edit.mechanism_id for edit in refused if edit.action == "admit"] == []
    assert [item["pairs"] for item in reasons] == [["holdout-one"]]
    admitted = propose_mechanism_edits(cases, store("allowed.jsonl", "train-one"), tmp_path / "scan2.jsonl")
    assert [edit.mechanism_id for edit in admitted if edit.action == "admit"], "a train-taught shape is still admissible"


def test_the_corrected_lever_number_is_measured_and_committed() -> None:
    report = Path("benchmarks/measurements/2026-09-06-mechanism-lever-split.json")
    assert report.is_file()
    payload = json.loads(report.read_text())
    assert payload["slice"] == "vibe-py" and payload["holdout_pairs"] > 0
    assert set(payload["before"]) >= {"detected", "silent", "youden", "shapes"}
    assert set(payload["after"]) >= {"detected", "silent", "youden", "shapes"}
    assert payload["after"]["shapes"] < payload["before"]["shapes"]  # holdout pairs no longer teach
    assert payload["after"]["youden"] <= payload["before"]["youden"]
