"""Pilot reports use small git fixtures and never run the held-out pilot."""

import json
from dataclasses import replace

import pytest

pytest.importorskip("dspy")
pytest.importorskip("pandas")
pytest.importorskip("statsmodels")

from test_hunt_rounds import candidate_at, finding, model  # noqa: E402
from test_hunt_rounds import population as population  # noqa: E402

from benchmarks.unseen import score  # noqa: E402
from benchmarks.valid import metrics  # noqa: E402
from openultrasast.hunt import accept, report, runner  # noqa: E402


@pytest.fixture
def pilot_case(population, tmp_path):
    """Create an accepted candidate, a checked training run and recorded before metrics."""
    pool, repos, changes, _ = population
    _, _, candidate = candidate_at(tmp_path / "proposal")
    decision = accept.Decision(True, [], {"candidate_id": candidate.program_id, "accepted": True, "rule": {"version": "fixture"}})
    training = tmp_path / "training"
    training.mkdir()
    (training / "contamination.json").write_text('{"contaminated": false}')
    # These are fixture numbers in exactly the pilot metrics file's shape.
    before = dict(
        recall=score.rate([False, True]),
        precision=score.rate([False, True, False]),
        false_alarms_per_100_pushes={**score.rate([True, True]), "rate": 100, "wilson95": [34.237, 100]},
    )
    paths = {}
    for name in ("raw", "filtered"):
        path = tmp_path / f"metrics_b_{name}.json"
        path.write_text(json.dumps(before))
        paths[name] = path
    kwargs = dict(
        pilot_manifest=pool,
        repos=repos,
        training_runs=[training],
        out_root=tmp_path / "reports",
        lm=model([[finding()], [], [finding()], []]),
        budget={"usd": 1, "calls": 100},
        pilot_metrics=paths,
        load_changes=lambda m, s: changes,
    )
    return candidate, decision, kwargs


@pytest.mark.parametrize("accepted,matches", [(False, True), (True, False)])
def test_refuse_unaccepted_or_unrelated_decision(pilot_case, accepted, matches):
    """Only the decision for this accepted program authorizes a pilot attempt."""
    candidate, decision, kwargs = pilot_case
    decision = replace(decision, accepted=accepted, comparison={"candidate_id": candidate.program_id if matches else "other"})
    with pytest.raises(ValueError, match="accepted"):
        report.pilot_gain(candidate, decision, **kwargs)
    assert not kwargs["out_root"].exists()


@pytest.mark.parametrize("check", [None, {"contaminated": True}, {"contaminated": "false"}])
def test_refuse_contaminated_or_unchecked_training(pilot_case, check):
    """Missing, malformed and contaminated checks cannot lead to a pilot number."""
    candidate, decision, kwargs = pilot_case
    path = kwargs["training_runs"][0] / "contamination.json"
    path.unlink() if check is None else path.write_text(json.dumps(check))
    with pytest.raises(ValueError, match="unchecked|contaminat"):
        report.pilot_gain(candidate, decision, **kwargs)
    assert not kwargs["out_root"].exists()


def test_valid_report_before_after_workload_curve_and_ledger(pilot_case, population):
    """A readable run writes metrics, per-family tables, instrument proof and a durable reservation."""
    candidate, decision, kwargs = pilot_case
    analysis = report.pilot_gain(candidate, decision, **kwargs)
    assert analysis["valid"]
    directory = kwargs["out_root"] / analysis["measurement_directory"]
    assert json.loads((directory / "analysis.json").read_text()) == analysis
    instruments = json.loads((directory / "instrument.json").read_text())
    assert instruments["failures"] == 0 and instruments["changes"] == 4
    for row in instruments["records"]:
        assert row["changed_bytes"]["app.py"] > 0
        assert row["base_verified"] and row["head_verified"] and row["base"] and row["head"]
    assert analysis["before"]["raw"]["metrics"] == json.loads(kwargs["pilot_metrics"]["raw"].read_text())
    records = score.load_records(directory / "records")
    assert analysis["after"]["pooled"]["push"] == metrics.summarize(records, scored=score.score(metrics.scoring_records(records)))
    assert analysis["after"]["injection"]["search"]["recall"]["rate"] == 1
    assert analysis["after"]["pooled"]["search"]["suspicions_per_push"]["rate"] == 0
    assert analysis["workload"]["suspicions_per_100_pushes"]["rate"] == 50
    assert analysis["workload"]["flagged_pushes_per_100_pushes"]["rate"] == 50
    assert analysis["gate_distance"]["false_alarms_at_recall_90"]["false_alarms_per_100_pushes"] == 0
    assert analysis["gate_distance"]["recall_under_10_false_alarms"]["recall"] == 1
    notes = (directory / "NOTES.md").read_text()
    for phrase in ("raw", "filtered", "injection", "pooled", "Workload", "Gate", "Instrument", candidate.program_id):
        assert phrase in notes
    ledger = [json.loads(line) for line in (kwargs["out_root"] / "hunt-pilot-runs.jsonl").read_text().splitlines()]
    assert ledger[0]["program_id"] == candidate.program_id and ledger[0]["date"]
    calls = len(kwargs["lm"].history)
    with pytest.raises(ValueError, match="already"):
        report.pilot_gain(candidate, decision, **kwargs)
    assert len(kwargs["lm"].history) == calls


def test_invalid_instrument_quotes_no_numbers(pilot_case, population):
    """One unreadable change out of four invalidates the run before any metrics are computed."""
    candidate, decision, kwargs = pilot_case
    changes = [dict(c) for c in population[2]]
    changes[0]["files"] = [{"path": "missing.py", "head_lines": [[1, 2]]}]
    kwargs["load_changes"] = lambda m, s: changes
    analysis = report.pilot_gain(candidate, decision, **kwargs)
    assert not analysis["valid"] and analysis["instrument"]["failures"] == 1
    for name in ("before", "after", "workload", "gate_distance", "paired"):
        assert name not in analysis
    directory = kwargs["out_root"] / analysis["measurement_directory"]
    notes = (directory / "NOTES.md").read_text()
    assert "invalid" in notes.lower() and "No performance numbers" in notes
    assert "Wilson" not in notes and "0.5" not in notes
    assert (directory / "instrument.json").is_file() and (directory / "analysis.json").is_file()


def test_crash_consumes_program_id(pilot_case, monkeypatch):
    """The reservation is on disk before runner.run starts, including a failed launch."""
    candidate, decision, kwargs = pilot_case

    def crash(*args, **kw):
        assert kw["pilot_report"] is True and kw["only"] == "all"
        ledger = kwargs["out_root"] / "hunt-pilot-runs.jsonl"
        assert json.loads(ledger.read_text())["program_id"] == candidate.program_id
        raise RuntimeError("fixture crash")

    monkeypatch.setattr(runner, "run", crash)
    with pytest.raises(RuntimeError, match="fixture crash"):
        report.pilot_gain(candidate, decision, **kwargs)
    with pytest.raises(ValueError, match="already"):
        report.pilot_gain(candidate, decision, **kwargs)


def test_baseline_repeats_are_paired_with_single_run(pilot_case, population, tmp_path):
    """Two baseline repeats yield four positive pairs and two repository clusters."""
    import dspy

    candidate, decision, kwargs = pilot_case
    base, _, _ = candidate_at(tmp_path / "baseline-program")
    directories = []
    for repeat in range(2):
        out = tmp_path / f"baseline-{repeat}"
        with dspy.context(lm=model([[]] * 4), adapter=dspy.ChatAdapter()):
            runner.run(
                population[0], population[1], out, program=base, program_id=candidate.base_program_id, load_changes=kwargs["load_changes"]
            )
        directories.append(out)
    analysis = report.pilot_gain(candidate, decision, **{**kwargs, "baseline_runs": directories})
    recall = analysis["paired"]["pooled"]["search_recall"]
    assert recall["diff"] == 1 and recall["units"] == 4 and recall["groups"] == 2
    assert recall["ci"] == [1, 1]
    assert analysis["paired"]["pooled"]["mcnemar"]["c"] == 4
    assert analysis["paired"]["pooled"]["recall_mcnemar"]["c"] == 4
    assert analysis["paired"]["pooled"]["false_alarms_per_100_pushes"]["diff"] == 0
    assert len(analysis["baseline"]) == 2


def test_curve_reports_unreached_bounds_and_counts_unknown_families(pilot_case):
    """Low recall and ordinary alarms leave both gate bounds explicitly unreached."""
    candidate, decision, kwargs = pilot_case
    kwargs["lm"] = model([[], [finding(0.4, "path"), finding(0.4)], [], [finding(0.4)]])
    analysis = report.pilot_gain(candidate, decision, **kwargs)
    assert analysis["gate_distance"]["false_alarms_at_recall_90"] is None
    assert analysis["gate_distance"]["recall_under_10_false_alarms"] is None
    assert analysis["after"]["path"]["search"]["recall"]["n"] == 0
    assert analysis["after"]["path"]["search"]["suspicions_per_push"]["count"] == 1
    point = analysis["curve"][0]
    assert point["false_alarms_per_100_pushes"] == 100 and point["suspicions_per_push"] == 1.5
    notes = (kwargs["out_root"] / analysis["measurement_directory"] / "NOTES.md").read_text()
    assert "never reaches" in notes


def test_gate_reads_both_bounds_from_different_confidence_cuts(pilot_case):
    """A quiet high cut and a noisy complete cut report different gate distances."""
    candidate, decision, kwargs = pilot_case
    kwargs["lm"] = model([[finding(0.9)], [finding(0.4)], [finding(0.4)], [finding(0.4)]])
    analysis = report.pilot_gain(candidate, decision, **kwargs)
    assert [p["confidence"] for p in analysis["curve"]] == [0.9, 0.4]
    assert analysis["gate_distance"]["false_alarms_at_recall_90"]["false_alarms_per_100_pushes"] == 100
    assert analysis["gate_distance"]["recall_under_10_false_alarms"]["recall"] == 0.5
    assert all(p["estimates"]["recall"]["n"] == 2 and p["estimates"]["recall"]["ci"] for p in analysis["curve"])


def test_budget_stop_keeps_unrun_changes_in_instrument_denominator(pilot_case):
    """A partial runner input index cannot make an unfinished pilot look complete."""
    candidate, decision, kwargs = pilot_case
    analysis = report.pilot_gain(candidate, decision, **{**kwargs, "budget": {"usd": 1, "calls": 1}})
    assert not analysis["valid"]
    assert analysis["instrument"]["changes"] == 4 and analysis["instrument"]["failures"] == 3
    assert "after" not in analysis


def test_report_restores_tool_program_and_reads_checkout(pilot_case, tmp_path):
    """A saved ReAct candidate keeps its tools and reads source through the runner."""
    from dspy.utils import DummyLM

    _, decision, kwargs = pilot_case
    _, _, candidate = candidate_at(tmp_path / "tool-proposal", tools=True)
    decision = replace(decision, comparison={"candidate_id": candidate.program_id})
    kwargs["lm"] = DummyLM(
        [
            answer
            for _ in range(4)
            for answer in (
                {"next_thought": "Read", "next_tool_name": "read_file", "next_tool_args": {"path": "app.py"}},
                {"next_thought": "Done", "next_tool_name": "finish", "next_tool_args": {}},
                {"reasoning": "The interpreter receives input.", "findings": json.dumps([finding()])},
            )
        ]
    )
    analysis = report.pilot_gain(candidate, decision, **kwargs)
    assert analysis["valid"] and analysis["after"]["pooled"]["search"]["recall"]["rate"] == 1
    assert all("Failed to execute" not in str(entry.get("messages")) for entry in kwargs["lm"].history)


def test_push_metrics_use_pilots_alternate_target_projection(pilot_case, population):
    """A catch at an additional verified site counts once in the pilot's push metric."""
    candidate, decision, kwargs = pilot_case
    # This test isolates scoring projection; the remote primary site supplies no shown source lines.
    kwargs["lm"] = model([[{**finding(), "cited_lines": []}], [], [{**finding(), "cited_lines": []}], []])
    changes = []
    for original in population[2]:
        change = dict(original)
        if change["kind"] == "vulnerability":
            change.update(
                path="other.py",
                function="other",
                function_lines=[40, 50],
                files=[{"path": "app.py", "head_lines": [[40, 50]]}],
                targets=[dict(path="app.py", function="run", function_lines=[1, 2], family="injection")],
            )
        changes.append(change)
    analysis = report.pilot_gain(candidate, decision, **{**kwargs, "load_changes": lambda m, s: changes})
    assert analysis["after"]["pooled"]["push"]["recall"]["count"] == 2
    assert analysis["after"]["pooled"]["search"]["recall"]["count"] == 0
