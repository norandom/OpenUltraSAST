"""Score real fixture checkouts with scripted answers and compare separate folds."""

import json
import subprocess
from copy import deepcopy
from dataclasses import replace

import pytest

dspy = pytest.importorskip("dspy")
pytest.importorskip("pandas")
pytest.importorskip("statsmodels")
from dspy.utils import DummyLM  # noqa: E402

from openultrasast.hunt import accept, rounds, runner  # noqa: E402
from openultrasast.hunt import program as hp  # noqa: E402
from openultrasast.hunt.propose import Candidate  # noqa: E402
from openultrasast.hunt.table import FeatureTable  # noqa: E402


@pytest.fixture
def population(tmp_path):
    """Make two repository groups, each with a positive and an ordinary push."""
    changes, rows, repos = [], [], {}
    for fold in range(2):
        root = tmp_path / f"repo-{fold}"
        root.mkdir()

        def git(*args, root=root):
            return subprocess.run(
                ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args], check=True, capture_output=True, text=True
            ).stdout.strip()

        git("init", "-q")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        (root / "app.py").write_text("def run():\n    return input()\n")
        git("add", ".")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD")
        (root / "app.py").write_text("def run():\n    return eval(input())\n")
        git("add", ".")
        git("commit", "-qm", "head")
        head = git("rev-parse", "HEAD")
        repo = f"fixture/repo-{fold}"
        repos[repo] = str(root)
        for kind in ("vulnerability", "ordinary"):
            change = dict(
                id=f"{fold}-{kind}",
                repo=repo,
                base=base,
                head=head,
                kind=kind,
                family="injection",
                path="app.py",
                function="run",
                function_lines=[1, 2],
                case_id=f"case-{fold}-{kind}",
                files=[{"path": "app.py", "head_lines": [[2, 2]]}],
            )
            changes.append(change)
            rows.append(dict(change_id=change["id"], repo=repo, fold=fold))
    pool = tmp_path / "pool-fixture.toml"
    pool.write_text("status = 'fixture'\n")
    return pool, repos, changes, FeatureTable(rows)


def finding(confidence=0.9, family="injection"):
    """A suspicion at the fixture's changed interpreter call."""
    return dict(path="app.py", line=2, family=family, confidence=confidence, rationale="eval", cited_lines=[2])


def model(answers):
    """Return a local model whose answers go through ChatAdapter."""
    return DummyLM([{"findings": json.dumps(answer)} for answer in answers])


def candidate_at(out, *, tools=False):
    """Save one instruction edit with the same structure as a real proposal."""
    base = hp.HuntProgram(tools=hp.repository_tools(out) if tools else ())
    program = base.deepcopy()
    predictor = program.hunt.extract.predict if tools else program.hunt
    predictor.signature = predictor.signature.with_instructions("Follow the changed interpreter call.")
    candidate = Candidate(
        hp.program_id(program),
        "instruction",
        {"instruction": "Follow the changed interpreter call."},
        {},
        deepcopy(program.dump_state()),
        hp.program_id(base),
        deepcopy(base.dump_state()),
        (),
        (),
        str(out),
    )
    return base, program, candidate


def score_args(population, out, lm):
    """Supply the fixture manifest and its row folds to the runner wrapper."""
    pool, repos, changes, table = population
    return dict(
        pool_manifest=pool,
        repos=repos,
        table=table,
        folds=[0],
        out_dir=out,
        lm=lm,
        budget={"usd": 1, "calls": 100},
        load_changes=lambda m, s: changes,
    )


def test_fold_selection_repeat_resume_and_tools(population, tmp_path):
    """Only selected folds run, and tools read each detached checkout on both repeats."""
    base, _, _ = candidate_at(tmp_path, tools=True)
    answers = []
    for _ in range(4):
        answers.extend(
            [
                {"next_thought": "Read the change", "next_tool_name": "read_file", "next_tool_args": {"path": "app.py"}},
                {"next_thought": "Done", "next_tool_name": "finish", "next_tool_args": {}},
                {"reasoning": "The changed call evaluates input.", "findings": json.dumps([finding()])},
            ]
        )
    lm = DummyLM(answers)
    kwargs = score_args(population, tmp_path / "folds", lm)
    out = rounds.score_folds(base, program_id=hp.program_id(base), mask=(), repeats=2, **kwargs)
    assert out == tmp_path / "folds"
    for repeat in (0, 1):
        entries = json.loads((out / str(repeat) / "inputs.json").read_text())
        assert [e["item_id"] for e in entries] == [c["id"] for c in population[2][:2]]
        record = json.loads(runner.record_path(out / str(repeat), entries[0]["item_id"]).read_text())
        assert record["instrument"]["changed_bytes"]["app.py"] > 0
        assert record["instrument"]["base_verified"] and record["instrument"]["head_verified"]
        assert record["push"]["admission"]["defects"]
    assert any("eval(input())" in str(entry.get("messages")) for entry in lm.history)
    assert 2 in base.seen["app.py"]
    calls = len(lm.history)
    rounds.score_folds(base, program_id=hp.program_id(base), mask=(), repeats=2, **kwargs)
    assert len(lm.history) == calls


def test_fold_refuses_pilot_and_conflicting_rows(population, tmp_path):
    """Fold selection cannot bypass the pilot guard or split repository groups."""
    pool, _, _, table = population
    kwargs = score_args(population, tmp_path / "folds", model([]))
    (pool.with_name("freeze-fixture.json")).write_text(json.dumps({"freeze_digest": runner.PILOT_FREEZE_DIGEST}))
    with pytest.raises(ValueError, match="held out"):
        rounds.score_folds(hp.HuntProgram(), program_id="p", mask=(), **kwargs)
    pool.with_name("freeze-fixture.json").unlink()
    table.rows[1]["fold"] = 1
    with pytest.raises(ValueError, match="repository"):
        rounds.score_folds(hp.HuntProgram(), program_id="p", mask=(), **kwargs)


def test_fold_results_feed_decide_and_outcomes_flip_it(population, tmp_path):
    """Paired repository estimates accept an improvement and reject the reversed outcomes."""
    base, program, candidate = candidate_at(tmp_path / "candidate")
    for name, prog, answers in (("current", base, [[]] * 8), ("candidate", program, [[finding()], []] * 4)):
        kwargs = score_args(population, tmp_path / name, model(answers))
        rounds.score_folds(prog, program_id=hp.program_id(prog), mask=(), repeats=2, **{**kwargs, "folds": [0, 1]})
    current, proposed = tmp_path / "current", tmp_path / "candidate"

    def results(a, b, scope):
        return rounds.fold_results(a, b, population[2], scope=scope, tolerance=10, seed=13, resamples=50)

    compiled = results(current, proposed, "compile")
    held = results(current, proposed, "holdout")
    assert compiled["pooled"].recall.diff == 1
    assert compiled["pooled"].recall.units == 4 and compiled["pooled"].recall.groups == 2
    assert compiled["injection"].suspicions_per_push.diff == 0
    rule = accept.Rule(0, {}, 10000)
    assert accept.decide(candidate.base_program_id, candidate, compiled, held, rule).accepted
    assert not accept.decide(
        candidate.base_program_id, candidate, results(proposed, current, "compile"), results(proposed, current, "holdout"), rule
    ).accepted
    # Each failure mode retains a positive unit but removes stale findings.
    for repeat, change, field in ((0, population[2][0], "parse_failed"), (1, population[2][0], "status")):
        path = runner.record_path(proposed / str(repeat), change["id"])
        record = json.loads(path.read_text())
        record[field] = True if field == "parse_failed" else "instrument_failure"
        path.write_text(json.dumps(record))
    runner.record_path(proposed / "0", population[2][2]["id"]).unlink()
    remaining = results(current, proposed, "compile")["pooled"].recall
    assert remaining.units == 4 and remaining.diff == 0.25
    changed_folds = [{**c, "fold": 99} for c in population[2]]
    with pytest.raises(ValueError, match="saved study"):
        rounds.fold_results(current, proposed, changed_folds, scope="compile", tolerance=10, seed=13, resamples=50)


def test_round_trip_scores_four_passes_and_records_rejection(population, tmp_path):
    """Compile and holdout run separately; a rejected tie reaches the proposal history."""
    base, _, candidate = candidate_at(tmp_path / "proposal")
    kwargs = score_args(population, tmp_path / "round", model([[]] * 8))
    kwargs.pop("folds")
    decision = rounds.round_trip(
        base,
        candidate,
        current_id=candidate.base_program_id,
        compile_folds=[0],
        holdout_folds=[1],
        rule=accept.Rule(0, {}, 10000),
        seed=13,
        resamples=50,
        **kwargs,
    )
    assert not decision.accepted and "holdout_tie" in decision.reasons
    assert len(list((tmp_path / "round").glob("*/*/0/inputs.json"))) == 4
    rejected = json.loads((tmp_path / "proposal" / "rejected.jsonl").read_text())
    assert rejected["program_id"] == candidate.program_id and "holdout_results" not in rejected
    with pytest.raises(ValueError, match="disjoint"):
        rounds.round_trip(
            base,
            replace(candidate),
            current_id=candidate.base_program_id,
            compile_folds=[0],
            holdout_folds=[0],
            rule=accept.Rule(0, {}, 10000),
            **kwargs,
        )
