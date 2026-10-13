"""Compile-only proposals on six changes and a scripted model."""

import json
from copy import deepcopy

import pytest

dspy = pytest.importorskip("dspy")
pytest.importorskip("statsmodels")
from dspy.utils import DummyLM  # noqa: E402

from openultrasast.hunt import program as hp  # noqa: E402
from openultrasast.hunt.propose import OPTIMISERS, Round, compile_examples, propose, visible_to_proposer  # noqa: E402


@pytest.fixture
def population(tmp_path):
    """Read real source bytes for three repositories with two changes each."""
    changes, rows = [], {}
    source = tmp_path / "app.py"
    source.write_text("def run():\n    return eval(input())\n")
    data = source.read_bytes()
    print(f"fixture app.py: {len(data)} bytes read")
    assert len(data) > 0
    for repo in range(3):
        for item in range(2):
            change = dict(
                id=f"c{repo}-{item}",
                repo=f"repo-{repo}",
                fold=repo,
                kind="vulnerability" if item == 0 else "ordinary",
                family="injection",
                path="app.py",
                files=[{"path": "app.py", "head_lines": [[2, 2]]}],
                advisory="PRIVATE-ADVISORY",
                verification="PRIVATE-VERIFICATION",
            )
            changes.append(change)
            rows[change["id"]] = [
                {
                    "path": "app.py",
                    "fold": repo,
                    "label": int(item == 0),
                    "feature.source.function": f"run{repo}{item}",
                    "feature.source.span": [1, 2],
                    "feature.diff.hunks": [[2, 2]],
                    "verification": "PRIVATE-VERIFICATION",
                }
            ]

    def render(change, selected):
        """Bind source text to the shipped renderer."""
        return hp.render_rows(change, selected, {"app.py": data.decode().splitlines()})

    return changes, rows, render


def instruction(program, examples, metric):
    """Change only the instruction using the same callable interface as an optimiser."""
    assert callable(metric)
    program.hunt.signature = program.hunt.signature.with_instructions("Check the changed interpreter call.")
    return program


def run_round(population, tmp_path, optimiser=instruction, kind="instruction"):
    """Run a fixed baseline and candidate sequence without network access."""
    changes, rows, render = population
    examples = compile_examples(changes, rows, compile_folds=[0, 1], render=render)
    program = hp.HuntProgram()
    round = Round(kind, hp.program_id(program), [0, 1], 13, "callable", {"usd": 1, "calls": 100})
    finding = {"path": "app.py", "line": 2, "family": "injection", "cited_lines": [2]}
    lm = DummyLM([{"findings": "[]"}] * 4 + [{"findings": json.dumps([finding])}] * 4)
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        candidate = propose(round, program, examples, optimiser=optimiser, out_dir=tmp_path)
    return candidate, program, examples


def test_instruction_scores_only_compile_changes_and_preserves_base(population, tmp_path):
    """The optimiser and provenance see four compile changes, never the two held out."""

    def checked(program, examples, metric):
        assert [e.change_id for e in examples] == ["c0-0", "c0-1", "c1-0", "c1-1"]
        for example in examples:
            assert "change" not in example.inputs()
            assert "PRIVATE" not in json.dumps(example.toDict())
        return instruction(program, examples, metric)

    candidate, base, examples = run_round(population, tmp_path, checked)
    assert candidate.program_id != hp.program_id(base)
    assert base.hunt.signature.instructions == hp.BASELINE_INSTRUCTION
    assert candidate.compile_score["recall"] == 1
    assert candidate.compile_score["ci"] is not None
    assert candidate.compile_score["positive_units"] == 2
    assert candidate.compile_score["paired"]["recall"]["diff"] == 1
    assert candidate.compile_score["paired"]["recall"]["groups"] == 2
    provenance = json.loads((tmp_path / "proposer_inputs.json").read_text())
    assert provenance == [{"change_id": e.change_id, "fold": e.fold} for e in examples]
    assert "c2-" not in json.dumps(provenance)
    saved = hp.HuntProgram()
    saved.load_state(candidate.state)
    assert hp.program_id(saved, mask=candidate.mask) == candidate.program_id


def test_two_surfaces_are_refused(population, tmp_path):
    """Instruction and demo edits cannot enter the same round."""

    def two(program, examples, metric):
        instruction(program, examples, metric)
        program.hunt.demos = [dspy.Example(**examples[0].inputs(), findings=[])]
        return program

    with pytest.raises(ValueError, match="one"):
        run_round(population, tmp_path, two)
    assert not (tmp_path / "candidates.jsonl").exists()


def test_history_contains_all_candidates_but_no_holdout(population, tmp_path):
    """Acceptance records in the same directory cannot leak through the history reader."""
    candidate, _, _ = run_round(population, tmp_path)

    def other_instruction(program, examples, metric):
        """Produce a distinct second candidate for the same compile population."""
        program.hunt.signature = program.hunt.signature.with_instructions("Follow the changed value into the interpreter.")
        return program

    second, _, _ = run_round(population, tmp_path, other_instruction)
    (tmp_path / "comparison.json").write_text('{"holdout": 987.654}')
    (tmp_path / "rejected.jsonl").write_text(json.dumps({"program_id": second.program_id, "holdout": 987.654}) + "\n")
    history = visible_to_proposer(tmp_path)
    assert [record["program_id"] for record in history] == [candidate.program_id, second.program_id]
    assert history[0]["compile_score"]["recall"] == 1
    assert "holdout" not in json.dumps(history) and "987.654" not in json.dumps(history)


def test_demo_and_mask_rounds(population, tmp_path):
    """Single demo and mask changes retain their actual provenance."""

    def demos(program, examples, metric):
        program.hunt.demos = [dspy.Example(**examples[0].inputs(), findings=[])]
        return program

    demo, _, _ = run_round(population, tmp_path / "demos", demos, "demos")
    assert demo.change == {"demos": {"count": 1, "change_ids": ["c0-0"]}}
    mask, _, _ = run_round(population, tmp_path / "mask", lambda p, e, m: hp.HuntProgram(mask=["roles"]), "mask")
    assert mask.change == {"mask": ["roles"]}


def test_examples_are_not_an_editable_answer_key(population, tmp_path):
    """An optimiser's mutation of an example cannot change the paired scoring population."""

    def mutate(program, examples, metric):
        examples[0].change["kind"] = "ordinary"
        return instruction(program, examples, metric)

    candidate, _, examples = run_round(population, tmp_path, mutate)
    assert candidate.compile_score["positive_units"] == 2
    assert examples[0].change["kind"] == "vulnerability"


def test_invalid_round_and_cross_fold_repository_are_refused(population):
    """A round has one kind, and a repository cannot straddle compile and holdout."""
    with pytest.raises(ValueError, match="kind"):
        Round(("instruction", "demos"), "base", [0], 0, "callable", {"usd": 1, "calls": 10})
    changes, rows, render = deepcopy(population)
    changes[-1]["repo"] = changes[0]["repo"]
    with pytest.raises(ValueError, match="repository"):
        compile_examples(changes, rows, compile_folds=[0, 1], render=render)


def test_registry_resolves_dspy_classes():
    """Registry lookups load the real DSPy optimiser classes."""
    assert OPTIMISERS["gepa"] is dspy.GEPA
    assert OPTIMISERS["miprov2"] is dspy.MIPROv2
    assert OPTIMISERS["bootstrap"] is dspy.BootstrapFewShot


@pytest.mark.parametrize("name", ["gepa", "miprov2", "bootstrap", "configured-miprov2"])
def test_named_optimisers_construct_and_receive_only_compile_examples(population, tmp_path, monkeypatch, name):
    """Exercise real constructors and the compile call without running a model search."""
    changes, rows, render = population
    examples = compile_examples(changes, rows, compile_folds=[0, 1], render=render)
    base = hp.HuntProgram()
    called = []

    def compile(self, student, *, trainset, **kwargs):
        """Inspect the real optimiser and supply a deterministic compiled result."""
        called.append(type(self))
        assert {e.fold for e in trainset} == {0, 1}
        assert all("change" not in e.inputs() for e in trainset)
        if name == "gepa":
            feedback = self.metric_fn(trainset[0], dspy.Prediction(findings=[]))
            assert feedback.score == 0 and "missed" in feedback.feedback
        if name.endswith("miprov2"):
            assert kwargs == {"data_aware_proposer": False}
        return instruction(student, trainset, lambda *args: 0)

    cls = OPTIMISERS[name.removeprefix("configured-")]
    monkeypatch.setattr(cls, "compile", compile)
    round = Round("instruction", hp.program_id(base), [0, 1], 13, name, {"usd": 1, "calls": 100})
    with dspy.context(lm=DummyLM([{"findings": "[]"}] * 8), adapter=dspy.ChatAdapter()):
        optimiser = cls(metric=lambda *args: 0) if name.startswith("configured-") else name
        candidate = propose(round, base, examples, optimiser=optimiser, out_dir=tmp_path)
    assert called == [cls] and candidate.compile_score["ci"]


def test_gepa_without_model_fails_clearly(population, tmp_path):
    """A missing reflection model is diagnosed before an optimiser is launched."""
    changes, rows, render = population
    examples = compile_examples(changes, rows, compile_folds=[0, 1], render=render)
    base = hp.HuntProgram()
    round = Round("instruction", hp.program_id(base), [0, 1], 13, "gepa", {"usd": 1, "calls": 100})
    with dspy.context(lm=None), pytest.raises(ValueError, match="reflection model"):
        propose(round, base, examples, optimiser="gepa", out_dir=tmp_path)
