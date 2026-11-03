"""The hunt runner over a fixture repository with a scripted program: records, resumability, the pilot refusal."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime

import pytest

dspy = pytest.importorskip("dspy")
from dspy.utils import DummyLM  # noqa: E402

from benchmarks.unseen import score  # noqa: E402
from benchmarks.valid.hunt_handoff import (  # noqa: E402
    HUNT_RUNNER_PRODUCER,
    discover_hunt_runner_context,
    persist_hunt_runner_records,
    read_hunt_runner_records,
)
from openultrasast.hunt import program as hp  # noqa: E402
from openultrasast.hunt import runner  # noqa: E402


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    (root / "app.py").write_text(
        "def first():\n    value = input()\n    return value\n\ndef second():\n    value = first()\n    return value\n"
    )
    git("add", "app.py")
    git("commit", "-qm", "initial")
    base = git("rev-parse", "HEAD")
    (root / "app.py").write_text(
        "def first():\n    value = input()\n    return value\n\ndef second():\n    value = first()\n    return eval(value)\n"
    )
    git("add", "app.py")
    git("commit", "-qm", "change")
    head = git("rev-parse", "HEAD")
    positive = {
        "id": "pos", "repo": "fixture/repo", "base": base, "head": head, "kind": "vulnerability", "case_id": "case-1",
        "path": "app.py", "function": "second", "function_lines": [5, 7], "family": "injection",
        "files": [{"path": "app.py", "head_lines": [[7, 7]]}],
    }  # fmt: skip
    ordinary = {
        "id": "ord",
        "repo": "fixture/repo",
        "base": base,
        "head": head,
        "kind": "ordinary",
        "case_id": "ord-1",
        "files": [{"path": "app.py", "head_lines": [[7, 7]]}],
    }
    manifest = tmp_path / "pool-fixture.toml"
    manifest.write_text("status = 'fixture'\n")
    return root, manifest, [positive, ordinary]


def _scripted_program():
    answer = [{"path": "app.py", "line": 7, "family": "injection", "confidence": 0.9, "rationale": "eval of input", "cited_lines": [7]}]
    lm = DummyLM([{"findings": json.dumps(answer)}, {"findings": "[]"}, {"findings": json.dumps(answer)}, {"findings": "[]"}])
    dspy.configure(lm=lm, adapter=dspy.ChatAdapter())
    return hp.HuntProgram(mask=["obligations"])


def test_runner_writes_scorable_records_and_resumes(repository, tmp_path):
    root, manifest, changes = repository
    program = _scripted_program()
    pid = hp.program_id(program, mask=program.mask)
    out = tmp_path / "out"
    artifact = runner.run(
        manifest, {"fixture/repo": str(root)}, out, program=program, program_id=pid, mask=program.mask, load_changes=lambda m, s: changes
    )
    assert artifact is not None and artifact.program_id == pid
    context = discover_hunt_runner_context(out, manifest, producer=HUNT_RUNNER_PRODUCER, freeze_digest="e" * 64)
    rows = list(read_hunt_runner_records(out, context=context, changes=changes))
    assert {r["id"]: r["status"] for r in rows} == {"pos": "hunt_covered", "ord": "hunt_covered"}
    pos = next(r for r in rows if r["id"] == "pos")
    assert pos["instrument"]["head_verified"] and pos["instrument"]["hook_bytes_read"] > 0
    defects = pos["push"]["admission"]["defects"]
    assert defects and defects[0]["family"] == "injection" and defects[0]["locations"] == [["app.py", 7]]
    assert defects[0]["program_id"] == pid and defects[0]["mask"] == ["obligations"]
    assert defects[0]["function"] == "second"
    assert score.catches(pos)
    assert "obligations" not in pos["inputs_present"] and "function_text" in pos["inputs_present"]
    # a second run with the same program and mask touches nothing
    before = {p.name: p.read_bytes() for p in out.glob("*.json")}
    runner.run(
        manifest, {"fixture/repo": str(root)}, out, program=program, program_id=pid, mask=program.mask, load_changes=lambda m, s: changes
    )
    assert {p.name: p.read_bytes() for p in out.glob("*.json") if p.name in before} == before


def _budget_attempt(manifest, root, source, program, pid, changes):
    return runner.run(
        manifest,
        {"fixture/repo": str(root)},
        source,
        program=program,
        program_id=pid,
        mask=program.mask,
        load_changes=lambda _manifest, _slice: changes,
        budget={"calls": 1},
        versions={"dspy": dspy.__version__},
    )


def test_budget_stop_resume_handoff_binds_all_attempt_artifacts(repository, tmp_path, monkeypatch):
    root, manifest, changes = repository
    program = _scripted_program()
    pid = hp.program_id(program, mask=program.mask)
    source = tmp_path / "attempts"
    destination = tmp_path / "benchmark-v2"
    instant = datetime(2026, 11, 2, tzinfo=UTC)
    instants = iter((instant, instant))

    class AttemptClock:
        @classmethod
        def now(cls, _timezone):
            return next(instants)

    monkeypatch.setattr(runner, "datetime", AttemptClock)
    monkeypatch.setattr(runner.time, "monotonic", lambda: 100.0)

    first = _budget_attempt(manifest, root, source, program, pid, changes)
    (first_path,) = [path for path in source.glob("*.json") if "artifact_id" in path.read_text()]
    first_before = (first_path.read_bytes(), first_path.stat().st_mtime_ns)
    second = _budget_attempt(manifest, root, source, program, pid, changes)
    artifacts = [path for path in source.glob("*.json") if "artifact_id" in path.read_text()]
    assert first is None and second is None
    assert len(artifacts) == 2
    assert all(path.stat().st_size > 0 for path in artifacts)
    assert (first_path.read_bytes(), first_path.stat().st_mtime_ns) == first_before
    source_before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.iterdir()}

    context = discover_hunt_runner_context(source, manifest, producer=HUNT_RUNNER_PRODUCER, freeze_digest="e" * 64)
    assert context.artifact_ids == tuple(sorted(path.stem for path in artifacts))
    assert {row["id"] for row in read_hunt_runner_records(source, context=context, changes=changes)} == {"pos", "ord"}
    persist_hunt_runner_records(source, destination, context=context, changes=changes)
    destination_before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()}
    persist_hunt_runner_records(source, destination, context=context, changes=changes)
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.iterdir()} == source_before
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()} == destination_before


def test_runner_refuses_the_pilot_unless_it_is_a_report_run(tmp_path):
    manifest = tmp_path / "pool-valid.toml"
    manifest.write_text("status = 'frozen'\n")
    (tmp_path / "freeze-valid.json").write_text(json.dumps({"freeze_digest": runner.PILOT_FREEZE_DIGEST}))
    with pytest.raises(ValueError, match="held out"):
        runner.refuse_pilot(manifest, pilot_report=False)
    runner.refuse_pilot(manifest, pilot_report=True)


def test_instrument_failure_is_recorded_with_a_type_only(repository, tmp_path):
    root, manifest, changes = repository
    program = _scripted_program()
    broken = {**changes[0], "id": "bad", "head": "0" * 40}
    record = runner.hunt_change(broken, root, program=program, program_id="p", mask=(), render=hp.render_rows, tools_for=None)
    assert record["status"] == "instrument_failure"
    assert record["instrument"]["failure"] == "CalledProcessError"
    assert record["push"]["admission"]["defects"] == []


def test_full_checkout_restores_a_truncated_file_and_refuses_an_unread_tree(repository, tmp_path, monkeypatch):
    root, _manifest, changes = repository
    worktree = tmp_path / "head"
    subprocess.run(
        ["git", "-C", str(root), "worktree", "add", "--detach", str(worktree), changes[0]["head"]], check=True, capture_output=True
    )
    (worktree / "app.py").write_bytes(b"")
    runner._full_checkout(worktree)
    assert (worktree / "app.py").read_bytes()  # the truncated file was restored, not read as empty
    real = runner._git

    def still_dirty(target, *args):
        return " M app.py\n" if args[:2] == ("status", "--porcelain") else real(target, *args)

    monkeypatch.setattr(runner, "_git", still_dirty)
    with pytest.raises(runner.InstrumentFailure, match="checkout_incomplete"):
        runner._full_checkout(worktree)


def test_spent_since_prices_only_the_new_calls_of_a_registered_model():
    history = [
        {"model": "openai/deepseek-flash", "usage": {"prompt_tokens": 10, "completion_tokens": 10}},
        {
            "model": "openai/deepseek-flash",
            "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 100_000, "prompt_tokens_details": {"cached_tokens": 500_000}},
        },
        {"model": "other/unregistered", "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000}},
        {"model": "openai/deepseek-flash", "usage": None},
    ]
    assert runner.spent_since(history, 1) == pytest.approx(0.5 * 0.44 + 0.5 * 0.014 + 0.1 * 1.32)
    assert runner.spent_since(None, 0) == 0.0
