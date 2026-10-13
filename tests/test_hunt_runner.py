"""The hunt runner over a fixture repository with a scripted program: records, resumability, the pilot refusal."""

from __future__ import annotations

import json
import subprocess

import pytest

dspy = pytest.importorskip("dspy")
from dspy.utils import DummyLM  # noqa: E402

from benchmarks.unseen import score  # noqa: E402
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
    rows = score.load_records(out)
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
