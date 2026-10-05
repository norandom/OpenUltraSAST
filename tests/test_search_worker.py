import json
from dataclasses import asdict

import pytest

from openultrasast.plane.memory import FileStore
from openultrasast.search.board import Board
from openultrasast.search.budget import SearchBudget
from openultrasast.search.coordinator import Coordinator, SearchTask
from openultrasast.search.probe import materialise
from openultrasast.search.verify import verify
from openultrasast.search.worker import StubModel, Worker


def reply(value):
    return {"content": json.dumps(value)}


def tool(name, **arguments):
    return {"tool_calls": [{"id": "call-1", "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}


def task(step="reason"):
    return SearchTask("task-1", "search-1", step, "facts: []\nhints: []", {}, asdict(SearchBudget()))


def test_reason_no_tools_and_bounded(tmp_path):
    model = StubModel([reply({"intents": [{"description": "inspect", "from_facts": []}]})])
    result = Worker(model, repo=tmp_path, demo=tmp_path / "demo")(task())
    assert result["intents"][0]["description"] == "inspect"
    assert model.calls[0]["tools"] == []
    assert result["cost_usd"] == 0
    model = StubModel([reply({"intents": [{"description": "x"}] * 4})])
    assert Worker(model, repo=tmp_path, demo=tmp_path / "demo")(task())["status"] == "execution_failure"


def test_tools_bounds_and_path_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "many").write_text("needle\n" * 1000)
    (repo / "link").symlink_to("/etc/passwd")
    worker = Worker(StubModel([]), repo=repo, demo=tmp_path / "demo")
    assert len(worker.tool("read_file", {"path": "many", "lines": 900})["text"].splitlines()) == 400
    assert len(worker.tool("grep", {"pattern": "needle"})["matches"]) == 200
    for path in ("../escape", "/etc/passwd", "link"):
        with pytest.raises(ValueError):
            worker.tool("read_file", {"path": path})
    with pytest.raises(ValueError):
        worker.tool("write_demo", {"path": "../escape", "content": "bad"})


def test_run_scrubs_model_key_in_real_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-reach-repo")
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo")
    result = worker.tool(
        "run",
        {
            "command": ["/usr/bin/python3", "-I", "-c", 'import os; print("OPENROUTER_API_KEY" in os.environ); print(os.getuid())'],
            "timeout_seconds": 2,
        },
    )
    assert result["exit_code"] == 0, result
    assert result["stdout"].splitlines()[0] == "False"
    assert "must-not-reach-repo" not in json.dumps(result)


def test_coordinator_stub_smoke_real_verify(tmp_path):
    sides, _ = materialise(tmp_path / "pair", "path")
    demo = tmp_path / "demo"
    model = StubModel(
        [
            reply({"intents": [{"description": "prove path traversal", "from_facts": []}]}),
            tool("read_file", path="app.py"),
            tool("write_demo", path="build.sh", content="test -s /workspace/app.py\n"),
            tool("write_demo", path="request.json", content='["path", "../canary"]'),
            tool("finish", fact={"text": "Traversal candidate", "evidence_refs": ["tool:1"], "demo": "demo/"}),
        ]
    )
    worker = Worker(model, repo=sides[0].checkout, demo=demo)
    outcomes = []

    def executor(job):
        if job.step != "verify":
            return worker(job)
        result = verify(*sides, demo, "path")
        outcomes.append(result.outcome)
        return {"status": "ok", "outcome": result.outcome, "evidence_refs": ["verify:local"], "cost_usd": 0}

    board = Board(FileStore(tmp_path / "memory"), "smoke", coordinator="host")
    result = Coordinator(board, executor).run()
    assert outcomes == ["demonstrated"]
    assert result["end_reason"] == "goal_met"
    assert result["facts"][-1]["step"] == "verify"


def test_reservation_precedes_each_call_and_refuses_over_budget(tmp_path):
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget

    class MeteredStub(StubModel):
        def complete_chat_raw(self, **kwargs):
            assert meter.reserved > 0
            return super().complete_chat_raw(**kwargs)

    client = MeteredStub([reply({}), reply({})])
    worker = Worker(client, repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 1))
    meter = SpendBudget(0.1)
    assert worker.reason("facts: []", meter) == {}
    assert meter.reserved == 0
    job = task()
    job.limits["max_call_usd"] = 0.000001
    result = worker(job)
    assert result["failure"] == "BudgetExhausted"
    assert len(client.calls) == 1


def test_failed_model_call_charged_and_secrets_not_reported(tmp_path):
    from openultrasast.model.endpoint import Prices

    class Broken(StubModel):
        def complete_chat_raw(self, **kwargs):
            raise RuntimeError("Authorization: super-private-key")

    result = Worker(Broken([]), repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 1))(task())
    assert result["cost_usd"] > 0
    assert result["status"] == "execution_failure"
    assert "super-private-key" not in json.dumps(result)


def test_run_timeout_truncation_and_disk_bound(tmp_path):
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo")
    result = worker.tool("run", {"command": ["/bin/sleep", "3"], "timeout_seconds": 1})
    assert result["timed_out"]
    result = worker.tool("run", {"command": ["/usr/bin/python3", "-I", "-c", 'print("x" * 20000)']})
    assert result["truncated"] and len(result["stdout"]) == 16384
    worker.limits["disk_bytes"] = 4096
    result = worker.tool("run", {"command": ["/usr/bin/python3", "-I", "-c", 'open("/scratch/full", "wb").write(b"x" * 16384)']})
    assert result["exit_code"] != 0
    assert "No space left" in result["stderr"]


def test_finish_requires_actual_evidence_and_single_fact(tmp_path):
    for response in (
        tool("finish", fact={"text": "fake", "evidence_refs": ["missing"]}),
        tool("finish", fact={"text": "x", "evidence_refs": []}, failure="both"),
    ):
        result = Worker(StubModel([response]), repo=tmp_path, demo=tmp_path / "demo")(task("explore"))
        assert result["status"] == "execution_failure"
        assert "fact" not in result


def test_reason_completion_cites_board_facts(tmp_path):
    good = {"complete": {"from": ["f1"], "description": "Candidate ready"}}
    worker = Worker(StubModel([reply(good)]), repo=tmp_path, demo=tmp_path / "demo")
    job = task()
    from dataclasses import replace

    assert worker(replace(job, snapshot="facts: [{id: f1}]"))["complete"] == good["complete"]
