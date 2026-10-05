import json
from dataclasses import asdict

import pytest

from openultrasast.plane.memory import FileStore
from openultrasast.search import _sandbox
from openultrasast.search.board import Board
from openultrasast.search.budget import SearchBudget
from openultrasast.search.coordinator import Coordinator, SearchTask
from openultrasast.search.executor import InProcessExecutor
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
    assert result["isolation_mode"] == "brain-only"
    assert result["cost_usd"] == 0
    model = StubModel([reply({"intents": [{"description": "x"}] * 4})])
    assert Worker(model, repo=tmp_path, demo=tmp_path / "demo")(task())["status"] == "execution_failure"


def test_tools_bounds_and_path_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "many").write_text("needle\n" * 1000)
    (repo / "link").symlink_to("/etc/passwd")
    worker = Worker(StubModel([]), repo=repo, demo=tmp_path / "demo", executor=InProcessExecutor(repo))
    assert len(worker.tool("read_file", {"path": "many", "lines": 900})["text"].splitlines()) == 400
    assert len(worker.tool("grep", {"pattern": "needle"})["matches"]) == 200
    for path in ("../escape", "/etc/passwd", "link"):
        with pytest.raises(ValueError):
            worker.tool("read_file", {"path": path})
    with pytest.raises(ValueError):
        worker.tool("write_demo", {"path": "../escape", "content": "bad"})


def test_run_scrubs_model_key_in_real_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-reach-repo")
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo", executor=InProcessExecutor(tmp_path))
    result = worker.tool(
        "run",
        {
            "command": ["/usr/bin/python3", "-I", "-c", 'import os; print("OPENROUTER_API_KEY" in os.environ); print(os.getuid())'],
            "timeout_seconds": 2,
        },
    )
    assert result["isolation_mode"] == _sandbox.isolation_mode()
    assert result["exit_code"] == 0, result
    assert result["stdout"].splitlines()[0] == "False"
    assert "must-not-reach-repo" not in json.dumps(result)


def test_coordinator_stub_smoke_real_verify(tmp_path):
    sides, probe_demos = materialise(tmp_path / "pair", "path")
    demo = tmp_path / "demo"
    model = StubModel(
        [
            reply({"intents": [{"description": "prove path traversal", "from_facts": []}]}),
            tool("read_file", path="app.py"),
            tool("write_demo", schema=json.loads((probe_demos["real"] / "demo.json").read_text())),
            tool("finish", fact={"text": "Traversal candidate", "evidence_refs": ["tool:1"], "demo": "demo/"}),
        ]
    )
    worker = Worker(model, repo=sides[0].checkout, demo=demo, executor=InProcessExecutor(sides[0].checkout))
    outcomes = []

    def executor(job):
        if job.step != "verify":
            return worker(job)
        assert job.payload["oracle"] == "path"
        result = verify(*sides, demo, "path", oracle=job.payload["oracle"])
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
    assert result["failure"].startswith("BudgetExhausted: ")
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
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo", executor=InProcessExecutor(tmp_path))
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


def test_brain_routes_every_repository_tool_without_local_access(tmp_path, monkeypatch):
    class RecordingExecutor:
        def __init__(self):
            self.calls = []

        def submit(self, name, args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {"executor": name}

    executor = RecordingExecutor()
    worker = Worker(StubModel([]), repo=tmp_path / "absent", demo=tmp_path / "demo", executor=executor)
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("brain touched repository")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(type(tmp_path), "open", forbidden)
    for name, args in (
        ("list_files", {}),
        ("read_file", {"path": "app.py"}),
        ("grep", {"pattern": "needle"}),
        ("run", {"command": ["python3", "app.py"]}),
    ):
        assert worker.tool(name, args) == {"executor": name}
    assert [c[0] for c in executor.calls] == ["list_files", "read_file", "grep", "run"]


def test_brain_refuses_repository_tools_without_executor(tmp_path):
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo")
    with pytest.raises(ValueError, match="executor"):
        worker.tool("list_files", {})


def test_write_demo_accepts_only_declarative_json(tmp_path):
    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo")
    schema = {
        "oracle": "path",
        "build": {"recipe": "none", "arguments": []},
        "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
        "steps": [{"type": "cli", "arguments": ["hello"]}],
    }
    assert worker.tool("write_demo", {"schema": schema})["path"] == "demo/demo.json"
    assert json.loads((tmp_path / "demo/demo.json").read_text()) == schema
    with pytest.raises(ValueError):
        worker.tool("write_demo", {"path": "build.sh", "content": "touch /tmp/pwn"})


def test_inprocess_executor_observes_all_brain_repository_commands(tmp_path):
    class RecordingExecutor(InProcessExecutor):
        def __init__(self, repo):
            super().__init__(repo)
            self.commands = []

        def execute(self, command):
            self.commands.append(command)
            return super().execute(command)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.txt").write_text("needle")
    executor = RecordingExecutor(repo)
    worker = Worker(StubModel([]), repo=repo, demo=tmp_path / "demo", executor=executor)
    assert worker.tool("list_files", {})["files"] == ["sample.txt"]
    assert worker.tool("read_file", {"path": "sample.txt"})["input_bytes"] == 6
    assert worker.tool("grep", {"pattern": "needle"})["matches"][0]["line"] == 1
    assert worker.tool("run", {"command": ["/bin/cat", "/workspace/sample.txt"]})["stdout"] == "needle"
    assert [c.name for c in executor.commands] == ["list_files", "read_file", "grep", "run"]
    assert [c.seq for c in executor.commands] == [1, 2, 3, 4]


def test_empty_reason_retried_with_reminder_then_refused(tmp_path):
    model = StubModel([reply({}), reply({})])
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo")
    board = Board(FileStore(tmp_path / "memory"), "refused", coordinator="host")
    result = Coordinator(board, worker).run()
    assert result["end_reason"] == "reason_refused"
    assert len(model.calls) == 2
    assert "No intents are open" in model.calls[1]["messages"][0]["content"]
    assert result["checkpoint"]["failures"][-1]["reason"] == "reason_refused"


def test_reason_retry_can_recover(tmp_path):
    model = StubModel(
        [
            reply({}),
            reply({"intents": [{"description": "inspect entry", "from_facts": []}]}),
            tool("finish", failure="entry unavailable"),
        ]
    )
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo")
    board = Board(FileStore(tmp_path / "memory"), "retry", coordinator="host")
    state = Coordinator(board, worker, budget=SearchBudget(reason_rounds=1)).run()
    assert state["intents"][0]["status"] == "concluded"
    assert state["end_reason"] == "budget_spent"
    assert len(model.calls) == 3


def test_bootstrap_durable_before_first_model_call(tmp_path):
    import yaml

    board = Board(FileStore(tmp_path / "memory"), "bootstrap", coordinator="host")
    board.commit(
        writer="host",
        hints=[
            dict(id="candidate", step="reason", task_id="manifest", text=json.dumps(dict(family="path", file="app.py", function="main")))
        ],
    )

    class InspectingStub(StubModel):
        def complete_chat_raw(self, **kwargs):
            intent = board.state["intents"][0]
            assert intent["id"] == "bootstrap" and intent["status"] == "claimed"
            assert board.state["checkpoint"]["pending"]["step"] == "explore"
            snapshot = yaml.safe_load(kwargs["messages"][1]["content"].split("\nIntent:")[0])
            assert snapshot["family"] == "path"
            assert snapshot["candidate"]["function"] == "main"
            assert snapshot["budget_left"]["tasks"] == 0
            return super().complete_chat_raw(**kwargs)

    model = InspectingStub([tool("finish", failure="entry unavailable")])
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo")
    state = Coordinator(board, worker, budget=SearchBudget(tasks=1)).run()
    assert state["end_reason"] == "budget_spent"
    assert len(model.calls) == 1
    prompt = model.calls[0]["messages"][0]["content"]
    assert "Read the candidate function main in app.py" in prompt


@pytest.mark.parametrize("step", ["reason", "explore"])
def test_prompt_contracts_and_demo_example(tmp_path, step):
    from openultrasast.search.demo import validate_demo
    from openultrasast.search.worker import DEMO_GUIDE, ORACLE_GUIDE

    model = StubModel([reply({}) if step == "reason" else tool("finish", failure="no input")])
    Worker(model, repo=tmp_path, demo=tmp_path / "demo")(task(step))
    prompt = model.calls[0]["messages"][0]["content"]
    assert DEMO_GUIDE in prompt and ORACLE_GUIDE in prompt
    for text in ("private nonce file", "secret rows", "marker location", "loopback listener", "alert('ousast-xss')"):
        assert text in prompt
    example = DEMO_GUIDE.removeprefix("Demo schema: ").split(". This is a minimal example")[0]
    assert validate_demo(json.loads(example))
    if step == "reason":
        assert "MUST propose 1-3" in prompt
        assert len(prompt) / 4 < 1000  # rough offline token estimate, not a tokenizer
    else:
        assert "file:line" in prompt and "final call for finish" in prompt


@pytest.mark.parametrize("with_evidence", [False, True])
def test_task_spend_finishes_with_confirmed_observations(tmp_path, with_evidence):
    from openultrasast.model.endpoint import Prices

    (tmp_path / "input.txt").write_text("confirmed input\n" * 400)

    class UsageStub(StubModel):
        def complete_chat_raw(self, **kwargs):
            raw = super().complete_chat_raw(**kwargs)
            raw["usage"] = {"prompt_tokens": 100, "completion_tokens": 100}
            return raw

    model = UsageStub([tool("read_file", path="input.txt")])
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 1), executor=InProcessExecutor(tmp_path))
    job = task("explore")
    # First reservation fits; the second includes the real file contents and cannot fit.
    job.limits["max_call_usd"] = 0.01 if with_evidence else 0.000001
    result = worker(job)
    assert result["end_detail"] == result["budget_exhaustion"]["end_detail"] == "task_spend"
    assert len(model.calls) == int(with_evidence)
    assert worker.metrics["reserved"] >= worker.metrics["settled"]
    if with_evidence:
        assert result["status"] == "ok"
        assert "confirmed input" in result["fact"]["text"]
        assert result["fact"]["evidence_refs"] == ["tool:1"]
        assert result["cost_usd"] == pytest.approx(0.0002)
    else:
        assert result["status"] == "execution_failure"
        assert "task_spend" in result["failure"]
        assert "fact" not in result


def test_calibrated_reservation_covers_reported_usage(tmp_path):
    import math

    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget

    class UsageStub(StubModel):
        def complete_chat_raw(self, **kwargs):
            raw = super().complete_chat_raw(**kwargs)
            raw["usage"] = {"prompt_tokens": 27000, "completion_tokens": 1024}
            return raw

    model = UsageStub([reply({})])
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 2))
    worker.reason("facts: []\nnote: " + "x" * 85000, SpendBudget(1))
    call = model.calls[0]
    expected_input = math.ceil(len(json.dumps([call["messages"], call["tools"]], ensure_ascii=False).encode()) / 2) + 1024 * (
        len(call["messages"]) + 1
    )
    assert worker.metrics["reserved"] == pytest.approx((expected_input + 1024 * 2) / 1_000_000)
    assert worker.metrics["reserved"] >= worker.metrics["settled"] == pytest.approx(0.029048)


@pytest.mark.parametrize("detail", ["worker_steps", "worker_wall", "run_ceiling"])
def test_worker_exhaustion_is_structured(tmp_path, monkeypatch, detail):
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget

    worker = Worker(
        StubModel([tool("list_files")]),
        repo=tmp_path,
        demo=tmp_path / "demo",
        executor=InProcessExecutor(tmp_path),
        max_steps=1,
        prices=Prices(1, 1, 1),
        run_budget=SpendBudget(0 if detail == "run_ceiling" else 1),
    )
    if detail == "worker_wall":
        from openultrasast.search import worker as module

        times = iter([0, 901])
        monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    result = worker(task("explore"))
    assert result["budget_exhaustion"]["end_detail"] == detail
    assert result["end_detail"] == detail


def malformed_tool(arguments="{"):
    response = tool("read_file")
    response["tool_calls"][0]["function"]["arguments"] = arguments
    return response


def test_malformed_arguments_recover_with_tool_result(tmp_path):
    (tmp_path / "input").write_text("readable")
    model = StubModel(
        [
            malformed_tool(),
            tool("read_file", path="input"),
            tool("finish", fact={"text": "read input", "evidence_refs": ["tool:1"]}),
        ]
    )
    result = Worker(model, repo=tmp_path, demo=tmp_path / "demo", executor=InProcessExecutor(tmp_path))(task("explore"))
    assert result["status"] == "ok" and result["fact"]["text"] == "read input"
    feedback = model.calls[1]["messages"][-1]
    assert feedback["role"] == "tool" and feedback["tool_call_id"] == "call-1"
    assert json.loads(feedback["content"])["error"].startswith("invalid JSON arguments: ")
    assert len(model.calls) == 3


def test_two_malformed_arguments_record_failure(tmp_path):
    model = StubModel([malformed_tool(), malformed_tool()])
    result = Worker(model, repo=tmp_path, demo=tmp_path / "demo")(task("explore"))
    assert result["status"] == "execution_failure"
    assert "two consecutive malformed tool calls" in result["failure"]
    assert len(model.calls) == 2


def test_valid_call_resets_malformed_streak(tmp_path):
    model = StubModel([malformed_tool(), tool("list_files"), malformed_tool(), tool("finish", failure="done")])
    result = Worker(model, repo=tmp_path, demo=tmp_path / "demo", executor=InProcessExecutor(tmp_path))(task("explore"))
    assert result["failure"] == "done" and len(model.calls) == 4


def test_malformed_call_consumes_step(tmp_path):
    model = StubModel([malformed_tool(), tool("finish", failure="unused")])
    result = Worker(model, repo=tmp_path, demo=tmp_path / "demo", max_steps=1)(task("explore"))
    assert result["end_detail"] == "worker_steps" and len(model.calls) == 1


def test_worker_run_uses_search_memory_budget(tmp_path):
    class Recorder:
        def submit(self, name, args, **kwargs):
            return kwargs["limits"]

    worker = Worker(StubModel([]), repo=tmp_path, demo=tmp_path / "demo", executor=Recorder())
    assert worker.tool("run", {"command": ["node", "app.js"]})["memory_bytes"] == SearchBudget().memory_bytes
    assert worker.tool("grep", {"pattern": "needle"})["memory_bytes"] == 256 * 1024**2
    worker.limits["memory_bytes"] = 128 * 1024**2
    assert worker.tool("read_file", {"path": "app.py"})["memory_bytes"] == 128 * 1024**2


@pytest.mark.parametrize("finish_first", [False, True])
def test_finish_wins_over_other_calls_without_executing_them(tmp_path, finish_first):
    finish = tool("finish", fact={"text": "Confirmed app source", "evidence_refs": ["tool:1"]})["tool_calls"][0]
    other = tool("read_file", path="must-not-read")["tool_calls"][0]
    model = StubModel([tool("read_file", path="app.py"), {"tool_calls": [finish, other] if finish_first else [other, finish]}])
    (tmp_path / "app.py").write_text("print('readable')")
    worker = Worker(model, repo=tmp_path, demo=tmp_path / "demo", executor=InProcessExecutor(tmp_path))
    result = worker(task("explore"))
    assert result["status"] == "ok"
    assert result["fact"]["text"] == "Confirmed app source"
    assert worker.metrics["warnings"] == 1
    assert worker.evidence == {"tool:1"}
