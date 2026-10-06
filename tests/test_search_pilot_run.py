import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json

import pytest

from benchmarks.search.pilot_run import main


@pytest.mark.parametrize("side,outcome", [("vulnerable", "demonstrated"), ("fixed", "inconclusive")])
def test_probe_pilot_end_to_end(tmp_path, capsys, side, outcome):
    output = tmp_path / "records.jsonl"
    assert (
        main(
            [
                "--dry-run",
                "--side",
                side,
                "--pairs",
                "0",
                "--ceiling-usd",
                "0.5",
                "--out",
                str(output),
                "--private-root",
                str(tmp_path / "private"),
            ]
        )
        == 0
    )
    records = [json.loads(line) for line in output.read_text().splitlines()]
    search, summary = records
    assert search["outcome"] == outcome
    assert search["model_calls"] == (3 if side == "vulnerable" else 5)
    assert search["input_bytes"] > 0
    assert search["board_bytes"] > 0
    assert search["spend"]["settled"] == 0
    assert summary["searches"] == 1
    assert summary["outcomes"] == {outcome: 1}
    assert "app.py" not in output.read_text()


def test_ceiling_refuses_before_stub_call(tmp_path):
    output = tmp_path / "records.jsonl"
    main(
        [
            "--dry-run",
            "--side",
            "vulnerable",
            "--pairs",
            "0",
            "--ceiling-usd",
            "0",
            "--out",
            str(output),
            "--private-root",
            str(tmp_path / "private"),
        ]
    )
    record = json.loads(output.read_text().splitlines()[0])
    assert record["model_calls"] == 0
    assert record["end_reason"] == "budget_spent"
    assert record["end_detail"] == "run_ceiling"
    assert record["task_metrics"][0]["end"] == "run_ceiling"


def make_pilot(tmp_path, *, side="fixed", dry_run=False):
    from argparse import Namespace

    from benchmarks.search.pilot_run import Pilot
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget
    from openultrasast.plane.memory import FileStore
    from openultrasast.search.worker import StubModel

    args = Namespace(side=side, dry_run=dry_run, model="scripted", max_tokens=128, verify_lane="vm", image="unused")
    row = dict(
        repo="https://github.com/private/project",
        vulnerable="a" * 40,
        fixed="b" * 40,
        family="path",
        language="python",
        file="app.py",
        function="main",
    )
    return Pilot(args, row, 0, tmp_path, FileStore(tmp_path / "board"), SpendBudget(1), StubModel([{"content": "{}"}]), Prices(1, 1, 1))


def test_fixed_verification_never_acquires_vulnerable_revision(tmp_path, monkeypatch):
    from benchmarks.search import pilot_run
    from openultrasast.search.probe import materialise

    pilot = make_pilot(tmp_path)
    sides, demos = materialise(tmp_path / "probe", "path")
    schema = json.loads((demos["real"] / "demo.json").read_text())
    (tmp_path / "demo/demo.json").write_text(json.dumps(schema))
    prepared = []

    def prepare(revision, spec):
        prepared.append(revision)
        return b"executor-built-bundle"

    monkeypatch.setattr(pilot, "prepare", prepare)
    monkeypatch.setattr(pilot_run._sandbox, "isolation_mode", lambda: "userns")

    # Inspect requested pins without relying on archive mechanics.
    class StopVerification(Exception):
        pass

    def stop(archive, bundle):
        bundle.mkdir()
        (bundle / "spec.json").write_text(json.dumps({"demo": schema, "family": "path", "timeout_seconds": 5}))

    monkeypatch.setattr(pilot_run, "extract_checkout", stop)
    monkeypatch.setattr(pilot_run, "verify", lambda *args, **kwargs: (_ for _ in ()).throw(StopVerification()))
    with pytest.raises(StopVerification):
        pilot.verification()
    assert prepared == ["b" * 40, "b" * 40]
    assert "a" * 40 not in json.dumps(pilot.row)


def test_worker_failure_is_not_no_evidence(tmp_path):
    pilot = make_pilot(tmp_path, dry_run=True)
    from openultrasast.search.probe import materialise

    pilot.sides, _ = materialise(tmp_path / "probe", "path")
    pilot.worker.client.responses = iter([{"content": "invalid json"}, {"content": "{}"}, {"content": "{}"}])
    record = pilot.run()
    assert record["outcome"] == "inconclusive"
    assert record["failures"][0]["phase"] == "explore"
    assert "second plain-text reply:" in record["failures"][0]["reason"]


def test_shared_budget_reserved_and_settled_on_error(tmp_path):
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget
    from openultrasast.search.worker import Worker

    run = SpendBudget(0.5)
    task = SpendBudget(0.05)

    class Client:
        max_attempts = 1

        def complete_chat_raw(self, **kwargs):
            assert run.reserved == task.reserved > 0
            raise RuntimeError("secret-provider-diagnostic")

    worker = Worker(Client(), repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 1), run_budget=run)
    with pytest.raises(RuntimeError):
        worker.reason("facts: []", task)
    assert run.reserved == task.reserved == 0
    assert run.spent == task.spent == worker.metrics["settled"] > 0
    assert worker.metrics["model_calls"] == 1


@pytest.mark.parametrize("verify_lane", ["vm", "ax"])
def test_live_wiring_with_fake_mailbox_no_network(tmp_path, monkeypatch, verify_lane):
    import shutil
    from dataclasses import asdict

    from benchmarks.search import pilot_run
    from openultrasast.search.demo import load_demo
    from openultrasast.search.executor import InProcessExecutor
    from openultrasast.search.probe import materialise
    from openultrasast.search.verify import RunObservation, SideRecord
    from openultrasast.search.verify_task import pack_checkout

    pilot = make_pilot(tmp_path, side="vulnerable")
    pilot.args.verify_lane = verify_lane
    pilot.args.image = "registry.example/search@sha256:" + "0" * 64
    sides, demos = materialise(tmp_path / "probe", "path")
    pilot.worker.client = pilot_run.scripted(load_demo(demos["real"]))
    events = []
    active = []

    class Mailbox:
        def submit(self, name, args, **kwargs):
            if name == "run":
                assert args["command"][:3] == ["sh", "-ec", pilot_run.CLONE]
                self.side = 0 if args["command"][-1] == "a" * 40 else 1
                events.append(("clone", self.side))
                return {"exit_code": 0}
            return InProcessExecutor(sides[self.side].checkout).submit(name, args, **kwargs)

    class Executor:
        def __init__(self, lane, archive, *, deadline):
            assert 0 < deadline <= 900
            self.client = Mailbox()

        def __enter__(self):
            assert not active
            active.append(self)
            return self

        def __exit__(self, *exc):
            active.remove(self)
            events.append(("cleanup", self.client.side))

        def prepare(self, spec):
            bundle = tmp_path / ("export-" + str(len(events)))
            shutil.copytree(sides[self.client.side].checkout, bundle / "checkout")
            (bundle / "products").mkdir()
            (bundle / "spec.json").write_text(json.dumps(spec))
            return pack_checkout(bundle)

    def verify_lane_call(item, output, attempt):
        assert not active  # No executor consumes a slot during verification.
        assert item.command == ("python3", "-m", "openultrasast.search.verify_task")
        assert set(item.inputs) == {"VERIFY_INPUT_URL"}
        events.append(("verify", None))
        # The dispatcher's six fresh repetitions get owned observations.
        observed = sum(kind == "verify" for kind, _ in events) <= 3
        return asdict(SideRecord("observed", (RunObservation(observed, "owned", 0.1),), 0.1, "completed", isolation_mode="task-boundary"))

    monkeypatch.setattr(pilot_run, "SearchExecutorTask", Executor)
    pilot.lane = verify_lane_call
    record = pilot.run()
    assert record["outcome"] == "demonstrated", record
    assert record["end_reason"] == "goal_met"
    assert record["model_calls"] == 3
    assert record["executor_tasks"] == 3
    assert len(record["executor_task_metrics"]) == 3
    assert sum(t["model_calls"] for t in record["executor_task_metrics"]) == 3
    for row in record["executor_task_metrics"]:
        assert row["reserved"] >= row["settled"]
        assert row["wall_seconds"] > 0
        assert row["end"] == "ok"
        assert {"tokens_in", "tokens_out"} <= row.keys()
    assert record["verify_tasks"] == (6 if verify_lane == "ax" else 0)
    assert record["tasks_submitted"] == (9 if verify_lane == "ax" else 3)
    assert record["input_bytes"] > 0
    assert [event for event in events if event[0] == "clone"] == [("clone", 0), ("clone", 0), ("clone", 1)]
    assert not active
    assert "private/project" not in json.dumps(record)
    calls = json.dumps(pilot.worker.client.calls)
    assert "b" * 40 not in calls
    assert "family" in calls and "main" in calls and "app.py" in calls


def test_no_oracle_does_not_acquire_or_build(tmp_path, monkeypatch):
    from openultrasast.search.probe import materialise

    pilot = make_pilot(tmp_path)
    _, demos = materialise(tmp_path / "probe", "path")
    (tmp_path / "demo/demo.json").write_bytes((demos["real"] / "demo.json").read_bytes())
    pilot.family = "deserialization"
    monkeypatch.setattr(pilot, "prepare", lambda *args: pytest.fail("no-oracle must not build"))
    assert pilot.verification().outcome == "no_oracle"
    assert pilot.record["tasks_submitted"] == 0


@pytest.mark.parametrize("ceiling", ["-1", "nan", "inf"])
def test_invalid_ceiling_rejected_before_work(tmp_path, ceiling):
    with pytest.raises(SystemExit, match="2"):
        main(["--dry-run", "--side", "fixed", "--pairs", "0", "--ceiling-usd", ceiling, "--out", str(tmp_path / "record")])
    assert not (tmp_path / "record").exists()


@pytest.mark.parametrize("observed,expected", [([True] * 3, True), ([False] * 3, False), ([True, False, True], None)])
def test_fixed_effect_reporting_is_independent_of_differential(tmp_path, monkeypatch, observed, expected):
    from dataclasses import asdict

    from openultrasast.search.budget import SearchBudget
    from openultrasast.search.coordinator import SearchTask
    from openultrasast.search.verify import RunObservation, SideRecord, VerificationRecord

    pilot = make_pilot(tmp_path)
    side = SideRecord("observed", tuple(RunObservation(value, "owned", 0) for value in observed), 0, "completed")
    result = VerificationRecord("inconclusive", (side, side), 0, "no differential")
    monkeypatch.setattr(pilot, "verification", lambda: result)
    task = SearchTask("task-1", "search-1", "verify", "", {}, asdict(SearchBudget()))
    assert pilot.dispatch(task)["outcome"] == "inconclusive"
    assert pilot.record["fixed_effect_observed"] is expected


def test_vm_preflight_refuses_before_client_or_store(tmp_path, monkeypatch):
    from benchmarks.search import pilot_run

    monkeypatch.setattr(pilot_run._sandbox, "isolation_mode", lambda: "task-boundary")
    monkeypatch.setattr(pilot_run, "OpenRouterChatClient", lambda **kwargs: pytest.fail("client must not open"))
    monkeypatch.setattr(pilot_run, "AXLane", lambda *args: pytest.fail("store must not open"))
    with pytest.raises(SystemExit, match="2"):
        main(
            [
                "--side",
                "vulnerable",
                "--pairs",
                "0,1,2",
                "--ceiling-usd",
                "1.5",
                "--image",
                "registry.example/search@sha256:" + "0" * 64,
                "--out",
                str(tmp_path / "records"),
            ]
        )


def test_actual_usage_settles_shared_budget_and_counts_tokens(tmp_path):
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import SpendBudget
    from openultrasast.search.worker import Worker

    run, task = SpendBudget(0.5), SpendBudget(0.05)

    class Client:
        max_attempts = 1

        def complete_chat_raw(self, **kwargs):
            assert run.reserved == task.reserved > 0.0003
            return {"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 100, "completion_tokens": 100}}

    worker = Worker(Client(), repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 2), run_budget=run)
    assert worker.reason("facts: []", task) == {}
    assert worker.metrics["tokens_in"] == worker.metrics["tokens_out"] == 100
    assert worker.metrics["settled"] == run.spent == task.spent == 0.0003
    assert run.reserved == task.reserved == 0


def test_refused_shared_reservation_releases_task_allowance(tmp_path):
    from openultrasast.model.endpoint import Prices
    from openultrasast.plane.budget import BudgetExhausted, SpendBudget
    from openultrasast.search.worker import StubModel, Worker

    run, task = SpendBudget(0), SpendBudget(0.05)
    client = StubModel([])
    worker = Worker(client, repo=tmp_path, demo=tmp_path / "demo", prices=Prices(1, 1, 2), run_budget=run)
    with pytest.raises(BudgetExhausted):
        worker.reason("facts: []", task)
    assert not client.calls
    assert task.reserved == task.spent == run.reserved == run.spent == 0


@pytest.mark.parametrize("through_worker", [False, True])
def test_explore_exception_keeps_sanitized_message(tmp_path, monkeypatch, through_worker):
    from contextlib import contextmanager

    from openultrasast.search.worker import StubModel

    pilot = make_pilot(tmp_path)
    monkeypatch.setenv("MODEL_API_KEY", "private-token-1234")

    def fail():
        raise RuntimeError("mailbox failed: " + "app.py " * 100 + "https://host/private?token=secret private-token-1234: diagnostic tail")

    class Broken(StubModel):
        def complete_chat_raw(self, **kwargs):
            fail()

    @contextmanager
    def executor(*args, **kwargs):
        if not through_worker:
            fail()
        from types import SimpleNamespace

        yield SimpleNamespace(client=None)

    monkeypatch.setattr(pilot, "executor", executor)
    if through_worker:
        pilot.worker.client = Broken([])
    record = pilot.run()
    failure = record["failures"][0]
    assert failure["phase"] == "explore"
    assert failure["reason"].startswith("RuntimeError: ")
    assert "diagnostic tail" in failure["reason"]
    assert len(failure["reason"]) <= 300
    assert "app.py" not in failure["reason"]
    assert "https://" not in failure["reason"]
    assert "private-token-1234" not in failure["reason"]


@pytest.mark.parametrize(
    "kind,calls,aborts", [("cluster", 0, True), ("cluster", 1, True), ("infra", 0, True), ("infra", 1, False), ("repo", 0, False)]
)
def test_pilot_classifies_run_abort(tmp_path, monkeypatch, kind, calls, aborts):
    from benchmarks.ax.batch import ClusterUnavailable
    from benchmarks.search import pilot_run

    pilot = make_pilot(tmp_path)
    error = {
        "cluster": ClusterUnavailable("worker pods: total=2, running=0, pending=2"),
        "infra": RuntimeError("port-forward unavailable"),
        "repo": pilot_run.RepositoryFailure("checkout failed"),
    }[kind]

    def dispatch(task):
        pilot.worker.metrics["model_calls"] = calls
        raise error

    monkeypatch.setattr(pilot, "dispatch", dispatch)
    record = pilot.run()
    assert bool(record.get("aborted_reason")) is aborts
    assert record["end_reason"] == "instrument_failure"
    if aborts:
        assert record["aborted_reason"] == record["failures"][-1]["reason"]


@pytest.mark.parametrize("setup_failure", [False, True])
def test_live_driver_stops_remaining_pairs_on_infrastructure_failure(tmp_path, monkeypatch, setup_failure):
    from benchmarks.ax.batch import ClusterUnavailable
    from benchmarks.search import pilot_run

    monkeypatch.chdir(tmp_path)
    root = Path("benchmarks/search/private")
    root.mkdir(parents=True)
    row = dict(
        repo="https://github.com/private/project",
        vulnerable="a" * 40,
        fixed="b" * 40,
        family="path",
        language="python",
        file="app.py",
        function="main",
    )
    manifest = root / "pilot.json"
    manifest.write_text(json.dumps({"pairs": [row] * 7}))
    monkeypatch.setattr(pilot_run, "load_dotenv", lambda: None)
    monkeypatch.setenv(pilot_run.DEEPSEEK_KEY_ENV, "fake-test-key")
    monkeypatch.setattr(pilot_run, "OpenRouterChatClient", lambda **kw: __import__("types").SimpleNamespace(max_attempts=1))

    def lane(*args):
        if setup_failure:
            raise RuntimeError("store unavailable")
        return object()

    monkeypatch.setattr(pilot_run, "AXLane", lane)
    attempts = []

    def enter(task):
        attempts.append(task.name)
        raise ClusterUnavailable("worker pods: total=2, running=0, pending=2")

    monkeypatch.setattr(pilot_run.SearchExecutorTask, "__enter__", enter)
    output = tmp_path / "records.jsonl"
    status = main(
        [
            "--side",
            "vulnerable",
            "--pairs",
            "2,5,6",
            "--ceiling-usd",
            "1",
            "--verify-lane",
            "ax",
            "--image",
            "image@sha256:" + "a" * 64,
            "--out",
            str(output),
        ]
    )
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert status == 1
    if setup_failure:
        assert not attempts and len(records) == 1
        assert records[0]["aborted_reason"] == "RuntimeError: store unavailable"
        assert records[0]["skipped_pairs"] == [2, 5, 6]
        assert records[0]["searches"] == 0
        return
    assert len(attempts) == 1
    search, summary = records
    assert search["pair_index"] == 2 and search["model_calls"] == 0
    assert summary["searches"] == 1 and summary["skipped_pairs"] == [5, 6]
    assert summary["end_reason"] == "instrument_failure"
    assert summary["aborted_reason"] == search["aborted_reason"]
    assert "running=0" in summary["aborted_reason"]


@pytest.mark.parametrize("oracle", ["sql", "command"])
def test_injection_pilot_uses_demo_choice_without_manifest_subtype(tmp_path, oracle):
    from openultrasast.search.probe import materialise

    pilot = make_pilot(tmp_path, side="vulnerable", dry_run=True)
    pilot.family = "injection"
    pilot.row.pop("oracle", None)
    pilot.sides, demos = materialise(tmp_path / "probe", oracle)
    (tmp_path / "demo/demo.json").write_bytes((demos["real"] / "demo.json").read_bytes())
    result = pilot.verification()
    assert result.outcome == "demonstrated", result


@pytest.mark.parametrize("phase", ["build_export", "verify/could_not_run"])
def test_pilot_retains_command_diagnostics(tmp_path, phase):
    from openultrasast.search.task_storage import CommandFailure
    from openultrasast.search.verify import SideRecord

    pilot = make_pilot(tmp_path)
    stderr = "\n".join(f"line-{i}" for i in range(30)) + "\ntoken=hidden https://example.test/?key=hidden"
    if phase == "build_export":
        pilot.failure(phase, CommandFailure("build", 7, stderr))
    else:
        side = SideRecord("could_not_run", (), 0, "start failed", phase="start", exit_code=7, stderr=stderr)
        pilot.failure(phase, side.reason, command=side)
    failure = pilot.record["failures"][-1]
    assert failure["exit_code"] == 7
    assert failure["command_phase"] == ("build" if phase == "build_export" else "start")
    assert "line-29" in failure["stderr"] and "line-0\n" not in failure["stderr"]
    assert "hidden" not in failure["stderr"] and "https://" not in failure["stderr"]
    assert len(failure["stderr"]) <= 1500


@pytest.mark.parametrize("failure_at", ["acquire", "body"])
def test_pilot_executor_deletes_task_when_submit_times_out(tmp_path, monkeypatch, failure_at):
    import time
    from types import SimpleNamespace

    from openultrasast.search.executor import ObjectStoreExecutor

    pilot = make_pilot(tmp_path)
    deleted, calls = [], []
    store = SimpleNamespace(
        _put=lambda *a: None,
        _delete=deleted.append,
        presign_get=lambda key, expires: "https://files.example/" + key,
        presign_put=lambda key, expires: "https://files.example/" + key,
    )
    pilot.lane = SimpleNamespace(
        store=store,
        host="files.example",
        args=SimpleNamespace(atespace="default"),
        workload=SimpleNamespace(image="registry/task@sha256:" + "a" * 64),
        ax=lambda *a, **kw: calls.append((a, kw)),
        clock=time.monotonic,
        pause=lambda _: None,
    )

    def submit(self, name, args, **kwargs):
        if failure_at == "acquire" or name == "list_files":
            raise TimeoutError("executor command upload deadline")
        return {"exit_code": 0, "input_bytes": 10}

    monkeypatch.setattr(ObjectStoreExecutor, "submit", submit)
    with pytest.raises(TimeoutError, match="upload deadline"), pilot.executor("a" * 40, deadline=60) as session:
        session.client.submit("list_files", {})
    assert calls[-1][0][:2] == ("delete", "task")
    assert len(deleted) == 4
    assert pilot.record["executor_task_metrics"][-1]["end"] == "execution_failure"
