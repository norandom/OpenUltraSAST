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
    assert search["model_calls"] == (4 if side == "vulnerable" else 5)
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
    pilot.worker.client.responses = iter([{"content": "invalid json"}])
    record = pilot.run()
    assert record["outcome"] == "inconclusive"
    assert record["failures"] == [{"phase": "reason", "reason": "worker_execution_failed"}]


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
    assert record["model_calls"] == 4
    assert record["executor_tasks"] == 3
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
    pilot.family = "injection"
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
