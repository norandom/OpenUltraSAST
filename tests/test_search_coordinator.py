import pytest

from openultrasast.plane.memory import FileStore
from openultrasast.search.board import Board
from openultrasast.search.budget import SearchBudget
from openultrasast.search.coordinator import Coordinator


def board(tmp_path):
    return Board(FileStore(tmp_path), "search-1", coordinator="host")


def test_reason_explore_verify_and_resume(tmp_path):
    calls = []

    def execute(task):
        calls.append(task)
        assert task.limits["memory_bytes"] > 0
        if task.step == "reason":
            return {"status": "ok", "cost_usd": 0.01, "intents": [{"description": "try input", "from_facts": []}]}
        if task.step == "explore":
            return {"status": "ok", "cost_usd": 0.02, "fact": {"text": "candidate", "evidence_refs": ["capture:1"], "demo": "demo:1"}}
        return {"status": "ok", "outcome": "demonstrated", "evidence_refs": ["verify:1"]}

    b = board(tmp_path)
    result = Coordinator(b, execute).run()
    assert result["end_reason"] == "goal_met"
    assert [t.step for t in calls] == ["reason", "explore", "verify"]
    assert result["checkpoint"]["spent_usd"] == pytest.approx(0.03)
    resumed = Board.resume(b.store, "search-1", b.head, coordinator="host")
    assert Coordinator(resumed, execute).run() == result
    assert len(calls) == 3


def test_reason_claim_cannot_prove_goal(tmp_path):
    result = Coordinator(board(tmp_path), lambda task: {"status": "ok", "cost_usd": 0, "complete": True, "facts": []}).run()
    assert result["end_reason"] == "exhausted"


def test_refusal_before_dispatch_and_run_deadline(tmp_path):
    calls = []
    result = Coordinator(board(tmp_path), calls.append, budget=SearchBudget(spend_usd=0.01)).run()
    assert result["end_reason"] == "budget_spent" and calls == []
    times = iter([0, 100, 100, 100, 100])
    result = Coordinator(board(tmp_path / "two"), calls.append, budget=SearchBudget(wall_seconds=1), clock=lambda: next(times)).run()
    assert result["end_reason"] == "budget_spent" and calls == []


def test_retry_fallback_bounded_and_cost_released(tmp_path):
    calls = []

    def fail(task):
        calls.append(task.lane)
        return {"status": "sandbox_failure", "cost_usd": 0}

    state = Coordinator(board(tmp_path), fail, budget=SearchBudget(retries=1)).run()
    assert calls == ["ax", "docker"]
    assert state["end_reason"] == "exhausted"
    assert state["checkpoint"]["retries"] == 1
    assert state["checkpoint"]["spent_usd"] == 0


def test_claim_checkpoint_survives_interrupt_without_free_spend(tmp_path):
    b = board(tmp_path)

    def interrupt(task):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        Coordinator(b, interrupt).run()
    checkpoint = b.head
    resumed = Board.resume(b.store, "search-1", checkpoint, coordinator="host")
    state = Coordinator(resumed, lambda task: {"status": "ok", "cost_usd": 0, "intents": []}).run()
    assert state["checkpoint"]["spent_usd"] == SearchBudget().max_call_usd
    assert state["checkpoint"]["tasks"] == 3


def test_invalid_fact_fails_closed_and_records_failure(tmp_path):
    def execute(task):
        if task.step == "reason":
            return {"status": "ok", "cost_usd": 0, "intents": [{"description": "x", "from_facts": []}]}
        return {"status": "ok", "cost_usd": 0, "fact": {"text": "unbacked"}}

    state = Coordinator(board(tmp_path), execute, budget=SearchBudget(reason_rounds=1)).run()
    assert not state["facts"]
    assert state["intents"][0]["status"] == "concluded"
    assert state["intents"][0]["failure"] == "invalid_result"


def test_cleanup_failure_halts_and_charges_unknown_spend(tmp_path):
    b = board(tmp_path)
    calls = []

    def broken(task):
        calls.append(task)
        raise RuntimeError("AX cleanup failed; stop dispatching")

    with pytest.raises(RuntimeError, match="cleanup"):
        Coordinator(b, broken).run()
    assert len(calls) == 1
    assert b.state["checkpoint"]["spent_usd"] == SearchBudget().max_call_usd
    assert b.state["checkpoint"]["pending"]["id"] == calls[0].id


def test_overclaimed_cost_stops_before_another_dispatch(tmp_path):
    calls = []

    def overrun(task):
        calls.append(task)
        return {"status": "ok", "cost_usd": 99, "intents": []}

    result = Coordinator(board(tmp_path), overrun).run()
    assert result["end_reason"] == "budget_spent"
    assert len(calls) == 1


def test_claim_is_visible_in_worker_snapshot(tmp_path):
    import yaml

    def execute(task):
        if task.step == "reason":
            return {"status": "ok", "cost_usd": 0, "intents": [{"description": "read", "from_facts": []}]}
        intent = yaml.safe_load(task.snapshot)["intents"][0]
        assert intent["status"] == "claimed" and intent["claimant"] == task.id
        return {"status": "execution_failure", "cost_usd": 0}

    Coordinator(board(tmp_path), execute, budget=SearchBudget(reason_rounds=1)).run()


def test_batch_adapter_offline_checkpoint_and_step_dispatch(tmp_path, monkeypatch):
    from dataclasses import asdict
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    from openultrasast.search.coordinator import BatchExecutor, SearchTask

    calls = []

    def lane(item, output, attempt):
        import json

        spec = json.loads(item.inputs["SPEC_URL"])
        calls.append(spec)
        assert item.extra_env["SEARCH_STEP"] == spec["step"]
        return {"status": "ok", "cost_usd": 0, "intents": []}

    adapter = BatchExecutor(
        image="registry/task@sha256:" + "a" * 64, command=("python3", "/worker.py"), output=tmp_path, lanes={"ax": lane}
    )
    for index, step in enumerate(("reason", "explore", "verify")):
        task = SearchTask(f"task-{index}", "search-1", step, "facts: []", {}, asdict(SearchBudget()))
        assert adapter(task)["status"] == "ok"
        assert adapter(task)["status"] == "ok"
    assert len(calls) == 3


def test_invalid_identifiers_refused_before_paths(tmp_path):
    from dataclasses import asdict

    from openultrasast.search.coordinator import SearchTask

    for bad in ("../escape", "/tmp/escape", "bad\nNAME", ""):
        with pytest.raises(ValueError):
            Board(FileStore(tmp_path), bad, coordinator="host")
        with pytest.raises(ValueError):
            SearchTask(bad, "search-1", "reason", "", {}, asdict(SearchBudget()))
