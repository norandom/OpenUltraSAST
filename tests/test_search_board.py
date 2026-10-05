import json

import pytest

from openultrasast.plane.memory import FileStore
from openultrasast.search.board import Board


def test_versions_provenance_claims_and_resume(tmp_path):
    store = FileStore(tmp_path)
    board = Board(store, "search-1", coordinator="host")
    first = board.commit(
        writer="host", facts=[dict(id="f1", text="sink", evidence_refs=["engine:1"], from_intents=[], step="triage", task_id="seed")]
    )
    second = board.commit(
        writer="host",
        intents=[dict(id="i1", description="trace input", from_facts=["f1"], status="open", claimant=None, step="reason", task_id="r1")],
    )
    assert first != second
    assert json.loads(store.get_blob(board.prefix, first))["intents"] == []
    assert Board.resume(store, "search-1", second, coordinator="host").state == board.state
    with pytest.raises(PermissionError):
        board.commit(writer="worker", hints=[])
    state = board.state
    state["facts"].clear()
    assert board.state["facts"]
    assert len(board.snapshot(max_bytes=256).encode()) <= 256
    with pytest.raises(ValueError):
        board.commit(writer="host", end_reason="clean")


def test_bad_references_and_oversize_are_atomic(tmp_path):
    board = Board(FileStore(tmp_path), "one", coordinator="host", max_bytes=1024)
    before = board.head
    with pytest.raises(ValueError):
        board.commit(writer="host", facts=[dict(id="f", text="x", evidence_refs=[], from_intents=["missing"], step="explore", task_id="t")])
    with pytest.raises(ValueError):
        board.commit(writer="host", hints=[dict(id="h", text="x" * 2048, step="human", task_id="operator")])
    assert board.head == before


def test_snapshot_caps_fact_text_and_preserves_context(tmp_path):
    import yaml

    board = Board(FileStore(tmp_path), "context", coordinator="host")
    facts = [
        dict(id=f"f{i}", text="observation " * 500, evidence_refs=["tool:1"], from_intents=[], step="explore", task_id=f"t{i}")
        for i in range(10)
    ]
    intents = [
        dict(id=f"i{i}", description="inspect", from_facts=[], status=status, claimant=None, step="reason", task_id="r")
        for i, status in enumerate(("open", "concluded"))
    ]
    board.commit(
        writer="host",
        facts=facts,
        intents=intents,
        hints=[
            dict(
                id="candidate",
                step="reason",
                task_id="manifest",
                text=json.dumps(dict(family="injection", oracle="sql", file="app.py", function="main")),
            )
        ],
    )
    view = yaml.safe_load(board.snapshot(budget_left={"tasks": 3}))
    assert view["candidate"]["file"] == "app.py" and view["family"] == "injection"
    assert view["budget_left"]["tasks"] == 3
    assert {i["status"] for i in view["intents"]} == {"open", "concluded"}
    assert all(len(f["text"]) <= 2000 for f in view["facts"])
    assert sum(len(f["text"]) for f in view["facts"]) <= 12000
    assert view["facts"][-1]["text"].startswith("observation")
    assert view["facts"][-1]["text_truncated"]
    assert board.state["facts"] == facts
