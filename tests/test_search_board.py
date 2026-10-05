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
