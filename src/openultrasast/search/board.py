"""Coordinator-owned, content-addressed search checkpoints in the plane memory store.

Workers receive snapshots and return proposals; they never receive this writer or
store credentials. Persist the returned head in the host's run checkpoint.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
from typing import Any

import yaml

from ..plane.memory import MemoryStore


class Board:
    def __init__(self, store: MemoryStore, search_id: str, *, coordinator: str, max_bytes: int = 262144) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", search_id) or not coordinator or max_bytes < 256:
            raise ValueError("invalid board configuration")
        self.store, self.coordinator, self.max_bytes = store, coordinator, max_bytes
        self.prefix = "boards/" + hashlib.sha256(search_id.encode()).hexdigest()
        self._lock = threading.RLock()
        self.head: str | None = None
        self._state: dict[str, Any] = dict(
            search_id=search_id, version=0, previous=None, facts=[], intents=[], hints=[], end_reason=None, checkpoint={}
        )

    @property
    def state(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._state)

    @classmethod
    def resume(cls, store: MemoryStore, search_id: str, head: str, *, coordinator: str, max_bytes: int = 262144) -> Board:
        board = cls(store, search_id, coordinator=coordinator, max_bytes=max_bytes)
        data = store.get_blob(board.prefix, head)
        if data is None or len(data) > max_bytes:
            raise ValueError("missing or oversized board checkpoint")
        state = json.loads(data)
        if state["search_id"] != search_id:
            raise ValueError("checkpoint belongs to another search")
        board._validate(state)
        board._state, board.head = state, head
        return board

    def commit(self, *, writer: str, **changes: Any) -> str:
        with self._lock:
            if writer != self.coordinator:
                raise PermissionError("only the coordinator may write the board")
            if self._state["end_reason"] is not None:
                raise ValueError("search already ended")
            if changes.keys() - {"facts", "intents", "hints", "end_reason", "checkpoint"}:
                raise ValueError("unknown board fields")
            state = {**self.state, **copy.deepcopy(changes), "version": self._state["version"] + 1, "previous": self.head}
            self._validate(state)
            data = json.dumps(state, sort_keys=True, allow_nan=False).encode()
            if len(data) > self.max_bytes:
                raise ValueError("board size cap exceeded")
            head = self.store.put_blob(self.prefix, data)
            self._state, self.head = state, head
            return head

    @staticmethod
    def _validate(state: dict[str, Any]) -> None:
        if state["end_reason"] not in (None, "goal_met", "budget_spent", "exhausted"):
            raise ValueError("invalid end reason")
        ids: dict[str, set[str]] = {}
        for kind in ("facts", "intents", "hints"):
            ids[kind] = set()
            for row in state[kind]:
                required = ("id", "step", "task_id", "description" if kind == "intents" else "text")
                if any(not isinstance(row.get(key), str) or not row[key] for key in required):
                    raise ValueError("entry requires text and writer provenance")
                if row["id"] in ids[kind]:
                    raise ValueError("duplicate board id")
                ids[kind].add(row["id"])
        for fact in state["facts"]:
            if not isinstance(fact.get("evidence_refs"), list) or not fact["evidence_refs"]:
                raise ValueError("facts require evidence references")
            if any(not isinstance(ref, str) or not ref for ref in fact["evidence_refs"]):
                raise ValueError("invalid evidence reference")
            if not isinstance(fact.get("from_intents"), list) or set(fact["from_intents"]) - ids["intents"]:
                raise ValueError("unknown source intent")
        for intent in state["intents"]:
            if not isinstance(intent.get("from_facts"), list) or set(intent["from_facts"]) - ids["facts"]:
                raise ValueError("unknown source fact")
            if intent.get("status") not in ("open", "claimed", "concluded"):
                raise ValueError("invalid intent status")
            if intent["status"] == "claimed" and not intent.get("claimant"):
                raise ValueError("claimed intent requires claimant")
            if intent["status"] == "open" and intent.get("claimant") is not None:
                raise ValueError("open intent cannot have claimant")

    def snapshot(self, *, max_bytes: int = 32768) -> str:
        """Valid YAML even when truncated; explicit omission counts, never a cut string."""
        if max_bytes < 128:
            raise ValueError("snapshot cap must be at least 128 bytes")
        state = self.state
        view = {key: state[key] for key in ("version", "end_reason", "facts", "intents", "hints")}
        view["omitted"] = dict.fromkeys(("facts", "intents", "hints"), 0)
        while True:
            text = str(yaml.safe_dump(view, sort_keys=False, allow_unicode=True))
            if len(text.encode()) <= max_bytes:
                return text
            kind = next((k for k in ("facts", "intents", "hints") if view[k]), None)
            if kind is None:
                raise ValueError("snapshot cap too small")
            view[kind].pop(0)
            view["omitted"][kind] += 1
