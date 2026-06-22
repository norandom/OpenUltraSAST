"""Improvement journal: per-round audit + novelty memory (task 7.3, 7.9).

Persistent JSON record of every self-improvement round so each rule/policy edit is
attributable and reversible, and so a previously-reverted edit is not re-proposed
without a new rationale (the novelty gate).
"""

from __future__ import annotations

import json
from pathlib import Path


def load_journal(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text())
    return payload if isinstance(payload, list) else []


def write_journal(path: Path, rounds: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rounds, indent=2, sort_keys=True) + "\n")


def reverted_edit_keys(rounds: list[dict[str, object]]) -> set[str]:
    """Edit keys from reverted rounds — blocked from re-proposal unless a new rationale appears."""
    keys: set[str] = set()
    for entry in rounds:
        if entry.get("outcome") != "reverted":
            continue
        for edit in _edits(entry):
            key = edit.get("key")
            if isinstance(key, str) and not edit.get("rationale"):
                keys.add(key)
    return keys


def next_round_index(rounds: list[dict[str, object]]) -> int:
    return len(rounds) + 1


def append_round(path: Path, entry: dict[str, object]) -> None:
    rounds = load_journal(path)
    rounds.append(entry)
    write_journal(path, rounds)


def _edits(entry: dict[str, object]) -> list[dict[str, object]]:
    edits = entry.get("edits")
    return [edit for edit in edits if isinstance(edit, dict)] if isinstance(edits, list) else []
