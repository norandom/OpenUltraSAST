"""Append-only slice usage; a hash chain detects rewritten rows, not a rebuilt entire history.

Keep the published final digest to authenticate a history against truncation or wholesale replacement.
Only opaque decision/experiment labels belong here; repository identities are never accepted.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import re
from datetime import date
from pathlib import Path

FIELDS = {"slice", "decision", "purpose", "date", "result_digest", "freeze_digest"}
PURPOSES = {"baseline", "exploratory", "informed", "qualifies"}
ZERO = "0" * 64


def digest(row: dict) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate(row: dict) -> None:
    if set(row) != FIELDS or row["purpose"] not in PURPOSES:
        raise ValueError("invalid_usage_fields")
    if type(row["slice"]) is not int or row["slice"] < 1:
        raise ValueError("invalid_slice")
    if not isinstance(row["decision"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", row["decision"]):
        raise ValueError("invalid_decision_label")
    for key in ("result_digest", "freeze_digest"):
        if not isinstance(row[key], str) or not re.fullmatch(r"[0-9a-f]{64}", row[key]):
            raise ValueError("invalid_digest")
    try:
        if date.fromisoformat(row["date"]).isoformat() != row["date"]:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("invalid_date") from None


def _read(text: str) -> list[dict]:
    previous = ZERO
    rows = []
    if text and not text.endswith("\n"):
        raise ValueError("broken_digest_chain")
    for line in text.splitlines():
        try:
            row = json.loads(line)
            stored = row.pop("digest")
            if row["previous"] != previous or digest(row) != stored:
                raise ValueError
            validate({k: v for k, v in row.items() if k != "previous"})
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError("broken_digest_chain") from None
        rows.append({**row, "digest": stored})
        previous = stored
    return rows


def read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as handle:
        fcntl.flock(handle, fcntl.LOCK_SH)
        return _read(handle.read())


def append(path: Path, row: dict) -> str:
    validate(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        rows = _read(handle.read())
        if any(all(old[key] == row[key] for key in FIELDS) for old in rows):
            raise ValueError("duplicate_usage")
        if rows and rows[0]["freeze_digest"] != row["freeze_digest"]:
            raise ValueError("freeze_digest_changed")
        if row["purpose"] == "qualifies" and any(
            old["slice"] == row["slice"] and old["decision"] == row["decision"] and old["purpose"] == "informed" for old in rows
        ):
            raise ValueError("slice_informed_decision")
        entry = {**row, "previous": rows[-1]["digest"] if rows else ZERO}
        sha = digest(entry)
        handle.write(json.dumps({**entry, "digest": sha}, sort_keys=True) + "\n")
        handle.flush()
        return sha
