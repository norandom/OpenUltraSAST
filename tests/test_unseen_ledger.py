"""Append-only use and tamper detection, with opaque fixture identifiers."""

import json
from pathlib import Path

import pytest

with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/unseen"))
    import ledger


def row(**extra):
    return {
        "slice": 1,
        "decision": "decision-001",
        "purpose": "baseline",
        "date": "2026-10-04",
        "result_digest": "a" * 64,
        "freeze_digest": "b" * 64,
        **extra,
    }


def test_append_and_refuse_rewrite(tmp_path):
    path = tmp_path / "usage-p1.jsonl"
    ledger.append(path, row())
    original = path.read_bytes()
    ledger.append(path, row(purpose="exploratory"))
    assert path.read_bytes().startswith(original)
    assert len(ledger.read(path)) == 2
    with pytest.raises(ValueError, match="duplicate"):
        ledger.append(path, row())


def test_informed_slice_cannot_qualify_same_decision(tmp_path):
    path = tmp_path / "usage-p1.jsonl"
    ledger.append(path, row(purpose="informed"))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="informed"):
        ledger.append(path, row(purpose="qualifies"))
    assert path.read_bytes() == before
    ledger.append(path, row(purpose="qualifies", slice=2))
    ledger.append(path, row(purpose="qualifies", decision="decision-002"))


def test_rewritten_row_breaks_digest_chain(tmp_path):
    path = tmp_path / "usage-p1.jsonl"
    ledger.append(path, row())
    ledger.append(path, row(purpose="exploratory"))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["purpose"] = "informed"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(ValueError, match="chain"):
        ledger.read(path)
    with pytest.raises(ValueError, match="chain"):
        ledger.append(path, row(slice=2))


@pytest.mark.parametrize("extra", [{"decision": "owner/name"}, {"purpose": "other"}, {"freeze_digest": "bad"}, {"slice": 0}])
def test_invalid_rows_refused(tmp_path, extra):
    with pytest.raises(ValueError):
        ledger.append(tmp_path / "usage-p1.jsonl", row(**extra))
