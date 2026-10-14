"""Checks for stable run records and budget accounting."""

import json

import pytest

from openultrasast.hunt.artifact import RunArtifact, UsageLedger


def artifact():
    return RunArtifact(
        program_id="program",
        schema_version=1,
        mask=("source",),
        data_digests={"train": "abc"},
        configurations=[{"seed": 0}],
        usage={"usd": 0.1, "calls": 1, "replay_hits": 0, "wall_seconds": 2},
        versions={"dspy": "3.4.0", "litellm": "1", "openultrasast": "2.0.1"},
        created="2026-10-13T00:00:00Z",
    )


def test_artifact_round_trip_and_tamper(tmp_path):
    run = artifact()
    assert run.artifact_id == artifact().artifact_id
    path = run.write(tmp_path)
    assert RunArtifact.read(path) == run
    payload = json.loads(path.read_text())
    payload["program_id"] = "tampered"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="id"):
        RunArtifact.read(path)


def test_ledger_and_budget_prevent_artifact(tmp_path):
    run = artifact()
    ledger = UsageLedger(artifact=run)
    ledger.add({"usd": 0.25, "calls": 1, "wall_seconds": 2})
    ledger.add({"usd": 0, "replay_hits": 1, "wall_seconds": 1})
    assert ledger.usage == {"usd": 0.25, "calls": 1, "replay_hits": 1, "wall_seconds": 3}
    assert ledger.exhausted({"usd": 0.25, "calls": 10})
    assert ledger.exhausted({"usd": 10, "calls": 1})
    assert ledger.finish({"usd": 0.25}) is None
    assert not list(tmp_path.iterdir())
    result = ledger.finish({"usd": 1, "calls": 2})
    assert result is run
    assert result.usage == ledger.usage
    assert run.finish({"usd": 0.25}) is None
    assert run.write(tmp_path, budget={"usd": 0.25}) is None
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
def test_invalid_usage_rejected(value):
    with pytest.raises(ValueError):
        UsageLedger().add({"usd": value})
