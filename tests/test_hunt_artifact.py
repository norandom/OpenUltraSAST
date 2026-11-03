"""Checks for stable run records and budget accounting."""

import errno
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from openultrasast.hunt import artifact as artifact_module
from openultrasast.hunt.artifact import MAX_ATTEMPT_ORDINAL, RunArtifact, UsageLedger


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


def test_artifact_persistence_is_create_only_and_idempotent(tmp_path):
    run = artifact()
    path = run.write(tmp_path)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    assert run.write(tmp_path) == path
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before

    path.write_text("conflicting bytes\n")
    with pytest.raises(ValueError, match="conflict"):
        run.write(tmp_path)


def test_missing_attempt_sequence_fails_closed_when_artifacts_exist(tmp_path):
    first = artifact()
    first_path = first.write(tmp_path, reserve_attempt=True)
    before = (first_path.read_bytes(), first_path.stat().st_mtime_ns)
    (tmp_path / ".attempt-sequence").unlink()
    resumed = artifact()
    resumed.created = "2026-11-02T00:00:01+00:00"

    with pytest.raises(ValueError, match="attempt sequence is missing"):
        resumed.write(tmp_path, reserve_attempt=True)
    assert (first_path.read_bytes(), first_path.stat().st_mtime_ns) == before
    assert not (tmp_path / ".attempt-sequence").exists()


def test_attempt_ordinals_are_unique_under_concurrency_and_resume(tmp_path):
    def persist(index):
        run = artifact()
        run.created = f"2026-11-02T00:00:{index:02d}+00:00"
        run.write(tmp_path, reserve_attempt=True)
        return run.attempt_ordinal

    with ThreadPoolExecutor(max_workers=4) as pool:
        ordinals = list(pool.map(persist, range(4)))
    resumed = artifact()
    resumed.created = "2026-11-02T00:01:00+00:00"
    resumed.write(tmp_path, reserve_attempt=True)

    assert sorted(ordinals) == [1, 2, 3, 4]
    assert resumed.attempt_ordinal == 5
    assert (tmp_path / ".attempt-sequence").read_text() == "5\n"


@pytest.mark.parametrize(("state", "message"), (("corrupt\n", "unreadable"), ("-1\n", "invalid")))
def test_corrupt_attempt_sequence_fails_closed(tmp_path, state, message):
    (tmp_path / ".attempt-sequence").write_text(state)

    with pytest.raises(ValueError, match=message):
        artifact().write(tmp_path, reserve_attempt=True)


def test_attempt_sequence_allocates_the_signed_64_bit_maximum(tmp_path):
    (tmp_path / ".attempt-sequence").write_text(f"{MAX_ATTEMPT_ORDINAL - 1}\n")
    run = artifact()

    run.write(tmp_path, reserve_attempt=True)

    assert run.attempt_ordinal == MAX_ATTEMPT_ORDINAL
    assert (tmp_path / ".attempt-sequence").read_text() == f"{MAX_ATTEMPT_ORDINAL}\n"


def test_attempt_sequence_refuses_overflow_without_mutation(tmp_path):
    sequence = tmp_path / ".attempt-sequence"
    sequence.write_text(f"{MAX_ATTEMPT_ORDINAL}\n")
    before = (sequence.read_bytes(), sequence.stat().st_mtime_ns)

    with pytest.raises(ValueError, match="exhausted"):
        artifact().write(tmp_path, reserve_attempt=True)

    assert (sequence.read_bytes(), sequence.stat().st_mtime_ns) == before
    assert not list(tmp_path.glob("*.json"))


def test_attempt_sequence_and_artifact_creation_fsync_the_directory(tmp_path, monkeypatch):
    real_fsync = os.fsync
    directory_syncs = []

    def recording_fsync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(artifact_module.os, "fsync", recording_fsync)
    artifact().write(tmp_path, reserve_attempt=True)

    assert len(directory_syncs) == 2


def test_directory_fsync_ignores_only_unsupported_platform_errors(tmp_path, monkeypatch):
    def unsupported(_descriptor):
        raise OSError(errno.EOPNOTSUPP, "unsupported")

    monkeypatch.setattr(artifact_module.os, "fsync", unsupported)
    artifact_module._sync_directory(tmp_path)

    def io_failure(_descriptor):
        raise OSError(errno.EIO, "I/O failure")

    monkeypatch.setattr(artifact_module.os, "fsync", io_failure)
    with pytest.raises(OSError, match="I/O failure"):
        artifact_module._sync_directory(tmp_path)


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
