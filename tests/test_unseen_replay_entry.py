"""Replay entry uses real local git and an injected transfer, never a network."""

import importlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
e = importlib.import_module("benchmarks.unseen.replay_entry")


@pytest.fixture
def local_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Fixture")
    (repo / "app.py").write_text("print(1)\n")
    git("add", "app.py")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (repo / "app.py").write_text("print(2)\n")
    git("commit", "-qam", "head")
    return repo, base, git("rev-parse", "HEAD")


@pytest.mark.parametrize("failure", [None, "missing", "fetch", "crash", "fast", "unread", "unsupported"])
def test_entry(local_repo, tmp_path, monkeypatch, failure):
    repo, base, head = local_repo
    spec = {
        "repository_url": "https://public.example/project.git",
        "base": base,
        "head": head,
        "id": "opaque",
        "image": "digest",
        "hook_flags": [],
    }
    if failure == "missing":
        spec["head"] = "a" * 40
    received = {}

    def transfer(request, destination=None, **kwargs):
        assert kwargs["readiness_budget"] == 60
        if destination:
            destination.write_text(json.dumps(spec))
        else:
            with tarfile.open(fileobj=io.BytesIO(request.data)) as archive:
                received.update({m.name: archive.extractfile(m).read() for m in archive.getmembers()})

    monkeypatch.setenv("SPEC_URL", "https://files.example/spec.dat?secret")
    monkeypatch.setenv("RESULT_URL", "https://files.example/result.dat?secret")
    monkeypatch.setattr(e, "transfer", transfer)
    real_run = subprocess.run

    def run(command, **kwargs):
        if command[0] == "ousast":
            assert command[command.index("--base") + 1] == base
            assert kwargs["env"]["OPENULTRASAST_CPG_HEAP_MB"] == "1700"
            if failure == "crash":
                return subprocess.CompletedProcess(command, 2, "", "crash https://secret")
            target = Path(command[command.index("--artifact") + 1])
            target.write_text(
                json.dumps(
                    {
                        "quick_tier": [{"files": ["app.py"], "bytes_read": 0 if failure == "unread" else 9, "findings": []}],
                        "scans": [
                            {
                                "side": "head",
                                "scan": {"build_seconds": 0.1 if failure == "fast" else 8, "query_seconds": 2, "question_outcomes": []},
                            }
                        ],
                    }
                )
            )
            if failure == "unsupported":
                target.write_text(
                    json.dumps(
                        {
                            "quick_tier": [{"files": [], "bytes_read": 0, "findings": []}],
                            "admission": {"coverage_reasons": ["language_not_covered:rust:1:1"]},
                            "scans": [
                                {
                                    "side": "head",
                                    "scan": {
                                        "build_seconds": 0.01,
                                        "query_seconds": 0,
                                        "partitions": [
                                            {
                                                "language": "rust",
                                                "frontend": None,
                                                "paths": ["app.rs"],
                                                "source_bytes": 0,
                                                "status": "unsupported",
                                            }
                                        ],
                                    },
                                }
                            ],
                        }
                    )
                )
            return subprocess.CompletedProcess(command, 0, "Skipped: deadline\n", "")
        command = [
            str(repo) if arg == spec["repository_url"] else "protocol.file.allow=always" if arg == "protocol.file.allow=never" else arg
            for arg in command
        ]
        if failure == "fetch" and "fetch" in command:
            return subprocess.CompletedProcess(command, 1, "", "fetch secret")
        return real_run(command, **kwargs)

    result = e.main(work_root=tmp_path / "work", runner=run)
    instrument = json.loads(received["instrument.json"])
    assert instrument["image"] == "digest"
    assert b"secret" not in received["instrument.json"]
    if failure == "unsupported":
        from benchmarks.unseen.score import coverage

        assert result == 0 and not instrument["suspect_fast"]
        assert coverage({"instrument": instrument, "push": json.loads(received["push.json"])}) == "unanalysable"
    elif failure:
        assert result == 1 and instrument["status"] == "instrument_failure"
    else:
        assert result == 0 and instrument["changed_bytes"] == {"app.py": 9}
        assert instrument["head_verified"] and instrument["base_verified"]
        assert instrument["jvm_wall_seconds"] == 10
        assert b"Skipped:" in received["push.txt"]
