from __future__ import annotations

import hashlib
import importlib.util
import subprocess
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("push_measure", Path("benchmarks/push/measure.py"))
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


def test_authored_snapshot_keeps_whole_tree_and_original_repository(tmp_path):
    from test_push_runner import history

    root, base, head, git = history(tmp_path)
    (root / "unchanged.txt").write_text("first-party context remains in the whole tree")
    git("add", "unchanged.txt")
    git("commit", "-m", "unchanged context")
    head = git("rev-parse", "HEAD")
    # The helper consumes objects, never the deliberately dirty live source.
    before = git("show", head + ":api.js") + "\n"
    after = before.replace("req.body.value", '"fixed"')
    entry = {
        "id": "authored",
        "files": [
            {
                "path": "api.js",
                "size": len(after.encode()),
                "sha256": hashlib.sha256(after.encode()).hexdigest(),
                "original_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "edit": {"before": "req.body.value", "after": '"fixed"', "provenance": "authored repair"},
            }
        ],
    }
    bare = tmp_path / "objects.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
    (bare / "objects/info/alternates").write_text(str(root / ".git/objects") + "\n")
    original = (root / ".git/index").read_bytes(), (root / "api.js").read_bytes()
    oid = measure.pin_snapshot(bare, head, entry)
    result = subprocess.run(["git", "-C", str(bare), "show", oid + ":api.js"], check=True, capture_output=True)
    assert result.stdout.decode() == after
    retained = subprocess.run(["git", "-C", str(bare), "show", oid + ":unchanged.txt"], check=True, capture_output=True)
    assert retained.stdout == b"first-party context remains in the whole tree"

    assert original == ((root / ".git/index").read_bytes(), (root / "api.js").read_bytes())
    assert oid == measure.pin_snapshot(bare, head, entry), "authored object identities must be reproducible"
    entry["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash|identity"):
        measure.pin_snapshot(bare, head, entry)


def payload():
    return {
        "result": {"coverage_status": "incomplete"},
        "admission": {"coverage_reasons": ["deadline_exhausted"], "dispositions": [], "defects": []},
        "scans": [],
        "timings": {"total_seconds": 30},
    }


def test_timeout_stays_unresolved_and_uses_whole_cli_elapsed_time():
    record = measure.execution_record("case", payload(), elapsed=30.8)
    assert record["coverage"] == "timeout" and record["delta"] == "unknown"
    assert record["rank"] is None and record["queries"] == [] and record["alerts"] == []
    assert record["timings"]["total"] == 30.8 and record["cache_state"] == "cold"


def test_zero_cli_exit_cannot_earn_negative_without_witness():
    data = payload()
    data["result"]["coverage_status"] = "complete_within_scope"
    data["admission"]["coverage_reasons"] = []
    identity = {"unit": "repository", "language": "php", "path": "api.php", "function": "handler", "family": "injection"}
    data["scans"] = [
        {
            "side": "head",
            "scan": {
                "scope": {"ranking_mode": "evidence", "selected": [{"identity": identity}], "deferred": []},
                "question_outcomes": [{"identity": identity, "status": "completed", "raw_rows_json": "[]"}],
                "findings": [],
                "build_seconds": 1,
                "query_seconds": 2,
            },
        }
    ]
    record = measure.execution_record("case", data, elapsed=4)
    assert record["queries"][0]["outcome"] == "unknown"
    assert "witness" not in record["queries"][0]
    assert record["alerts"] == []
