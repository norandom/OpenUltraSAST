"""Offline replay, resume, scoring and instrument refusal for the prover arm."""

import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_hunt_prover import repository  # noqa: E402

from benchmarks.unseen import score  # noqa: E402
from benchmarks.valid import prover_arm  # noqa: E402


@pytest.fixture
def pool(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    root = tmp_path / "repo"
    root.mkdir()
    text = """class X extends Descriptor<Thing> {
 public Object doTestConnection() {
  return lookupCredentials();
 }
}"""
    root, positive = repository(root, text)
    positive.update(
        id="positive",
        kind="vulnerability",
        family="access_control",
        path="Fixture.java",
        function="doTestConnection",
        function_lines=[2, 4],
        targets=[{"path": "Fixture.java", "function": "doTestConnection", "function_lines": [2, 4], "family": "access_control"}],
    )
    (root / "Fixture.java").write_text(text.replace("  return", "  Jenkins.get().checkPermission(Jenkins.ADMINISTER);\n  return"))
    subprocess.run(["git", "-C", str(root), "add", "Fixture.java"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", "commit", "-qm", "safe"], check=True)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    ordinary = {
        **positive,
        "id": "ordinary",
        "kind": "ordinary",
        "base": positive["head"],
        "head": head,
        "targets": [],
        "files": [{"path": "Fixture.java", "head_lines": [[3, 3]]}],
    }
    changes = [positive, ordinary]
    manifest = tmp_path / "frozen.json"
    manifest.write_text(
        json.dumps({"changes": changes, "sha256": hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()})
    )
    repos = tmp_path / "repos.json"
    repos.write_text(json.dumps({"fixture/app": str(root)}))
    return root, manifest, repos, tmp_path / "out"


def test_run_resume_summary_and_locations(pool, monkeypatch, capsys):
    root, manifest, repos, out = pool
    assert prover_arm.main(["run", str(manifest), "--repos", str(repos), "--out", str(out)]) == 0
    rows = score.load_records(out)
    assert len(rows) == 2 and all(r["done"] and r["seconds"] > 0 for r in rows)
    assert score.catches(rows[0]) == ["alerts"] and not score.false_alarm(rows[1])
    summary = json.loads((out / "summary.json").read_text())
    assert summary["recall"]["count"] == summary["recall"]["n"] == 1
    assert summary["location_recall"]["count"] == summary["location_recall"]["n"] == 1
    assert summary["false_alarms_per_100_pushes"]["rate"] == 0
    assert summary["precision"]["rate"] == 1
    assert summary["instrument_failures"] == 0
    assert "fixture/app" in summary["per_repository"] and "stapler" in summary["per_framework"]
    assert summary["changes_over_120_seconds"] == [] and summary["uncovered_repositories"] == []
    assert summary["seconds_per_change"]["n"] == 2
    assert "bytes read" in capsys.readouterr().out
    old = {p.name: p.read_bytes() for p in out.glob("*.json") if p.name not in {"inputs.json", "summary.json"}}

    def forbidden(*args, **kwargs):
        pytest.fail("completed change re-run")

    monkeypatch.setattr(prover_arm, "prove_change", forbidden)
    assert prover_arm.run(manifest, repos, out) == 0
    assert old == {p.name: p.read_bytes() for p in out.glob("*.json") if p.name not in {"inputs.json", "summary.json"}}
    assert (
        len(
            subprocess.run(
                ["git", "-C", str(root), "worktree", "list", "--porcelain"], check=True, capture_output=True, text=True
            ).stdout.split("worktree ")
        )
        == 2
    )


def test_zero_byte_record_refuses(pool):
    _, manifest, repos, out = pool
    assert prover_arm.run(manifest, repos, out) == 0
    path = out / (hashlib.sha256(b"positive").hexdigest() + ".json")
    record = json.loads(path.read_text())
    record["instrument"]["changed_bytes"]["Fixture.java"] = 0
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="zero-byte"):
        prover_arm.summarize(out)


def test_checkout_error_is_type_only(pool):
    _, manifest, repos, out = pool
    repos.write_text("{}")
    assert prover_arm.run(manifest, repos, out) == 2
    rows = score.load_records(out)
    assert all(row["status"] == "instrument_failure" and row["instrument"]["failure"] == "KeyError" for row in rows)


def test_resume_rejects_new_depth(pool):
    _, manifest, repos, out = pool
    assert prover_arm.run(manifest, repos, out) == 0
    with pytest.raises(ValueError, match="inputs"):
        prover_arm.run(manifest, repos, out, max_depth=2)


def test_unchanged_file_empty_read_refuses(pool, monkeypatch):
    _, manifest, repos, out = pool
    real = prover_arm.Context.read

    def empty(ctx, path):
        if path == "Fixture.java":
            return ""
        return real(ctx, path)

    monkeypatch.setattr(prover_arm.Context, "read", empty)
    assert prover_arm.run(manifest, repos, out) == 2
    with pytest.raises(ValueError, match="zero-byte"):
        prover_arm.summarize(out)
