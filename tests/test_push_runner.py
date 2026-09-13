from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from openultrasast.config import PushConfig
from openultrasast.cpg.backend import NullBackend
from openultrasast.push.runner import replay


def history(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout.strip().decode()

    git("init")
    git("config", "user.name", "Replay test")
    git("config", "user.email", "replay@example.invalid")
    git("config", "core.hooksPath", os.devnull)
    source = root / "api.js"
    source.write_text('function handler(req, res) {\n const value = "fixed";\n eval(value);\n}\napp.post("/run", handler);\n')
    git("add", "api.js")
    git("commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    source.write_text(source.read_text().replace('"fixed"', "req.body.value"))
    git("add", "api.js")
    git("commit", "-m", "head")
    head = git("rev-parse", "HEAD")
    source.write_text("dirty source must never be scanned")
    return root, base, head, git


def test_replay_unavailable_preserves_input_and_records_scope(tmp_path):
    root, base, head, git = history(tmp_path)
    before = (root / ".git/index").read_bytes(), git("status", "--porcelain")
    artifact = tmp_path / "result.json"
    delivery = replay(root, base=base, head=head, artifact=artifact, backend=NullBackend())
    data = json.loads(artifact.read_text())
    assert delivery.exit_code == 0
    assert delivery.result.coverage_status in ("unavailable", "incomplete")
    assert data["result"]["analyses"][0]["comparison"]["base_oid"] == base
    assert data["result"]["analyses"][0]["comparison"]["head_oid"] == head
    assert data["scans"][0]["scan"]["scope"]["ranking_mode"] == "evidence"
    assert data["provenance"]["model"] == "disabled"
    assert data["snapshots"][0]["bytes_read"] > 0
    assert (root / "api.js").read_text() == "dirty source must never be scanned"
    assert ((root / ".git/index").read_bytes(), git("status", "--porcelain")) == before


def test_missing_revision_is_unavailable_not_clean(tmp_path):
    root, base, head, _ = history(tmp_path)
    result = replay(root, base="missing-ref", head=head, artifact=tmp_path / "missing.json")
    assert result.result.coverage_status == "unavailable"
    assert result.exit_code == 0
    assert "Notice:" in result.text


def test_expired_preparation_obeys_total_deadline(tmp_path):
    root, base, head, _ = history(tmp_path)
    start = time.monotonic()
    result = replay(
        root,
        base=base,
        head=head,
        artifact=tmp_path / "expired.json",
        config=PushConfig(deadline_seconds=0.001, cancellation_allowance_seconds=0.5),
    )
    assert time.monotonic() - start < 0.55
    assert result.result.coverage_status != "complete_within_scope"


def test_strict_incomplete_policy_and_artifact_failure(tmp_path):
    root, base, head, _ = history(tmp_path)
    result = replay(
        root,
        base=base,
        head=head,
        artifact=tmp_path,
        config=PushConfig(mode="blocking", incomplete_coverage_policy="block"),
        backend=NullBackend(),
    )
    assert result.exit_code == 1 and result.error and result.artifact is None


def test_hanging_discovery_is_bounded(tmp_path, monkeypatch):
    from openultrasast.push import runner

    root, base, head, _ = history(tmp_path)
    monkeypatch.setattr(runner, "_discover", lambda *args: time.sleep(5))
    start = time.monotonic()
    result = replay(
        root,
        base=base,
        head=head,
        artifact=tmp_path / "hung.json",
        config=PushConfig(deadline_seconds=0.3, cancellation_allowance_seconds=0.5),
    )
    assert time.monotonic() - start < 0.85
    assert result.result.coverage_status == "unavailable"
    assert "deadline" in (tmp_path / "hung.json").read_text()


def test_cli_exposes_replay(tmp_path, capsys):
    from openultrasast.cli import main

    root, base, head, _ = history(tmp_path)
    assert (
        main(["pre-push", str(root), "--base", base, "--head", head, "--artifact", str(tmp_path / "cli.json"), "--deadline", "0.001"]) == 0
    )
    assert "Notice:" in capsys.readouterr().out


def test_replay_artifact_cannot_overwrite_live_repository(tmp_path):
    root, base, head, _ = history(tmp_path)
    source = root / "api.js"
    before = source.read_bytes()
    result = replay(root, base=base, head=head, artifact=source, backend=NullBackend())
    assert result.artifact is None and result.error == "artifact_inside_repository"
    assert source.read_bytes() == before


def test_snapshot_resolution_uses_shared_deadline(tmp_path, monkeypatch):
    from openultrasast.model.contracts import ExecutionBudget
    from openultrasast.push.snapshot import SnapshotAdapter, SnapshotInputError

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    launcher = bin_dir / "git"
    launcher.write_text("#!/bin/sh\nexec sleep 5\n")
    launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    started = time.monotonic()
    with pytest.raises(SnapshotInputError, match="deadline"):
        SnapshotAdapter(tmp_path, execution_budget=ExecutionBudget(started + 0.1, 0.5))
    assert time.monotonic() - started < 0.65


def test_preparation_exit_zero_without_receipt_is_failure():
    from openultrasast.model.contracts import ExecutionBudget
    from openultrasast.push.runner import _prepare

    with pytest.raises(RuntimeError, match="worker_failed"):
        _prepare(lambda: os._exit(0), ExecutionBudget(time.monotonic() + 1, 0.5))


def test_base_failure_retains_completed_head_evidence(tmp_path, monkeypatch):
    from test_push_policy import scan

    from openultrasast.push import runner

    root, base, head, _ = history(tmp_path)
    seen = []

    def head_scan(root, regions, **kwargs):
        assert (root / "api.js").read_bytes() and regions
        assert kwargs["ranking_mode"] == "evidence" and kwargs["change_context"].head_revision == head
        seen.append(kwargs["execution_budget"])
        return scan(path="api.js")

    def failed_base(*args, **kwargs):
        assert kwargs["execution_budget"] is seen[0]
        raise RuntimeError("failed comparison")

    monkeypatch.setattr(runner, "scan_repository", head_scan)
    monkeypatch.setattr(runner, "compare_targeted_base", failed_base)
    artifact = tmp_path / "partial.json"
    result = replay(root, base=base, head=head, artifact=artifact)
    data = json.loads(artifact.read_text())
    assert result.result.coverage_status == "incomplete"
    assert len(data["scans"][0]["scan"]["findings"]) == 1
    assert len(data["result"]["analyses"][0]["completed_questions"]) == 1
    assert "base_failed:RuntimeError" in data["admission"]["coverage_reasons"]


def test_preparation_large_result_does_not_deadlock():
    from openultrasast.model.contracts import ExecutionBudget
    from openultrasast.push.runner import _prepare

    assert len(_prepare(lambda: b"x" * 1_000_000, ExecutionBudget(time.monotonic() + 2, 0.5))) == 1_000_000


def test_snapshot_boundaries_reach_engine_change_context(tmp_path):
    root, base, head, git = history(tmp_path)
    (root / "external.js").symlink_to("/unavailable/external.js")
    git("add", "external.js")
    git("commit", "-m", "external context")
    head = git("rev-parse", "HEAD")
    artifact = tmp_path / "boundary.json"
    result = replay(root, base=base, head=head, artifact=artifact, backend=NullBackend())
    data = json.loads(artifact.read_text())
    assert result.result.coverage_status == "incomplete"
    assert "snapshot:symlink_not_materialized" in data["change_context"]["unresolved_boundaries"]


def test_default_replay_does_not_launch_unbudgeted_availability_probe(tmp_path, monkeypatch):
    from openultrasast.push import runner
    from openultrasast.semantic import engines

    root, base, head, _ = history(tmp_path)
    builds = []

    class Backend:
        def build(self, root, **kwargs):
            assert any(p.read_bytes() for p in root.rglob("*.js"))
            builds.append(kwargs["execution_budget"])
            return None

    def forbidden_probe(*args, **kwargs):
        raise AssertionError("availability probe has no shared deadline")

    monkeypatch.setattr(engines, "joern_available", forbidden_probe)
    monkeypatch.setattr(runner, "JoernBackend", Backend, raising=False)
    result = replay(root, base=base, head=head, artifact=tmp_path / "probe.json")
    assert builds and result.result.coverage_status == "incomplete"


def test_replay_persists_discovery_without_skipping_readable_snapshots(tmp_path, monkeypatch):
    from openultrasast.push import runner

    root, base, head, _ = history(tmp_path)
    cache = tmp_path / "cache"
    cold = tmp_path / "cold.json"
    warm = tmp_path / "warm.json"
    replay(root, base=base, head=head, artifact=cold, backend=NullBackend(), cache_dir=cache)

    def should_reuse(*args):
        raise AssertionError("discovery should be cached")

    monkeypatch.setattr(runner, "_discover", should_reuse)
    replay(root, base=base, head=head, artifact=warm, backend=NullBackend(), cache_dir=cache)
    a, b = json.loads(cold.read_text()), json.loads(warm.read_text())
    assert a["result"] == b["result"]
    assert a["snapshots"] == b["snapshots"]
    assert b["timings"]["discovery_hits"] == 2
    assert b["snapshots"][0]["bytes_read"] > 0


def test_cache_cannot_write_inside_repository(tmp_path):
    root, base, head, git = history(tmp_path)
    before = git("status", "--porcelain")
    with pytest.raises(ValueError, match="cache.*outside"):
        replay(root, base=base, head=head, artifact=tmp_path / "out.json", cache_dir=root / "cache")
    assert git("status", "--porcelain") == before


def test_cached_discovery_invalidates_source_and_dependency_edits(tmp_path):
    root, base, head, git = history(tmp_path)
    cache = tmp_path / "cache"
    replay(root, base=base, head=head, artifact=tmp_path / "initial.json", backend=NullBackend(), cache_dir=cache)
    (root / "api.js").write_text("function replacement(req) { eval(req.body.other); }")
    git("add", "api.js")
    git("commit", "-m", "change source")
    edited = git("rev-parse", "HEAD")
    replay(root, base=base, head=edited, artifact=tmp_path / "edited.json", backend=NullBackend(), cache_dir=cache)
    data = json.loads((tmp_path / "edited.json").read_text())
    assert data["timings"]["discovery_hits"] == 1
    (root / "package.json").write_text('{"dependencies":{"express":"5"}}')
    git("add", "package.json")
    git("commit", "-m", "change dependencies")
    dependency = git("rev-parse", "HEAD")
    replay(root, base=base, head=dependency, artifact=tmp_path / "dependency.json", backend=NullBackend(), cache_dir=cache)
    data = json.loads((tmp_path / "dependency.json").read_text())
    assert data["timings"]["discovery_hits"] == 1
    assert data["change_context"]["head_revision"] == dependency


def test_identical_revision_materializes_once_and_reuses_discovery(tmp_path, monkeypatch):
    from openultrasast.push.snapshot import SnapshotAdapter

    root, base, _, _ = history(tmp_path)
    original = SnapshotAdapter.materialize
    calls = []

    def counted(self, oid, **kwargs):
        calls.append(oid)
        return original(self, oid, **kwargs)

    monkeypatch.setattr(SnapshotAdapter, "materialize", counted)
    replay(root, base=base, head=base, artifact=tmp_path / "same.json", backend=NullBackend(), cache_dir=tmp_path / "cache")
    data = json.loads((tmp_path / "same.json").read_text())
    assert calls == [base]
    assert data["timings"]["discovery_hits"] == 1
    assert len(data["snapshots"]) == 2


def test_admission_provenance_invalidates_when_installed_runtime_changes(tmp_path, monkeypatch):
    from openultrasast.model.scan import ScanBudget
    from openultrasast.push import runner

    monkeypatch.setattr(runner, "engine_runtime_identity", lambda: "first-installation")
    first = runner._provenance(tmp_path, ScanBudget())
    monkeypatch.setattr(runner, "engine_runtime_identity", lambda: "second-installation")
    second = runner._provenance(tmp_path, ScanBudget())
    assert first["semantics"] != second["semantics"]
    assert first["facts"] == second["facts"] and first["graph_layout"] == second["graph_layout"]
