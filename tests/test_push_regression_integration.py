"""Combined transaction controls, not detector qualification."""

import json
import multiprocessing
import os
import time

from test_push_runner import history

from openultrasast.config import PushConfig
from openultrasast.cpg.backend import NullBackend
from openultrasast.push.runner import push


def test_mixed_transaction_retains_exact_objects_and_external_boundaries(tmp_path):
    root, base, head, git = history(tmp_path)
    git("tag", "-a", "release", "-m", "release", head)
    tag = git("rev-parse", "release")
    # Non-HEAD push while the live tree contains unrelated unusual paths and a symlink.
    path = root / "space ü\tname.js"
    path.write_text("function route(req) { return req.body; }\n")
    (root / "outside.js").symlink_to(tmp_path / "outside-secret")
    (tmp_path / "outside-secret").write_text("must never be read by analysis")
    git("add", "--", path.name, "outside.js")
    git("commit", "-m", "external boundary")
    tip = git("rev-parse", "HEAD")
    before = (root / ".git/index").read_bytes(), git("show-ref"), git("status", "--porcelain")
    zero = "0" * 40
    lines = (
        f"refs/tags/release {tag} refs/tags/release {base}\n"
        f"refs/heads/rewind {base} refs/heads/rewind {head}\n"
        f"refs/heads/new {tip} refs/heads/new {zero}\n"
        f"(delete) {zero} refs/heads/deleted {head}\n"
    )
    artifact = tmp_path / "mixed.json"
    result = push(
        root,
        updates=lines,
        remote_name="origin",
        remote_url="/local",
        artifact=artifact,
        backend=NullBackend(),
        config=PushConfig(comparison_base=base),
    )
    data = json.loads(artifact.read_text())
    assert len(data["resolution"]["updates"]) == 4
    assert len(result.result.analyses) == 3
    assert [(a.comparison.head_oid, a.comparison.base_oid) for a in result.result.analyses] == [(head, base), (base, head), (tip, base)]
    assert result.result.coverage_status != "complete_within_scope"
    assert any(m["boundaries"] for m in data["snapshots"])
    assert all(m["bytes_read"] > 0 for m in data["snapshots"])
    assert "must never be read by analysis" not in artifact.read_text()
    assert ((root / ".git/index").read_bytes(), git("show-ref"), git("status", "--porcelain")) == before


def test_interrupted_writer_preserves_previous_artifact_and_reaps_child(tmp_path, monkeypatch):
    import openultrasast.push.report as reporting

    root, base, head, _ = history(tmp_path)
    artifact = tmp_path / "result.json"
    artifact.write_text("previous completed artifact")
    pidfile = tmp_path / "writer.pid"

    def interrupted(*args):
        pidfile.write_text(str(os.getpid()))
        time.sleep(10)

    monkeypatch.setattr(reporting, "_write_artifact", interrupted)
    before = {p.pid for p in multiprocessing.active_children()}
    start = time.monotonic()
    result = push(
        root,
        updates="",
        remote_name="origin",
        remote_url="/local",
        artifact=artifact,
        config=PushConfig(deadline_seconds=0.2, cancellation_allowance_seconds=0.4),
    )
    assert time.monotonic() - start < 0.8
    assert result.error == "report_deadline_exhausted"
    assert artifact.read_text() == "previous completed artifact"
    assert result.result.coverage_status == "not_applicable"
    assert {p.pid for p in multiprocessing.active_children()} == before
    assert pidfile.exists()
    assert not os.path.exists("/proc/" + pidfile.read_text())


def test_failed_census_after_physical_vendor_filter_is_not_clean(tmp_path):
    from openultrasast.cpg.backend import CpgResult

    root, base, head, git = history(tmp_path)
    vendor = root / "node_modules/dependency"
    vendor.mkdir(parents=True)
    (vendor / "vendor.js").write_text("function vendor(req) { eval(req.body); }\n")
    git("add", "--", "node_modules")
    git("commit", "-m", "vendor boundary")
    tip = git("rev-parse", "HEAD")
    reads = []

    class FailedCensus:
        def build(self, source, **kwargs):
            files = [p for p in source.rglob("*") if p.is_file()]
            assert files
            assert not any("node_modules" in p.parts for p in files)
            reads.extend(len(p.read_bytes()) for p in files)
            return CpgResult(tmp_path / "graph", lambda *_: None, lambda *_: {})

    artifact = tmp_path / "census.json"
    result = push(
        root,
        updates=f"refs/heads/main {tip} refs/heads/main {base}\n",
        remote_name="origin",
        remote_url="/local",
        artifact=artifact,
        backend=FailedCensus(),
    )
    data = json.loads(artifact.read_text())
    assert reads and all(n > 0 for n in reads)
    assert result.result.coverage_status in ("unavailable", "incomplete")
    assert result.result.finding_status == "none"
    assert data["admission"]["coverage_reasons"]
    assert not any(a.completed_questions for a in result.result.analyses)
