"""Engine honesty within the deadline and the background engine (task 17.5, Requirement 9.5)."""

from __future__ import annotations

import json
import os
import time

from test_push_runner import history

from openultrasast.cpg.backend import NullBackend
from openultrasast.push import background
from openultrasast.push.runner import replay


def test_engine_off_runs_the_quick_tier_and_says_the_engine_was_skipped(tmp_path):
    root, base, head, _ = history(tmp_path)
    delivery = replay(root, base=base, head=head, artifact=tmp_path / "r.json", backend=NullBackend(), engine="off")
    assert delivery.exit_code == 0
    assert "Skipped: engine checks were switched off for this run (--engine off)" in delivery.text
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["scans"] == [] and data["quick_tier"][0]["status"] == "completed"


def test_background_engine_result_is_shown_once_on_the_next_run(tmp_path):
    root, base, head, _ = history(tmp_path)
    artifacts = tmp_path / "artifacts"
    first = replay(root, base=base, head=head, artifact=artifacts / "push-1.json", engine="background", background_deadline=60)
    assert first.exit_code == 0
    assert "Engine: running in the background for " + head[:12] in first.text
    assert "Skipped: engine checks run in the background after this push" in first.text
    started = json.loads((artifacts / "push-1.json").read_text())["engine_background"]
    assert started["status"] == "started" and started["head"] == head
    result = background.results_dir(artifacts / "push-1.json", root) / f"{head}.json"
    deadline = time.monotonic() + 90
    while not result.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    assert result.exists(), (background.results_dir(artifacts / "push-1.json", root) / f"{head}.log").read_text()
    second = replay(root, base=base, head=head, artifact=artifacts / "push-2.json", backend=NullBackend(), engine="off")
    assert f"Engine result for {head[:12]} from the previous push:" in second.text
    assert str(result) in second.text
    third = replay(root, base=base, head=head, artifact=artifacts / "push-3.json", backend=NullBackend(), engine="off")
    assert "from the previous push" not in third.text


def test_one_background_engine_at_a_time(tmp_path):
    root, base, head, _ = history(tmp_path)
    artifact = tmp_path / "a" / "push.json"
    directory = background.results_dir(artifact, root)
    directory.mkdir(parents=True)
    (directory / "running.json").write_text(json.dumps({"pid": os.getpid(), "head": "f" * 40}))
    state = background.start(root, base=base, head=head, artifact=artifact, deadline_seconds=5)
    assert state["status"] == "busy" and not (directory / f"{head}.log").exists()
    delivery = replay(root, base=base, head=head, artifact=artifact, backend=NullBackend(), engine="background")
    assert "is still busy, so none was started" in delivery.text


def test_previous_summarises_advisory_engine_findings(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    artifact = tmp_path / "out" / "push.json"
    directory = background.results_dir(artifact, root)
    directory.mkdir(parents=True)
    delta = {
        "family": "injection",
        "novelty": "new",
        "witness": "req.query.code -> eval",
        "head_operation": {"path": "debug.js", "line": 2},
    }
    payload = {
        "result": {"coverage_status": "incomplete"},
        "admission": {
            "defects": [],
            "coverage_reasons": ["capability_unavailable"],
            "dispositions": [{"admitted": False, "reasons": ["capability_unavailable"], "candidate": {"delta": delta}}],
        },
    }
    (directory / ("a" * 40 + ".json")).write_text(json.dumps(payload))
    (item,) = background.previous(artifact, root)
    assert item["advisory"] == [{"family": "injection", "path": "debug.js", "line": 2, "novelty": "new"}]
    assert item["finished"] and item["engine_ran"] and item["alerts"] == 0
    assert background.previous(artifact, root) == []
