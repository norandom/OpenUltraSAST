"""The quick-rule tier of pre-push (task 17.3, Requirement 9.3): fast, advisory, never an alert."""

from __future__ import annotations

import json

from test_push_runner import history

from openultrasast.cpg.backend import NullBackend
from openultrasast.push.quick import run_quick_tier
from openultrasast.push.runner import push, replay

HANDLER = "module.exports = function debug (req, res) {\n  res.end(String(eval(req.query.code)))\n}\n"


def test_only_matches_on_changed_lines_are_kept_and_input_is_proven(tmp_path):
    (tmp_path / "debug.js").write_text(HANDLER)
    (tmp_path / "old.js").write_text("eval(x)\n")
    hit = run_quick_tier(tmp_path, {"debug.js": [(2, 2)], "old.js": [(5, 5)]})
    assert hit.status == "completed" and hit.files == ("debug.js", "old.js")
    assert hit.bytes_read == len(HANDLER) + len("eval(x)\n")
    assert {(f["rule"], f["path"], f["line"], f["scope"]) for f in hit.findings} >= {("js-eval", "debug.js", 2, "changed_line")}
    assert all(f["path"] == "debug.js" for f in hit.findings)
    miss = run_quick_tier(tmp_path, {"debug.js": [(3, 3)]})
    assert miss.findings == () and miss.files == ("debug.js",)


def test_replay_shows_quick_matches_as_advisory_and_never_admits_or_blocks(tmp_path):
    root, _, base, git = history(tmp_path)
    (root / "debug.js").write_text(HANDLER)
    git("add", "debug.js")
    git("commit", "-m", "debug")
    head = git("rev-parse", "HEAD")
    artifact = tmp_path / "r.json"
    delivery = replay(root, base=base, head=head, artifact=artifact, backend=NullBackend())
    assert delivery.exit_code == 0 and delivery.result.actionable_defect_ids == ()
    assert "Quick rules: " in delivery.text and "Advisory: not verified by the engine." in delivery.text
    assert "- js-eval (CWE-95" in delivery.text and "debug.js:2" in delivery.text
    data = json.loads(artifact.read_text())
    (tier,) = data["quick_tier"]
    assert tier["status"] == "completed" and tier["basis"] == "comparison" and tier["files"] == ["debug.js"]
    assert tier["bytes_read"] == len(HANDLER) and "advisory" in tier["label"]
    assert data["admission"]["defects"] == []


def test_new_branch_says_there_is_no_base_and_what_was_checked_instead(tmp_path):
    root, _, head, git = history(tmp_path)
    updates = f"refs/heads/feature {head} refs/heads/feature {'0' * 40}\n"
    delivery = push(root, updates=updates, remote_name="origin", remote_url="/r", artifact=tmp_path / "p.json", backend=NullBackend())
    assert delivery.exit_code == 0
    assert "Skipped: new branch: the remote has no base to compare against" in delivery.text
    assert "New branch: instead, quick rules checked the files its last commit changed" in delivery.text
    (tier,) = json.loads((tmp_path / "p.json").read_text())["quick_tier"]
    assert tier["basis"] == "last_commit" and tier["files"] == ["api.js"]
