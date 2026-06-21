"""Automatic in-pipeline calibration feedback.

A scan that rejects a finding (e.g. an unreachable pattern match) must persist a
scoped false-positive learning, and the *next* scan on the same target must load
that learning and demote the rejected scope's ranking without any agent in the
loop. Accepted (reachable) findings must not be demoted.
"""

import json
from pathlib import Path

import pytest

from openultrasast.cli import main


def _run_dirs(repo: Path) -> set[Path]:
    runs = repo / ".runs"
    return set(runs.iterdir()) if runs.exists() else set()


def _ranking_priority(run_dir: Path, path: str) -> float:
    rankings = json.loads((run_dir / "rank" / "ranking.json").read_text())["rankings"]
    return next(r["priority"] for r in rankings if r["path"] == path)


def _finding_priority(run_dir: Path, path: str) -> float:
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    return next(f["ranking_priority"] for f in findings if f["path"] == path)


def test_rejected_finding_demotes_its_scope_on_the_next_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Reachable route eval -> accepted (never demoted).
    (repo / "app.py").write_text("@app.route('/x')\ndef view():\n    return eval(request.data)\n")
    # Helper eval with no entry point -> unknown reachability -> rejected -> learning.
    (repo / "lib.py").write_text("def helper(x):\n    return eval(x)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    ledger = repo / ".openultrasast" / "calibration" / "false_positive_learnings.json"

    # --- First scan: produces the learning, applies nothing yet ---------------
    before = _run_dirs(repo)
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    (run1,) = _run_dirs(repo) - before
    learnings = json.loads(ledger.read_text())["learnings"]
    lib_learnings = [item for item in learnings if item["path"] == "lib.py"]
    assert lib_learnings and lib_learnings[0]["reason"] == "unreachable_path"
    assert json.loads((run1 / "calibration" / "applied_calibrations.json").read_text())["calibrations"] == []
    lib_priority_1 = _ranking_priority(run1, "lib.py")
    lib_finding_1 = _finding_priority(run1, "lib.py")
    app_priority_1 = _ranking_priority(run1, "app.py")

    # --- Second scan: loads the ledger and demotes the rejected scope ---------
    before = _run_dirs(repo)
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    (run2,) = _run_dirs(repo) - before
    applied = json.loads((run2 / "calibration" / "applied_calibrations.json").read_text())["calibrations"]
    applied_paths = {item["path"] for item in applied}

    assert "lib.py" in applied_paths
    assert "app.py" not in applied_paths  # accepted finding is never demoted
    assert _ranking_priority(run2, "lib.py") < lib_priority_1
    assert _finding_priority(run2, "lib.py") < lib_finding_1
    assert _ranking_priority(run2, "app.py") == app_priority_1  # scoped: unrelated path untouched
