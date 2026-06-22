"""Phase 1 in-pipeline wiring: project score artifact + fail-loud CWE invariant."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from openultrasast import cli
from openultrasast.cli import main
from openultrasast.policy import PolicyError


def test_scan_writes_score_artifact_and_manifest_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/x')\ndef view():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "quick"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    score = json.loads((run_dir / "score.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())

    assert isinstance(score["project_score"], int) and 0 <= score["project_score"] <= 100
    assert set(score["gate"]) == {"min_score", "block_severity_reachable", "blocking", "passed"}
    assert manifest["score"] == score
    assert manifest["artifacts"]["score"] == "score.json"


def test_scan_fails_loud_when_an_enabled_rule_cwe_is_unmapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    unmapped = SimpleNamespace(rule_id="bogus", cwe="CWE-99999", status="enabled")
    monkeypatch.setattr(cli, "PATTERN_RULES", (*cli.PATTERN_RULES, unmapped))

    with pytest.raises(PolicyError):
        main(["scan", str(repo), "--mode", "quick"])
