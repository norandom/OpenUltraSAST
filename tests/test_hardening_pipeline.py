"""Hardening wired into the scan: redaction + bounded-CI finding budget (Phase 15)."""

import json
from pathlib import Path

import pytest

from openultrasast.cli import main

# Two vulnerable routes whose source quotes a live-looking secret. The secret is
# assembled at runtime so no scannable token literal lives in the repository.
_SECRET = "sk-" + "abcdEFGH1234567890zzzzzz"
_VULN_WITH_SECRET = (
    f'API_KEY = "{_SECRET}"\n'
    "@app.route('/a')\n"
    "def a():\n"
    "    return eval(request.data)\n"
    "@app.route('/b')\n"
    "def b():\n"
    "    return eval(request.args['x'])\n"
)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, config_body: str | None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(_VULN_WITH_SECRET)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    argv = ["scan", str(repo), "--mode", "quick"]
    if config_body is not None:
        cfg = tmp_path / "openultrasast.toml"
        cfg.write_text(config_body)
        argv += ["--config", str(cfg)]
    assert main(argv) == 0
    return sorted((repo / ".runs").iterdir())[-1]


def test_trace_does_not_leak_secrets_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _run(tmp_path, monkeypatch, config_body=None)
    trace = (run_dir / "trace" / "events.jsonl").read_text()
    assert _SECRET not in trace


def test_max_findings_budget_truncates_and_records_degradation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The fixture yields two eval findings; cap to 1 and confirm truncation is disclosed.
    uncapped = _run(tmp_path / "full", monkeypatch, config_body=None)
    assert len(json.loads((uncapped / "findings.json").read_text())["findings"]) >= 2

    run_dir = _run(tmp_path / "capped", monkeypatch, config_body="[hardening]\nmax_findings = 1\n")
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert len(findings) == 1
    budget = next(d for d in manifest["degradations"] if d["stage"] == "budget")
    assert budget["reason"] == "max_findings_exceeded" and budget["actual"] >= 2


def test_redaction_can_be_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _run(tmp_path, monkeypatch, config_body="[hardening]\nredact_secrets = false\n")
    trace = (run_dir / "trace" / "events.jsonl").read_text()
    # With redaction off, the trace is not scrubbed (target path/source may appear verbatim).
    assert "***REDACTED***" not in trace
