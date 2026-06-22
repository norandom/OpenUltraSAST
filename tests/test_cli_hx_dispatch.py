"""CLI capability-gated dispatch + graceful degradation (Phase 3 task 6.5).

These run in the default (extra-absent) environment: standard mode with models
configured must fall back to the deterministic hunter/structural verifier and
record a degradation; with no models configured the manifest stays byte-identical.
"""

import json
from pathlib import Path

import pytest

from openultrasast import cli
from openultrasast.cli import main

_VULN = "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n"


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config_body: str | None) -> dict:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(_VULN)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    argv = ["scan", str(repo), "--mode", "standard"]
    if config_body is not None:
        cfg = tmp_path / "openultrasast.toml"
        cfg.write_text(config_body)
        argv += ["--config", str(cfg)]
    assert main(argv) == 0
    run_dir = sorted((repo / ".runs").iterdir())[-1]
    return json.loads((run_dir / "manifest.json").read_text())


def test_degradation_recorded_when_models_set_but_extra_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert not cli.has_harnessx()  # this CI env has no harnessx extra
    manifest = _run(tmp_path, monkeypatch, '[models]\nhunter = "anthropic/claude"\nverifier = "anthropic/claude"\n')

    degradations = manifest.get("degradations", [])
    stages = {entry["stage"] for entry in degradations}
    assert stages == {"hunter_pool", "verify"}
    assert all(entry["reason"] == "harnessx_extra_unavailable" for entry in degradations)
    # Fallback still produced findings (deterministic hunter ran).
    assert manifest["findings"]


def test_manifest_has_no_degradations_without_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = _run(tmp_path, monkeypatch, config_body=None)
    assert "degradations" not in manifest


def test_standard_scan_falls_back_to_run_hunter_pool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = cli.run_hunter_pool
    monkeypatch.setattr(cli, "run_hunter_pool", lambda *a, **k: calls.append("fallback") or real(*a, **k))
    _run(tmp_path, monkeypatch, '[models]\nhunter = "anthropic/claude"\n')
    assert calls == ["fallback"]
