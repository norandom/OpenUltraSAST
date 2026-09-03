"""Deep mode: skip regression when the sandbox is missing; record verdicts with a fake runner (task 6.3)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.sandbox import runner as sandbox_runner

_VULN = "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(_VULN)
    return repo


def _fail(message: str):  # type: ignore[no-untyped-def]
    def _inner(*args: object, **kwargs: object) -> object:
        raise AssertionError(message)

    return _inner


def _guard_docker(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    docker_argv: list[list[str]] = []
    original_run = subprocess.run

    def guarded_run(command: object, *args: object, **kwargs: object) -> object:
        argv = list(command) if isinstance(command, list | tuple) else [command]
        if argv and Path(str(argv[0])).name == "docker":
            docker_argv.append([str(item) for item in argv])
            raise AssertionError(f"deep scan test must not start docker: {argv}")
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(sandbox_runner.DockerCliRunner, "run", _fail("deep scan test must not use DockerCliRunner"))
    return docker_argv


def _latest_run(repo: Path) -> Path:
    return sorted((repo / ".runs").iterdir())[-1]


def test_deep_scan_skips_regress_when_sandbox_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    docker_argv = _guard_docker(monkeypatch)

    assert main(["scan", str(repo), "--mode", "deep"]) == 0

    run_dir = _latest_run(repo)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    stages = manifest["stages"]
    degradations = manifest.get("degradations", [])

    assert (run_dir / "complexity_map.json").is_file()
    assert not (run_dir / "verdicts.json").exists()
    assert docker_argv == []
    assert stages["requested"] == ["static", "map", "regress"]
    assert stages["completed"] == ["static", "map"]
    assert {"stage": "regress", "reason": "sandbox_unavailable"} in stages["skipped"]
    assert any(entry.get("stage") == "regress" and entry.get("reason") == "sandbox_unavailable" for entry in degradations)


def test_deep_scan_with_fake_runner_writes_verdicts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_RUNNER", "fake")
    docker_argv = _guard_docker(monkeypatch)

    assert main(["scan", str(repo), "--mode", "deep"]) == 0

    run_dir = _latest_run(repo)
    verdicts_path = run_dir / "verdicts.json"
    manifest = json.loads((run_dir / "manifest.json").read_text())
    payload = json.loads(verdicts_path.read_text())
    stages = manifest["stages"]

    assert docker_argv == []
    assert verdicts_path.is_file()
    assert (run_dir / "complexity_map.json").is_file()
    assert stages["requested"] == ["static", "map", "regress"]
    assert stages["completed"] == ["static", "map", "regress"]
    assert not any(entry.get("reason") == "sandbox_unavailable" for entry in stages["skipped"])
    assert isinstance(payload["verdicts"], list)
    assert payload["verdicts"]
    for item in payload["verdicts"]:
        assert item["verdict"] in {"triggerable", "not_triggerable", "already_covered", "inconclusive"}
        assert "reason" in item
        assert "path" in item
    assert manifest["artifacts"]["verdicts"] == "verdicts.json"
    assert manifest["artifacts"]["complexity_map"] == "complexity_map.json"
