"""Deep mode: skip regression when the sandbox is missing; record verdicts with a fake runner (task 6.3)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.sandbox import FakeSandboxRunner, SandboxResult
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


def _crash_runner() -> FakeSandboxRunner:
    return FakeSandboxRunner(SandboxResult(exit_code=139, stdout="", stderr="Segmentation fault\n", timed_out=False))


def _enable_crash_sandbox(monkeypatch: pytest.MonkeyPatch) -> FakeSandboxRunner:
    from openultrasast import cli

    fake = _crash_runner()
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    monkeypatch.setattr(cli, "resolve_sandbox_runner", lambda: fake)
    return fake


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
    assert manifest["worth_fixing"]["count"] == sum(1 for item in payload["verdicts"] if item.get("worth_fixing"))
    report = (run_dir / "report.md").read_text()
    inventory_at = report.index("## Inventory")
    map_at = report.index("## Complexity map")
    worth_at = report.index("## Worth fixing")
    assert inventory_at < map_at < worth_at
    map_section = report[map_at:worth_at]
    assert "app.py" in map_section
    assert "Gap:" in map_section
    ledger_path = repo / ".openultrasast" / "calibration" / "complexity_ledger.json"
    assert ledger_path.is_file()
    ledger = json.loads(ledger_path.read_text())
    assert ledger
    assert any(entry.get("last_verdict") in {"triggerable", "not_triggerable"} for entry in ledger.values())


def test_deep_scan_unsafe_hunter_snippet_is_safety_rejected_without_docker_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli
    from openultrasast.sandbox import FakeSandboxRunner

    repo = _repo(tmp_path)
    config = tmp_path / "openultrasast.toml"
    config.write_text('[models]\nhunter = "test-hunter"\n')
    fake = FakeSandboxRunner()
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "unsafe-snippet")
    monkeypatch.setattr(cli, "has_harnessx", lambda: False)
    monkeypatch.setattr(cli, "resolve_sandbox_runner", lambda: fake)
    docker_argv = _guard_docker(monkeypatch)

    assert main(["scan", str(repo), "--mode", "deep", "--config", str(config)]) == 0

    run_dir = _latest_run(repo)
    payload = json.loads((run_dir / "verdicts.json").read_text())
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    hunter_findings = [item for item in findings if str(item["finding_id"]).startswith("tool-hunter:")]

    assert docker_argv == []
    assert hunter_findings
    assert all(item["evidence_level"] == "suspicion" for item in hunter_findings)
    hunter_ids = {item["finding_id"] for item in hunter_findings}
    # Overlay promotions may still be proven; hunter suspicion never becomes a sandbox candidate.
    for item in payload["verdicts"]:
        assert hunter_ids.isdisjoint(item["inventory_finding_ids"])


def test_deep_scan_fail_on_worth_fixing_exits_one_when_triggerable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    _enable_crash_sandbox(monkeypatch)
    docker_argv = _guard_docker(monkeypatch)

    assert main(["scan", str(repo), "--mode", "deep", "--fail-on", "worth-fixing"]) == 1
    assert docker_argv == []

    run_dir = _latest_run(repo)
    payload = json.loads((run_dir / "verdicts.json").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    report = (run_dir / "report.md").read_text()
    worth_fixing = [item for item in payload["verdicts"] if item.get("worth_fixing")]

    assert worth_fixing
    assert len(worth_fixing) >= 1
    assert any(item["verdict"] == "triggerable" for item in worth_fixing)
    assert manifest["worth_fixing"]["count"] == len(worth_fixing)
    assert "## Complexity map" in report
    assert "## Worth fixing" in report
    assert "triggerable" in report
    ledger = json.loads((repo / ".openultrasast" / "calibration" / "complexity_ledger.json").read_text())
    assert any(entry.get("last_verdict") == "triggerable" for entry in ledger.values())


def test_deep_scan_fail_on_never_exits_zero_with_worth_fixing_verdict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    _enable_crash_sandbox(monkeypatch)
    docker_argv = _guard_docker(monkeypatch)

    assert main(["scan", str(repo), "--mode", "deep", "--fail-on", "never"]) == 0
    assert docker_argv == []

    payload = json.loads((_latest_run(repo) / "verdicts.json").read_text())
    assert any(item.get("worth_fixing") for item in payload["verdicts"])
