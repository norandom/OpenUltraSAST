"""authorization-obligations task 3.1: the checker runs in MAP with config, manifest counters and no sandbox candidacy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.cli import main

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/mine/<title>')\ndef constrained(title):\n"
    "    user_id = request.user.id\n"
    "    return Book.query.filter_by(user_id=user_id, book_title=title).first()\n\n\n"
    "@app.route('/books/shared/<title>')\ndef constrained_too(title):\n"
    "    owner = current_user.id\n"
    "    return Book.query.filter_by(owner=owner, book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n"
)


def _repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    return repo


def _run_dir(repo: Path) -> Path:
    return sorted((repo / ".runs").iterdir())[-1]


def test_standard_scan_emits_obligation_findings_and_the_manifest_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch)
    (repo / "openultrasast.toml").write_text("[obligations]\nmin_siblings = 2\n")
    assert main(["scan", str(repo), "--mode", "standard", "--config", str(repo / "openultrasast.toml")]) == 0
    run_dir = _run_dir(repo)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    obligations = [f for f in findings if f["finding_id"].startswith("obligation:")]
    leaky = [f for f in obligations if f["function_name"] == "leaky" and "discharger:identity_constraint" in f["tags"]]
    assert leaky and leaky[0]["evidence_level"] == "suspicion" and "obligation_evidence:consistency_violation" in leaky[0]["tags"]
    assert "app.py::constrained" in leaky[0]["rationale"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    block = manifest["obligations"]
    assert block["sibling_sets"] == 1 and block["operations"] == 4 and block["policy_version"] is None
    assert block["findings_by_label"]["consistency_violation"] >= 1 and block["under_populated"] == 0
    assert any(d["reason"] == "obligations_function_local" for d in manifest["degradations"])
    (local,) = [d for d in block["degradations"] if d["reason"] == "obligations_function_local"]  # design: the block carries them
    assert local["language"] == "python" and local["files"] == ["app.py"]
    assert block["sets"] == [{"module": "app", "resource": "book", "handlers": 4}]
    report = (run_dir / "report.md").read_text()
    assert "Sibling sets evaluated: 1 (under-populated: 0)" in report and "Policy version: none" in report
    assert "- `app` / `book`: 4 handlers" in report


def test_declared_policy_is_read_from_the_target_and_versioned_in_the_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch)
    (repo / "openultrasast.toml").write_text("[obligations]\nmin_siblings = 2\n")
    (repo / ".openultrasast").mkdir()
    (repo / ".openultrasast" / "obligations.toml").write_text(
        'version = 1\n[[resource]]\nname = "book"\nsensitivity = "high"\nidentity_field = "user_id"\n\n'
        '[[route]]\npath = "/books/any/*"\naccess = "public"\n'
    )
    assert main(["scan", str(repo), "--mode", "standard", "--config", str(repo / "openultrasast.toml")]) == 0
    run_dir = _run_dir(repo)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert len(manifest["obligations"]["policy_version"]) == 40
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    leaky = [f for f in findings if f["finding_id"].startswith("obligation:") and f["function_name"] == "leaky"]
    assert any("obligation_evidence:declared_policy_violation" in f["tags"] for f in leaky)
    assert not any("discharger:path_guard" in f["tags"] for f in leaky)  # declared public: the guard obligation is waived


def test_quick_scan_and_disabled_config_skip_obligations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch)
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    manifest = json.loads((_run_dir(repo) / "manifest.json").read_text())
    assert "obligations" not in manifest
    (repo / "openultrasast.toml").write_text("[obligations]\nenabled = false\n")
    assert main(["scan", str(repo), "--mode", "standard", "--config", str(repo / "openultrasast.toml")]) == 0
    manifest = json.loads((_run_dir(repo) / "manifest.json").read_text())
    assert "obligations" not in manifest
    findings = json.loads((_run_dir(repo) / "findings.json").read_text())["findings"]
    assert not any(f["finding_id"].startswith("obligation:") for f in findings)


def test_deep_scan_never_offers_obligation_findings_to_the_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli
    from openultrasast.sandbox import FakeSandboxRunner, SandboxResult

    repo = _repo(tmp_path, monkeypatch)
    (repo / "openultrasast.toml").write_text("[obligations]\nmin_siblings = 2\n")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    fake = FakeSandboxRunner(SandboxResult(exit_code=0, stdout="", stderr="", timed_out=False))
    monkeypatch.setattr(cli, "resolve_sandbox_runner", lambda: fake)
    assert main(["scan", str(repo), "--mode", "deep", "--config", str(repo / "openultrasast.toml")]) == 0
    run_dir = _run_dir(repo)
    verdicts = json.loads((run_dir / "verdicts.json").read_text())["verdicts"]
    offered = {finding_id for item in verdicts for finding_id in item["inventory_finding_ids"]}
    assert not any(finding_id.startswith("obligation:") for finding_id in offered)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    assert any(f["finding_id"].startswith("obligation:") for f in findings)  # still reported
