"""learning-harness task 3.4: family detectors, verifiers and tags in a scan (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.cli import main

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n"
)


def _repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, *, configs: bool = True) -> Path:
    from openultrasast.learning.detectors import write_default_configs
    from openultrasast.learning.families import load_families

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP)
    (repo / "openultrasast.toml").write_text(toml)
    if configs:  # round zero writes these; a scan reads them and never creates them
        write_default_configs(repo / ".openultrasast/learning/configs", load_families(), prompt="You hunt.", version="0")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    return repo


def _run_dir(repo: Path) -> Path:
    return sorted((repo / ".runs").iterdir())[-1]


def _scan(repo: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    assert main(["scan", str(repo), "--mode", "standard", "--config", str(repo / "openultrasast.toml")]) == 0
    run_dir = _run_dir(repo)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    return findings, manifest


def test_a_standard_scan_tags_findings_with_family_detector_and_verifier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch, '[learning]\nenabled = true\n\n[models]\nhunter = "scripted-model"\n')
    findings, manifest = _scan(repo)
    detected = [item for item in findings if any(str(tag).startswith("family:") for tag in item["tags"])]
    assert detected, "the family detectors ran and their findings are in the report"
    tags = set(detected[0]["tags"])
    assert any(tag.startswith("family:") for tag in tags)
    assert any(tag.startswith("detector:") for tag in tags)
    assert any(tag.startswith("verifier:") for tag in tags)
    assert detected[0]["evidence_level"] == "suspicion"  # nothing rises without a verifier saying so
    block = manifest["learning"]
    assert block["taxonomy_version"] and block["round"] is None
    assert block["families"] and isinstance(block["classifier"], dict)
    assert block["classifier"]["hierarchical_credit"] is False


def test_a_missing_family_directory_is_a_recorded_reason_not_a_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(
        tmp_path,
        monkeypatch,
        '[learning]\nenabled = true\nconfigs_dir = "nowhere/configs"\n\n[models]\nhunter = "scripted-model"\n',
        configs=False,
    )
    findings, manifest = _scan(repo)
    assert not any(str(tag).startswith("family:") for item in findings for tag in item["tags"])
    reasons = {str(item.get("reason")) for item in manifest["degradations"]}
    assert "learning_configs_unavailable" in reasons
    assert "learning" not in manifest or manifest["learning"]["families"] == {}


def test_the_feature_is_off_by_configuration_and_leaves_no_trace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch, "[learning]\nenabled = false\n", configs=False)
    findings, manifest = _scan(repo)
    assert not any(str(tag).startswith("family:") for item in findings for tag in item["tags"])
    assert "learning" not in manifest


def test_family_findings_never_become_sandbox_candidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch, '[learning]\nenabled = true\n\n[models]\nhunter = "scripted-model"\n')
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_RUNNER", "fake")
    assert main(["scan", str(repo), "--mode", "deep", "--config", str(repo / "openultrasast.toml")]) == 0
    run_dir = _run_dir(repo)
    verdicts = json.loads((run_dir / "verdicts.json").read_text())["verdicts"]
    payload = json.loads((run_dir / "findings.json").read_text())["findings"]
    family_findings = {item["finding_id"] for item in payload if any(str(tag).startswith("family:") for tag in item["tags"])}
    assert family_findings, "the fixture must actually produce family findings, or this proves nothing"
    # A family detector's claim is a suspicion until a verifier speaks; handing it to the sandbox would let an
    # unverified model claim drive execution (Req 7.1).
    candidates = {str(item.get("finding_id") or item.get("id") or "") for item in verdicts}
    assert candidates.isdisjoint(family_findings)


def test_the_sarif_report_carries_the_family_properties(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path, monkeypatch, '[learning]\nenabled = true\n\n[models]\nhunter = "scripted-model"\n')
    _scan(repo)
    sarif = json.loads((_run_dir(repo) / "report.sarif").read_text())
    props = [result["properties"] for result in sarif["runs"][0]["results"]]
    family_props = [item for item in props if item.get("family")]
    assert family_props and all(item.get("detector") and item.get("verifier") for item in family_props)
