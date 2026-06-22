"""Scan-pipeline integrity & serialization (Phase 4 task 9).

9.1 — with the extra absent, quick and standard scans run through the existing sync
driver with behaviour unchanged from the deterministic baseline, and a
requested-but-unavailable HarnessX stage records a manifest degradation.
9.2 — every persisted scan-state slot serializes and restores without loss (guards
against a non-serializable slot silently restoring as empty). This covers the
current artifact-persistence model; the HarnessX processor slot-contract variant
(spec task 9.2 over task 6.3) remains deferred with 6.3.
"""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from openultrasast import cli
from openultrasast.benchmark import load_findings
from openultrasast.cli import main
from openultrasast.findings import StaticFinding, write_findings
from openultrasast.preprocess import FileTarget
from openultrasast.rank import RankingScore
from openultrasast.scoring import build_score_artifact
from openultrasast.verification import EvidenceLevel, VerificationResult, VerificationStatus

_VULN = "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n"


# ---- 9.1 fallback parity + degradation --------------------------------------


def _scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, mode: str, config_body: str | None, harnessx: bool) -> tuple[list, dict]:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(_VULN)
    monkeypatch.setattr(cli, "has_harnessx", lambda: harnessx)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    argv = ["scan", str(repo), "--mode", mode]
    if config_body is not None:
        cfg = tmp_path / "openultrasast.toml"
        cfg.write_text(config_body)
        argv += ["--config", str(cfg)]
    assert main(argv) == 0
    run_dir = sorted((repo / ".runs").iterdir())[-1]
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    return findings, manifest


def test_standard_scan_extra_absent_matches_deterministic_baseline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Requested-but-unavailable HarnessX (models set, extra absent) must produce the
    # same findings as the plain deterministic path (no models), differing only by
    # the recorded degradation.
    requested, requested_manifest = _scan(
        tmp_path / "a",
        monkeypatch,
        mode="standard",
        config_body='[models]\nhunter = "openai/gpt-4o"\nverifier = "openai/gpt-4o"\n',
        harnessx=False,
    )
    baseline, baseline_manifest = _scan(tmp_path / "b", monkeypatch, mode="standard", config_body=None, harnessx=False)

    assert requested == baseline  # byte-identical findings -> sync driver behaviour unchanged
    stages = {entry["stage"] for entry in requested_manifest.get("degradations", [])}
    assert stages == {"hunter_pool", "verify"}
    assert all(entry["reason"] == "harnessx_extra_unavailable" for entry in requested_manifest["degradations"])
    assert "degradations" not in baseline_manifest


def test_quick_scan_is_unaffected_by_the_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Quick mode never touches the agentic plane: identical findings whether the
    # extra is present or absent, and never a degradation.
    present, present_manifest = _scan(tmp_path / "a", monkeypatch, mode="quick", config_body=None, harnessx=True)
    absent, _ = _scan(tmp_path / "b", monkeypatch, mode="quick", config_body=None, harnessx=False)

    assert present == absent
    assert present  # findings were produced
    assert "degradations" not in present_manifest


# ---- 9.2 per-slot serialization round-trip ----------------------------------


def _finding() -> StaticFinding:
    return StaticFinding(
        finding_id="python-unsafe-eval:app.py:3",
        path="app.py",
        title="Dynamic Python execution",
        severity="critical",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="eval on request data",
        line=3,
        function_name="admin",
        reachability_status="reachable",
        reachability_evidence=[{"kind": "route", "access_level": "public", "line": 1, "end_line": 3}],
        reachability_conditions=["public route"],
        tags=["syscall_entry", "injection"],
        ranking_priority=3.0,
    )


def _ranking() -> RankingScore:
    return RankingScore(
        path="app.py",
        surface=4,
        influence=3,
        reachability=4,
        priority=3.5,
        rationale="entry",
        model_id=None,
        static_boosts=["input_parser"],
    )


def _file_target() -> FileTarget:
    return FileTarget(
        path="app.py",
        absolute_path="/repo/app.py",
        language="python",
        loc=42,
        tags=["network_entry"],
        has_fuzz_entry_point=False,
        static_hints=[{"rule": "x", "line": 1}],
        reachability_hints=[{"kind": "route", "line": 1}],
    )


def _verification() -> VerificationResult:
    return VerificationResult(
        finding_id="python-unsafe-eval:app.py:3",
        status=VerificationStatus.ACCEPTED,
        evidence_level=EvidenceLevel.STATIC_CORROBORATION,
        verified=True,
        pro_case="reachable tainted sink",
        counter_case="needs dynamic confirmation",
        tie_breaker="confirm attacker control",
        required_next_step="dynamic repro",
        context_sources=["app.py", "routes"],
    )


@pytest.mark.parametrize(
    "obj", [_finding(), _ranking(), _file_target(), _verification()], ids=["finding", "ranking", "file_target", "verification"]
)
def test_scan_slot_json_round_trips_without_loss(obj: object) -> None:
    restored = type(obj)(**json.loads(json.dumps(asdict(obj))))
    assert restored == obj


def test_score_artifact_round_trips() -> None:
    from openultrasast.policy import load_policy

    finding = _finding()
    artifact = build_score_artifact([finding], {finding.finding_id: "CWE-95"}, load_policy())
    payload = json.loads(json.dumps(artifact.to_dict()))
    assert payload == artifact.to_dict()  # serialization is total and stable
    assert payload["project_score"] == artifact.project_score


def test_findings_reload_preserves_nested_slots(tmp_path: Path) -> None:
    # The real resume path (benchmark reloads findings.json); nested collection
    # slots must survive rather than restore as empty.
    path = tmp_path / "findings.json"
    write_findings([_finding()], path)
    (restored,) = load_findings(path)

    assert restored == _finding()
    assert restored.reachability_evidence == [{"kind": "route", "access_level": "public", "line": 1, "end_line": 3}]
    assert restored.reachability_conditions == ["public route"]
    assert restored.tags == ["syscall_entry", "injection"]
