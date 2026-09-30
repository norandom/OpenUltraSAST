"""Scan-pipeline integrity & serialization (Phase 4 task 9).

9.1 — quick and standard scans run through the sync driver with the deterministic
hunter, verifier and fusion; a configured hunter model never changes the
deterministic findings.
9.2 — every persisted scan-state slot serializes and restores without loss (guards
against a non-serializable slot silently restoring as empty).
"""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from openultrasast.benchmark import load_findings
from openultrasast.cli import main
from openultrasast.findings import StaticFinding, write_findings
from openultrasast.preprocess import FileTarget
from openultrasast.rank import RankingScore
from openultrasast.scoring import build_score_artifact
from openultrasast.verification import EvidenceLevel, VerificationResult, VerificationStatus

_VULN = "@app.route('/admin')\ndef admin():\n    return eval(request.data)\n"


# ---- 9.1 deterministic parity + degradation --------------------------------------


def _scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, mode: str, config_body: str | None) -> tuple[list, dict]:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(_VULN)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENULTRASAST_HUNTER_CLIENT", raising=False)
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


def test_standard_scan_with_a_hunter_model_keeps_deterministic_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A configured hunter model (no client reachable here) must leave the deterministic findings byte-identical.
    requested, requested_manifest = _scan(tmp_path / "a", monkeypatch, mode="standard", config_body='[models]\nhunter = "openai/gpt-4o"\n')
    baseline, baseline_manifest = _scan(tmp_path / "b", monkeypatch, mode="standard", config_body=None)

    assert requested == baseline
    # The hunter model runs the tool hunter (its client is absent here, so it contributes nothing) and removes the
    # `map` skip; `model` records that no CPG engine was available (contributor-scan Req 1.3).
    assert requested_manifest["degradations"] == [{"reason": "cpg_unavailable", "stage": "model"}]
    assert {(e["stage"], e["reason"]) for e in baseline_manifest["degradations"]} == {
        ("model", "cpg_unavailable"),
        ("map", "hunter_model_unavailable"),
    }


def test_quick_scan_records_no_degradation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Quick mode never touches a model: findings are produced and no degradation is recorded.
    findings, manifest = _scan(tmp_path, monkeypatch, mode="quick", config_body=None)

    assert findings
    assert "degradations" not in manifest


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
