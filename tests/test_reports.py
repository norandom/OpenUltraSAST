import json
from pathlib import Path

from openultrasast.cli import main
from openultrasast.findings import StaticFinding
from openultrasast.reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from openultrasast.run import ScanRun
from openultrasast.verification import verify_finding


def test_sarif_report_uses_finding_ids_and_evidence_properties(tmp_path: Path) -> None:
    finding = _finding()
    verification = verify_finding(finding)
    output = tmp_path / "report.sarif"

    write_sarif_report([finding], [verification], output)

    payload = json.loads(output.read_text())
    result = payload["runs"][0]["results"][0]

    assert payload["version"] == "2.1.0"
    assert result["partialFingerprints"]["openultrasastFindingId"] == finding.finding_id
    assert result["properties"]["finding_id"] == finding.finding_id
    assert result["properties"]["evidence_level"] == "static_corroboration"
    assert result["properties"]["verification"]["status"] == "accepted"


def test_manifest_links_shared_artifacts_by_finding_id(tmp_path: Path) -> None:
    run = ScanRun(scan_id="scan-1", root=tmp_path / "run", target=tmp_path / "repo")
    run.root.mkdir()
    finding = _finding()
    verification = verify_finding(finding)
    artifacts = {
        "findings": run.root / "findings.json",
        "verification": run.root / "verification.json",
        "markdown": run.root / "report.md",
        "sarif": run.root / "report.sarif",
    }
    output = run.root / "manifest.json"

    write_manifest(run=run, findings=[finding], verifications=[verification], artifact_paths=artifacts, path=output)

    payload = json.loads(output.read_text())
    manifest_finding = payload["findings"][0]

    assert payload["scan_id"] == "scan-1"
    assert manifest_finding["finding_id"] == finding.finding_id
    assert manifest_finding["verification_status"] == "accepted"
    assert manifest_finding["artifact_refs"]["sarif"] == "report.sarif"


def test_markdown_report_includes_verification_status(tmp_path: Path) -> None:
    finding = _finding()
    output = tmp_path / "report.md"

    write_markdown_report([finding], output, [verify_finding(finding)])

    text = output.read_text()
    assert "Verification: `accepted`" in text
    assert finding.finding_id in text


def test_scan_exit_code_policy() -> None:
    finding = _finding()
    verification = verify_finding(finding)

    assert scan_exit_code([finding], [verification], "never") == 0
    assert scan_exit_code([finding], [verification], "findings") == 1
    assert scan_exit_code([finding], [verification], "verified") == 1
    assert scan_exit_code([], [], "verified") == 0


def test_cli_scan_writes_sarif_manifest_and_honors_fail_policy(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "quick", "--fail-on", "verified"]) == 1

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    sarif = json.loads((run_dir / "report.sarif").read_text())
    manifest = json.loads((run_dir / "manifest.json").read_text())

    finding_id = manifest["findings"][0]["finding_id"]
    assert sarif["runs"][0]["results"][0]["properties"]["finding_id"] == finding_id
    assert manifest["findings"][0]["artifact_refs"]["verification_json"] == "verification.json"


def _finding() -> StaticFinding:
    return StaticFinding(
        finding_id="python-unsafe-eval:app.py:3",
        path="app.py",
        title="Dynamic Python execution needs review",
        severity="high",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="Static pattern matched.",
        line=3,
        function_name="admin",
        reachability_status="reachable",
        reachability_evidence=[
            {
                "kind": "route",
                "access_level": "public",
                "line": 1,
                "end_line": 3,
                "function_name": "admin",
                "conditions": [],
            }
        ],
        reachability_conditions=[],
        tags=["syscall_entry"],
        ranking_priority=3.0,
    )
