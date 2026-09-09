import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from openultrasast.cli import main
from openultrasast.complexity.hints import TestHint
from openultrasast.complexity.map import ComplexityMap, Hotspot
from openultrasast.findings import StaticFinding
from openultrasast.regress import CandidateVerdict
from openultrasast.reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from openultrasast.run import ScanRun
from openultrasast.stages import Stage, plan_for_mode, record_completed, stages_payload
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
    assert "stages" not in payload


def test_manifest_includes_requested_completed_skipped_stages(tmp_path: Path) -> None:
    run = ScanRun(scan_id="scan-1", root=tmp_path / "run", target=tmp_path / "repo")
    run.root.mkdir()
    finding = _finding()
    artifacts = {
        "findings": run.root / "findings.json",
        "verification": run.root / "verification.json",
        "markdown": run.root / "report.md",
        "sarif": run.root / "report.sarif",
    }
    output = run.root / "manifest.json"
    plan = record_completed(plan_for_mode("quick"), Stage.STATIC)

    write_manifest(
        run=run,
        findings=[finding],
        verifications=[verify_finding(finding)],
        artifact_paths=artifacts,
        path=output,
        stages=stages_payload(plan),
    )

    payload = json.loads(output.read_text())
    assert payload["stages"] == {"requested": ["static"], "completed": ["static"], "skipped": []}
    assert payload["findings"][0]["finding_id"] == finding.finding_id


def test_markdown_report_includes_verification_status(tmp_path: Path) -> None:
    finding = _finding()
    output = tmp_path / "report.md"

    write_markdown_report([finding], output, [verify_finding(finding)])

    text = output.read_text()
    assert "## Inventory" in text
    assert "Verification: `accepted`" in text
    assert finding.finding_id in text
    assert "worth-fixing" not in text.lower()
    assert "worth_fixing" not in text.lower()


def test_markdown_report_includes_complexity_map_and_worth_fixing_sections(tmp_path: Path) -> None:
    finding = _finding()
    output = tmp_path / "report.md"
    hint = TestHint(
        path="app.py",
        function_name="admin",
        gap="no_adjacent_test",
        test_kind="http-contract",
        reason="no adjacent test file for app.py::admin; recommend http-contract.",
    )
    hotspot = Hotspot(
        path="app.py",
        function_name="admin",
        score=6.5,
        band="high",
        signals={"loc": 12, "has_adjacent_test": False},
        rationale="high band: nested public route",
        test_hint=hint,
        inventory_finding_ids=(finding.finding_id,),
    )
    verdict = CandidateVerdict(
        path="app.py",
        function_name="admin",
        language="python",
        verdict="triggerable",
        reason="crash",
        inventory_finding_ids=(finding.finding_id,),
        worth_fixing=True,
    )
    skipped = CandidateVerdict(
        path="safe.py",
        function_name=None,
        language="python",
        verdict="not_triggerable",
        reason="exit_zero",
        inventory_finding_ids=(),
        worth_fixing=False,
    )

    write_markdown_report(
        [finding],
        output,
        [verify_finding(finding)],
        complexity_map=ComplexityMap(hotspots=(hotspot,), heuristic_only=True),
        verdicts=(verdict, skipped),
    )

    text = output.read_text()
    inventory_at = text.index("## Inventory")
    map_at = text.index("## Complexity map")
    worth_at = text.index("## Worth fixing")
    assert inventory_at < map_at < worth_at
    map_section = text[map_at:worth_at]
    worth_section = text[worth_at:]
    assert "app.py::admin" in map_section
    assert "Gap: `no_adjacent_test`" in map_section
    assert "Recommended test: `http-contract`" in map_section
    assert "triggerable" in worth_section
    assert "crash" in worth_section
    assert "safe.py" not in worth_section
    assert "## Inventory" in text


def test_markdown_report_labels_hits_as_inventory_not_worth_fixing(tmp_path: Path) -> None:
    finding = _finding()
    output = tmp_path / "report.md"

    write_markdown_report([finding], output, [verify_finding(finding)])

    text = output.read_text()
    inventory_at = text.index("## Inventory")
    finding_at = text.index(f"## {finding.title}")
    assert inventory_at < finding_at
    assert "worth-fixing" not in text.lower()


def test_scan_exit_code_policy() -> None:
    finding = _finding()
    verification = verify_finding(finding)
    worth_fixing = SimpleNamespace(worth_fixing=True)

    assert scan_exit_code([finding], [verification], "never") == 0
    assert scan_exit_code([finding], [verification], "findings") == 1
    assert scan_exit_code([], [], "findings") == 0
    assert scan_exit_code([finding], [verification], "verified") == 1
    assert scan_exit_code([], [], "verified") == 0
    # findings/verified ignore worth-fixing verdicts
    assert scan_exit_code([], [], "findings", worth_fixing_verdicts=[worth_fixing]) == 0
    assert scan_exit_code([], [], "verified", worth_fixing_verdicts=[worth_fixing]) == 0
    assert scan_exit_code([finding], [verification], "findings", worth_fixing_verdicts=[worth_fixing]) == 1
    assert scan_exit_code([finding], [verification], "verified", worth_fixing_verdicts=[worth_fixing]) == 1


def test_scan_exit_code_worth_fixing() -> None:
    finding = _finding()
    verification = verify_finding(finding)
    worth_fixing = SimpleNamespace(worth_fixing=True)
    not_worth_fixing = SimpleNamespace(worth_fixing=False)

    assert scan_exit_code([finding], [verification], "worth-fixing") == 0
    assert scan_exit_code([finding], [verification], "worth-fixing", worth_fixing_verdicts=[]) == 0
    assert scan_exit_code([finding], [verification], "worth-fixing", worth_fixing_verdicts=[not_worth_fixing]) == 0
    assert scan_exit_code([finding], [verification], "worth-fixing", worth_fixing_verdicts=[worth_fixing]) == 1


def test_scan_exit_code_unknown_policy() -> None:
    with pytest.raises(ValueError, match="unknown fail policy"):
        scan_exit_code([], [], "maybe")


def test_scan_help_lists_worth_fixing(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "worth-fixing" in help_text
    assert "findings" in help_text
    assert "verified" in help_text


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


def test_cli_scan_fail_on_worth_fixing_exits_zero_without_verdicts(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "quick", "--fail-on", "worth-fixing"]) == 0


def test_quick_scan_report_is_inventory_without_map_or_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import tool_hunter
    from openultrasast.complexity import map as complexity_map
    from openultrasast.sandbox import probe as sandbox_probe
    from openultrasast.sandbox import runner as sandbox_runner

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    docker_argv: list[list[str]] = []
    original_run = subprocess.run

    def guarded_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
        argv = list(command) if isinstance(command, list | tuple) else [command]
        if argv and Path(str(argv[0])).name == "docker":
            docker_argv.append(argv)
            raise AssertionError(f"quick scan must not start docker: {argv}")
        return original_run(command, *args, **kwargs)

    def fail(message: str):  # type: ignore[no-untyped-def]
        def _fail(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError(message)

        return _fail

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(sandbox_runner, "build_docker_argv", fail("quick scan must not build docker argv"))
    monkeypatch.setattr(sandbox_probe.SandboxProbe, "available", fail("quick scan must not probe docker"))
    monkeypatch.setattr(complexity_map, "build_complexity_map", fail("quick scan must not build a complexity map"))
    monkeypatch.setattr(tool_hunter, "run_tool_hunter", fail("quick scan must not start a hunter model"))

    assert main(["scan", str(repo), "--mode", "quick"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    report = (run_dir / "report.md").read_text()
    manifest = json.loads((run_dir / "manifest.json").read_text())

    assert "## Inventory" in report
    assert "worth-fixing" not in report.lower()
    assert not (run_dir / "complexity_map.json").exists()
    assert docker_argv == []
    assert manifest["stages"]["requested"] == ["static"]
    assert manifest["stages"]["completed"] == ["static"]
    assert manifest["stages"]["skipped"] == []
    assert "complexity" not in manifest
    assert "complexity_map" not in manifest.get("artifacts", {})
    assert not any(entry.get("reason") == "hunter_model_unavailable" for entry in manifest.get("degradations", []))


def test_standard_scan_writes_complexity_map_without_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.sandbox import probe as sandbox_probe
    from openultrasast.sandbox import runner as sandbox_runner

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    docker_argv: list[list[str]] = []
    original_run = subprocess.run

    def guarded_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
        argv = list(command) if isinstance(command, list | tuple) else [command]
        if argv and Path(str(argv[0])).name == "docker":
            docker_argv.append(argv)
            raise AssertionError(f"standard scan must not start docker: {argv}")
        return original_run(command, *args, **kwargs)

    def fail(message: str):  # type: ignore[no-untyped-def]
        def _fail(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError(message)

        return _fail

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(sandbox_runner, "build_docker_argv", fail("standard scan must not build docker argv"))
    monkeypatch.setattr(sandbox_probe.SandboxProbe, "available", fail("standard scan must not probe docker"))

    assert main(["scan", str(repo), "--mode", "standard"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    map_path = run_dir / "complexity_map.json"
    manifest = json.loads((run_dir / "manifest.json").read_text())
    complexity_map = json.loads(map_path.read_text())

    assert map_path.is_file()
    assert complexity_map["heuristic_only"] is True
    assert isinstance(complexity_map["hotspots"], list)
    assert complexity_map["hotspots"]
    assert docker_argv == []
    assert manifest["stages"]["requested"] == ["static", "map"]
    assert manifest["stages"]["completed"] == ["static", "map"]
    assert manifest["stages"]["skipped"] == []
    assert manifest["complexity"]["hotspot_count"] == len(complexity_map["hotspots"])
    assert manifest["complexity"]["heuristic_only"] is True
    assert manifest["artifacts"]["complexity_map"] == "complexity_map.json"
    report = (run_dir / "report.md").read_text()
    assert "## Inventory" in report
    assert "## Complexity map" in report
    assert "Gap:" in report
    assert "## Worth fixing" not in report


def test_standard_scan_records_hunter_model_unavailable_when_model_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.sandbox import probe as sandbox_probe
    from openultrasast.sandbox import runner as sandbox_runner

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    def fail(message: str):  # type: ignore[no-untyped-def]
        def _fail(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError(message)

        return _fail

    monkeypatch.setattr(sandbox_runner, "build_docker_argv", fail("standard scan must not build docker argv"))
    monkeypatch.setattr(sandbox_probe.SandboxProbe, "available", fail("standard scan must not probe docker"))

    assert main(["scan", str(repo), "--mode", "standard"]) == 0

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    degradations = manifest.get("degradations", [])

    assert any(entry.get("reason") == "hunter_model_unavailable" for entry in degradations)
    hunter_skip = next(entry for entry in degradations if entry.get("reason") == "hunter_model_unavailable")
    assert hunter_skip["stage"] in {"map", "hunter_pool"}
    assert manifest["complexity"]["heuristic_only"] is True
    assert (run_dir / "complexity_map.json").is_file()


def test_manifest_includes_complexity_summary(tmp_path: Path) -> None:
    run = ScanRun(scan_id="scan-1", root=tmp_path / "run", target=tmp_path / "repo")
    run.root.mkdir()
    finding = _finding()
    artifacts = {
        "findings": run.root / "findings.json",
        "verification": run.root / "verification.json",
        "markdown": run.root / "report.md",
        "sarif": run.root / "report.sarif",
        "complexity_map": run.root / "complexity_map.json",
    }
    output = run.root / "manifest.json"

    write_manifest(
        run=run,
        findings=[finding],
        verifications=[verify_finding(finding)],
        artifact_paths=artifacts,
        path=output,
        complexity={"hotspot_count": 3, "heuristic_only": True},
    )

    payload = json.loads(output.read_text())
    assert payload["complexity"] == {"hotspot_count": 3, "heuristic_only": True}
    assert payload["artifacts"]["complexity_map"] == "complexity_map.json"


def test_manifest_includes_worth_fixing_count(tmp_path: Path) -> None:
    run = ScanRun(scan_id="scan-1", root=tmp_path / "run", target=tmp_path / "repo")
    run.root.mkdir()
    finding = _finding()
    artifacts = {
        "findings": run.root / "findings.json",
        "verification": run.root / "verification.json",
        "markdown": run.root / "report.md",
        "sarif": run.root / "report.sarif",
        "verdicts": run.root / "verdicts.json",
    }
    output = run.root / "manifest.json"

    write_manifest(
        run=run,
        findings=[finding],
        verifications=[verify_finding(finding)],
        artifact_paths=artifacts,
        path=output,
        stages={"requested": ["static", "map", "regress"], "completed": ["static", "map", "regress"], "skipped": []},
        worth_fixing={
            "count": 1,
            "verdicts": [{"path": "app.py", "function_name": "admin", "verdict": "triggerable", "reason": "crash"}],
        },
    )

    payload = json.loads(output.read_text())
    assert payload["stages"]["completed"] == ["static", "map", "regress"]
    assert payload["worth_fixing"]["count"] == 1
    assert payload["worth_fixing"]["verdicts"][0]["verdict"] == "triggerable"


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


def _pattern_finding(rule: str, path: str, line: int) -> StaticFinding:
    from dataclasses import replace

    base = _finding()
    return replace(base, finding_id=f"{rule}:{path}:{line}", path=path, line=line, title=f"{rule} needs review")


def test_a_pattern_rule_with_many_sites_is_summarised_not_repeated(tmp_path: Path) -> None:
    """contributor-scan 2.11. libpng emitted 198 sections, 163 of them asserting that `memcpy` and `strcpy`
    are PRESENT in a library that uses them correctly throughout. That is the noise developers have learned
    to skip in every other tool, and shipping it costs the findings beside it their credibility."""
    crowded = [_pattern_finding("c-unsafe-copy", f"src/f{i}.c", i) for i in range(20)]
    output = tmp_path / "report.md"

    write_markdown_report(crowded, output)

    text = output.read_text()
    assert "## Pattern matches" in text
    assert "20 site(s) across 20 file(s)" in text
    assert text.count("## c-unsafe-copy needs review") == 0, "twenty sections for one rule is the noise"
    assert "`findings.json`" in text, "counted, never dropped"


def test_a_pattern_rule_with_few_sites_keeps_its_sections(tmp_path: Path) -> None:
    """One `python-flask-debug` is a finding a contributor can act on, and must not be summarised away."""
    output = tmp_path / "report.md"

    write_markdown_report([_pattern_finding("python-flask-debug", "app.py", 17)], output)

    text = output.read_text()
    assert "## python-flask-debug needs review" in text
    assert "## Pattern matches" not in text


def test_a_reasoned_claim_keeps_its_section_whatever_its_rung(tmp_path: Path) -> None:
    """An obligation or model finding sits at `suspicion` too, but it is a claim about a site rather than an
    observation that an API exists. Twenty of them are twenty findings, not one property of the codebase."""
    from dataclasses import replace

    base = _finding()
    reasoned = [
        replace(base, finding_id=f"obligation:protected_read:api/u.py:{i}", evidence_level="suspicion", path="api/u.py", line=i)
        for i in range(20)
    ]
    output = tmp_path / "report.md"

    write_markdown_report(reasoned, output)

    assert output.read_text().count(f"## {base.title}") == 20
