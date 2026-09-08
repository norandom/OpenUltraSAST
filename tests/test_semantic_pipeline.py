"""MAP overlay, prove filter, reports, pair scoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.cli import main
from openultrasast.complexity.map import Hotspot
from openultrasast.findings import StaticFinding, quick_scan_findings
from openultrasast.gate import LANGUAGE_MANIFESTS
from openultrasast.pairs import PairCase, evaluate_pair, load_pair_catalog
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets
from openultrasast.semantic import OverlayRecord, filter_promoted_hotspots
from openultrasast.semantic.prove_filter import promoted_findings


def _latest_run(repo: Path) -> Path:
    return sorted((repo / ".runs").iterdir())[-1]


def _finding(finding_id: str, path: str = "app.py", line: int = 1) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path=path,
        title="test",
        severity="high",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="Static pattern python-unsafe-eval (CWE-95) matched",
        line=line,
        function_name="run",
        reachability_status="reachable",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["syscall_entry"],
        ranking_priority=1.0,
    )


def _record(proposal_id: str, disposition: str, **kwargs: object) -> OverlayRecord:
    dominating = kwargs.get("dominating_fact")
    sanitizers = kwargs.get("sanitizers", ())
    return OverlayRecord(
        proposal_id=proposal_id,
        path=str(kwargs.get("path", "app.py")),
        line=int(kwargs.get("line", 1)),
        disposition=disposition,
        reason=str(kwargs.get("reason", disposition)),
        cwe=str(kwargs.get("cwe", "CWE-95")),
        sources=tuple(kwargs.get("sources", ())),  # type: ignore[arg-type]
        sinks=tuple(kwargs.get("sinks", ("eval",))),  # type: ignore[arg-type]
        sanitizers=tuple(sanitizers) if isinstance(sanitizers, tuple | list) else (),
        evidence_level="static_corroboration",
        dominating_fact=str(dominating) if dominating else ("constant" if disposition == "demote" else None),
        language=str(kwargs.get("language", "python")),
    )


def _hotspot(*finding_ids: str, score: float = 5.0, path: str = "app.py") -> Hotspot:
    return Hotspot(
        path=path,
        function_name="run",
        score=score,
        band="high",
        signals={},
        rationale="test",
        test_hint=None,
        inventory_finding_ids=finding_ids,
    )


def test_quick_scan_writes_no_overlay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def run():\n    return eval(request.args)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    run_dir = _latest_run(repo)
    assert not (run_dir / "overlay.json").exists()
    report = (run_dir / "report.md").read_text()
    assert "## Overlay" not in report


def test_standard_scan_writes_overlay_without_executing_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def run():\n    return eval(request.args)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    run_dir = _latest_run(repo)
    payload = json.loads((run_dir / "overlay.json").read_text())
    assert payload["records"]
    assert payload["records"][0]["disposition"] == "promote"
    report = (run_dir / "report.md").read_text()
    assert "promoted" in report
    assert "Disposition: `promote`" in report
    sarif = json.loads((run_dir / "report.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["properties"]["disposition"] == "promote"
    assert (run_dir / "manifest.json").read_text()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["artifacts"]["overlay"] == "overlay.json"


def test_prove_filter_drops_demoted_keeps_promoted() -> None:
    promoted_id = "python-unsafe-eval:app.py:2"
    demoted_id = "python-unsafe-eval:app.py:1"
    hotspots = (
        _hotspot(demoted_id, score=9.0),
        _hotspot(promoted_id, score=3.0),
    )
    records = (
        _record(demoted_id, "demote", dominating_fact="constant"),
        _record(promoted_id, "promote", sources=("request",)),
    )
    selected = filter_promoted_hotspots(hotspots, records)
    assert len(selected) == 1
    assert selected[0].inventory_finding_ids == (promoted_id,)
    findings = [_finding(demoted_id, line=1), _finding(promoted_id, line=2)]
    assert [item.finding_id for item in promoted_findings(findings, records)] == [promoted_id]


def test_deep_scan_offers_only_promotions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli
    from openultrasast.sandbox import FakeSandboxRunner, SandboxResult

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def safe():\n    exec('ls')\n\ndef bad():\n    return eval(request.args)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    fake = FakeSandboxRunner(SandboxResult(exit_code=0, stdout="", stderr="", timed_out=False))
    monkeypatch.setattr(cli, "resolve_sandbox_runner", lambda: fake)
    assert main(["scan", str(repo), "--mode", "deep", "--fail-on", "worth-fixing"]) == 0
    run_dir = _latest_run(repo)
    overlay = json.loads((run_dir / "overlay.json").read_text())["records"]
    dispositions = {item["proposal_id"]: item["disposition"] for item in overlay}
    demoted = [key for key, value in dispositions.items() if value == "demote"]
    promoted = [key for key, value in dispositions.items() if value == "promote"]
    assert demoted
    assert promoted
    verdicts = json.loads((run_dir / "verdicts.json").read_text())["verdicts"]
    offered = {finding_id for item in verdicts for finding_id in item["inventory_finding_ids"]}
    assert offered <= set(promoted)
    assert not (offered & set(demoted))


def test_fail_on_worth_fixing_ignores_unadjudicated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "broken.py").write_text("eval(request.args)\ndef oops(\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    assert main(["scan", str(repo), "--mode", "standard", "--fail-on", "worth-fixing"]) == 0
    run_dir = _latest_run(repo)
    overlay = json.loads((run_dir / "overlay.json").read_text())["records"]
    assert overlay
    assert all(item["disposition"] == "unadjudicated" for item in overlay)
    report = (run_dir / "report.md").read_text()
    assert "unadjudicated" in report


def test_unlabeled_messy_tree_has_both_dispositions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "broken.py").write_text("eval(request.args)\ndef oops(\n")
    (repo / "app.py").write_text("def run():\n    return eval(request.args)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    overlay = json.loads((_latest_run(repo) / "overlay.json").read_text())["records"]
    by_path = {}
    for item in overlay:
        by_path.setdefault(item["path"], set()).add(item["disposition"])
    assert "unadjudicated" in by_path["broken.py"]
    assert "promote" in by_path["app.py"]


def test_sast_slice_scores_overlay_not_inventory(tmp_path: Path) -> None:
    vuln = tmp_path / "vuln.py"
    fixed = tmp_path / "fixed.py"
    vuln.write_text("def bad(x):\n    exec(x)\n")
    fixed.write_text("def goodG2B():\n    exec('ls')\n")
    case = PairCase(
        name="synth-overlay-exec",
        slice="sast",
        language="python",
        origin="test",
        vuln_file=vuln,
        fixed_file=fixed,
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-95",
                vulnerability_class="code injection",
                path="app.py",
                evidence="exec",
                rule_id="python-unsafe-eval",
                sink="exec",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
    )
    fix_root = tmp_path / "fix-tree"
    fix_root.mkdir()
    (fix_root / "app.py").write_text(fixed.read_text())
    _, fix_targets = preprocess_repository(fix_root)
    assert quick_scan_findings(fix_root, fix_targets, rank_targets(fix_targets)), "inventory still fires on goodG2B exec"
    outcome = evaluate_pair(case)
    assert outcome.detected_vuln
    assert outcome.silent_fix
    assert outcome.pair_correct


def test_sast_pairs_stay_out_of_language_manifests() -> None:
    listed = {name for names in LANGUAGE_MANIFESTS.values() for name in names}
    leaked = [case.name for case in load_pair_catalog() if case.name in listed]
    assert leaked == []


def test_markdown_report_includes_four_overlay_labels(tmp_path: Path) -> None:
    from openultrasast.reports import write_markdown_report

    finding = _finding("python-unsafe-eval:app.py:1")
    records = (
        _record("python-unsafe-eval:app.py:1", "promote", sources=("request",)),
        _record("python-unsafe-eval:b.py:1", "demote", path="b.py", dominating_fact="constant"),
        OverlayRecord(
            proposal_id="python-unsafe-eval:c.py:1",
            path="c.py",
            line=1,
            disposition="unadjudicated",
            reason="parse_failed",
            cwe="CWE-95",
            sources=(),
            sinks=(),
            sanitizers=(),
            evidence_level="static_corroboration",
        ),
        OverlayRecord(
            proposal_id="overlay-coverage:d.py:1:hashlib",
            path="d.py",
            line=1,
            disposition="coverage",
            reason="uninventoried sink hashlib",
            cwe="CWE-327",
            sources=("parameter",),
            sinks=("hashlib",),
            sanitizers=(),
            evidence_level="static_corroboration",
            origin="overlay",
        ),
    )
    output = tmp_path / "report.md"
    write_markdown_report([finding], output, overlay=records)
    text = output.read_text()
    assert "promoted" in text
    assert "demoted" in text
    assert "unadjudicated" in text
    assert "coverage" in text
