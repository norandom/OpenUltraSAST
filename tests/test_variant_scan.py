"""corpus-seeded-mechanisms task 2.3: variant findings in a standard scan, sandbox-eligible, counted in the manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair

VARIANT = "import os\nfrom flask import request\n\n\ndef handler():\n    q = request.args.get('q')\n    os.system(q)\n"
UNSEEN_SINK = (
    "from shelltools import run_shell\n\n\ndef handler(q):\n    run_shell(q)\n"  # a project helper: no inventory rule, no fact sink
)


def _seed(repo: Path) -> str:
    from openultrasast.semantic.variants import Shape

    shape = Shape(
        language="python",
        sink_name="run_shell",
        arity=1,
        source_positions=(0,),
        source_kinds=("parameter",),
        guard="allowlist_test",
        mechanism="source_reaches_sink",
    )
    store = MechanismStore(repo / ".openultrasast" / "calibration" / "mechanisms.jsonl")
    return append_from_pair(
        store, shape, summary="parameter into run_shell; fix adds allowlist", cwe="CWE-78", pair="p1", provenance="human", tier="seeded"
    ).id


def _latest_run(repo: Path) -> Path:
    runs = sorted((repo / ".runs").iterdir())
    return runs[-1]


def test_standard_scan_emits_variant_findings_and_manifest_counters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(UNSEEN_SINK)  # only the learned shape can find a project-specific sink
    mechanism_id = _seed(repo)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    run_dir = _latest_run(repo)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    variant = [f for f in findings if f["finding_id"].startswith("variant:")]
    assert len(variant) == 1 and variant[0]["finding_id"] == f"variant:{mechanism_id}:app.py:5"
    assert variant[0]["evidence_level"] == "suspicion" and f"mechanism:{mechanism_id}" in variant[0]["tags"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["variants"] == {"mechanisms_searched": 1, "files_searched": 1, "findings": 1, "merged_into_overlay": 0}


def test_variant_hit_merges_into_an_overlay_flow_at_the_same_call_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.semantic.variants import Shape

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(VARIANT)  # os.system is both an inventory rule and a fact sink: the overlay records the flow
    shape = Shape(
        language="python",
        sink_name="system",
        arity=1,
        source_positions=(0,),
        source_kinds=("fact_source",),
        guard="none",
        mechanism="source_reaches_sink",
    )
    record = append_from_pair(
        MechanismStore(repo / ".openultrasast" / "calibration" / "mechanisms.jsonl"),
        shape,
        summary="s",
        cwe="CWE-78",
        pair="p",
        provenance="human",
        tier="seeded",
    )
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    run_dir = _latest_run(repo)
    overlay = json.loads((run_dir / "overlay.json").read_text())["records"]
    assert any(item["mechanism_id"] == record.id and item["line"] == 7 for item in overlay)
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    assert not any(f["finding_id"].startswith("variant:") for f in findings)  # merged, not duplicated
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["variants"]["merged_into_overlay"] == 1 and manifest["variants"]["findings"] == 0
    # Req 6.1 end to end: the merged inventory finding names the mechanism in both reports and keeps its own evidence level
    report = (run_dir / "report.md").read_text()
    assert f"- Mechanism: `{record.id}`" in report and "- Learned from pairs: `p`" in report
    sarif = json.loads((run_dir / "report.sarif").read_text())
    props = [item["properties"] for item in sarif["runs"][0]["results"] if item["properties"].get("mechanism_id") == record.id]
    assert props and props[0]["mechanism_guard"] == "none" and props[0]["evidence_level"] != "suspicion"


def test_quick_scan_never_searches_variants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(UNSEEN_SINK)
    _seed(repo)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    run_dir = _latest_run(repo)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert "variants" not in manifest
    assert not any(f["finding_id"].startswith("variant:") for f in json.loads((run_dir / "findings.json").read_text())["findings"])


def test_deep_scan_offers_variant_findings_to_the_sandbox_after_promotions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast import cli
    from openultrasast.sandbox import FakeSandboxRunner, SandboxResult

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(UNSEEN_SINK)
    mechanism_id = _seed(repo)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "1")
    fake = FakeSandboxRunner(SandboxResult(exit_code=0, stdout="", stderr="", timed_out=False))
    monkeypatch.setattr(cli, "resolve_sandbox_runner", lambda: fake)
    assert main(["scan", str(repo), "--mode", "deep"]) == 0
    run_dir = _latest_run(repo)
    verdicts = json.loads((run_dir / "verdicts.json").read_text())["verdicts"]
    offered = {finding_id for item in verdicts for finding_id in item["inventory_finding_ids"]}
    assert f"variant:{mechanism_id}:app.py:5" in offered
