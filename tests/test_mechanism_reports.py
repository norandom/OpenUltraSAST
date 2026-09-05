"""corpus-seeded-mechanisms task 5.1: reports name the mechanism, the known fix guard, and the pair provenance."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.findings import StaticFinding
from openultrasast.reports import write_markdown_report, write_sarif_report
from openultrasast.semantic.overlay import OverlayRecord


def _variant() -> StaticFinding:
    return StaticFinding(
        finding_id="variant:corpus:abc:app.py:5",
        path="app.py",
        title="Variant of known mechanism: run_shell",
        severity="medium",
        confidence="low",
        evidence_level="suspicion",
        rationale="parameter into run_shell; fix adds allowlist_test. Structural variant of a mechanism learned from p1, p2.",
        line=5,
        function_name="handler",
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["variant", "mechanism:corpus:abc"],
        ranking_priority=0.0,
    )


MECHANISMS = {
    "corpus:abc": {
        "summary": "source_reaches_sink: parameter into run_shell (CWE-78); fix adds allowlist_test",
        "guard": "allowlist_test",
        "pairs": ["p1", "p2"],
        "cwe": "CWE-78",
    }
}


def test_markdown_names_mechanism_guard_and_provenance_and_keeps_the_suspicion_label(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    write_markdown_report([_variant()], path, mechanisms=MECHANISMS)
    text = path.read_text()
    assert "- Mechanism: `corpus:abc`" in text
    assert "source_reaches_sink: parameter into run_shell" in text
    assert "- Known fix guard: `allowlist_test`" in text
    assert "- Learned from pairs: `p1, p2`" in text
    assert "- Evidence level: `suspicion`" in text
    assert "## Mechanisms" in text  # a section summarising every mechanism the report cites


def test_sarif_carries_mechanism_properties_for_variant_and_merged_overlay_findings(tmp_path: Path) -> None:
    merged = OverlayRecord(
        proposal_id="python-os-command:app.py:9",
        path="app.py",
        line=9,
        disposition="promote",
        reason="request reaches os.system",
        cwe="CWE-78",
        sources=("request",),
        sinks=("os.system",),
        sanitizers=(),
        evidence_level="static_corroboration",
        origin="inventory",
        engine="python-ast",
        language="python",
        mechanism_id="corpus:abc",
    )
    inventory = StaticFinding(
        **{
            **_variant().__dict__,
            "finding_id": "python-os-command:app.py:9",
            "line": 9,
            "tags": ["injection"],
            "evidence_level": "static_corroboration",
        }
    )
    path = tmp_path / "report.sarif"
    write_sarif_report([_variant(), inventory], [], path, overlay=[merged], mechanisms=MECHANISMS)
    results = json.loads(path.read_text())["runs"][0]["results"]
    by_id = {item["properties"]["finding_id"]: item["properties"] for item in results}
    variant = by_id["variant:corpus:abc:app.py:5"]
    assert (
        variant["mechanism_id"] == "corpus:abc"
        and variant["mechanism_guard"] == "allowlist_test"
        and variant["mechanism_pairs"] == ["p1", "p2"]
    )
    assert variant["evidence_level"] == "suspicion"
    merged_props = by_id["python-os-command:app.py:9"]
    assert merged_props["mechanism_id"] == "corpus:abc" and merged_props["mechanism_guard"] == "allowlist_test"  # from the overlay record


def test_reports_without_mechanisms_are_unchanged(tmp_path: Path) -> None:
    plain = StaticFinding(**{**_variant().__dict__, "finding_id": "python-os-command:app.py:9", "tags": ["injection"]})
    path = tmp_path / "report.md"
    write_markdown_report([plain], path)
    text = path.read_text()
    assert "Mechanism:" not in text and "## Mechanisms" not in text


def test_standard_scan_report_names_the_mechanism_behind_a_variant_finding(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from openultrasast.cli import main
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.variants import Shape

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("from shelltools import run_shell\n\n\ndef handler(q):\n    run_shell(q)\n")
    shape = Shape(
        language="python",
        sink_name="run_shell",
        arity=1,
        source_positions=(0,),
        source_kinds=("parameter",),
        guard="allowlist_test",
        mechanism="source_reaches_sink",
    )
    record = append_from_pair(
        MechanismStore(repo / ".openultrasast" / "calibration" / "mechanisms.jsonl"),
        shape,
        summary="parameter into run_shell",
        cwe="CWE-78",
        pair="p1",
        provenance="human",
        tier="seeded",
    )
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    monkeypatch.setenv("OPENULTRASAST_SANDBOX_PROBE", "0")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    run_dir = sorted((repo / ".runs").iterdir())[-1]
    report = (run_dir / "report.md").read_text()
    assert (
        f"- Mechanism: `{record.id}`" in report
        and "- Known fix guard: `allowlist_test`" in report
        and "- Learned from pairs: `p1`" in report
    )
    sarif = json.loads((run_dir / "report.sarif").read_text())
    props = [item["properties"] for item in sarif["runs"][0]["results"] if item["properties"]["finding_id"].startswith("variant:")]
    assert props and props[0]["mechanism_guard"] == "allowlist_test" and props[0]["evidence_level"] == "suspicion"
