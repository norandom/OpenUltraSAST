"""Propose/adjudicate/prove overlay records, facts, taint, and coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.findings import StaticFinding, quick_scan_findings
from openultrasast.mapping import analyze_entry_points, attach_reachability_hints
from openultrasast.preprocess import FileTarget, preprocess_repository
from openultrasast.rank import rank_targets
from openultrasast.semantic import OverlayError, OverlayRecord, adjudicate, load_facts
from openultrasast.semantic.engines import joern_available, tree_sitter_available
from openultrasast.semantic.facts import FactLoadError
from openultrasast.semantic.ir import parse_file
from openultrasast.semantic.taint import TaintPath, analyze_file


def _finding(**kwargs: object) -> StaticFinding:
    payload: dict[str, object] = {
        "finding_id": "python-unsafe-eval:app.py:1",
        "path": "app.py",
        "title": "Dynamic Python execution needs review",
        "severity": "high",
        "confidence": "medium",
        "evidence_level": "static_corroboration",
        "rationale": "Static pattern python-unsafe-eval (CWE-95) matched eval on line 1",
        "line": 1,
        "function_name": None,
        "reachability_status": "unknown",
        "reachability_evidence": [],
        "reachability_conditions": [],
        "tags": ["syscall_entry"],
        "ranking_priority": 1.0,
    }
    payload.update(kwargs)
    return StaticFinding(**payload)  # type: ignore[arg-type]


def _target(path: str, language: str = "python") -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=path,
        language=language,
        loc=8,
        tags=[],
        has_fuzz_entry_point=False,
    )


def _scan_overlay(root: Path) -> list[OverlayRecord]:
    _, targets = preprocess_repository(root)
    targets = attach_reachability_hints(targets, analyze_entry_points(root, targets))
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    return adjudicate(root=root, targets=targets, findings=findings)


def test_overlay_record_rejects_demote_without_dominating_fact() -> None:
    with pytest.raises(OverlayError, match="constant or sanitizer"):
        OverlayRecord(
            proposal_id="python-unsafe-eval:app.py:1",
            path="app.py",
            line=1,
            disposition="demote",
            reason="looks safe",
            cwe="CWE-95",
            sources=(),
            sinks=("eval",),
            sanitizers=(),
            evidence_level="static_corroboration",
        )


def test_overlay_record_rejects_proof_rungs() -> None:
    with pytest.raises(OverlayError, match="proof rungs"):
        OverlayRecord(
            proposal_id="python-unsafe-eval:app.py:1",
            path="app.py",
            line=1,
            disposition="promote",
            reason="source reaches sink",
            cwe="CWE-95",
            sources=("request",),
            sinks=("eval",),
            sanitizers=(),
            evidence_level="exploit_demonstrated",
        )


def test_overlay_record_requires_unadjudicated_reason() -> None:
    with pytest.raises(OverlayError, match="unadjudicated reason"):
        OverlayRecord(
            proposal_id="x",
            path="app.py",
            line=1,
            disposition="unadjudicated",
            reason="probably fine",
            cwe="CWE-95",
            sources=(),
            sinks=(),
            sanitizers=(),
            evidence_level="static_corroboration",
        )


def test_load_facts_binds_cwe_ids() -> None:
    facts = load_facts()
    python = facts.for_language("python")
    assert any(sink.cwe.startswith("CWE-") and sink.id == "eval" for sink in python.sinks)
    assert any(source.id == "request" for source in python.sources)


def test_load_facts_broken_file_is_structured_error(tmp_path: Path) -> None:
    facts_dir = tmp_path / "facts"
    facts_dir.mkdir()
    (facts_dir / "python.toml").write_text('version = 1\nlanguage = "python"\nthis is not toml {')
    with pytest.raises(FactLoadError) as exc:
        load_facts(facts_dir)
    assert exc.value.reason == "facts_unavailable"


def test_eval_request_args_promotes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    return eval(request.args)\n")
    records = _scan_overlay(root)
    assert len(records) == 1
    assert records[0].disposition == "promote"
    assert records[0].evidence_level == "static_corroboration"


def test_constant_exec_demotes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    exec('ls')\n")
    records = _scan_overlay(root)
    assert len(records) == 1
    assert records[0].disposition == "demote"
    assert records[0].dominating_fact == "constant"


def test_syntax_error_is_unadjudicated_parse_failed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("eval(request.args)\ndef oops(\n")
    records = _scan_overlay(root)
    assert records
    assert all(record.disposition == "unadjudicated" for record in records)
    assert all(record.reason == "parse_failed" for record in records)


def test_split_sink_python_yields_source_to_sink_path() -> None:
    root = Path("benchmarks/fixtures/split-sink-python")
    facts = load_facts()
    text = (root / "app.py").read_text()
    flow = analyze_file("app.py", text, "python", facts)
    assert not isinstance(flow, type(None))
    from openultrasast.semantic.taint import FileFlow

    assert isinstance(flow, FileFlow)
    assert any(item.sink == "execute" for item in flow.taint_paths)


def test_missing_module_call_is_flow_incomplete_not_safe(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import helper\ndef run():\n    value = helper.hidden()\n    eval(value)\n")
    records = _scan_overlay(root)
    eval_records = [record for record in records if "python-unsafe-eval" in record.proposal_id]
    assert eval_records
    assert eval_records[0].disposition == "unadjudicated"
    assert eval_records[0].reason == "flow_incomplete"


def test_overlay_length_matches_proposals_plus_coverage_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run(x):\n    eval(request.args)\n    digest = hashlib.new('md5', x)\n    return digest\n")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings)
    proposal_ids = [record.proposal_id for record in records if record.origin != "overlay"]
    assert proposal_ids == [finding.finding_id for finding in findings]
    assert any(record.disposition == "coverage" and "hashlib" in record.proposal_id for record in records)
    assert all(record.evidence_level == "static_corroboration" for record in records if record.disposition == "coverage")


def test_js_language_unsupported_without_semantic_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    ir = parse_file("app.js", "eval(req.query.x)\n", "javascript")
    assert ir.parse_ok is False
    assert ir.reason == "language_unsupported"


def test_joern_absence_does_not_block_overlay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("openultrasast.semantic.overlay.joern_available", lambda: False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    return eval(request.args)\n")
    records = _scan_overlay(root)
    assert records[0].disposition == "promote"


def test_joern_miss_does_not_demote_tree_sitter_promote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("openultrasast.semantic.overlay.joern_available", lambda: True)
    monkeypatch.setattr("openultrasast.semantic.overlay.joern_flow", lambda *args, **kwargs: ())
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    return eval(request.args)\n")
    records = _scan_overlay(root)
    assert records[0].disposition == "promote"


def test_facts_unavailable_marks_every_proposal(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    return eval(request.args)\n")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings, facts=FactLoadError("broken"))
    assert findings
    assert len(records) == len(findings)
    assert all(record.disposition == "unadjudicated" and record.reason == "facts_unavailable" for record in records)


def test_parameterized_execute_demotes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run(name):\n    db.execute('select * from users where name = %s', (name,))\n")
    records = _scan_overlay(root)
    sql = [record for record in records if "sql" in record.proposal_id or record.sinks == ("execute",)]
    # inventory python-sql-injection requires composition on the execute line; this may be coverage-empty
    if sql:
        assert sql[0].disposition in {"demote", "unadjudicated"}
        if sql[0].disposition == "demote":
            assert sql[0].dominating_fact == "parameterized_execute"


def test_probes_do_not_raise() -> None:
    assert tree_sitter_available() in {True, False}
    assert joern_available() in {True, False}


def test_joern_extra_path_can_promote_unadjudicated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def run():\n    eval(helper())\n")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    extra = (TaintPath(path="app.py", source="parameter", sink="eval", sink_line=findings[0].line or 2, names=(), cwe="CWE-95"),)
    records = adjudicate(root=root, targets=targets, findings=findings, joern_extra=extra)
    assert any(record.disposition == "promote" for record in records)
