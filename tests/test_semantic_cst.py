"""Extra-on CST walker and overlay. Skips when wheels are absent."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.findings import quick_scan_findings
from openultrasast.preprocess import preprocess_repository
from openultrasast.rank import rank_targets
from openultrasast.semantic import adjudicate, has_semantic_extra
from openultrasast.semantic.ir import parse_file

pytestmark = pytest.mark.semantic


def _require_extra() -> None:
    if not has_semantic_extra():
        pytest.skip("requires openultrasast[semantic]")


def test_javascript_eval_query_is_tree_sitter_call() -> None:
    _require_extra()
    ir = parse_file("app.js", "eval(req.query.x)\n", "javascript")
    assert ir.parse_ok is True
    assert ir.engine == "tree-sitter"
    calls = [call for function in ir.functions for call in function.calls]
    eval_calls = [call for call in calls if call.name == "eval"]
    assert eval_calls
    assert any("req.query" in arg for arg in eval_calls[0].arg_texts)


def test_broken_javascript_is_parse_failed() -> None:
    _require_extra()
    ir = parse_file("app.js", "eval(req.query.x\n", "javascript")
    assert ir.parse_ok is False
    assert ir.reason == "parse_failed"


def test_javascript_eval_promotes(tmp_path: Path) -> None:
    _require_extra()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.js").write_text("eval(req.query.x)\n")
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings)
    eval_records = [record for record in records if "js-eval" in record.proposal_id]
    assert eval_records
    assert eval_records[0].disposition == "promote"
    assert eval_records[0].evidence_level == "static_corroboration"
    assert eval_records[0].engine == "tree-sitter"


def test_c_constant_system_demotes(tmp_path: Path) -> None:
    _require_extra()
    root = tmp_path / "repo"
    root.mkdir()
    (root / "run.c").write_text('void f(void) { system("ls"); }\n')
    _, targets = preprocess_repository(root)
    findings = quick_scan_findings(root, targets, rank_targets(targets))
    records = adjudicate(root=root, targets=targets, findings=findings)
    hits = [record for record in records if record.path == "run.c"]
    assert hits
    assert all(record.disposition != "unadjudicated" or record.reason != "language_unsupported" for record in hits)
    demoted = [record for record in hits if record.disposition == "demote"]
    assert demoted
    assert demoted[0].dominating_fact == "constant"
    assert demoted[0].evidence_level == "static_corroboration"
