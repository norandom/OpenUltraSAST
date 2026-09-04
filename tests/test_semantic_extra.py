"""Semantic extra packaging and extra-free overlay parse."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from openultrasast.cli import main
from openultrasast.semantic.extra import grammar_for, has_semantic_extra
from openultrasast.semantic.ir import parse_file


def test_core_dependencies_stay_empty_and_semantic_is_optional() -> None:
    payload = tomllib.loads(Path("pyproject.toml").read_text())
    assert payload["project"]["dependencies"] == []
    extra = payload["project"]["optional-dependencies"]["semantic"]
    joined = " ".join(extra)
    assert "tree-sitter" in joined
    assert "tree-sitter-javascript" in joined
    assert "tree-sitter-c" in joined
    assert "tree-sitter-java" in joined
    assert "semantic:" in " ".join(payload["tool"]["pytest"]["ini_options"]["markers"])


def test_cli_import_does_not_load_tree_sitter(assert_cold_of_harnessx) -> None:  # type: ignore[no-untyped-def]
    proc_code = (
        "import sys\n"
        "import openultrasast.cli\n"
        "leaked = sorted(m for m in sys.modules if m == 'tree_sitter' or m.startswith('tree_sitter_'))\n"
        "assert not leaked, leaked\n"
    )
    assert_cold_of_harnessx(proc_code)


def test_probe_off_yields_no_javascript_grammar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    assert has_semantic_extra() is False
    assert grammar_for("javascript") is None
    ir = parse_file("app.js", "eval(req.query.x)\n", "javascript")
    assert ir.parse_ok is False
    assert ir.reason == "language_unsupported"


def test_standard_javascript_is_unadjudicated_without_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("eval(req.query.x)\n")
    assert main(["scan", str(repo), "--mode", "standard"]) == 0
    run_dir = sorted((repo / ".runs").iterdir())[-1]
    overlay = json.loads((run_dir / "overlay.json").read_text())["records"]
    assert overlay
    assert all(item["disposition"] == "unadjudicated" for item in overlay)
    assert all(item["reason"] in {"language_unsupported", "parse_failed"} for item in overlay)


def test_quick_scan_without_extra_still_inventories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def run():\n    return eval(request.args)\n")
    assert main(["scan", str(repo), "--mode", "quick"]) == 0
    run_dir = sorted((repo / ".runs").iterdir())[-1]
    findings = json.loads((run_dir / "findings.json").read_text())["findings"]
    assert findings
    assert not (run_dir / "overlay.json").exists()
