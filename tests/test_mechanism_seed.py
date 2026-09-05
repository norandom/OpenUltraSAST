"""corpus-seeded-mechanisms task 2.1: export trusted pairs as mechanism records (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import PairCase, load_pair_catalog, select_slice
from openultrasast.semantic.mechanisms import MechanismStore

VULN = "from flask import request\nimport os\n\n\ndef run():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n"
FIXED = (
    "from flask import request\nimport os\n\nALLOWED = {'ls', 'date'}\n\n\ndef run():\n    cmd = request.args.get('cmd')\n"
    "    if cmd not in ALLOWED:\n        return None\n    os.system(cmd)\n"
)


def _case(tmp_path: Path, name: str, *, tier: str, known_limit: str | None = None, vuln: str = VULN, language: str = "python") -> PairCase:
    ext = {"python": "py", "javascript": "js"}[language]
    (tmp_path / f"{name}-v.{ext}").write_text(vuln)
    (tmp_path / f"{name}-f.{ext}").write_text(FIXED if language == "python" else vuln)
    return PairCase(
        name=name,
        slice="vibe-py",
        language=language,
        origin="test",
        vuln_file=tmp_path / f"{name}-v.{ext}",
        fixed_file=tmp_path / f"{name}-f.{ext}",
        relpath=f"app.{ext}",
        expected=(
            ExpectedFinding(
                cwe="CWE-78",
                vulnerability_class="command injection",
                path=f"app.{ext}",
                evidence="",
                sink="os.system",
                function="run",
                mechanism="source_reaches_sink",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        provenance="human",
        review_tier=tier,
        reviewer="t" if tier == "reviewed" else "",
        known_limit=known_limit,
    )


def test_export_seeds_only_trusted_parsing_pairs_and_reports_every_skip(tmp_path: Path) -> None:
    from openultrasast.semantic.seed import export_mechanisms

    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    cases = [
        _case(tmp_path, "seeded", tier="seeded"),
        _case(tmp_path, "reviewed-twin", tier="reviewed"),
        _case(tmp_path, "advisory", tier="advisory"),
        _case(tmp_path, "title", tier="title"),
        _case(tmp_path, "limit", tier="seeded", known_limit="engine cannot see it"),
        _case(tmp_path, "broken", tier="seeded", vuln="def run(:\n"),
    ]
    report = export_mechanisms(cases, store)
    records = store.load()
    assert len(records) == 1  # seeded and reviewed-twin share one shape: one record, two pairs
    (record,) = records
    assert record.origin == "corpus" and record.pairs == ("seeded", "reviewed-twin") and record.shape is not None
    assert report.seeded == 2 and report.records == 1
    reasons = dict(report.skipped)
    assert reasons["advisory"] == "tier:advisory" and reasons["title"] == "tier:title"
    assert reasons["limit"].startswith("known_limit") and reasons["broken"] == "parse_failed"
    text = (tmp_path / "mechanisms.jsonl").read_text()
    assert "request.args" not in text and "app.py" not in text  # Req 2.4: no code text in the store


def test_export_skips_languages_without_a_grammar_with_a_degradation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.semantic.seed import export_mechanisms

    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    js = "function run(req) {\n  const cmd = req.query.cmd;\n  exec(cmd);\n}\n"
    report = export_mechanisms([_case(tmp_path, "js", tier="seeded", vuln=js, language="javascript")], store)
    assert store.load() == () and dict(report.skipped)["js"] == "variants_language_unsupported"
    assert {"stage": "mechanisms", "reason": "variants_language_unsupported", "language": "javascript"} in report.degradations


def test_export_over_the_vendored_vibe_py_slice_is_offline_and_deterministic(tmp_path: Path) -> None:
    from openultrasast.pairs import select_vendored
    from openultrasast.semantic.seed import export_mechanisms

    cases = select_vendored(select_slice(load_pair_catalog(), "vibe-py"))
    first = export_mechanisms(cases, MechanismStore(tmp_path / "a.jsonl"))
    second = export_mechanisms(cases, MechanismStore(tmp_path / "b.jsonl"))
    assert first.records >= 1 and first.records == second.records
    assert (tmp_path / "a.jsonl").read_text() == (tmp_path / "b.jsonl").read_text()
    assert first.seeded + len(first.skipped) == len(cases)


def test_cli_mechanisms_export_writes_the_store_and_prints_the_report(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from openultrasast.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["mechanisms", "export", "--slice", "vibe-py", "--store", str(tmp_path / "m.jsonl"), "--json"]) == 0
    payload = json.loads(buf.getvalue())
    assert payload["records"] >= 1 and payload["slice"] == "vibe-py" and "skipped" in payload
    assert (tmp_path / "m.jsonl").is_file()
