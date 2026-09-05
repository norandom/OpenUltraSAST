"""corpus-seeded-mechanisms task 3.1: leave-one-out is the corpus's own detection rate (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import PairCase

EXEC_A = (
    "import sqlite3\n\n\ndef lookup(user):\n    c = sqlite3.connect('x').cursor()\n"
    + "    c.execute(\"SELECT * FROM t WHERE u = '%s'\" % user)\n"
)
EXEC_A_FIX = (
    "import sqlite3\n\n\ndef lookup(user):\n    c = sqlite3.connect('x').cursor()\n    c.execute('SELECT * FROM t WHERE u = ?', (user,))\n"
)
EXEC_B = (
    "import sqlite3\n\n\ndef delete(name):\n    cur = sqlite3.connect('y').cursor()\n    cur.execute('DELETE FROM t WHERE n = ' + name)\n"
)
EXEC_B_FIX = (
    "import sqlite3\n\n\ndef delete(name):\n    cur = sqlite3.connect('y').cursor()\n"
    + "    cur.execute('DELETE FROM t WHERE n = ?', (name,))\n"
)
SYS_C = "import os\n\n\ndef ping(host):\n    os.system('ping ' + host)\n"
SYS_C_FIX = "import os\nimport subprocess\n\n\ndef ping(host):\n    subprocess.run(['ping', host])\n"


def _case(tmp_path: Path, name: str, vuln: str, fixed: str, *, function: str, cwe: str, provenance: str = "human") -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(vuln)
    (tmp_path / f"{name}-f.py").write_text(fixed)
    return PairCase(
        name=name,
        slice="toy",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe=cwe, vulnerability_class="x", path="app.py", evidence="", function=function, mechanism="source_reaches_sink"
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        provenance=provenance,
        review_tier="seeded",
    )


def _toy(tmp_path: Path) -> list[PairCase]:
    return [
        _case(tmp_path, "a", EXEC_A, EXEC_A_FIX, function="lookup", cwe="CWE-89"),
        _case(tmp_path, "b", EXEC_B, EXEC_B_FIX, function="delete", cwe="CWE-89", provenance="agent"),
        _case(tmp_path, "c", SYS_C, SYS_C_FIX, function="ping", cwe="CWE-78"),
    ]


def test_leave_one_out_reports_which_pair_taught_which(tmp_path: Path) -> None:
    from openultrasast.semantic.loo import evaluate_loo

    result = evaluate_loo(_toy(tmp_path))
    by_name = {outcome.pair: outcome for outcome in result.outcomes}
    assert set(by_name) == {"a", "b", "c"}
    assert by_name["a"].detected and by_name["a"].silent and by_name["a"].found_by  # taught by b's execute shape
    assert by_name["b"].detected and by_name["b"].silent and any("a" in pairs for _, pairs in by_name["b"].found_by)
    assert not by_name["c"].detected and by_name["c"].found_by == ()  # nobody else teaches os.system: c only tests
    slice_metrics = result.per_slice["toy"]
    assert slice_metrics["pairs"] == 3 and slice_metrics["detected"] == 2 and slice_metrics["silent"] == 3
    assert abs(slice_metrics["recall"] - 2 / 3) < 1e-9 and slice_metrics["silence"] == 1.0 and abs(slice_metrics["youden"] - 2 / 3) < 1e-9
    assert result.per_profile["agent"]["pairs"] == 1 and result.per_profile["human"]["pairs"] == 2
    assert "source_reaches_sink" in result.per_mechanism
    payload = result.to_dict()
    assert set(payload) >= {"per_slice", "per_profile", "per_mechanism", "outcomes"}
    json.dumps(payload)  # artifact-ready


def test_leave_one_out_seeds_only_trusted_pairs_and_skips_known_limit(tmp_path: Path) -> None:
    from openultrasast.semantic.loo import evaluate_loo

    cases = _toy(tmp_path)
    cases[1] = PairCase(**{**cases[1].__dict__, "review_tier": "advisory"})  # b may be tested, never teaches
    cases[2] = PairCase(**{**cases[2].__dict__, "known_limit": "engine"})
    result = evaluate_loo(cases)
    by_name = {outcome.pair: outcome for outcome in result.outcomes}
    assert set(by_name) == {"a", "b"}  # known_limit excluded entirely
    assert not by_name["a"].detected  # b is advisory: it cannot teach a
    assert by_name["b"].detected  # a (seeded) teaches b, which is scored as a held-out target
    assert result.skipped == (("c", "known_limit:engine"),)


def test_cli_pairs_loo_writes_the_artifact_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    from contextlib import redirect_stdout

    from openultrasast.cli import main

    monkeypatch.chdir(Path.cwd())
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["pairs", "--slice", "vibe-py", "--loo", "--json", "--loo-out", str(tmp_path / "loo.json")]) == 0
    payload = json.loads(buf.getvalue())
    assert payload["per_slice"]["vibe-py"]["pairs"] == 35 and "found_by" in payload["outcomes"][0]
    assert json.loads((tmp_path / "loo.json").read_text()) == payload
