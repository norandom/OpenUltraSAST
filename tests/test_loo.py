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


HELPER_SINK = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\ndef ping(host):\n    return run('ping ' + host)\n"
HELPER_SINK_FIX = (
    "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd.split())\n\n\ndef ping(host):\n    return run('ping ' + host)\n"
)


def test_hits_outside_the_labeled_function_or_off_label_never_count(tmp_path: Path) -> None:
    """Round-3 mutants: a hit must sit inside the labeled function and name the labeled mechanism or sink."""
    from openultrasast.semantic.loo import evaluate_loo

    teacher = _case(tmp_path, "t", SYS_C, SYS_C_FIX, function="ping", cwe="CWE-78")
    outside = _case(
        tmp_path, "outside", HELPER_SINK, HELPER_SINK_FIX, function="ping", cwe="CWE-78"
    )  # sink call lives in `run`, not `ping`
    off_label = PairCase(
        **{
            **_case(tmp_path, "offlabel", SYS_C, SYS_C_FIX, function="ping", cwe="CWE-78").__dict__,
            "expected": (
                ExpectedFinding(
                    cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="ping", mechanism="missing_auth_guard"
                ),
            ),
        }
    )
    result = evaluate_loo([teacher, outside, off_label])
    by_name = {outcome.pair: outcome for outcome in result.outcomes}
    assert by_name["outside"].hits_vuln >= 1 and not by_name["outside"].detected
    assert by_name["offlabel"].hits_vuln >= 1 and not by_name["offlabel"].detected


def test_leave_one_out_forwards_search_degradations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.semantic.loo import evaluate_loo

    monkeypatch.setenv("OPENULTRASAST_TREE_SITTER_PROBE", "0")
    js = "function run(req) {\n  const cmd = req.query.cmd;\n  exec(cmd);\n}\n"
    (tmp_path / "j-v.js").write_text(js)
    (tmp_path / "j-f.js").write_text(js)
    case = PairCase(
        **{
            **_toy(tmp_path)[0].__dict__,
            "name": "j",
            "language": "javascript",
            "vuln_file": tmp_path / "j-v.js",
            "fixed_file": tmp_path / "j-f.js",
            "relpath": "app.js",
        }
    )
    result = evaluate_loo([*_toy(tmp_path), case])
    assert any(item["reason"] == "variants_language_unsupported" for item in result.degradations)


# --- authorization-obligations 4.2: leave-one-out per obligation kind -------------------------------------------------

_HANDLER = "from flask import request\n\n\n@app.route('/{route}/<key>')\ndef {fn}(key):\n{body}"
OBL_A = _HANDLER.format(route="books", fn="get_book", body="    return Book.query.filter_by(book_title=key).first()\n")
OBL_A_FIX = _HANDLER.format(
    route="books",
    fn="get_book",
    body="    user_id = request.user.id\n    return Book.query.filter_by(user_id=user_id, book_title=key).first()\n",
)
OBL_B = _HANDLER.format(route="orders", fn="get_order", body="    return Order.query.filter_by(ref=key).first()\n")
OBL_B_FIX = _HANDLER.format(
    route="orders", fn="get_order", body="    owner = current_user.id\n    return Order.query.filter_by(owner=owner, ref=key).first()\n"
)
OBL_C = _HANDLER.format(
    route="login", fn="login", body="    resp = make_response('ok')\n    resp.set_cookie('sid', key, samesite='None')\n    return resp\n"
)
OBL_C_FIX = _HANDLER.format(
    route="login",
    fn="login",
    body="    resp = make_response('ok')\n    resp.set_cookie('sid', key, samesite='Strict', httponly=1)\n    return resp\n",
)


def _obligation_case(tmp_path: Path, name: str, vuln: str, fixed: str, *, function: str, obligation: str, mechanism: str) -> PairCase:
    case = _case(tmp_path, name, vuln, fixed, function=function, cwe="CWE-639")
    row = case.expected[0]
    return PairCase(
        **{
            **case.__dict__,
            "slice": "vibe-py",
            "expected": (ExpectedFinding(**{**row.__dict__, "mechanism": mechanism, "obligation": obligation}),),
        }
    )


def _obligation_toy(tmp_path: Path) -> list[PairCase]:
    read = {"obligation": "protected_read", "mechanism": "unconstrained_protected_read"}
    return [
        _obligation_case(tmp_path, "a", OBL_A, OBL_A_FIX, function="get_book", **read),
        _obligation_case(tmp_path, "b", OBL_B, OBL_B_FIX, function="get_order", **read),
        _obligation_case(tmp_path, "c", OBL_C, OBL_C_FIX, function="login", obligation="security_setting", mechanism="permissive_default"),
    ]


def test_leave_one_out_scores_obligation_rows_per_kind_and_names_the_teaching_pair(tmp_path: Path) -> None:
    """Req 7.4: recall, silence and Youden per obligation kind; found_by names the shape record that supplied known_fix."""
    from openultrasast.semantic.loo import evaluate_loo

    result = evaluate_loo(_obligation_toy(tmp_path))
    by_name = {outcome.pair: outcome for outcome in result.outcomes}
    a, b, c = by_name["a"], by_name["b"], by_name["c"]
    assert a.obligations == ("protected_read",) and c.obligations == ("security_setting",)
    assert a.detected and a.silent and [pairs for _, pairs in a.found_by] == [("b",)]  # b taught the identity discharger
    assert b.detected and b.silent and [pairs for _, pairs in b.found_by] == [("a",)]
    assert all(record_id.startswith("corpus:") for record_id, _ in a.found_by)
    assert c.teaches and not c.detected and c.found_by == () and c.silent  # reached and undischarged, but nobody else teaches the kind
    kinds = result.per_obligation_kind
    assert kinds["protected_read"]["pairs"] == 2 and kinds["protected_read"]["detected"] == 2 and kinds["protected_read"]["youden"] == 1.0
    assert kinds["security_setting"]["pairs"] == 1 and kinds["security_setting"]["detected"] == 0
    assert "unconstrained_protected_read" in result.per_mechanism  # flow mechanisms and obligation kinds sit side by side
    payload = result.to_dict()
    assert "per_obligation_kind" in payload and payload["outcomes"][0]["obligations"] == ["protected_read"]
    json.dumps(payload)


def test_obligation_rows_are_not_found_by_the_facts_alone(tmp_path: Path) -> None:
    """A finding without a known fix from the held-out store is the checker's own work, not the corpus teaching."""
    from openultrasast.semantic.loo import evaluate_loo

    (only,) = [outcome for outcome in evaluate_loo(_obligation_toy(tmp_path)[:1]).outcomes]
    assert only.hits_vuln >= 1 and not only.detected and only.found_by == ()  # the leaky read is flagged, but no pair taught it
