"""authorization-obligations task 1.3: obligation shapes travel through the existing exporter and store."""

from __future__ import annotations

from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import PairCase
from openultrasast.semantic.mechanisms import MechanismStore

VULN = (
    "from flask import request\n\n\ndef get_book(book_title):\n"
    "    resp = token_validator(request.headers.get('Authorization'))\n    if 'error' in resp:\n        return None\n"
    "    book = Book.query.filter_by(book_title=book_title).first()\n    return book\n"
)
FIXED = (
    "from flask import request\n\n\ndef get_book(book_title):\n"
    "    resp = token_validator(request.headers.get('Authorization'))\n    if 'error' in resp:\n        return None\n"
    "    user = User.query.filter_by(username=resp['sub']).first()\n"
    "    book = Book.query.filter_by(user=user, book_title=book_title).first()\n    return book\n"
)
FLOW_VULN = "from flask import request\nimport os\n\n\ndef run():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n"
FLOW_FIXED = (
    "from flask import request\nimport os\n\n\ndef run():\n    cmd = request.args.get('cmd')\n"
    + "    if cmd not in ALLOWED:\n        return None\n    os.system(cmd)\n"
)


def _case(
    tmp_path: Path, name: str, vuln: str, fixed: str, *, function: str, mechanism: str, tier: str = "seeded", sink: str | None = None
) -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(vuln)
    (tmp_path / f"{name}-f.py").write_text(fixed)
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-639", vulnerability_class="x", path="app.py", evidence="", function=function, mechanism=mechanism, sink=sink
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        provenance="human",
        review_tier=tier,
        reviewer="t" if tier == "reviewed" else "",
    )


def test_exporter_writes_obligation_rows_deduped_with_provenance_and_skips_untrusted(tmp_path: Path) -> None:
    from openultrasast.semantic.obligations.shapes import obligation_mechanisms
    from openultrasast.semantic.seed import export_mechanisms

    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    cases = [
        _case(tmp_path, "a", VULN, FIXED, function="get_book", mechanism="missing_auth_guard"),
        _case(
            tmp_path,
            "b",
            VULN.replace("book", "item"),
            FIXED.replace("book", "item"),
            function="get_item",
            mechanism="missing_auth_guard",
            tier="reviewed",
        ),
        _case(tmp_path, "advisory", VULN, FIXED, function="get_book", mechanism="missing_auth_guard", tier="advisory"),
        _case(tmp_path, "flow", FLOW_VULN, FLOW_FIXED, function="run", mechanism="source_reaches_sink", sink="os.system"),
    ]
    report = export_mechanisms(cases, store)
    rows = store.load()
    obligations = obligation_mechanisms(rows)
    assert len(obligations) == 1 and obligations[0].pairs == ("a", "b") and obligations[0].origin == "corpus"
    assert (
        obligations[0].shape is not None
        and obligations[0].shape["family"] == "obligation"
        and obligations[0].guard == "identity_constraint"
    )
    sinks = [r for r in rows if r.shape and r.shape.get("family", "sink") != "obligation"]
    assert len(sinks) == 1 and sinks[0].shape is not None and sinks[0].shape["sink_name"] == "system"  # flow rows unaffected
    assert report.seeded == 3 and dict(report.skipped)["advisory"] == "tier:advisory"
    text = (tmp_path / "mechanisms.jsonl").read_text()
    assert "book_title" not in text and "resp" not in text and "app.py" not in text


def test_absence_pair_without_a_lesson_is_skipped_with_the_derivation_reason(tmp_path: Path) -> None:
    from openultrasast.semantic.seed import export_mechanisms

    store = MechanismStore(tmp_path / "m.jsonl")
    report = export_mechanisms([_case(tmp_path, "same", VULN, VULN, function="get_book", mechanism="missing_auth_guard")], store)
    assert store.load() == () and dict(report.skipped)["same"].startswith("no_discharger_added:identity_constraint")


def test_sink_search_ignores_obligation_rows(tmp_path: Path) -> None:
    from openultrasast.preprocess import preprocess_repository
    from openultrasast.semantic.facts import load_facts
    from openultrasast.semantic.seed import export_mechanisms
    from openultrasast.semantic.variant_search import search_tree

    store = MechanismStore(tmp_path / "m.jsonl")
    export_mechanisms([_case(tmp_path, "a", VULN, FIXED, function="get_book", mechanism="missing_auth_guard")], store)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "views.py").write_text(VULN)
    _, targets = preprocess_repository(repo)
    result = search_tree(repo, targets, store, load_facts(), max_mechanisms=500)
    assert result.mechanisms_searched == 0 and result.hits == () and result.degradations == ()


def test_real_vibe_py_absence_pairs_seed_at_least_one_obligation_shape(tmp_path: Path) -> None:
    from openultrasast.pairs import load_pair_catalog, select_slice, select_vendored
    from openultrasast.semantic.obligations.shapes import obligation_mechanisms
    from openultrasast.semantic.seed import export_mechanisms

    store = MechanismStore(tmp_path / "m.jsonl")
    report = export_mechanisms(select_vendored(select_slice(load_pair_catalog(), "vibe-py")), store)
    rows = obligation_mechanisms(store.load())
    assert rows and any("vampi-books-get-by-title" in r.pairs and "vampi-users-update-password" in r.pairs for r in rows)
    vampi = next(r for r in rows if "vampi-books-get-by-title" in r.pairs)
    assert vampi.shape is not None
    assert (vampi.shape["operation_kind"], vampi.shape["discharger_kind"], vampi.shape["provenance"], vampi.shape["resource_class"]) == (
        "protected_read",
        "identity_constraint",
        "authenticated_context",
        "owned",
    )
    assert all(
        r.shape is not None and r.shape["operation_kind"] in {"protected_read", "protected_write", "privileged_action", "security_setting"}
        for r in rows
    )
    flow_rows = [r for r in store.load() if r.shape is not None and r.shape.get("family", "sink") == "sink"]
    assert report.records == len(flow_rows) + len(rows) and len(flow_rows) >= 1  # both families, nothing lost to the other


def test_absence_row_without_an_obligation_lesson_still_teaches_its_sink_shape(tmp_path: Path) -> None:
    """The fallback that keeps the flow store unchanged: a `missing_auth_guard` row whose twin adds no discharger but whose
    labeled sink call carries a source still seeds a sink shape (the threatbyte pairs do exactly this)."""
    from openultrasast.semantic.obligations.shapes import obligation_mechanisms
    from openultrasast.semantic.seed import export_mechanisms

    vuln = (
        "import sqlite3\n\n\ndef get(user_id):\n    cur = sqlite3.connect('x').cursor()\n"
        "    cur.execute('SELECT * FROM users WHERE id = ' + user_id)\n    return cur.fetchone()\n"
    )
    fixed = (
        "import sqlite3\n\n\ndef login(username):\n    cur = sqlite3.connect('x').cursor()\n"
        "    cur.execute('SELECT * FROM users WHERE name = ?', (username,))\n    return cur.fetchone()\n"
    )
    store = MechanismStore(tmp_path / "m.jsonl")
    report = export_mechanisms([_case(tmp_path, "tb", vuln, fixed, function="get", mechanism="missing_auth_guard", sink="execute")], store)
    rows = store.load()
    assert report.seeded == 1 and obligation_mechanisms(rows) == ()
    assert len(rows) == 1 and rows[0].shape is not None and rows[0].shape.get("family", "sink") == "sink"
    assert rows[0].shape["sink_name"] == "execute"
