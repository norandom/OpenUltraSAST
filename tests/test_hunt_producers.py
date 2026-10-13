"""Checks for repository-only annotations on real local git changes."""

import json
import subprocess

import pytest

from openultrasast import mapping, source
from openultrasast.hunt import producers as module
from openultrasast.hunt.producers import PRODUCERS, Context, candidate_rows, compute_rows
from openultrasast.hunt.table import FeatureTable
from openultrasast.model.taxonomy import FAMILY_IDS


@pytest.fixture
def repository(tmp_path):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    initial = "def first():\n    value = input()\n    return value\n\ndef second():\n    value = first()\n    return value\n"
    (tmp_path / "app.py").write_text(initial)
    (tmp_path / "notes.txt").write_text("GHSA-xxxx-xxxx-xxxx CVE-2024-0001\n")
    (tmp_path / "unknown.zzz").write_text("opaque\n")
    git("add", "app.py", "notes.txt", "unknown.zzz")
    git("commit", "-qm", "initial")
    base = git("rev-parse", "HEAD")
    (tmp_path / "app.py").write_text(initial.replace("return value", "return eval(value)", 1))
    (tmp_path / "unknown.zzz").write_text("opaque changed\n")
    git("add", "app.py", "unknown.zzz")
    git("commit", "-qm", "fix XSS CVE-2024-0001")
    head = git("rev-parse", "HEAD")
    data = {
        "id": "change",
        "repo": "fixture/repo",
        "base": base,
        "head": head,
        "kind": "vulnerability",
        "fold": 1,
        "path": "app.py",
        "function": "second",
        "function_lines": [5, 7],
        "family": "injection",
        "case_id": "verified",
        "advisory": "GHSA-xxxx-xxxx-xxxx",
        "commit_message": "fix XSS CVE-2024-0001",
        "files": [{"path": "app.py", "head_lines": [[3, 3]]}],
    }
    return tmp_path, data


def test_every_column_candidates_and_cached_work(repository, monkeypatch):
    root, change = repository
    calls = []
    real = mapping.analyze_entry_points

    def entries(*args):
        calls.append(1)
        return real(*args)

    monkeypatch.setattr(mapping, "analyze_entry_points", entries)
    candidates = candidate_rows(root, change)
    assert [r["line"] for r in candidates] == [1, 5]
    rows = compute_rows(root, change)
    assert len(calls) == 1
    table = FeatureTable(rows)
    assert len(table.feature_columns()) == 13
    assert [r["label"] for r in rows] == [None, 1]
    first, second = rows
    assert first["feature.diff.hunks"] == [[3, 3]]
    assert first["feature.diff.deletions"] == [] and first["provenance.diff.version"] == "2"
    assert first["feature.diff.distance"] == 2
    assert not first["feature.diff.on_changed_line"]
    assert first["feature.source.function"] == "first"
    assert first["feature.source.span"] == [1, 3]
    assert first["feature.source.callers"] == [["app.py", 6]]
    assert first["feature.source.language"] == "python"
    assert isinstance(first["feature.source.entry_points"], list)
    assert first["feature.semantic.roles"]["input"] == "source"
    assert first["feature.semantic.roles"]["eval"] == "sink"
    assert first["feature.semantic.def_use"]["binds"] == [{"line": 2, "name": "value", "names": ["input"], "call_name": "input"}]
    assert {c["name"] for c in first["feature.semantic.def_use"]["calls"]} == {"input", "eval"}
    assert isinstance(first["feature.semantic.obligations"], list)
    assert [f["id"] for f in first["feature.taxonomy.families"]] == list(FAMILY_IDS)
    assert second["feature.diff.distance"] == 2
    for row in rows:
        for producer in PRODUCERS:
            assert set(producer.columns) <= set(row)
            assert row[f"provenance.{producer.name}.ok"] is True
            assert row[f"provenance.{producer.name}.reason"] is None
            assert row[f"provenance.{producer.name}.version"]
            assert row[f"provenance.{producer.name}.bytes_read"] > 0
    ctx = Context(root, change)
    diff = PRODUCERS[0]
    assert diff.compute(root, change, "app.py", 3, ctx)["feature.diff.on_changed_line"]
    assert diff.compute(root, change, "notes.txt", 1, ctx)["feature.diff.distance"] is None


def test_unsupported_language_is_absent_with_reason(repository):
    root, change = repository
    change = {**change, "kind": "ordinary", "files": [{"path": "unknown.zzz", "head_lines": [[1, 1]]}]}
    rows = compute_rows(root, change)
    assert len(rows) == 1
    assert rows[0]["provenance.semantic.ok"] is False
    assert rows[0]["provenance.semantic.reason"] == "language_unsupported"
    assert all(rows[0][column] is None for column in PRODUCERS[2].columns if column.startswith("feature."))
    assert rows[0]["label"] == 0
    FeatureTable(rows)


def test_planted_advisory_and_commit_text_never_enter_features(repository):
    root, change = repository
    rows = compute_rows(root, change)
    values = json.dumps([{k: v for k, v in row.items() if k.startswith("feature.")} for row in rows])
    for planted in ("GHSA-xxxx-xxxx-xxxx", "CVE-2024-0001", "fix XSS"):
        assert planted not in values


def test_producer_exceptions_are_type_only(repository, monkeypatch):
    root, change = repository

    def failed(*args, **kwargs):
        raise RuntimeError("secret credential")

    monkeypatch.setattr(source, "facts_for", failed)
    row = compute_rows(root, change)[0]
    assert row["provenance.source.reason"] == "RuntimeError"
    assert row["provenance.source.ok"] is False
    assert all(row[c] is None for c in PRODUCERS[1].columns if c.startswith("feature."))
    assert "secret credential" not in json.dumps(row)


def test_range_rejection_retains_row_and_reason(repository, monkeypatch):
    root, change = repository

    def failed(*args):
        raise ValueError("private text")

    monkeypatch.setattr(source, "ranges", failed)
    rows = compute_rows(root, {**change, "kind": "ordinary"})
    assert len(rows) == 1
    assert rows[0]["provenance.source.reason"] == "ValueError"
    assert rows[0]["provenance.source.ok"] is False


def test_private_or_outside_paths_are_not_read(repository):
    root, change = repository
    for path in (".env", "../outside.py"):
        with pytest.raises(ValueError):
            candidate_rows(root, {**change, "files": [{"path": path, "head_lines": [[1, 1]]}]})


def test_head_mismatch_is_not_a_clean_measurement(repository):
    root, change = repository
    rows = compute_rows(root, {**change, "head": change["base"], "kind": "ordinary"})
    assert rows[0]["provenance.diff.ok"] is False
    assert rows[0]["provenance.diff.reason"] == "head_mismatch"


def test_obligation_result_uses_dominance_not_absence_of_findings(repository, monkeypatch):
    root, change = repository
    text = 'from flask import request\n@app.route("/item")\ndef first():\n    return User.query.get(request.args["id"])\n'
    (root / "app.py").write_text(text)
    monkeypatch.setattr(module, "_git", lambda *args: change["head"])
    row = compute_rows(root, {**change, "kind": "ordinary", "files": [{"path": "app.py", "head_lines": [[4, 4]]}]})[0]
    assert row["feature.semantic.obligations"]
    assert row["feature.semantic.obligations"][0]["discharged"] is False


def test_a_removed_guard_anchors_the_function_it_left(tmp_path):
    """Replayed base-to-head, a fix that added a check is a push that removes it: no added line, one deletion anchor."""

    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    check = "    if not user.is_admin:\n        raise PermissionError\n"
    guarded = "def first():\n    return 1\n\n\ndef admin(user):\n" + check + "    return delete_everything()\n"
    (tmp_path / "app.py").write_text(guarded)
    git("add", "app.py")
    git("commit", "-qm", "fix: require admin")
    base = git("rev-parse", "HEAD")
    (tmp_path / "app.py").write_text(guarded.replace(check, ""))
    git("add", "app.py")
    git("commit", "-qm", "unguarded")
    head = git("rev-parse", "HEAD")
    change = {"id": "c", "case_id": "c-1", "repo": "fixture/repo", "base": base, "head": head, "kind": "ordinary", "fold": 1,
              "files": [{"path": "app.py", "head_lines": [[1, 1], [5, 6]]}]}  # fmt: skip
    rows = compute_rows(tmp_path, change)
    row = next(r for r in rows if r["feature.source.function"] == "admin")
    assert row["feature.diff.hunks"] == [] and row["feature.diff.deletions"] == [5]
    assert row["feature.diff.on_changed_line"] and row["feature.diff.distance"] == 0
    first = next(r for r in rows if r["feature.source.function"] == "first")
    assert first["feature.diff.distance"] == 4 and not first["feature.diff.on_changed_line"]
