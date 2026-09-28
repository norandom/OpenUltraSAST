from pathlib import Path

import pytest

from openultrasast.hunter_tools import PathEscapesRepo, clamp_repo_path, find_refs, grep_repo, read_file
from openultrasast.mapping import EntryPointRecord

SPLIT_SINK = """\
term = request.args["q"]
query = "select * from items where title like '%" + term + "%'"
return db.execute(query)
"""


def _repo_with_split_sink(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(SPLIT_SINK)
    return root


def test_read_grep_and_reject_path_escape(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)

    source = read_file(root, "app.py", max_chars=4000)
    assert "query =" in source
    assert "db.execute(query)" in source

    matches = grep_repo(root, r"query\s*=", max_matches=10)
    assert matches
    assert matches[0]["path"] == "app.py"
    assert matches[0]["line"] == 2
    assert "query =" in str(matches[0]["text"])

    with pytest.raises(PathEscapesRepo):
        read_file(root, "../etc/passwd", max_chars=100)


def test_clamp_repo_path_rejects_dotdot_and_absolute_escapes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("ok\n")

    assert clamp_repo_path(root, "app.py") == (root / "app.py").resolve()

    with pytest.raises(PathEscapesRepo):
        clamp_repo_path(root, "../etc/passwd")
    with pytest.raises(PathEscapesRepo):
        clamp_repo_path(root, "/etc/passwd")
    with pytest.raises(PathEscapesRepo):
        clamp_repo_path(root, "..")


def test_grep_repo_does_not_search_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text('query = "inside"\n')
    (tmp_path / "outside.py").write_text('query = "outside"\n')

    matches = grep_repo(root, r"query\s*=", max_matches=10)

    assert [match["path"] for match in matches] == ["app.py"]
    assert all("outside" not in str(match["text"]) for match in matches)


def test_grep_repo_honors_max_matches(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("sink = 1\nsink = 2\nsink = 3\n")

    matches = grep_repo(root, r"sink\s*=", max_matches=2)

    assert len(matches) == 2
    assert [match["line"] for match in matches] == [1, 2]


def test_read_file_truncates_and_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("abcdef")
    (root / "link.py").symlink_to("/etc/passwd")

    assert read_file(root, "app.py", max_chars=3) == "abc"
    with pytest.raises(PathEscapesRepo):
        read_file(root, "link.py", max_chars=100)


def test_find_refs_uses_mapping_index_and_clamped_text_search(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)
    mapping_index = [
        {"path": "app.py", "name": "query", "line": 2},
        EntryPointRecord(
            path="app.py",
            line=3,
            end_line=3,
            function_name="search",
            name="search",
            kind="route",
            access_level="public",
            trust_boundary="http_request",
            access_evidence=[],
            conditions=[],
            provenance="test",
            rationale="fixture",
        ),
    ]

    query_refs = find_refs(root, "query", mapping_index)
    assert any(ref["path"] == "app.py" and ref["name"] == "query" for ref in query_refs)
    assert any(ref.get("source") == "mapping" for ref in query_refs)
    assert any(ref.get("source") == "text" and "query" in str(ref.get("text", ref.get("name", ""))) for ref in query_refs)

    search_refs = find_refs(root, "search", mapping_index)
    assert any(ref["path"] == "app.py" and ref["name"] == "search" for ref in search_refs)


def test_find_refs_rejects_mapping_path_escape(tmp_path: Path) -> None:
    root = _repo_with_split_sink(tmp_path)

    with pytest.raises(PathEscapesRepo):
        find_refs(root, "passwd", [{"path": "../etc/passwd", "name": "passwd"}])
    with pytest.raises(PathEscapesRepo):
        find_refs(root, "passwd", [{"path": "/etc/passwd", "name": "passwd"}])


def test_grep_reads_the_tree_once_and_sees_an_edit(tmp_path, monkeypatch) -> None:
    """Every call re-enumerated and re-read the repository; now once per root state, re-validated per file."""
    import os

    from openultrasast import hunter_tools

    sub = tmp_path / "pkg"
    sub.mkdir()
    source = sub / "app.py"
    source.write_text("def run(q):\n    return query(q)\n")
    calls = []
    real = hunter_tools._iter_clamped_source_files
    monkeypatch.setattr(hunter_tools, "_iter_clamped_source_files", lambda root: calls.append(root) or real(root))
    assert [m["line"] for m in hunter_tools.grep_repo(tmp_path, r"query\(", max_matches=5)] == [2]
    assert [m["line"] for m in hunter_tools.grep_repo(tmp_path, r"def run", max_matches=5)] == [1]
    assert len(calls) == 1, "the tree was enumerated again for an unchanged root"
    source.write_text("def run(q):\n    x = 1\n    return query(q)\n")
    stamp = source.stat().st_mtime_ns + 10_000_000
    os.utime(source, ns=(stamp, stamp))
    assert [m["line"] for m in hunter_tools.grep_repo(tmp_path, r"query\(", max_matches=5)] == [3], "a stale read survived an edit"
