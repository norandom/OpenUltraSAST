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
