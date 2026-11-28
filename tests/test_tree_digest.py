"""The key of the ledger a scan keeps for a tree it could not write into: a digest of the tree's files
(contributor-scan, the design note of 2026-11-27 approved on 2026-11-28)."""

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from openultrasast.tree_digest import tree_digest


def _write(root: Path, relative: str, content: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Two source files, a file under an ignored directory and a link to a source file."""
    root = tmp_path / "tree"
    _write(root, "app.py", b"print('hello')\n")
    _write(root, "pkg/lib.py", b"def helper(x):\n    return eval(x)\n")
    _write(root, ".git/config", b"[core]\n")
    _write(root, "node_modules/x/index.js", b"module.exports = 1;\n")
    (root / "link.py").symlink_to("app.py")
    return root


def test_the_same_bytes_give_the_same_digest_and_one_changed_byte_another(tmp_path: Path, tree: Path) -> None:
    twin = tmp_path / "twin"
    shutil.copytree(tree, twin, symlinks=True)
    digest = tree_digest(tree)

    assert tree_digest(twin) == digest
    assert len(digest) == 64
    int(digest, 16)

    _write(twin, "pkg/lib.py", b"def helper(x):\n    return eval(x) \n")

    assert tree_digest(twin) != digest


def test_links_and_the_ignored_directories_are_left_out(tmp_path: Path, tree: Path) -> None:
    """The ledger lives under `.openultrasast`: a ledger must not change its own key."""
    before = tree_digest(tree)

    (tree / "link.py").unlink()
    _write(tree, "node_modules/y/index.js", b"module.exports = 2;\n")
    _write(tree, "__pycache__/app.cpython-311.pyc", b"\x00")
    _write(tree, ".openultrasast/calibration/false_positive_learnings.json", b'{"learnings": []}\n')

    assert tree_digest(tree) == before


def test_the_runs_directory_is_left_out_whichever_way_it_is_reached(tmp_path: Path, tree: Path) -> None:
    runs = _write(tree / "cache" / "runs" / "20260101T000000Z-00000000", "manifest.json", b"{}").parents[1]
    (tree / "alias").symlink_to(runs, target_is_directory=True)
    before = tree_digest(tree, runs)

    _write(runs / "20260102T000000Z-00000000", "manifest.json", b"{}")

    assert tree_digest(tree, runs) == before
    assert tree_digest(tree) != before


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists every directory and reads every file")
def test_a_file_that_cannot_be_read_and_a_directory_that_cannot_be_listed_are_named_not_skipped(tmp_path: Path, tree: Path) -> None:
    before = tree_digest(tree)
    secret = _write(tree, "pkg/secret.py", b"x = 1\n")
    with_secret = tree_digest(tree)
    secret.chmod(0)
    unreadable = tree_digest(tree)
    hidden = _write(tree / "hidden", "a.py", b"a = 1\n").parent
    hidden.chmod(0)

    assert (with_secret, unreadable) != (before, before)
    assert tree_digest(tree) not in (before, with_secret, unreadable)


def test_a_change_of_mode_leaves_the_digest_and_a_change_of_line_endings_gives_another(tmp_path: Path, tree: Path) -> None:
    before = tree_digest(tree)

    (tree / "app.py").chmod(0o600)

    assert tree_digest(tree) == before

    _write(tree, "app.py", b"print('hello')\r\n")

    assert tree_digest(tree) != before


def test_a_name_cannot_spell_two_entries(tmp_path: Path) -> None:
    """One file whose name holds what would be the first entry of a two-file tree, and the next path."""
    two = tmp_path / "two"
    _write(two, "a", b"one")
    _write(two, "b", b"two")
    one = tmp_path / "one"
    _write(one, f"a\t{hashlib.sha256(b'one').hexdigest()}\nb", b"two")

    assert tree_digest(one) != tree_digest(two)


@pytest.mark.skipif(os.geteuid() == 0, reason="root searches every directory")
def test_a_directory_that_can_be_listed_but_not_searched_stops_the_digest(tmp_path: Path, tree: Path) -> None:
    """As the scan's own reading of the tree stops: a digest that skipped it would key a ledger to a tree
    nobody scanned."""
    locked = _write(tree / "locked", "a.py", b"a = 1\n").parent
    locked.chmod(0o444)

    with pytest.raises(PermissionError):
        tree_digest(tree)
