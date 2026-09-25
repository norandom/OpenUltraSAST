"""`.gitignore` is read with git's own semantics, checked against git itself.

The first reader dropped every `!` line and matched with `fnmatch`, whose `*` crosses `/`. YesWiki's
`tools/*` + `!tools/bazar` removed all 583 of its tool PHP files, the vulnerable one among them, and the scan
completed every question it had over the 243 files left -- a clean-looking zero from an unread tree.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from openultrasast.preprocess import _is_ignored, _load_ignore_patterns, enumerate_source_files

GITIGNORE = """\
# YesWiki's shape
tools/*
!tools/README.md
!tools/bazar
!tools/bazar/*
# anchoring, depth, directory-only, double star
/build
cache/
*.min.js
docs/**/generated.py
!keep.min.js
secret?.php
logs/
!logs/keep.php
"""

FILES = [
    "tools/bazar/services/FormManager.php",
    "tools/bazar/FormController.php",
    "tools/attach/attach.php",
    "tools/README.md",
    "build/out.py",
    "src/build/inner.py",
    "cache/x.py",
    "src/cache/y.py",
    "src/app.min.js",
    "keep.min.js",
    "docs/a/b/generated.py",
    "docs/generated.py",
    "secret1.php",
    "secret12.php",
    "logs/keep.php",
    "app.py",
]


def _git_ignored(root: Path, relative: str) -> bool:
    return subprocess.run(["git", "-C", str(root), "check-ignore", "-q", relative], check=False).returncode == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="git is the oracle")
def test_ignore_rules_agree_with_git(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(GITIGNORE)
    for name in FILES:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("x\n")
    rules = _load_ignore_patterns(tmp_path)
    disagreements = {
        name: (_git_ignored(tmp_path, name), _is_ignored(tmp_path, tmp_path / name, rules))
        for name in FILES
        if _git_ignored(tmp_path, name) != _is_ignored(tmp_path, tmp_path / name, rules)
    }
    assert not disagreements, f"(git, ours) per file: {disagreements}"
    assert not _is_ignored(tmp_path, tmp_path / "tools/bazar/services/FormManager.php", rules)


def test_an_export_keeps_what_the_ignore_file_re_includes(tmp_path: Path) -> None:
    """A `git archive` export has no `.git`: the re-included tree must still be read."""
    (tmp_path / ".gitignore").write_text("tools/*\n!tools/bazar\n!tools/bazar/*\n")
    for name in ("tools/bazar/services/FormManager.php", "tools/attach/attach.php", "includes/App.php"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("<?php\n")
    read = {p.relative_to(tmp_path).as_posix() for p in enumerate_source_files(tmp_path)}
    assert read == {"tools/bazar/services/FormManager.php", "includes/App.php"}, read


@pytest.mark.skipif(shutil.which("git") is None, reason="needs a work tree")
def test_a_tracked_file_is_never_ignored(tmp_path: Path) -> None:
    """Git ignores only what it does not track; a committed file under an ignored pattern is source."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "committed.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "gen/committed.py"], check=True)
    (tmp_path / ".gitignore").write_text("gen/\n")
    (tmp_path / "gen" / "untracked.py").write_text("y = 2\n")
    read = {p.relative_to(tmp_path).as_posix() for p in enumerate_source_files(tmp_path)}
    assert read == {"gen/committed.py"}, read
