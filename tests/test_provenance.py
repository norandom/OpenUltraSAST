"""Deterministic provenance fingerprint (pair-corpus-honesty Req 6)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from openultrasast.provenance import AGENT_SHARE_THRESHOLD, fingerprint


def test_empty_tree_is_human_with_no_signals(tmp_path: Path) -> None:
    result = fingerprint(tmp_path, git=False)
    assert result.value == "human"
    assert result.signals == ()


def test_agent_config_file_makes_tree_mixed(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("# agents\n")
    (tmp_path / ".claude").mkdir()
    result = fingerprint(tmp_path, git=False)
    assert result.value == "mixed"
    assert "path:AGENTS.md" in result.signals and "path:.claude" in result.signals


def test_lovable_marker_in_index_html(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text('<html><head><meta name="author" content="Lovable" /></head></html>')
    result = fingerprint(tmp_path, git=False)
    assert result.value == "mixed"
    assert "marker:lovable" in result.signals


def test_git_trailer_share_over_threshold_is_agent(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    for index in range(10):
        (tmp_path / f"f{index}.py").write_text("x = 1\n")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        trailer = "\n\nCo-Authored-By: Claude <noreply@anthropic.com>" if index < 9 else ""
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-q", "-m", f"c{index}{trailer}"], check=True, env={**env, "PATH": "/usr/bin:/bin"}
        )
    result = fingerprint(tmp_path, git=True)
    assert result.sampled_commits == 10 and result.agent_commits == 9
    assert result.agent_commits / result.sampled_commits >= AGENT_SHARE_THRESHOLD
    assert result.value == "agent"
    assert any(signal.startswith("git:trailers") for signal in result.signals)


def test_git_unavailable_is_a_signal_not_an_error(tmp_path: Path) -> None:
    result = fingerprint(tmp_path, git=True)  # tmp_path is not a repository
    assert result.value == "human"
    assert "git:unavailable" in result.signals


def test_scan_never_reports_synthetic(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# claude\n")
    assert fingerprint(tmp_path, git=False).value != "synthetic"
