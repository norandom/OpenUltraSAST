import json
from pathlib import Path

import pytest

from openultrasast.config import load_config
from openultrasast.run import create_scan_run


def _runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The default run root for this test, with the user's cache pointed away from the real one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    return tmp_path / "cache" / "openultrasast" / "runs"


def test_create_scan_run_writes_directories_and_config_under_the_user_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runs = _runs(tmp_path, monkeypatch)
    target = tmp_path / "repo"
    target.mkdir()

    run = create_scan_run(target, load_config(None))

    assert run.root == runs / run.scan_id
    assert (run.root / "preprocess").is_dir()
    recorded = json.loads((run.root / "resolved_config.json").read_text())
    assert recorded["runs_dir"] == str(runs)
    assert run.target == target.resolve()
    assert list(target.iterdir()) == []


def test_a_relative_runs_dir_is_taken_from_the_working_directory_not_the_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    working = tmp_path / "working"
    working.mkdir()
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.chdir(working)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    run = create_scan_run(target, load_config(None))

    assert run.root == working / ".runs" / run.scan_id
    assert list(target.iterdir()) == []


def test_an_absolute_runs_dir_is_used_as_given(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "link"
    link.symlink_to(elsewhere, target_is_directory=True)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(link / "runs"))

    run = create_scan_run(tmp_path, load_config(None))

    assert run.root == link / "runs" / run.scan_id
    assert (elsewhere / "runs" / run.scan_id).is_dir()
