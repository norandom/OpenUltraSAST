"""Where a scan writes (contributor-scan Requirement 5.3): the run goes to the user's cache, and the analysed
tree is left as it was unless the scan has a false positive to remember."""

import errno
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from openultrasast import cli
from openultrasast.cli import main
from openultrasast.config import ResolvedConfig

LEDGER = ".openultrasast/calibration/false_positive_learnings.json"
LEDGER_DIRECTORIES = {".openultrasast", ".openultrasast/calibration"}
LEDGER_UNWRITTEN = {"stage": "record_calibration", "reason": "ledger_not_written"}


def _user_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The default run root for this test, with the user's cache pointed away from the real one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    return tmp_path / "cache" / "openultrasast" / "runs"


def _target(root: Path, *, repository: bool = False, learns: bool = False) -> Path:
    repo = root / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    # An eval no route reaches is rejected as unreachable, and a rejected finding is a false-positive learning.
    helper = "def helper(x):\n    return eval(x)\n" if learns else "def helper():\n    return 1\n"
    (repo / "pkg" / "lib.py").write_text(helper)
    (repo / ".gitignore").write_text("__pycache__/\n")
    if repository:
        git = ["git", "-C", str(repo), "-c", "user.name=tests", "-c", "user.email=tests@example.invalid", "-c", "commit.gpgsign=false"]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)
    return repo


def _tree(root: Path) -> tuple[dict[str, str], set[str]]:
    """Every file with its size and digest, and every directory, hidden entries included."""
    files: dict[str, str] = {}
    directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.add(relative)
        else:
            data = path.read_bytes()
            files[relative] = f"{len(data)} {hashlib.sha256(data).hexdigest()}"
    return files, directories


def _scan(repo: Path, mode: str = "quick") -> int:
    return main(["scan", str(repo), "--mode", mode])


@pytest.mark.parametrize("repository", [False, True])
@pytest.mark.parametrize("mode", ["quick", "standard"])
def test_a_scan_that_learns_nothing_leaves_the_target_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str, repository: bool
) -> None:
    if repository and shutil.which("git") is None:
        pytest.skip("git is needed to prepare a repository target")
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, repository=repository)
    before = _tree(repo)

    assert _scan(repo, mode) == 0

    (run,) = runs.iterdir()
    assert (run / "manifest.json").is_file()
    assert _tree(repo) == before


def test_a_scan_that_learns_writes_the_ledger_into_the_tree_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    files_before, directories_before = _tree(repo)

    assert _scan(repo) == 0

    (run,) = runs.iterdir()
    learnings = json.loads((repo / LEDGER).read_text())["learnings"]
    assert [learning["path"] for learning in learnings] == ["pkg/lib.py"]
    kept = json.loads((run / "calibration" / "false_positive_learnings.json").read_text())["learnings"]
    assert kept == learnings
    files_after, directories_after = _tree(repo)
    assert {name: files_after[name] for name in files_before} == files_before
    assert set(files_after) - set(files_before) == {LEDGER}
    assert directories_after - directories_before == LEDGER_DIRECTORIES


@pytest.mark.parametrize("mode", ["quick", "standard"])
def test_a_scan_that_cannot_write_the_ledger_records_it_and_goes_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    # A file where the ledger's directory has to be created. Permission bits do not stop root, and CI runs as
    # root; this stops every user the way a read-only mount does.
    (repo / ".openultrasast").write_text("not a directory\n")
    before = _tree(repo)

    assert _scan(repo, mode) == 0

    (run,) = runs.iterdir()
    degradations = json.loads((run / "manifest.json").read_text())["degradations"]
    recorded = [{key: item.get(key) for key in LEDGER_UNWRITTEN} for item in degradations]
    assert LEDGER_UNWRITTEN in recorded
    detail = next(item["detail"] for item in degradations if item["reason"] == "ledger_not_written")
    assert str(repo) in detail
    assert _tree(repo) == before
    assert json.loads((run / "calibration" / "false_positive_learnings.json").read_text())["learnings"]


def _learning_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A target with one rejected finding, scanned once: the store in the tree now holds that learning."""
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    assert _scan(repo) == 0
    assert (repo / LEDGER).is_file()
    return runs, repo


def _learned_again(run: Path) -> bool:
    """The scan rejected the same false positive once more, so it had a learning in hand."""
    learnings = json.loads((run / "calibration" / "false_positive_learnings.json").read_text())["learnings"]
    return [learning["path"] for learning in learnings] == ["pkg/lib.py"]


def test_a_rescan_that_rejects_a_stored_false_positive_leaves_the_store_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs, repo = _learning_scan(tmp_path, monkeypatch)
    ledger = repo / LEDGER
    tree_before = _tree(repo)
    stamp_before = (ledger.stat().st_mtime_ns, ledger.read_bytes())
    earlier = set(runs.iterdir())

    assert _scan(repo) == 0

    (run,) = set(runs.iterdir()) - earlier
    assert _learned_again(run)
    assert (ledger.stat().st_mtime_ns, ledger.read_bytes()) == stamp_before
    assert _tree(repo) == tree_before


def test_a_rescan_on_a_read_only_tree_records_nothing_because_nothing_needed_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs, repo = _learning_scan(tmp_path, monkeypatch)
    ledger = repo / LEDGER
    tree_before = _tree(repo)
    write = cli.write_false_positive_learnings

    def refuse_the_store(learnings, path):
        # The tree is read-only from here on, so the one write into it fails as on a `:ro` mount. Permission
        # bits cannot arrange that for a store that has to stay readable, because root ignores them.
        if path == ledger.resolve():
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        write(learnings, path)

    monkeypatch.setattr(cli, "write_false_positive_learnings", refuse_the_store)
    earlier = set(runs.iterdir())

    assert _scan(repo) == 0

    (run,) = set(runs.iterdir()) - earlier
    assert _learned_again(run)
    degradations = json.loads((run / "manifest.json").read_text()).get("degradations") or []
    assert "ledger_not_written" not in [item["reason"] for item in degradations]
    assert _tree(repo) == tree_before


def test_the_scan_prints_the_run_directory_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    (run,) = runs.iterdir()
    out = capsys.readouterr().out
    assert re.findall(r"^run_dir=(.+)$", out, flags=re.MULTILINE) == [str(run)]
    assert out.count(str(run)) == 1


def test_an_absolute_runs_dir_override_replaces_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(tmp_path / "elsewhere" / "runs"))
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    (run,) = (tmp_path / "elsewhere" / "runs").iterdir()
    assert (run / "report.md").is_file()
    assert not (tmp_path / "cache").exists()


def test_a_relative_runs_dir_override_is_taken_from_the_working_directory_not_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    working = tmp_path / "working"
    working.mkdir()
    monkeypatch.chdir(working)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    (run,) = (working / ".runs").iterdir()
    assert (run / "report.md").is_file()
    assert not (repo / ".runs").exists()


def test_no_test_can_write_a_scan_run_into_the_developers_cache(tmp_path_factory: pytest.TempPathFactory) -> None:
    """tests/conftest.py redirects the override for every test, so one that forgets to name a location cannot
    write into the real `~/.cache/openultrasast/runs`."""
    assert Path(ResolvedConfig().runs_dir).is_relative_to(tmp_path_factory.getbasetemp())
