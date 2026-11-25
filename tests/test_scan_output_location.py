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
from openultrasast.preprocess import enumerate_source_files

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


def _runs_inside(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, form: str) -> Path:
    """The runs directory inside the scanned tree: by the override, by the default location, or by the override
    through a symlink (as macOS keeps `/tmp`)."""
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    runs = repo / (".cache/openultrasast/runs" if form == "default_location" else ".runs")
    runs.mkdir(parents=True)
    if form == "default_location":
        monkeypatch.setenv("XDG_CACHE_HOME", str(repo / ".cache"))
    elif form == "symlinked_override":
        link = tmp_path / "runs-link"
        link.symlink_to(runs, target_is_directory=True)
        monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(link))
    else:
        monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(runs))
    return runs


def _files_read(run: Path) -> list[str]:
    return [target["path"] for target in json.loads((run / "preprocess" / "file_targets.json").read_text())["file_targets"]]


@pytest.mark.parametrize("form", ["override", "default_location", "symlinked_override"])
def test_a_scan_skips_the_runs_directory_when_it_lies_inside_the_scanned_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], form: str
) -> None:
    repo = _target(tmp_path)
    runs = _runs_inside(repo, tmp_path, monkeypatch, form)
    # A constructed case, since no run of this package keeps a source file: one with the finding under study,
    # under the runs directory.
    (runs / "earlier").mkdir()
    (runs / "earlier" / "copy.py").write_text((repo / "app.py").read_text())

    assert _scan(repo) == 0

    (run,) = [path for path in runs.iterdir() if path.name != "earlier"]
    assert _files_read(run) == ["app.py", "pkg/lib.py"]
    assert re.findall(r"^findings=(\d+)$", capsys.readouterr().out, flags=re.MULTILINE) == ["1"]


def test_only_the_runs_directory_is_skipped_the_rest_of_the_cache_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _target(tmp_path)
    runs = _runs_inside(repo, tmp_path, monkeypatch, "default_location")
    copy = (repo / "app.py").read_text()
    # The last two are not the runs directory either: a sibling that shares its name's prefix, and a directory
    # of that name elsewhere in the tree.
    for kept in (runs / "earlier", runs.parent / "other", runs.parent / "runs-other", repo / "elsewhere" / "runs"):
        kept.mkdir(parents=True)
        (kept / "copy.py").write_text(copy)

    assert _scan(repo) == 0

    (run,) = [path for path in runs.iterdir() if path.name != "earlier"]
    assert _files_read(run) == [
        ".cache/openultrasast/other/copy.py",
        ".cache/openultrasast/runs-other/copy.py",
        "app.py",
        "elsewhere/runs/copy.py",
        "pkg/lib.py",
    ]


@pytest.mark.parametrize("where", ["a_parent_of_the_target", "the_target_itself"])
def test_a_target_that_lies_inside_the_runs_directory_is_read_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], where: str
) -> None:
    # The runs directory is skipped where it lies inside the scanned path, not the other way round: set to a
    # working directory or to `.`, it must not silence the scan.
    repo = _target(tmp_path)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(tmp_path if where == "a_parent_of_the_target" else repo))

    assert _scan(repo) == 0

    (printed,) = re.findall(r"^run_dir=(.+)$", capsys.readouterr().out, flags=re.MULTILINE)
    assert _files_read(Path(printed)) == ["app.py", "pkg/lib.py"]


def test_the_runs_directory_is_found_under_a_relative_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The scan passes a resolved root; a direct caller need not, and the skip must hold for both.
    (tmp_path / "runs" / "earlier").mkdir(parents=True)
    for name in ("app.py", "runs/earlier/copy.py"):
        (tmp_path / name).write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)

    assert [path.as_posix() for path in enumerate_source_files(Path("."), Path("runs"))] == ["app.py"]


def test_no_test_can_write_a_scan_run_into_the_developers_cache(tmp_path_factory: pytest.TempPathFactory) -> None:
    """tests/conftest.py redirects the override for every test, so one that forgets to name a location cannot
    write into the real `~/.cache/openultrasast/runs`."""
    assert Path(ResolvedConfig().runs_dir).is_relative_to(tmp_path_factory.getbasetemp())
