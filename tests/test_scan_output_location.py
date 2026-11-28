"""Where a scan writes (contributor-scan Requirement 5.3): the run goes to the user's cache, and the analysed
tree is left as it was unless the scan has a false positive to remember."""

import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast import cli, digest_ledger
from openultrasast.calibration import FalsePositiveLearning, FalsePositiveReason, write_false_positive_learnings
from openultrasast.cli import main
from openultrasast.config import ResolvedConfig, load_config
from openultrasast.preprocess import enumerate_source_files
from openultrasast.tree_digest import tree_digest

LEDGER = ".openultrasast/calibration/false_positive_learnings.json"
LEDGER_DIRECTORIES = {".openultrasast", ".openultrasast/calibration"}
LEDGER_UNWRITTEN = {"stage": "record_calibration", "reason": "ledger_not_written"}
DIGEST_LEDGERS = "calibration"


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
    assert _ledger_of(run)["digest_ledger"] == "none"
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

    # This scan learned something the tree could not take: its learnings are kept in the ledger of the tree's digest.
    (run,) = [path for path in runs.iterdir() if path.name != DIGEST_LEDGERS]
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


def _refusing(monkeypatch: pytest.MonkeyPatch, ledger: Path) -> None:
    """The tree refuses its ledger from here on, as a read-only mount does, while its bytes stay as they are."""
    write = cli.write_false_positive_learnings

    def refuse_the_store(learnings, path):
        if path == ledger:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        write(learnings, path)

    monkeypatch.setattr(cli, "write_false_positive_learnings", refuse_the_store)


def _digest_ledger(runs: Path, repo: Path) -> Path:
    """Where a scan keeps what it learned while `repo` could not be written."""
    return runs / DIGEST_LEDGERS / f"{tree_digest(repo, runs)}.json"


def _ledger_of(run: Path) -> dict[str, object]:
    return json.loads((run / "manifest.json").read_text())["ledger"]


def _reasons(run: Path) -> list[str]:
    return [item["reason"] for item in json.loads((run / "manifest.json").read_text()).get("degradations") or []]


def test_a_scan_whose_tree_refuses_the_ledger_keeps_it_under_the_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """What a scan in the image learns is not lost: it goes to the ledger of the tree's digest, which only a scan of
    the very same bytes reads."""
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    tree_before = _tree(repo)

    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, (repo / LEDGER).resolve())

        assert _scan(repo) == 0

    (run,) = [path for path in runs.iterdir() if path.name != DIGEST_LEDGERS]
    kept = _digest_ledger(runs, repo)
    learnings = json.loads(kept.read_text())["learnings"]
    assert [learning["path"] for learning in learnings] == ["pkg/lib.py"]
    assert json.loads((run / "calibration" / "false_positive_learnings.json").read_text())["learnings"] == learnings
    assert _ledger_of(run) == {
        "tree_digest": tree_digest(repo, runs),
        "learnings_read": {"tree": 0, "digest": 0},
        "digest_ledger": "written",
    }
    assert (
        "The false-positive ledger in the analysed tree could not be written, so this scan's learnings are kept in "
        f"the ledger of this tree's digest under the runs directory, at `{kept}`, and the next scan of the same "
        "bytes reads them."
    ) in (run / "report.md").read_text()
    assert _tree(repo) == tree_before


def test_the_next_scan_of_the_same_bytes_reads_the_ledger_of_its_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)

    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, (repo / LEDGER).resolve())

        assert _scan(repo) == 0
        assert "calibrations_applied=0\n" in capsys.readouterr().out
        kept = _digest_ledger(runs, repo)
        assert kept.is_file()
        earlier = set(runs.iterdir())

        assert _scan(repo) == 0

    assert "calibrations_applied=1\n" in capsys.readouterr().out
    (run,) = set(runs.iterdir()) - earlier
    assert _ledger_of(run)["learnings_read"] == {"tree": 0, "digest": 1}
    assert _ledger_of(run)["digest_ledger"] == "left as it was"
    assert [path.name for path in (runs / DIGEST_LEDGERS).iterdir()] == [kept.name]


@pytest.mark.parametrize("learns_again", [True, False])
def test_the_first_scan_that_can_write_the_tree_carries_the_entries_into_it_and_removes_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], learns_again: bool
) -> None:
    """By the decision of 2026-11-28, also when that scan learns nothing new: the entries are new to the tree."""
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    ledger = (repo / LEDGER).resolve()

    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, ledger)
        assert _scan(repo) == 0

    kept = _digest_ledger(runs, repo)
    assert kept.is_file()
    if not learns_again:
        monkeypatch.setattr(cli, "learnings_from_verifications", lambda findings, verifications: [])
    earlier = set(runs.iterdir())

    assert _scan(repo) == 0

    (run,) = set(runs.iterdir()) - earlier
    assert [learning["path"] for learning in json.loads(ledger.read_text())["learnings"]] == ["pkg/lib.py"]
    assert not kept.exists()
    assert _ledger_of(run)["digest_ledger"] == "removed"
    assert "ledger_not_written" not in _reasons(run)


def test_a_ledger_of_a_digest_is_removed_once_the_tree_holds_its_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    ledger = (repo / LEDGER).resolve()

    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, ledger)
        assert _scan(repo) == 0

    kept = _digest_ledger(runs, repo)
    # The entries reach the tree's ledger by hand, as a commit could bring them. `.openultrasast` is no part of the
    # digest, so this is still the same tree to a scan.
    ledger.parent.mkdir(parents=True)
    shutil.copyfile(kept, ledger)
    stamp = ledger.stat().st_mtime_ns
    earlier = set(runs.iterdir())

    assert _scan(repo) == 0

    (run,) = set(runs.iterdir()) - earlier
    assert not kept.exists()
    assert ledger.is_file()
    assert ledger.stat().st_mtime_ns == stamp
    assert _ledger_of(run)["digest_ledger"] == "removed"


def test_an_entry_that_is_in_both_ledgers_is_taken_from_the_trees(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The tree's ledger is the file a user can read, edit and commit: where the two disagree, its version is applied."""
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path)
    tree_entry = FalsePositiveLearning(
        "py-eval:pkg/lib.py:2", "pkg/lib.py", "xss", FalsePositiveReason.UNREACHABLE_PATH, "the tree's evidence", "pkg"
    )
    tree_ledger = repo / LEDGER
    write_false_positive_learnings([tree_entry], tree_ledger)
    write_false_positive_learnings([replace(tree_entry, evidence="the digest's evidence")], _digest_ledger(runs, repo))

    tree_learnings, ledger, prior_learnings = cli._read_ledgers(tree_ledger.resolve(), runs, tree_digest(repo, runs))

    assert (ledger.found, [learning.evidence for learning in tree_learnings]) == ("read", ["the tree's evidence"])
    assert [learning.evidence for learning in prior_learnings] == ["the tree's evidence"]


@pytest.mark.parametrize("content", ["not a ledger\n", "[" * 5000 + "]" * 5000], ids=["not a ledger", "nested too deep"])
def test_a_ledger_of_a_digest_that_is_not_a_ledger_does_not_stop_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    """Whatever a hand or another tool left there: taken for empty, said unreadable, and gone."""
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    ledger = (repo / LEDGER).resolve()
    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, ledger)
        assert _scan(repo) == 0
    kept = _digest_ledger(runs, repo)
    kept.write_text(content)
    earlier = set(runs.iterdir())

    assert _scan(repo) == 0

    (run,) = set(runs.iterdir()) - earlier
    assert _ledger_of(run)["digest_ledger"] == "unreadable"
    assert not kept.exists()
    assert [learning["path"] for learning in json.loads(ledger.read_text())["learnings"]] == ["pkg/lib.py"]


@pytest.mark.parametrize("failure", ["write", "removal"])
def test_a_ledger_of_a_digest_that_cannot_be_written_or_removed_is_said_once_and_costs_the_scan_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failure: str
) -> None:
    runs = _user_cache(tmp_path, monkeypatch)
    repo = _target(tmp_path, learns=True)
    ledger = (repo / LEDGER).resolve()
    rename = os.replace
    unlink = Path.unlink

    def refusing_rename(source, target):  # type: ignore[no-untyped-def]
        if Path(target) == kept:
            raise PermissionError(errno.EACCES, "Permission denied", str(target))
        return rename(source, target)

    def refusing_unlink(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == kept:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return unlink(path, *args, **kwargs)

    kept = _digest_ledger(runs, repo)
    with pytest.MonkeyPatch.context() as refusing:
        _refusing(refusing, ledger)
        if failure == "write":
            refusing.setattr(digest_ledger.os, "replace", refusing_rename)
        assert _scan(repo) == 0
    if failure == "write":
        (run,) = [path for path in runs.iterdir() if path.name != DIGEST_LEDGERS]
        assert not kept.exists()
        assert "kept only in this run directory" in (run / "report.md").read_text()
    else:
        assert kept.is_file()
        earlier = set(runs.iterdir())
        monkeypatch.setattr(Path, "unlink", refusing_unlink)

        assert _scan(repo) == 0

        (run,) = set(runs.iterdir()) - earlier
        assert kept.is_file()
        assert ledger.is_file()

    assert _ledger_of(run)["digest_ledger"] == "failed"
    assert (
        capsys.readouterr().out.count(
            f"notice: the ledger of this tree's digest could not be written or removed: [Errno 13] Permission denied: '{kept}'"
        )
        == 1
    )


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

    out = capsys.readouterr().out
    (printed,) = re.findall(r"^run_dir=(.+)$", out, flags=re.MULTILINE)
    assert _files_read(Path(printed)) == ["app.py", "pkg/lib.py"]
    # Nothing is left out there, so nothing is said.
    assert "notice:" not in out


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


def _notices(capsys: pytest.CaptureFixture[str]) -> list[str]:
    return re.findall(r"^notice: (.+)$", capsys.readouterr().out, flags=re.MULTILINE)


@pytest.mark.parametrize("form", ["override", "default_location", "symlinked_override"])
@pytest.mark.parametrize("left_out", [2, 1])
def test_a_scan_says_how_many_source_files_it_left_out_under_its_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], form: str, left_out: int
) -> None:
    repo = _target(tmp_path)
    runs = _runs_inside(repo, tmp_path, monkeypatch, form)
    (runs / "earlier").mkdir()
    (runs / "earlier" / "copy.py").write_text((repo / "app.py").read_text())
    # What a run keeps: no source file, so none of these is counted.
    (runs / "earlier" / "report.md").write_text("# report\n")
    (runs / "earlier" / "findings.json").write_text("{}\n")
    if left_out == 2:
        (runs / "earlier" / "pkg").mkdir()
        (runs / "earlier" / "pkg" / "lib.py").write_text((repo / "pkg" / "lib.py").read_text())

    assert _scan(repo) == 0

    runs_dir = load_config(None).runs_dir
    files = "file" if left_out == 1 else "files"
    assert _notices(capsys) == [f"skipped {left_out} source {files} under the runs directory {runs_dir}"]


@pytest.mark.parametrize("where", ["inside", "outside"])
def test_nothing_is_said_when_no_source_file_is_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], where: str
) -> None:
    # Inside the scanned path a run keeps no source file, and outside it nothing is skipped: neither is said.
    repo = _target(tmp_path)
    if where == "inside":
        runs = _runs_inside(repo, tmp_path, monkeypatch, "override")
        kept = ("report.md", "findings.json")
    else:
        runs = tmp_path / "elsewhere" / "runs"
        runs.mkdir(parents=True)
        monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(runs))
        kept = ("copy.py",)
    (runs / "earlier").mkdir()
    for name in kept:
        (runs / "earlier" / name).write_text("x = 1\n")

    assert _scan(repo) == 0

    assert _notices(capsys) == []


def _left_out_copy(repo: Path, runs: Path) -> None:
    """A source file under the runs directory, where a run of this package keeps none."""
    (runs / "earlier").mkdir(parents=True)
    (runs / "earlier" / "copy.py").write_text((repo / "app.py").read_text())


def test_a_gitignore_inside_the_runs_directory_does_not_hide_what_the_scan_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The scan reads the target's root .gitignore and no other: one inside the runs directory hides nothing from
    # the count.
    repo = _target(tmp_path)
    runs = repo / "pkg"
    (runs / ".gitignore").write_text("*.py\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(runs))

    assert _scan(repo) == 0

    assert _notices(capsys) == [f"skipped 1 source file under the runs directory {runs}"]


def test_nothing_is_left_out_where_the_target_already_ignores_the_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _target(tmp_path)
    (repo / ".gitignore").write_text("__pycache__/\n.runs/\n")
    runs = _runs_inside(repo, tmp_path, monkeypatch, "override")
    _left_out_copy(repo, runs)

    assert _scan(repo) == 0

    assert _notices(capsys) == []


def test_nothing_is_left_out_under_a_directory_the_scan_ignores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _target(tmp_path)
    runs = repo / ".openultrasast" / "runs"
    _left_out_copy(repo, runs)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(runs))

    assert _scan(repo) == 0

    assert _notices(capsys) == []


def test_a_directory_named_gitignore_in_the_runs_directory_costs_the_scan_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The count reads what the preprocess stage read, and nothing of its own under the runs directory.
    repo = _target(tmp_path)
    runs = _runs_inside(repo, tmp_path, monkeypatch, "override")
    (runs / ".gitignore").mkdir()

    assert _scan(repo) == 0

    assert _notices(capsys) == []
