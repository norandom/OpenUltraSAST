"""What a scan removes from its cache (contributor-scan Requirement 5.3, decisions of 2026-11-24 and 2026-11-27):
once its run is written, the expired runs go from the default location and from the shell wrapper's mount of it,
and nothing else does."""

import errno
import os
import re
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_scan_output_location import _scan, _target, _user_cache

from openultrasast import run
from openultrasast.config import WRAPPER_RUNS_MOUNT, ResolvedConfig, load_config
from openultrasast.run import prune_old_runs, prune_scan_runs

NOW = datetime(2026, 11, 24, 12, tzinfo=UTC)
RETENTION = "OPENULTRASAST_RUNS_RETENTION_DAYS"
OVER_THE_CALENDAR = (NOW - datetime(1, 1, 1, tzinfo=UTC)).days + 1


def _run_id(started_at: datetime, suffix: str = "00000000") -> str:
    """The id `create_scan_run` gives a run that started at `started_at`."""
    return f"{started_at:%Y%m%dT%H%M%SZ}-{suffix}"


def _run(root: Path, name: str) -> Path:
    """What an earlier scan left under `root`: a directory called `name` that holds a manifest."""
    path = root / name
    path.mkdir(parents=True)
    (path / "manifest.json").write_text("{}\n")
    return path


def _earlier_run(runs: Path, age_days: int) -> Path:
    """A run under `runs` that started `age_days` ago by the real clock."""
    return _run(runs, _run_id(datetime.now(UTC) - timedelta(days=age_days), uuid.uuid4().hex[:8]))


def _default_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The default run root for this test, in a cache of its own, with the retention left at its default."""
    monkeypatch.delenv(RETENTION, raising=False)
    return _user_cache(tmp_path, monkeypatch)


def _notices(out: str) -> list[str]:
    return re.findall(r"^notice: (.+)$", out, flags=re.MULTILINE)


def _refuse_removal(monkeypatch: pytest.MonkeyPatch, run_dir: Path, error: Exception) -> None:
    """Make the removal of `run_dir` raise `error`, as a cache that refuses deletion would; other removals go on."""
    remove = shutil.rmtree

    def refuse(path, *args, **kwargs):
        # Permission bits cannot stand in for a cache that refuses deletion: root ignores them, and CI runs as root.
        if Path(path) == run_dir:
            raise error
        remove(path, *args, **kwargs)

    monkeypatch.setattr(run.shutil, "rmtree", refuse)


def test_a_run_older_than_the_retention_is_removed_and_younger_ones_stay(tmp_path: Path) -> None:
    six_weeks_ago = _run(tmp_path, _run_id(NOW - timedelta(days=40)))
    a_month_ago = _run(tmp_path, _run_id(NOW - timedelta(days=31)))
    just_past_the_limit = _run(tmp_path, _run_id(NOW - timedelta(days=30, seconds=1)))
    at_the_limit = _run(tmp_path, _run_id(NOW - timedelta(days=30)))
    last_week = _run(tmp_path, _run_id(NOW - timedelta(days=5)))

    removed = prune_old_runs(tmp_path, keep=None, retention_days=30, now=NOW)

    assert sorted(removed) == [six_weeks_ago, a_month_ago, just_past_the_limit]
    assert sorted(tmp_path.iterdir()) == [at_the_limit, last_week]


def test_the_current_run_stays_even_when_its_id_says_it_started_long_ago(tmp_path: Path) -> None:
    current = _run(tmp_path, _run_id(NOW - timedelta(days=40)))

    assert prune_old_runs(tmp_path, keep=current, retention_days=30, now=NOW) == []
    assert (current / "manifest.json").is_file()


def test_prune_scan_runs_keeps_the_run_it_is_told_to_keep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    expired = _run(runs, _run_id(NOW - timedelta(days=40), "deadbeef"))
    current = _run(runs, _run_id(NOW - timedelta(days=40), "badc0de0"))

    assert prune_scan_runs(ResolvedConfig(), keep=current) == (f"removed 1 run older than 30 days from {runs}",)
    assert (current / "manifest.json").is_file()
    assert not expired.exists()


@pytest.mark.parametrize(
    "name",
    [
        "notes",
        "20261015T110527Z-b1dc097",  # seven hex digits, not eight
        "20261015T110527Z-nothex00",  # a suffix that is not hex
        "20261015T110527Z-DEADBEEF",  # uppercase: create_scan_run writes lowercase hex
        "20261015T110527Z-deadbeef.bak",  # a run's id with something after it
        "20261340T000000Z-deadbeef",  # month 13: no run ever started then
    ],
)
def test_a_directory_whose_name_is_not_the_id_of_a_run_stays(tmp_path: Path, name: str) -> None:
    directory = tmp_path / name
    directory.mkdir()
    (directory / "manifest.json").write_text("{}\n")

    assert prune_old_runs(tmp_path, keep=None, retention_days=30, now=NOW) == []
    assert (directory / "manifest.json").is_file()


def test_a_file_and_a_run_nested_under_another_directory_stay(tmp_path: Path) -> None:
    old_id = _run_id(NOW - timedelta(days=40))
    readme = tmp_path / "README"
    readme.write_text("kept\n")
    named_like_a_run = tmp_path / old_id
    named_like_a_run.write_text("a file, although it is named like an expired run\n")
    nested = _run(tmp_path / "archive", old_id)

    assert prune_old_runs(tmp_path, keep=None, retention_days=30, now=NOW) == []
    assert sorted(tmp_path.iterdir()) == sorted([readme, tmp_path / "archive", named_like_a_run])
    assert (nested / "manifest.json").is_file()


def test_a_symlink_to_an_expired_run_is_neither_removed_nor_followed(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    kept_elsewhere = _run(tmp_path, "kept-elsewhere")
    link = runs / _run_id(NOW - timedelta(days=40))
    link.symlink_to(kept_elsewhere, target_is_directory=True)

    assert prune_old_runs(runs, keep=None, retention_days=30, now=NOW) == []
    assert link.is_symlink()
    assert (kept_elsewhere / "manifest.json").is_file()


def test_a_retention_of_zero_removes_nothing(tmp_path: Path) -> None:
    expired = _run(tmp_path, _run_id(NOW - timedelta(days=400)))

    assert prune_old_runs(tmp_path, keep=None, retention_days=0, now=NOW) == []
    assert (expired / "manifest.json").is_file()


def test_the_retention_decides_which_runs_are_expired(tmp_path: Path) -> None:
    six_weeks_ago = _run(tmp_path, _run_id(NOW - timedelta(days=40)))
    last_week = _run(tmp_path, _run_id(NOW - timedelta(days=5)))

    assert prune_old_runs(tmp_path, keep=None, retention_days=60, now=NOW) == []
    assert prune_old_runs(tmp_path, keep=None, retention_days=7, now=NOW) == [six_weeks_ago]
    assert (last_week / "manifest.json").is_file()


def test_a_run_is_dated_by_its_id_not_by_the_filesystem(tmp_path: Path) -> None:
    copied_today = _run(tmp_path, _run_id(NOW - timedelta(days=40)))
    os.utime(copied_today, (NOW.timestamp(), NOW.timestamp()))
    restored_from_an_old_backup = _run(tmp_path, _run_id(NOW - timedelta(days=5)))
    os.utime(restored_from_an_old_backup, (0, 0))

    assert prune_old_runs(tmp_path, keep=None, retention_days=30, now=NOW) == [copied_today]
    assert (restored_from_an_old_backup / "manifest.json").is_file()


def test_the_retention_is_thirty_days_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RETENTION, raising=False)

    assert load_config(None).runs_retention_days == 30
    assert ResolvedConfig().runs_retention_days == 30


@pytest.mark.parametrize("value", ["0", "7"])
def test_the_environment_sets_the_retention(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(RETENTION, value)

    assert load_config(None).runs_retention_days == int(value)
    assert ResolvedConfig().runs_retention_days == int(value)


def test_an_empty_retention_leaves_the_default_as_an_empty_runs_dir_does(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RETENTION, "")

    assert load_config(None).runs_retention_days == 30


@pytest.mark.parametrize("value", ["-1", "3.5", "soon"])
def test_a_retention_that_is_negative_or_not_a_whole_number_is_rejected(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(RETENTION, value)

    with pytest.raises(ValueError, match=RETENTION):
        load_config(None)


def test_a_scan_with_a_retention_of_zero_keeps_every_run_and_says_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    monkeypatch.setenv(RETENTION, "0")
    expired = _earlier_run(runs, 40)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert (expired / "manifest.json").is_file()
    assert _notices(capsys.readouterr().out) == []


@pytest.mark.parametrize(("expired_count", "runs_removed"), [(1, "run"), (2, "runs")])
def test_a_scan_removes_the_expired_runs_from_the_default_location_and_says_how_many(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], expired_count: int, runs_removed: str
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    expired = [_earlier_run(runs, 40) for _ in range(expired_count)]
    last_week = _earlier_run(runs, 5)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    out = capsys.readouterr().out
    (this_run,) = re.findall(r"^run_dir=(.+)$", out, flags=re.MULTILINE)
    assert sorted(runs.iterdir()) == sorted([last_week, Path(this_run)])
    assert _notices(out) == [f"removed {expired_count} {runs_removed} older than 30 days from {runs}"]
    assert not any(path.exists() for path in expired)


def test_a_scan_with_a_runs_dir_of_its_own_removes_nothing_and_says_nothing_about_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    elsewhere = tmp_path / "elsewhere" / "runs"
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(elsewhere))
    monkeypatch.delenv(RETENTION, raising=False)
    kept_in_the_cache = _earlier_run(tmp_path / "cache" / "openultrasast" / "runs", 40)
    kept_elsewhere = _earlier_run(elsewhere, 40)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert (kept_in_the_cache / "manifest.json").is_file()
    assert (kept_elsewhere / "manifest.json").is_file()
    assert _notices(capsys.readouterr().out) == []


@pytest.mark.parametrize("through_a_symlink", [False, True], ids=["literal-path", "through-a-symlink"])
def test_a_scan_with_the_runs_dir_override_pointing_at_the_default_location_removes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], through_a_symlink: bool
) -> None:
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.delenv(RETENTION, raising=False)
    default = cache / "openultrasast" / "runs"
    expired = _earlier_run(default, 40)
    chosen = default
    if through_a_symlink:
        link = tmp_path / "link"
        link.symlink_to(cache, target_is_directory=True)
        chosen = link / "openultrasast" / "runs"
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(chosen))
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    out = capsys.readouterr().out
    (this_run,) = re.findall(r"^run_dir=(.+)$", out, flags=re.MULTILINE)
    assert (default / Path(this_run).name / "manifest.json").is_file()
    assert (expired / "manifest.json").is_file()
    assert _notices(out) == []


def test_a_scan_through_the_wrapper_removes_the_expired_runs_from_the_mounted_runs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What a scan in the image sees through the shell wrapper. The runs directory is a stand-in for `/reports`,
    which only root can make on the host."""
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", "/reports")
    monkeypatch.delenv(RETENTION, raising=False)
    mounted = tmp_path / "reports"
    _earlier_run(mounted, 40)
    last_week = _earlier_run(mounted, 5)
    current = _run(mounted, _run_id(datetime.now(UTC), "badc0de0"))

    notices = prune_scan_runs(ResolvedConfig(runs_dir=str(mounted)), keep=current)

    assert notices == (f"removed 1 run older than 30 days from {mounted}",)
    assert sorted(mounted.iterdir()) == [last_week, current]


def test_a_scan_that_compose_runs_without_the_wrapper_removes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The compose file's own `OPENULTRASAST_RUNS_DIR`, `/reports/runs`: a location chosen, where nothing is removed."""
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", "/reports/runs")
    monkeypatch.delenv(RETENTION, raising=False)
    runs = tmp_path / "reports" / "runs"
    expired = _earlier_run(runs, 40)
    current = _run(runs, _run_id(datetime.now(UTC), "badc0de0"))

    assert prune_scan_runs(ResolvedConfig(runs_dir=str(runs)), keep=current) == ()
    assert sorted(runs.iterdir()) == [expired, current]


def test_the_wrapper_passes_the_override_that_a_scan_prunes() -> None:
    """The wrapper's word and the scan's mount point must not drift apart: the scan prunes `/reports` by that name."""
    wrapper = Path(__file__).resolve().parents[1] / "ops" / "shell" / "ousast.sh"
    assert f"OPENULTRASAST_RUNS_DIR={WRAPPER_RUNS_MOUNT}" in wrapper.read_text().split()


def test_a_scan_with_an_empty_runs_dir_override_removes_the_expired_runs_from_the_default_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", "")
    expired = _earlier_run(runs, 40)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert not expired.exists()
    assert _notices(capsys.readouterr().out) == [f"removed 1 run older than 30 days from {runs}"]


def test_a_scan_whose_removal_fails_still_succeeds_and_prints_one_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    expired = _earlier_run(runs, 40)
    repo = _target(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied", str(expired))
    _refuse_removal(monkeypatch, expired, refusal)

    assert _scan(repo) == 0

    assert (expired / "manifest.json").is_file()
    assert _notices(capsys.readouterr().out) == [f"old runs could not be removed from {runs}: {refusal}"]


def test_a_scan_whose_removal_runs_out_of_recursion_still_succeeds_and_prints_one_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    expired = _earlier_run(runs, 40)
    repo = _target(tmp_path)
    failure = RecursionError("maximum recursion depth exceeded")
    _refuse_removal(monkeypatch, expired, failure)

    assert _scan(repo) == 0

    assert (expired / "manifest.json").is_file()
    assert _notices(capsys.readouterr().out) == [f"old runs could not be removed from {runs}: {failure}"]


@pytest.mark.parametrize("retention_days", [OVER_THE_CALENDAR, 1_000_000, 10**9])
def test_a_retention_longer_than_the_calendar_removes_nothing(tmp_path: Path, retention_days: int) -> None:
    expired = _run(tmp_path, _run_id(NOW - timedelta(days=40)))

    assert prune_old_runs(tmp_path, keep=None, retention_days=retention_days, now=NOW) == []
    assert (expired / "manifest.json").is_file()


def test_a_scan_with_a_retention_longer_than_the_calendar_succeeds_and_says_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    monkeypatch.setenv(RETENTION, "1000000")
    expired = _earlier_run(runs, 40)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert (expired / "manifest.json").is_file()
    assert _notices(capsys.readouterr().out) == []


def _ledger_file(runs: Path, age_days: int, name: str) -> Path:
    """A file under the directory of the ledgers of tree digests, last used `age_days` ago by the real clock."""
    path = runs / "calibration" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"learnings": []}\n')
    last_used = (datetime.now(UTC) - timedelta(days=age_days)).timestamp()
    os.utime(path, (last_used, last_used))
    return path


def _digest(suffix: str = ".json") -> str:
    return f"{uuid.uuid4().hex}{uuid.uuid4().hex[:32]}{suffix}"


def test_a_ledger_of_a_tree_digest_unused_for_longer_than_the_retention_is_removed_with_the_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """By the decision of 2026-11-28: a ledger is dated by its last use, a run by its id."""
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    monkeypatch.delenv(RETENTION, raising=False)
    runs = tmp_path / "runs"
    _ledger_file(runs, 40, _digest())
    last_week = _ledger_file(runs, 5, _digest())
    current = _run(runs, _run_id(datetime.now(UTC), "badc0de0"))

    notices = prune_scan_runs(ResolvedConfig(runs_dir=str(runs)), keep=current)

    assert notices == (f"removed 1 ledger of a tree digest unused for 30 days from {runs / 'calibration'}",)
    assert list((runs / "calibration").iterdir()) == [last_week]
    assert sorted(runs.iterdir()) == sorted([runs / "calibration", current])


def test_a_scan_removes_the_expired_ledgers_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    _ledger_file(runs, 40, _digest(".json." + uuid.uuid4().hex + ".tmp"))
    _ledger_file(runs, 40, _digest())
    last_week = _ledger_file(runs, 5, _digest())
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert list((runs / "calibration").iterdir()) == [last_week]
    assert _notices(capsys.readouterr().out) == [f"removed 2 ledgers of a tree digest unused for 30 days from {runs / 'calibration'}"]


def test_nothing_under_the_ledgers_directory_that_is_not_a_ledger_is_touched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    runs = tmp_path / "runs"
    notes = _ledger_file(runs, 40, "notes.txt")
    elsewhere = _ledger_file(tmp_path, 40, _digest())
    link = runs / "calibration" / _digest()
    link.symlink_to(elsewhere)
    directory = runs / "calibration" / _digest()
    directory.mkdir()

    assert prune_scan_runs(ResolvedConfig(runs_dir=str(runs)), keep=runs / _run_id(datetime.now(UTC), "badc0de0")) == ()
    assert sorted(path.name for path in (runs / "calibration").iterdir()) == sorted([notes.name, link.name, directory.name])
    assert elsewhere.is_file()


def test_a_retention_of_zero_keeps_every_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    monkeypatch.setenv(RETENTION, "0")
    runs = tmp_path / "runs"
    expired = _ledger_file(runs, 40, _digest())

    assert prune_scan_runs(ResolvedConfig(runs_dir=str(runs), runs_retention_days=0), keep=None) == ()
    assert expired.is_file()


def test_a_ledger_is_kept_through_compose_without_the_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", "/reports/runs")
    monkeypatch.delenv(RETENTION, raising=False)
    runs = tmp_path / "reports" / "runs"
    expired = _ledger_file(runs, 40, _digest())

    assert prune_scan_runs(ResolvedConfig(runs_dir=str(runs)), keep=None) == ()
    assert expired.is_file()


def test_a_ledger_that_cannot_be_removed_is_said_once_and_costs_the_scan_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runs = _default_cache(tmp_path, monkeypatch)
    expired = _ledger_file(runs, 40, _digest())
    refusal = PermissionError(errno.EACCES, "Permission denied", str(expired))
    unlink = Path.unlink

    def refuse(path, *args, **kwargs):
        if path == expired:
            raise refusal
        unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    repo = _target(tmp_path)

    assert _scan(repo) == 0

    assert expired.is_file()
    assert _notices(capsys.readouterr().out) == [f"a ledger of a tree digest could not be removed from {runs / 'calibration'}: {refusal}"]
