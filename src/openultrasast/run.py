from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from .config import ResolvedConfig, runs_dir_is_overridden, runs_dir_is_the_wrappers, write_resolved_config
from .digest_ledger import LEDGER_NAME, LEDGERS_DIRNAME

_RUN_ID = re.compile(r"(\d{8}T\d{6}Z)-[0-9a-f]{8}")


@dataclass(frozen=True)
class ScanRun:
    scan_id: str
    root: Path
    target: Path


def create_scan_run(target: Path, config: ResolvedConfig) -> ScanRun:
    resolved_target = target.resolve()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    scan_id = f"{timestamp}-{uuid4().hex[:8]}"
    root = Path(config.runs_dir) / scan_id
    root.mkdir(parents=True, exist_ok=False)
    (root / "preprocess").mkdir()
    write_resolved_config(config, root / "resolved_config.json")
    return ScanRun(scan_id=scan_id, root=root, target=resolved_target)


def _run_started_at(name: str) -> datetime | None:
    """When the run called `name` started, or None when `name` is not the id of a run."""
    match = _RUN_ID.fullmatch(name)
    if match is None:
        return None
    try:
        return datetime.strptime(match[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _is_expired_run(entry: Path, cutoff: datetime) -> bool:
    """A run directory, not a link to one, that started before `cutoff`."""
    started_at = _run_started_at(entry.name)
    return started_at is not None and started_at < cutoff and entry.is_dir() and not entry.is_symlink()


def prune_old_runs(runs_root: Path, *, keep: Path | None = None, retention_days: int, now: datetime | None = None) -> list[Path]:
    """Remove the runs directly under `runs_root` that are older than `retention_days`, and return them.

    A run is as old as the timestamp in its id says, whatever its file times say. Everything else stays: files,
    directories called something else, symbolic links, and `keep`, the run just written.
    """
    if retention_days <= 0:
        return []
    try:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    except OverflowError:
        return []  # a retention longer than the calendar: no run is that old
    removed = []
    for entry in runs_root.iterdir():
        if entry != keep and _is_expired_run(entry, cutoff):
            shutil.rmtree(entry)
            removed.append(entry)
    return removed


def prune_scan_runs(config: ResolvedConfig, *, keep: Path) -> tuple[str, ...]:
    """Remove the expired runs and ledgers once a scan has written its own; returns what the scan is to say about it.

    Two locations are pruned: the default one, and the shell wrapper's runs directory, which is the user's runs
    directory mounted in the image (`runs_dir_is_the_wrappers`). While `OPENULTRASAST_RUNS_DIR` points anywhere
    else, wherever it points, every run stays. Nothing is said when nothing was removed, and a removal that
    fails is said once and costs the scan nothing.

    The ledgers of tree digests (`prune_expired_ledgers`) lie under the same two locations and go by the same
    number of days, dated by their last use.
    """
    if runs_dir_is_overridden() and not runs_dir_is_the_wrappers():
        return ()
    root = Path(config.runs_dir)
    try:
        removed = prune_old_runs(root, keep=keep, retention_days=config.runs_retention_days)
    except (OSError, RecursionError) as exc:
        return (f"old runs could not be removed from {root}: {exc}",)
    notices = []
    if removed:
        runs = "run" if len(removed) == 1 else "runs"
        notices.append(f"removed {len(removed)} {runs} older than {config.runs_retention_days} days from {root}")
    ledgers = root / LEDGERS_DIRNAME
    gone, failed = prune_expired_ledgers(ledgers, retention_days=config.runs_retention_days)
    if gone:
        name = "ledger" if len(gone) == 1 else "ledgers"
        notices.append(f"removed {len(gone)} {name} of a tree digest unused for {config.runs_retention_days} days from {ledgers}")
    notices.extend(f"a ledger of a tree digest could not be removed from {ledgers}: {exc}" for _, exc in failed)
    return tuple(notices)


def _is_expired_ledger(entry: Path, cutoff: datetime) -> bool:
    """A ledger of a tree digest, or the temporary file it was written through, last used before `cutoff`."""
    if LEDGER_NAME.fullmatch(entry.name) is None or entry.is_symlink() or not entry.is_file():
        return False
    try:
        return datetime.fromtimestamp(entry.stat().st_mtime, UTC) < cutoff
    except (OSError, OverflowError, ValueError):
        return False


def prune_expired_ledgers(
    directory: Path, *, retention_days: int, now: datetime | None = None
) -> tuple[list[Path], list[tuple[Path, OSError]]]:
    """Remove the ledgers of tree digests under `directory` that were last used before `retention_days`; return them
    and the removals that failed.

    A ledger is dated by its use, since a scan marks it when it reads it, where a run is dated by its id. Files
    called something else, links and directories stay. Nothing raises.
    """
    if retention_days <= 0 or not directory.is_dir():
        return [], []
    try:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    except OverflowError:
        return [], []  # a retention longer than the calendar: no ledger is that old
    removed: list[Path] = []
    failed: list[tuple[Path, OSError]] = []
    try:
        entries = sorted(directory.iterdir())
    except OSError as exc:
        return [], [(directory, exc)]
    for entry in entries:
        if not _is_expired_ledger(entry, cutoff):
            continue
        try:
            entry.unlink()
        except FileNotFoundError:
            pass  # already gone
        except OSError as exc:
            failed.append((entry, exc))
        else:
            removed.append(entry)
    return removed, failed
