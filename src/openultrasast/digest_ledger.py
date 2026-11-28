"""The ledger of a tree's digest: what scans learned while the tree could not be written into, kept under the runs
directory and read by the next scan of the very same bytes (the decision of 2026-11-28)."""

from __future__ import annotations

import contextlib
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .calibration import (
    FalsePositiveLearning,
    load_false_positive_learnings,
    merge_false_positive_learnings,
    write_false_positive_learnings,
)

LEDGERS_DIRNAME = "calibration"
FOUND_NONE = "none"
FOUND_READ = "read"
FOUND_UNREADABLE = "unreadable"
WRITTEN = "written"
LEFT_AS_IT_WAS = "left as it was"
REMOVED = "removed"
FAILED = "failed"
# What became of a ledger after which it holds what a refusing tree could not take.
HOLDS_LEARNINGS = (WRITTEN, LEFT_AS_IT_WAS)
# A ledger, and the temporary file it is written through before its rename.
LEDGER_NAME = re.compile(r"[0-9a-f]{64}\.json(?:\.[0-9a-f]{32}\.tmp)?")


@dataclass(frozen=True)
class DigestLedger:
    """The ledger of one tree digest: where it is, whether a scan could read it, and what it held."""

    path: Path
    found: str
    learnings: list[FalsePositiveLearning] = field(default_factory=list)


def digest_ledger_path(runs_directory: Path, digest: str) -> Path:
    return Path(runs_directory) / LEDGERS_DIRNAME / f"{digest}.json"


def read_digest_ledger(path: Path) -> DigestLedger:
    """The ledger at `path` and what it held: `FOUND_NONE` when there is no file, `FOUND_UNREADABLE` when there is one
    that is not a ledger (a cache must not stop a scan), `FOUND_READ` otherwise.

    Reading one marks it as used, so that a ledger read every day stays while one left alone goes.
    """
    if not path.is_file():
        return DigestLedger(path, FOUND_NONE)
    try:
        learnings = load_false_positive_learnings(path)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        # Whatever a hand or another tool left there: the reader of the tree's ledger stops on it, a cache must not.
        return DigestLedger(path, FOUND_UNREADABLE)
    with contextlib.suppress(OSError):  # a mark that fails costs the scan nothing
        os.utime(path)
    return DigestLedger(path, FOUND_READ, learnings)


def settle_digest_ledger(
    ledger: DigestLedger,
    *,
    tree: list[FalsePositiveLearning],
    merged: list[FalsePositiveLearning],
    new: list[FalsePositiveLearning],
    tree_takes_it: bool,
) -> tuple[str, str]:
    """Bring the ledger of the digest in line with what this scan did to the tree's ledger.

    Returns what became of it and, when something failed, why. `tree` is what the tree's ledger held before this
    scan, `merged` what it is to hold now, `new` what this scan learned, and `tree_takes_it` whether the tree took
    that write, when there was one.

    - The tree took the write: everything the ledger held is in the tree's ledger now, so the ledger is removed.
    - The tree refused the write: the ledger is written instead, with its own entries and this scan's new ones,
      never one whose finding id the tree's ledger has, and only when that differs from its content; when that
      would leave it empty, it is removed.
    - There was no write: a ledger whose every entry the tree's ledger also has is removed. It has nothing left
      to give. This is also what removes a ledger again when an earlier removal failed, and one that could not
      be read, which is taken for empty.

    A ledger that could not be read is "unreadable" unless this scan wrote it or failed to: it is taken for
    empty and goes, since it has nothing left to give. A removal that finds the file already gone is nothing,
    and nothing here raises.
    """
    outcome = FOUND_NONE if ledger.found == FOUND_NONE else LEFT_AS_IT_WAS
    error = ""
    tree_ids = {learning.finding_id for learning in tree}
    if merged != tree:
        if tree_takes_it:
            if ledger.found != FOUND_NONE:
                outcome, error = _remove(ledger.path)
        else:
            kept = [learning for learning in merge_false_positive_learnings(ledger.learnings, new) if learning.finding_id not in tree_ids]
            if not kept:
                if ledger.found != FOUND_NONE:
                    outcome, error = _remove(ledger.path)
            elif kept != ledger.learnings:
                outcome, error = _write(ledger.path, kept)
    elif ledger.found != FOUND_NONE and all(learning.finding_id in tree_ids for learning in ledger.learnings):
        outcome, error = _remove(ledger.path)
    if ledger.found == FOUND_UNREADABLE and outcome not in (WRITTEN, FAILED):
        outcome = FOUND_UNREADABLE
    return outcome, error


def _write(path: Path, learnings: list[FalsePositiveLearning]) -> tuple[str, str]:
    """Through a temporary file of this writer's own and a rename: a scan stopped midway leaves the old ledger or the
    new one, and two scans of one tree never share a name."""
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        write_false_positive_learnings(learnings, temporary)
        os.replace(temporary, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
        return FAILED, str(exc)
    return WRITTEN, ""


def _remove(path: Path) -> tuple[str, str]:
    try:
        path.unlink()
    except FileNotFoundError:
        pass  # already gone: nothing to remove
    except OSError as exc:
        return FAILED, str(exc)
    return REMOVED, ""
