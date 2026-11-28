"""The ledger of a tree's digest (contributor-scan, the design note of 2026-11-27, approved on 2026-11-28): what
scans learned while the tree could not be written, kept under the runs directory and read by the next scan of the
very same bytes."""

import errno
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from openultrasast import digest_ledger
from openultrasast.calibration import FalsePositiveLearning, FalsePositiveReason, write_false_positive_learnings
from openultrasast.digest_ledger import digest_ledger_path, read_digest_ledger, settle_digest_ledger

DIGEST = "a" * 64


def _learning(finding_id: str, evidence: str = "no route reaches it") -> FalsePositiveLearning:
    return FalsePositiveLearning(finding_id, f"pkg/{finding_id}.py", "xss", FalsePositiveReason.UNREACHABLE_PATH, evidence, "pkg")


def _ids(learnings: list[FalsePositiveLearning]) -> list[str]:
    return [learning.finding_id for learning in learnings]


def _ledger(runs: Path, learnings: list[FalsePositiveLearning] | None) -> digest_ledger.DigestLedger:
    """The ledger of one digest under `runs`, holding `learnings` (no file when None), as a scan reads it."""
    path = digest_ledger_path(runs, DIGEST)
    if learnings is not None:
        write_false_positive_learnings(learnings, path)
    return read_digest_ledger(path)


def _settle(
    ledger: digest_ledger.DigestLedger,
    *,
    tree: list[FalsePositiveLearning],
    merged: list[FalsePositiveLearning],
    new: list[FalsePositiveLearning],
    tree_takes_it: bool = False,
) -> str:
    return settle_digest_ledger(ledger, tree=tree, merged=merged, new=new, tree_takes_it=tree_takes_it)[0]


def test_the_ledger_of_a_digest_sits_under_the_runs_directory_named_by_the_digest(tmp_path: Path) -> None:
    assert digest_ledger_path(tmp_path, DIGEST) == tmp_path / "calibration" / f"{DIGEST}.json"


def test_reading_a_ledger_marks_it_as_used(tmp_path: Path) -> None:
    """A ledger read every day stays while one left alone goes: an expired ledger is dated by its use."""
    path = digest_ledger_path(tmp_path, DIGEST)
    write_false_positive_learnings([_learning("a")], path)
    old = datetime.now(UTC) - timedelta(days=40)
    os.utime(path, (old.timestamp(), old.timestamp()))

    ledger = read_digest_ledger(path)

    assert (ledger.found, _ids(ledger.learnings)) == ("read", ["a"])
    assert path.stat().st_mtime > (datetime.now(UTC) - timedelta(days=1)).timestamp()


def test_a_missing_ledger_is_none_and_one_that_is_not_a_ledger_is_unreadable(tmp_path: Path) -> None:
    """Whatever a hand or another tool left there: a file that is not a ledger must not stop a scan. (An object whose
    `learnings` is a string or an object reads as an empty ledger, as the tree's own loader reads it.)"""
    path = digest_ledger_path(tmp_path, DIGEST)
    assert read_digest_ledger(path).found == "none"

    path.parent.mkdir(parents=True)
    for content in ("not a ledger\n", "", "{", "[]\n", "null\n", "5\n", '"text"\n', "true\n", "[" * 5000 + "]" * 5000):
        path.write_text(content)

        assert read_digest_ledger(path).found == "unreadable", content


def test_when_the_tree_refuses_the_ledger_takes_what_the_tree_does_not_already_hold(tmp_path: Path) -> None:
    """The tree's ledger holds `a`; this scan learned `a` once more and `b`: only `b` is new to the tree."""
    ledger = _ledger(tmp_path, None)

    outcome = _settle(ledger, tree=[_learning("a")], merged=[_learning("a"), _learning("b")], new=[_learning("a"), _learning("b")])

    assert outcome == "written"
    assert _ids(read_digest_ledger(ledger.path).learnings) == ["b"]


def test_a_ledger_whose_content_would_not_change_is_left_as_it_was(tmp_path: Path) -> None:
    """The common case in the image: the same bytes scanned again re-learn what the ledger already holds."""
    ledger = _ledger(tmp_path, [_learning("b")])
    before = ledger.path.read_bytes()

    outcome = _settle(ledger, tree=[], merged=[_learning("b")], new=[_learning("b")])

    assert outcome == "left as it was"
    assert ledger.path.read_bytes() == before


def test_when_the_tree_takes_the_write_the_ledger_is_removed(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path, [_learning("b")])

    assert _settle(ledger, tree=[], merged=[_learning("b")], new=[], tree_takes_it=True) == "removed"
    assert not ledger.path.exists()


def test_a_ledger_is_removed_once_the_tree_holds_every_entry_it_had(tmp_path: Path) -> None:
    """Nothing was written into the tree this scan: the entries were put there by hand, as a commit could."""
    ledger = _ledger(tmp_path, [_learning("b")])

    assert _settle(ledger, tree=[_learning("b")], merged=[_learning("b")], new=[_learning("b")]) == "removed"
    assert not ledger.path.exists()


def test_an_emptied_ledger_is_removed_rather_than_written_empty(tmp_path: Path) -> None:
    """The tree holds `b` with other evidence; the scan re-learned `b`, the tree refused, and nothing is left to keep."""
    ledger = _ledger(tmp_path, [_learning("b", "the first evidence")])

    outcome = _settle(ledger, tree=[_learning("b", "the first evidence")], merged=[_learning("b")], new=[_learning("b")])

    assert outcome == "removed"
    assert not ledger.path.exists()


def test_a_ledger_that_cannot_be_read_is_taken_for_empty_and_said_unreadable_unless_it_is_written(
    tmp_path: Path,
) -> None:
    path = digest_ledger_path(tmp_path, DIGEST)
    path.parent.mkdir(parents=True)
    path.write_text("not a ledger\n")

    assert _settle(read_digest_ledger(path), tree=[], merged=[_learning("b")], new=[_learning("b")]) == "written"
    assert _ids(read_digest_ledger(path).learnings) == ["b"]

    path.write_text("not a ledger\n")
    assert _settle(read_digest_ledger(path), tree=[_learning("b")], merged=[_learning("b")], new=[]) == "unreadable"
    assert not path.exists()


def test_a_write_that_fails_leaves_the_old_ledger_and_no_temporary_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Written through a temporary file of its own and a rename: a scan stopped midway leaves the old ledger or the
    new one, never the two together."""
    ledger = _ledger(tmp_path, [_learning("b")])
    before = ledger.path.read_bytes()
    names: list[str] = []

    def interrupted(source, target):  # type: ignore[no-untyped-def]
        names.append(Path(source).name)
        raise InterruptedError(errno.EINTR, "interrupted", str(source))

    monkeypatch.setattr(digest_ledger.os, "replace", interrupted)

    outcome = settle_digest_ledger(ledger, tree=[], merged=[_learning("b"), _learning("c")], new=[_learning("c")], tree_takes_it=False)

    assert outcome[0] == "failed"
    assert "interrupted" in outcome[1]
    assert ledger.path.read_bytes() == before
    assert names and names[0].startswith(ledger.path.name) and names[0] != ledger.path.name
    assert [entry.name for entry in ledger.path.parent.iterdir()] == [ledger.path.name]


def test_a_removal_that_fails_is_failed_and_raises_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger(tmp_path, [_learning("b")])
    unlink = Path.unlink

    def refusing(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == ledger.path:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refusing)

    assert settle_digest_ledger(ledger, tree=[], merged=[_learning("b")], new=[], tree_takes_it=True) == (
        "failed",
        f"[Errno 13] Permission denied: '{ledger.path}'",
    )
    assert ledger.path.is_file()
