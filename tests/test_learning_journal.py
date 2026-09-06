"""learning-harness task 2.8: the round journal, the archive and the rejected buffer (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.learning.scoring import PairFamilyScore


def _record(round_number: int, family: str, outcome: str, **extra: object) -> object:
    from openultrasast.learning.journal import Attribution, RoundRecord

    defaults: dict[str, object] = {
        "round": round_number,
        "family": family,
        "hypothesis": "the checklist never asks about ownership",
        "levers": ("checklist",),
        "predicted_affected": (family,),
        "predicted_at_risk": ("injection",),
        "outcome": outcome,
        "reason": "",
        "target_train_delta": 0.1,
        "target_holdout_delta": 0.2,
        "sweep": {"injection": 0},
        "attribution": Attribution(flipped_predicted=2, flipped_unpredicted=0, precision=1.0),
        "cost_usd": 0.42,
        "taxonomy_version": "1",
        "config_version": "2",
    }
    return RoundRecord(**{**defaults, **extra})  # type: ignore[arg-type]


def test_a_record_round_trips_through_the_file(tmp_path: Path) -> None:
    from openultrasast.learning.journal import LearningJournal

    journal = LearningJournal(tmp_path / "journal.jsonl")
    assert journal.rounds() == ()
    record = _record(1, "access_control", "accepted")
    journal.append(record)
    journal.append(_record(2, "injection", "rejected", reason="tie"))
    rounds = journal.rounds()
    assert [item.round for item in rounds] == [1, 2] and rounds[0] == record
    assert rounds[0].attribution.precision == 1.0 and rounds[0].sweep == {"injection": 0}
    assert rounds[1].outcome == "rejected" and rounds[1].reason == "tie"
    rows = [json.loads(line) for line in (tmp_path / "journal.jsonl").read_text().splitlines() if line.strip()]
    assert len(rows) == 2 and rows[0]["hypothesis"].startswith("the checklist")


def test_the_journal_is_append_only_and_a_round_number_is_never_reused(tmp_path: Path) -> None:
    from openultrasast.learning.journal import JournalError, LearningJournal

    journal = LearningJournal(tmp_path / "journal.jsonl")
    journal.append(_record(1, "access_control", "accepted"))
    before = (tmp_path / "journal.jsonl").read_text()
    try:
        journal.append(_record(1, "injection", "accepted"))
        raise AssertionError("a repeated round number must be refused")
    except JournalError as error:
        assert "1" in str(error)
    assert (tmp_path / "journal.jsonl").read_text() == before
    assert journal.next_round() == 2


def test_the_rejected_buffer_returns_only_the_target_family(tmp_path: Path) -> None:
    from openultrasast.learning.journal import LearningJournal

    journal = LearningJournal(tmp_path / "journal.jsonl")
    journal.append(_record(1, "access_control", "rejected", hypothesis="ask about ownership", reason="tie"))
    journal.append(_record(2, "injection", "rejected", hypothesis="ask about quoting", reason="tie"))
    journal.append(_record(3, "access_control", "accepted", hypothesis="give it the obligations tool"))
    assert journal.rejected_buffer("access_control") == ("ask about ownership",)
    assert journal.rejected_buffer("injection") == ("ask about quoting",)
    assert journal.rejected_buffer("memory") == ()


def test_the_archive_names_one_winning_configuration_per_pair_and_family(tmp_path: Path) -> None:
    from openultrasast.learning.journal import Archive

    archive = Archive(tmp_path / "archive.jsonl")
    correct = PairFamilyScore(pair="a", family="access_control", runs=("pair_correct",), outcome="pair_correct")
    missed = PairFamilyScore(pair="a", family="access_control", runs=("both_silent",), outcome="both_silent")
    archive.record("access_control", "1", correct)
    archive.record("access_control", "2", missed)  # a later version that loses this pair does not take it
    archive.record(
        "access_control", "2", PairFamilyScore(pair="b", family="access_control", runs=("pair_correct",), outcome="pair_correct")
    )
    assert archive.winners("access_control") == {"a": "1", "b": "2"}
    assert archive.winners("injection") == {}
    reopened = Archive(tmp_path / "archive.jsonl")
    assert reopened.winners("access_control") == {"a": "1", "b": "2"}  # survives a reload, like the store it copies


def test_a_later_version_takes_a_pair_only_by_winning_it(tmp_path: Path) -> None:
    from openultrasast.learning.journal import Archive

    archive = Archive(tmp_path / "archive.jsonl")
    archive.record("injection", "1", PairFamilyScore(pair="a", family="injection", runs=("both_silent",), outcome="both_silent"))
    assert archive.winners("injection") == {}
    archive.record("injection", "2", PairFamilyScore(pair="a", family="injection", runs=("pair_correct",), outcome="pair_correct"))
    assert archive.winners("injection") == {"a": "2"}


def test_everything_persisted_passes_redaction(tmp_path: Path) -> None:
    from openultrasast.learning.journal import LearningJournal

    leaked = "api_key = " + "'" + "A" * 24 + "'"  # assembled here so no key-shaped literal sits in the file
    journal = LearningJournal(tmp_path / "journal.jsonl")
    journal.append(_record(1, "access_control", "rejected", hypothesis=f"the prompt should show {leaked}", reason="tie"))
    text = (tmp_path / "journal.jsonl").read_text()
    assert "A" * 24 not in text and "REDACTED" in text
    assert journal.rounds()[0].hypothesis.endswith("'")
