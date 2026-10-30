"""Task 12.3 -- runner instrument and hard runtime gates (Reqs 5.6, 6.1, 6.3).

Gate fixtures refuse the summary: zero-byte and stale-anchor records raise
InstrumentFailure, a change over the 120-second budget raises GateFailure, and
the deadline record stamps budget + exceeded flag per record.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import development_runner  # noqa: E402
from benchmarks.valid.development_runner import (  # noqa: E402
    DevelopmentRecord,
    InstrumentFailure,
    deadline_record,
    enforce_gates,
    summarize_development,
)

GateFailure = development_runner.GateFailure


def _record(
    *,
    seconds: float = 1.0,
    change_id: str = "change-1",
    instrument_reason: str | None = None,
) -> DevelopmentRecord:
    judgment: dict[str, object] = {"unguarded": 0, "discharged": 0, "indeterminate": 1}
    funnel: dict[str, dict[str, object]] = {"judgment": judgment}
    if instrument_reason is not None:
        funnel["instrument"] = {"reason": instrument_reason}
    return DevelopmentRecord(
        change_id=change_id,
        analyzer_revision="0" * 12,
        fact_set_digest="1" * 12,
        acquisition_record_digest="2" * 12,
        configuration_digest="3" * 12,
        population_digest="4" * 12,
        input_digest="5" * 12,
        stage_funnel=funnel,
        judgment_transition="same",
        seconds=seconds,
    )


def test_enforce_gates_passes_clean_records() -> None:
    enforce_gates((_record(seconds=1.0), _record(seconds=119.9, change_id="change-2")))


def test_enforce_gates_fails_a_change_over_the_budget() -> None:
    with pytest.raises(GateFailure) as caught:
        enforce_gates((_record(seconds=0.5), _record(seconds=121.0, change_id="slow-change")))
    assert "slow-change" in str(caught.value)


def test_budget_is_overridable_for_fixtures() -> None:
    with pytest.raises(GateFailure):
        enforce_gates((_record(seconds=6.0),), budget_seconds=5.0)


def test_deadline_record_stamps_budget_and_exceeded() -> None:
    kept = deadline_record(_record(seconds=1.0), budget_seconds=120.0)
    assert kept == {"deadline_seconds": 120.0, "exceeded": False}
    blown = deadline_record(_record(seconds=121.0), budget_seconds=120.0)
    assert blown == {"deadline_seconds": 120.0, "exceeded": True}


def test_summary_refuses_an_overrun_never_reports_it_passing() -> None:
    with pytest.raises(GateFailure):
        summarize_development((_record(seconds=121.0),))


def test_summary_reports_clean_records() -> None:
    summary = summarize_development((_record(seconds=1.0), _record(seconds=2.0, change_id="change-2")))
    assert summary["total_changes"] == 2
    assert summary["max_seconds"] == 2.0


def test_zero_byte_record_refuses_the_summary() -> None:
    with pytest.raises(InstrumentFailure) as caught:
        summarize_development((_record(instrument_reason="zero-byte read"),))
    assert "zero-byte" in str(caught.value)


def test_stale_anchor_record_refuses_the_summary() -> None:
    with pytest.raises(InstrumentFailure) as caught:
        summarize_development((_record(instrument_reason="stale_anchor"),))
    assert "stale_anchor" in str(caught.value)
