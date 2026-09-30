"""Model-disabled, slot-contracted deterministic stages (Phase 3 task 6.3).

Proves: deterministic stages carry work in declared slots, a slot-contract violation
is raised on undeclared slot access, the pipeline is model-disabled, the slot pipeline
reproduces the deterministic quick-scan path byte-for-byte, and lifecycle hooks fire.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from openultrasast.gate import _quick_scan
from openultrasast.slot_contract import SlotContractError, SlotContractMixin, SlotPipeline
from openultrasast.stage_processors import (
    build_deterministic_pipeline,
    deterministic_processors,
    run_quick_pipeline,
)


class _GoodStage(SlotContractMixin):
    name = "good"
    reads_slots = ("a",)
    writes_slots = ("b",)

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        return {"b": slots["a"] + 1}


class _UndeclaredWriteStage(SlotContractMixin):
    name = "bad_write"
    reads_slots = ()
    writes_slots = ("declared",)

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        return {"undeclared": 1}


class _MissingReadStage(SlotContractMixin):
    name = "bad_read"
    reads_slots = ("required",)
    writes_slots = ()

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        return {}


# ---- slot contract enforcement (1.5) ----------------------------------------


def test_declared_slots_pass() -> None:
    assert _GoodStage().execute({"a": 1}) == {"b": 2}


def test_undeclared_write_is_rejected() -> None:
    with pytest.raises(SlotContractError, match="undeclared write slots: undeclared"):
        _UndeclaredWriteStage().execute({})


def test_missing_read_is_rejected() -> None:
    with pytest.raises(SlotContractError, match="missing read slots: required"):
        _MissingReadStage().execute({})


# ---- model-disabled invariant (1.6) -----------------------------------------


def test_all_deterministic_stages_are_model_disabled() -> None:
    assert all(proc.skip_model for proc in deterministic_processors())


def test_pipeline_rejects_a_model_enabled_stage() -> None:
    enabled = _GoodStage()
    enabled.skip_model = False
    with pytest.raises(SlotContractError, match="model-disabled"):
        SlotPipeline([enabled])


# ---- parity with the deterministic quick-scan path --------------------------


def test_pipeline_findings_match_quick_scan_baseline() -> None:
    target = Path("benchmarks/fixtures/python-vulnerable")
    slots = run_quick_pipeline(target)
    assert slots["reported_findings"] == _quick_scan(target)
    assert "score" in slots  # the score slot is produced too


# ---- lifecycle hooks fire per stage -----------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None]] = []

    def emit(self, event_type: Any, stage: str | None, payload: dict[str, Any]) -> None:
        self.events.append((event_type, stage))


def test_pipeline_emits_lifecycle_hooks_per_stage() -> None:
    recorder = _Recorder()
    run_quick_pipeline(Path("benchmarks/fixtures/python-vulnerable"), runtime=recorder)
    names = [proc.name for proc in build_deterministic_pipeline().processors]
    for name in names:
        assert ("stage_start", name) in recorder.events
        assert ("stage_end", name) in recorder.events
