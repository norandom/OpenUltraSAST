"""Slot-contract discipline for model-disabled deterministic stages (task 6.3).

The deterministic scan stages carry their work in named *slots* and run with model
invocation disabled (``skip_model = True``). Each stage declares a read/write slot
allow-list that is validated on every lifecycle hook, preserving the
``ProcessorSpec.reads/writes`` provenance discipline of the sync ``HarnessRuntime``
(the top-level driver) — without forcing the deterministic stages through HarnessX's
agent loop ("bridge, do not map", per the spec design).

This is the zero-dependency substrate. When the optional ``openultrasast[harnessx]``
extra is present, the same model-disabled processors can be hosted under a HarnessX
``MultiHookProcessor`` (see ``stage_processors.host_under_harnessx``); the
``skip_model`` marker maps onto HarnessX's ``BeforeModelEvent.skip_model`` so no
deterministic stage incurs a model call.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .harness import HarnessContractError


class SlotContractError(HarnessContractError):
    """Raised when a stage reads or writes a slot outside its declared allow-list."""


class SlotContractMixin:
    """A model-disabled stage that carries work in slots under a read/write allow-list."""

    name: str = "slot-stage"
    version: str = "1"
    reads_slots: tuple[str, ...] = ()
    writes_slots: tuple[str, ...] = ()
    skip_model: bool = True  # deterministic: never invokes a model

    def run(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def validate_reads(self, slots: Mapping[str, Any]) -> None:
        missing = sorted(slot for slot in self.reads_slots if slot not in slots)
        if missing:
            raise SlotContractError(f"{self.name}: missing read slots: {', '.join(missing)}")

    def validate_writes(self, updates: Mapping[str, Any]) -> None:
        undeclared = sorted(set(updates) - set(self.writes_slots))
        if undeclared:
            raise SlotContractError(f"{self.name}: undeclared write slots: {', '.join(undeclared)}")

    def execute(self, slots: Mapping[str, Any]) -> dict[str, Any]:
        """Validate the read allow-list, run the stage, validate the write allow-list."""
        self.validate_reads(slots)  # pre-hook
        updates = self.run(slots) or {}
        if not isinstance(updates, dict):
            raise SlotContractError(f"{self.name}: stage returned a non-dict update")
        self.validate_writes(updates)  # post-hook
        return updates


class _Emitter(Protocol):
    def emit(self, event_type: Any, stage: str | None, payload: dict[str, Any]) -> None: ...


class SlotPipeline:
    """Runs slot processors in order, validating contracts and enforcing model-disable."""

    def __init__(self, processors: list[SlotContractMixin]) -> None:
        for proc in processors:
            if not proc.skip_model:
                raise SlotContractError(f"{proc.name}: deterministic stage must be model-disabled (skip_model=True)")
        self._processors = processors

    @property
    def processors(self) -> list[SlotContractMixin]:
        return list(self._processors)

    def run(self, initial_slots: Mapping[str, Any], *, runtime: _Emitter | None = None) -> dict[str, Any]:
        """Execute every stage; with ``runtime`` set, emit stage_start/stage_end lifecycle hooks."""
        slots: dict[str, Any] = dict(initial_slots)
        for proc in self._processors:
            if runtime is not None:
                runtime.emit(
                    "stage_start", proc.name, {"reads": list(proc.reads_slots), "writes": list(proc.writes_slots), "skip_model": True}
                )
            updates = proc.execute(slots)
            slots.update(updates)
            if runtime is not None:
                runtime.emit("stage_end", proc.name, {"status": "succeeded", "wrote": sorted(updates)})
        return slots


__all__ = ["SlotContractError", "SlotContractMixin", "SlotPipeline"]
