from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

from .config import ResolvedConfig

EventType = Literal[
    "task_start",
    "stage_start",
    "before_model",
    "after_model",
    "before_tool",
    "after_tool",
    "stage_end",
    "task_end",
]

ContractMode = Literal["strict", "warn"]


class HarnessContractError(ValueError):
    """Raised when a processor violates its declared state contract."""


@dataclass(frozen=True)
class HarnessEvent:
    event_type: EventType
    scan_id: str
    stage: str | None
    timestamp: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProcessorSpec:
    name: str
    version: str
    handles: tuple[EventType, ...]
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()


class Processor(Protocol):
    spec: ProcessorSpec

    def handle(self, event: HarnessEvent, state: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError


@dataclass(frozen=True)
class SerializedHarnessConfig:
    contract_mode: ContractMode
    model_roles: dict[str, str | None]
    processor_versions: dict[str, str]
    prompt_hashes: dict[str, str]


class HarnessTraceWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: HarnessEvent) -> None:
        with self.path.open("a") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")


class HarnessRuntime:
    def __init__(
        self,
        *,
        scan_id: str,
        config: ResolvedConfig,
        trace_writer: HarnessTraceWriter,
        processors: list[Processor] | None = None,
        contract_mode: ContractMode = "strict",
    ) -> None:
        self.scan_id = scan_id
        self.config = config
        self.trace_writer = trace_writer
        self.processors = processors or []
        self.contract_mode = contract_mode
        self.state: dict[str, Any] = {"degradations": []}

    def start(self, *, mode: str, target: Path) -> None:
        self.emit("task_start", None, {"mode": mode, "target": str(target)})

    def finish(self, *, status: str) -> None:
        self.emit("task_end", None, {"status": status})

    def run_stage(self, name: str, callback: Callable[[], Any]) -> Any:
        self.emit("stage_start", name, {})
        try:
            result = callback()
        except Exception as exc:
            self.emit("stage_end", name, {"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            raise
        self.emit("stage_end", name, {"status": "succeeded"})
        return result

    def emit(self, event_type: EventType, stage: str | None, payload: dict[str, Any]) -> None:
        event = HarnessEvent(
            event_type=event_type,
            scan_id=self.scan_id,
            stage=stage,
            timestamp=datetime.now(UTC).isoformat(),
            payload=payload,
        )
        self.trace_writer.append(event)
        for processor in self.processors:
            if event_type in processor.spec.handles:
                self._run_processor(processor, event)

    def _run_processor(self, processor: Processor, event: HarnessEvent) -> None:
        before = set(self.state)
        missing_reads = [key for key in processor.spec.reads if key not in self.state]
        if missing_reads:
            self._contract_violation(processor.spec.name, f"missing reads: {', '.join(missing_reads)}")
            return

        updates = processor.handle(event, dict(self.state)) or {}
        if not isinstance(updates, dict):
            self._contract_violation(processor.spec.name, "processor returned a non-dict update")
            return
        undeclared = sorted(set(updates) - set(processor.spec.writes))
        if undeclared:
            self._contract_violation(processor.spec.name, f"undeclared writes: {', '.join(undeclared)}")
            return
        self.state.update(updates)
        changed = sorted(set(self.state) - before | set(updates))
        self.trace_writer.append(
            HarnessEvent(
                event_type=event.event_type,
                scan_id=self.scan_id,
                stage=event.stage,
                timestamp=datetime.now(UTC).isoformat(),
                payload={"processor": processor.spec.name, "changed_state": changed},
            )
        )

    def _contract_violation(self, processor_name: str, reason: str) -> None:
        message = f"processor {processor_name} contract violation: {reason}"
        if self.contract_mode == "strict":
            raise HarnessContractError(message)
        self.state.setdefault("degradations", []).append(message)
        self.trace_writer.append(
            HarnessEvent(
                event_type="stage_end",
                scan_id=self.scan_id,
                stage="processor_contract",
                timestamp=datetime.now(UTC).isoformat(),
                payload={"status": "degraded", "reason": message},
            )
        )


def write_harness_config(
    *,
    config: ResolvedConfig,
    processors: list[Processor],
    contract_mode: ContractMode,
    path: Path,
    prompts: dict[str, str] | None = None,
) -> None:
    prompts = prompts or {}
    serialized = SerializedHarnessConfig(
        contract_mode=contract_mode,
        model_roles={
            "ranker": config.models.ranker,
            "hunter": config.models.hunter,
            "verifier": config.models.verifier,
            "patcher": config.models.patcher,
        },
        processor_versions={processor.spec.name: processor.spec.version for processor in processors},
        prompt_hashes={name: _hash_text(prompt) for name, prompt in sorted(prompts.items())},
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(serialized), indent=2, sort_keys=True) + "\n")


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
