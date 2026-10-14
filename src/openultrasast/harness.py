from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

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


@dataclass(frozen=True)
class HarnessEvent:
    event_type: EventType
    scan_id: str
    stage: str | None
    timestamp: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SerializedHarnessConfig:
    model_roles: dict[str, str | None]
    prompt_hashes: dict[str, str]


class HarnessTraceWriter:
    def __init__(self, path: Path, *, redact: bool = True) -> None:
        self.path = path
        self.redact = redact
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: HarnessEvent) -> None:
        line = json.dumps(asdict(event), sort_keys=True)
        if self.redact:
            from .redaction import redact_secrets

            line = redact_secrets(line)
        with self.path.open("a") as handle:
            handle.write(line + "\n")


class HarnessRuntime:
    def __init__(
        self,
        *,
        scan_id: str,
        config: ResolvedConfig,
        trace_writer: HarnessTraceWriter,
    ) -> None:
        self.scan_id = scan_id
        self.config = config
        self.trace_writer = trace_writer
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


def write_harness_config(
    *,
    config: ResolvedConfig,
    path: Path,
    prompts: dict[str, str] | None = None,
) -> None:
    prompts = prompts or {}
    serialized = SerializedHarnessConfig(
        model_roles={
            "ranker": config.models.ranker,
            "hunter": config.models.hunter,
            "verifier": None,  # schema kept byte for byte; LLM verification runs on the plane
            "patcher": None,  # schema kept; `[models] patcher` was retired 2026-10-02 (never read)
        },
        prompt_hashes={name: _hash_text(prompt) for name, prompt in sorted(prompts.items())},
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(serialized), indent=2, sort_keys=True) + "\n")


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
