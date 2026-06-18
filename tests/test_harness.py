import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from openultrasast.config import load_config
from openultrasast.harness import (
    HarnessContractError,
    HarnessEvent,
    HarnessRuntime,
    HarnessTraceWriter,
    ProcessorSpec,
    write_harness_config,
)


@dataclass
class RecordingProcessor:
    spec: ProcessorSpec

    def handle(self, event: HarnessEvent, state: dict[str, Any]) -> dict[str, Any]:
        return {"seen_stage": event.stage}


@dataclass
class BadWriteProcessor:
    spec: ProcessorSpec

    def handle(self, event: HarnessEvent, state: dict[str, Any]) -> dict[str, Any]:
        return {"undeclared": event.event_type}


def test_runtime_emits_stage_events_and_processor_state(tmp_path: Path) -> None:
    trace_path = tmp_path / "events.jsonl"
    processor = RecordingProcessor(ProcessorSpec(name="recorder", version="1", handles=("stage_start",), writes=("seen_stage",)))
    runtime = HarnessRuntime(
        scan_id="scan-1",
        config=load_config(None),
        trace_writer=HarnessTraceWriter(trace_path),
        processors=[processor],
    )

    result = runtime.run_stage("preprocess", lambda: "ok")

    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    assert result == "ok"
    assert runtime.state["seen_stage"] == "preprocess"
    assert [event["event_type"] for event in events] == ["stage_start", "stage_start", "stage_end"]
    assert events[1]["payload"] == {"changed_state": ["seen_stage"], "processor": "recorder"}


def test_strict_contract_mode_rejects_undeclared_writes(tmp_path: Path) -> None:
    processor = BadWriteProcessor(ProcessorSpec(name="bad", version="1", handles=("stage_start",), writes=()))
    runtime = HarnessRuntime(
        scan_id="scan-1",
        config=load_config(None),
        trace_writer=HarnessTraceWriter(tmp_path / "events.jsonl"),
        processors=[processor],
    )

    with pytest.raises(HarnessContractError, match="undeclared writes"):
        runtime.emit("stage_start", "rank", {})


def test_warn_contract_mode_records_degradation(tmp_path: Path) -> None:
    processor = BadWriteProcessor(ProcessorSpec(name="bad", version="1", handles=("stage_start",), writes=()))
    runtime = HarnessRuntime(
        scan_id="scan-1",
        config=load_config(None),
        trace_writer=HarnessTraceWriter(tmp_path / "events.jsonl"),
        processors=[processor],
        contract_mode="warn",
    )

    runtime.emit("stage_start", "rank", {})

    assert "undeclared writes" in runtime.state["degradations"][0]
    assert '"status": "degraded"' in (tmp_path / "events.jsonl").read_text()


def test_harness_config_serializes_models_processors_and_prompt_hashes(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text('[models]\nranker = "openrouter/ranker"\n')
    processor = RecordingProcessor(ProcessorSpec(name="recorder", version="2026-01-01", handles=("stage_start",), writes=("seen_stage",)))
    output = tmp_path / "harness.json"

    write_harness_config(
        config=load_config(config_path),
        processors=[processor],
        contract_mode="strict",
        path=output,
        prompts={"ranker": "score files"},
    )

    payload = json.loads(output.read_text())
    assert payload["model_roles"]["ranker"] == "openrouter/ranker"
    assert payload["processor_versions"] == {"recorder": "2026-01-01"}
    assert len(payload["prompt_hashes"]["ranker"]) == 64
