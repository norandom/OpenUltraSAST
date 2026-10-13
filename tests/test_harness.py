import json
from pathlib import Path

from openultrasast.config import load_config
from openultrasast.harness import HarnessRuntime, HarnessTraceWriter, write_harness_config


def test_runtime_emits_stage_events(tmp_path: Path) -> None:
    trace_path = tmp_path / "events.jsonl"
    runtime = HarnessRuntime(
        scan_id="scan-1",
        config=load_config(None),
        trace_writer=HarnessTraceWriter(trace_path),
    )

    result = runtime.run_stage("preprocess", lambda: "ok")

    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    assert result == "ok"
    assert [event["event_type"] for event in events] == ["stage_start", "stage_end"]


def test_harness_config_serializes_models_and_prompt_hashes(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text('[models]\nranker = "openrouter/ranker"\n')
    output = tmp_path / "harness.json"

    write_harness_config(
        config=load_config(config_path),
        path=output,
        prompts={"ranker": "score files"},
    )

    payload = json.loads(output.read_text())
    assert payload["model_roles"]["ranker"] == "openrouter/ranker"
    assert len(payload["prompt_hashes"]["ranker"]) == 64
