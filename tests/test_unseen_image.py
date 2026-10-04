"""Static image contract; no Docker invocation."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE_SHA = "06ec67d411cd7abbfcd0735b1c2a70e4f3eb65ddcfeef89975709c664f59ad42"


def test_image_stages():
    text = (ROOT / "plane/Dockerfile.engine-task").read_text()
    engine, replay = text.split("FROM engine AS replay", 1)
    original = engine.replace("v0.3.1 AS engine", "v0.3.1").rstrip() + "\n"
    assert hashlib.sha256(original.encode()).hexdigest() == ENGINE_SHA
    assert "FROM ghcr.io/norandom/ax-task-runner:v0.3.1 AS engine" in engine
    assert "git" in replay and "replay_entry.py" in replay and "ousast pre-push --help" in replay
