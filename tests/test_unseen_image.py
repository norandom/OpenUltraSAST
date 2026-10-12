"""Static image contract; no Docker invocation."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The engine portion is pinned so that adding the replay stage cannot silently change the engine image.
# Recompute after an intentional engine-stage change: it is sha256 of `engine.rstrip() + "\n"` where `engine`
# is everything before the `FROM ${ENGINE_REF} AS replay` line.
ENGINE_SHA = "77c34f3381cef6c6d1f7fd761cd3924a3656cc5e6eb20c51c819de77afb4b2fc"


def test_image_stages():
    text = (ROOT / "plane/Dockerfile.engine-task").read_text()
    # The replay stage builds FROM the engine stage (via the ENGINE_REF arg, default `engine`).
    engine, replay = text.split("FROM ${ENGINE_REF} AS replay", 1)
    assert hashlib.sha256((engine.rstrip() + "\n").encode()).hexdigest() == ENGINE_SHA
    # Task base is digest-pinned (no floating fallback) and built in two stages: joern-build -> engine.
    assert "FROM ghcr.io/norandom/ousast-task-base:${TASK_BASE_TAG}@${TASK_BASE_DIGEST} AS joern-build" in engine
    assert "FROM ghcr.io/norandom/ousast-task-base:${TASK_BASE_TAG}@${TASK_BASE_DIGEST} AS engine" in engine
    # The replay stage is a pure addition on top of engine: the unseen replay harness + a smoke check.
    assert "replay_entry.py" in replay and "ousast pre-push --help" in replay
