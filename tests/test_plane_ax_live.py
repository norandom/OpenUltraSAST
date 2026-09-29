"""ai-service-plane Req 3.5/3.6: one trivial Task end to end on the real ax cluster of ``ops/ax/up.sh``.

Marker ``ax``; opt-in only (``OUSAST_AX_LIVE=1``) and skipped unless every check of ``ousast plane doctor``
passes, so the host suite never depends on cluster state. It applies the digest-pinned smoke manifest that
``ops/ax/up.sh`` renders. Run it on purpose: ``OUSAST_AX_LIVE=1 pytest -m ax tests/test_plane_ax_live.py``.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from openultrasast.plane.reconciler import TRANSIENT, Ax, doctor

pytestmark = pytest.mark.ax
SMOKE = Path.home() / ".cache/ousast/ax-src/smoke-task.yaml"


@pytest.fixture(scope="module")
def live_ax() -> Ax:
    if os.environ.get("OUSAST_AX_LIVE") != "1":
        pytest.skip("live ax test is opt-in: set OUSAST_AX_LIVE=1")
    checks = doctor()
    failing = [f"{name}: {text}" for name, ok, text in checks if not ok]
    if failing:
        pytest.skip("no live ax cluster: " + "; ".join(failing))
    if not SMOKE.is_file():
        pytest.skip(f"{SMOKE} is not in this checkout")
    return Ax()


def resume_until_accepted(ax: Ax, name: str, deadline: float) -> None:
    """ax creates a Task Suspended; the first resume of a new image may time out while its snapshot is built."""
    error: str | None = "not tried"
    while error is not None and time.monotonic() < deadline:
        error = ax.resume(name)
        if error is not None and not TRANSIENT.search(error):
            raise AssertionError(f"ax resume task {name} failed: {error}")
        if error is not None:
            time.sleep(10)
    assert error is None, f"ax resume task {name} never went through: {error}"


def test_smoke_task_runs_and_its_runner_survives_suspend_and_resume(live_ax: Ax) -> None:
    """ax has no Completed phase: the smoke task must reach Running after resume, and its runner must stay up after
    the command so that a suspend and a second resume still go through (an exiting runner made resumes time out)."""
    name = "ousast-smoke"
    live_ax.delete(name)
    live_ax.apply(SMOKE)
    deadline = time.monotonic() + 900
    try:
        resume_until_accepted(live_ax, name, deadline)
        phase, message = live_ax.phase(name)
        assert phase == "Running", f"after resume: {phase} ({message})"
        time.sleep(30)  # the model-free repo-facts command is finished by now
        suspended = subprocess.run(["ax", "suspend", "task", name], capture_output=True, text=True, check=False)
        assert suspended.returncode == 0, suspended.stderr
        resume_until_accepted(live_ax, name, deadline)
        phase, message = live_ax.phase(name)
        assert phase == "Running", f"after the second resume: {phase} ({message})"
    finally:
        live_ax.delete(name)
