"""ai-service-plane Req 3.5/3.6: one trivial Task end to end on the real ax cluster of ``ops/ax/up.sh``.

Marker ``ax``; skipped unless every check of ``ousast plane doctor`` passes, so the host suite never depends on
the cluster. Run it on purpose: ``pytest -m ax tests/test_plane_ax_live.py``.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from openultrasast.plane.reconciler import Ax, doctor

pytestmark = pytest.mark.ax
SMOKE = Path("ops/ax/smoke-task.yaml")


@pytest.fixture(scope="module")
def live_ax() -> Ax:
    checks = doctor()
    failing = [f"{name}: {text}" for name, ok, text in checks if not ok]
    if failing:
        pytest.skip("no live ax cluster: " + "; ".join(failing))
    if not SMOKE.is_file():
        pytest.skip(f"{SMOKE} is not in this checkout")
    return Ax()


def test_smoke_task_completes_on_the_cluster(live_ax: Ax) -> None:
    live_ax.apply(SMOKE)
    deadline = time.monotonic() + 600
    phase = "Pending"
    try:
        while time.monotonic() < deadline:
            phase = live_ax.phase("ousast-smoke")
            if any(word in phase.lower() for word in ("completed", "succeeded", "failed", "error")):
                break
            time.sleep(5)
    finally:
        live_ax.delete("ousast-smoke")
    assert phase.lower() in ("completed", "succeeded"), f"smoke task ended in phase {phase!r}"
