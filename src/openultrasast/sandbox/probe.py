"""Docker CLI presence and usability probe."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from subprocess import CompletedProcess

PROBE_TIMEOUT_SECONDS = 5

_DOCKER_INFO = ("docker", "info")


class SandboxProbe:
    """Report whether `docker info` succeeds without raising into the scan."""

    def __init__(self, *, runner: Callable[..., CompletedProcess[str]] | None = None) -> None:
        self._runner = runner

    def available(self) -> bool:
        run = self._runner if self._runner is not None else subprocess.run
        try:
            result = run(
                list(_DOCKER_INFO),
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False


class FakeSandboxProbe:
    """Test double that reports a programmed availability without touching Docker."""

    def __init__(self, available: bool) -> None:
        self._available = available

    def available(self) -> bool:
        return self._available
