import subprocess
from typing import Any

import pytest

from openultrasast.sandbox import FakeSandboxProbe, SandboxProbe
from openultrasast.sandbox import probe as probe_mod


def _completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["docker", "info"], returncode, stdout="", stderr="")


def test_fake_probe_can_be_forced_off() -> None:
    probe = FakeSandboxProbe(available=False)
    assert probe.available() is False


def test_fake_probe_can_be_forced_on() -> None:
    probe = FakeSandboxProbe(available=True)
    assert probe.available() is True


def test_real_probe_is_available_when_docker_info_succeeds() -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return _completed(0)

    assert SandboxProbe(runner=runner).available() is True


def test_real_probe_is_unavailable_when_docker_info_fails() -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return _completed(1)

    assert SandboxProbe(runner=runner).available() is False


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("docker"),
        PermissionError("denied"),
        OSError("cannot talk to daemon"),
        subprocess.TimeoutExpired(cmd=["docker", "info"], timeout=5),
        RuntimeError("unexpected probe failure"),
    ],
)
def test_real_probe_returns_unavailable_without_raising(error: Exception) -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise error

    assert SandboxProbe(runner=runner).available() is False


def test_real_probe_runs_docker_info_with_short_timeout() -> None:
    seen: dict[str, Any] = {}

    def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["command"] = list(command)
        seen["timeout"] = kwargs.get("timeout")
        seen["check"] = kwargs.get("check")
        return _completed(0)

    assert SandboxProbe(runner=runner).available() is True
    assert seen["command"] == ["docker", "info"]
    assert seen["timeout"] == probe_mod.PROBE_TIMEOUT_SECONDS
    assert probe_mod.PROBE_TIMEOUT_SECONDS <= 10
    assert seen["check"] is False


def test_real_probe_is_skippable_in_unit_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("unit tests must not invoke the docker daemon")

    monkeypatch.setattr(probe_mod.subprocess, "run", boom)

    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return _completed(0)

    assert SandboxProbe(runner=runner).available() is True


def test_real_probe_default_path_uses_subprocess_run(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["command"] = list(command)
        seen["timeout"] = kwargs.get("timeout")
        seen["capture_output"] = kwargs.get("capture_output")
        seen["text"] = kwargs.get("text")
        return _completed(0)

    monkeypatch.setattr(probe_mod.subprocess, "run", fake_run)
    assert SandboxProbe().available() is True
    assert seen["command"] == ["docker", "info"]
    assert seen["timeout"] == probe_mod.PROBE_TIMEOUT_SECONDS
    assert seen["capture_output"] is True
    assert seen["text"] is True
