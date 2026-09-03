"""Docker CLI sandbox runner that never mounts the host Docker socket."""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess
from typing import Protocol

NONROOT_USER = "65534:65534"
WORKSPACE_MOUNT = "/workspace"
SCRATCH_MOUNT = "/scratch"
SCRATCH_SEED_MOUNT = "/scratch-in"
RUNNER_ENV = "OPENULTRASAST_SANDBOX_RUNNER"
_COPY_SEED_THEN_EXEC = 'cp -r /scratch-in/. /scratch/ && exec "$@"'
_SEED_ARGV0 = "ousast-sandbox"
_FAKE_RUNNER = frozenset({"fake"})


class SandboxRunner(Protocol):
    def run(self, spec: SandboxJob) -> SandboxResult: ...


@dataclass(frozen=True)
class SandboxJob:
    image: str
    command: tuple[str, ...]
    repo_root: Path
    scratch_files: dict[str, str]
    timeout_seconds: int
    memory_mb: int
    pids_limit: int


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class FakeSandboxRunner:
    """Record jobs and return a programmed result without a Docker daemon."""

    def __init__(self, result: SandboxResult | None = None) -> None:
        self.jobs: list[SandboxJob] = []
        self.result = result if result is not None else SandboxResult(exit_code=0, stdout="", stderr="", timed_out=False)

    def run(self, spec: SandboxJob) -> SandboxResult:
        self.jobs.append(spec)
        return self.result


def resolve_sandbox_runner() -> SandboxRunner:
    """Return the Docker CLI runner, or a fake when OPENULTRASAST_SANDBOX_RUNNER=fake."""
    flag = os.environ.get(RUNNER_ENV, "").strip().lower()
    if flag in _FAKE_RUNNER:
        return FakeSandboxRunner()
    return DockerCliRunner()


class DockerCliRunner:
    """Run a job with Docker CLI flags that match the threat model."""

    def __init__(self, *, runner: Callable[..., CompletedProcess[str]] | None = None) -> None:
        self._runner = runner

    def run(self, spec: SandboxJob) -> SandboxResult:
        if spec.scratch_files:
            with tempfile.TemporaryDirectory(prefix="ousast-scratch-") as tmp:
                seed = Path(tmp)
                _write_scratch_files(seed, spec.scratch_files)
                return self._invoke(_argv_with_scratch_seed(spec, seed), spec)
        return self._invoke(build_docker_argv(spec), spec)

    def _invoke(self, argv: list[str], spec: SandboxJob) -> SandboxResult:
        _reject_unsafe_argv(argv)
        run = self._runner if self._runner is not None else subprocess.run
        try:
            completed = run(
                argv,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                exit_code=-1,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                timed_out=True,
            )
        return SandboxResult(
            exit_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            timed_out=False,
        )


def build_docker_argv(job: SandboxJob) -> list[str]:
    argv = [*_isolation_argv(job), job.image, *job.command]
    _reject_unsafe_argv(argv)
    return argv


def _isolation_argv(job: SandboxJob) -> list[str]:
    repo = str(job.repo_root.resolve())
    return [
        "docker",
        "run",
        "--rm",
        "--init",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"{SCRATCH_MOUNT}:rw,exec",
        "--memory",
        f"{job.memory_mb}m",
        "--pids-limit",
        str(job.pids_limit),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        NONROOT_USER,
        "--mount",
        f"type=bind,src={repo},dst={WORKSPACE_MOUNT},ro",
    ]


def _argv_with_scratch_seed(job: SandboxJob, seed: Path) -> list[str]:
    argv = [
        *_isolation_argv(job),
        "--mount",
        f"type=bind,src={seed.resolve()},dst={SCRATCH_SEED_MOUNT},ro",
        job.image,
        "/bin/sh",
        "-c",
        _COPY_SEED_THEN_EXEC,
        _SEED_ARGV0,
        *job.command,
    ]
    _reject_unsafe_argv(argv)
    return argv


def _write_scratch_files(root: Path, files: Mapping[str, str]) -> None:
    resolved_root = root.resolve()
    for relative, content in files.items():
        candidate = Path(relative)
        if candidate.is_absolute():
            raise ValueError(f"scratch path {relative!r} must be relative to {SCRATCH_MOUNT}")
        destination = (resolved_root / candidate).resolve()
        try:
            common = os.path.commonpath([str(resolved_root), str(destination)])
        except ValueError as exc:
            raise ValueError(f"scratch path {relative!r} escapes {SCRATCH_MOUNT}") from exc
        if common != str(resolved_root):
            raise ValueError(f"scratch path {relative!r} escapes {SCRATCH_MOUNT}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
    _chmod_seed_tree(resolved_root)


def _chmod_seed_tree(root: Path) -> None:
    # Container user 65534 must be able to traverse and read the seed bind.
    for dirpath, _dirnames, filenames in os.walk(root):
        Path(dirpath).chmod(0o755)
        for name in filenames:
            (Path(dirpath) / name).chmod(0o644)


def _reject_unsafe_argv(argv: list[str]) -> None:
    joined = " ".join(argv)
    if "/var/run/docker.sock" in joined:
        raise ValueError("sandbox argv must not mount the host Docker socket")
    if "--privileged" in argv:
        raise ValueError("sandbox argv must not be privileged")
    for index, item in enumerate(argv):
        if item in {"--network", "--net"} and index + 1 < len(argv) and argv[index + 1] == "host":
            raise ValueError("sandbox argv must not use host network")
        if item in {"--network=host", "--net=host"}:
            raise ValueError("sandbox argv must not use host network")


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
