"""Job and result types shared by the search sandbox and verifier."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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

