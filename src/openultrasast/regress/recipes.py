"""Language command recipes for isolated regression snippets."""

from __future__ import annotations

from pathlib import Path

from ..config import SandboxConfig
from ..sandbox.runner import SCRATCH_MOUNT, WORKSPACE_MOUNT, SandboxJob

_PYTHON_FILE = "case.py"
_JS_FILE = "case.js"
_C_FILE = "case.c"
_C_BIN = "case"


def recipe_for(
    language: str,
    snippet: str,
    image: str,
    sandbox_limits: SandboxConfig,
    *,
    repo_root: Path,
) -> SandboxJob | None:
    """Return a sandbox job for `language`, or None when no recipe exists."""
    key = language.strip().lower()
    if key == "python":
        return _job(
            image,
            sandbox_limits,
            repo_root,
            command=("env", f"PYTHONPATH={WORKSPACE_MOUNT}", "python", f"{SCRATCH_MOUNT}/{_PYTHON_FILE}"),
            scratch_files={_PYTHON_FILE: snippet},
        )
    if key == "javascript":
        return _job(
            image,
            sandbox_limits,
            repo_root,
            command=("env", f"NODE_PATH={WORKSPACE_MOUNT}", "node", f"{SCRATCH_MOUNT}/{_JS_FILE}"),
            scratch_files={_JS_FILE: snippet},
        )
    if key == "c":
        source = f"{SCRATCH_MOUNT}/{_C_FILE}"
        binary = f"{SCRATCH_MOUNT}/{_C_BIN}"
        return _job(
            image,
            sandbox_limits,
            repo_root,
            command=("sh", "-c", f"cc {source} -o {binary} && {binary}"),
            scratch_files={_C_FILE: snippet},
        )
    return None


def _job(
    image: str,
    sandbox_limits: SandboxConfig,
    repo_root: Path,
    *,
    command: tuple[str, ...],
    scratch_files: dict[str, str],
) -> SandboxJob:
    return SandboxJob(
        image=image,
        command=command,
        repo_root=repo_root,
        scratch_files=scratch_files,
        timeout_seconds=sandbox_limits.timeout_seconds,
        memory_mb=sandbox_limits.memory_mb,
        pids_limit=sandbox_limits.pids_limit,
    )
