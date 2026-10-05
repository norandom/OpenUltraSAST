"""Disk-backed task scratch and aggregate workspace guard for kube-ax."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_SCRATCH_BYTES = 2 * 1024**3
WORKSPACE = Path("/workspace")


class ScratchLimit(ValueError):
    """The task workspace exceeded its configured scratch budget."""


def environment() -> dict[str, str]:
    if not WORKSPACE.is_dir():
        return {}
    root = str(WORKSPACE)
    return {
        "TMPDIR": root + "/tmp",
        "npm_config_cache": root + "/.npm",
        "MAVEN_OPTS": "-Dmaven.repo.local=" + root + "/.m2",
        "COMPOSER_HOME": root + "/.composer",
        "PIP_CACHE_DIR": root + "/.pip",
        "GRADLE_USER_HOME": root + "/.gradle",
    }


def configure() -> int:
    limit = int(os.environ.get("OUSAST_SCRATCH_BYTES", DEFAULT_SCRATCH_BYTES))
    if limit < 1:
        raise ValueError("scratch limit must be positive")
    env = environment()
    if env:
        Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
        os.environ.update(env)
        # tempfile may have cached /tmp before this entry point ran.
        tempfile.tempdir = env["TMPDIR"]
    os.environ["OUSAST_SCRATCH_BYTES"] = str(limit)
    return limit


def check(root: Path | None = None, limit: int | None = None, *, additional_bytes: int = 0) -> int:
    root = root or WORKSPACE
    limit = limit if limit is not None else int(os.environ.get("OUSAST_SCRATCH_BYTES", DEFAULT_SCRATCH_BYTES))
    if not root.is_dir():
        raise OSError("scratch root unavailable")

    def unreadable(error: OSError) -> None:
        raise error

    total = additional_bytes
    if total > limit:
        raise ScratchLimit("scratch limit")
    for parent, directories, names in os.walk(root, followlinks=False, onerror=unreadable):
        directories[:] = [d for d in directories if not (Path(parent) / d).is_symlink()]
        for name in names:
            try:
                info = (Path(parent) / name).lstat()
            except FileNotFoundError:  # A running build may remove its temporary files.
                continue
            if stat.S_ISREG(info.st_mode):
                total += max(info.st_size, info.st_blocks * 512)
            if total > limit:
                raise ScratchLimit("scratch limit")
    return total


def communicate(proc: subprocess.Popen[Any], data: bytes, timeout: float, root: Path, *, files: tuple[Any, ...] = ()) -> None:
    """Poll while the child runs and after exit, catching short-lived growth too."""

    def guard() -> None:
        # TemporaryFile logs are unlinked, so a directory walk cannot see them.
        check(WORKSPACE if WORKSPACE.is_dir() else root, additional_bytes=sum(os.fstat(f.fileno()).st_size for f in files))

    end = time.monotonic() + timeout
    first = True
    while True:
        guard()
        try:
            proc.communicate(input=data if first else None, timeout=min(0.05, max(0, end - time.monotonic())))
            guard()
            return
        except subprocess.TimeoutExpired:
            first = False
            if time.monotonic() >= end:
                raise
