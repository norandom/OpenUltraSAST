"""Probe semantic extra and Joern. Host CLI alone is not overlay-ready."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from subprocess import CompletedProcess

from .extra import has_semantic_extra

JOERN_PROBE_ENV = "OPENULTRASAST_JOERN_PROBE"
PROBE_TIMEOUT_SECONDS = 5
_PROBE_OFF = frozenset({"0", "off", "false", "unavailable", "no"})
_PROBE_ON = frozenset({"1", "on", "true", "available", "yes"})


def tree_sitter_available(*, runner: Callable[..., CompletedProcess[str]] | None = None) -> bool:
    """True when a grammar extra can produce overlay IR. Host CLI is not sufficient."""
    del runner
    return has_semantic_extra()


def joern_available(*, runner: Callable[..., CompletedProcess[str]] | None = None) -> bool:
    flag = os.environ.get(JOERN_PROBE_ENV, "").strip().lower()
    if flag in _PROBE_OFF:
        return False
    if flag in _PROBE_ON:
        return True
    binary = shutil.which("joern") or shutil.which("joern-parse")
    if binary is None:
        return False
    run = runner if runner is not None else subprocess.run
    try:
        result = run([binary, "--help"], capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS, check=False)
        return result.returncode == 0
    except Exception:
        return False


def joern_flow(path: str, text: str, language: str) -> tuple[object, ...]:
    """Optional CPG sidecar. Absence or incomplete export must not demote."""
    del path, text, language
    if not joern_available():
        return ()
    return ()
