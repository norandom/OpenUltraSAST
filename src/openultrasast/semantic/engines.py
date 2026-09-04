"""Probe tree-sitter and Joern like the Docker sandbox probe. Never required for inventory."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from collections.abc import Callable
from subprocess import CompletedProcess

TREE_SITTER_PROBE_ENV = "OPENULTRASAST_TREE_SITTER_PROBE"
JOERN_PROBE_ENV = "OPENULTRASAST_JOERN_PROBE"
PROBE_TIMEOUT_SECONDS = 5
_PROBE_OFF = frozenset({"0", "off", "false", "unavailable", "no"})
_PROBE_ON = frozenset({"1", "on", "true", "available", "yes"})


def tree_sitter_available(*, runner: Callable[..., CompletedProcess[str]] | None = None) -> bool:
    flag = os.environ.get(TREE_SITTER_PROBE_ENV, "").strip().lower()
    if flag in _PROBE_OFF:
        return False
    if flag in _PROBE_ON:
        return True
    if _python_tree_sitter_present():
        return True
    binary = shutil.which("tree-sitter")
    if binary is None:
        return False
    run = runner if runner is not None else subprocess.run
    try:
        result = run([binary, "--version"], capture_output=True, text=True, timeout=PROBE_TIMEOUT_SECONDS, check=False)
        return result.returncode == 0
    except Exception:
        return False


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


def _python_tree_sitter_present() -> bool:
    return importlib.util.find_spec("tree_sitter") is not None
