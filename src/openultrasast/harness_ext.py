"""Capability guard for the optional HarnessX agentic plane.

HarnessX is an optional extra (``pip install 'openultrasast[harnessx]'``). The core
install is zero-dependency, so nothing here imports ``harnessx`` at module load:
:func:`has_harnessx` only probes importability via ``find_spec`` and
:func:`require_harnessx` performs the import lazily, on demand. Every HarnessX-backed
code path (Phase 3+: build_sast, the hunter sub-harness, the llm-judge verifier, the
MetaAgent.evolve loop) routes through this seam.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType

HARNESSX_EXTRA = "openultrasast[harnessx]"


class HarnessXUnavailableError(RuntimeError):
    """Raised when a HarnessX-backed capability is requested but the extra is absent."""


def has_harnessx() -> bool:
    """Return True if the HarnessX extra is importable, without importing it."""
    return importlib.util.find_spec("harnessx") is not None


def require_harnessx() -> ModuleType:
    """Lazily import and return the ``harnessx`` module, or raise with install guidance."""
    if not has_harnessx():
        raise HarnessXUnavailableError(f"HarnessX is not installed. Install the optional agentic extra: pip install '{HARNESSX_EXTRA}'")
    return importlib.import_module("harnessx")
