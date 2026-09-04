"""Optional semantic extra: lazy grammar load. Never import wheels at package load."""

from __future__ import annotations

import importlib
import importlib.util
import os
from typing import Any

_GRAMMAR_MODULES = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "java": "tree_sitter_java",
}
_PROBE_ENV = "OPENULTRASAST_TREE_SITTER_PROBE"
_PROBE_OFF = frozenset({"0", "off", "false", "unavailable", "no"})
_PROBE_ON = frozenset({"1", "on", "true", "available", "yes"})


def has_semantic_extra() -> bool:
    """True when the parser runtime and at least one in-scope grammar are importable."""
    flag = os.environ.get(_PROBE_ENV, "").strip().lower()
    if flag in _PROBE_OFF:
        return False
    if importlib.util.find_spec("tree_sitter") is None:
        return False
    return any(importlib.util.find_spec(module) is not None for module in _GRAMMAR_MODULES.values())


def grammar_for(language: str) -> Any | None:
    """Return a tree_sitter.Language for an in-scope language, or None. Never raises into the scan."""
    flag = os.environ.get(_PROBE_ENV, "").strip().lower()
    if flag in _PROBE_OFF:
        return None
    module_name = _GRAMMAR_MODULES.get(language)
    if module_name is None or importlib.util.find_spec("tree_sitter") is None:
        return None
    if importlib.util.find_spec(module_name) is None:
        return None
    try:
        from tree_sitter import Language

        module = importlib.import_module(module_name)
        return Language(module.language())
    except Exception:
        return None
