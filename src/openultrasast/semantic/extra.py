"""Optional semantic extra: lazy grammar load. Never import wheels at package load."""

from __future__ import annotations

import importlib
import importlib.util
import os
from typing import Any

# language -> (wheel module, the module attribute that builds the grammar). TypeScript ships two grammars;
# `.tsx` needs the JSX-aware one and plain `.ts` needs the other, so the caller asks for the one it needs.
_GRAMMAR_MODULES = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "java": ("tree_sitter_java", "language"),
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
    return any(importlib.util.find_spec(module) is not None for module, _ in _GRAMMAR_MODULES.values())


def grammar_for(language: str) -> Any | None:
    """Return a tree_sitter.Language for an in-scope language, or None. Never raises into the scan."""
    flag = os.environ.get(_PROBE_ENV, "").strip().lower()
    if flag in _PROBE_OFF:
        return None
    entry = _GRAMMAR_MODULES.get(language)
    if entry is None or importlib.util.find_spec("tree_sitter") is None:
        return None
    module_name, attribute = entry
    if importlib.util.find_spec(module_name) is None:
        return None
    try:
        from tree_sitter import Language

        module = importlib.import_module(module_name)
        return Language(getattr(module, attribute)())
    except Exception:
        return None
