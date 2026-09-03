"""Structural deny-list for untrusted regression snippets.

Snippets are data for `/scratch` inside the sandbox. Mentions of sockets, curl,
host networking, or writes under the source mount (`/workspace`) are rejected
before any `SandboxRunner.run` call.
"""

from __future__ import annotations

import re

from ..sandbox.runner import WORKSPACE_MOUNT

_WORKSPACE = re.escape(WORKSPACE_MOUNT)


class UnsafeSnippetError(ValueError):
    """Raised when a snippet fails the structural sandbox safety check."""


_HOST_NETWORK = re.compile(
    r"--net(?:work)?(?:\s*=\s*|\s+|['\"]\s*,\s*['\"])host\b",
    re.IGNORECASE,
)
_SOCKET_WORD = re.compile(r"\bsocket\b", re.IGNORECASE)
_CURL_WORD = re.compile(r"\bcurl\b", re.IGNORECASE)
_OPEN_WORKSPACE_WRITE = re.compile(
    rf"open\s*\(\s*[fFrRbBuU]*['\"]{_WORKSPACE}[^'\"]*['\"]\s*,\s*(?:mode\s*=\s*)?[fFrRbBuU]*['\"][^'\"]*[wax+]",
    re.IGNORECASE | re.DOTALL,
)
_PATH_WORKSPACE_WRITE = re.compile(
    rf"Path\s*\(\s*['\"]{_WORKSPACE}[^'\"]*['\"]\s*\)\s*\.\s*"
    r"(?:write_text|write_bytes|touch|mkdir|unlink|rmdir|replace|chmod|rename|open)\b",
    re.IGNORECASE | re.DOTALL,
)
_FS_WORKSPACE_WRITE = re.compile(
    r"(?:writeFile(?:Sync)?|appendFile(?:Sync)?|mkdir(?:Sync)?|rm(?:dir)?(?:Sync)?|"
    rf"unlink(?:Sync)?|rename(?:Sync)?)\s*\(\s*['\"]{_WORKSPACE}",
    re.IGNORECASE,
)
_FOPEN_WORKSPACE_WRITE = re.compile(
    rf"fopen\s*\(\s*['\"]{_WORKSPACE}[^'\"]*['\"]\s*,\s*['\"][^'\"]*[wax+]",
    re.IGNORECASE | re.DOTALL,
)
_SHUTIL_OS_WORKSPACE_WRITE = re.compile(
    r"(?:shutil\.(?:copy(?:2)?|copyfile|copytree|move|rmtree)|"
    r"os\.(?:remove|unlink|replace|rename|mkdir|makedirs|rmdir|chmod))"
    rf"\s*\([^;]{{0,240}}{_WORKSPACE}",
    re.IGNORECASE | re.DOTALL,
)
_REDIRECT_WORKSPACE = re.compile(rf"(?:>>|>)\s*['\"]?{_WORKSPACE}\b", re.IGNORECASE)

_WORKSPACE_WRITES = (
    _OPEN_WORKSPACE_WRITE,
    _PATH_WORKSPACE_WRITE,
    _FS_WORKSPACE_WRITE,
    _FOPEN_WORKSPACE_WRITE,
    _SHUTIL_OS_WORKSPACE_WRITE,
    _REDIRECT_WORKSPACE,
)


def check_snippet_safety(snippet: str) -> None:
    """Return None when `snippet` is structurally safe; raise otherwise."""
    lowered = snippet.lower()
    if "docker.sock" in lowered:
        raise UnsafeSnippetError("snippet mentions the Docker socket")
    if _SOCKET_WORD.search(snippet) is not None:
        raise UnsafeSnippetError("snippet mentions socket")
    if _CURL_WORD.search(snippet) is not None:
        raise UnsafeSnippetError("snippet mentions curl")
    if _HOST_NETWORK.search(snippet) is not None:
        raise UnsafeSnippetError("snippet requests host network")
    if _writes_under_workspace(snippet):
        raise UnsafeSnippetError(f"snippet writes under {WORKSPACE_MOUNT}")


def _writes_under_workspace(snippet: str) -> bool:
    if WORKSPACE_MOUNT not in snippet.lower():
        return False
    return any(pattern.search(snippet) is not None for pattern in _WORKSPACE_WRITES)
