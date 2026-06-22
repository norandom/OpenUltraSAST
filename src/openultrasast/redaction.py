"""Secret redaction for traces and reports (Phase 15 hardening).

Scan artifacts (trace events, reports) can quote source code that contains live
credentials. This module masks well-known secret shapes before they are persisted, so
a finding's evidence never leaks a key into an artifact an analyst later shares.
Conservative by design: it targets recognizable secret formats, not arbitrary text.
"""

from __future__ import annotations

import re

REDACTED = "***REDACTED***"

# (compiled pattern, replacement). Replacements keep any non-secret prefix group so the
# redaction is legible (e.g. `api_key = ***REDACTED***`, `Authorization: Bearer ***REDACTED***`).
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM private key blocks.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), REDACTED),
    # Authorization: Bearer <token>
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{12,}"), r"\1" + REDACTED),
    # Provider API keys: OpenAI/Anthropic sk-..., AWS AKIA..., GitHub gh*_..., Slack xox*, Google AIza...
    (re.compile(r"\bsk-[A-Za-z0-9._\-]{16,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bAIza[A-Za-z0-9_\-]{20,}"), REDACTED),
    # Credentials embedded in a URL: scheme://user:secret@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)[^\s:/@]{3,}(@)"), r"\1" + REDACTED + r"\2"),
    # Generic `key = "value"` assignments for sensitive names.
    (
        re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\b(\s*[=:]\s*)(['\"]?)[A-Za-z0-9/+_\-]{8,}\3"),
        r"\1\2\3" + REDACTED + r"\3",
    ),
)


def redact_secrets(text: str) -> str:
    """Return ``text`` with recognizable secrets masked. Idempotent and pattern-scoped."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


__all__ = ["REDACTED", "redact_secrets"]
