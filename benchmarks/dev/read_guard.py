#!/usr/bin/env python3
"""PreToolUse hook: a whole-file Read of more than LIMIT lines is denied and redirected.

Measured 2026-09-29: 90% of a development session's tokens were tool I/O -- inline scripts and what they
printed -- not reasoning. Whole-file reads are the largest single item that a summary could replace. A Read with
`offset`/`limit` is a deliberate range and passes; a file at or under LIMIT lines passes.

Wired in .claude/settings.local.json (PreToolUse, matcher Read). Stdin: the hook JSON; stdout: a permission
decision only when denying. Never fails the tool: any error here exits 0 silently.
"""

import json
import sys

LIMIT = 350


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0
    if event.get("tool_name") != "Read":
        return 0
    tool_input = event.get("tool_input") or {}
    path = tool_input.get("file_path")
    if not path or tool_input.get("limit") or tool_input.get("offset"):
        return 0
    try:
        with open(path, "rb") as handle:
            lines = sum(1 for _ in handle)
    except OSError:
        return 0
    if lines <= LIMIT:
        return 0
    reason = (
        f"{path} has {lines} lines (limit {LIMIT} for a whole-file read). Read a range with offset/limit, or ask "
        f"the bulk reader for what you need: .venv/bin/python benchmarks/dev/bulk_read.py '<question>' {path}"
    )
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
