"""Where a Claude Code session's tokens go: tool input vs tool output vs text, from the transcript.

The 2026-09-29 measurement of this project's main session: tool_use input 47.5% (inline scripts), tool results
42%, assistant text 6%, thinking 2%, user 2%. Re-run after a workflow change to see whether it moved.

Usage: python benchmarks/dev/token_report.py [TRANSCRIPT.jsonl]   (default: the newest under ~/.claude/projects)
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path


def newest() -> Path:
    candidates = sorted(Path.home().glob(".claude/projects/*/*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        raise SystemExit("no transcript found")
    return candidates[-1]


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else newest()
    chars: collections.Counter[str] = collections.Counter()
    tools: collections.Counter[str] = collections.Counter()
    for line in path.open():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        content = (entry.get("message") or {}).get("content")
        kind = entry.get("type", "?")
        if isinstance(content, str):
            chars[kind] += len(content)
        elif isinstance(content, list):
            for block in content:
                block_type = block.get("type")
                if block_type == "text":
                    chars[f"{kind}:text"] += len(block.get("text", ""))
                elif block_type == "tool_use":
                    tools[str(block.get("name"))] += 1
                    chars["tool_use_input"] += len(json.dumps(block.get("input")))
                elif block_type == "tool_result":
                    result = block.get("content")
                    chars["tool_result"] += len(result if isinstance(result, str) else json.dumps(result))
                elif block_type == "thinking":
                    chars["thinking"] += len(block.get("thinking", ""))
    total = sum(chars.values()) or 1
    print(f"{path.name}: {total / 1e6:.1f}M chars unique (~{total / 4e6:.2f}M tokens once; re-sent every turn)")
    for key, value in chars.most_common():
        print(f"  {key:16s} {value / 1e6:6.2f}M  {value / total:5.1%}")
    print("tool calls:", sum(tools.values()), dict(tools.most_common(5)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
