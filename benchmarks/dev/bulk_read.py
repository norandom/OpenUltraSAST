"""Bulk reader: answer a question about one or more files with the cheap chat model, citing line numbers.

The Portal pattern (Spotify, 2026-09): reading five files to answer one question is I/O, not reasoning, so a
cheap model reads and the expensive one gets the answer. Files are sent in numbered chunks; the answer must cite
`path:line`, which is what a summary otherwise lacks. Reasoning stays with the caller: this reports what the
files say, it does not decide anything.

Usage: .venv/bin/python benchmarks/dev/bulk_read.py "<question>" FILE [FILE ...] [--max-usd 0.05]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CHUNK_LINES = 400
PROMPT = (
    "Answer the question using only the files below (numbered lines). Be specific and brief; cite every claim as "
    "path:line. If the files do not answer it, say so.\n\nQuestion: {question}\n\n{files}"
)


def numbered(path: Path) -> list[str]:
    lines = path.read_text(errors="ignore").splitlines()
    chunks = []
    for start in range(0, max(len(lines), 1), CHUNK_LINES):
        body = "\n".join(f"{n + 1:5d}| {line}" for n, line in enumerate(lines[start : start + CHUNK_LINES], start=start))
        chunks.append(f"--- {path} (lines {start + 1}-{min(start + CHUNK_LINES, len(lines))})\n{body}")
    return chunks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("question")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--max-usd", type=float, default=0.05)
    args = parser.parse_args()
    from openultrasast import tool_hunter
    from openultrasast.config import load_config
    from openultrasast.model.endpoint import DEFAULT_DETECTOR_MODEL

    load_config()
    client = tool_hunter.resolve_hunter_client()
    if client is None:
        print("no chat client: set DEEPSEEK_API_KEY", file=sys.stderr)
        return 2
    chunks = [chunk for path in args.files for chunk in numbered(path)]
    answers = []
    for chunk in chunks:
        if float(client.cost_usd()) >= args.max_usd:
            answers.append(f"[stopped at the ${args.max_usd} ceiling before: {chunk.splitlines()[0]}]")
            break
        response = client.complete(
            model=DEFAULT_DETECTOR_MODEL,
            messages=[{"role": "user", "content": PROMPT.format(question=args.question, files=chunk)}],
            tools=[],
            timeout_seconds=90,
        )
        answers.append((response.content or "").strip())
    print("\n\n".join(a for a in answers if a))
    print(f"\n[bulk_read: {len(chunks)} chunk(s), ${float(client.cost_usd()):.4f}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
