"""A stub task module for the runner tests: records its contract, writes one artifact and ``summary.json``.

Registered by the tests as ``openultrasast.plane.tasks.stub_task``; ``STUB_MODE`` picks the outcome
(``done``, ``failed``, ``unfinished``, ``crash``, ``nosummary``, ``exit``).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path


def main(argv: list[str]) -> None:
    out = Path(os.environ["OUSAST_OUTPUT_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("STUB_MODE", "done")
    workspace = Path(os.environ["OUSAST_WORKSPACE_DIR"])
    readyz: int | None = None
    port = os.environ.get("AX_RUNNER_BOUND_PORT")
    if port:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=5) as response:
            readyz = int(response.status)
    record = {
        "argv": argv,
        "env": {k: v for k, v in os.environ.items() if k.startswith("OUSAST_")},
        "workspace_files": sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob("*") if p.is_file()),
        "readyz": readyz,
    }
    (out / "facts.json").write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    if mode == "crash":
        raise RuntimeError("stub exploded")
    if mode == "exit":
        raise SystemExit(7)
    if mode == "nosummary":
        return
    summary = {"status": mode, "units_done": 1, "units_total": 1, "usd": 0.0, "calls": 0, "usage": {}}
    (out / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
