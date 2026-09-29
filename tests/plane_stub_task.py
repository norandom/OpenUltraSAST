"""A stub task module for the runner tests: records its contract, writes one artifact and ``summary.json``.

The tests copy it into a throwaway package (``AX_RUNNER_TASK_PACKAGE``) so the runner starts it the way it starts
a real task, ``python -m <package>.stub_task``. ``STUB_MODE`` picks the outcome (``done``, ``failed``,
``unfinished``, ``crash``, ``nosummary``, ``exit``, ``sleep``); ``STUB_COUNTER`` names a file that gets one line
per run.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def _get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return int(response.status), response.read().decode("utf-8")


def main(argv: list[str]) -> None:
    out = Path(os.environ["OUSAST_OUTPUT_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("STUB_MODE", "done")
    counter = os.environ.get("STUB_COUNTER")
    if counter:
        with open(counter, "a", encoding="utf-8") as handle:
            handle.write(f"{os.getpid()}\n")
    workspace = Path(os.environ["OUSAST_WORKSPACE_DIR"])
    port = os.environ.get("AX_RUNNER_BOUND_PORT")
    readyz = _get(f"http://127.0.0.1:{port}/readyz")[0] if port else None
    metadata = os.environ.get("AX_METADATA_URL")
    record = {
        "argv": argv,
        "env": {k: v for k, v in os.environ.items() if k.startswith("OUSAST_")},
        "workspace_files": sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob("*") if p.is_file()),
        "readyz": readyz,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "pgid": os.getpgid(0),
        "metadata_url": metadata,
        "metadata_task": _get(f"{metadata}/metadata/v1alpha1/ax/task")[1] if metadata else None,
    }
    (out / "facts.json").write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    if mode == "sleep":  # ignore SIGTERM so only the runner's SIGKILL ends the group; the grandchild inherits it
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        grandchild = subprocess.Popen(["sleep", "60"])
        (out / "pids.json").write_text(json.dumps([os.getpid(), grandchild.pid]), encoding="utf-8")
        time.sleep(60)
    if mode == "crash":
        raise RuntimeError("stub exploded")
    if mode == "exit":
        raise SystemExit(7)
    if mode == "nosummary":
        return
    summary = {"status": mode, "units_done": 1, "units_total": 1, "usd": 0.0, "calls": 0, "usage": {}}
    (out / "summary.json").write_text(json.dumps(summary), encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1:])
