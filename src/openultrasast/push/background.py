"""Run the engine after the push, and show its result on the next one (task 17.5, Requirement 9.5).

The engine cannot finish a small repository inside a 30 s hook deadline (the 2026-10-02 audit
measured 260 s on 26 files). Until graph reuse makes it fast, `--engine background` lets the hook
return after the quick tier and starts one detached explicit replay of the same base and head. That
replay writes an ordinary artifact under the artifact directory; the next run in the same repository
prints "engine result for <head> from the previous push" once, then marks it shown.

One background engine at a time per artifact directory: the host this was built on has 7 GB, and
two Joern JVMs is what this project has seen killed. No speed work happens here.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from openultrasast.push.report import CAPABILITY_VETOES

_LOCK = "running.json"


def results_dir(artifact: Path, repository: Path) -> Path:
    """Per-repository directory beside the artifact; the repository path is hashed, never stored raw."""
    key = hashlib.sha256(str(repository.resolve()).encode()).hexdigest()[:16]
    return artifact.parent / "engine" / key


def _alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def start(
    repository: Path,
    *,
    base: str,
    head: str,
    artifact: Path,
    deadline_seconds: float,
    max_regions: int = 500,
    cache_dir: Path | None = None,
) -> dict[str, object]:
    """Start one detached engine replay of base..head; never waits for it and never raises."""
    directory = results_dir(artifact, repository)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        lock = directory / _LOCK
        try:
            running = json.loads(lock.read_text())
        except (OSError, ValueError):
            running = {}
        if isinstance(running, dict) and _alive(running.get("pid")):
            return {"status": "busy", "head": str(running.get("head", "")), "directory": str(directory)}
        target = directory / f"{head}.json"
        log = directory / f"{head}.log"
        command = [
            sys.executable,
            "-m",
            "openultrasast.cli",
            "pre-push",
            str(repository.resolve()),
            "--base",
            base,
            "--head",
            head,
            "--artifact",
            str(target),
            "--deadline",
            f"{deadline_seconds:g}",
            "--max-regions",
            str(max_regions),
            "--engine",
            "inline",
        ]
        if cache_dir is not None:
            command.extend(("--cache-dir", str(cache_dir)))
        with open(log, "wb") as output:
            process = subprocess.Popen(  # noqa: S603 -- our own CLI with immutable commit ids, no shell
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                cwd=str(repository.resolve()),
                start_new_session=True,
                close_fds=True,
            )
        lock.write_text(json.dumps({"pid": process.pid, "head": head, "base": base}))
        return {
            "status": "started",
            "head": head,
            "deadline_seconds": deadline_seconds,
            "artifact": str(target),
            "log": str(log),
        }
    except Exception as error:  # noqa: BLE001 -- a background start that fails is a stated gap, never a block
        return {"status": "failed", "reason": type(error).__name__}


def _summary(data: Mapping[str, object]) -> dict[str, object]:
    admission = data.get("admission")
    result = data.get("result")
    admission = admission if isinstance(admission, Mapping) else {}
    result = result if isinstance(result, Mapping) else {}
    defects = admission.get("defects")
    reasons = admission.get("coverage_reasons")
    reasons = [str(r) for r in reasons] if isinstance(reasons, list) else []
    advisory = []
    dispositions = admission.get("dispositions")
    for item in dispositions if isinstance(dispositions, list) else []:
        try:
            delta = item["candidate"]["delta"]
            op = delta["head_operation"] or {}
            if (
                not item["admitted"]
                and delta["novelty"] in ("new", "worsened")
                and set(item["reasons"]) <= CAPABILITY_VETOES
                and op
                and delta["witness"]
            ):
                advisory.append({"family": delta["family"], "path": op["path"], "line": op["line"], "novelty": delta["novelty"]})
        except (KeyError, TypeError):
            continue
    unique = list({(a["family"], a["path"], a["line"]): a for a in advisory}.values())
    return {
        "alerts": len(defects) if isinstance(defects, list) else 0,
        "advisory": unique,
        "coverage": result.get("coverage_status", "unknown"),
        "finished": "deadline_exhausted" not in reasons,
        "engine_ran": not any(r in ("cpg_build_failed", "cpg_unavailable") for r in reasons),
    }


def previous(artifact: Path, repository: Path) -> list[dict[str, object]]:
    """Finished background results not yet shown for this repository; each is shown exactly once."""
    directory = results_dir(artifact, repository)
    shown: list[dict[str, object]] = []
    try:
        candidates = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime)
    except OSError:
        return shown
    for path in candidates:
        if path.name == _LOCK or path.with_suffix(".shown").exists():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue  # still being written, or unreadable: leave it for the next run
        if not isinstance(data, dict):
            continue
        shown.append({"head": path.stem, "artifact": str(path), **_summary(data)})
        with contextlib.suppress(OSError):
            path.with_suffix(".shown").touch()
    return shown
