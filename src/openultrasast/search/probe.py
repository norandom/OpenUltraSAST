"""No-model image probe: python -m openultrasast.search.probe.

The packaged app is data, deliberately never imported into the worker process.
RESULT_URL is an optional object-scoped PUT; no store credentials are used.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import asdict, replace
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import _sandbox
from .demo import FAMILY_ORACLES, load_demo
from .oracles import BrowserExecutor
from .task_storage import exception_reason
from .verify import Side, VerificationRecord, verify, verify_side_task

FAMILIES = ("sql", "path", "command", "ssrf", "xss")
PAYLOADS = {
    "sql": "' OR public=0 --",
    "path": "../canary",
    "command": "; touch marker",
    "ssrf": "internal",
    "xss": '<script>alert("ousast-xss")</script>',
}


def materialise(root: Path, family: str) -> tuple[tuple[Side, Side], dict[str, Path]]:
    source = files("openultrasast.search").joinpath("probe_apps/app.py.txt").read_bytes()
    if not source:
        raise ValueError("empty packaged toy input")
    sides = []
    for name in ("vulnerable", "fixed"):
        checkout = root / name
        checkout.mkdir(parents=True)
        (checkout / "app.py").write_bytes(source)
        if name == "fixed":
            (checkout / "fixed").touch()
        sides.append(Side(checkout))
    demos = {}
    for name in ("real", "observer_access", "revision_patch"):
        demo = root / name
        demo.mkdir()
        demos[name] = demo
    schema: dict[str, Any] = {
        "oracle": family,
        "build": {"recipe": "none", "arguments": []},
        "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
        "steps": [{"type": "cli", "arguments": [family, PAYLOADS[family]]}],
    }
    (demos["real"] / "demo.json").write_text(json.dumps(schema))
    schema["steps"][0]["arguments"] = ["/fixture/canary"]
    (demos["observer_access"] / "demo.json").write_text(json.dumps(schema))
    schema["start"]["path"] = "../fixed/app.py"
    (demos["revision_patch"] / "demo.json").write_text(json.dumps(schema))
    return (sides[0], sides[1]), demos


def image_facts() -> dict[str, Any]:
    facts = {}
    for name, argv in {
        "python": ["python3", "--version"],
        "node": ["node", "--version"],
        "tsc": ["tsc", "--version"],
        "php": ["php", "--version"],
        "java": ["java", "-version"],
        "sqlite": ["sqlite3", "--version"],
        "bwrap": ["bwrap", "--version"],
        "chromium": ["chromium", "--version"],
    }.items():
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=10, env={"PATH": os.defpath + ":/opt/java/openjdk/bin"})
            facts[name] = {"exit_code": done.returncode, "version": (done.stdout + done.stderr).strip()[:2000]}
        except (OSError, subprocess.SubprocessError) as exc:
            facts[name] = {"error": str(exc)}
    return facts


def namespace_facts() -> dict[str, Any]:
    """Try capabilities independently, even when the combined preflight fails."""
    commands = {
        name: ["bwrap", f"--unshare-{name}", "--bind", "/", "/", "--", "/bin/true"]
        for name in ("user", "pid", "net", "ipc", "uts", "cgroup")
    }
    commands["mount"] = ["bwrap", "--bind", "/", "/", "--", "/bin/true"]
    commands["setpriv"] = [*_sandbox.drop_privileges(), "/usr/bin/id"]
    facts = {}
    for name, argv in commands.items():
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=5, env={"PATH": os.defpath})
            facts[name] = {"exit_code": done.returncode, "stderr": done.stderr[:2000], "stdout": done.stdout[:2000]}
        except (OSError, subprocess.SubprocessError) as exc:
            facts[name] = {"exit_code": None, "stderr": str(exc)}
    return facts


def _verify_task_pair(sides: tuple[Side, Side], demo: Path, family: str) -> VerificationRecord:
    """Exercise the task executor on packaged toys only, not arbitrary checkouts.

    Repetitions get fresh scratch, but share this probe task's outer boundary.
    This is an instrument self-test, not a fresh-task dispatcher for evidence.
    """
    started = time.monotonic()
    records = []
    try:
        load_demo(demo)
    except (OSError, ValueError) as exc:
        return VerificationRecord(
            "inconclusive",
            (),
            time.monotonic() - started,
            "invalid declarative demo: " + exception_reason(exc),
            isolation_mode="task-boundary",
        )
    search_family = next(f for f, kinds in FAMILY_ORACLES.items() if family in kinds)
    for side in sides:
        runs = [verify_side_task(side, demo, search_family) for _ in range(3)]
        first = next((run for run in runs if run.outcome != "observed"), runs[0])
        records.append(
            replace(
                first,
                runs=tuple(observation for run in runs for observation in run.runs),
                elapsed_seconds=sum(run.elapsed_seconds for run in runs),
                build_seconds=sum(run.build_seconds for run in runs),
                ready_seconds=sum(run.ready_seconds for run in runs),
                run_seconds=sum(run.run_seconds for run in runs),
                scratch_peak_bytes=max(run.scratch_peak_bytes for run in runs),
                reason=first.reason if first.outcome != "observed" else "three probe task executions completed",
            )
        )
    demonstrated = (
        all(side.outcome == "observed" and len(side.runs) == 3 for side in records)
        and all(run.observed for run in records[0].runs)
        and not any(run.observed for run in records[1].runs)
    )
    return VerificationRecord(
        "demonstrated" if demonstrated else "inconclusive",
        tuple(records),
        time.monotonic() - started,
        "owned effect in 3/3 affected runs and 0/3 safe runs" if demonstrated else "no consistent differential effect",
        isolation_mode="task-boundary",
        chromium_no_sandbox=any(side.chromium_no_sandbox for side in records),
    )


def probe(root: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "status": "ok",
        "oracles": {},
        "image": image_facts(),
        "namespaces": namespace_facts(),
        "isolation_check": None,
        "isolation_mode": _sandbox.isolation_mode(),
    }
    namespaces = record["namespaces"]
    if namespaces and all(namespaces[name]["exit_code"] != 0 for name in ("user", "pid", "net", "ipc", "uts", "mount")):
        record["isolation_mode"] = "task-boundary"
    task_boundary = record["isolation_mode"] == "task-boundary"
    if task_boundary:
        # Real verification still needs fresh side tasks; only these packaged
        # self-test applications share the probe task's boundary.
        record["requires_fresh_side_tasks"] = True
    start = time.monotonic()
    try:
        if task_boundary:
            record["isolation_check"] = {"status": "skipped", "reason": "task-boundary"}
        else:
            _sandbox.isolation_check()
            record["isolation_check"] = {"status": "ok", "input_bytes": len(b"isolation-ready\n")}
        for family in FAMILIES:
            sides, demos = materialise(root / family, family)
            results: dict[str, Any] = {}
            record["oracles"][family] = results
            for name, demo in demos.items():
                search_family = next(f for f, kinds in FAMILY_ORACLES.items() if family in kinds)
                if task_boundary:
                    tick = time.monotonic()
                    try:
                        result = _verify_task_pair(sides, demo, family)
                    except Exception as exc:
                        result = VerificationRecord(
                            "inconclusive", (), time.monotonic() - tick, exception_reason(exc), isolation_mode="task-boundary"
                        )
                else:
                    result = verify(
                        *sides,
                        demo,
                        search_family,
                        oracle=family,
                        browser=BrowserExecutor() if family == "xss" else None,
                    )
                results[name] = asdict(result)
                if task_boundary and (result.outcome == "demonstrated") != (name == "real") and record["status"] == "ok":
                    expected = "demonstrated" if name == "real" else "not demonstrated"
                    record.update(
                        status="instrument_failure",
                        exception=f"{family}/{name}: expected {expected}, got {result.outcome}",
                    )
                # SSRF/browser need additional namespace capabilities beyond the
                # generic preflight. These failures must not look like oracle misses.
                for side in result.sides:
                    if not task_boundary and side.reason.startswith("verification unavailable or refused:"):
                        raise _sandbox.IsolationUnavailable(f"{family}/{name}: {side.reason}")
    except Exception as exc:
        record.update(status="instrument_failure", exception=exception_reason(exc))
        namespaces = record["namespaces"]
        if namespaces and all(namespaces[name]["exit_code"] != 0 for name in ("user", "pid", "net", "ipc", "uts", "mount")):
            record["isolation_mode"] = "task-boundary"
            record["requires_fresh_side_tasks"] = True
        if record["isolation_check"] is None:
            record["isolation_check"] = {"status": "instrument_failure", "exception": exception_reason(exc)}
    finally:
        record["wall_seconds"] = time.monotonic() - start
        record["peak_rss_kib"] = {
            "self": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "children": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        }
        record["peak_rss_kib"]["sum"] = sum(record["peak_rss_kib"].values())
        record["scratch_disk_bytes"] = sum(p.stat().st_blocks * 512 for p in root.rglob("*") if p.is_file())
        record["verification_scratch_peak_bytes"] = max(
            (s["scratch_peak_bytes"] for results in record["oracles"].values() for result in results.values() for s in result["sides"]),
            default=0,
        )
        record["scratch_filesystem_used_bytes"] = shutil.disk_usage(root).used
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heap-profile", choices=("vm", "ax"), help=argparse.SUPPRESS)
    parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="ousast-search-probe-") as directory:
        record = probe(Path(directory))
    data = (json.dumps(record, sort_keys=True) + "\n").encode()
    print(data.decode(), end="", flush=True)
    if url := os.environ.get("RESULT_URL"):
        request = urllib.request.Request(url, data=data, method="PUT", headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if not 200 <= response.status < 300:
                    return 1
        except Exception as exc:
            record.update(status="instrument_failure", phase="result upload", reason=exception_reason(exc))
            print(json.dumps(record), flush=True)
            return 1
    return 0 if record["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
