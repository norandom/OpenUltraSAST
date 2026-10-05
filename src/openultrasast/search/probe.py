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
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import _sandbox
from .oracles import BrowserExecutor
from .verify import Side, verify

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


def probe(root: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "status": "ok",
        "oracles": {},
        "image": image_facts(),
        "namespaces": namespace_facts(),
        "isolation_check": None,
        "isolation_mode": _sandbox.isolation_mode(),
    }
    start = time.monotonic()
    try:
        _sandbox.isolation_check()
        record["isolation_check"] = {"status": "ok", "input_bytes": len(b"isolation-ready\n")}
        for family in FAMILIES:
            sides, demos = materialise(root / family, family)
            results: dict[str, Any] = {}
            record["oracles"][family] = results
            for name, demo in demos.items():
                result = verify(*sides, demo, family, browser=BrowserExecutor() if family == "xss" else None)
                results[name] = asdict(result)
                # SSRF/browser need additional namespace capabilities beyond the
                # generic preflight. These failures must not look like oracle misses.
                for side in result.sides:
                    if side.reason.startswith("verification unavailable or refused:"):
                        raise _sandbox.IsolationUnavailable(f"{family}/{name}: {side.reason}")
    except Exception as exc:
        record.update(status="instrument_failure", exception=f"{type(exc).__name__}: {exc}")
        namespaces = record["namespaces"]
        if namespaces and all(namespaces[name]["exit_code"] != 0 for name in ("user", "pid", "net", "ipc", "uts", "mount")):
            record["isolation_mode"] = "task-boundary"
            record["requires_fresh_side_tasks"] = True
        if record["isolation_check"] is None:
            record["isolation_check"] = {"status": "instrument_failure", "exception": str(exc)}
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
        except Exception:
            # Presigned URL is a bearer secret; never print upload exceptions.
            return 1
    return 0 if record["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
