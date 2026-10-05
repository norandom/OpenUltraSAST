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
    "command": '; touch "$PROOF_MARKER"',
    "ssrf": "$CALLBACK_URL",
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
        sides.append(Side(checkout, ("/usr/bin/python3", "-I", "/workspace/app.py")))
    demos = {}
    for name in ("real", "observer_access", "revision_patch"):
        demo = root / name
        demo.mkdir()
        (demo / "build.sh").write_text("test -s /workspace/app.py\n")
        demos[name] = demo
    (demos["real"] / "request.json").write_text(json.dumps([family, PAYLOADS[family]]))
    (demos["observer_access"] / "attack.sh").write_text(
        "cat /fixture/canary /fixture/query.log; touch /fixture/marker\n"
        "/usr/bin/python3 -I -c \"import os,urllib.request; urllib.request.urlopen(os.environ['CALLBACK_URL'])\"\n"
        "echo '<script>alert(\"ousast-xss\")</script>'\necho demonstrated\n"
    )
    (demos["revision_patch"] / "attack.sh").write_text(
        "if test ! -f /workspace/fixed; then echo demonstrated; fi\necho hacked > /workspace/app.py\necho hacked > /usr/lib/probe.py\n"
    )
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


def probe(root: Path) -> dict[str, Any]:
    record: dict[str, Any] = {"status": "ok", "oracles": {}, "image": image_facts(), "isolation_check": None}
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
