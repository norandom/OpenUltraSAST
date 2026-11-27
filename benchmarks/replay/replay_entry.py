"""Credential-free replay actor. Standard library only; PUT is completion."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "learn"))
from engine_task_entry import transfer

CLUSTER_FLAGS = (
    "-Xms1700m -Xmx1700m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m "
    "-XX:MaxDirectMemorySize=256m -Xss512k -XX:ActiveProcessorCount=2 -XX:+UseG1GC"
)


class ReplayFailure(Exception):
    """Locally controlled diagnostic only."""


def validate_spec(spec):
    parts = urlsplit(spec["repository_url"])
    if (
        parts.scheme != "https"
        or not parts.hostname
        or "." not in parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise ReplayFailure("repository must be public HTTPS")
    if parts.port not in (None, 443) or parts.hostname.endswith((".local", ".internal", ".localhost")):
        raise ReplayFailure("repository must be public HTTPS")
    import ipaddress

    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        pass
    else:
        raise ReplayFailure("repository must use public DNS")
    if any(not re.fullmatch("[0-9a-f]{40,64}", spec[key]) for key in ("base", "head")):
        raise ReplayFailure("invalid revision")
    flags = spec.get("hook_flags", [])
    if flags and (len(flags) != 2 or flags[0] != "--deadline" or not re.fullmatch(r"[1-9][0-9]*", str(flags[1]))):
        raise ReplayFailure("unsupported hook flags")


def main(*, work_root=Path("/tmp"), runner=subprocess.run, heap_profile="cluster", clock=time.monotonic):
    output = work_root / "out"
    output.mkdir(parents=True, exist_ok=True)
    instrument = {
        "status": "instrument_failure",
        "head_verified": False,
        "base_verified": False,
        "changed_bytes": {},
        "checkout_files": 0,
        "checkout_bytes": 0,
        "hook_bytes_read": 0,
        "jvm_wall_seconds": 0,
        "jvm_time_basis": "scan build_seconds + query_seconds",
        "hook_exit": None,
        "timings": {},
        "heap_profile": heap_profile,
    }
    spec = {}
    step = "GET spec"
    started = clock()

    def run(command, *, timeout=180, env=None):
        before = clock()
        result = runner(command, capture_output=True, text=True, timeout=timeout, env=env)
        instrument["timings"][step] = instrument["timings"].get(step, 0) + clock() - before
        if result.returncode:
            raise ReplayFailure(f"exit {result.returncode}")
        return result

    try:
        spec_path = work_root / "spec.dat"
        transfer(os.environ["SPEC_URL"], spec_path, readiness_budget=60)
        step = "validate spec"
        spec = json.loads(spec_path.read_text())
        instrument["image"] = spec.get("image")
        validate_spec(spec)
        instrument["deadline_seconds"] = int(spec["hook_flags"][1]) if spec.get("hook_flags") else 30
        instrument["deadline_scale"] = spec.get("deadline_scale", 1.0)
        case = work_root / "case"
        case.mkdir()
        git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-C", str(case)]
        step = "git init"
        run([*git, "init", "-q"])
        run([*git, "remote", "add", "origin", spec["repository_url"]])
        # One total fetch budget, independent of the hook deadline.
        fetch_end = clock() + 180
        for key in ("head", "base"):
            step = "fetch " + key
            remaining = fetch_end - clock()
            if remaining <= 0:
                raise ReplayFailure("fetch deadline")
            run([*git, "fetch", "--no-tags", "--depth", "1", "origin", spec[key]], timeout=remaining)
            step = "verify " + key
            run([*git, "cat-file", "-e", spec[key] + "^{commit}"])
            instrument[key + "_verified"] = True
        step = "checkout"
        run([*git, "checkout", "--detach", spec["head"]])
        paths = run([*git, "ls-files", "-z"]).stdout.split("\0")
        for name in filter(None, paths):
            path = case / name
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                instrument["checkout_files"] += 1
                instrument["checkout_bytes"] += len(data)
                if instrument["checkout_bytes"] > 500 * 1024 * 1024:
                    raise ReplayFailure("checkout size limit")
        step = "changed files"
        changed = run([*git, "diff", "--name-only", "--diff-filter=ACMRT", "-z", spec["base"], spec["head"]]).stdout.split("\0")
        for name in filter(None, changed):
            path = case / name
            if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(case.resolve()):
                instrument["changed_bytes"][name] = len(path.read_bytes())
        if not instrument["checkout_bytes"] or not sum(instrument["changed_bytes"].values()):
            instrument["suspect_fast"] = True
            raise ReplayFailure("no changed bytes read")
        step = "pre-push"
        env = {
            key: value for key, value in os.environ.items() if key not in {"SPEC_URL", "RESULT_URL", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"}
        }
        env["OPENULTRASAST_CPG_HEAP_MB"] = "1700" if heap_profile == "cluster" else "2560"
        env["JAVA_TOOL_OPTIONS"] = CLUSTER_FLAGS if heap_profile == "cluster" else "-Xmx2560m"
        command = [
            "ousast",
            "pre-push",
            str(case),
            "--base",
            spec["base"],
            "--head",
            spec["head"],
            "--artifact",
            str(output / "push.json"),
            *spec.get("hook_flags", []),
        ]
        before = clock()
        completed = runner(
            command, capture_output=True, text=True, timeout=int(spec["hook_flags"][1]) + 30 if spec.get("hook_flags") else 60, env=env
        )
        instrument["timings"][step] = clock() - before
        instrument["hook_exit"] = completed.returncode
        (output / "push.txt").write_text(completed.stdout)
        if completed.returncode not in (0, 1):
            raise ReplayFailure(f"hook exit {completed.returncode}")
        step = "read push artifact"
        push = json.loads((output / "push.json").read_text())
        instrument["hook_bytes_read"] = sum(t.get("bytes_read", 0) for t in push.get("quick_tier", []))
        scans = push.get("scans", [])
        instrument["jvm_wall_seconds"] = sum(s.get("scan", {}).get(k, 0) for s in scans for k in ("build_seconds", "query_seconds"))
        uncovered = "language_not_covered" in json.dumps(push.get("admission", {}).get("coverage_reasons", []))
        partitions = [part for scan in scans for part in scan.get("scan", {}).get("partitions", [])]
        unsupported_only = (
            uncovered
            and instrument["hook_bytes_read"] == 0
            and bool(partitions)
            and all(part.get("status") == "unsupported" for part in partitions)
        )
        instrument["suspect_fast"] = bool(scans) and not unsupported_only and instrument["jvm_wall_seconds"] < 5
        if instrument["suspect_fast"] or (instrument["hook_bytes_read"] <= 0 and not uncovered):
            instrument["suspect_fast"] = True
            raise ReplayFailure("suspect_fast or unread hook input")
        engine = {
            "repository": spec["repository_url"],
            "revisions": {key: spec[key] for key in ("base", "head")},
            "scans": scans,
            "admission": push.get("admission", {}),
        }
        (output / "engine.json").write_text(json.dumps(engine))
        instrument["status"] = "ok"
    except Exception as exc:
        detail = (
            f"HTTP {exc.code}"
            if isinstance(exc, urllib.error.HTTPError)
            else str(exc)
            if isinstance(exc, ReplayFailure)
            else type(exc).__name__
        )
        instrument["failure"] = {"step": step, "status": detail}
        # A crash artifact must never be mistaken for a completed scan.
        if not (output / "push.json").exists():
            (output / "push.json").write_text("{}")
        if not (output / "push.txt").exists():
            (output / "push.txt").write_text("")
        if not (output / "engine.json").exists():
            (output / "engine.json").write_text("{}")
    instrument["seconds"] = clock() - started
    (output / "instrument.json").write_text(json.dumps(instrument))
    try:
        archive = work_root / "result.dat"
        with tarfile.open(archive, "w") as tar:
            for name in ("push.json", "push.txt", "engine.json", "instrument.json"):
                tar.add(output / name, arcname=name)
        request = urllib.request.Request(
            os.environ["RESULT_URL"], data=archive.read_bytes(), method="PUT", headers={"Content-Type": "application/x-tar"}
        )
        transfer(request, readiness_budget=60)
    except Exception as exc:
        detail = f"HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
        print("PUT result: " + detail, file=sys.stderr)
        return 1
    return int(instrument["status"] != "ok")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heap-profile", choices=("cluster", "vm"), default="cluster")
    raise SystemExit(main(heap_profile=parser.parse_args().heap_profile))
