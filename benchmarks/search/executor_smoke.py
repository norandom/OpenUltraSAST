"""One no-model executor task; run as python -m benchmarks.search.executor_smoke.

Runtime acquisition/install needs network inside the executor. Unit tests are offline.
Records contain measurements, never command output or presigned bearer URLs.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import tarfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from benchmarks.ax.batch import AXLane, DockerLane, SearchExecutorTask, Workload, validate_image

# URL and pin are positional shell arguments, never interpolated into shell code.
# Retry the initial acquisition for delayed task egress activation (at most 60 s).
CLONE = """git init -q .
git remote add origin "$1"
end=$(($(date +%s) + 60))
until git -c protocol.version=2 fetch --depth=1 origin "$2"; do
  test "$(date +%s)" -lt "$end" || exit 1
  sleep 3
done
git checkout -q --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$2"
"""


def install_recipe(files):
    """Fixed recipes, selected from checkout root manifests only."""
    files = set(files)
    if "requirements.txt" in files:
        return "pip", ["python3", "-m", "pip", "install", "--target", "/workspace/packages", "-r", "requirements.txt"]
    if files & {"pyproject.toml", "setup.py", "setup.cfg"}:
        return "pip", ["python3", "-m", "pip", "install", "--target", "/workspace/packages", "."]
    if "package.json" in files:
        return "npm", ["npm", "ci" if "package-lock.json" in files else "install"]
    if "composer.json" in files:
        return "composer", ["composer", "install", "--no-interaction", "--prefer-dist"]
    if "pom.xml" in files:
        return "maven", ["mvn", "-B", "-Dmaven.repo.local=/workspace/.m2", "-DskipTests", "package"]
    raise ValueError("no recognised install manifest")


def run_smoke(lane, repo_url, commit, *, deadline=900):
    record = {
        "status": "instrument_failure",
        "commands": [],
        "scratch_peak_bytes": 0,
        "scratch_measurement": "sampled workspace allocated bytes plus command logs",
        "model_calls": 0,
    }
    started = time.monotonic()
    try:
        parts = urlsplit(repo_url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("credential-free HTTPS repository URL required")
        if not re.fullmatch("[0-9a-f]{40}", commit):
            raise ValueError("full lowercase commit SHA required")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w"):
            pass
        # The empty checkout is filled by the first command inside the key-free task.
        with SearchExecutorTask(lane, archive.getvalue(), deadline=deadline) as task:
            record["task"] = task.name

            def command(step, name, args):
                remaining = deadline - (time.monotonic() - started) - 2
                if remaining <= 0:
                    raise TimeoutError("smoke deadline")
                timeout = min(300, remaining)
                if name == "run":
                    args = {**args, "timeout_seconds": timeout}
                before = time.monotonic()
                result = task.client.submit(
                    name, args, timeout_seconds=timeout, limits={"memory_bytes": 2 * 1024**3, "disk_bytes": 2 * 1024**3}
                )
                output_bytes = sum(result.get(k + "_bytes", len(result.get(k, "").encode())) for k in ("stdout", "stderr"))
                if name != "run":
                    output_bytes = len(json.dumps(result).encode())
                row = {
                    "step": step,
                    "command": name,
                    "wall_seconds": result.get("wall_seconds", time.monotonic() - before),
                    "roundtrip_seconds": time.monotonic() - before,
                    "exit_code": result.get("exit_code"),
                    "output_bytes": output_bytes,
                    "scratch_peak_bytes": result.get("scratch_peak_bytes"),
                    "truncated": result.get("truncated", False),
                }
                if "input_bytes" in result:
                    row["input_bytes"] = result["input_bytes"]
                record["commands"].append(row)
                record["scratch_peak_bytes"] = max(record["scratch_peak_bytes"], result.get("scratch_peak_bytes", 0))
                if result.get("error") or result.get("timed_out") or result.get("status") == "could_not_build":
                    raise ValueError(step + " executor failure")
                if name == "run" and result.get("exit_code") != 0:
                    raise ValueError(step + " nonzero or missing exit code")
                if step == "install" and output_bytes == 0 and row["wall_seconds"] < 1:
                    raise ValueError("empty fast install: exit 0 with empty output in under 1 s")
                return result

            command("clone", "run", {"command": ["sh", "-ec", CLONE, "clone", repo_url, commit]})
            files = command("list_files", "list_files", {}).get("files", [])
            if not files:
                raise ValueError("clone yielded zero files")
            record["files_listed"] = len(files)
            readme = next((p for p in files if Path(p).name.lower().startswith("readme")), None)
            # Always open input even when the repository has no README.
            read = command("read_file", "read_file", {"path": readme or files[0]})
            record["readme_present"] = readme is not None
            record["input_bytes"] = read.get("input_bytes")
            if not isinstance(record["input_bytes"], int):
                raise ValueError("file read lacks input size")
            command("grep", "grep", {"pattern": "test"})
            recipe, argv = install_recipe(files)
            record["recipe"] = recipe
            command("install", "run", {"command": argv})
            trivial = ["node", "-e", "console.log(1)"] if recipe == "npm" else ["python3", "-c", "print(1)"]
            ran = command("trivial", "run", {"command": trivial})
            if ran.get("stdout", "").strip() != "1":
                raise ValueError("trivial command did not print 1")
            if not command("stop", "stop", {}).get("stopped"):
                raise ValueError("stop not acknowledged")
            record["status"] = "ok"
    except Exception as exc:
        record["status"] = "instrument_failure"
        # Only our fixed diagnostic strings are safe; transport errors may contain URLs.
        record["reason"] = (
            str(exc)
            if isinstance(exc, ValueError)
            and str(exc)
            in {
                "credential-free HTTPS repository URL required",
                "full lowercase commit SHA required",
                "no recognised install manifest",
                "clone yielded zero files",
                "file read lacks input size",
                "trivial command did not print 1",
                "stop not acknowledged",
                "empty fast install: exit 0 with empty output in under 1 s",
                *(
                    step + suffix
                    for step in ("clone", "list_files", "read_file", "grep", "install", "trivial", "stop")
                    for suffix in (" executor failure", " nonzero or missing exit code")
                ),
            }
            else type(exc).__name__
        )
    record["wall_seconds"] = time.monotonic() - started
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=("ax", "docker"), required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True, help="One JSON record")
    parser.add_argument("--deadline", type=float, default=900)
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--kubeconfig")
    args = parser.parse_args(argv)
    try:
        validate_image(args.image)
        lane = (DockerLane if args.lane == "docker" else AXLane)(args, Workload(args.image, frozenset(), args.deadline, None))
        record = run_smoke(lane, args.repo_url, args.commit, deadline=args.deadline)
    except Exception as exc:
        record = {"status": "instrument_failure", "reason": "lane setup: " + type(exc).__name__}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record))
    return int(record["status"] != "ok")


if __name__ == "__main__":
    raise SystemExit(main())
