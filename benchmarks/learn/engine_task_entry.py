"""AX task entry: object-scoped transfers and stdlib only; result PUT is completion."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class TaskEntryError(RuntimeError):
    """A task-entry diagnostic containing only locally controlled text."""


def transfer(request, destination=None, *, readiness_budget=None):
    """Wait for actor egress on startup; bound later transfers to three attempts."""
    deadline = time.monotonic() + readiness_budget if readiness_budget is not None else None
    delay = 0.5
    attempt = 0
    while True:
        remaining = deadline - time.monotonic() if deadline is not None else 60
        if remaining <= 0:
            raise TaskEntryError("egress not open after 60 s")
        attempt += 1
        try:
            with urllib.request.urlopen(request, timeout=min(60, remaining)) as response:
                if destination is not None:
                    with destination.open("wb") as output:
                        shutil.copyfileobj(response, output)
            return
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code != 403 and not 500 <= exc.code < 600:
                raise
            if deadline is None and attempt >= 3:
                raise
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            if deadline is None and attempt >= 3:
                raise
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TaskEntryError("egress not open after 60 s") from None
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 8)
        else:
            time.sleep(attempt)


def download(url, destination, *, readiness_budget=None):
    transfer(url, destination, readiness_budget=readiness_budget)


def unpack(source, destination):
    """Reject links and traversal; source archives contain only regular files/directories."""
    with tarfile.open(source) as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()) or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe source archive member")
        archive.extractall(destination, filter="data")


def failure_record(pin, reason):
    return {
        **pin,
        "done": True,
        "status": "failed",
        "reason": reason,
        "units": [
            {
                **unit,
                "status": "failed" if unit.get("supported", True) else "unsupported",
                "reason": reason,
                "instrument": {"files": [], "bytes": 0, "jvm": []},
                "questions": {},
                "questions_asked": [],
                "questions_completed": [],
                "witness_rows": [],
                "traces": [],
            }
            for unit in pin.get("units", [])
        ],
    }


def main(*, work_root=Path("/tmp"), worker_script=None, readiness_budget=60):
    pin = {}
    failed = False
    output = work_root / "out"
    result = output / "result.json"
    step = "prepare output"
    try:
        output.mkdir(parents=True, exist_ok=True)
        result.unlink(missing_ok=True)
        questions = work_root / "questions.json"
        step = "GET questions"
        download(os.environ["QUESTIONS_URL"], questions, readiness_budget=readiness_budget)
        step = "parse questions"
        pin = json.loads(questions.read_text())
        if not isinstance(pin, dict):
            pin = {}
            raise ValueError("questions object must contain a prepared pin")
        source = work_root / "source.tar"
        step = "GET source"
        download(os.environ["SOURCE_URL"], source)
        step = "unpack source"
        case = work_root / "case"
        case.mkdir(parents=True, exist_ok=True)
        unpack(source, case)
        step = "configure worker"
        deadline = int(os.environ.get("DEADLINE", "900"))
        command = [
            sys.executable,
            str(worker_script or Path(__file__).with_name("engine_trace_worker.py")),
            "--worker",
            str(questions),
            "--root",
            str(case),
            "--output",
            str(result),
            "--heap-profile",
            "cluster",
            "--deadline",
            str(deadline),
            "--question-deadline",
            os.environ.get("QUESTION_DEADLINE", "120"),
        ]
        step = "run worker"
        completed = subprocess.run(command, timeout=deadline + 5, check=False)
        if completed.returncode:
            raise TaskEntryError(f"worker exited {completed.returncode}")
        step = "read worker result"
        if not result.is_file() or not json.loads(result.read_text()).get("done"):
            raise TaskEntryError("worker did not write a completed result")
    except Exception as exc:
        failed = True
        # Avoid including exception text containing a presigned URL in durable output.
        if isinstance(exc, urllib.error.HTTPError):
            detail = f"HTTP {exc.code}"
        else:
            detail = str(exc) if isinstance(exc, TaskEntryError) else type(exc).__name__
        reason = f"{step}: {detail}"
        try:
            output.mkdir(parents=True, exist_ok=True)
            result.write_text(json.dumps(failure_record(pin, reason)) + "\n")
        except Exception:
            print("task entry could not write failure result", file=sys.stderr)
    step = "pack result"
    try:
        archive = work_root / "result.tar"
        with tarfile.open(archive, "w") as tar:
            for path in sorted(output.iterdir()):
                tar.add(path, arcname=path.name)
        data = archive.read_bytes()
        step = "PUT result"
        request = urllib.request.Request(os.environ["RESULT_URL"], data=data, method="PUT", headers={"Content-Type": "application/x-tar"})
        transfer(request, readiness_budget=readiness_budget if failed else None)
    except Exception as exc:
        detail = f"HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
        print(f"{step}: {detail}; dispatcher deadline remains authoritative", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
