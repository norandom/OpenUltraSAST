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

from benchmarks.valid.artifact_contract import write_benchmark_artifact


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


def _read_worker_result(path, pin):
    """Validate the engine worker's raw handoff before benchmark-owned persistence."""
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise TaskEntryError("worker result is unreadable") from error
    if not isinstance(value, dict) or {"schema_version", "artifact_kind", "artifact_digest"}.intersection(value):
        raise TaskEntryError("worker result has an unsupported raw schema")
    units = value.get("units")
    expected = [unit.get("unit") for unit in pin.get("units", [])]
    if value.get("done") is not True or not isinstance(units, list):
        raise TaskEntryError("worker did not write a completed result")
    actual = [unit.get("unit") for unit in units if isinstance(unit, dict)]
    if len(actual) != len(units) or actual != expected:
        raise TaskEntryError("worker result units do not match the prepared pin")
    return value


def _produce_result(work_root, worker_script, readiness_budget, state):
    output = work_root / "out"
    result = output / "result.json"
    output.mkdir(parents=True, exist_ok=True)
    result.unlink(missing_ok=True)
    questions = work_root / "questions.json"
    state["step"] = "GET questions"
    download(os.environ["QUESTIONS_URL"], questions, readiness_budget=readiness_budget)
    state["step"] = "parse questions"
    pin = json.loads(questions.read_text())
    if not isinstance(pin, dict):
        raise ValueError("questions object must contain a prepared pin")
    state["pin"] = pin
    source, case = work_root / "source.tar", work_root / "case"
    state["step"] = "GET source"
    download(os.environ["SOURCE_URL"], source)
    state["step"] = "unpack source"
    case.mkdir(parents=True, exist_ok=True)
    unpack(source, case)
    deadline = int(os.environ.get("DEADLINE", "900"))
    command = _worker_command(worker_script, questions, case, result, deadline)
    state["step"] = "run worker"
    completed = subprocess.run(command, timeout=deadline + 5, check=False)
    if completed.returncode:
        raise TaskEntryError(f"worker exited {completed.returncode}")
    state["step"] = "read worker result"
    worker_result = _read_worker_result(result, pin) if result.is_file() else {}
    if not worker_result:
        raise TaskEntryError("worker did not write a completed result")
    write_benchmark_artifact(result, "engine-task-result", worker_result, replace=True)
    return output, result


def _worker_command(worker_script, questions, case, result, deadline):
    return [
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


def _failure_detail(error):
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP {error.code}"
    return str(error) if isinstance(error, TaskEntryError) else type(error).__name__


def _persist_failure(work_root, state, error):
    output, result = work_root / "out", work_root / "out/result.json"
    reason = f"{state['step']}: {_failure_detail(error)}"
    try:
        output.mkdir(parents=True, exist_ok=True)
        write_benchmark_artifact(result, "engine-task-failure", failure_record(state["pin"], reason), replace=True)
    except Exception:
        print("task entry could not write failure result", file=sys.stderr)
    return output


def _pack_result(work_root, output, readiness_budget, failed):
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


def main(*, work_root=Path("/tmp"), worker_script=None, readiness_budget=60):
    state = {"pin": {}, "step": "prepare output"}
    failed = False
    try:
        output, _result = _produce_result(work_root, worker_script, readiness_budget, state)
    except Exception as error:
        failed = True
        output = _persist_failure(work_root, state, error)
    _pack_result(work_root, output, readiness_budget, failed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
