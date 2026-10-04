"""Image-resident queue workers. Requires strongly consistent S3 GET/PUT/LIST.

Per-task Lamport bakery tickets use only ordinary object operations. A choosing
marker precedes ticket selection; contenders wait for choosing peers and lower
(ticket, worker) pairs. Late arrivals cannot displace a running owner. Leases
assume bounded clock skew (less than MARGIN / 2) and a worker killed by its deadline.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import io
import json
import logging
import multiprocessing
import os
import signal
import socket
import tarfile
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from engine_trace_worker import unit_record, worker

from openultrasast.plane.memory import S3Client, s3_settings

PENDING = "engine-queue/pending/"
CLAIMED = "engine-queue/claimed/"
RESULTS = "engine-results/"
MARGIN = 60
LOG = logging.getLogger(__name__)


def client_from_env():
    settings = s3_settings(os.environ)
    bucket = os.environ.get("S3_BUCKET")
    if not bucket:
        raise ValueError("S3_BUCKET is required")
    return S3Client(bucket=bucket, **settings)


def read(client, key):
    value = client.get(key)
    return json.loads(value[0]) if value else None


def put(client, key, value):
    client.put(key, json.dumps(value).encode(), {})


def result_key(task):
    return f"{RESULTS}{task['run']}/{task['id']}.json"


def pack(root):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        archive.add(root, arcname=".")
    return stream.getvalue()


def unpack(data, root):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        # Source snapshots need only regular files and directories, never links/devices.
        for member in archive.getmembers():
            target = (root / member.name).resolve()
            if not target.is_relative_to(root.resolve()) or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe source archive")
        archive.extractall(root, filter="data")


class Queue:
    def __init__(self, client, identity=None, *, now=time.time, pause=time.sleep, stop=None):
        self.client = client
        self.identity = identity or f"{socket.gethostname()}-{uuid.uuid4().hex}"
        self.now, self.pause = now, pause
        self.stop = stop or threading.Event()

    def markers(self, task_id=None):
        result = []
        for key in self.client.keys(CLAIMED):
            if task_id is None or key.rsplit("/", 1)[-1] == task_id:
                marker = read(self.client, key)
                if marker:
                    result.append((key, marker))
        return result

    def tasks(self):
        tasks = {}
        for key in self.client.keys(PENDING):
            task = read(self.client, key)
            if task:
                tasks[task["task_id"]] = task
        # A dead worker may have removed pending already. Its task remains in the lease.
        for _, marker in self.markers():
            if marker["expires"] < self.now():
                task = marker["task"]
                tasks.setdefault(task["task_id"], task)
        return list(tasks.values())

    def claim(self, task):
        if read(self.client, result_key(task)) is not None or self.stop.is_set():
            return None
        key = f"{CLAIMED}{self.identity}/{task['task_id']}"
        marker = dict(task=task, ticket=0, expires=self.now() + task["deadline"] + MARGIN)
        put(self.client, key, marker)
        try:
            live = [m for _, m in self.markers(task["task_id"]) if m["expires"] > self.now()]
            marker["ticket"] = 1 + max((m["ticket"] for m in live), default=0)
            put(self.client, key, marker)
            while not self.stop.is_set():
                # Do not start once the execution budget no longer fits within our lease.
                if self.now() >= marker["expires"] - task["deadline"] - MARGIN / 2:
                    break
                peers = [(k, m) for k, m in self.markers(task["task_id"]) if k != key and m["expires"] > self.now()]
                if any(m["ticket"] == 0 for _, m in peers):
                    self.pause(0.1)
                    continue
                if any((m["ticket"], k) < (marker["ticket"], key) for k, m in peers):
                    break  # loser backs off and can try another pending task
                if read(self.client, key) != marker or read(self.client, result_key(task)) is not None:
                    break
                self.client.delete(PENDING + task["task_id"])
                return key
        except Exception:
            self.client.delete(key)
            raise
        self.client.delete(key)
        return None

    def process_one(self, execute=None):
        for task in self.tasks():
            key = self.claim(task)
            if key is None:
                continue
            try:
                lease = read(self.client, key)
                if lease is None:
                    continue
                budget = min(task["deadline"], lease["expires"] - self.now() - MARGIN / 2)
                if budget <= 0:
                    continue  # Leave the expired lease's task available to recovery.
                result = (execute or execute_task)(self.client, {**task, "runtime_budget": budget})
                result.update(executor="queue", worker=self.identity, pod=socket.gethostname(), image=os.environ.get("ENGINE_IMAGE", ""))
                put(self.client, result_key(task), result)
                # Publish the result before removing either the input or the claim.
                self.client.delete(task["input"])
                for old_key, old in self.markers(task["task_id"]):
                    if old_key == key or old["expires"] < self.now():
                        self.client.delete(old_key)
                return True
            except Exception:
                # Keep the lease and task for recovery, without logging credential-bearing errors.
                LOG.error("task failed; lease retained for recovery")
                return False
        return False


def _child(pin, root, out, deadline, question_deadline):
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    worker(pin, root, out, deadline, question_deadline)


def adopt_orphans():
    # Linux PR_SET_CHILD_SUBREAPER: escaped Joern sessions reparent here, not
    # outside the service. There is exactly one task process tree per worker.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError("cannot enable task descendant cleanup")


def kill_children():
    """Freeze parents before walking children, including new-session JVMs."""
    seen = set()

    def freeze(parent):
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) in seen:
                continue
            try:
                # comm can contain spaces or parentheses. Fields after it begin at state.
                fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[1]) != parent:
                    continue
                pid = int(entry.name)
                os.kill(pid, signal.SIGSTOP)
                seen.add(pid)
                freeze(pid)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue

    # A child that exited during discovery can reparent descendants to this
    # subreaper. Repeat until every remaining descendant is frozen.
    while True:
        count = len(seen)
        freeze(os.getpid())
        if len(seen) == count:
            break
    for pid in seen:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def execute_task(client, task):
    adopt_orphans()
    pin = task["pin"]
    started = time.monotonic()
    budget = task.get("runtime_budget", task["deadline"])
    status, reason, code = "failed", "worker produced no result", None
    with tempfile.TemporaryDirectory(prefix="engine-task-") as scratch:
        root, out = Path(scratch) / "case", Path(scratch) / "result.json"
        root.mkdir()
        try:
            if task["deadline"] > 900 or task["deadline"] <= 0:
                raise ValueError("deadline exceeds deployment grace")
            if task.get("image") != os.environ.get("ENGINE_IMAGE"):
                raise ValueError("task image differs from deployed image")
            source = client.get(task["input"])
            if source is None:
                raise ValueError("missing source")
            unpack(source[0], root)
            # The shipped worker also checks frontend input and graph output for every language.
            files = [p for p in root.rglob("*") if p.is_file()]
            if not files:
                raise ValueError("empty source")
            LOG.info("input proof: first file bytes=%d", len(files[0].read_bytes()))
            if time.monotonic() - started >= budget:
                status, reason = "timeout", "task input deadline"
                raise TimeoutError(reason)
            process = multiprocessing.get_context("fork").Process(target=_child, args=(pin, root, out, budget, task["question_deadline"]))
            process.start()
            try:
                process.join(max(0, budget - (time.monotonic() - started)))
                if process.is_alive():
                    status, reason = "timeout", "task deadline"
                else:
                    reason = f"worker exit {process.exitcode}"
                code = process.exitcode
            finally:
                # Joern creates separate sessions. Kill the whole descendant tree,
                # not merely the Python wrapper's process group.
                kill_children()
                process.join()
                # Reap adopted JVMs and their launchers after the direct child.
                while True:
                    try:
                        os.waitpid(-1, 0)
                    except ChildProcessError:
                        break
            record = json.loads(out.read_text()) if out.exists() else {**pin, "units": []}
        except Exception:
            record = {**pin, "units": []}
            reason = "worker input or execution failed"
        if not record.get("done") or code != 0:
            previous = {u["unit"]: u for u in record["units"]}
            record["units"] = [
                previous[u["unit"]]
                if code is None and previous.get(u["unit"], {}).get("status") in {"path", "asked-nothing"}
                else unit_record(u, status if u["supported"] else "unsupported", reason if u["supported"] else u["reason"])
                for u in pin["units"]
            ]
        record.update(done=True, container_exit=code, seconds=time.monotonic() - started)
        return record


def status(client):
    return {
        "pending": len(client.keys(PENDING)),
        "claimed": len(client.keys(CLAIMED)),
        "done": len([k for k in client.keys(RESULTS) if k.endswith(".json")]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    client = client_from_env()
    queue = Queue(client, stop=stop)

    class Health(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/healthz" and not stop.is_set() else 503)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while not stop.is_set():
            try:
                if not queue.process_one():
                    stop.wait(2)
            except Exception:
                LOG.error("queue unavailable; retrying")
                stop.wait(5)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
