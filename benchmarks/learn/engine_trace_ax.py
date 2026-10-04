"""Host-only AX Task transport; credentials never enter task manifests."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import queue
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from engine_trace_k8s import pack

from openultrasast.config import load_dotenv
from openultrasast.plane.memory import S3Store, open_store


class EgressError(ValueError):
    """Safe diagnostic without presigned URL contents."""


def public_endpoint(url):
    """Reject endpoints the actor's hostname-based HTTPS egress policy cannot reach."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if (
        parts.scheme != "https"
        or not host
        or is_ip
        or "." not in host
        or host.endswith((".localhost", ".local", ".internal"))
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
    ):
        raise EgressError(
            "AX requires a public HTTPS DNS hostname in S3_ENDPOINT and presigned URLs: "
            "the egress policy allows the store hostname on port 443 only (no IP or plain HTTP)"
        )
    return host.lower()


def task_manifest(name, args, urls):
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", args.image):
        raise ValueError("AX --image must be pinned by sha256 digest")
    if set(urls) != {"SOURCE_URL", "QUESTIONS_URL", "RESULT_URL"}:
        raise ValueError("AX Task accepts only source, questions and result presigned URLs")
    for url in urls.values():
        public_endpoint(url)
    env = [{"name": key, "value": value} for key, value in urls.items()]
    env.extend(
        {"name": key, "value": str(value)}
        for key, value in {"DEADLINE": args.deadline, "QUESTION_DEADLINE": args.question_deadline}.items()
    )
    if len(json.dumps(env).encode()) >= 32768:
        raise ValueError("AX Task env exceeds the 32 KB limit")
    return {
        "apiVersion": "ax.io/v1alpha1",
        "kind": "Task",
        "metadata": {"name": name, "atespace": args.atespace},
        "spec": {"image": args.image, "env": env, "command": ["python3", "/app/benchmarks/learn/engine_task_entry.py"]},
    }


def task_state(text, name):
    """Accept AX YAML/JSON output and its human-readable tasks table."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        doc = None
    rows = doc.get("items", doc.get("tasks", [doc])) if isinstance(doc, dict) else doc if isinstance(doc, list) else []
    for row in rows:
        if not isinstance(row, dict) or row.get("metadata", {}).get("name", row.get("name")) != name:
            continue
        status = row.get("status", {})
        ip = next(
            (status.get(key) or row.get(key) for key in ("workerIP", "workerIp", "worker_ip", "ip") if status.get(key) or row.get(key)),
            None,
        )
        worker = status.get("worker")
        if not ip and isinstance(worker, dict):
            ip = worker.get("ip") or worker.get("address")
        return str(status.get("phase", row.get("phase", ""))), ip
    lines = [line.split() for line in text.splitlines() if line.strip()]
    if lines:
        headers = [re.sub(r"[^a-z]", "", cell.lower()) for cell in lines[0]]
        for cells in lines[1:]:
            if name not in cells:
                continue
            row = dict(zip(headers, cells, strict=False))
            phase = row.get("phase", row.get("status", ""))
            ip = row.get("workerip") or row.get("ip")
            if not ip:
                for cell in cells:
                    try:
                        ipaddress.ip_address(cell)
                        ip = cell
                        break
                    except ValueError:
                        pass
            return phase, None if ip in {"<none>", "-", ""} else ip
    return "", None


def bounded_read(read, timeout):
    """Do not let SDK retries postpone task teardown beyond the pin deadline.

    Only the read runs in a daemon thread; it cannot publish a late result to disk.
    No executor shutdown waits for an SDK call whose socket has stopped responding.
    """
    if timeout <= 0:
        raise TimeoutError("AX result deadline")
    replies = queue.Queue(maxsize=1)

    def fetch():
        try:
            replies.put((True, read()))
        except Exception as exc:
            replies.put((False, exc))

    threading.Thread(target=fetch, daemon=True, name="engine-ax-result-read").start()
    try:
        ok, result = replies.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError("AX result deadline") from None
    if not ok:
        raise result
    return result


class AX:
    def __init__(self, args, store=None, pause=time.sleep, clock=time.monotonic):
        self.args = args
        self.pause, self.clock = pause, clock
        self.run = uuid.uuid4().hex
        load_dotenv()
        self.host = public_endpoint(os.environ.get("S3_ENDPOINT", ""))
        # Validate the image before opening a store, whose constructor probes the bucket.
        task_manifest("validate", args, {key: f"https://{self.host}/" for key in ("SOURCE_URL", "QUESTIONS_URL", "RESULT_URL")})
        self.store = store if store is not None else open_store()
        if store is None and not isinstance(self.store, S3Store):
            raise ValueError("AX requires OUSAST_MEMORY=s3://bucket[/prefix]")

    def ax(self, *args, manifest=None, timeout=30):
        env = dict(os.environ)
        if self.args.kubeconfig:
            env["KUBECONFIG"] = str(Path(self.args.kubeconfig).expanduser())
        done = subprocess.run(
            [str(Path(self.args.ax_bin).expanduser()), *args, *(["--atespace", self.args.atespace] if args[0] != "apply" else [])],
            input=json.dumps(manifest) if manifest is not None else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=max(0.01, timeout),
        )
        if done.returncode:
            # AX errors may echo manifest URLs; report only verb and exit code.
            raise ValueError(f"ax {args[0]} failed (exit {done.returncode})")
        return done

    def receive(self, data, output, pin):
        # Validate in isolation: malformed results must never become usable checkpoints.
        with tempfile.TemporaryDirectory(prefix="engine-ax-result-") as temporary:
            root = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.extractall(root, filter="data")
            record = json.loads((root / "result.json").read_text())
            units = record.get("units", [])
            if record.get("done") and record.get("status") == "failed" and not units:
                # Questions download can fail before the actor learns any unit identities.
                # Keep that explicit failure, filling identities only from the host input.
                record = {
                    **pin,
                    **record,
                    "units": [
                        {
                            **unit,
                            "status": "failed" if unit["supported"] else "unsupported",
                            "reason": record.get("reason", "AX task entry failed"),
                            "instrument": {"files": [], "bytes": 0, "cpg_path": None, "cpg_bytes": 0, "jvm": []},
                            "questions": {},
                            "questions_asked": [],
                            "questions_completed": [],
                            "witness_rows": [],
                            "traces": [],
                        }
                        for unit in pin["units"]
                    ],
                }
                units = record["units"]
                (root / "result.json").write_text(json.dumps(record))
            expected = [u["unit"] for u in pin["units"]]
            actual = [u["unit"] for u in units]
            if not record.get("done") or sorted(actual) != sorted(expected):
                raise ValueError("AX Task returned incomplete or mismatched units")
            output.mkdir(parents=True, exist_ok=True)
            # Keep the artifacts without interpreting any remote paths as host destinations.
            shutil.copytree(root, output, dirs_exist_ok=True)

    def execute(self, checkout, output, pin, pin_id):
        digest = hashlib.sha256(f"{self.run}/{pin_id}".encode()).hexdigest()[:12]
        slug = re.sub(r"[^a-z0-9]+", "-", str(pin_id).lower()).strip("-")[:22]
        name = f"ousast-engine-{slug or 'pin'}-{digest}"
        key_id = hashlib.sha256(str(pin_id).encode()).hexdigest()
        prefix = f"engine-queue/{self.run}/{key_id}/"
        keys = [prefix + suffix for suffix in ("source.tar", "questions.json", "result.tar")]
        expires = timedelta(seconds=self.args.deadline + 600)
        worker_ip = None
        submitted = False
        try:
            self.store._put(keys[0], pack(checkout))
            self.store._put(keys[1], json.dumps(pin).encode())
            urls = {
                "SOURCE_URL": self.store.presign_get(keys[0], expires),
                "QUESTIONS_URL": self.store.presign_get(keys[1], expires),
                "RESULT_URL": self.store.presign_put(keys[2], expires),
            }
            if any(public_endpoint(url) != self.host for url in urls.values()):
                raise EgressError("AX presign hostname must match S3_ENDPOINT for the store egress policy")
            manifest = task_manifest(name, self.args, urls)
            end = self.clock() + self.args.deadline
            # An apply timeout can still have created the task; cleanup must cover it.
            submitted = True
            self.ax("apply", "-f", "-", manifest=manifest, timeout=min(30, self.args.deadline))
            while self.clock() < end:
                result = bounded_read(lambda: self.store._get(keys[2]), end - self.clock())
                if self.clock() >= end:
                    return None, worker_ip
                phase = ""
                try:
                    state = self.ax("get", "tasks", timeout=min(30, end - self.clock())).stdout
                    phase, ip = task_state(state, name)
                    worker_ip = ip or worker_ip
                except (ValueError, OSError, subprocess.SubprocessError):
                    # The object is authoritative even when AX status is temporarily unavailable.
                    pass
                if self.clock() >= end:
                    return None, worker_ip
                if result is not None:
                    self.receive(result[0], output, pin)
                    return subprocess.CompletedProcess([], 0, "", ""), worker_ip
                if phase.lower() == "failed":
                    return subprocess.CompletedProcess([], 1, "", "AX Task phase Failed"), worker_ip
                self.pause(min(2, max(0, end - self.clock())))
            return None, worker_ip
        except (subprocess.TimeoutExpired, TimeoutError):
            return None, worker_ip
        except Exception as exc:
            # Never expose exception strings which may contain object-scoped bearer URLs.
            detail = str(exc) if isinstance(exc, EgressError) else type(exc).__name__
            return subprocess.CompletedProcess([], 1, "", "AX transport failed: " + detail), worker_ip
        finally:
            errors = []
            if submitted:
                try:
                    self.ax("delete", "task", name)
                except Exception as exc:
                    errors.append("task: " + type(exc).__name__)
            for key in keys:
                try:
                    self.store._delete(key)
                except Exception as exc:
                    errors.append("object: " + type(exc).__name__)
            if errors:
                raise RuntimeError("AX cleanup failed; stop dispatching: " + ", ".join(errors))
