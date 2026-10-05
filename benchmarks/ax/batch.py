"""Host-only AX Task transport; credentials never enter task manifests."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from openultrasast.config import load_dotenv
from openultrasast.plane.memory import PRESIGNED_ARCHIVE_SUFFIX, S3Store, open_store


class EgressError(ValueError):
    """Safe diagnostic without presigned URL contents."""


class SandboxFailure(Exception):
    """A terminal AX task without an authoritative result object."""


class NoFreeWorkers(Exception):
    """Capacity back-pressure, never a sandbox or instrument failure."""


class CapacityDeadline(Exception):
    """No worker became available before the task deadline."""


# Shared by every workload/lane instance in this dispatcher process, including
# long-lived search executors. The operator runs one task per worker, two workers.
AX_SLOTS = threading.BoundedSemaphore(2)


def apply_when_available(lane, document, end):
    while lane.clock() < end:
        try:
            lane.ax("apply", "-f", "-", manifest=document, timeout=min(30, end - lane.clock()))
            return
        except NoFreeWorkers:
            lane.pause(min(random.uniform(15, 30), max(0, end - lane.clock())))
    raise CapacityDeadline("no free workers available before deadline")


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
    listed = isinstance(doc, (dict, list)) or bool(lines and "name" in headers and {"phase", "status"}.intersection(headers))
    return "Missing" if listed else "", None


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


class AXLane:
    def __init__(self, args, workload, store=None, pause=time.sleep, clock=time.monotonic):
        self.workload = workload
        self.args = args
        self.pause, self.clock = pause, clock
        self.run = uuid.uuid4().hex
        load_dotenv()
        self.host = public_endpoint(os.environ.get("S3_ENDPOINT", ""))
        # Validate the image before opening a store, whose constructor probes the bucket.
        validate_image(workload.image)
        self.store = store if store is not None else open_store()
        if store is None and not isinstance(self.store, S3Store):
            raise ValueError("AX requires OUSAST_MEMORY=s3://bucket[/prefix]")

    def __call__(self, item, output, attempt):
        attempts = []
        # Docker has its own capacity and must not hold an AX worker slot.
        slot = not isinstance(self, DockerLane)
        if slot and not AX_SLOTS.acquire(timeout=self.workload.deadline):
            return {"status": "capacity_timeout", "ax_attempts": attempts}
        try:
            done, worker = self._execute_attempt(item, output, attempt, attempts)
        except CapacityDeadline:
            return {"status": "capacity_timeout", "ax_attempts": attempts}
        except SandboxFailure:
            return {"status": "sandbox_failure", "ax_attempts": attempts}
        except RuntimeError:
            # Teardown did not prove the worker free; retain its reservation.
            slot = False
            raise
        finally:
            if slot:
                AX_SLOTS.release()
        if done is None or done.returncode:
            return {"status": "instrument_failure", "ax_attempts": attempts}
        record = json.loads((output / "result.json").read_text())
        return {**record, "worker_ip": worker, "ax_attempts": attempts}

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
            if args[0] == "apply" and "no free workers available" in (done.stdout + done.stderr).lower():
                raise NoFreeWorkers
            # AX errors may echo manifest URLs; report only verb and exit code.
            raise ValueError(f"ax {args[0]} failed (exit {done.returncode})")
        return done

    def _execute_attempt(self, item, output, attempt, attempts):
        pin_id = item.id
        digest = hashlib.sha256(f"{self.run}/{pin_id}/attempt-{attempt}".encode()).hexdigest()[:12]
        slug = re.sub(r"[^a-z0-9]+", "-", str(pin_id).lower()).strip("-")[:22]
        name = f"ousast-engine-{slug or 'pin'}-{digest}"
        key_id = hashlib.sha256(str(pin_id).encode()).hexdigest()
        prefix = f"engine-queue/{self.run}/{key_id}/attempt-{attempt}/"
        keys = [prefix + item.object_names.get(key, key.lower() + PRESIGNED_ARCHIVE_SUFFIX) for key in item.inputs]
        keys.append(prefix + item.result_object)
        expires = timedelta(seconds=self.workload.deadline + 600)
        worker_ip = None
        submitted = False
        started = self.clock()
        phase = ""
        try:
            for key, data in zip(keys, item.inputs.values(), strict=False):
                self.store._put(key, data)
            urls = {env: self.store.presign_get(key, expires) for env, key in zip(item.inputs, keys, strict=False)}
            urls["RESULT_URL"] = self.store.presign_put(keys[-1], expires)
            if any(public_endpoint(url) != self.host for url in urls.values()):
                raise EgressError("AX presign hostname must match S3_ENDPOINT for the store egress policy")
            document = manifest(name, self.workload, item, urls, self.args.atespace)
            end = self.clock() + self.workload.deadline
            # An apply timeout can still have created the task; cleanup must cover it.
            submitted = True
            try:
                apply_when_available(self, document, end)
            except CapacityDeadline:
                submitted = False  # All applies were explicitly rejected.
                raise
            while self.clock() < end:
                result = bounded_read(lambda: self.store._get(keys[-1]), end - self.clock())
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
                    self.workload.validate(result[0], output)
                    return subprocess.CompletedProcess([], 0, "", ""), worker_ip
                if phase.lower() in {"failed", "missing"}:
                    # The worker may have uploaded while we were reading AX status.
                    result = bounded_read(lambda: self.store._get(keys[-1]), end - self.clock())
                    if self.clock() >= end:
                        return None, worker_ip
                    if result is not None:
                        self.workload.validate(result[0], output)
                        return subprocess.CompletedProcess([], 0, "", ""), worker_ip
                    raise SandboxFailure
                self.pause(min(2, max(0, end - self.clock())))
            return None, worker_ip
        except (subprocess.TimeoutExpired, TimeoutError):
            return None, worker_ip
        except (SandboxFailure, CapacityDeadline):
            raise
        except Exception as exc:
            # Never expose exception strings which may contain object-scoped bearer URLs.
            detail = str(exc) if isinstance(exc, EgressError) else type(exc).__name__
            return subprocess.CompletedProcess([], 1, "", "AX transport failed: " + detail), worker_ip
        finally:
            attempts.append({"name": name, "phase": phase, "seconds": self.clock() - started})
            errors = []
            if submitted:
                try:
                    self.ax("delete", "task", name)
                except Exception as exc:
                    # A successful list already confirmed a disappeared task is gone.
                    if phase != "Missing":
                        errors.append("task: " + type(exc).__name__)
            for key in keys:
                try:
                    self.store._delete(key)
                except Exception as exc:
                    errors.append("object: " + type(exc).__name__)
            if errors:
                raise RuntimeError("AX cleanup failed; stop dispatching: " + ", ".join(errors))


@dataclass
class Item:
    id: str
    inputs: dict[str, bytes]
    result_object: str
    command: tuple[str, ...]
    extra_env: dict[str, str]
    input_digest: str
    object_names: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Workload:
    image: str
    url_env: frozenset[str]
    deadline: float
    validate: object


def validate_image(image):
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("AX --image must be pinned by sha256 digest")


def manifest(name, workload, item, urls, atespace="default", *, validate_name=True):
    validate_image(workload.image)
    if validate_name and (not re.fullmatch(r"ousast-engine-[a-z0-9-]+", name) or len(name.encode()) > 49):
        raise ValueError("invalid AX task name")
    if set(urls) != workload.url_env:
        raise ValueError("unexpected URL environment names")
    # Fixed names and semantic values, never inherited environment or credentials.
    patterns = {
        "OUSAST_SCRATCH_BYTES": r"[1-9][0-9]*",
        "DEADLINE": r"[0-9]+(?:\.[0-9]+)?",
        "QUESTION_DEADLINE": r"[0-9]+(?:\.[0-9]+)?",
        "SEARCH_STEP": r"reason|explore|verify",
        "SEARCH_ID": r"[a-z0-9][a-z0-9-]{0,63}",
        "SEARCH_TASK_ID": r"[a-z0-9][a-z0-9-]{0,63}",
    }
    if any(key not in patterns or not re.fullmatch(patterns[key], str(value)) for key, value in item.extra_env.items()):
        raise ValueError("unexpected task environment")
    if set(item.extra_env) & set(urls):
        raise ValueError("overlapping task environment")
    for url in urls.values():
        public_endpoint(url)
    env = [{"name": key, "value": str(value)} for key, value in {**urls, **item.extra_env}.items()]
    if len(json.dumps(env).encode()) >= 32768:
        raise ValueError("AX Task env exceeds the 32 KB limit")
    return {
        "apiVersion": "ax.io/v1alpha1",
        "kind": "Task",
        "metadata": {"name": name, "atespace": atespace},
        "spec": {"image": workload.image, "env": env, "command": list(item.command)},
    }


def write_json(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True) + "\n")
    temporary.replace(path)


def schedule(pending, lanes, out, execute, complete, *, fallbacks=(), overflow=True, progress=None):
    """The sole progress writer; callbacks carry workload-specific records, never transport."""
    if sum(lane in {"ax", "kind"} for lane in lanes) > 2 or lanes.count("docker") > 1:
        raise ValueError("at most two AX lanes and one VM lane")
    pending, fallbacks = deque(pending), deque(fallbacks)
    progress = progress if progress is not None else {"pins_done": 0, "pins_total": len(pending) + len(fallbacks)}
    progress["lanes"] = dict(Counter(lanes))
    active = {}
    failures = False

    def persist():
        progress.update(pins_in_flight=len(active), active_lanes=dict(Counter(lane for _, lane in active.values())))
        if any(lane in {"ax", "kind"} for lane in lanes):
            progress["fallbacks_pending"] = len(fallbacks)
        write_json(out / "progress.json", progress)

    with ThreadPoolExecutor(max_workers=len(lanes)) as pool:

        def launch(lane):
            if (out / "STOP").exists():
                return
            if lane == "docker" and fallbacks:
                item, previous = fallbacks.popleft()
            elif pending and (lane != "docker" or overflow):
                item, previous = pending.popleft(), None
            else:
                return
            active[pool.submit(execute, item, lane, previous)] = item, lane

        for lane in lanes:
            launch(lane)
        persist()
        try:
            while active:
                finished, _ = wait(active, return_when=FIRST_COMPLETED)
                # Resolve ALL completed futures before launching; cleanup exceptions stop launches.
                results = [(active.pop(future), future.result()) for future in finished]
                for (item, lane), result in results:
                    failed, fallback = complete(item, lane, result, progress)
                    if fallback is not None:
                        fallbacks.append((item, fallback))
                    else:
                        failures |= failed
                        progress["pins_done"] += 1
                for lane, count in (Counter(lanes) - Counter(lane for _, lane in active.values())).items():
                    for _ in range(count):
                        launch(lane)
                persist()
        finally:
            persist()
    return failures


def dispatch(items, workload, out, executors, *, lanes=("ax", "ax", "docker"), overflow=True, max_attempts=2):
    """Digest checkpoints, one instrument rerun, sandbox retry, priority VM fallback."""
    if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 2:
        raise ValueError("batch attempts must be one or two")
    out.mkdir(parents=True, exist_ok=True)
    pending, fallbacks = [], []

    def path(item):
        return out / (hashlib.sha256(item.id.encode()).hexdigest() + ".json")

    for item in items:
        previous = json.loads(path(item).read_text()) if path(item).exists() else {}
        if previous.get("input_digest") == item.input_digest:
            if previous.get("fallback_pending"):
                fallbacks.append((item, previous))
                continue
            if previous.get("done"):
                continue
        pending.append(item)

    def execute(item, lane, previous):
        output = out / hashlib.sha256(item.id.encode()).hexdigest()
        output.mkdir(exist_ok=True)
        attempts = []
        for attempt in range(max_attempts):
            attempt_output = output / ("attempt-" + uuid.uuid4().hex)
            attempt_output.mkdir()
            record = executors[lane](item, attempt_output, attempt)
            for artifact in attempt_output.iterdir():
                if artifact.is_file():
                    shutil.copyfile(artifact, output / artifact.name)
            attempts.append(
                {
                    "lane": lane,
                    "status": record.get("status"),
                    "attempt": attempt,
                    "transport": record.get("ax_attempts", []),
                    "docker_errors": record.get("docker_errors", []),
                }
            )
            if record.get("status") not in {"sandbox_failure", "instrument_failure"}:
                break
        return {**record, "attempts": (previous or {}).get("attempts", []) + attempts, "input_digest": item.input_digest, "done": True}

    def complete(item, lane, record, progress):
        fallback = lane in {"ax", "kind"} and record.get("status") in {"sandbox_failure", "oom"} and "docker" in lanes
        record["fallback_pending"] = fallback
        write_json(path(item), record)
        progress["last_item"] = hashlib.sha256(item.id.encode()).hexdigest()
        return record.get("status") not in {"ok", "unanalysable", "quick_only", "engine_covered"}, record if fallback else None

    return schedule(pending, lanes, out, execute, complete, fallbacks=fallbacks, overflow=overflow)


def docker_diagnostic(text):
    """Bound diagnostics and remove bearer URLs, environment secrets and assignments."""
    text = str(text or "")
    for key, value in os.environ.items():
        if len(value) >= 4 and any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "KEY")):
            text = text.replace(value, "[redacted]")
    text = re.sub(r"https?://[^\s\"']+", "[redacted-url]", text)
    text = re.sub(
        r"(?i)(authorization|bearer|password|token|secret|signature|credential|[\w-]*key)\s*[:= ]\s*[^\s,;]+", r"\1=[redacted]", text
    )
    return "\n".join(text.splitlines()[-10:])[-4000:]


class DockerLane(AXLane):
    """VM lane uses the same presigned-object protocol and pinned replay image."""

    def __init__(self, *args, runner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or subprocess.run
        self._prepared = False

    def __call__(self, item, output, attempt):
        self._diagnostics = []
        try:
            if not self._prepared:
                self._prepare_image()
                self._prepared = True
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            if not self._diagnostics:
                self._diagnostics.append({"step": "preflight", "exit_code": None, "stderr": docker_diagnostic(str(exc))})
            record = {"status": "instrument_failure", "docker_errors": self._diagnostics}
            write_json(output / "docker-error.json", record)
            return record
        try:
            record = super().__call__(item, output, attempt)
        finally:
            if self._diagnostics:
                write_json(output / "docker-error.json", {"docker_errors": self._diagnostics})
        if self._diagnostics:
            record["docker_errors"] = self._diagnostics
        return record

    def _run_docker(self, command, timeout):
        try:
            done = self.runner(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            self._diagnostics.append(
                {"step": command[1], "exit_code": None, "stderr": docker_diagnostic(getattr(exc, "stderr", "") or type(exc).__name__)}
            )
            raise
        if done.returncode:
            self._diagnostics.append({"step": command[1], "exit_code": done.returncode, "stderr": docker_diagnostic(done.stderr)})
            raise ValueError(f"docker {command[1]} failed (exit {done.returncode})")
        return done

    def _prepare_image(self):
        # Docker's data root, not the coordinator checkout, is where layers consume space.
        root = self._run_docker(["docker", "info", "--format", "{{.DockerRootDir}}"], 30).stdout.strip()
        size = getattr(self.args, "docker_image_bytes", None)
        if not isinstance(size, int) or size <= 0:
            raise ValueError("set --docker-image-bytes to the unpacked image size upper bound before pulling")
        free = self.runner(["df", "-B1", "--output=avail", root], capture_output=True, text=True, timeout=30)
        if free.returncode:
            raise ValueError("cannot check free space on Docker data root")
        available = int(free.stdout.splitlines()[-1].strip())
        required = size + 1024**3
        if available < required:
            raise ValueError(f"refusing Docker pull: free bytes {available} below image + 1 GiB ({required})")
        self._run_docker(["docker", "pull", self.workload.image], 900)

    def _execute_attempt(self, item, output, attempt, attempts):
        # Reuse all object/validation/cleanup logic, replacing only the task runner.
        import copy

        lane = copy.copy(self)
        lane.ax = lane._docker_command
        lane._docker_name = None
        return AXLane._execute_attempt(lane, item, output, attempt, attempts)

    def _docker_command(self, *args, manifest=None, timeout=30):
        if args[0] == "apply":
            self._docker_name = manifest["metadata"]["name"]
            self._docker_created = True  # Even a failed run can leave a created container.
            command = [
                "docker",
                "run",
                "-d",
                "--runtime",
                "runc",
                "--pull",
                "never",
                "--name",
                self._docker_name,
                "--entrypoint",
                manifest["spec"]["command"][0],
            ]
            for env in manifest["spec"]["env"]:
                command += ["-e", env["name"] + "=" + env["value"]]
            command += [manifest["spec"]["image"], *manifest["spec"]["command"][1:]]
            if "openultrasast.search.executor" not in manifest["spec"]["command"]:
                command += ["--heap-profile", "vm"]
        elif args[0] == "get":
            command = ["docker", "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", self._docker_name]
        else:
            if not getattr(self, "_docker_created", False):
                return subprocess.CompletedProcess([], 0, "", "")
            command = ["docker", "rm", "-f", self._docker_name or args[2]]
        try:
            done = self._run_docker(command, timeout)
        except ValueError:
            if args[0] == "delete" and "No such container" in self._diagnostics[-1]["stderr"]:
                self._diagnostics.pop()
                return subprocess.CompletedProcess(command, 0, "", "")
            raise
        if args[0] == "apply":
            self._docker_created = True
        if args[0] == "get":
            phase = "Running" if done.stdout.startswith("true") else "Failed"
            if phase == "Failed":
                logs = self._run_docker(["docker", "logs", "--tail", "10", self._docker_name], timeout)
                self._diagnostics.append(
                    {"step": "container", "exit_code": int(done.stdout.split()[-1]), "stderr": docker_diagnostic(logs.stderr)}
                )
            done.stdout = json.dumps({"metadata": {"name": self._docker_name}, "status": {"phase": phase}})
        return done


class SearchExecutorTask:
    """Host-owned executor lifecycle using the shared AX/presigning transport.

    Supply a bounded tar archive of the checkout. The brain receives only the
    command PUT/result GET pair; the task receives their opposite permissions.
    Closing the context deletes the task even after an uncertain command.
    """

    def __init__(self, lane, checkout_archive, *, deadline=900):
        if not 0 < deadline <= 3600 or len(checkout_archive) > 128 * 1024**2:
            raise ValueError("executor task input limit")
        if isinstance(lane, DockerLane):
            import copy

            lane = copy.copy(lane)
            lane._diagnostics = []
            lane.ax = lane._docker_command
        self.lane, self.archive, self.deadline = lane, checkout_archive, deadline
        token = uuid.uuid4().hex[:20]
        self.name = "ousast-engine-search-exec-" + token
        self.keys = [f"engine-queue/search-exec/{token}/{name}" for name in ("repo.tar", "command.json", "result.json", "prepared.tar.gz")]
        self.submitted = False
        self.slot = False

    def __enter__(self):
        from openultrasast.search.executor import ObjectStoreExecutor

        self.end = time.monotonic() + self.deadline
        if not isinstance(self.lane, DockerLane):
            if not AX_SLOTS.acquire(timeout=self.deadline):
                raise CapacityDeadline
            self.slot = True
        expires = timedelta(seconds=self.deadline + 600)
        store = self.lane.store
        try:
            store._put(self.keys[0], self.archive)
            urls = {
                "REPO_URL": store.presign_get(self.keys[0], expires),
                "COMMAND_GET_URL": store.presign_get(self.keys[1], expires),
                "EXECUTOR_RESULT_PUT_URL": store.presign_put(self.keys[2], expires),
                "PREPARED_PUT_URL": store.presign_put(self.keys[3], expires),
            }
            command_put = store.presign_put(self.keys[1], expires)
            result_get = store.presign_get(self.keys[2], expires)
            if any(public_endpoint(url) != self.lane.host for url in [*urls.values(), command_put, result_get]):
                raise EgressError("executor presign hostname must match store egress policy")
            work = Workload(self.lane.workload.image, frozenset(urls), self.deadline, None)
            item = Item(
                self.name,
                {},
                "result.json",
                (
                    "python3",
                    "-m",
                    "openultrasast.search.executor",
                    "--repo",
                    "/workspace/checkout",
                    "--task-boundary",
                    "--deadline",
                    str(self.deadline),
                ),
                {},
                "",
            )
            document = manifest(self.name, work, item, urls, self.lane.args.atespace)
            self.submitted = True
            try:
                apply_when_available(self.lane, document, self.end)
            except CapacityDeadline:
                self.submitted = False
                raise
            self.client = ObjectStoreExecutor(command_put, result_get)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def prepare(self, spec):
        """Return the executor-built single verifier input, checking its digest."""
        remaining = min(300, self.end - time.monotonic())
        result = self.client.submit("prepare_verification", spec, timeout_seconds=remaining)
        if result.get("status") != "ok":
            raise ValueError(result.get("reason", "could_not_build"))
        stored = bounded_read(lambda: self.lane.store._get(self.keys[3]), self.end - time.monotonic())
        if stored is None or hashlib.sha256(stored[0]).hexdigest() != result.get("sha256"):
            raise ValueError("executor archive missing or digest mismatch")
        return stored[0]

    def __exit__(self, *exc):
        errors = []
        if self.submitted:
            try:
                self.lane.ax("delete", "task", self.name)
            except Exception as error:
                errors.append(type(error).__name__)
        for key in self.keys:
            try:
                self.lane.store._delete(key)
            except Exception as error:
                errors.append(type(error).__name__)
        if self.slot and not errors:
            AX_SLOTS.release()
            self.slot = False
        if errors:
            raise RuntimeError("executor cleanup failed: " + ", ".join(errors))
