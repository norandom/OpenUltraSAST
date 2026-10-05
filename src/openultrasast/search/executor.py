"""Key-free repository executor and sequential presigned-object mailbox protocol.

The in-process implementation is a test adapter. Production brains use
ObjectStoreExecutor and an independently dispatched executor task.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import os
import resource
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..sandbox import SandboxJob
from . import _sandbox, task_storage

MAX_COMMAND_BYTES = 65536
MAX_RESULT_BYTES = 65536
SAFE_ENV = {"PATH": "/venv/bin:/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "JAVA_HOME": "/opt/java/openjdk"}


def clean_environment(_source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Explicit allowlist; even PATH is owned by the executor."""
    return {**SAFE_ENV, **task_storage.environment()}


@dataclass(frozen=True)
class Command:
    seq: int
    name: str
    args: dict[str, Any]
    timeout_seconds: float = 30
    limits: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> bytes:
        if type(self.seq) is not int or self.seq < 1 or self.seq > 100000:
            raise ValueError("invalid sequence")
        if self.name not in {"list_files", "read_file", "grep", "run", "stop", "prepare_verification"} or not isinstance(self.args, dict):
            raise ValueError("invalid command")
        if type(self.timeout_seconds) not in (float, int) or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("invalid timeout")
        if not isinstance(self.limits, dict) or self.limits.keys() - {
            "result_bytes",
            "memory_bytes",
            "disk_bytes",
            "task_wall_seconds",
            "max_call_usd",
        }:
            raise ValueError("invalid limits")
        for name in ("result_bytes", "memory_bytes", "disk_bytes"):
            if name in self.limits and (type(self.limits[name]) is not int or self.limits[name] < 512):
                raise ValueError("invalid resource limit")
        data = json.dumps(asdict(self), sort_keys=True, allow_nan=False).encode()
        if len(data) > MAX_COMMAND_BYTES:
            raise ValueError("command too large")
        return data


def _bounded(result: dict[str, Any], maximum: int) -> dict[str, Any]:
    result = copy.deepcopy(result)
    if len(json.dumps(result).encode()) <= maximum:
        return result
    result["truncated"] = True
    # Preserve structured evidence when possible; otherwise make loss explicit.
    while len(json.dumps(result).encode()) > maximum:
        fields = [(len(v), k) for k, v in result.items() if isinstance(v, (str, list)) and k not in {"status", "error", "isolation_mode"}]
        if not fields or max(fields)[0] == 0:
            return {"seq": result["seq"], "error": "result_limit", "truncated": True}
        _, key = max(fields)
        keep = len(result[key]) // 2
        result[key] = result[key][-keep:] if key == "stderr" and keep else result[key][:keep]
    return result


class InProcessExecutor:
    """Test adapter; task_boundary is only enabled by the key-free task entrypoint."""

    def __init__(self, repo: Path, demo: Path | None = None, *, task_boundary: bool = False) -> None:
        self.repo = repo.resolve()
        if not self.repo.is_dir():
            raise ValueError("checkout unavailable")
        self.demo = demo
        self.task_boundary = task_boundary
        self.seq = 0
        self.stopped = False
        self.last_digest = ""
        self.last_result: dict[str, Any] = {}
        self.isolation_mode = "unprobed"
        self.prepared_put_url: str | None = None

    def submit(
        self, name: str, args: dict[str, Any], *, timeout_seconds: float = 30, limits: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        result = self.execute(Command(self.seq + 1, name, args, timeout_seconds, limits or {}))
        if result.get("error") in {"ValueError", "KeyError", "TypeError", "FileNotFoundError", "OSError"}:
            raise ValueError(result.get("reason", "repository command rejected"))
        return result

    def execute(self, command: Command) -> dict[str, Any]:
        digest = hashlib.sha256(command.validate()).hexdigest()
        if command.seq == self.seq:
            if digest != self.last_digest:
                raise ValueError("retry changed command")
            return copy.deepcopy(self.last_result)
        if self.stopped:
            raise ValueError("executor stopped")
        if command.seq != self.seq + 1:
            raise ValueError("out of order sequence")
        started = time.monotonic()
        self.deadline = started + command.timeout_seconds
        self.phase = "run"
        try:
            result = self._execute(command)
        except task_storage.ScratchLimit as exc:
            self.stopped = True
            result = {
                "status": "could_not_build",
                "reason": task_storage.exception_reason(exc, private=(str(self.repo), self.repo.name)),
                "phase": "scratch guard",
                "exit_code": None,
                "stderr": "",
                "stopped": True,
            }
        except (ValueError, OSError, KeyError, TypeError, TimeoutError, subprocess.SubprocessError) as exc:
            result = {
                "error": type(exc).__name__,
                "reason": task_storage.exception_reason(exc, private=(str(self.repo), self.repo.name)),
                "phase": self.phase,
                "exit_code": None,
                "stderr": "",
                "timed_out": isinstance(exc, TimeoutError),
            }
        result["wall_seconds"] = time.monotonic() - started
        result = _bounded({"seq": command.seq, **result}, min(MAX_RESULT_BYTES, command.limits.get("result_bytes", MAX_RESULT_BYTES)))
        self.seq, self.last_digest, self.last_result = command.seq, digest, copy.deepcopy(result)
        return result

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("executor deadline")
        return remaining

    def _path(self, value: str) -> Path:
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError("invalid path")
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
            raise ValueError("path escapes checkout")
        result = self.repo / path
        if any(p.is_symlink() for p in [result, *result.parents] if p.is_relative_to(self.repo)):
            raise ValueError("symlink refused")
        if not result.resolve().is_relative_to(self.repo):
            raise ValueError("path escapes checkout")
        return result

    def _files(self) -> Iterator[Path]:
        for parent, directories, names in os.walk(self.repo, followlinks=False):
            self._remaining()
            directories[:] = sorted(d for d in directories if d != ".git" and not (Path(parent) / d).is_symlink())
            for name in sorted(names):
                self._remaining()
                path = Path(parent) / name
                if stat.S_ISREG(path.lstat().st_mode):
                    yield path

    def _read(self, path: Path) -> bytes:
        # O_NOFOLLOW closes the final-component symlink race; repository programs
        # are terminated before the next command so there are no concurrent writers.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("regular file required")
            return stream.read(1024 * 1024)

    def _execute(self, command: Command) -> dict[str, Any]:
        name, args = command.name, command.args
        if self.task_boundary:
            self.phase = "scratch guard"
            task_storage.check(task_storage.WORKSPACE if task_storage.WORKSPACE.is_dir() else self.repo)
            self.phase = "run"
        if name == "prepare_verification":
            return self._prepare_verification(args)
        if name == "stop":
            self.stopped = True
            return {"stopped": True}
        if name == "list_files":
            files = []
            for path in self._files():
                files.append(str(path.relative_to(self.repo)))
                if len(files) == 1000:
                    break
            return {"files": files}
        if name == "read_file":
            path = self._path(args["path"])
            data = self._read(path)
            start = max(1, int(args.get("start", 1)))
            lines = min(400, max(1, int(args.get("lines", 400))))
            text = "\n".join(data.decode(errors="replace").splitlines()[start - 1 : start - 1 + lines])
            return {"text": text[:16384], "input_bytes": len(data), "truncated": len(text) > 16384 or path.stat().st_size > len(data)}
        if name == "grep":
            pattern = args["pattern"]
            if not isinstance(pattern, str) or not pattern:
                raise ValueError("nonempty pattern required")
            matches = []
            for index, path in enumerate(self._files()):
                if index >= 10000:
                    break
                for number, line in enumerate(self._read(path).decode(errors="replace").splitlines(), 1):
                    if pattern in line:
                        matches.append({"path": str(path.relative_to(self.repo)), "line": number, "text": line[:200]})
                        if len(matches) == 200:
                            return {"matches": matches}
            return {"matches": matches}
        argv = args["command"]
        if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and "\0" not in v for v in argv):
            raise ValueError("command must be argv")
        timeout = min(self._remaining(), max(1, int(args.get("timeout_seconds", 30))))
        self.deadline = min(self.deadline, time.monotonic() + timeout)
        if self.task_boundary:
            self.isolation_mode = "task-boundary"
            return self._task_run(argv, timeout, command.limits)
        _sandbox.isolation_check(timeout_seconds=self._remaining())
        self.isolation_mode = _sandbox.isolation_mode()
        with tempfile.TemporaryDirectory(prefix="ousast-executor-") as directory:
            result = _sandbox.run(
                SandboxJob(
                    "",
                    tuple(argv),
                    self.repo,
                    {},
                    max(1, math.ceil(min(timeout, self._remaining()))),
                    max(1, command.limits.get("memory_bytes", 256 * 1024**2) // 1024**2),
                    128,
                ),
                scratch=Path(directory),
                mounts={"/demo": self.demo} if self.demo else {},
                scratch_bytes=command.limits.get("disk_bytes", task_storage.DEFAULT_SCRATCH_BYTES),
                wall_timeout_seconds=self._remaining(),
            )
        return {
            **(
                {
                    "phase": "timeout" if result.timed_out else "run",
                    "reason": "TimeoutError: command deadline" if result.timed_out else f"CommandFailure: exit code {result.exit_code}",
                }
                if result.timed_out or result.exit_code
                else {}
            ),
            "isolation_mode": self.isolation_mode,
            "exit_code": result.exit_code,
            "stdout": result.stdout[:16384],
            "stderr": task_storage.diagnostic(result.stderr, maximum=4000),
            "timed_out": result.timed_out,
            "truncated": len(result.stdout) > 16384 or len(result.stderr) > 16384,
        }

    def _task_run(self, argv: list[str], timeout: float, limits: dict[str, Any]) -> dict[str, Any]:
        process_limit = None
        try:
            uid = os.getuid()
            current = 0
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    status = (entry / "status").read_text()
                except FileNotFoundError:
                    continue
                fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                # The kernel's NPROC counter counts threads, not processes: a single IDE or agent
                # process with 60 threads uses 60 of the allowance.
                if int(fields["Uid"].split()[0]) == uid:
                    current += int(fields.get("Threads", "1").strip() or 1)
            process_limit = current + 256
        except (OSError, ValueError, IndexError, StopIteration):
            pass

        def constrain() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limits.get("disk_bytes", task_storage.DEFAULT_SCRATCH_BYTES),) * 2)
            # NPROC counts all processes of the real uid, so an absolute 128 blocks builds on busy hosts.
            if process_limit is not None:
                resource.setrlimit(resource.RLIMIT_NPROC, (process_limit,) * 2)
            resource.setrlimit(resource.RLIMIT_AS, (limits.get("memory_bytes", 256 * 1024**2),) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (math.ceil(timeout) + 1,) * 2)

        timeout = min(timeout, self._remaining())
        initial_bytes = self._tree_bytes()
        guard_root = task_storage.WORKSPACE if task_storage.WORKSPACE.is_dir() else self.repo
        peak_bytes = task_storage.check(guard_root)
        self.phase = "spawn"
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(
                argv, cwd=self.repo, env=clean_environment(), stdout=out, stderr=err, start_new_session=True, preexec_fn=constrain
            )
            self.phase = "run"
            timed_out = False
            disk_exceeded = False
            failure = None
            # Monitor the full disk-backed workspace, including package caches.
            # An unnamespaced child can still hardcode RAM-backed paths: this
            # guard is not a replacement for the operator's memory limit.
            try:
                while True:
                    peak_bytes = max(
                        peak_bytes,
                        task_storage.check(guard_root, additional_bytes=os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size),
                    )
                    if self._tree_bytes() - initial_bytes > limits.get("disk_bytes", task_storage.DEFAULT_SCRATCH_BYTES):
                        disk_exceeded = True
                        break
                    try:
                        proc.wait(timeout=min(0.05, self._remaining()))
                        peak_bytes = max(
                            peak_bytes,
                            task_storage.check(
                                guard_root, additional_bytes=os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size
                            ),
                        )
                        if self._tree_bytes() - initial_bytes > limits.get("disk_bytes", task_storage.DEFAULT_SCRATCH_BYTES):
                            disk_exceeded = True
                        break
                    except subprocess.TimeoutExpired:
                        self._remaining()
            except task_storage.ScratchLimit as exc:
                disk_exceeded = True
                failure = exc
                self.stopped = True
            except TimeoutError as exc:
                timed_out = True
                failure = exc
            except OSError as exc:
                self.phase = "scratch guard"
                failure = exc
            finally:
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            out.seek(0)
            err.seek(max(0, os.fstat(err.fileno()).st_size - 16384))
            stderr = task_storage.diagnostic(err.read().decode(errors="replace"), maximum=4000)
            phase = "scratch guard" if disk_exceeded else "timeout" if timed_out else self.phase
            if disk_exceeded:
                self.stopped = True
            failed = failure or (task_storage.ScratchLimit("scratch limit") if disk_exceeded else None)
            reason = (
                task_storage.exception_reason(failed)
                if failed
                else (f"CommandFailure: exit code {proc.returncode}" if proc.returncode else "")
            )
            return {
                **({"status": "could_not_build", "stopped": self.stopped} if disk_exceeded else {}),
                **({"reason": reason, "phase": phase} if reason else {}),
                **({"error": type(failure).__name__} if failure and not (timed_out or disk_exceeded) else {}),
                "isolation_mode": "task-boundary",
                "exit_code": proc.returncode,
                "timed_out": timed_out,
                "disk_limit_exceeded": disk_exceeded,
                "aggregate_disk_isolation": "outer-task-quota-required",
                "scratch_peak_bytes": peak_bytes,
                "stdout_bytes": os.fstat(out.fileno()).st_size,
                "stderr_bytes": os.fstat(err.fileno()).st_size,
                "stdout": out.read(16384).decode(errors="replace"),
                "stderr": stderr,
                "truncated": os.fstat(out.fileno()).st_size > 16384 or os.fstat(err.fileno()).st_size > 16384,
            }

    def _prepare_verification(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Build and export through the host-scoped output URL, never a model URL."""
        import shutil

        from .demo import BUILD_RECIPES, validate_demo
        from .verify import _tree
        from .verify_task import pack_checkout, validate_spec

        if not self.task_boundary or not self.prepared_put_url:
            raise ValueError("preparation requires an executor task output")
        spec = copy.deepcopy(spec)
        validate_demo(spec["demo"])
        recipe = spec["demo"]["build"]
        spec["demo"]["build"] = {"recipe": "none", "arguments": []}
        validate_spec(spec)
        with tempfile.TemporaryDirectory(prefix="ousast-built-") as directory:
            bundle = Path(directory)
            products = bundle / "products"
            products.mkdir()
            if recipe["recipe"] != "none":
                path = self._path(recipe["arguments"][0])
                argv = [
                    arg.replace("/scratch", str(products))
                    for arg in BUILD_RECIPES[recipe["recipe"]]
                    if arg not in {"--offline", "--no-index"}
                ]
                argv.append(str(path))
                if recipe["recipe"] == "maven":
                    argv += ["package", "-DskipTests"]
                elif recipe["recipe"] == "gradle":
                    # The project pins its Gradle version through its wrapper.
                    # Invoke with sh because checkout archives may lose execute bits.
                    wrapper = self._path(str(path.relative_to(self.repo) / "gradlew"))
                    argv = ["/bin/sh", str(wrapper), "--no-daemon", "--project-dir", str(path), "assemble"]
                built = self._task_run(argv, self._remaining(), {"disk_bytes": task_storage.DEFAULT_SCRATCH_BYTES})
                if built.get("disk_limit_exceeded") or built["exit_code"] or built["timed_out"]:
                    return {**built, "status": "could_not_build"}
            # Validate internal generated links before materializing them as
            # regular archive members. No host/external files may be exported.
            _tree(self.repo, generated_links=True)
            _tree(products, generated_links=True)
            shutil.copytree(self.repo, bundle / "checkout", symlinks=False)
            materialized = bundle / "materialized"
            shutil.copytree(products, materialized, symlinks=False)
            shutil.rmtree(products)
            materialized.rename(products)
            (bundle / "spec.json").write_text(json.dumps(spec))
            task_storage.check(task_storage.WORKSPACE if task_storage.WORKSPACE.is_dir() else bundle)
            blob = pack_checkout(bundle)
            self.phase = "result upload"
            URLTransport().put(self.prepared_put_url, blob, self._remaining())
            return {"status": "ok", "archive_bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}

    def _tree_bytes(self) -> int:
        total = 0
        for parent, directories, names in os.walk(self.repo, followlinks=False):
            self._remaining()
            directories[:] = [name for name in directories if not (Path(parent) / name).is_symlink()]
            for name in names:
                with suppress(OSError):
                    info = (Path(parent) / name).lstat()
                    if stat.S_ISREG(info.st_mode):
                        total += info.st_size
        return total


class Transport(Protocol):
    def get(self, url: str, timeout: float) -> bytes | None: ...

    def put(self, url: str, data: bytes, timeout: float) -> None: ...


class URLTransport:
    """Only presigned object URLs; redirects are refused to preserve their scope."""

    def __init__(self) -> None:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, url: str, timeout: float) -> bytes | None:
        try:
            with self.opener.open(url, timeout=timeout) as response:
                data = bytes(response.read(max(MAX_RESULT_BYTES, MAX_COMMAND_BYTES) + 1))
                if len(data) > max(MAX_RESULT_BYTES, MAX_COMMAND_BYTES):
                    raise ValueError("mailbox object too large")
                return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise OSError(f"object read failed: HTTP {exc.code}") from None

    def put(self, url: str, data: bytes, timeout: float) -> None:
        with self.opener.open(
            urllib.request.Request(url, data=data, method="PUT", headers={"Content-Type": "application/json"}), timeout=timeout
        ):
            pass


class ObjectStoreExecutor:
    def __init__(self, command_put_url: str, result_get_url: str, *, transport: Transport | None = None, poll_seconds: float = 0.2) -> None:
        for url in (command_put_url, result_get_url):
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                raise ValueError("HTTPS presigned URLs required")
        self.command_url, self.result_url = command_put_url, result_get_url
        self.transport = transport or URLTransport()
        self.poll_seconds = poll_seconds
        self.seq = 0
        self.uncertain = False
        self.isolation_mode = "remote-executor"

    def submit(
        self, name: str, args: dict[str, Any], *, timeout_seconds: float = 30, limits: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self.uncertain:
            raise RuntimeError("previous command outcome uncertain; discard executor task")
        command = Command(self.seq + 1, name, args, timeout_seconds, limits or {})
        payload = command.validate()
        end = time.monotonic() + timeout_seconds
        self.uncertain = True
        last_error = ""
        phase = "result upload"
        while time.monotonic() < end:
            try:
                # A lost PUT acknowledgement is retried with the exact same sequence.
                phase = "command upload"
                self.transport.put(self.command_url, payload, max(0.001, end - time.monotonic()))
                phase = "result read"
                raw = self.transport.get(self.result_url, max(0.001, end - time.monotonic()))
                if raw is not None:
                    if len(raw) > MAX_RESULT_BYTES:
                        raise ValueError("result too large")
                    result = json.loads(raw)
                    if not isinstance(result, dict) or type(result.get("seq")) is not int:
                        raise ValueError("invalid result envelope")
                    if result["seq"] > command.seq:
                        raise ValueError("future result sequence")
                    if result["seq"] == command.seq:
                        self.seq, self.uncertain = command.seq, False
                        self.isolation_mode = result.get("isolation_mode", self.isolation_mode)
                        return result
            except (OSError, TimeoutError) as exc:
                last_error = task_storage.exception_reason(exc)
            time.sleep(min(self.poll_seconds, max(0, end - time.monotonic())))
        raise TimeoutError(f"executor {phase} deadline; {last_error or 'no result received'}")


def serve(
    executor: InProcessExecutor,
    command_get_url: str,
    result_put_url: str,
    *,
    transport: Transport | None = None,
    deadline_seconds: float = 900,
    poll_seconds: float = 0.2,
) -> None:
    transport = transport or URLTransport()
    end = time.monotonic() + deadline_seconds
    while time.monotonic() < end:
        try:
            raw = transport.get(command_get_url, min(10, max(0.001, end - time.monotonic())))
            if raw is not None:
                if len(raw) > MAX_COMMAND_BYTES:
                    raise ValueError("command too large")
                command = Command(**json.loads(raw))
                if command.seq != executor.seq and command.timeout_seconds > end - time.monotonic():
                    raise TimeoutError("command exceeds task lifetime")
                result = executor.execute(command)
                transport.put(result_put_url, json.dumps(result).encode(), min(10, max(0.001, end - time.monotonic())))
                if result.get("stopped"):
                    return
        except (OSError, TimeoutError) as exc:
            if executor.last_result:
                executor.last_result["result_upload_reason"] = task_storage.exception_reason(exc)
                executor.last_result["result_upload_phase"] = "result upload"

        time.sleep(min(poll_seconds, max(0, end - time.monotonic())))
    raise TimeoutError("executor task deadline")


def unpack_checkout(data: bytes, root: Path) -> None:
    """Bounded regular-file archive only; no links, special files, or metadata."""
    if len(data) > 128 * 1024**2:
        raise ValueError("checkout archive too large")
    root.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        total = 0
        for index, member in enumerate(archive):
            path = Path(member.name)
            total += member.size
            if (
                index >= 100000
                or total > 256 * 1024**2
                or path.is_absolute()
                or ".." in path.parts
                or ".git" in path.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("unsafe checkout archive")
            destination = root / path
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("archive member is not a regular file")
                with source, destination.open("xb") as target:
                    while chunk := source.read(65536):
                        target.write(chunk)
                destination.chmod(0o755 if member.mode & 0o111 else 0o644)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--command-get-url")
    parser.add_argument("--result-put-url")
    parser.add_argument("--deadline", type=float, default=900)
    parser.add_argument("--task-boundary", action="store_true")
    args = parser.parse_args()
    command_url = args.command_get_url or os.environ.get("COMMAND_GET_URL")
    result_url = args.result_put_url or os.environ.get("EXECUTOR_RESULT_PUT_URL")
    repo_url = os.environ.get("REPO_URL")
    prepared_url = os.environ.get("PREPARED_PUT_URL")
    # Clearing Python's environment cannot remove initial /proc/self/environ.
    # Refuse a misconfigured task before any repository input is opened.
    inherited = sorted(
        key
        for key, value in os.environ.items()
        if value and any(word in key.upper() for word in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))
    )
    if inherited:
        # Names only, never values, so a misconfigured task can be diagnosed from the worker log.
        raise SystemExit("executor refuses inherited credentials: " + ", ".join(inherited))
    scratch_limit = task_storage.configure()
    os.environ.clear()
    os.environ.update(clean_environment())
    os.environ["OUSAST_SCRATCH_BYTES"] = str(scratch_limit)
    if not command_url or not result_url:
        raise SystemExit("executor requires presigned mailbox URLs")
    if repo_url:
        from .verify_task import download

        unpack_checkout(download(repo_url, 128 * 1024**2, readiness_budget=min(60, args.deadline)), args.repo)
    executor = InProcessExecutor(args.repo, task_boundary=args.task_boundary)
    executor.prepared_put_url = prepared_url
    serve(executor, command_url, result_url, deadline_seconds=args.deadline)


if __name__ == "__main__":
    main()
