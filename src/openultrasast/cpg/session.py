"""A transaction-owned Joern interpreter session on loopback (release milestone M2).

Measured on this project: JVM startup, not analysis, is what a push scan spends its time on.
Each disposable ``joern --script`` invocation costs 13 to 23 seconds while the work itself takes
under a second, and one session starts in about 13 seconds and then answers in well under one.

What this module does NOT do is decide anything. It is a transport. Every answer it returns is
the same payload the disposable path would have produced, or nothing at all, and the caller keeps
its existing fresh-build and disposable-query paths as the default and as the fallback.

Three properties are load-bearing, and each exists because its absence has already produced a
wrong answer somewhere in this project:

* **An HTTP status is not an answer.** The lifecycle probe's first attempt received
  ``success=true`` with an empty body because the payload went to the server's own log, and a
  census of nothing would have been read as a census. So every request writes its output to a
  fresh private file under a nonce, and the nonce is verified before the answer is accepted.
* **A poisoned session answers nothing.** A session that crashed, timed out or returned an
  unparseable body is marked failed, and every later request on it returns ``None`` rather than
  an answer from an unknown state.
* **The process group dies, not just the launcher.** ``joern`` is a shell script that starts a
  JVM. Killing the script leaves the JVM holding its heap; this project has already run a machine
  out of memory that way. Cancellation signals the group and waits inside the allowance.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openultrasast.model.contracts import ExecutionBudget

logger = logging.getLogger(__name__)

STARTUP_PROBE_SECONDS = 5.0
STARTUP_POLL_SECONDS = 0.25


def _free_port() -> int:
    """Let the OS choose, so concurrent transactions cannot collide on a fixed port."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class SessionAnswer:
    """One verified answer: the stdout the evaluated code produced, and what it cost."""

    stdout: str
    seconds: float


@dataclass
class EngineSession:
    """One Joern server owned by one transaction. Not reusable across transactions."""

    scratch: Path
    budget: ExecutionBudget
    env: dict[str, str]
    joern: str = "joern"
    startup_timeout_seconds: float = 180.0
    # Startup measured 9 to 13 seconds. Waiting for it out of the transaction's own budget is only
    # worth doing when enough budget survives to run the work the session exists to serve, and the
    # wait itself must be bounded by an allowance rather than by the whole deadline. Without both,
    # a session that cannot start in time consumes every second that was left and the fallback runs
    # with nothing: measured as a 25.3 s "build" of which only 4.5 s was the frontend.
    startup_allowance_seconds: float = 20.0
    work_reserve_seconds: float = 10.0
    output_observer: Callable[[str], bool] | None = None
    failure: str = ""
    startup_seconds: float = 0.0
    loaded_graph: str = ""
    requests: int = 0
    # What the engine printed for the most recent request. The server answers `success` even for a
    # compile error and puts the diagnostic here, so discarding it leaves a missing receipt with no
    # explanation and nothing to debug. Kept for exactly that reason.
    last_body: str = ""
    _process: subprocess.Popen[str] | None = field(default=None, init=False, repr=False)
    _port: int = field(default=0, init=False, repr=False)
    _log: Any = field(default=None, init=False, repr=False)

    @property
    def alive(self) -> bool:
        return not self.failure and self._process is not None and self._process.poll() is None

    def log_tail(self, limit: int = 2000) -> str:
        """The end of the server's own log, which is where a crash or an OOM kill is recorded."""
        try:
            data = (self.scratch / "session.log").read_bytes()
        except OSError:
            return ""
        return data[-limit:].decode("utf-8", "replace")

    def exit_code(self) -> int | None:
        return self._process.poll() if self._process is not None else None

    def _poison(self, reason: str) -> None:
        if not self.failure:
            self.failure = reason
            logger.warning("engine session poisoned: %s", reason)

    def _remaining(self, limit: float) -> float:
        return min(limit, self.budget.deadline_monotonic - time.monotonic())

    def start(self) -> bool:
        """Launch on loopback with an OS-chosen port. No published port, no network exposure."""
        if self._process is not None:
            return self.alive
        if self._remaining(self.startup_timeout_seconds) <= 0:
            self._poison("deadline_exhausted")
            return False
        available = self.budget.deadline_monotonic - time.monotonic()
        if available < self.startup_allowance_seconds + self.work_reserve_seconds:
            # Refuse rather than spend the caller's remaining budget discovering this.
            self._poison("session_budget_insufficient")
            return False
        self.scratch.mkdir(parents=True, exist_ok=True)
        self._port = _free_port()
        started = time.monotonic()
        try:
            self._log = (self.scratch / "session.log").open("w")
            self._process = subprocess.Popen(  # noqa: S603 -- fixed argument array
                [self.joern, "--server", "--server-host", "127.0.0.1", "--server-port", str(self._port)],
                cwd=str(self.scratch),
                env=self.env,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            self._poison("session_launch_failed:" + type(error).__name__)
            return False
        while True:
            if self._process.poll() is not None:
                self._poison("session_exited_during_startup")
                return False
            allowance = min(self.startup_timeout_seconds, self.startup_allowance_seconds)
            remaining = self._remaining(allowance - (time.monotonic() - started))
            if remaining <= 0:
                self._poison("session_startup_timeout")
                return False
            if self._post("1", timeout=min(STARTUP_PROBE_SECONDS, remaining)) is not None:
                self.startup_seconds = time.monotonic() - started
                return True
            time.sleep(STARTUP_POLL_SECONDS)

    def _post(self, code: str, *, timeout: float) -> dict[str, object] | None:
        """One synchronous request. A transport failure is not an answer."""
        if timeout <= 0:
            return None
        payload = json.dumps({"query": code}).encode()
        call = urllib.request.Request(
            f"http://127.0.0.1:{self._port}/query-sync",  # loopback: the Joern server this process started
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(call, timeout=timeout) as response:  # noqa: S310 -- fixed loopback URL
                body = json.load(response)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            # A transport failure usually means the server is gone, and the only account of why is
            # in its own log. Without this the caller sees `session_request_failed` and nothing else,
            # which is indistinguishable from a timeout, a crash and an out-of-memory kill.
            self.last_body = f"{type(error).__name__}: {error}\n{self.log_tail()}"
            return None
        if not isinstance(body, dict):
            self.last_body = ""
            return None
        self.last_body = str(body.get("stdout", ""))
        return body

    def evaluate(self, code: str, *, timeout: float) -> SessionAnswer | None:
        """Evaluate Scala in the session and return the output it printed, verified by receipt.

        The evaluated code's console output is redirected into a private file whose first line is
        a nonce this call generated. An answer is accepted only when that nonce comes back, so an
        empty body, a cached file or another request's output cannot be read as this answer.
        """
        if not self.alive:
            self._poison(self.failure or "session_not_running")
            return None
        remaining = self._remaining(timeout)
        if remaining <= 0:
            self._poison("deadline_exhausted")
            return None
        nonce = uuid.uuid4().hex
        target = self.scratch / f"answer-{nonce}.txt"
        wrapped = _redirected(code, target, nonce)
        started = time.monotonic()
        if self.output_observer is None:
            body = self._post(wrapped, timeout=remaining)
        else:
            # Only HTTP runs in the helper; observation and cancellation stay on the caller.
            done = threading.Event()
            response: list[dict[str, object] | None] = []

            def post() -> None:
                try:
                    response.append(self._post(wrapped, timeout=remaining))
                finally:
                    done.set()

            threading.Thread(target=post, daemon=True).start()
            while True:
                finished = done.wait(0.05)
                try:
                    first, _, output = target.read_text(errors="replace").partition("\n")
                except OSError:
                    first, output = "", ""
                if not self.output_observer(output if first.strip() == nonce else ""):
                    self._poison("session_observer_cancelled")
                    self.close()
                    target.unlink(missing_ok=True)
                    return None
                if finished:
                    break
            body = response[0] if response else None
        seconds = time.monotonic() - started
        self.requests += 1
        if body is None:
            self._poison("session_request_failed")
            return None
        if body.get("success") not in (True, "true"):
            self._poison("session_request_unsuccessful")
            return None
        try:
            written = target.read_text()
        except OSError:
            self._poison("session_answer_missing")
            return None
        finally:
            target.unlink(missing_ok=True)
        first, _, rest = written.partition("\n")
        if first.strip() != nonce:
            # A body that does not carry this call's receipt is somebody else's output, or none.
            self._poison("session_receipt_mismatch")
            return None
        return SessionAnswer(rest, seconds)

    def define(self, code: str, *, timeout: float) -> str | None:
        """Send code that must reach the REPL's top level, such as a definition.

        A definition cannot be nested inside the receipt wrapper: `@main` and top-level
        declarations are not block expressions, and wrapping them fails to compile. So this path
        has no receipt, and its return value is therefore NOT proof that anything was defined.
        The server answers `success` even for a compile error and puts the diagnostic in its body,
        which is exactly why every real answer goes through `evaluate` and its receipt instead.
        Returns the body the engine printed, or None when the request itself failed.
        """
        if not self.alive:
            self._poison(self.failure or "session_not_running")
            return None
        remaining = self._remaining(timeout)
        if remaining <= 0:
            self._poison("deadline_exhausted")
            return None
        body = self._post(code, timeout=remaining)
        self.requests += 1
        if body is None:
            self._poison("session_request_failed")
            return None
        return str(body.get("stdout", ""))

    def load(self, graph: Path, *, timeout: float) -> bool:
        """Load one graph, recording which is resident so a stale `cpg` cannot answer.

        Loading a second graph replaces the first. The recorded identity is what lets the caller
        refuse to answer a question about a graph that is not the one loaded.
        """
        answer = self.evaluate(f'importCpg({json.dumps(str(graph))}); "loaded"', timeout=timeout)
        if answer is None:
            self.loaded_graph = ""
            return False
        self.loaded_graph = str(graph)
        return True

    def close(self) -> None:
        """Kill the group and reap it inside the cancellation allowance."""
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            end = time.monotonic() + self.budget.cancellation_allowance_seconds
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                self._poison("session_cleanup_incomplete")
            try:
                process.wait(timeout=max(0.0, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                self._poison("session_cleanup_incomplete")
        for stream in (process.stdout if process else None, process.stderr if process else None):
            if stream is not None:
                stream.close()
        if self._log is not None:
            self._log.close()
            self._log = None

    def __enter__(self) -> EngineSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _redirected(code: str, target: Path, nonce: str) -> str:
    """Wrap `code` so its console output lands in `target` behind this call's receipt line.

    The receipt is written before the code runs, so a body that never executed leaves a file
    whose payload is empty rather than a file that does not exist: the two are distinguishable.
    """
    path = json.dumps(str(target))
    return (
        "{ val __ousastPath = java.nio.file.Path.of(" + path + "); "
        "java.nio.file.Files.writeString(__ousastPath, " + json.dumps(nonce + "\n") + "); "
        "val __ousastOut = new java.io.FileOutputStream(" + path + ", true); "
        # `scala.Console`, fully qualified: the Joern REPL shadows `Console` with
        # `io.joern.console.Console`, which has no `withOut`, and the resulting compile error
        # arrives as a successful response with an empty receipt.
        "try { scala.Console.withOut(new java.io.PrintStream(__ousastOut, true)) { " + code + " } } "
        'finally { __ousastOut.close() }; "ok" }'
    )
