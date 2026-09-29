"""ax's runner contract for a task container (ai-service-plane Requirement 4).

This module is ``/usr/local/bin/ax-task-runner`` in the runner image, PID 1 of the task container. ax hands it
the Task as YAML in ``AX_TASK_YAML`` and the bound Workspaces as a multi-document stream in ``AX_WORKSPACES_YAML``;
nothing else comes from the command line (Requirement 4.1). It serves ``/healthz``, ``/readyz`` and ax's two
metadata paths on port 80, ``/readyz`` answering 503 until every workspace is materialised (Requirement 4.2).
Workspaces are prepared on the first boot only: ``/workspace`` survives suspend and resume, the process tree does
not (ax docs/runner.md).

The command runs as a child process, ``python -m openultrasast.plane.tasks.<spec.command[0]> <spec.command[1:]>``,
in its own process group, with the first workspace as its working directory and ``AX_METADATA_URL`` pointing at
this server. ax has no artifact channel and never reports that a command finished, so after the child exits the
runner reads ``summary.json`` (a crash without one becomes ``failed`` with the exit code and the stderr tail),
posts the whole ``OUSAST_OUTPUT_DIR`` as a tar to ``OUSAST_ARTIFACT_URL`` -- that delivery is the task's
completion (Requirement 4.4); a failed one is reported ``failed``, never done -- and writes the completion marker
``<OUSAST_STATE_DIR>/<task>.done.json`` (``exit``, ``status``, ``delivered``). Then it keeps serving until SIGTERM,
as ax requires of PID 1. A boot that finds the marker never reruns the command (a resumed actor must not repeat
billed work); when the marker says the delivery failed, it retries the delivery alone. SIGTERM (ax's stop and
suspend) goes to the command's process group; after ``OUSAST_TERM_GRACE`` seconds the rest is killed and the
runner exits 0.

Environment the runner reads, all optional except the two ax variables:

    AX_TASK_YAML, AX_WORKSPACES_YAML   ax's contract
    AX_RUNNER_HTTP                     "0" disables the health server (unit tests only)
    AX_RUNNER_PORT                     port of the health server, default 80; "0" picks a free port
    AX_RUNNER_EXIT_AFTER_COMMAND       "1" exits after delivery with 0 done, 2 failed, 3 unfinished (unit tests only)
    AX_RUNNER_TASK_PACKAGE             package the command's module is looked up in (unit tests only)
    OUSAST_STATE_DIR                   completion markers, default ``/workspace/.ousast-state`` (the durable volume)
    OUSAST_TERM_GRACE                  seconds between SIGTERM and SIGKILL of the command's group, default 10
    OUSAST_CASE_CACHE                  a directory of git checkouts (``benchmarks/independent`` cache layout)
    OUSAST_GIT_PINS                    JSON ``{"<workspace>/<git name>": "<40-hex commit>"}`` from the reconciler
    OUSAST_ARTIFACT_URL, OUSAST_RUN    where to deliver, and the run name carried in ``X-Ousast-Run``
    OUSAST_DELIVERY_BACKOFF            seconds before the second delivery attempt, doubled per retry

The runner exports ``OUSAST_WORKSPACE_DIR`` (the first bound workspace) when the Task's env leaves it unset,
``AX_RUNNER_BOUND_PORT`` with the health server's port and ``AX_METADATA_URL``.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from openultrasast.plane.manifests import GitSource, ManifestError, Task, Workspace, parse_manifest

__all__ = [
    "DEFAULT_PORT",
    "DELIVERY_ATTEMPTS",
    "EXIT_BY_STATUS",
    "STATE_DIR",
    "TASK_PACKAGE",
    "Child",
    "DeliveryError",
    "HealthServer",
    "RunnerError",
    "build_tar",
    "deliver",
    "clone_destination",
    "find_cached_checkout",
    "load_pins",
    "load_task",
    "load_workspaces",
    "main",
    "materialise",
    "read_summary",
    "run_command",
    "start_health_server",
    "summary_after",
    "task_module",
    "write_summary",
]

DEFAULT_PORT = 80
DELIVERY_ATTEMPTS = 3
TASK_PACKAGE = "openultrasast.plane.tasks"
STATE_DIR = "/workspace/.ousast-state"
TERM_GRACE = 10.0  # ax's own runner: SIGTERM, ten seconds, SIGKILL
STDERR_TAIL_LINES = 40
EXIT_BY_STATUS = {"done": 0, "failed": 2, "unfinished": 3}
SUMMARY = "summary.json"
METADATA_PATHS = {"/metadata/v1alpha1/ax/task": "task", "/metadata/v1alpha1/ax/workspaces": "workspaces"}
DEFAULT_BRANCH = "main"  # ax internal/workspace/setup.go: defaultBranch
_PLACEHOLDER_NAMES = ("", "repo", "origin")  # setup.go: names that do not name a checkout directory
_SHA = re.compile(r"[0-9a-f]{40}")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

log = logging.getLogger("ousast.plane.runner")


class RunnerError(RuntimeError):
    """The runner itself cannot proceed (bad manifests, a workspace that cannot be materialised)."""


class DeliveryError(RuntimeError):
    """Every delivery attempt failed; the message names the last cause."""


# --- manifests ---------------------------------------------------------------------------------------------------

# Fields ax's API server sets on what it hands the runner (ax.proto: ObjectMeta.creation_timestamp, Task.status).
# They are not authoring fields, so they are dropped before the strict schema sees the document; any other
# unknown field still fails.
_SERVER_META = ("creationTimestamp", "creation_timestamp")


def _without_server_fields(document: object) -> object:
    if not isinstance(document, dict):
        return document
    cleaned = {k: v for k, v in document.items() if k != "status"}
    meta = cleaned.get("metadata")
    if isinstance(meta, dict):
        cleaned["metadata"] = {k: v for k, v in meta.items() if k not in _SERVER_META}
    return cleaned


def load_task(text: str) -> Task:
    """Parse ``AX_TASK_YAML``; raise :class:`RunnerError` unless it is exactly one Task."""
    try:
        documents = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RunnerError(f"AX_TASK_YAML is not valid YAML: {exc}") from exc
    if len(documents) != 1:
        raise RunnerError(f"AX_TASK_YAML must hold exactly one Task document, found {len(documents)}")
    try:
        manifest = parse_manifest(_without_server_fields(documents[0]), source="AX_TASK_YAML")
    except ManifestError as exc:
        raise RunnerError(str(exc)) from exc
    if not isinstance(manifest, Task):
        raise RunnerError(f"AX_TASK_YAML holds a {type(manifest).__name__}, not a Task")
    return manifest


def load_workspaces(text: str) -> dict[str, Workspace]:
    """Parse ``AX_WORKSPACES_YAML`` (multi-document, empty allowed) into Workspaces by name."""
    try:
        documents = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RunnerError(f"AX_WORKSPACES_YAML is not valid YAML: {exc}") from exc
    workspaces: dict[str, Workspace] = {}
    for index, document in enumerate(documents):
        try:
            manifest = parse_manifest(_without_server_fields(document), source=f"AX_WORKSPACES_YAML[{index}]")
        except ManifestError as exc:
            raise RunnerError(str(exc)) from exc
        if not isinstance(manifest, Workspace):
            raise RunnerError(f"AX_WORKSPACES_YAML[{index}] holds a {type(manifest).__name__}, not a Workspace")
        workspaces[manifest.metadata.name] = manifest
    return workspaces


# --- health server -----------------------------------------------------------------------------------------------


class _HealthHandler(BaseHTTPRequestHandler):
    server: HealthServer

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        path = self.path.split("?", 1)[0]  # ax's controller probes /readyz?check=workspace
        if path == "/healthz":
            self._answer(200, "ok")
        elif path == "/readyz":
            ready = self.server.ready.is_set()
            self._answer(200 if ready else 503, "ready" if ready else "workspaces not materialised")
        elif path in METADATA_PATHS:
            self._answer(200, self.server.metadata.get(METADATA_PATHS[path], ""), "application/yaml")
        else:
            self._answer(404, "not found")

    def _answer(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server's signature
        log.debug("health server: " + format, *args)


class HealthServer(ThreadingHTTPServer):
    """``/healthz`` always 200; ``/readyz`` 503 until ``ready`` is set; the Task and Workspaces YAML under
    ``/metadata/v1alpha1/ax/``. Serves in a daemon thread."""

    daemon_threads = True

    def __init__(self, port: int, ready: threading.Event, metadata: Mapping[str, str] | None = None) -> None:
        super().__init__(("0.0.0.0", port), _HealthHandler)
        self.ready = ready
        self.metadata = dict(metadata or {})
        self._thread = threading.Thread(target=self.serve_forever, name="ax-health", daemon=True)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=5)


def start_health_server(port: int, ready: threading.Event, metadata: Mapping[str, str] | None = None) -> HealthServer:
    """Serve ``/healthz``, ``/readyz`` and ax's metadata paths (``metadata`` keyed ``task``/``workspaces``)."""
    server = HealthServer(port, ready, metadata)
    server.start()
    return server


# --- workspaces --------------------------------------------------------------------------------------------------


def _git(*args: str, cwd: Path | None = None) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RunnerError(f"git {' '.join(args)} failed ({done.returncode}): {done.stderr.strip()[:400]}")
    return done.stdout


def _repo_key(url: str) -> str:
    key = url.strip().lower().rstrip("/")
    if key.startswith("git@") and ":" in key:
        host, _, path = key[4:].partition(":")
        key = f"https://{host}/{path}"
    key = key.removeprefix("ssh://git@").removeprefix("http://").removeprefix("https://").removeprefix("git://")
    return key.removesuffix(".git")


def find_cached_checkout(cache: Path, repo: str) -> Path | None:
    """The checkout under ``cache`` (or ``cache`` itself) whose ``origin`` is ``repo``, or None.

    ``benchmarks/independent`` keeps one blob-less clone per case at ``<cache>/<case-id>``; the case id says
    nothing about the URL, so the match is on ``git remote get-url origin``.
    """
    if not cache.is_dir():
        return None
    wanted = _repo_key(repo)
    candidates = [cache, *sorted(p for p in cache.iterdir() if p.is_dir())]
    for candidate in candidates:
        if not (candidate / ".git").exists() and not (candidate / "HEAD").exists():
            continue
        done = subprocess.run(["git", "-C", str(candidate), "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
        if done.returncode == 0 and _repo_key(done.stdout) == wanted:
            return candidate
    return None


def load_pins(text: str) -> dict[str, str]:
    """Parse ``OUSAST_GIT_PINS``: the reconciler's rendering of the Workspaces' ``openultrasast.io/git-commits``."""
    if not text.strip():
        return {}
    try:
        pins = json.loads(text)
    except ValueError as exc:
        raise RunnerError(f"OUSAST_GIT_PINS is not JSON: {exc}") from exc
    if not isinstance(pins, dict) or not all(
        isinstance(k, str) and "/" in k and isinstance(v, str) and _SHA.fullmatch(v) for k, v in pins.items()
    ):
        raise RunnerError(f'OUSAST_GIT_PINS must map "<workspace>/<git name>" to a 40-hex commit, got {text[:200]!r}')
    return pins


def repo_dir_name(url: str) -> str:
    """setup.go ``RepoDirName``: ``https://github.com/chalk/chalk.git`` -> ``chalk``."""
    trimmed = url.strip().removesuffix("/").removesuffix(".git")
    return trimmed[max(trimmed.rfind("/"), trimmed.rfind(":")) + 1 :]


def clone_destination(source: GitSource, root: Path) -> Path:
    """setup.go ``cloneDestination``: ``dir`` wins (``.`` the workspace root, absolute as-is, else under the root);
    otherwise the entry's ``name``, unless that is a placeholder (``repo``, ``origin``), then the URL's last segment."""
    if source.dir:
        return root if source.dir == "." else root / source.dir  # an absolute dir replaces root in the join
    name = source.name
    if name in _PLACEHOLDER_NAMES:
        name = repo_dir_name(source.repo) or name or "repo"
    return root / name


def _pinned_ref(source: GitSource, commit: str | None) -> str:
    return commit or source.branch or DEFAULT_BRANCH


def _export_from_cache(checkout: Path, source: GitSource, commit: str | None, dest: Path) -> None:
    """``git archive`` the pinned ref out of the cache into ``dest`` (no ``.git``), as ``evaluate.export`` does."""
    ref = commit or (f"origin/{source.branch}" if source.branch else "HEAD")
    done = subprocess.run(["git", "-C", str(checkout), "archive", ref], capture_output=True, check=False)
    if done.returncode != 0:
        raise RunnerError(f"git archive {ref} in {checkout} failed: {done.stderr.decode(errors='replace').strip()[:400]}")
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(done.stdout), mode="r:") as archive:
        if hasattr(tarfile, "data_filter"):  # 3.11.4+ / 3.12; the image is 3.12
            archive.extractall(dest, filter="data")
        else:  # pragma: no cover
            archive.extractall(dest)  # noqa: S202
    if not any(dest.iterdir()):
        raise RunnerError(f"{source.repo}@{ref}: the export from {checkout} is empty")


def _fetch(source: GitSource, commit: str | None, dest: Path) -> None:
    """setup.go ``fetchRepo`` (init, remote, fetch ``--depth`` when ``depth`` > 0, checkout FETCH_HEAD), then the pin.

    A pinned entry without a branch fetches the commit itself rather than ax's default ``main``.
    """
    dest.mkdir(parents=True, exist_ok=True)
    depth = [f"--depth={source.depth}"] if source.depth else []
    _git("init", "--quiet", cwd=dest)
    try:
        _git("remote", "add", "origin", source.repo, cwd=dest)
    except RunnerError:
        _git("remote", "set-url", "origin", source.repo, cwd=dest)
    _git("fetch", "--quiet", *depth, "origin", source.branch or commit or DEFAULT_BRANCH, cwd=dest)
    _git("checkout", "--quiet", "-f", "FETCH_HEAD", cwd=dest)
    if commit:
        present = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=dest, capture_output=True, check=False)
        if present.returncode != 0:
            _git("fetch", "--quiet", *depth, "origin", commit, cwd=dest)
        _git("checkout", "--quiet", "-f", "--detach", commit, cwd=dest)


def _materialise_git(source: GitSource, root: Path, cache: Path | None, commit: str | None) -> Path:
    dest = clone_destination(source, root)
    resumed = (dest / ".git").exists() if dest == root else dest.is_dir() and any(dest.iterdir())
    if resumed:
        log.info("workspace repo %s already present at %s (resumed volume); keeping it", source.repo, dest)
        return dest
    checkout = find_cached_checkout(cache, source.repo) if cache is not None else None
    if checkout is not None:
        log.info("exporting %s@%s from cache %s to %s", source.repo, _pinned_ref(source, commit), checkout, dest)
        _export_from_cache(checkout, source, commit, dest)
    else:
        log.info("fetching %s@%s to %s (depth %s)", source.repo, _pinned_ref(source, commit), dest, source.depth or "full")
        _fetch(source, commit, dest)
    return dest


def materialise(task: Task, workspaces: Mapping[str, Workspace], cache: Path | None, pins: Mapping[str, str] | None = None) -> list[Path]:
    """Write every bound workspace at its path (``spec.files`` verbatim, ``spec.git`` where ax's setup puts it).

    ``pins`` (from ``OUSAST_GIT_PINS``) names the commit of ``<workspace>/<git name>``; a pin naming no bound git
    entry, or a binding without a Workspace, raises :class:`RunnerError` before anything is written.
    """
    pins = dict(pins or {})
    for binding in task.workspaces:
        if binding.name not in workspaces:
            raise RunnerError(f"Task/{task.metadata.name}: workspace {binding.name!r} is bound but not in AX_WORKSPACES_YAML")
    known = {f"{b.name}/{g.name}" for b in task.workspaces for g in workspaces[b.name].git}
    unknown = sorted(set(pins) - known)
    if unknown:
        raise RunnerError(f"OUSAST_GIT_PINS names no bound git entry: {', '.join(unknown)}")
    paths: list[Path] = []
    for binding in task.workspaces:
        workspace = workspaces[binding.name]
        root = Path(binding.path)
        root.mkdir(parents=True, exist_ok=True)
        for entry in workspace.files:
            target = root / entry.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(entry.content, encoding="utf-8")
        for source in workspace.git:
            _materialise_git(source, root, cache, pins.get(f"{binding.name}/{source.name}"))
        paths.append(root)
    return paths


# --- the task ----------------------------------------------------------------------------------------------------


def read_summary(output_dir: Path) -> dict[str, Any] | None:
    path = output_dir / SUMMARY
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def write_summary(output_dir: Path, summary: Mapping[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / SUMMARY).write_text(json.dumps(dict(summary), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _failed(reason: str, base: Mapping[str, Any] | None = None) -> dict[str, Any]:
    summary = dict(base or {})
    summary.update({"status": "failed", "reason": reason})
    return summary


def task_module(command: Sequence[str], package: str = TASK_PACKAGE) -> str:
    """``spec.command[0]`` as a module under ``package`` (``repo-facts`` -> ``<package>.repo_facts``)."""
    if not command:
        raise RunnerError("spec.command is empty")
    name = command[0].replace("-", "_")
    if not _MODULE.fullmatch(name):
        raise RunnerError(f"spec.command[0] {command[0]!r} does not name a task module")
    return f"{package}.{name}"


class Child:
    """``spec.command`` as a child in its own process group; its stderr is echoed and the tail kept."""

    def __init__(self, argv: Sequence[str], cwd: str | None, env: Mapping[str, str]) -> None:
        self.proc = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), stderr=subprocess.PIPE, start_new_session=True)
        self.tail: deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self._reader = threading.Thread(target=self._echo, name="task-stderr", daemon=True)
        self._reader.start()

    def _echo(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            line = raw.decode("utf-8", errors="replace")
            sys.stderr.write(line)
            sys.stderr.flush()
            self.tail.append(line.rstrip("\n"))

    def signal_group(self, signum: int) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.proc.pid, signum)

    def wait(self, stop: threading.Event, grace: float) -> int | None:
        """The exit code; or, once ``stop`` is set, SIGTERM to the group, ``grace`` seconds, SIGKILL, and None."""
        while self.proc.poll() is None:
            if stop.wait(0.1):
                log.info("stopping: SIGTERM to the command's process group %d", self.proc.pid)
                self.signal_group(signal.SIGTERM)
                try:
                    self.proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    log.warning("the command outlived the %gs grace period; SIGKILL", grace)
                self.signal_group(signal.SIGKILL)
                self.proc.wait()
                self._reader.join(timeout=5)
                return None
        self._reader.join(timeout=5)
        return self.proc.returncode


def summary_after(code: int, output_dir: Path, name: str, stderr_tail: Sequence[str] = ()) -> dict[str, Any]:
    """The task's ``summary.json`` after it exited with ``code``; a failed one when it wrote none that is valid.

    A task exits 2 or 3 with a ``failed``/``unfinished`` summary by design; a non-zero exit next to ``done``, or no
    valid summary at all, is a crash: the failed summary keeps the task's fields and carries the exit code and the
    tail of its stderr (the traceback of an uncaught exception).
    """
    written = read_summary(output_dir)
    status = None if written is None else written.get("status")
    if status in EXIT_BY_STATUS and (code == 0 or status != "done"):
        return dict(written or {})
    why = "reported done" if status == "done" else f"wrote no valid {SUMMARY} (status {status!r})"
    reason = f"task {name} exited with {code} and {why}"
    if stderr_tail:
        reason += "; stderr tail:\n" + "\n".join(stderr_tail)
    summary = _failed(reason, written)
    summary["exit"] = code
    write_summary(output_dir, summary)
    return summary


def run_command(
    task: Task, output_dir: Path, env: Mapping[str, str], stop: threading.Event, grace: float
) -> tuple[int | None, dict[str, Any]]:
    """Run ``python -m <package>.<command[0]> <command[1:]>`` in the first workspace; (exit code, summary).

    (None, {}) when ``stop`` interrupted it: the command did not finish and a resume runs it again.
    """
    module = task_module(task.command, env.get("AX_RUNNER_TASK_PACKAGE") or TASK_PACKAGE)
    cwd = task.workspaces[0].path if task.workspaces else None
    child = Child([sys.executable, "-m", module, *task.command[1:]], cwd, env)
    code = child.wait(stop, grace)
    if code is None:
        return None, {}
    log.info("task %s exited with %d", task.metadata.name, code)
    return code, summary_after(code, output_dir, task.command[0], list(child.tail))


# --- artifact delivery -----------------------------------------------------------------------------------------


def build_tar(output_dir: Path) -> bytes:
    """The output directory as an uncompressed tar with paths relative to it, in sorted order."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
            archive.add(path, arcname=path.relative_to(output_dir).as_posix())
    return buffer.getvalue()


def deliver(url: str, payload: bytes, headers: Mapping[str, str], *, attempts: int = DELIVERY_ATTEMPTS, backoff: float = 1.0) -> int:
    """POST ``payload`` to ``url`` with ``headers``; retry with doubling backoff; return the 2xx status."""
    last = "no attempt made"
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=payload, method="POST", headers=dict(headers))
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - the reconciler's URL
                status = int(response.status)
                if 200 <= status < 300:
                    return status
                last = f"HTTP {status}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        log.warning("artifact delivery attempt %d/%d to %s failed: %s", attempt, attempts, url, last)
        if attempt < attempts:
            time.sleep(backoff * (2 ** (attempt - 1)))
    raise DeliveryError(f"{last} after {attempts} attempts to {url}")


def _deliver_output(task: Task, output_dir: Path, environ: Mapping[str, str]) -> bool:
    """POST the output directory; False when there is nowhere to deliver; :class:`DeliveryError` when it fails."""
    url = environ.get("OUSAST_ARTIFACT_URL")
    if not url:
        return False
    headers = {"Content-Type": "application/x-tar", "X-Ousast-Task": task.metadata.name}
    run = environ.get("OUSAST_RUN")
    if run:
        headers["X-Ousast-Run"] = run
    backoff = float(environ.get("OUSAST_DELIVERY_BACKOFF", "1.0"))
    deliver(url, build_tar(output_dir), headers, backoff=backoff)
    return True


# --- entrypoint --------------------------------------------------------------------------------------------------


@dataclass
class _Session:
    task: Task
    workspaces: dict[str, Workspace]
    output_dir: Path
    state_dir: Path

    @property
    def marker(self) -> Path:
        """``<state>/<task>.done.json``: the command finished; ``delivered`` says whether the receiver has it."""
        return self.state_dir / f"{self.task.metadata.name}.done.json"

    @property
    def prepared(self) -> Path:
        return self.state_dir / f"{self.task.metadata.name}.workspaces.done"


def _prepare(environ: MutableMapping[str, str]) -> _Session:
    task_yaml = environ.get("AX_TASK_YAML")
    if not task_yaml:
        raise RunnerError("AX_TASK_YAML is not set")
    task = load_task(task_yaml)
    workspaces = load_workspaces(environ.get("AX_WORKSPACES_YAML", ""))
    for var in task.env:
        environ[var.name] = var.value
    if "OUSAST_WORKSPACE_DIR" not in environ and task.workspaces:
        environ["OUSAST_WORKSPACE_DIR"] = task.workspaces[0].path
    if "OUSAST_OUTPUT_DIR" not in environ:
        base = environ.get("OUSAST_WORKSPACE_DIR") or os.getcwd()
        environ["OUSAST_OUTPUT_DIR"] = str(Path(base) / "output")
    output_dir = Path(environ["OUSAST_OUTPUT_DIR"])
    state_dir = Path(environ.get("OUSAST_STATE_DIR") or STATE_DIR)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RunnerError(f"cannot create the output or state directory: {exc}") from exc
    return _Session(task, workspaces, output_dir, state_dir)


def _exit_of(marker: Mapping[str, Any]) -> int:
    return EXIT_BY_STATUS.get(str(marker.get("status")), EXIT_BY_STATUS["failed"])


def _finish(session: _Session, env: Mapping[str, str], exit_code: int | None, summary: Mapping[str, Any]) -> dict[str, Any]:
    """Deliver the output directory and write the completion marker; a failed delivery reports ``failed``.

    The marker keeps the task's own summary so a later boot can put it back and retry the delivery alone.
    """
    marker: dict[str, Any] = {"exit": exit_code, "status": str(summary.get("status")), "delivered": False, "summary": dict(summary)}
    try:
        marker["delivered"] = _deliver_output(session.task, session.output_dir, env)
    except DeliveryError as exc:
        log.error("artifact delivery failed: %s", exc)
        marker.update(status="failed", reason=f"artifact delivery failed: {exc}")
        write_summary(session.output_dir, _failed(marker["reason"], summary))
    session.marker.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("task %s: status %s, delivered %s", session.task.metadata.name, marker["status"], marker["delivered"])
    return marker


def _run_once(env: MutableMapping[str, str], ready: threading.Event, stop: threading.Event) -> int:
    """Materialise, run the command once, deliver; on a resumed volume, only what the marker says is left."""
    session: _Session | None = None
    try:
        session = _prepare(env)
        if session.prepared.exists():
            log.info("workspaces were prepared on an earlier boot; keeping them")
        else:
            cache_dir = env.get("OUSAST_CASE_CACHE")
            materialise(session.task, session.workspaces, Path(cache_dir) if cache_dir else None, load_pins(env.get("OUSAST_GIT_PINS", "")))
            session.prepared.touch()
        ready.set()
        done = _read_marker(session.marker)
        if done is not None and done.get("delivered"):
            log.info("task %s already ran and was delivered (%s); not running it again", session.task.metadata.name, done.get("status"))
            return _exit_of(done)
        if done is not None:
            log.info("task %s already ran; retrying the delivery only", session.task.metadata.name)
            stored = done.get("summary")
            kept: dict[str, Any] = stored if isinstance(stored, dict) else read_summary(session.output_dir) or {}
            write_summary(session.output_dir, kept)
            return _exit_of(_finish(session, env, done.get("exit"), kept))
        if stop.is_set():
            return 0
        log.info("workspaces ready; running task %s: %s", session.task.metadata.name, list(session.task.command))
        code, summary = run_command(session.task, session.output_dir, env, stop, float(env.get("OUSAST_TERM_GRACE") or TERM_GRACE))
        if code is None:
            log.info("task %s was stopped before its command finished; a resume runs it again", session.task.metadata.name)
            return 0
        return _exit_of(_finish(session, env, code, summary))
    except RunnerError as exc:
        log.error("runner failed: %s", exc)
        if session is None:
            return EXIT_BY_STATUS["failed"]
        summary = _failed(f"runner failed: {exc}", read_summary(session.output_dir))
        write_summary(session.output_dir, summary)
        return _exit_of(_finish(session, env, None, summary))


def _read_marker(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def main(argv: Sequence[str] | None = None, environ: MutableMapping[str, str] | None = None) -> int:
    """The ``ax-task-runner`` entrypoint (PID 1): run the command once, deliver, then serve until SIGTERM.

    Returns 0 after SIGTERM. ``AX_RUNNER_EXIT_AFTER_COMMAND=1`` (unit tests only; the image never sets it) returns
    right after delivery with the task's exit code: 0 done, 2 failed, 3 unfinished.
    """
    env = os.environ if environ is None else environ
    if argv:
        log.warning("ax-task-runner ignores command-line arguments %r; the Task manifest is the only input", list(argv))
    ready, stop = threading.Event(), threading.Event()
    previous = _on_sigterm(stop)
    server: HealthServer | None = None
    if env.get("AX_RUNNER_HTTP", "1") != "0":
        metadata = {"task": env.get("AX_TASK_YAML", ""), "workspaces": env.get("AX_WORKSPACES_YAML", "")}
        server = start_health_server(int(env.get("AX_RUNNER_PORT", str(DEFAULT_PORT))), ready, metadata)
        env["AX_RUNNER_BOUND_PORT"] = str(server.port)
        env["AX_METADATA_URL"] = f"http://127.0.0.1:{server.port}"
        log.info("health and metadata server on port %d", server.port)
    try:
        code = _run_once(env, ready, stop)
        if stop.is_set():
            return 0
        if env.get("AX_RUNNER_EXIT_AFTER_COMMAND") == "1":
            return code
        log.info("the command is finished (exit %d by status); serving until SIGTERM", code)
        while not stop.wait(1.0):
            pass
        log.info("SIGTERM: shutting down")
        return 0
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
        if server is not None:
            server.stop()


def _on_sigterm(stop: threading.Event) -> Any:
    """Route SIGTERM (ax's stop and suspend) to ``stop``; the previous handler, or None off the main thread."""
    if threading.current_thread() is not threading.main_thread():
        return None
    return signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s", stream=sys.stderr)
    sys.exit(main(sys.argv[1:]))
