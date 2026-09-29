"""ax's runner contract for a task container (ai-service-plane Requirement 4).

This module is ``/usr/local/bin/ax-task-runner`` in the runner image, PID 1 of the task container. ax hands it
the Task as YAML in ``AX_TASK_YAML`` and the bound Workspaces as a multi-document stream in ``AX_WORKSPACES_YAML``;
nothing else comes from the command line (Requirement 4.1). It serves ``/healthz`` and ``/readyz`` on port 80,
``/readyz`` answering 503 until every workspace is materialised (Requirement 4.2), then runs ``spec.command``:
its first element names ``openultrasast.plane.tasks.<name>`` whose ``main(argv)`` gets the rest.

ax has no artifact channel, so after the task returns the runner posts the whole ``OUSAST_OUTPUT_DIR`` as a tar
stream to ``OUSAST_ARTIFACT_URL`` before it reports completion; a failed delivery is reported as ``failed``, never
as done (Requirement 4.4). The exit code follows the task's ``summary.json``: 0 ``done``, 2 ``failed``, 3
``unfinished``.

Environment the runner reads, all optional except the two ax variables:

    AX_TASK_YAML, AX_WORKSPACES_YAML   ax's contract
    AX_RUNNER_HTTP                     "0" disables the health server (unit tests only)
    AX_RUNNER_PORT                     port of the health server, default 80; "0" picks a free port
    OUSAST_CASE_CACHE                  a directory of git checkouts (``benchmarks/independent`` cache layout)
    OUSAST_GIT_PINS                    JSON ``{"<workspace>/<git name>": "<40-hex commit>"}`` from the reconciler
    OUSAST_ARTIFACT_URL, OUSAST_RUN    where to deliver, and the run name carried in ``X-Ousast-Run``
    OUSAST_DELIVERY_BACKOFF            seconds before the second delivery attempt, doubled per retry

The runner exports ``OUSAST_WORKSPACE_DIR`` (the first bound workspace) when the Task's env leaves it unset, and
``AX_RUNNER_BOUND_PORT`` with the health server's port.
"""

from __future__ import annotations

import http.client
import importlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.error
import urllib.request
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
    "TASK_PACKAGE",
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
    "run_task_module",
    "start_health_server",
    "write_summary",
]

DEFAULT_PORT = 80
DELIVERY_ATTEMPTS = 3
TASK_PACKAGE = "openultrasast.plane.tasks"
EXIT_BY_STATUS = {"done": 0, "failed": 2, "unfinished": 3}
SUMMARY = "summary.json"
DEFAULT_BRANCH = "main"  # ax internal/workspace/setup.go: defaultBranch
_PLACEHOLDER_NAMES = ("", "repo", "origin")  # setup.go: names that do not name a checkout directory
_SHA = re.compile(r"[0-9a-f]{40}")

log = logging.getLogger("ousast.plane.runner")


class RunnerError(RuntimeError):
    """The runner itself cannot proceed (bad manifests, a workspace that cannot be materialised)."""


class DeliveryError(RuntimeError):
    """Every delivery attempt failed; the message names the last cause."""


# --- manifests ---------------------------------------------------------------------------------------------------


def load_task(text: str) -> Task:
    """Parse ``AX_TASK_YAML``; raise :class:`RunnerError` unless it is exactly one Task."""
    try:
        documents = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RunnerError(f"AX_TASK_YAML is not valid YAML: {exc}") from exc
    if len(documents) != 1:
        raise RunnerError(f"AX_TASK_YAML must hold exactly one Task document, found {len(documents)}")
    try:
        manifest = parse_manifest(documents[0], source="AX_TASK_YAML")
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
            manifest = parse_manifest(document, source=f"AX_WORKSPACES_YAML[{index}]")
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
        if self.path == "/healthz":
            self._answer(200, "ok")
        elif self.path == "/readyz":
            ready = self.server.ready.is_set()
            self._answer(200 if ready else 503, "ready" if ready else "workspaces not materialised")
        else:
            self._answer(404, "not found")

    def _answer(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server's signature
        log.debug("health server: " + format, *args)


class HealthServer(ThreadingHTTPServer):
    """``/healthz`` always 200; ``/readyz`` 503 until ``ready`` is set. Serves in a daemon thread."""

    daemon_threads = True

    def __init__(self, port: int, ready: threading.Event) -> None:
        super().__init__(("0.0.0.0", port), _HealthHandler)
        self.ready = ready
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


def start_health_server(port: int, ready: threading.Event) -> HealthServer:
    server = HealthServer(port, ready)
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


def run_task_module(command: Sequence[str], output_dir: Path) -> dict[str, Any]:
    """Import ``openultrasast.plane.tasks.<command[0]>`` and call ``main(command[1:])``; return the summary.

    A crash (any exception, or ``sys.exit`` with a non-zero code) writes ``summary.json`` with ``status: failed``
    and the traceback; a task that returns without writing ``summary.json`` is failed too.
    """
    name = f"{TASK_PACKAGE}.{command[0].replace('-', '_')}"
    argv = list(command[1:])
    try:
        try:
            module = importlib.import_module(name)
        except ImportError as exc:
            raise RunnerError(f"task module {name} cannot be imported: {exc}") from exc
        entry = getattr(module, "main", None)
        if not callable(entry):
            raise RunnerError(f"{name} has no main()")
        entry(argv)
    except RunnerError as exc:
        log.error("%s", exc)
        summary = _failed(str(exc), read_summary(output_dir))
        write_summary(output_dir, summary)
        return summary
    except SystemExit as exc:
        if exc.code not in (None, 0):
            summary = _failed(f"task {command[0]} exited with {exc.code!r}", read_summary(output_dir))
            write_summary(output_dir, summary)
            return summary
    except BaseException:
        reason = f"task {command[0]} crashed:\n{traceback.format_exc()}"
        log.error("%s", reason)
        summary = _failed(reason, read_summary(output_dir))
        write_summary(output_dir, summary)
        return summary
    written = read_summary(output_dir)
    if written is not None and written.get("status") in EXIT_BY_STATUS:
        return written
    found = None if written is None else written.get("status")
    summary = _failed(f"task {command[0]} wrote no valid {SUMMARY} (status {found!r})", written)
    write_summary(output_dir, summary)
    return summary


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


def _deliver_output(task: Task, output_dir: Path, environ: Mapping[str, str]) -> None:
    url = environ.get("OUSAST_ARTIFACT_URL")
    if not url:
        return
    headers = {"Content-Type": "application/x-tar", "X-Ousast-Task": task.metadata.name}
    run = environ.get("OUSAST_RUN")
    if run:
        headers["X-Ousast-Run"] = run
    backoff = float(environ.get("OUSAST_DELIVERY_BACKOFF", "1.0"))
    deliver(url, build_tar(output_dir), headers, backoff=backoff)


# --- entrypoint --------------------------------------------------------------------------------------------------


@dataclass
class _Session:
    task: Task
    workspaces: dict[str, Workspace]
    output_dir: Path


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
    output_dir.mkdir(parents=True, exist_ok=True)
    return _Session(task, workspaces, output_dir)


def main(argv: Sequence[str] | None = None, environ: MutableMapping[str, str] | None = None) -> int:
    """The ``ax-task-runner`` entrypoint; returns the exit code (0 done, 2 failed, 3 unfinished)."""
    env = os.environ if environ is None else environ
    if argv:
        log.warning("ax-task-runner ignores command-line arguments %r; the Task manifest is the only input", list(argv))
    ready = threading.Event()
    server: HealthServer | None = None
    if env.get("AX_RUNNER_HTTP", "1") != "0":
        server = start_health_server(int(env.get("AX_RUNNER_PORT", str(DEFAULT_PORT))), ready)
        env["AX_RUNNER_BOUND_PORT"] = str(server.port)
        log.info("health server on port %d", server.port)
    session: _Session | None = None
    try:
        session = _prepare(env)
        cache_dir = env.get("OUSAST_CASE_CACHE")
        pins = load_pins(env.get("OUSAST_GIT_PINS", ""))
        materialise(session.task, session.workspaces, Path(cache_dir) if cache_dir else None, pins)
        ready.set()
        log.info("workspaces ready; running task %s: %s", session.task.metadata.name, list(session.task.command))
        summary = run_task_module(session.task.command, session.output_dir)
        try:
            _deliver_output(session.task, session.output_dir, env)
        except DeliveryError as exc:
            log.error("artifact delivery failed: %s", exc)
            summary = _failed(f"artifact delivery failed: {exc}", summary)
            write_summary(session.output_dir, summary)
        status = str(summary.get("status"))
        log.info("task %s finished with status %s", session.task.metadata.name, status)
        return EXIT_BY_STATUS.get(status, EXIT_BY_STATUS["failed"])
    except RunnerError as exc:
        log.error("runner failed: %s", exc)
        if session is not None:
            write_summary(session.output_dir, _failed(f"runner failed: {exc}", read_summary(session.output_dir)))
        return EXIT_BY_STATUS["failed"]
    finally:
        if server is not None:
            server.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s", stream=sys.stderr)
    sys.exit(main(sys.argv[1:]))
