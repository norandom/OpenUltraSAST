"""ax-backed reconciler of a ``Run``: submission, status, resume, artifact receipt (ai-service-plane Req 3, 7).

Every task of a Run is executed by ax on this host's kind cluster; nothing here runs a task as a local subprocess
and nothing here knows a prompt, a score or a model call. For each ready task the reconciler renders one YAML
file (the Task with its env extended, its Workspaces, one generated Workspace carrying the consumed artifacts as
``files`` entries, and the bound Model), runs ``ax apply -f``, polls ``ax get task`` until a terminal phase and
``ax delete task`` afterwards. The outcome is read from the delivered ``summary.json``, never from the phase alone.

Model binding: a Task names its Model in ``metadata.annotations["openultrasast.io/model"]`` (ax's ObjectMeta has no
annotations, so the rendered Task carries only ``name``/``atespace``); the task receives ``OUSAST_MODEL`` and the
Model's ``spec.parameters`` as ``OUSAST_MODEL_PARAMS`` JSON (Req 7.1). Inputs: ``OUSAST_INPUT_<NAME>`` points into a
generated Workspace bound at ``/workspace/.ousast-in/<task>`` (ax mounts every workspace under ``/workspace``).
Artifacts: the runner POSTs an uncompressed tar of its output directory to ``OUSAST_ARTIFACT_URL`` with
``X-Ousast-Run`` and ``X-Ousast-Task`` headers; the receiver listens on ``0.0.0.0`` at ``OUSAST_ARTIFACT_PORT``
(default: a free port) and advertises ``OUSAST_ARTIFACT_HOST`` (default ``172.17.0.1``, the docker bridge address
of this host, which kind nodes reach; ``127.0.0.1`` for a fake ax on the host). Run state lives in
``~/ousast-results/plane/<run>/`` (``OUSAST_RESULTS`` overrides the root): ``state.json``, a PID ``lock``, one
directory per task, ``attribution.json`` written by ``status``; ``OUSAST_POLL_SECONDS`` (default 3) paces polling.
"""

from __future__ import annotations

import io
import json
import os
import queue
import re
import subprocess
import tarfile
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from .manifests import AX_API_VERSION, Manifests, Model, Run, RunTask, Task, Workspace, load_manifests

MODEL_ANNOTATION = "openultrasast.io/model"
OUTPUT_ROOT = "/workspace/.ousast-out"
INPUTS_ROOT = "/workspace/.ousast-in"
DEFAULT_ARTIFACT_HOST = "172.17.0.1"
FAILURE_PHASES = ("failed", "error")
TERMINAL_PHASES = ("succeeded", "completed", *FAILURE_PHASES)
UP = "ops/ax/up.sh brings it up"
_ROW = "{:<28} {:<20} {:>7} {:>10} {:>10} {:>9} {:>10}"
_COLUMNS = ("calls", "prompt", "cache_hit", "output", "usd")
_USAGE_KEYS = {"prompt": "prompt_tokens", "cache_hit": "prompt_cache_hit_tokens", "output": "completion_tokens"}


def results_root() -> Path:
    return Path(os.environ.get("OUSAST_RESULTS") or Path.home() / "ousast-results") / "plane"


def run_dir(run_name: str, root: Path | None = None) -> Path:
    return (root or results_root()) / run_name


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write_json(path: Path, payload: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _ax_name(*parts: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", "-".join(parts).lower()).strip("-")[:63]


def _is(phase: str, words: tuple[str, ...]) -> bool:
    return any(word in phase.lower() for word in words)


def load_run(run_manifest: Path) -> tuple[Run, Manifests]:
    """Load the Run file; a file under ``.../runs/`` also loads the sibling ``tasks``, ``models`` and ``workspaces``."""
    paths = [run_manifest]
    if run_manifest.parent.name == "runs":
        for kind in ("tasks", "models", "workspaces"):
            paths.extend(sorted((run_manifest.parent.parent / kind).glob("*.y*ml")))
    manifests = load_manifests(paths)
    if len(manifests.runs) != 1:
        raise ValueError(f"{run_manifest}: expected exactly one Run, found {len(manifests.runs)}")
    return next(iter(manifests.runs.values())), manifests


def _doc(kind: str, name: str, spec: dict[str, Any], namespace: str | None = None) -> dict[str, Any]:
    meta = {"name": name, **({"atespace": namespace} if namespace else {})}
    return {"apiVersion": AX_API_VERSION, "kind": kind, "metadata": meta, "spec": spec}


def _fields(value: object) -> dict[str, Any]:
    return {k: v for k, v in vars(value).items() if v is not None}


def _workspace_doc(ws: Workspace) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if ws.git:
        spec["git"] = [_fields(g) for g in ws.git]
    if ws.files:
        spec["files"] = [_fields(f) for f in ws.files]
    if ws.mcp:
        spec["mcp"] = {"registries": list(ws.mcp.registries), "servers": list(ws.mcp.servers)}
    if ws.skills:
        spec["skills"] = {"registries": list(ws.skills.registries), **({"path": ws.skills.path} if ws.skills.path else {})}
    return _doc("Workspace", ws.metadata.name, spec, ws.metadata.namespace)


def _model_doc(model: Model) -> dict[str, Any]:
    spec: dict[str, Any] = {"provider": model.provider, "model": model.model}
    if model.secret_key:
        spec["secretKey"] = _fields(model.secret_key)
    if model.parameters:
        spec["parameters"] = dict(model.parameters)
    return _doc("Model", model.metadata.name, spec, model.metadata.namespace)


def _input_files(entry: RunTask, base: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for ref in entry.inputs.values():
        source = base / ref
        for path in sorted(source.rglob("*")) if source.is_dir() else [source]:
            if path.is_file():
                files.append({"path": path.relative_to(base).as_posix(), "content": path.read_text(encoding="utf-8")})
    return files


def render_task(run: Run, entry: RunTask, manifests: Manifests, base: Path, artifact_url: str) -> list[dict[str, Any]]:
    """The documents ``ax apply`` receives for one Run task: Task, its Model, its Workspaces, the inputs Workspace."""
    task: Task = manifests.tasks[entry.task]
    ax_name = _ax_name(run.metadata.name, entry.name)
    env = {e.name: e.value for e in task.env}
    env.update(OUSAST_RUN=run.metadata.name, OUSAST_TASK=entry.name, OUSAST_OUTPUT_DIR=f"{OUTPUT_ROOT}/{entry.name}")
    env["OUSAST_ARTIFACT_URL"] = artifact_url
    budget = _fields(entry.budget) if entry.budget else {}
    env.update({f"OUSAST_BUDGET_{k.upper()}": str(v) for k, v in budget.items()})
    for input_name, ref in entry.inputs.items():
        env[f"OUSAST_INPUT_{re.sub(r'[^A-Z0-9]+', '_', input_name.upper())}"] = f"{INPUTS_ROOT}/{entry.name}/{ref}"
    docs: list[dict[str, Any]] = []
    model_name = task.metadata.annotations.get(MODEL_ANNOTATION)
    if model_name:
        model = manifests.models[model_name]
        env.update(OUSAST_MODEL=model_name, OUSAST_MODEL_PARAMS=json.dumps(dict(model.parameters), sort_keys=True))
        docs.append(_model_doc(model))
    bindings = [_fields(b) for b in task.workspaces]
    docs.extend(_workspace_doc(manifests.workspaces[b.name]) for b in task.workspaces)
    if entry.inputs:
        docs.append(_doc("Workspace", f"{ax_name}-inputs", {"files": _input_files(entry, base)}, task.metadata.namespace))
        bindings.append({"name": f"{ax_name}-inputs", "path": f"{INPUTS_ROOT}/{entry.name}"})
    spec: dict[str, Any] = {"command": list(task.command), "env": [{"name": k, "value": v} for k, v in env.items()]}
    if task.image:
        spec["image"] = task.image
    if task.resources:
        spec["resources"] = {k: _fields(v) for k, v in _fields(task.resources).items()}
    if bindings:
        spec["workspaces"] = bindings
    if task.debug:
        spec["debug"] = True
    return [_doc("Task", ax_name, spec, task.metadata.namespace), *docs]


class Ax:
    """The three ``ax`` verbs the reconciler uses; the executable path is injectable so tests use a fake."""

    def __init__(self, executable: str = "ax") -> None:
        self.executable = executable

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.executable, *args], capture_output=True, text=True, check=False)

    def apply(self, path: Path) -> None:
        proc = self._run("apply", "-f", str(path))
        if proc.returncode != 0:
            raise RuntimeError(f"ax apply failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")

    def phase(self, name: str) -> str:
        """``status.phase`` from ``ax get task <name>`` (YAML; Pending when unset; ``Unknown: ...`` when ax fails)."""
        proc = self._run("get", "task", name)
        if proc.returncode != 0:
            return "Unknown: " + (proc.stderr.strip() or proc.stdout.strip())
        try:
            doc = yaml.safe_load(proc.stdout)
        except yaml.YAMLError:
            return "Unknown: unreadable ax output"
        status = doc.get("status") if isinstance(doc, dict) else None
        return str(status.get("phase") or "Pending") if isinstance(status, dict) else "Pending"

    def delete(self, name: str) -> None:
        self._run("delete", "task", name)


class Receiver(ThreadingHTTPServer):
    """Accepts one tar per running task and extracts it under ``<run dir>/<task>/``."""

    daemon_threads = True

    def __init__(self, run_name: str, base: Path, port: int) -> None:
        super().__init__(("0.0.0.0", port), _Handler)
        self.run_name, self.base, self.running, self.delivered = run_name, base, set[str](), set[str]()
        self.lock = threading.Lock()

    def url(self) -> str:
        return f"http://{os.environ.get('OUSAST_ARTIFACT_HOST') or DEFAULT_ARTIFACT_HOST}:{self.server_address[1]}/"

    def accept(self, headers: Any, body: bytes) -> tuple[int, str]:
        task = headers.get("X-Ousast-Task", "")
        if headers.get("X-Ousast-Run") != self.run_name or task not in self.running:
            return 403, "unknown run or task"
        if not str(headers.get("Content-Type", "")).startswith("application/x-tar"):
            return 415, "expected application/x-tar"
        dest = (self.base / task).resolve()
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as tar:
                members = tar.getmembers()
                for m in members:
                    if m.issym() or m.islnk() or not (dest / m.name).resolve().is_relative_to(dest):
                        return 400, f"rejected member {m.name}"
                dest.mkdir(parents=True, exist_ok=True)
                tar.extractall(dest, members)  # every member checked above
        except tarfile.TarError as exc:
            return 400, f"bad tar: {exc}"
        with self.lock:
            self.delivered.add(task)
        return 200, "ok"


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        server: Receiver = self.server  # type: ignore[assignment]
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        code, text = server.accept(self.headers, body)
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(text.encode())

    def log_message(self, format: str, *args: object) -> None:
        return


# --- the run -------------------------------------------------------------------------------------------------------


@dataclass
class _State:
    path: Path
    data: dict[str, Any]
    lock: threading.Lock = field(default_factory=threading.Lock)

    def set(self, task: str, **fields: object) -> None:
        with self.lock:
            self.data["tasks"].setdefault(task, {"status": "pending", "started": None, "finished": None, "usd": None, "model": None})
            self.data["tasks"][task].update(fields)
            _write_json(self.path, self.data)

    def status(self, task: str) -> str:
        return str(self.data["tasks"].get(task, {}).get("status", "pending"))


def outcome_of(summary: Mapping[str, Any] | None, phase: str) -> tuple[str, str]:
    """(status, reason) of a finished task from its delivered summary and ax's terminal phase."""
    if _is(phase, FAILURE_PHASES):
        return "failed", f"ax phase {phase}"
    if summary is None:
        return "failed", "no summary.json delivered"
    if summary.get("status") == "done" and summary.get("units_done") == summary.get("units_total"):
        return "done", ""
    if summary.get("status") == "unfinished":
        return "unfinished", str(summary.get("reason") or "budget stop")
    return "failed", str(summary.get("reason") or summary.get("status") or "task did not report done")


def _acquire_lock(base: Path) -> Path:
    lock = base / "lock"
    pid = _read_json(lock)
    if isinstance(pid, int) and pid != os.getpid():
        try:
            os.kill(pid, 0)
        except OSError:
            pass
        else:
            raise RuntimeError(f"run is held by pid {pid} ({lock})")
    lock.write_text(json.dumps(os.getpid()), encoding="utf-8")
    return lock


def _execute(ax: Ax, run: Run, entry: RunTask, manifests: Manifests, base: Path, receiver: Receiver, poll: float) -> tuple[str, str]:
    ax_name = _ax_name(run.metadata.name, entry.name)
    manifest = base / entry.name / "task.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    docs = render_task(run, entry, manifests, base, receiver.url())
    manifest.write_text(yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8")
    try:
        ax.apply(manifest)
    except RuntimeError as exc:
        return "failed", str(exc)
    phase, unknown = "Pending", 0
    try:
        while not _is(phase, TERMINAL_PHASES):
            time.sleep(poll)
            phase = ax.phase(ax_name)
            unknown = unknown + 1 if phase.startswith("Unknown") else 0
            if unknown >= 10:  # ten consecutive unreadable polls: ax itself is broken, not the task
                phase = "Error: " + phase
        for _ in range(5):  # delivery may trail the phase change by a few seconds
            if entry.name in receiver.delivered or _is(phase, FAILURE_PHASES):
                break
            time.sleep(poll)
    finally:
        ax.delete(ax_name)
    return outcome_of(_read_json(base / entry.name / "summary.json"), phase)


def run(run_manifest: Path, *, workers: int = 1, ax: str = "ax", results_root: Path | None = None) -> str:
    """Execute a Run on ax and return its status: ``done``, ``unfinished`` or ``failed`` (Req 3.1-3.3, 2.2)."""
    run_spec, manifests = load_run(Path(run_manifest))
    base = run_dir(run_spec.metadata.name, results_root)
    base.mkdir(parents=True, exist_ok=True)
    lock = _acquire_lock(base)
    poll = float(os.environ.get("OUSAST_POLL_SECONDS") or 3)
    fresh = {"run": run_spec.metadata.name, "started": _now(), "tasks": {}}
    state = _State(base / "state.json", _read_json(base / "state.json") or fresh)
    receiver = Receiver(run_spec.metadata.name, base, int(os.environ.get("OUSAST_ARTIFACT_PORT") or 0))
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    cli, finished = Ax(ax), queue.Queue[tuple[str, str, str]]()
    pending = [t for t in run_spec.tasks if state.status(t.name) != "done"]
    for entry in run_spec.tasks:
        state.set(entry.name, **({"status": "pending"} if entry in pending else {}))
    running: dict[str, RunTask] = {}
    halted = False

    def worker(entry: RunTask) -> None:
        if state.status(entry.name) in ("running", "suspended"):
            cli.delete(_ax_name(run_spec.metadata.name, entry.name))  # an interrupted attempt; ax must not keep it
        state.set(entry.name, status="running", started=_now(), finished=None)
        finished.put((entry.name, *_execute(cli, run_spec, entry, manifests, base, receiver, poll)))

    try:
        while pending or running:
            blocked = {t.serialize for t in running.values() if t.serialize}
            for entry in list(pending):
                if halted or len(running) >= max(workers, 1) or (entry.serialize and entry.serialize in blocked):
                    continue
                if not all(state.status(p) == "done" for p in entry.producers):
                    continue
                pending.remove(entry)
                running[entry.name] = entry
                blocked.add(entry.serialize or "")
                with receiver.lock:
                    receiver.running.add(entry.name)
                threading.Thread(target=worker, args=(entry,), daemon=True).start()
            if not running:
                break  # nothing can start: a producer stopped short
            name, status, reason = finished.get()
            del running[name]
            summary = _read_json(base / name / "summary.json") or {}
            state.set(name, status=status, finished=_now(), usd=summary.get("usd"), model=summary.get("model"), reason=reason or None)
            halted = halted or status == "failed"
            if status == "unfinished":
                pending = [t for t in pending if name not in t.producers]
    finally:
        receiver.shutdown()
        lock.unlink(missing_ok=True)
    statuses = [state.status(t.name) for t in run_spec.tasks]
    result = "failed" if "failed" in statuses else "done" if all(s == "done" for s in statuses) else "unfinished"
    state.data.update(status=result, finished=_now())
    _write_json(state.path, state.data)
    return result


# --- status and attribution (Req 7.3) ------------------------------------------------------------------------------


def _number(value: object) -> float | None:
    return value if isinstance(value, int | float) and not isinstance(value, bool) else None


def _row(name: str, model: str | None, payload: Mapping[str, Any]) -> dict[str, Any]:
    raw = payload.get("usage")
    usage: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    row: dict[str, Any] = {"task": name, "model": model, "calls": _number(payload.get("calls", payload.get("turns")))}
    row.update({column: _number(usage.get(key)) for column, key in _USAGE_KEYS.items()})
    row["usd"] = _number(payload.get("usd"))
    return row


def _sum(rows: Iterable[Mapping[str, Any]], label: str, model: str | None) -> dict[str, Any]:
    """Column sums over rows bound to a Model; a missing value makes the sum ``n/a``, never a smaller number."""
    priced = [r for r in rows if r.get("model")]
    total: dict[str, Any] = {"task": label, "model": model}
    for column in _COLUMNS:
        values = [r.get(column) for r in priced]
        total[column] = None if not values or any(v is None for v in values) else round(sum(v or 0 for v in values), 6)
    return total


def _fmt(row: Mapping[str, Any]) -> str:
    cells = [str(row["task"])[:28], str(row.get("model") or "-")[:20]]
    for column in _COLUMNS:
        value = row.get(column)
        cells.append("n/a" if value is None else f"{value:.4f}" if column == "usd" else str(int(value)))
    return _ROW.format(*cells)


def attribution(run_name: str, *, units: bool = False, results_root: Path | None = None) -> dict[str, Any]:
    """Token attribution from the tasks' ``summary.json`` usage fields; ``units`` adds rows from ``units.jsonl``."""
    base = run_dir(run_name, results_root)
    state = _read_json(base / "state.json") or {}
    tasks: dict[str, dict[str, Any]] = state.get("tasks") or {}
    rows: list[dict[str, Any]] = []
    unit_rows: dict[str, list[dict[str, Any]]] = {}
    for name, info in tasks.items():
        summary = _read_json(base / name / "summary.json") or {}
        rows.append({**_row(name, summary.get("model") or info.get("model"), summary), "status": info.get("status")})
        if units and (base / name / "units.jsonl").is_file():
            lines = (base / name / "units.jsonl").read_text(encoding="utf-8").splitlines()
            unit_rows[name] = [
                _row(str(u.get("unit") or u.get("path") or u.get("candidate") or f"unit {i}"), rows[-1]["model"], u)
                for i, u in enumerate(json.loads(line) for line in lines if line.strip())
            ]
    names = sorted({r["model"] for r in rows if r["model"]})
    models = [_sum([r for r in rows if r["model"] == m], f"subtotal {m}", m) for m in names]
    return {"run": run_name, "tasks": rows, "models": models, "total": _sum(rows, "total", None), "units": unit_rows}


def status(run_name: str, *, units: bool = False, results_root: Path | None = None) -> str:
    """Per-task status and the attribution table (Req 3.2, 7.3); written to ``<run dir>/attribution.json``."""
    report = attribution(run_name, units=units, results_root=results_root)
    base = run_dir(run_name, results_root)
    state = _read_json(base / "state.json") or {}
    header = _ROW.format("TASK", "MODEL", "CALLS", "PROMPT", "CACHE-HIT", "OUTPUT", "USD")
    lines = [f"run {run_name}: {state.get('status') or 'not started'} ({base})", "", header]
    for row in report["tasks"]:
        lines.append(_fmt(row) + f"  [{row.get('status') or 'pending'}]")
        lines.extend("  " + _fmt(u) for u in report["units"].get(row["task"], []))
    lines.append("-" * len(header))
    lines.extend(_fmt(m) for m in report["models"])
    lines.append(_fmt(report["total"]))
    if base.is_dir():
        _write_json(base / "attribution.json", report)
    return "\n".join(lines)


# --- doctor (Req 3.5) ----------------------------------------------------------------------------------------------


def _sh(*args: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def _pods_ready(namespace: str, context: str) -> tuple[bool, str]:
    ok, out = _sh("kubectl", "--context", context, "-n", namespace, "get", "pods", "--no-headers")
    if not ok or not out:
        return False, out or "no pods"
    rows = [line.split() for line in out.splitlines()]
    bad = [r[0] for r in rows if len(r) > 2 and r[2] not in ("Completed", "Succeeded") and r[1].split("/")[0] != r[1].split("/")[-1]]
    return not bad, f"not ready: {', '.join(bad)}" if bad else f"{len(rows)} pods ready"


def doctor() -> list[tuple[str, bool, str]]:
    """Four checks of the host's ax: kind, Agent Substrate, the ax controller, the runner image (Req 3.5)."""
    context = "kind-" + (os.environ.get("KIND_CLUSTER_NAME") or "ousast")
    ok, out = _sh("kubectl", "--context", context, "cluster-info")
    checks = [("kind cluster", ok, "reachable" if ok else f"context {context} unreachable ({out[:80]}); {UP}")]
    for label, ns in (("agent substrate (ate-system)", "ate-system"), ("ax controller (ax-system)", "ax-system")):
        ok, out = _pods_ready(ns, context)
        checks.append((label, ok, out if ok else f"{out}; {UP}"))
    ok, out = _sh("curl", "-s", "localhost:5001/v2/_catalog")
    present = ok and "ousast-runner" in out
    text = "ousast-runner present" if present else f"missing from localhost:5001 ({out[:80]}); {UP} and loads it"
    checks.append(("runner image in kind registry", present, text))
    return checks


__all__ = ["Ax", "Receiver", "attribution", "doctor", "load_run", "outcome_of", "render_task", "run", "run_dir", "status"]
