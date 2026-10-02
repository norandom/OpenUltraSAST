"""ax-backed reconciler of a ``Run``: submission, resume, start, completion by delivery (ai-service-plane Req 3, 4, 7).

ax executes every task on the profile's cluster (``profile.py``: kube context, registry, store); nothing here runs a
task locally or knows a prompt, a score or a model call. Per ready task: one rendered YAML file (the Task with its
env extended, its Workspaces, the bound Model), ``ax apply -f``, ``ax resume task`` (retried on
DeadlineExceeded/Unavailable -- a new image's first resume waits for Agent Substrate's golden snapshot -- for up to
``OUSAST_RESUME_TIMEOUT`` s, 900), and once ax says
``Running`` one start request through Substrate's router (``router.py``, Req 4.5) carrying the bound Model's
credential from this process's environment, never from a file (Req 4.6). Completion is the runner's artifact
delivery (ax has no Completed phase); ``Failed``, the task vanishing, a refused start or ``OUSAST_TASK_TIMEOUT`` s
(7200) without delivery fail it; ``ax delete task`` follows.

ax rejects unknown fields, so rendered documents carry only ax's fields; ``openultrasast.io/model`` reaches the
task as ``OUSAST_MODEL`` plus ``OUSAST_MODEL_PARAMS`` (Req 7.1), each Workspace's pin annotation as
``OUSAST_GIT_PINS``. Inputs other tasks produced are never rendered: ``OUSAST_INPUTS`` maps each input's name to
``<producer>/<artifact>``, which the runner fetches after the start from the receiver's ``GET /inputs/...`` to
``OUSAST_INPUT_<NAME>`` under ``/workspace/.ousast-in/<task>`` (the receiver serves a running task its declared
inputs only). The receiver takes the runner's tar (``X-Ousast-Run``, ``X-Ousast-Task``) on
``OUSAST_ARTIFACT_PORT`` (18090), reached by its Service name through the egress gateway; between ``ax apply`` and
resume the task's egress policy is written (``egress.py``).
State: ``~/ousast-results/plane/<run>/`` (``OUSAST_RESULTS``), polled every ``OUSAST_POLL_SECONDS`` (3).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .doctor import doctor
from .egress import RECEIVER_PORT, Egress, Receiver, policy_for
from .manifests import AX_API_VERSION, Manifests, Model, Run, RunTask, Task, Workspace, load_manifests
from .profile import PlaneProfile, load_profile
from .router import Router, credentials, open_router

MODEL_ANNOTATION = "openultrasast.io/model"
OUTPUT_ROOT = "/workspace/.ousast-out"
INPUTS_ROOT = "/workspace/.ousast-in"
TRANSIENT = re.compile(r"deadline ?exceeded|unavailable", re.IGNORECASE)  # the golden-snapshot build outlives a resume
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


# ax names a task's ActorTemplate "<task>-tmpl-<8 hex>" and Substrate caps names at 63 bytes (live, 2026-09-29).
TASK_NAME_LIMIT = 63 - len("-tmpl-12345678")


def _ax_name(*parts: str, limit: int = 63) -> str:
    """An RFC 1123 label; a name over ``limit`` keeps a readable prefix plus a stable hash, so two never collide."""
    name = re.sub(r"[^a-z0-9-]+", "-", "-".join(parts).lower()).strip("-")
    if len(name) <= limit:
        return name
    digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
    return f"{name[: limit - 9].rstrip('-')}-{digest}"


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


def _doc(kind: str, name: str, spec: dict[str, Any], atespace: str | None = None) -> dict[str, Any]:
    meta = {"name": name, **({"atespace": atespace} if atespace else {})}
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
    return _doc("Workspace", ws.metadata.name, spec, ws.metadata.atespace)


def _model_doc(model: Model) -> dict[str, Any]:
    spec: dict[str, Any] = {"provider": model.provider, "model": model.model}
    if model.secret_key:
        spec["secretKey"] = _fields(model.secret_key)
    if model.parameters:
        spec["parameters"] = dict(model.parameters)
    return _doc("Model", model.metadata.name, spec, model.metadata.atespace)


def render_task(run: Run, entry: RunTask, manifests: Manifests, artifact_url: str, dial: str | None = None) -> list[dict[str, Any]]:
    """The documents ``ax apply`` receives for one Run task: its Model, its Workspaces, the Task last. Task-produced
    inputs are never rendered: ax puts every bound Workspace into one env value, which Substrate caps at 32768
    characters, so the runner fetches them from the receiver (``OUSAST_INPUTS``) after the start."""
    task: Task = manifests.tasks[entry.task]
    ax_name = _ax_name(run.metadata.name, entry.name, limit=TASK_NAME_LIMIT)
    env = {e.name: e.value for e in task.env}
    env.update(OUSAST_RUN=run.metadata.name, OUSAST_TASK=entry.name, OUSAST_OUTPUT_DIR=f"{OUTPUT_ROOT}/{entry.name}")
    env.update(OUSAST_ARTIFACT_URL=artifact_url, **({"OUSAST_ARTIFACT_DIAL": dial} if dial else {}))
    budget = _fields(entry.budget) if entry.budget else {}
    env.update({f"OUSAST_BUDGET_{k.upper()}": str(v) for k, v in budget.items()})
    inputs = {re.sub(r"[^A-Z0-9]+", "_", name.upper()): ref for name, ref in entry.inputs.items()}
    env.update({f"OUSAST_INPUT_{name}": f"{INPUTS_ROOT}/{entry.name}/{ref}" for name, ref in inputs.items()})
    env.update({"OUSAST_INPUTS": json.dumps(inputs, sort_keys=True)} if inputs else {})
    docs: list[dict[str, Any]] = []
    model_name = task.metadata.annotations.get(MODEL_ANNOTATION)
    if model_name:
        model = manifests.models[model_name]
        env.update(OUSAST_MODEL=model_name, OUSAST_MODEL_PARAMS=json.dumps(dict(model.parameters), sort_keys=True))
        docs.append(_model_doc(model))
    bindings = [_fields(b) for b in task.workspaces]
    docs.extend(_workspace_doc(manifests.workspaces[b.name]) for b in task.workspaces)
    pins = {f"{b.name}/{git}": sha for b in task.workspaces for git, sha in manifests.workspaces[b.name].pins.items()}
    env.update({"OUSAST_GIT_PINS": json.dumps(pins, sort_keys=True)} if pins else {})
    spec: dict[str, Any] = {"command": list(task.command), "env": [{"name": k, "value": v} for k, v in env.items()]}
    if task.image:
        spec["image"] = task.image
    if task.resources:
        spec["resources"] = {k: _fields(v) for k, v in _fields(task.resources).items()}
    if bindings:
        spec["workspaces"] = bindings
    if task.debug:
        spec["debug"] = True
    return [*docs, _doc("Task", ax_name, spec, task.metadata.atespace)]  # ax snapshots bound Workspaces at Task create


class Ax:
    """The four ``ax`` verbs the reconciler uses; the executable path is injectable so tests use a fake."""

    def __init__(self, executable: str = "ax") -> None:
        self.executable = executable

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.executable, *args], capture_output=True, text=True, check=False)

    def _error(self, proc: subprocess.CompletedProcess[str]) -> str:
        return proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"

    def apply(self, path: Path) -> None:
        proc = self._run("apply", "-f", str(path))
        if proc.returncode != 0:
            raise RuntimeError(f"ax apply failed ({proc.returncode}): {self._error(proc)}")

    def resume(self, name: str) -> str | None:
        """``ax resume task <name>``: None once ax accepted it, else ax's error text."""
        proc = self._run("resume", "task", name)
        return None if proc.returncode == 0 else self._error(proc)

    def phase(self, name: str) -> tuple[str, str]:
        """(``status.phase``, the Ready condition's message) from ``ax get task`` YAML; ``Pending`` while unset,
        ``Gone`` when ax no longer knows the task, ``Unknown`` when ax itself fails."""
        proc = self._run("get", "task", name)
        if proc.returncode != 0:
            return ("Gone" if re.search(r"not ?found", self._error(proc), re.IGNORECASE) else "Unknown"), self._error(proc)
        try:
            doc = yaml.safe_load(proc.stdout)
        except yaml.YAMLError:
            return "Unknown", "unreadable ax output"
        status = doc.get("status") if isinstance(doc, dict) else None
        if not isinstance(status, dict):
            return "Pending", ""
        conditions = [c for c in status.get("conditions") or [] if isinstance(c, dict)]
        ready = [c for c in conditions if c.get("type") == "Ready"] or conditions
        return str(status.get("phase") or "Pending"), str(ready[-1].get("message") or "") if ready else ""

    def delete(self, name: str) -> None:
        """``ax delete task <name>``; ax returns once the actor is torn down."""
        self._run("delete", "task", name)


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


def outcome_of(summary: Mapping[str, Any] | None) -> tuple[str, str]:
    """(status, reason) of a delivered task from its ``summary.json``: done only when every unit is."""
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
        with contextlib.suppress(OSError):
            os.kill(pid, 0)
            raise RuntimeError(f"run is held by pid {pid} ({lock})")
    lock.write_text(json.dumps(os.getpid()), encoding="utf-8")
    return lock


def mark_done(run_name: str, task: str, *, reused: Mapping[str, Any], results_root: Path | None = None) -> None:
    """Set ``task`` done without running it (its outputs came from the memory store), under the run lock."""
    base = run_dir(run_name, results_root)
    base.mkdir(parents=True, exist_ok=True)
    lock = _acquire_lock(base)
    try:
        state = _State(base / "state.json", _read_json(base / "state.json") or {"run": run_name, "started": _now(), "tasks": {}})
        state.set(task, status="done", finished=_now(), usd=None, model=None, reused=dict(reused))
    finally:
        lock.unlink(missing_ok=True)


def _await(ax: Ax, name: str, delivered: Callable[[], bool], start: Callable[[], str | None]) -> str | None:
    """Resume ``name``, ``start`` it once Running (again after a re-resume), await delivery: None, else why it failed.
    ``Failed`` is final only once a resume went through (ax sets it when a resume call fails); until then a
    DeadlineExceeded/Unavailable resume is retried with doubling backoff inside ``OUSAST_RESUME_TIMEOUT``."""
    task_limit, poll = float(os.environ.get("OUSAST_TASK_TIMEOUT") or 7200), float(os.environ.get("OUSAST_POLL_SECONDS") or 3)
    resume_limit = float(os.environ.get("OUSAST_RESUME_TIMEOUT") or 900)
    started = time.monotonic()
    resuming: float | None = started  # when the current resume spell began; None while ax runs the task
    retry_at, backoff, last, unknown, phase, sent = started, poll, "", 0, "Suspended", False
    while not delivered():
        now = time.monotonic()
        if now - started > task_limit:
            return f"no delivery within {task_limit:g}s (OUSAST_TASK_TIMEOUT); ax phase {phase}"
        if resuming is not None and now >= retry_at:
            if now - resuming > resume_limit:
                return f"ax resume did not succeed within {resume_limit:g}s (OUSAST_RESUME_TIMEOUT): {last}"
            error = ax.resume(name)
            if error is None:
                resuming = None
            elif TRANSIENT.search(error):
                last, retry_at, backoff = error, now + backoff, min(backoff * 2, 60.0)
            else:
                return f"ax resume failed: {error}"
        time.sleep(poll)
        if delivered():
            break
        phase, message = ax.phase(name)
        unknown = unknown + 1 if phase == "Unknown" else 0
        if phase == "Gone":
            return f"the task disappeared from ax before delivery: {message}"
        if unknown >= 10:  # ten consecutive unreadable polls: ax itself is broken, not the task
            return f"ax get task keeps failing: {message}"
        if resuming is None and phase == "Failed":
            return f"ax phase Failed: {message}"
        if resuming is None and phase == "Suspended":
            resuming, retry_at, backoff, sent = time.monotonic(), 0.0, poll, False
        if resuming is None and phase == "Running" and not sent:
            sent, refused = True, start()  # through Substrate's router: the golden actor is never addressed (Req 4.5)
            if refused and not delivered():
                return refused
    return None


def _execute(
    ax: Ax, egress: Egress, run: Run, entry: RunTask, manifests: Manifests, base: Path, receiver: Receiver, router: Router
) -> tuple[str, str]:
    ax_name, task = _ax_name(run.metadata.name, entry.name, limit=TASK_NAME_LIMIT), manifests.tasks[entry.task]
    atespace, manifest = task.metadata.atespace or "default", base / entry.name / "task.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    docs = render_task(run, entry, manifests, receiver.url, receiver.dial)
    manifest.write_text(yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8")
    model = manifests.models.get(task.metadata.annotations.get(MODEL_ANNOTATION) or "")
    policy = policy_for(task, [manifests.workspaces[b.name] for b in task.workspaces], model, urlsplit(receiver.url).hostname)
    try:  # Req 4.6: the bound Model's credential is read here and only ever sent in the start request
        start = router.starter(atespace, ax_name, run.metadata.name, credentials(model))
        ax.apply(manifest)  # creates the Substrate actor; its egress is denied until the policy exists
        egress.apply(ax_name, atespace, policy)
        egress.settle()
    except RuntimeError as exc:  # StartError included: a Model-bound task whose secret is unset
        ax.delete(ax_name)
        return "failed", str(exc)
    try:
        failure = _await(ax, ax_name, lambda: entry.name in receiver.delivered, start)
    finally:
        ax.delete(ax_name)
        leftover = egress.delete(ax_name, atespace)  # the policy goes with its actor; a survivor is reported
        if leftover:
            print(leftover, file=sys.stderr)
    return ("failed", failure) if failure else outcome_of(_read_json(base / entry.name / "summary.json"))


def run(
    run_manifest: Path,
    *,
    workers: int = 1,
    ax: str = "ax",
    results_root: Path | None = None,
    kubectl_ate: str | None = None,
    profile: PlaneProfile | None = None,
) -> str:
    """Execute a Run on ax and return its status: ``done``, ``unfinished`` or ``failed`` (Req 3.1-3.3, 2.2). Every
    address comes from ``profile`` (default: the one ``OUSAST_PLANE_PROFILE`` names)."""
    profile = profile or load_profile()
    run_spec, manifests = load_run(Path(run_manifest))
    base = run_dir(run_spec.metadata.name, results_root)
    base.mkdir(parents=True, exist_ok=True)
    lock = _acquire_lock(base)
    state = _State(base / "state.json", _read_json(base / "state.json") or {"run": run_spec.metadata.name, "started": _now(), "tasks": {}})
    port = os.environ.get("OUSAST_ARTIFACT_PORT") or (0 if os.environ.get("OUSAST_ARTIFACT_HOST") else RECEIVER_PORT)
    receiver = Receiver(run_spec.metadata.name, base, int(port), profile.kube_context)  # the Service targets RECEIVER_PORT
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    cli, egress, finished = Ax(ax), Egress(kubectl_ate, profile.kube_context), queue.Queue[tuple[str, str, str]]()
    pending = [t for t in run_spec.tasks if state.status(t.name) != "done"]
    for entry in run_spec.tasks:
        state.set(entry.name, **({"status": "pending"} if entry in pending else {}))
    running: dict[str, RunTask] = {}
    halted = False

    def worker(entry: RunTask) -> None:
        if state.status(entry.name) in ("running", "suspended"):
            cli.delete(_ax_name(run_spec.metadata.name, entry.name, limit=TASK_NAME_LIMIT))  # an interrupted attempt; ax must not keep it
        state.set(entry.name, status="running", started=_now(), finished=None)
        finished.put((entry.name, *_execute(cli, egress, run_spec, entry, manifests, base, receiver, router)))

    try:
        with open_router(profile.kube_context, url=profile.router_url or None) as router:  # one tunnel per run (ax-tunnel)
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
                    with receiver.lock:  # the receiver serves a running task its declared inputs, nothing else
                        receiver.running.add(entry.name)
                        receiver.inputs[entry.name] = frozenset(entry.inputs.values())
                    threading.Thread(target=worker, args=(entry,), daemon=True).start()
                if not running:
                    break  # nothing can start: a producer stopped short
                name, status, reason = finished.get()
                del running[name]
                with receiver.lock:
                    receiver.running.discard(name)
                    receiver.inputs.pop(name, None)
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


__all__ = ["Ax", "Receiver", "attribution", "doctor", "load_run", "mark_done", "outcome_of", "render_task", "run", "run_dir", "status"]
