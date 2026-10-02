"""Per-task network egress on Agent Substrate (ai-service-plane, task 0: gateway + receiver Service).

Every TCP connection an actor opens (DNS aside) is redirected to Substrate's egress gateway
(``atenet-egress.ate-system``), which denies by default: an actor without an ``EgressPolicy`` gets no tunnel, and
a refused connection is accepted and then closed. :func:`policy_for` grants a task exactly what it needs:

* ``http`` on port 80 to the artifact receiver's cluster name (``ousast-receiver.ax-system.svc.cluster.local``, a
  selector-less Service whose endpoint is this host's receiver, ``ops/ax/receiver-service.yaml.tmpl``). The actor
  cannot resolve cluster names, so the runner dials ``OUSAST_ARTIFACT_DIAL`` (the Service's ClusterIP, port 80)
  with the receiver's name as ``Host``. The gateway decides the policy on that ``Host`` but connects to the
  address the actor dialled (measured live: agentgateway's upstream is the CONNECT authority, not the Host), so
  the dial address must be one the gateway pod reaches: the ClusterIP, which kube-proxy maps to the host.
* ``tls_passthrough`` on 443 for the Git hosts of the bound Workspaces' ``https`` repos (smart HTTP talks to the
  repo's host only) and for the bound Model's ``openultrasast.io/egress-hosts`` (``api.deepseek.com``).

Nothing else: no wildcard, no IP address (the gateway rejects them), no ``https`` rule (that one intercepts TLS and
the actor would have to trust the gateway CA, which ax templates do not mount). :class:`Egress` writes the policy
with ``kubectl ate create egress-policy`` after ``ax apply`` created the actor, reads it back, and before resume
waits ``OUSAST_EGRESS_SETTLE`` s (11) because the gateway caches a missing policy as deny for 10 s. The kubectl-ate
CLI has no delete verb: Substrate's store deletes the policy with its actor (``ON DELETE CASCADE``), so
:meth:`Egress.delete` runs after ``ax delete task`` and confirms the policy is gone.
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import shutil
import subprocess
import tarfile
import threading
import time
from collections.abc import Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .manifests import Model, Task, Workspace

__all__ = [
    "INPUTS_PATH",
    "RECEIVER_HOST",
    "RECEIVER_PORT",
    "Egress",
    "Receiver",
    "git_hosts",
    "receiver_cluster_ip",
    "policy_for",
    "receiver_address",
    "rules_of",
]

RECEIVER_HOST = "ousast-receiver.ax-system.svc.cluster.local"
INPUTS_PATH = "/inputs/"  # GET <receiver>/inputs/<producer>/<artifact>: a consumer fetches a declared input
RECEIVER_PORT = 18090  # the receiver Service's targetPort; ops/ax/up.sh renders the Service with the same number
_NOT_FOUND = ("not found", "notfound")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def git_hosts(workspaces: Iterable[Workspace]) -> tuple[list[str], list[str]]:
    """(https hosts, http hosts) of the Workspaces' ``spec.git[].repo`` URLs; ssh and IP-address repos add nothing."""
    tls, plain = set[str](), set[str]()
    for ws in workspaces:
        for source in ws.git:
            parts = urlsplit(source.repo)
            host = (parts.hostname or "").lower()
            if (
                host
                and not _is_ip(host)
                and parts.scheme in ("https", "http")
                and parts.port in (None, 443 if parts.scheme == "https" else 80)
            ):
                (tls if parts.scheme == "https" else plain).add(host)
    return sorted(tls), sorted(plain)


def policy_for(
    task: Task,
    workspaces: Iterable[Workspace],
    model: Model | None,
    store_host: str | None,
    receiver_host: str | None = None,
) -> dict[str, Any]:
    """The task's EgressPolicy body (plane-on-kubernetes design section 3): one ``tlsPassthrough`` rule on 443 over
    the sorted union of the store's hostname (``store_host``: where the runner PUTs its tar and GETs its inputs), the
    bound Workspaces' https Git hosts and the bound Model's ``openultrasast.io/egress-hosts``. No ``http`` rule, unless
    ``receiver_host`` names the old receiver (the path task 2.6 removes). An http Git repo cannot be reached under
    this policy and is refused; a store given as an address is refused naming ``S3_ENDPOINT`` (the gateway allows
    hostnames only)."""
    tls, plain = git_hosts(workspaces)
    if plain:
        raise ValueError(f"Task/{task.metadata.name}: http Git repos ({', '.join(plain)}) cannot be reached: the policy grants TLS only")
    hosts = set(tls) | set(model.egress_hosts if model else ())
    if store_host:
        if _is_ip(store_host):
            raise ValueError(f"Task/{task.metadata.name}: the store endpoint is an address ({store_host}); S3_ENDPOINT must be a hostname")
        hosts.add(store_host.lower())
    rules: list[dict[str, Any]] = []
    if receiver_host and not _is_ip(receiver_host):  # the receiver path, kept for group 2 only (task 2.6 deletes it)
        rules.append({"http": {"hostnames": [receiver_host.lower()], "ports": {"numbers": [80]}}})
    if hosts:
        rules.append({"tlsPassthrough": {"hostnames": sorted(hosts), "ports": {"numbers": [443]}}})
    return {"rules": rules}


def rules_of(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The rules of a policy as ``kubectl ate get -o json`` prints them, normalised for comparison."""
    out = []
    for rule in policy.get("rules") or []:
        for kind, body in rule.items():
            key = "tlsPassthrough" if kind in ("tls_passthrough", "tlsPassthrough") else kind
            ports = body.get("ports") or {}
            norm_ports: dict[str, Any] = {"all": {}} if "all" in ports else {"numbers": sorted(int(n) for n in ports.get("numbers") or [])}
            out.append({key: {"hostnames": sorted(body.get("hostnames") or []), "ports": norm_ports}})
    return sorted(out, key=lambda r: json.dumps(r, sort_keys=True))


def receiver_cluster_ip(context: str) -> str | None:
    """The ClusterIP of the ``ousast-receiver`` Service (``kubectl get svc`` in the profile's ``context``); None when
    kubectl cannot say."""
    if not context:
        raise RuntimeError("receiver_cluster_ip needs the profile's kube context")
    argv = ["kubectl", "--context", context, "-n", "ax-system", "get", "svc", "ousast-receiver", "-o", "jsonpath={.spec.clusterIP}"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    address = proc.stdout.strip()
    return address if proc.returncode == 0 and _is_ip(address) else None


def receiver_address(port: int, context: str | None) -> tuple[str, str | None]:
    """(``OUSAST_ARTIFACT_URL``, ``OUSAST_ARTIFACT_DIAL``) for a receiver bound on ``port``; ``context`` is the
    profile's kube context the Service's ClusterIP is looked up in.

    ``OUSAST_ARTIFACT_HOST`` set: the old direct URL ``http://<host>:<port>/`` and no dial (tests, a host the actor
    reaches without the gateway). Otherwise the receiver Service's name, dialled at ``OUSAST_ARTIFACT_DIAL`` or the
    Service's ClusterIP on port 80: the gateway checks the policy against ``Host`` but connects to the address the
    actor dialled (its CONNECT authority), so that address must reach the receiver from the gateway pod.
    """
    host = os.environ.get("OUSAST_ARTIFACT_HOST")
    if host:
        return f"http://{host}:{port}/", None
    dial = os.environ.get("OUSAST_ARTIFACT_DIAL")
    if not dial:
        if not context:
            raise RuntimeError("receiver_address needs the profile's kube context to look the receiver Service up")
        address = receiver_cluster_ip(context)
        dial = f"{address}:80" if address else None
    return f"http://{RECEIVER_HOST}/", dial


class Egress:
    """``kubectl ate`` for one actor's egress policy; the executable is injectable so tests use a fake."""

    def __init__(self, executable: str | None, context: str) -> None:
        if not context:
            raise ValueError("Egress needs the profile's kube context; it never builds one")
        self.executable = executable or os.environ.get("OUSAST_KUBECTL_ATE") or "kubectl-ate"
        self.context = context

    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        argv = [self.executable, "--context", self.context, *args]
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)

    @staticmethod
    def _error(proc: subprocess.CompletedProcess[str]) -> str:
        return (proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}")[-400:]

    def get(self, actor: str, atespace: str) -> dict[str, Any] | None:
        """The stored policy, None when there is none (or no actor); RuntimeError when kubectl-ate fails otherwise."""
        proc = self._run("get", "egress-policy", actor, "-a", atespace, "-o", "json")
        if proc.returncode != 0:
            if "notfound" in self._error(proc).lower().replace(" ", ""):
                return None
            raise RuntimeError(f"kubectl ate get egress-policy {atespace}/{actor} failed: {self._error(proc)}")
        if not proc.stdout.strip():  # an actor without a policy: exit 0, "has no egress policy" on stderr only
            return None
        try:
            doc = json.loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError(f"kubectl ate get egress-policy {atespace}/{actor}: unreadable output ({exc})") from None
        return doc if isinstance(doc, dict) else None

    def apply(self, actor: str, atespace: str, policy: Mapping[str, Any], *, timeout: float | None = None) -> None:
        """Create (or replace) the policy, retrying while the actor does not exist yet, then read it back."""
        limit = float(os.environ.get("OUSAST_EGRESS_TIMEOUT") or 60) if timeout is None else timeout
        deadline, backoff = time.monotonic() + limit, 0.5
        while True:
            existing = self.get(actor, atespace)
            if existing is None:
                proc = self._run("create", "egress-policy", actor, "-a", atespace, "-f", "-", stdin=json.dumps(dict(policy)))
            else:
                meta = {k: existing.get("metadata", {}).get(k) for k in ("name", "atespace", "uid", "version")}
                body = json.dumps({**dict(policy), "metadata": meta})
                proc = self._run("update", "egress-policy", actor, "-a", atespace, "-f", "-", stdin=body)
            if proc.returncode == 0:
                break
            error = self._error(proc)
            retry = any(word in error.lower() for word in (*_NOT_FOUND, "already exists", "conflict", "unavailable"))
            if not retry or time.monotonic() + backoff > deadline:
                raise RuntimeError(f"egress policy for {atespace}/{actor} not written: {error}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 5.0)
        stored = self.get(actor, atespace)
        if stored is None or rules_of(stored) != rules_of(policy):
            raise RuntimeError(f"egress policy for {atespace}/{actor} reads back {stored!r}, not {dict(policy)!r}")

    def delete(self, actor: str, atespace: str) -> str | None:
        """After ``ax delete task``: None once the policy is gone with its actor, else why it is still there."""
        try:
            stored = self.get(actor, atespace)
        except RuntimeError as exc:
            return str(exc)
        return None if stored is None else f"egress policy for {atespace}/{actor} outlived its actor"

    @staticmethod
    def settle() -> None:
        """Wait out the gateway's cached deny (10 s) before the actor's first connection: ``OUSAST_EGRESS_SETTLE``."""
        time.sleep(float(os.environ.get("OUSAST_EGRESS_SETTLE") or 11))


class Receiver(ThreadingHTTPServer):
    """Accepts one tar per running task and extracts it under ``<run dir>/<task>/`` (POST); serves a running task
    the producer artifacts it declared as inputs (``GET /inputs/<producer>/<artifact>``, ``inputs[task]``)."""

    daemon_threads = True

    def __init__(self, run_name: str, base: Path, port: int, context: str | None = None) -> None:
        super().__init__(("0.0.0.0", port), _Handler)
        self.run_name, self.base, self.running, self.delivered = run_name, base, set[str](), set[str]()
        self.inputs: dict[str, frozenset[str]] = {}
        self.lock = threading.Lock()
        self.url, self.dial = receiver_address(self.server_address[1], context)

    def _task(self, headers: Any) -> str | None:
        """The ``X-Ousast-Task`` of a request naming this run and a task that is running now, else None."""
        task = str(headers.get("X-Ousast-Task", ""))
        with self.lock:
            return task if headers.get("X-Ousast-Run") == self.run_name and task in self.running else None

    def input_file(self, headers: Any, ref: str) -> tuple[int, str | Path]:
        """(200, the file) when ``ref`` is one of the requesting task's declared inputs, else (403/404, why).

        ``ref`` must equal a declared ``<producer>/<artifact>`` exactly and resolve to a regular file under the run
        directory; nothing is normalised first, so ``..`` or an absolute path never names a declared input."""
        task = self._task(headers)
        if task is None:
            return 403, "unknown run or task"
        with self.lock:
            declared = ref in self.inputs.get(task, frozenset())
        if not declared:
            return 403, f"{ref!r} is not an input of {task}"
        root = self.base.resolve()
        path = (root / ref).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return 404, f"{ref} was not delivered"
        return 200, path

    def accept(self, headers: Any, body: bytes) -> tuple[int, str]:
        task = self._task(headers)
        if task is None:
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
    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        server: Receiver = self.server  # type: ignore[assignment]
        path = urlsplit(self.path).path
        if not path.startswith(INPUTS_PATH):
            self._text(404, "not found")
            return
        code, found = server.input_file(self.headers, unquote(path[len(INPUTS_PATH) :]))
        if not isinstance(found, Path):
            self._text(code, found)
            return
        with found.open("rb") as source:  # streamed: a producer artifact can be far larger than any env value
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(os.fstat(source.fileno()).st_size))
            self.end_headers()
            shutil.copyfileobj(source, self.wfile, 1 << 16)

    def do_POST(self) -> None:  # noqa: N802 - http.server's naming
        server: Receiver = self.server  # type: ignore[assignment]
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._text(*server.accept(self.headers, body))

    def _text(self, code: int, text: str) -> None:
        data = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        return
