"""The start signal through Agent Substrate's router (ai-service-plane Requirements 4.5, 4.6).

Agent Substrate boots every new ActorTemplate once as a temporary "golden" actor to capture a snapshot, with the
same image and the same task environment ax baked into the template, so a runner cannot tell that boot from the
real one. The runner therefore never starts its command by itself: it prepares the workspaces, reports ready and
waits for ``POST /ousast/v1/start``. The reconciler sends that request through Substrate's router
(``svc/atenet-router`` in ``ate-system``), which routes on ``ate-target-actor: <atespace>/<task>`` to the task's
actor only -- never to the golden one -- and resumes a suspended actor before proxying.

:func:`open_router` port-forwards the router to a random local port for the duration of a Run (or uses
``OUSAST_ROUTER_URL`` when set, as the tests do); :meth:`Router.start_task` posts the start body, retrying 502/503/504
and connection errors with backoff for up to ``OUSAST_START_TIMEOUT`` s (default 300). Provider credentials travel
only in that body: :func:`credentials` reads the variable a bound Model's ``secretKey`` names from this process's
environment (``ousast`` loads ``.env`` at startup); nothing here writes or logs a value.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import queue
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from .manifests import Model

__all__ = ["ALREADY_STARTED", "START_PATH", "Router", "StartError", "credentials", "open_router", "redact"]

START_PATH = "/ousast/v1/start"
ALREADY_STARTED = "already started on this boot"  # the runner's 409 when its command is running
NAMESPACE = "ate-system"
SERVICE = "svc/atenet-router"
TARGET_HEADER = "ate-target-actor"
RETRY_STATUS = frozenset({502, 503, 504})
_FORWARDING = re.compile(r"Forwarding from 127\.0\.0\.1:(\d+)")


class StartError(RuntimeError):
    """The start request was refused, or no actor answered it in time; the message carries the response text."""


def redact(text: str, secrets: Iterable[str]) -> str:
    """``text`` with every non-empty secret value replaced by ``[redacted]``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def credentials(model: Model | None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The provider credentials of a task bound to ``model``: ``{secretKey.key: value}`` from the environment.

    A task without a Model, or a Model without ``secretKey``, gets none. A named variable that is unset or empty
    raises :class:`StartError` naming the variable (never a value).
    """
    if model is None or model.secret_key is None:
        return {}
    env = os.environ if environ is None else environ
    name = model.secret_key.key
    value = env.get(name, "")
    if not value:
        where = f"secretKey {model.secret_key.name}; it is not set in this environment or .env"
        raise StartError(f"Model/{model.metadata.name} needs {name} ({where})")
    return {name: value}


class Router:
    """Posts start requests to one task actor at a time through the router at ``url``."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def starter(
        self, atespace: str, task: str, run: str, credentials: Mapping[str, str], delivery: Mapping[str, Any] | None = None
    ) -> Callable[[], str | None]:
        """:meth:`start_task` bound to one task, returning the refusal text instead of raising (None once accepted).

        The reconciler calls it again after a re-resume, since a resumed actor may have rebooted and wait for a
        start; on those later calls a 409 saying the command is already started on this boot means the process
        tree survived and the command is still running, which is not a failure.
        """
        calls = 0

        def start() -> str | None:
            nonlocal calls
            calls += 1
            try:
                self.start_task(atespace, task, run, credentials, delivery)
            except StartError as exc:
                return None if calls > 1 and ALREADY_STARTED in str(exc) else str(exc)
            return None

        return start

    def start_task(
        self, atespace: str, task: str, run: str, credentials: Mapping[str, str], delivery: Mapping[str, Any] | None = None
    ) -> None:
        """Start ``<atespace>/<task>``'s command once; :class:`StartError` on 409, another 4xx, or the timeout.
        ``delivery`` (``{put, inputs}`` presigned URLs, ``delivery.py``) rides in the body like the credentials and is
        redacted like them."""
        payload: dict[str, Any] = {"run": run, "task": task, "credentials": dict(credentials)}
        if delivery:
            payload["delivery"] = dict(delivery)
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", TARGET_HEADER: f"{atespace}/{task}"}
        limit = float(os.environ.get("OUSAST_START_TIMEOUT") or 300)
        deadline, backoff, last = time.monotonic() + limit, 0.5, "no attempt made"
        secrets = list(credentials.values())
        if delivery:
            secrets.append(str(delivery.get("put") or ""))
            secrets.extend(str(u) for u in (delivery.get("inputs") or {}).values())
        while True:
            request = urllib.request.Request(self.url + START_PATH, data=body, method="POST", headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - the router's local URL
                    if 200 <= int(response.status) < 300:
                        return
                    last = f"HTTP {response.status}"
            except urllib.error.HTTPError as exc:
                text = redact(exc.read().decode("utf-8", errors="replace").strip()[:400], secrets)
                if exc.code not in RETRY_STATUS:
                    raise StartError(f"start of {atespace}/{task} refused (HTTP {exc.code}): {text}") from None
                last = f"HTTP {exc.code}: {text}"
            except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
                last = redact(f"{type(exc).__name__}: {exc}", secrets)
            if time.monotonic() + backoff > deadline:
                raise StartError(f"start of {atespace}/{task} not accepted within {limit:g}s (OUSAST_START_TIMEOUT): {last}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 10.0)


def _drain(stream: Iterable[str], lines: queue.Queue[str | None]) -> None:
    for line in stream:  # kubectl logs a line per proxied connection; an unread pipe would block it
        lines.put(line)
    lines.put(None)


@contextlib.contextmanager
def open_router(context: str, *, url: str | None = None, kubectl: str = "kubectl", ready_timeout: float = 30.0) -> Iterator[Router]:
    """A :class:`Router` for the duration of the block.

    ``url`` (the profile's ``router_url``) or ``OUSAST_ROUTER_URL`` set: that URL, nothing started. Otherwise
    ``kubectl port-forward svc/atenet-router :80`` in ``ate-system`` of the profile's ``context`` (ax-tunnel: the
    Kubernetes API is the one authenticated door), the local port read from kubectl's ``Forwarding from
    127.0.0.1:NNNN`` line; on exit that child process is terminated. No context is ever built here.
    """
    override = url or os.environ.get("OUSAST_ROUTER_URL")
    if override:
        yield Router(override)
        return
    if not context:
        raise StartError("open_router needs the profile's kube context (or router_url)")
    argv = [kubectl, "--context", context, "-n", NAMESPACE, "port-forward", SERVICE, ":80"]
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        assert proc.stdout is not None
        lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=_drain, args=(proc.stdout, lines), name="router-port-forward", daemon=True).start()
        deadline, seen, port = time.monotonic() + ready_timeout, list[str](), None
        while port is None:
            try:
                line = lines.get(timeout=max(deadline - time.monotonic(), 0.01))
            except queue.Empty:
                raise StartError(f"kubectl port-forward printed no port within {ready_timeout:g}s: {''.join(seen)[-400:]}") from None
            if line is None:
                raise StartError(f"kubectl port-forward exited ({proc.wait()}): {''.join(seen)[-400:]}")
            seen.append(line)
            match = _FORWARDING.search(line)
            port = int(match.group(1)) if match else None
        yield Router(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
