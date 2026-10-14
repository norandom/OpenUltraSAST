"""Per-task TLS egress to the store, Git hosts and model endpoints.

The gateway denies by default. Egress writes and checks each actor's policy before resume,
then waits for the cached denial to expire. Deleting the actor removes its policy.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from .manifests import Model, Task, Workspace

__all__ = [
    "Egress",
    "git_hosts",
    "policy_for",
    "rules_of",
]

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
) -> dict[str, Any]:
    """The task's EgressPolicy body (plane-on-kubernetes design section 3): one ``tlsPassthrough`` rule on 443 over
    the sorted union of the store's hostname (``store_host``: where the runner PUTs its tar and GETs its inputs), the
    bound Workspaces' https Git hosts and the bound Model's ``openultrasast.io/egress-hosts``. An http Git repo cannot be reached under
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
