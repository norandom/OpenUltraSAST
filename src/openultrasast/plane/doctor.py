"""``ousast plane doctor``: four checks of this host's ax before a Run is submitted (ai-service-plane Req 3.5).

A sibling of ``reconciler.py`` (tasks.md task 0 allows either), which re-exports :func:`doctor`.
"""

from __future__ import annotations

import os
import re
import subprocess

UP = "ops/ax/up.sh brings it up"


# --- checks ----------------------------------------------------------------------------------------------


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
    rows = [r for r in (line.split() for line in out.splitlines()) if len(r) > 2 and re.fullmatch(r"\d+/\d+", r[1])]
    if not rows:  # "No resources found" is not a ready namespace
        return False, f"no pods in {namespace}"
    bad = [r[0] for r in rows if r[2] not in ("Completed", "Succeeded") and r[1].split("/")[0] != r[1].split("/")[1]]
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


__all__ = ["doctor"]
