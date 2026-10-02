"""``ousast plane doctor``: checks of the configured cluster before a Run is submitted (ai-service-plane Req 3.5,
plane-on-kubernetes Req 1.2).

Everything is read from the :class:`~openultrasast.plane.profile.PlaneProfile`: the kube context is checked for
reachability and, when reachable, the two namespaces for ready pods; the ``images`` file's runner reference is
resolved in its registry (a local registry over its v2 API, a remote one through ``docker manifest inspect``); the
memory store is opened, which verifies an S3 bucket; and the first line reports every configured address. Nothing
here names a cluster, a registry or an address of its own: those are the profile's.

A sibling of ``reconciler.py`` (tasks.md task 0 allows either), which re-exports :func:`doctor`.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import urllib.error
import urllib.request

from .profile import PlaneProfile, ProfileError, load_profile

UP = "ops/ax/up.sh brings it up"
RUNBOOK = "docs/deployment.md lists the prerequisites"
_MANIFEST_TYPES = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


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


def _is_local(registry: str) -> bool:
    host = registry.rsplit(":", 1)[0] if re.search(r":\d+$", registry) else registry
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback or ipaddress.ip_address(host.strip("[]")).is_private
    except ValueError:
        return False


def _registry_has(image: str) -> tuple[bool, str]:
    """Resolve a digest-pinned reference ``<registry>/<repository>@sha256:<hex>``: a local registry answers its v2
    API for the manifest by digest (plain HTTP, as kind's registry speaks); a remote one is asked through
    ``docker manifest inspect``, which carries the operator's registry login."""
    name, _, digest = image.partition("@")
    registry, _, repository = name.partition("/")
    short = f"{repository}@{digest[:19]}..."
    if _is_local(registry):
        url = f"http://{registry}/v2/{repository}/manifests/{digest}"
        request = urllib.request.Request(url, method="HEAD", headers={"Accept": _MANIFEST_TYPES})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - the profile's registry
                found = 200 <= int(response.status) < 300
        except urllib.error.HTTPError as exc:
            return False, f"{short} missing from {registry} (HTTP {exc.code})"
        except (urllib.error.URLError, OSError) as exc:
            return False, f"{registry} unreachable ({str(exc)[:80]})"
        return found, f"{short} present in {registry}" if found else f"{short} missing from {registry}"
    ok, out = _sh("docker", "manifest", "inspect", image)
    return ok, f"{short} present in {registry}" if ok else f"{short} not resolved in {registry} ({out[:120]})"


def doctor(profile: PlaneProfile | None = None) -> list[tuple[str, bool, str]]:
    """The checks of the profile's cluster: ``(name, ok, text)`` per line, the configured addresses first."""
    profile = profile or load_profile()
    hint = UP if profile.name == "kind" else RUNBOOK
    context = profile.kube_context
    checks = [(f"profile {profile.name}", True, " ".join(f"{k}={v}" for k, v in profile.addresses().items()))]
    ok, out = _sh("kubectl", "--context", context, "cluster-info")
    checks.append((f"cluster {context}", ok, "reachable" if ok else f"context {context} unreachable ({out[:80]}); {hint}"))
    if ok:  # behind an unreachable context the namespaces cannot be told apart from it
        for label, ns in (("agent substrate (ate-system)", "ate-system"), ("ax controller (ax-system)", "ax-system")):
            ok, out = _pods_ready(ns, context)
            checks.append((label, ok, out if ok else f"{out}; {hint}"))
    try:
        images = profile.load_images()
        runner = images["runner"]
    except ProfileError as exc:
        checks.append((f"runner image in {profile.registry}", False, f"{exc}; {hint}"))
    except KeyError:
        checks.append((f"runner image in {profile.registry}", False, f"{profile.images} names no runner image; {hint}"))
    else:
        ok, out = _registry_has(runner)
        checks.append((f"runner image in {profile.registry}", ok, out if ok else f"{out}; {hint} and loads it"))
    from .memory import MemoryStoreError, open_store  # lazy: boto3 only when the profile names an S3 store

    try:
        store = open_store(profile.memory)
    except (MemoryStoreError, OSError, ValueError) as exc:
        checks.append((f"memory store {profile.memory}", False, str(exc)[:300]))
    else:
        checks.append((f"memory store {profile.memory}", True, f"{store.describe()} opens (an S3 bucket is verified)"))
    return checks


__all__ = ["doctor"]
