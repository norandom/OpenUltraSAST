"""plane-on-kubernetes Req 1.3: no module, manifest or page assumes this host.

The scan covers ``src/``, ``plane/``, ``ops/`` (minus ``ops/ax/up.sh``, which creates the kind cluster and may name
it, and ``ops/k8s/profiles/``, which *are* the configuration) and ``docs/`` for the kind context, the kind registry,
the kind network's gateway, a loopback address with a port, and ``port-forward``. Allowed: ``port-forward`` and the
loopback address inside ``router.py`` (the one module that opens the tunnel), and any line tagged ``ax-tunnel``
(the tunnel is how both profiles reach ax and the router) or ``loopback`` (a process talking to itself). A
digest-pinned ``image:`` line of a committed Task template under ``plane/tasks/`` is the kind profile's own value,
written there by ``ousast plane`` repinning from ``ops/k8s/profiles/kind-images.json``; it is accepted only while it
names that profile's registry, so the templates and the profile cannot drift apart. The patterns are built at runtime
so this file does not match them (as ``test_removed_plane_references.py`` does).
"""

from __future__ import annotations

import re
from pathlib import Path

from openultrasast.plane.profile import load_profile

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src", "plane", "ops", "docs")
EXEMPT = (Path("ops/ax/up.sh"), Path("ops/k8s/profiles"))
ROUTER = Path("src/openultrasast/plane/router.py")
PATTERNS = {
    "kind context": re.compile("kind-" + "ousast"),
    "kind registry": re.compile("localhost:" + "5001"),
    "kind gateway": re.compile(r"172\.19\."),
    "loopback with port": re.compile(r"127\.0\.0\.1" + ":"),
    "port-forward": re.compile("port-" + "forward"),
}
ROUTER_ONLY = {"loopback with port", "port-forward"}
TAGS = re.compile(r"ax-tunnel|loopback")
_IMAGE_LINE = re.compile(r'^\s*image:\s*"?(?P<ref>\S+?)@sha256:[0-9a-f]{64}"?\s*(#.*)?$')


def _files() -> list[Path]:
    out = []
    for top in SCANNED:
        for path in sorted((ROOT / top).rglob("*")):
            relative = path.relative_to(ROOT)
            if not path.is_file() or "__pycache__" in relative.parts or path.suffix in (".png", ".jpg", ".gz", ".zip"):
                continue
            if any(relative == e or e in relative.parents for e in EXEMPT):
                continue
            out.append(path)
    return out


def _pinned_template_image(relative: Path, line: str, registry: str) -> bool:
    """A committed template's digest-pinned image in the kind profile's registry: configuration, not a literal."""
    if relative.parts[:2] != ("plane", "tasks"):
        return False
    found = _IMAGE_LINE.match(line)
    return bool(found) and found.group("ref").startswith(registry + "/")


def offenders(paths: list[Path], registry: str, root: Path = ROOT) -> list[str]:
    found = []
    for path in paths:
        relative = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in PATTERNS.items():
                if not pattern.search(line):
                    continue
                if label in ROUTER_ONLY and relative == ROUTER:
                    continue
                if TAGS.search(line) or _pinned_template_image(relative, line, registry):
                    continue
                found.append(f"{relative}:{number}: [{label}] {line.strip()[:120]}")
    return found


def test_no_host_literal_outside_the_profile_and_the_kind_bring_up() -> None:
    kind = load_profile("kind", environ={})
    found = offenders(_files(), kind.registry)
    assert found == [], "host-only literals (Req 1.3):\n" + "\n".join(found)


def test_the_scan_sees_a_reinserted_literal(tmp_path: Path) -> None:
    """The instrument is not vacuous: each pattern is caught, a tag or the router exempts only what it says."""
    kind = load_profile("kind", environ={})
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text(f'ctx = "{"kind-" + "ousast"}"\nreg = "{"localhost:" + "5001"}"\nip = "172.19.0.1"\n', encoding="utf-8")
    (src / "b.py").write_text('url = "http://127.0.0.1:8080"  # loopback, this process\nargv = ["port-' + 'forward"]  # ax-tunnel\n')
    (src / "c.py").write_text('argv = ["port-' + 'forward"]\n', encoding="utf-8")
    paths = sorted(src.glob("*.py"))
    found = [o.split(": ", 1)[1] for o in offenders(paths, kind.registry, root=tmp_path)]
    assert found == [
        "[kind context] ctx = " + '"kind-' + 'ousast"',
        "[kind registry] reg = " + '"localhost:' + '5001"',
        '[kind gateway] ip = "172.19.0.1"',
        "[port-forward] argv = " + '["port-' + 'forward"]',
    ]


def test_the_committed_templates_name_the_kind_profiles_registry() -> None:
    """The one exemption is checked, not assumed: every template image is in the kind registry, by digest."""
    kind = load_profile("kind", environ={})
    images = []
    for path in sorted((ROOT / "plane/tasks").glob("*.yaml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            found = _IMAGE_LINE.match(line)
            if found:
                images.append(found.group("ref"))
                assert found.group("ref").startswith(kind.registry + "/"), f"{path.name}: {line.strip()}"
    assert images, "the templates carry digest-pinned images"
