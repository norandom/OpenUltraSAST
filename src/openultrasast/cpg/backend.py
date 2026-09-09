"""The Joern subprocess seam — the single place this codebase touches a CPG engine (Req 4.1, 4.4, 4.5).

Joern is JVM/Scala. Everything crosses one subprocess boundary: ``joern-parse`` builds a ``cpg.bin`` from a
source tree, then ``joern --script`` runs a CPGQL script that prints a JSON payload. Nothing is imported
in-process, so the core install keeps ``dependencies = []`` and an absent engine costs a recorded reason
rather than a traceback.

Two rules hold everywhere below:

* **Fail closed.** A build or query that errors, times out, or prints something unparseable yields *no*
  verdict. The model layer then reports ``suspicion``. A wrong verdict is worse than no verdict — that is the
  whole reason this arbiter exists.
* **Fence the payload.** Joern prints a banner, compilation notices and a REPL prompt on stdout. The script
  brackets its JSON between markers so parsing can never swallow the noise around it.

We do not build a control-flow or dataflow engine here (Req 4.4): the CFG, PDG and call graph our flat IR
lacks are exactly what is being adopted.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

QUERIES_DIR = Path(__file__).resolve().parent / "queries"

# The payload fence. Joern's stdout carries a banner and a prompt; the script prints these around its JSON.
BEGIN = "---OUSAST-CPG-BEGIN---"
END = "---OUSAST-CPG-END---"

BUILD_TIMEOUT_SECONDS = 900  # a large tree takes minutes; the go/no-go records what it actually cost
QUERY_TIMEOUT_SECONDS = 300
# A JVM with no -Xmx takes a quarter of physical RAM for its heap. On a contributor's laptop that is the
# difference between a scan running in the background and a scan the machine notices, and it made the
# first repository measurements unreproducible: runs were killed under memory pressure at different
# points, so the numbers described the host, not the engine. Bound it, and let the operator raise it.
CPG_HEAP_MB = 2048
HEAP_ENV = "OPENULTRASAST_CPG_HEAP_MB"

Runner = Callable[..., subprocess.CompletedProcess[str]]


def extract_payload(stdout: str) -> object | None:
    """The JSON between the fence markers, or ``None`` when it is absent or malformed."""
    start = stdout.find(BEGIN)
    end = stdout.find(END, start + 1) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    body = stdout[start + len(BEGIN) : end].strip()
    try:
        payload: object = json.loads(body)
    except json.JSONDecodeError:
        logger.debug("cpg query payload was not valid JSON")
        return None
    return payload


@dataclass(frozen=True)
class CpgResult:
    """A built CPG and the ways to query it. Opaque: only ``model/`` reads through these.

    ``run_batch`` is optional so a backend that cannot answer many questions in one invocation still fits
    this shape -- the driver falls back to ``run``, once per request. But a backend that CAN batch must
    attach it HERE, because this is the driver's only way to discover the capability. Leaving it off does
    not fail: it silently costs a JVM per region, which is how batching sat unreachable behind a passing
    test suite until a repository scan made the cost visible.
    """

    cpg_path: Path
    run: Callable[[str, Mapping[str, object]], object | None]
    run_batch: Callable[[str, Mapping[str, Mapping[str, object]]], dict[str, list[object]]] | None = None


class CpgBackend(Protocol):
    def available(self) -> bool: ...

    def build(self, root: Path) -> CpgResult | None: ...


@dataclass
class NullBackend:
    """No engine. Every verdict degrades to ``suspicion`` and the caller records ``cpg_unavailable``."""

    reason: str = "cpg_unavailable"

    def available(self) -> bool:
        return False

    def build(self, root: Path) -> CpgResult | None:
        del root
        return None


@dataclass
class JoernBackend:
    """``joern-parse`` then ``joern --script``, both out of process and both timeout-bounded."""

    runner: Runner | None = None
    build_timeout: int = BUILD_TIMEOUT_SECONDS
    query_timeout: int = QUERY_TIMEOUT_SECONDS
    heap_mb: int = 0  # 0 means read the environment, then fall back to CPG_HEAP_MB
    queries_dir: Path = field(default_factory=lambda: QUERIES_DIR)

    def available(self) -> bool:
        from .capability import has_cpg

        return has_cpg()

    def build(self, root: Path) -> CpgResult | None:
        """Build a CPG for ``root``. ``None`` on any failure — the caller degrades, never guesses."""
        parse = shutil.which("joern-parse")
        if parse is None and os.environ.get("OPENULTRASAST_JOERN_PROBE", "").strip().lower() not in {"1", "on", "true", "yes"}:
            return None
        scratch = Path(tempfile.mkdtemp(prefix="ousast-cpg-"))
        cpg_path = scratch / "cpg.bin"
        command = [parse or "joern-parse", self._heap_flag(), str(root), "--output", str(cpg_path)]
        completed = self._run(command, timeout=self.build_timeout, cwd=scratch)
        if completed is None or completed.returncode != 0 or not cpg_path.is_file():
            detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg build failed for %s: %s", root, detail)
            return None
        return CpgResult(
            cpg_path=cpg_path,
            run=lambda query, params: self.query(cpg_path, query, params),
            run_batch=lambda query, requests: self.query_batch(cpg_path, query, requests),
        )

    def query_batch(self, cpg_path: Path, query: str, requests: Mapping[str, Mapping[str, object]]) -> dict[str, list[object]]:
        """Run ONE script invocation carrying many requests, keyed back to their ids.

        JVM startup, not CPG construction, is what dominates a repository scan: every ``joern --script`` call
        starts a JVM of roughly thirty seconds, and issuing one per region per family put a ten-line Python
        file at four minutes and a thousand regions at about fifty hours. The CPG is already built and loaded
        by then; the work itself is milliseconds. So the batch carries the whole scan's questions in one
        parameter and the script loops over them.

        Fails closed like every other path here: an engine that could not answer returns ``{}``, never an
        empty result per request, because "no rows" and "could not ask" must stay distinguishable.
        """
        script = self.queries_dir / f"{query}.sc"
        if not script.is_file():
            logger.warning("no such cpg query: %s", script)
            return {}
        payload = json.dumps({rid: {k: _render(v) for k, v in req.items()} for rid, req in requests.items()})
        command = [
            shutil.which("joern") or "joern",
            self._heap_flag(),
            "--script",
            str(script),
            "--param",
            f"cpgFile={cpg_path}",
            "--param",
            f"requests={payload}",
        ]
        completed = self._run(command, timeout=self.query_timeout, cwd=cpg_path.parent)
        if completed is None or completed.returncode != 0:
            detail = (completed.stderr or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg batch %s failed: %s", query, detail)
            return {}
        parsed = extract_payload(completed.stdout or "")
        if not isinstance(parsed, Mapping):
            return {}
        # A request the engine did not answer is absent, not empty: the caller must be able to tell them apart.
        return {str(rid): list(rows) for rid, rows in parsed.items() if isinstance(rows, list)}

    def query(self, cpg_path: Path, query: str, params: Mapping[str, object]) -> object | None:
        """Run a shipped CPGQL script against a built CPG and return its fenced JSON payload."""
        script = self.queries_dir / f"{query}.sc"
        if not script.is_file():
            logger.warning("no such cpg query: %s", script)
            return None
        command = [shutil.which("joern") or "joern", self._heap_flag(), "--script", str(script), "--param", f"cpgFile={cpg_path}"]
        for key, value in sorted(params.items()):
            command += ["--param", f"{key}={_render(value)}"]
        # Joern writes a `workspace/` beside the working directory; run it inside the CPG's own scratch dir so
        # it can never land in the repository being analysed.
        completed = self._run(command, timeout=self.query_timeout, cwd=cpg_path.parent)
        if completed is None or completed.returncode != 0:
            detail = (completed.stderr or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg query %s failed: %s", query, detail)
            return None
        return extract_payload(completed.stdout or "")

    def _heap_flag(self) -> str:
        """``-J-Xmx``: both launchers forward ``-J`` arguments to the JVM."""
        if self.heap_mb > 0:
            return f"-J-Xmx{self.heap_mb}m"
        configured = os.environ.get(HEAP_ENV, "").strip()
        return f"-J-Xmx{configured if configured.isdigit() else CPG_HEAP_MB}m"

    def _run(self, command: list[str], *, timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str] | None:
        run = self.runner if self.runner is not None else subprocess.run
        try:
            return run(command, capture_output=True, text=True, timeout=timeout, check=False, cwd=str(cwd) if cwd else None)
        except (OSError, subprocess.SubprocessError):
            return None


def _render(value: object) -> str:
    """CPGQL parameters are strings; a sequence becomes a comma-separated list the script splits."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def resolve_cpg_backend(*, runner: Runner | None = None) -> CpgBackend:
    """The backend for this machine: Joern when it is installed, else the null one."""
    from .capability import has_cpg

    return JoernBackend(runner=runner) if has_cpg() else NullBackend()


__all__ = [
    "BEGIN",
    "END",
    "CpgBackend",
    "CpgResult",
    "JoernBackend",
    "NullBackend",
    "extract_payload",
    "resolve_cpg_backend",
]
