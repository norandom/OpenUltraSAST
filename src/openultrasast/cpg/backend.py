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
    """A built CPG and the way to query it. Opaque: only ``model/`` reads through ``run``."""

    cpg_path: Path
    run: Callable[[str, Mapping[str, object]], object | None]


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
        command = [parse or "joern-parse", str(root), "--output", str(cpg_path)]
        completed = self._run(command, timeout=self.build_timeout)
        if completed is None or completed.returncode != 0 or not cpg_path.is_file():
            detail = (completed.stderr or completed.stdout or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg build failed for %s: %s", root, detail)
            return None
        return CpgResult(cpg_path=cpg_path, run=lambda query, params: self.query(cpg_path, query, params))

    def query(self, cpg_path: Path, query: str, params: Mapping[str, object]) -> object | None:
        """Run a shipped CPGQL script against a built CPG and return its fenced JSON payload."""
        script = self.queries_dir / f"{query}.sc"
        if not script.is_file():
            logger.warning("no such cpg query: %s", script)
            return None
        command = [shutil.which("joern") or "joern", "--script", str(script), "--param", f"cpgFile={cpg_path}"]
        for key, value in sorted(params.items()):
            command += ["--param", f"{key}={_render(value)}"]
        completed = self._run(command, timeout=self.query_timeout)
        if completed is None or completed.returncode != 0:
            detail = (completed.stderr or "")[-400:] if completed is not None else "timeout"
            logger.warning("cpg query %s failed: %s", query, detail)
            return None
        return extract_payload(completed.stdout or "")

    def _run(self, command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str] | None:
        run = self.runner if self.runner is not None else subprocess.run
        try:
            return run(command, capture_output=True, text=True, timeout=timeout, check=False)
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
