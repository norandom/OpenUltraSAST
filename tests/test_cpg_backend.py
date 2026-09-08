"""model-grounded-detection task 2.1: the Joern seam, out of process and capability-detected.

Joern is a JVM tool. The whole integration is one subprocess boundary so that the core install stays
zero-dependency and an absent engine degrades to `suspicion` with a recorded reason rather than a traceback.
Nothing here imports a JVM binding, and every test runs with Joern absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_without_joern_the_resolved_backend_is_the_null_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cpg.backend import NullBackend, resolve_cpg_backend

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    backend = resolve_cpg_backend()
    assert isinstance(backend, NullBackend)
    assert backend.available() is False
    assert backend.build(Path(".")) is None, "an absent engine yields no CPG, and the caller degrades"


def test_the_capability_probe_reuses_the_existing_joern_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """`semantic/engines.joern_available` already exists; the model layer must not grow a second probe."""
    from openultrasast.cpg.capability import has_cpg

    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "off")
    assert has_cpg() is False
    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    assert has_cpg() is True


def test_the_seam_imports_nothing_outside_the_standard_library() -> None:
    """Req 4.2: the core install has no dependencies, so the seam may not import one at module load."""
    import ast

    source = Path("src/openultrasast/cpg/backend.py").read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
    stdlib = {
        "__future__",
        "json",
        "os",
        "re",
        "shutil",
        "subprocess",
        "tempfile",
        "dataclasses",
        "pathlib",
        "typing",
        "collections",
        "logging",
        "hashlib",
    }
    assert imported <= stdlib, f"the seam imports outside the standard library: {sorted(imported - stdlib)}"
    assert "import jpype" not in source and "py4j" not in source, "Joern is reached by subprocess, never in-process"


def test_a_scripted_backend_parses_a_query_result_without_joern(tmp_path: Path) -> None:
    """The parsing is exercised by canned JSON, so the query contract is testable with no engine installed."""
    from openultrasast.cpg.backend import CpgResult

    payload = [{"sink": "os.system", "source": "request.args", "path": ["a", "b"], "sanitized": False}]

    def run(query: str, params: dict[str, object]) -> object:
        assert query == "taint"
        return payload

    result = CpgResult(cpg_path=tmp_path / "cpg.bin", run=run)
    assert result.run("taint", {}) == payload


def test_joern_output_is_read_from_a_delimited_block_not_from_noisy_stdout() -> None:
    """Joern prints a banner and a REPL prompt; the payload is fenced so the parse cannot swallow either."""
    from openultrasast.cpg.backend import BEGIN, END, extract_payload

    noisy = f"Compiling...\nJoern v4.0\n{BEGIN}\n{json.dumps([{'sink': 'eval'}])}\n{END}\njoern> \n"
    assert extract_payload(noisy) == [{"sink": "eval"}]
    assert extract_payload("no markers at all") is None
    assert extract_payload(f"{BEGIN}\nnot json\n{END}") is None


def test_a_failing_or_slow_engine_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed: a build or query that errors yields no verdict, never a wrong one."""
    import subprocess

    from openultrasast.cpg.backend import JoernBackend

    def boom(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="joern-parse", timeout=1)

    backend = JoernBackend(runner=boom)
    monkeypatch.setenv("OPENULTRASAST_JOERN_PROBE", "on")
    assert backend.build(tmp_path) is None


def test_the_query_scripts_are_shipped_beside_the_seam() -> None:
    """The CPGQL is ours and is data: it lives with the package, not inlined in a Python string."""
    queries = Path("src/openultrasast/cpg/queries")
    assert (queries / "taint.sc").is_file(), "the injection taint query must ship with the package"
