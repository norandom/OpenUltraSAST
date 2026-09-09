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


def test_a_batch_is_one_invocation_carrying_many_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cost that dominates a repository scan is JVM startup, not CPG construction.

    Every `joern --script` call starts a JVM (~30s). The driver issued one per region per family, so a
    ten-line Python file -- six families, one region -- took over four minutes, and 1000 regions would take
    ~50 hours. Batching collapses that to one invocation per query kind.
    """
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    calls: list[list[str]] = []

    class _Done:
        returncode = 0
        stderr = ""
        stdout = f'{BEGIN}\n{{"r1": [{{"sink": "os.system(x)"}}], "r2": []}}\n{END}\n'

    def runner(command, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(command))
        return _Done()

    backend = JoernBackend(runner=runner)
    rows = backend.query_batch(
        Path("/tmp/c.bin"),
        "taint",
        {"r1": {"sources": ("request.args",), "sinks": ("os.system",)}, "r2": {"sources": ("request.args",), "sinks": ("eval",)}},
    )
    assert len(calls) == 1, "a batch must be ONE invocation, whatever it carries"
    assert rows["r1"] and rows["r2"] == []


def test_a_failed_batch_yields_no_rows_for_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed, as everywhere else: an engine that could not answer must not read as 'nothing here'."""
    from openultrasast.cpg.backend import JoernBackend

    class _Bad:
        returncode = 1
        stdout = ""
        stderr = "boom"

    backend = JoernBackend(runner=lambda c, **k: _Bad())
    assert backend.query_batch(Path("/tmp/c.bin"), "taint", {"r1": {}}) == {}


def test_a_batch_result_that_omits_a_request_returns_nothing_for_it() -> None:
    """A missing key is not an empty answer: the caller must be able to tell them apart."""
    from openultrasast.cpg.backend import BEGIN, END, JoernBackend

    class _Partial:
        returncode = 0
        stderr = ""
        stdout = f'{BEGIN}\n{{"r1": []}}\n{END}\n'

    backend = JoernBackend(runner=lambda c, **k: _Partial())
    rows = backend.query_batch(Path("/tmp/c.bin"), "taint", {"r1": {}, "r2": {}})
    assert rows.get("r1") == [] and "r2" not in rows
