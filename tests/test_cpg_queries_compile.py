"""The CPG queries are 900 lines of Scala that nothing else in this suite compiles.

A signature change to `rowsFor` once shipped with 850 tests passing and broke every query at runtime. It was
found by a measurement failing hours later, not by CI -- which is the same shape as every other failure this
project keeps having: the thing that was never checked reported nothing, and nothing read as fine.

These tests need a real Joern, so they skip where it is absent. Skipping is honest here in a way it is not
elsewhere: the suite still runs everywhere, and the check runs wherever the engine it checks exists.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

QUERIES = Path("src/openultrasast/cpg/queries")


def _joern() -> str | None:
    import shutil

    return shutil.which("joern")


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
@pytest.mark.parametrize("name", ["taint", "dominance", "config", "census"])
def test_each_query_compiles_and_answers(name: str, tmp_path: Path) -> None:
    """Compile and RUN each query against a graph, and require a fenced payload back.

    Compiling alone would miss a runtime arity error inside a branch, so the query has to answer -- and the
    answer has to parse, because a script that prints a stack trace still exits 0 often enough to matter.
    """
    from openultrasast.cpg.backend import extract_payload

    script = QUERIES / f"{name}.sc"
    assert script.is_file(), f"{script} is missing"

    source = tmp_path / "sample.php"
    source.write_text("<?php\nfunction handler($x) {\n  global $wpdb;\n  return $wpdb->query($x);\n}\n")
    cpg = tmp_path / "cpg.bin"
    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")

    command = [_joern() or "joern", "--script", str(script.resolve()), "--param", f"cpgFile={cpg}"]
    if name != "census":
        requests = tmp_path / "requests.json"
        requests.write_text(json.dumps({"0": {"sources": "$_GET", "sinks": "$wpdb->query", "function": "handler"}}))
        command += ["--param", f"requestsFile={requests}"]
    done = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)

    assert done.returncode == 0, f"{name}.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    assert extract_payload(done.stdout or "") is not None, f"{name}.sc produced no parseable payload"
