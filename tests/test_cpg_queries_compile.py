"""The CPG queries are 900 lines of Scala that nothing else in this suite compiles.

A signature change to `rowsFor` once shipped with 850 tests passing and broke every query at runtime. It was
found by a measurement failing hours later, not by CI -- which is the same shape as every other failure this
project keeps having: the thing that was never checked reported nothing, and nothing read as fine.

These tests need a real Joern, so they skip where it is absent. Skipping is honest here in a way it is not
elsewhere: the suite still runs everywhere, and the check runs wherever the engine it checks exists.

In practice that is nowhere by default, which the family census exposed: the image has Joern and no pytest,
the host has pytest and no Joern, so these six tests had never run on either. They run in the image with the
host's pytest mounted in, which needs no network and installs nothing:

    docker run --rm --init --network none --memory 4g --entrypoint bash \
      -v "$PWD/src:/app/src:ro" -v "$PWD/tests:/app/tests:ro" -v "$PWD/pyproject.toml:/app/pyproject.toml:ro" \
      -v "$PWD/.venv/lib/python3.11/site-packages:/hostsp:ro" -e PYTHONPATH=/hostsp -e TMPDIR=/tmp \
      openultrasast:dev -lc 'cd /app && python -m pytest tests/test_cpg_queries_compile.py -q'
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
@pytest.mark.parametrize("name", ["taint", "dominance", "config", "census", "overlay"])
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
    if name not in {"census", "overlay"}:
        requests = tmp_path / "requests.json"
        requests.write_text(json.dumps({"0": {"sources": "$_GET", "sinks": "$wpdb->query", "function": "handler"}}))
        command += ["--param", f"requestsFile={requests}"]
    done = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False, cwd=str(tmp_path))

    assert done.returncode == 0, f"{name}.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    payload = extract_payload(done.stdout or "")
    assert payload is not None, f"{name}.sc produced no parseable payload"
    if name == "census":
        # The overlay list is what the backend checks for the dataflow layer. It shipped once as a list of
        # CHARACTERS (`b,a,s,e,...`) -- one `flatten` too many -- and every real build warned that its graph
        # lacked `dataflowOss` while carrying it. `importCpg` applies the layer here, so it must be named.
        overlays = str(payload.get("overlays", "")).split(",")
        assert "dataflowOss" in overlays, f"census reports overlays {overlays!r}, which is not a list of layer names"
        assert str(payload.get("maxHeapMB", "")).isdigit()


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_sink_word_in_a_comment_is_not_a_sink(tmp_path: Path) -> None:
    """A handler that mentions a sink word in prose must not report that sink.

    The first family census ran this exact shape: NodeGoat's signup handler is one assignment node whose code
    is the whole arrow function, a comment inside it reads `// set these up in case we have an error case`,
    and `set` is a prototype-pollution sink. The word is bounded and the match was real, so the census
    reported a prototype finding for a handler that calls no `set`. The witness printed the function header,
    because there was no sink call to print.
    """
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    source = tmp_path / "handler.js"
    source.write_text(
        "function handler(req, res) {\n"
        "    const data = req.body;\n"
        "    // set these up in case we have an error case\n"
        "    return res.end(String(data));\n"
        "}\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")

    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"0": {"sources": "req.body", "sinks": "set", "function": "handler"}}))
    done = subprocess.run(
        [
            _joern() or "joern",
            "--script",
            str((QUERIES / "taint.sc").resolve()),
            "--param",
            f"cpgFile={cpg}",
            "--param",
            f"requestsFile={requests}",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
        cwd=str(tmp_path),
    )
    assert done.returncode == 0, f"taint.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    payload = extract_payload(done.stdout or "")
    assert payload is not None, "taint.sc produced no parseable payload"
    rows = payload.get("0") or []
    # The inventory row is the right answer and must survive: "zero operations in scope" is a statement, and
    # the point of the census was that it differs from "the query found nothing to say".
    flows = [row for row in rows if row.get("sink")]
    assert flows == [], f"a commented sink word produced {len(flows)} flow row(s): {flows[:2]}"
    inventory = [row for row in rows if row.get("kind") == "operation_inventory_complete"]
    assert inventory, f"taint.sc reported no inventory row: {rows[:3]}"
    assert all(int(row.get("operations", 0)) == 0 for row in inventory), f"a commented sink word was counted as an operation: {inventory}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_literal_destination_is_not_an_untrusted_destination(tmp_path: Path) -> None:
    """The client the request flows into is reported; the client called with a literal is not.

    The family census found this family answering 44 questions on NodeGoat while unable to ask about its
    documented SSRF, because `needle` was absent from a vocabulary holding axios, fetch, got and request.
    Widening a vocabulary is how a recall gap is closed and also how a false positive is created, so both
    halves are asserted here against the shipped token set rather than a copy of it.
    """
    from openultrasast.cpg.backend import extract_payload
    from openultrasast.model.specs import taint_specs

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    sinks = taint_specs(language="javascript")["untrusted_destination"].sinks
    assert "needle" in sinks, "the shipped vocabulary no longer holds the client this control is about"

    source = tmp_path / "research.js"
    source.write_text(
        'const axios = require("axios");\n'
        'const needle = require("needle");\n'
        "\n"
        "function handler(req, res) {\n"
        '    axios.get("https://api.example.com/health");\n'
        "    return needle.get(req.query.url, (error, response, body) => res.end(body));\n"
        "}\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")

    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"0": {"sources": "req.query", "sinks": ",".join(sinks), "function": "handler"}}))
    done = subprocess.run(
        [
            _joern() or "joern",
            "--script",
            str((QUERIES / "taint.sc").resolve()),
            "--param",
            f"cpgFile={cpg}",
            "--param",
            f"requestsFile={requests}",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert done.returncode == 0, f"taint.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    payload = extract_payload(done.stdout or "")
    assert payload is not None, "taint.sc produced no parseable payload"
    flows = [row for row in (payload.get("0") or []) if row.get("sink")]
    assert flows, "the request flowing into the client was not reported at all"
    assert all("needle" in str(row["sink"]) for row in flows), f"a client called with a literal was reported: {flows}"
