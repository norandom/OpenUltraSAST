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


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_response_body_write_is_an_output_encoding_sink(tmp_path: Path) -> None:
    """A request value written straight into a response body is reported; the JSON form is not.

    Every sink this family shipped with was a DOM sink, so on a Node application it completed its questions
    and could not have found anything: the census measured that on NodeGoat, 44 questions and no findings.
    `res.json` stays out because it sets an application/json content type, and that exclusion is asserted here
    rather than left to the reader of the fact table.
    """
    from openultrasast.cpg.backend import extract_payload
    from openultrasast.model.specs import taint_specs

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    sinks = taint_specs(language="javascript")["output_encoding"].sinks
    assert "res.write" in sinks, "the shipped vocabulary no longer holds the sink this control is about"
    assert "res.json" not in sinks, "res.json is a JSON content type, not a rendered document"

    source = tmp_path / "render.js"
    source.write_text(
        "function handler(req, res) {\n"
        "    const name = req.query.name;\n"
        "    res.json({ echoed: name });\n"
        '    res.write("<h1>" + name + "</h1>");\n'
        "    return res.end();\n"
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
    assert flows, "a request value written into the response body was not reported"
    assert all("res.json" not in str(row["sink"]) for row in flows), f"the JSON form was reported: {flows}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_qualified_setting_needs_its_receiver(tmp_path: Path) -> None:
    """`marked.setOptions` must not be answered by an unrelated `setOptions`.

    The setting matcher accepted a dotted spec's trailing segment alone, which was harmless while every
    shipped setting was a bare name and became load-bearing when the template engines joined the table: an
    editor's `setOptions` would have been read as a template engine's.
    """
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    source = tmp_path / "setup.js"
    source.write_text(
        "function configure(editor) {\n    editor.setOptions({ readOnly: false });\n    marked.setOptions({ sanitize: false });\n}\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")

    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"0": {"settings": "marked.setOptions", "function": "configure"}}))
    done = subprocess.run(
        [
            _joern() or "joern",
            "--script",
            str((QUERIES / "config.sc").resolve()),
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
    assert done.returncode == 0, f"config.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    payload = extract_payload(done.stdout or "")
    assert payload is not None, "config.sc produced no parseable payload"
    settings = [str(row.get("setting", "")) for row in (payload.get("0") or []) if row.get("setting")]
    assert any("marked.setOptions" in row for row in settings), f"the template engine's setting was missed: {settings}"
    assert all("editor.setOptions" not in row for row in settings), f"an unrelated setOptions was claimed: {settings}"


def _route_and_dao(tmp_path: Path) -> Path:
    """An application shaped the way the census found NodeGoat: route in one file, query in another.

    `displayNote` takes the record id from the URL; `displayMine` takes it from the caller's identity. Both
    reach the same data-access module, so the file holding the query cannot tell them apart and the file
    holding the decision holds no operation at all. A third module defines a member of the SAME NAME that
    nothing imports, which is the collision the file scope was originally closed to prevent.
    """
    routes = tmp_path / "app" / "routes"
    data = tmp_path / "app" / "data"
    routes.mkdir(parents=True)
    data.mkdir(parents=True)
    (routes / "notes.js").write_text(
        'const NotesDAO = require("../data/notes-dao").NotesDAO;\n'
        "\n"
        "function NotesHandler(db) {\n"
        "    const notesDAO = new NotesDAO(db);\n"
        "\n"
        "    this.displayNote = (req, res) => {\n"
        "        const noteId = req.params.noteId;\n"
        "        return notesDAO.getById(noteId, (err, note) => res.json(note));\n"
        "    };\n"
        "\n"
        "    this.displayMine = (req, res) => {\n"
        "        return notesDAO.getOwned(req.user.id, (err, notes) => res.json(notes));\n"
        "    };\n"
        "}\n"
        "\n"
        "module.exports = NotesHandler;\n"
    )
    (data / "notes-dao.js").write_text(
        "function NotesDAO(db) {\n"
        '    const notes = db.collection("notes");\n'
        "\n"
        "    this.getById = (noteId, callback) => {\n"
        "        notes.findOne({ _id: noteId }, callback);\n"
        "    };\n"
        "\n"
        "    this.getOwned = (userId, callback) => {\n"
        "        notes.findOne({ owner: userId }, callback);\n"
        "    };\n"
        "}\n"
        "\n"
        "module.exports.NotesDAO = NotesDAO;\n"
    )
    (data / "audit-dao.js").write_text(
        "function AuditDAO(db) {\n"
        '    const audit = db.collection("audit");\n'
        "\n"
        "    this.getById = (anyId, callback) => {\n"
        "        audit.findOne({ _id: anyId }, callback);\n"
        "    };\n"
        "}\n"
        "\n"
        "module.exports.AuditDAO = AuditDAO;\n"
    )
    return tmp_path


def _dominance_rows(tmp_path: Path, *, function: str, file: str) -> list[dict[str, object]]:
    from openultrasast.cpg.backend import extract_payload
    from openultrasast.model.dominance import request_params
    from openultrasast.model.specs import dominance_specs

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    spec = dominance_specs(language="javascript")["access_control"]
    params = request_params(spec, function=function, file=file)
    request = {k: v for k, v in params.items() if isinstance(v, str)}
    request["operations"] = ",".join(spec.operations)
    request["dischargers"] = ",".join(spec.dischargers)
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"0": request}))
    done = subprocess.run(
        [
            _joern() or "joern",
            "--script",
            str((QUERIES / "dominance.sc").resolve()),
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
    assert done.returncode == 0, f"dominance.sc did not run: {(done.stderr or done.stdout or '')[-500:]}"
    payload = extract_payload(done.stdout or "")
    assert payload is not None, "dominance.sc produced no parseable payload"
    return [row for row in (payload.get("0") or []) if row.get("operation")]


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_route_and_dao_split_raises_the_obligation_at_the_handler(tmp_path: Path) -> None:
    """The obligation follows the call the handler writes, and the witness names both sites."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict
    from openultrasast.model.ladder import Rung
    from openultrasast.model.specs import dominance_specs

    rows = _dominance_rows(_route_and_dao(tmp_path), function="displayNote", file="app/routes/notes.js")
    assert rows, "the route file raised no obligation at all, which is the gap this closes"
    carried = [row for row in rows if row.get("viaLine")]
    assert carried, f"no obligation was carried across the module boundary: {rows}"
    assert all("notes-dao.js" in str(row["opFile"]) for row in carried), f"an unimported module was attributed: {carried}"

    spec = dominance_specs(language="javascript")["access_control"]
    cpg = CpgResult(cpg_path=tmp_path / "cpg.bin", run=lambda q, p: rows)
    answer = verdict(cpg, spec, function="displayNote", file="app/routes/notes.js")
    assert answer is not None, f"no verdict from rows {rows}"
    # CORROBORATED, not entailed, and deliberately: the obligation crossed a module boundary, so the guarded
    # sibling need not share this route's trust context. Measured on NodeGoat, where entailing it reported a
    # signup handler that is public by design. The residual question the band carries is the right one.
    assert answer.rung is Rung.CORROBORATED, f"{answer.rung} from {answer.witness}"
    assert "displayNote" in answer.witness, answer.witness
    assert "notes-dao.js" in answer.witness, f"the witness does not name the operation's site: {answer.witness}"
    assert "getById" in answer.witness, f"the witness does not name the call that carries it: {answer.witness}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_an_identity_constrained_handler_is_not_reported(tmp_path: Path) -> None:
    """The control for the other direction: the sibling that passes the caller's own identity is guarded."""
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict
    from openultrasast.model.specs import dominance_specs

    rows = _dominance_rows(_route_and_dao(tmp_path), function="displayMine", file="app/routes/notes.js")
    spec = dominance_specs(language="javascript")["access_control"]
    cpg = CpgResult(cpg_path=tmp_path / "cpg.bin", run=lambda q, p: rows)
    answer = verdict(cpg, spec, function="displayMine", file="app/routes/notes.js")
    assert answer is None, f"a handler that passes the caller's own identity was reported: {answer}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_only_a_collection_read_is_an_obligated_find(tmp_path: Path) -> None:
    """`find` is a collection read, an array search and a jQuery selector. Only the first is obligated.

    The name was absent from the operation table for that reason, which left the family's obligation missing at
    the commonest read there is: NodeGoat's documented insecure direct object reference reads with
    `allocationsCol.find(searchCriteria())`. Measured on one WordPress plugin's shipped assets, 83 of 88 calls
    named `find` pass a selector or a predicate, and five pass a selector built at run time. Each exclusion
    below is one of those measured classes.
    """
    from openultrasast.model.specs import dominance_specs

    spec = dominance_specs(language="javascript")["access_control"]
    assert "find" in spec.document_shape, "the shape requirement is no longer declared for this call"

    source = tmp_path / "shapes.js"
    source.write_text(
        "function shapes(db, arr, $el, pred, query) {\n"
        '    const col = db.collection("notes");\n'
        "    const read = col.find({ owner: 1 });\n"
        "    const wide = col.find();\n"
        "    const built = col.find(criteria());\n"
        "    const search = arr.find(x => x.id === 1);\n"
        '    const selector = $el.find(".cls");\n'
        '    const interpolated = $el.find(`li[data-key="${pred}"]`);\n'
        "    const concatenated = $el.find('li[data-key=\"' + pred + '\"]');\n"
        "    return [read, wide, built, search, selector, interpolated, concatenated];\n"
        "}\n"
    )
    rows = _dominance_rows(tmp_path, function="shapes", file="shapes.js")
    lines = sorted(int(str(row["opLine"])) for row in rows)
    # 3 the object literal, 4 the whole collection, 5 the builder call.
    assert lines == [3, 4, 5], f"the wrong find shapes were claimed: {[(r['opLine'], r['operation']) for r in rows]}"
