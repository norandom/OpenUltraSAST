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
        "\n"
        "    this.displayDestructured = (req, res) => {\n"
        "        const { userId } = req.session;\n"
        "        return notesDAO.getOwned(userId, (err, notes) => res.json(notes));\n"
        "    };\n"
        "\n"
        "    this.displayEverything = (req, res) => {\n"
        "        const { userId } = req.session;\n"
        "        return notesDAO.getAll((err, notes) => res.json({ userId, notes }));\n"
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
        "\n"
        "    this.getAll = (callback) => {\n"
        "        notes.find({}).toArray(callback);\n"
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


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_destructured_identity_discharges_what_it_reaches(tmp_path: Path) -> None:
    """Reading the session discharges the query it constrains, and nothing else.

    `const { userId } = req.session` lowers to a temporary, so nothing in the graph spells `session.userId` by
    the time the value reaches the query, and two of NodeGoat's corroborated claims were correct code put to a
    judge for that reason. The second half is the measurement that keeps it honest: NodeGoat's memo listing
    reads the same session and RENDERS it while its query reads every memo in the collection, which is the leak
    that page exists to demonstrate. So the value has to reach the operation's own arguments.
    """
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.dominance import verdict
    from openultrasast.model.ladder import Rung
    from openultrasast.model.specs import dominance_specs

    root = _route_and_dao(tmp_path)
    spec = dominance_specs(language="javascript")["access_control"]

    def answer(function: str):  # type: ignore[no-untyped-def]
        rows = _dominance_rows(root, function=function, file="app/routes/notes.js")
        cpg = CpgResult(cpg_path=tmp_path / "cpg.bin", run=lambda q, p: rows)
        return verdict(cpg, spec, function=function, file="app/routes/notes.js")

    constrained = answer("displayDestructured")
    assert constrained is None, f"a query constrained by the session's own user was reported: {constrained}"

    leaked = answer("displayEverything")
    assert leaked is not None, "a query that reads the whole collection was not reported"
    assert leaked.rung is Rung.CORROBORATED, f"{leaked.rung} from {leaked.witness}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_prototype_pollution_is_established_on_the_shape_it_declares(tmp_path: Path) -> None:
    """The family had never established anything, on any subject, so this is what it can do.

    The 2026-09-19 census recorded prototype pollution asked on one repository, where its only report was the
    word `set` inside a comment. No repository available to this project contains the mechanism: the only
    first-party matches on the Node subject are `app.set("view engine", "html")` and its sibling, which are
    Express settings whose arguments are literals. So the family's ability to answer is demonstrated here, on
    a merge of the request body into an object, and the Express setting is asserted alongside it.
    """
    from openultrasast.cpg.backend import extract_payload
    from openultrasast.model.specs import taint_specs

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    sinks = taint_specs(language="javascript")["prototype"].sinks

    source = tmp_path / "merge.js"
    source.write_text(
        'const _ = require("lodash");\n'
        "\n"
        "function handler(req, res, app) {\n"
        '    app.set("view engine", "html");\n'
        "    const options = {};\n"
        "    _.merge(options, req.body);\n"
        "    return res.end();\n"
        "}\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")

    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"0": {"sources": "req.body", "sinks": ",".join(sinks), "function": "handler"}}))
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
    assert flows, "a request body merged into an object was not reported"
    assert all("merge" in str(row["sink"]) for row in flows), f"the Express setting was reported: {flows}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_the_taint_query_streams_one_line_per_request(tmp_path: Path) -> None:
    """Answers arrive as they finish, so a kill keeps what finished. The fence is unchanged."""
    from openultrasast.cpg.backend import BEGIN, END, extract_payload

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    (tmp_path / "a.js").write_text("function handler(req, res) { return eval(req.body.x); }\n")
    cpg = tmp_path / "cpg.bin"
    subprocess.run([frontend, str(tmp_path), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip("could not build a sample cpg")
    requests = tmp_path / "requests.json"
    requests.write_text(
        json.dumps(
            {
                "0": {"sources": "req.body", "sinks": "eval", "function": "handler"},
                "1": {"sources": "req.body", "sinks": "eval", "function": "nothing"},
            }
        )
    )
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    body = done.stdout[done.stdout.find(BEGIN) + len(BEGIN) : done.stdout.find(END)]
    lines = [line for line in body.splitlines() if line.strip().startswith("{")]
    assert len(lines) >= 3, lines  # census, then one per request
    assert json.loads(lines[0]).keys() == {"__census__"}
    assembled = extract_payload(done.stdout)
    assert assembled is not None and set(assembled) >= {"0", "1", "__census__"} and "__partial__" not in assembled
    # Every answer reports its own cost, which is what the portioner sizes from and how a kill names the
    # request that was running. Absent, the sizer falls back to guessing from wall time.
    answers = [json.loads(line) for line in lines[1:]]
    assert all(isinstance(a.get("ms"), (int, float)) and a["ms"] >= 0 for a in answers), answers
    assert [t["id"] for t in assembled["__timing__"]] == ["0", "1"]


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_context_locations_outside_the_changed_files_are_summarised(tmp_path: Path) -> None:
    """Only the changed files are itemised; every other location collapses into one checkable summary.

    Itemised, one PHP request returned 1,845 locations and a push over a WordPress plugin never finished.
    """
    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text(
        "const h = require('./b');\nfunction handler(req, res) { return h.helper(req.body.x); }\nmodule.exports = handler;\n"
    )
    (tmp_path / "src" / "b.js").write_text("function helper(x) { return eval(x); }\nmodule.exports = { helper };\n")
    cpg = tmp_path / "cpg.bin"
    subprocess.run([frontend, str(tmp_path / "src"), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip("could not build a sample cpg")
    # Repository-wide scope, so the context reaches methods in both files. A `require`d helper is not a
    # resolved call edge in the JavaScript graph, so a handler-scoped request would never leave `a.js`.
    request = {"sources": "req.body", "sinks": "eval", "evidenceOnly": "true", "contextEvidence": "true"}
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"whole": request, "filtered": {**request, "contextFilter": "true", "contextPaths": "b.js"}}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    from openultrasast.cpg.backend import extract_payload

    payload = extract_payload(done.stdout)
    assert isinstance(payload, dict)
    whole = [r for r in payload["whole"] if r.get("kind") == "context_method"]
    kept = [r for r in payload["filtered"] if r.get("kind") == "context_method"]
    summary = [r for r in payload["filtered"] if r.get("kind") == "context_elsewhere"]
    assert {r["path"] for r in whole} >= {"a.js", "b.js"}, whole  # the unfiltered form still itemises everything
    assert kept and all(r["path"] == "b.js" for r in kept), kept
    assert kept == [r for r in whole if r["path"] == "b.js"], "the changed file's locations must be unchanged"
    assert len(summary) == 1 and summary[0]["paths"] == sorted({r["path"] for r in whole if r["path"] != "b.js"})
    assert summary[0]["locations"] == len(whole) - len(kept)


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_path_through_a_query_result_or_a_whole_object_is_not_an_injection(tmp_path: Path) -> None:
    """The two steps every false PMPro injection took, cut; the flows real injections take, kept.

    Adjudicated 2026-09-23 and traced element by element: taint carried out of a query's RESULT into the next
    query (A), and taint written to one field of an object coming out of a DIFFERENT field, or passed into a
    method of an object coming out of its field (B). Reading a member of an object that is itself the tainted
    value, and reading back the field that was written, must still be found.
    """
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_text(
        "<?php\n"
        "class Order {\n  public $membership_id;\n  public $start;\n"
        '  function level() { global $wpdb; return $wpdb->get_row("SELECT * FROM l WHERE id = \'" . $this->membership_id . "\'"); }\n}\n'
        "class Logger {\n  public $table = 'log';\n  function note($m) { return $m; }\n}\n"
        "function a_handler() { global $wpdb;\n"
        "  $id = $wpdb->get_var(\"SELECT id FROM t WHERE code = '\" . $_GET['code'] . \"'\");\n"
        '  return $wpdb->get_row("SELECT * FROM t WHERE id = \'" . $id . "\'"); }\n'
        "function b_handler() { $o = new Order(); $o->start = $_GET['start']; return $o->level(); }\n"
        "function c_handler() { global $wpdb; $logger = new Logger(); $logger->note($_GET['m']);\n"
        '  return $wpdb->get_var("SELECT x FROM " . $logger->table); }\n'
        "function d_handler() { global $wpdb; $data = json_decode($_GET['j']);\n"
        '  return $wpdb->query("DELETE FROM t WHERE n = \'" . $data->name . "\'"); }\n'
        "function e_handler() { global $wpdb; $o = new Order(); $o->membership_id = $_GET['id'];\n"
        '  return $wpdb->query("DELETE FROM t WHERE id = \'" . $o->membership_id . "\'"); }\n'
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {"sources": "$_GET", "sinks": "$wpdb->get_var,$wpdb->get_row,$wpdb->query", "file": "app.php", "callDepth": "2"}
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({name: {**common, "function": f"{name}_handler"} for name in "abcde"}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    lines = {rid: sorted({int(r["sinkLine"]) for r in payload[rid] if isinstance(r, dict) and r.get("sourceKind")}) for rid in "abcde"}
    assert lines["a"] == [12], f"through a query's result: {lines['a']} (the injection is line 12, not line 13 fed by its result)"
    assert lines["b"] == [], f"a field written, another read through the object: {lines['b']}"
    assert lines["c"] == [], f"an argument into an object's method, its field read: {lines['c']}"
    assert lines["d"] == [18], f"a member of a decoded request value must still be found: {lines['d']}"
    assert lines["e"] == [20], f"the field that was written, read back, must still be found: {lines['e']}"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_filter_returns_its_value_argument_not_its_context(tmp_path: Path) -> None:
    """`apply_filters('h', $value, ...$context)` returns the filtered value. Request data passed as context
    made PMPro's random md5 order code an SQL injection; request data passed as the value must still flow."""
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_text(
        "<?php\n"
        "function context_handler() { global $wpdb; $code = apply_filters('h', md5('x'), $_GET['c']);\n"
        '  return $wpdb->query("DELETE FROM t WHERE code = \'" . $code . "\'"); }\n'
        "function value_handler() { global $wpdb; $v = apply_filters('h', $_GET['v'], 'context');\n"
        '  return $wpdb->query("DELETE FROM t WHERE code = \'" . $v . "\'"); }\n'
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {
        "sources": "$_GET",
        "sinks": "$wpdb->query",
        "file": "app.php",
        "dispatchApply": "apply_filters,do_action",
        "dispatchValue": "apply_filters:2,do_action:0",
    }
    requests = tmp_path / "requests.json"
    requests.write_text(
        json.dumps({"context": {**common, "function": "context_handler"}, "value": {**common, "function": "value_handler"}})
    )
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    flows = {rid: [r for r in payload[rid] if isinstance(r, dict) and r.get("sourceKind")] for rid in ("context", "value")}
    assert not flows["context"], f"filter context became its result: {flows['context']}"
    assert flows["value"], "the filtered value no longer carries request data"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_the_field_join_links_methods_only_through_the_object_itself(tmp_path: Path) -> None:
    """`$this->x` written in one method and read in another is object state; `$user->ID` in two functions is
    two variables. PMPro's `$user = new stdClass; $user->ID = $_POST['user_id']` in one function made the
    WP_User parameter's `$user->ID` in another an SQL injection."""
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_text(
        "<?php\n"
        "function fill() { $user = new stdClass; $user->ID = $_POST['user_id']; return $user; }\n"
        'function history($user) { global $wpdb; return $wpdb->get_var("SELECT 1 WHERE u = \'" . $user->ID . "\'"); }\n'
        "class Mailer {\n  public $attachments;\n  function collect() { $this->attachments = $_POST['files']; }\n"
        '  function send() { global $wpdb; return $wpdb->query("DELETE FROM t WHERE f = \'" . $this->attachments . "\'"); }\n}\n'
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {
        "sources": "$_POST",
        "sinks": "$wpdb->get_var,$wpdb->query",
        "file": "app.php",
        "parameterSources": "false",
        "fieldParameterSources": "true",
    }
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"local": {**common, "function": "history"}, "object": {**common, "function": "send"}}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    flows = {rid: [r for r in payload[rid] if isinstance(r, dict) and r.get("sourceKind")] for rid in ("local", "object")}
    assert not flows["local"], f"another function's local variable tainted this parameter's field: {flows['local']}"
    assert flows["object"], "object state written in one method and read in another is no longer traced"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_sanitizer_the_value_passes_through_inside_an_expression_counts(tmp_path: Path) -> None:
    """`isset($p["id"]) ? intval($p["id"]) : null`: the engine steps from intval's argument to the conditional,
    so `intval` is never a path element. PMPro's REST level id, cast exactly so, was reported as an injection.
    A sanitizer in the OTHER branch must not count."""
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_text(
        "<?php\n"
        "function cast() { global $wpdb; $id = isset($_GET['id']) ? intval($_GET['id']) : null;\n"
        '  return $wpdb->query("DELETE FROM t WHERE id = " . $id); }\n'
        "function other_branch($x) { global $wpdb; $id = isset($_GET['id']) ? $_GET['id'] : intval($x);\n"
        '  return $wpdb->query("DELETE FROM t WHERE id = " . $id); }\n'
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {"sources": "$_GET", "sinks": "$wpdb->query", "sanitizers": "intval", "file": "app.php"}
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({"cast": {**common, "function": "cast"}, "other": {**common, "function": "other_branch"}}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    unsanitized = {
        rid: [r for r in payload[rid] if isinstance(r, dict) and r.get("sourceKind") and not r.get("sanitized")]
        for rid in ("cast", "other")
    }
    assert not unsanitized["cast"], f"a value cast inside a conditional was reported unsanitized: {unsanitized['cast']}"
    assert unsanitized["other"], "a sanitizer in the other branch of the conditional cleaned the tainted branch"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_a_field_the_method_just_overwrote_is_not_object_state(tmp_path: Path) -> None:
    """Every PMPro MemberOrder method builds its statement in `$this->sqlQuery` and runs it at once. One writes
    request data there; `deleteMe()` had just set it from the internal id and was reported. A method that READS
    state another method left must still be found, and so must the method whose own write carries the input."""
    from openultrasast.cpg.backend import extract_payload

    frontend = __import__("shutil").which("php2cpg")
    if frontend is None:
        pytest.skip("php2cpg is not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "order.php").write_text(
        "<?php\nclass Order {\n  public $sqlQuery;\n  public $id;\n"
        "  function find() { global $wpdb;\n"
        "    $this->sqlQuery = \"SELECT 1 WHERE c = '\" . $_POST['c'] . \"'\"; return $wpdb->query($this->sqlQuery); }\n"
        "  function deleteMe() { global $wpdb;\n"
        '    $this->sqlQuery = "DELETE FROM t WHERE id = \'" . $this->id . "\'"; return $wpdb->query($this->sqlQuery); }\n'
        "  function rerun() { global $wpdb; return $wpdb->query($this->sqlQuery); }\n}\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {"sources": "$_POST", "sinks": "$wpdb->query", "file": "order.php", "fieldParameterSources": "true"}
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({name: {**common, "function": name} for name in ("find", "deleteMe", "rerun")}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    flows = {rid: [r for r in payload[rid] if isinstance(r, dict) and r.get("sourceKind")] for rid in ("find", "deleteMe", "rerun")}
    assert flows["find"], "the method whose own write carries request data must be found"
    assert not flows["deleteMe"], f"a field the method had just overwritten was read as object state: {flows['deleteMe']}"
    assert flows["rerun"], "a method reading the state another method left must still be found"


@pytest.mark.skipif(_joern() is None, reason="joern is not installed on this machine")
def test_node_vm_is_an_eval_and_a_package_name_is_not_a_sink(tmp_path: Path) -> None:
    """mongo-express CVE-2019-10758 ran the request body through `vm.runInNewContext`, which no sink named. Its fix
    parses with `mongodb-query-parser`, and every call on that parser carries the package name in its full name --
    which read as the SQL sink `query`. The shipped injection sinks are used, not a hand-picked list."""
    from openultrasast.cpg.backend import extract_payload
    from openultrasast.model.specs import taint_specs

    frontend = __import__("shutil").which("jssrc2cpg")
    if frontend is None:
        pytest.skip("jssrc2cpg is not installed")
    sinks = taint_specs(language="javascript")["injection"].sinks
    src = tmp_path / "src"
    src.mkdir()
    (src / "bson.js").write_text(
        "const vm = require('vm');\n"
        "const parser = require('mongodb-query-parser');\n"
        "const db = require('./db');\n"
        "function vulnerable(req, res) { const doc = req.body.document;\n"
        "  return vm.runInNewContext('doc = eval((' + doc + '));', {}); }\n"
        "function parsed(req, res) { return parser(req.body.document) + parser.toJSString(req.query.x, '  '); }\n"
        "function raw(req, res) { return db.query(req.query.q); }\n"
    )
    cpg = tmp_path / "cpg.bin"
    built = subprocess.run([frontend, str(src), "-o", str(cpg)], capture_output=True, text=True, timeout=600, check=False)
    if not cpg.is_file():
        pytest.skip(f"could not build a sample cpg: {(built.stderr or '')[-200:]}")
    common = {"sources": "req.body,req.query", "sinks": ",".join(sinks), "file": "bson.js"}
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps({name: {**common, "function": name} for name in ("vulnerable", "parsed", "raw")}))
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
    assert done.returncode == 0, (done.stderr or done.stdout or "")[-500:]
    payload = extract_payload(done.stdout or "")
    assert isinstance(payload, dict)
    flows = {rid: [r for r in payload[rid] if isinstance(r, dict) and r.get("sink")] for rid in ("vulnerable", "parsed", "raw")}
    assert any("runInNewContext" in str(r["sink"]) for r in flows["vulnerable"]), flows["vulnerable"]
    assert not flows["parsed"], f"a package name was read as a sink: {flows['parsed']}"
    assert any("query" in str(r["sink"]) for r in flows["raw"]), f"a real query call was lost: {flows['raw']}"
