"""Per-repository role inference (learned-decision-engine task 3; Req 8.1): wrapper inference to depth 3 from source
text with no framework table, the vocabulary overlay the engine takes, the ``roles``/``model_sinks`` feature parts,
and the model ``roles`` task under a scripted client -- no model is called."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.learn.features import Vocabulary, build_for_scan, function_of, model_sinks_part, roles_part
from openultrasast.learn.roles import (
    RoleSet,
    base_roles,
    from_model_roles,
    functions_of,
    infer_for_checkout,
    infer_wrappers,
    parameters,
    vocabulary_overlay,
)
from openultrasast.model.specs import taint_specs
from openultrasast.plane.budget import MeteredClient
from openultrasast.plane.tasks import roles as roles_task
from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient

APP_PHP = """<?php
function run_sql($q) {
    return mysqli_query($GLOBALS['db'], $q);
}
function fetch_rows($table, $where) {
    $sql = "SELECT * FROM " . $table . " WHERE " . $where;
    return run_sql($sql);
}
function find_user($id) {
    return fetch_rows('users', "id=" . $id);
}
function find_admin($x) {
    return find_user($x);
}
function constant_only() {
    return run_sql("SELECT 1");
}
function param_unused($a) {
    return run_sql("SELECT 1");
}
function clean_html($v) {
    $out = htmlspecialchars($v);
    return $out;
}
function param($k) {
    return $_GET[$k];
}
function current_id() {
    $v = param('id');
    return $v;
}
"""


def _write(root: Path, path: str, text: str) -> None:
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / path).write_text(text)


def _by_name(roles: RoleSet) -> dict[tuple[str, str], int]:
    return {(r.kind, r.name): r.depth for r in roles.roles}


def test_wrapper_inference_reaches_depth_three_and_stops(tmp_path: Path) -> None:
    _write(tmp_path, "src/app.php", APP_PHP)
    roles = infer_for_checkout(tmp_path)
    got = _by_name(roles)
    assert got[("sink", "run_sql")] == 1 and got[("sink", "fetch_rows")] == 2 and got[("sink", "find_user")] == 3
    assert ("sink", "find_admin") not in got, "depth 4 is past the bound"
    assert ("sink", "constant_only") not in got and ("sink", "param_unused") not in got, "a parameter must reach the call"
    assert got[("sanitizer", "clean_html")] == 1, "a parameter reaches htmlspecialchars and its result is returned"
    assert got[("source", "param")] == 1 and got[("source", "current_id")] == 2
    by = {r.name: r for r in roles.roles}
    assert by["run_sql"].operation == "sql" and by["run_sql"].via == "mysqli_query" and by["run_sql"].origin == "inferred_wrapper"
    assert by["find_user"].operation == "sql" and by["find_user"].via == "fetch_rows"
    assert roles.counts()["by_depth"] == {"1": 3, "2": 2, "3": 1}


def test_dependency_source_makes_a_framework_method_a_sink_without_a_table(tmp_path: Path) -> None:
    """A vendored database class reaching mysqli makes `->query` a sink of the plugin -- priors stay off."""
    _write(
        tmp_path,
        "vendor/acme/db/Db.php",
        "<?php\nclass Db {\n    public function query($sql) {\n        return mysqli_query($this->link, $sql);\n    }\n}\n",
    )
    _write(
        tmp_path,
        "plugin.php",
        '<?php\nfunction lookup($name) {\n    global $db;\n    return $db->query("SELECT * WHERE n=\'" . $name . "\'");\n}\n',
    )
    roles = infer_for_checkout(tmp_path)
    by = {r.name: r for r in roles.roles}
    assert by["query"].dependency and by["query"].depth == 1
    assert by["lookup"].depth == 2 and by["lookup"].via == "query" and not by["lookup"].dependency
    assert infer_for_checkout(tmp_path, dependencies=False).roles == (), "without the dependency source nothing is known"


def test_priors_are_optional_and_off_by_default(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "p.php",
        '<?php\nfunction count_rows($where) {\n    global $wpdb;\n    return $wpdb->get_var("SELECT COUNT(*) WHERE " . $where);\n}\n',
    )
    assert infer_for_checkout(tmp_path).roles == (), "the WordPress sink is a prior, off by default"
    with_priors = {r.name: r for r in infer_for_checkout(tmp_path, priors="all").roles}
    assert with_priors["count_rows"].via == "$wpdb->get_var"
    assert all(r.origin == "language" for r in base_roles("php")), "priors off: language-level entries only"
    assert any(r.origin == "prior" for r in base_roles("php", priors="all"))


def test_python_and_javascript_parameters_and_wrappers(tmp_path: Path) -> None:
    assert parameters("def run(self, cmd: str, *args, flag=False):", "run", "python") == ("cmd", "args", "flag")
    assert parameters("function go({ url, opts }, cb = null) {", "go", "javascript") == ("url", "opts", "cb")
    assert parameters("public void save(final String name, int n) {", "save", "java") == ("name", "n")
    assert parameters("function f(?int $a, array &$b = []) {", "f", "php") == ("$a", "$b")
    _write(
        tmp_path,
        "tool/shell.py",
        "import os\n\n\nclass Runner:\n    def shell(self, cmd):\n        full = 'sh -c ' + cmd\n        os.system(full)\n",
    )
    _write(tmp_path, "web/fetch.js", "const http = require('http');\nfunction runIt(code) {\n  return eval(code);\n}\n")
    got = _by_name(infer_for_checkout(tmp_path))
    assert got[("sink", "shell")] == 1 and got[("sink", "runIt")] == 1


def test_the_overlay_is_the_engine_vocabulary_with_origins(tmp_path: Path) -> None:
    _write(tmp_path, "src/app.php", APP_PHP)
    roles = infer_for_checkout(tmp_path)
    overlay = vocabulary_overlay(roles, "php")
    ids = {s.id for s in overlay.sinks}
    assert "inferred_wrapper:sql" in ids and "wpdb" not in ids, "priors off: the WordPress entry is not in the overlay"
    injection = taint_specs(language="php", facts=overlay)["injection"]
    assert {"run_sql", "fetch_rows", "find_user", "mysqli_query"} <= set(injection.sinks)
    assert "param(" in injection.sources and "clean_html" in injection.sanitizers
    vocabulary = Vocabulary.load("php", overlay)
    assert vocabulary.sink("run_sql") == ("sql", "inferred_wrapper") and vocabulary.sink("mysqli_query") == ("sql", "language")
    assert vocabulary.source("param('id')") == ("inferred_role", "inferred_wrapper")


def test_roles_feature_part(tmp_path: Path) -> None:
    _write(tmp_path, "src/app.php", APP_PHP)
    roles = infer_for_checkout(tmp_path)
    lines = APP_PHP.splitlines()
    run_sql = roles_part(function_of(lines, "src/app.php", "php", "run_sql"), roles, "php")
    find_user = roles_part(function_of(lines, "src/app.php", "php", "find_user"), roles, "php")
    getter = roles_part(function_of(lines, "src/app.php", "php", "current_id"), roles, "php")
    assert run_sql.values == {"roles.sink_confidence": 1.0, "roles.source_in_function": False}
    assert find_user.values["roles.sink_confidence"] == 0.333333, "it calls a depth-2 wrapper"
    assert getter.values == {"roles.sink_confidence": None, "roles.source_in_function": True}
    assert roles_part(None, roles, "php").state == "failed" and roles_part(None, None, "php").state == "none"
    assert [f.name for f in functions_of("a.php", lines, "php")][:2] == ["run_sql", "fetch_rows"]


def test_a_language_without_declarations_is_none_not_failed() -> None:
    """C has no declaration pattern: the span and wrapper roles cannot run there (no coverage), which is not a broken
    instrument (harvest 2026-10-01: every memory pair read as `failed`)."""
    from openultrasast.learn.features import source_part
    from openultrasast.learn.roles import RoleSet

    lines = ["int f(char *s) {", "  return strcpy(buf, s);", "}"]
    assert source_part(lines, "c", "f").state == "none"
    assert roles_part(None, RoleSet(sources=("inferred_wrapper",)), "c").state == "none"
    assert source_part(["def g():", "    pass"], "python", "missing").state == "failed"


def test_build_for_scan_records_the_roles_instrument(tmp_path: Path) -> None:
    from openultrasast.findings import quick_scan_findings
    from openultrasast.preprocess import preprocess_repository
    from openultrasast.rank import rank_targets

    _write(tmp_path, "app/one.py", "import os\n\n\ndef inner(value):\n    os.system(value)\n")
    _, targets = preprocess_repository(tmp_path)
    assert targets and (tmp_path / targets[0].path).stat().st_size > 0, "the fixture was read"
    findings = quick_scan_findings(tmp_path, targets, rank_targets(targets))
    records = build_for_scan(tmp_path, findings, None)
    assert records and records[0]["instruments"]["roles"]["state"] == "ran"
    assert records[0]["x"]["roles.sink_confidence"] == 1.0
    off = build_for_scan(tmp_path, findings, None, roles=False)
    assert off[0]["instruments"]["roles"]["state"] == "none" and off[0]["x"]["roles.sink_confidence"] is None


# --- model roles: the plane task under a scripted client ----------------------------------------------------------


def _answer(roles: list[dict[str, object]]) -> ChatResponse:
    return ChatResponse(content=json.dumps({"roles": roles}))


def test_model_roles_task_writes_roles_and_never_reads_a_failed_chunk_as_no_roles(tmp_path: Path) -> None:
    workspace, out = tmp_path / "ws", tmp_path / "out"
    _write(workspace, "a.py", "import requests\n\n\ndef fetch(u):\n    return requests.get(u)\n")
    _write(workspace, "b.py", "def other(x):\n    return x\n")
    sink = {
        "role": "sink",
        "function": "fetch",
        "line": 5,
        "call": "requests.get(u)",
        "operation": "outbound_request",
        "evidence": "requests.get(u)",
    }
    bogus = {"role": "villain", "function": "fetch", "line": 5, "call": "x"}
    client = ScriptedChatClient([_answer([sink, bogus]), ChatResponse(content="not json")])
    summary = roles_task.run(workspace, out, client=client, model="scripted")
    assert summary["status"] == "done" and summary["units_done"] == 2
    assert summary["unclassified_chunks"] == 1 and summary["roles"] == {"sink": 1}
    payload = json.loads((out / "roles.json").read_text())
    assert payload["unclassified_paths"] == ["b.py"] and payload["roles"][0]["operation"] == "outbound_request"
    modelled = from_model_roles(payload)
    assert [r.name for r in modelled.roles] == ["requests.get"] and modelled.roles[0].origin == "model_role"
    flagged = model_sinks_part(modelled, "a.py", "fetch", "scripted")
    assert flagged.values == {"ms.flagged": True, "ms.operation": "outbound_request"}
    assert model_sinks_part(modelled, "b.py", "other").state == "failed", "an unclassified file is never 'no sink'"
    assert model_sinks_part(modelled, "a.py", "helper").values == {"ms.flagged": False, "ms.operation": None}
    assert model_sinks_part(None, "a.py", "fetch").state == "none"
    overlay = vocabulary_overlay(modelled, "python")
    assert any(s.id == "model_role:outbound_request" and s.calls == ("requests.get",) for s in overlay.sinks), "priors off"
    assert "requests.get" in {c for s in overlay.sinks for c in s.calls}


def test_model_roles_task_stops_at_the_budget_and_resumes(tmp_path: Path) -> None:
    workspace, out = tmp_path / "ws", tmp_path / "out"
    _write(workspace, "a.py", "def a(x):\n    return x\n")
    _write(workspace, "b.py", "def b(x):\n    return x\n")
    client = ScriptedChatClient([_answer([])], cycle=True)
    first = roles_task.run(workspace, out, client=client, budget=MeteredClient(client, budget_calls=1), model="scripted")
    assert first["status"] == "unfinished" and first["units_done"] == 1
    second = roles_task.run(workspace, out, client=client, model="scripted")
    assert second["status"] == "done" and second["units_done"] == 2 and len(client.calls) == 2, "the finished file is not re-asked"


def test_model_roles_task_refuses_files_outside_the_workspace(tmp_path: Path) -> None:
    (tmp_path / "ws").mkdir()
    summary = roles_task.run(tmp_path / "ws", tmp_path / "out", client=ScriptedChatClient([]), files=["missing.py"])
    assert summary["status"] == "failed" and "missing.py" in summary["reason"]


def test_plane_features_carry_the_model_sinks_part(tmp_path: Path) -> None:
    from openultrasast.plane.tasks.features import case_features

    _write(tmp_path, "a.py", "import requests\n\n\ndef fetch(u):\n    return requests.get(u)\n")
    agreed = {"family": "untrusted_destination", "candidates": [{"candidate": "a.py::fetch", "site": "a.py:5:fetch", "agreed": True}]}
    roles = {
        "model": "scripted",
        "roles": [
            {"path": "a.py", "role": "sink", "function": "fetch", "line": 5, "call": "requests.get", "operation": "outbound_request"}
        ],
    }
    records = case_features(facts=None, passes={}, models={}, agreed=agreed, workspace=tmp_path, model_roles=roles)
    assert records[0]["x"]["ms.flagged"] is True and records[0]["instruments"]["model_sinks"] == {"state": "ran", "version": "scripted"}
    assert records[0]["instruments"]["roles"]["state"] == "ran"
    none = case_features(facts=None, passes={}, models={}, agreed=agreed, workspace=tmp_path)
    assert none[0]["instruments"]["model_sinks"]["state"] == "none"


def test_an_ambiguous_name_is_a_role_only_when_every_definition_derives_it(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "import os\n\n\ndef send(cmd):\n    os.system(cmd)\n")
    _write(tmp_path, "b.py", "def send(message):\n    return message\n")
    assert infer_for_checkout(tmp_path).roles == (), "one of two `send` definitions is not a sink"
    _write(tmp_path, "b.py", "import subprocess\n\n\ndef send(message):\n    subprocess.run(message)\n")
    assert _by_name(infer_for_checkout(tmp_path)) == {("sink", "send"): 1}


def test_infer_wrappers_is_deterministic_and_name_free_in_counts(tmp_path: Path) -> None:
    lines = APP_PHP.splitlines()
    one = infer_wrappers(functions_of("x/a.php", lines, "php"))
    two = infer_wrappers(list(reversed(functions_of("x/a.php", lines, "php"))))
    assert one == two
    assert RoleSet.from_json(json.loads(json.dumps(one.to_json()))) == one
    assert "run_sql" not in json.dumps(one.counts())
