"""The improvement loop as a plane Run (harnessx-removal Req 6.3, design section 6).

The whole graph runs through the reconciler and the fake ax of ``test_plane_reconciler``, whose ``exec`` mode runs the
real task modules on the inputs the receiver serves: a recorded case's chain (validation-46's lmdeploy case from
``tests/fixtures/plane-remember``, already done) -> ``alerts`` -> ``remember`` -> ``loop-measure`` -> ``loop-propose``
-> ``loop-improve``, with ``memory-snapshot`` seeded on the host from a crafted store.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from test_plane_reconciler import Fake, fake  # noqa: F401 -- `fake` is the fixture

import openultrasast
from openultrasast import cli
from openultrasast.plane import reconciler
from openultrasast.plane.generate import TEMPLATES, CaseInputs, Loop, fix_ranges, render
from openultrasast.plane.manifests import load_manifests
from openultrasast.plane.memory import SNAPSHOT_ANNOTATION, FileStore, row_id
from openultrasast.plane.tasks import alerts

FIXTURE = Path(__file__).parent / "fixtures" / "plane-remember" / "validation-46"
PLANE = Path(__file__).resolve().parents[1] / "plane"
SRC = str(Path(openultrasast.__file__).resolve().parents[1])
CASE = "lmdeploy-media-url-ssrf"
VULNERABLE = "71648d239c978452720a6d6692fe914efc8a7b94"
FIXED = "ab" * 20
OTHER = "12" * 20
EVAL = "python-unsafe-eval"  # a bundled, enabled rule
CHAIN = ("facts", "va", "vb", "agree", "vc", "final")
LOOP_TASKS = ("memory-snapshot", "loop-measure", "loop-propose", "loop-improve")


def _case(**ranges: Any) -> CaseInputs:
    record = {
        "id": CASE, "repo": "https://example.com/reserved/lmdeploy", "family": "untrusted_destination", "vulnerable": VULNERABLE,
        "fixed": FIXED, "sites": ["lmdeploy/vl/media/connection.py::_load_http_url"],
    }  # fmt: skip
    candidate = ("lmdeploy/vl/media/connection.py", "_load_http_url", 40)
    return CaseInputs(record, (candidate,), (candidate,), {}, 0.02, **ranges)


def _templates() -> dict:
    return load_manifests([PLANE / "tasks" / f"{name}.yaml" for name in TEMPLATES]).tasks


LOOP = Loop(repo="https://example.invalid/openultrasast.git", commit="c" * 40, manifest="bench.toml", catalog="catalog.toml")


def _write(plane: Path, files: dict[str, str]) -> Path:
    shutil.copytree(PLANE / "models", plane / "models")
    for relative, text in files.items():
        (plane / relative).parent.mkdir(parents=True, exist_ok=True)
        (plane / relative).write_text(text)
    return plane / "runs" / "validation-46.yaml"


# --- alerts --------------------------------------------------------------------------------------------------------


def test_alerts_attribute_functions_and_mark_the_fix_on_both_pins(tmp_path: Path) -> None:
    vulnerable, fixed = tmp_path / "v", tmp_path / "f"
    (vulnerable / "pkg").mkdir(parents=True)
    (fixed / "pkg").mkdir(parents=True)
    (vulnerable / "pkg" / "run.py").write_text("import os\n\ndef handle(x):\n    y = x\n    return eval(y)\n")
    (fixed / "pkg" / "run.py").write_text("import os\n\ndef handle(x):\n    return eval(x, {})\n\nprint(eval('1'))\n")
    case = tmp_path / "case.json"
    case.write_text(json.dumps({"ranges": {"pkg/run.py": [[4, 5]]}, "fixed_ranges": {"pkg/run.py": [[4, 4]]}}))
    out = tmp_path / "out"
    env = {
        "OUSAST_OUTPUT_DIR": str(out), "OUSAST_WORKSPACE_DIR": str(vulnerable), "OUSAST_FIXED_DIR": str(fixed),
        "OUSAST_INPUT_CASE": str(case), "OUSAST_VULNERABLE_PIN": VULNERABLE, "OUSAST_FIXED_PIN": FIXED,
    }  # fmt: skip
    assert alerts.main(env) == 0
    rows = [json.loads(line) for line in (out / "alerts.jsonl").read_text().splitlines()]
    got = [(r["rule_id"], r["pin_role"], r["pin"], r["line"], r["function"], r["in_fix_range"]) for r in rows if r["rule_id"] == EVAL]
    assert got == [
        (EVAL, "vulnerable", VULNERABLE, 5, "handle", True),
        (EVAL, "fixed", FIXED, 4, "handle", True),
        (EVAL, "fixed", FIXED, 6, "<global>", False),
    ]
    summary = json.loads((out / "summary.json").read_text())
    assert (summary["status"], summary["units_done"], summary["usd"], summary["calls"], summary["model"]) == ("done", 2, 0, 0, None)
    assert summary["read"]["vulnerable"]["files"] == 1 and summary["read"]["vulnerable"]["bytes"] > 0, "the scan read its tree"
    assert alerts.in_range(None, "pkg/run.py", 4) is None, "no ranges: unknown, not outside"

    empty = tmp_path / "empty"
    empty.mkdir()
    assert alerts.main({**env, "OUSAST_FIXED_DIR": str(empty)}) == 2
    assert "an unread tree is not a clean one" in json.loads((out / "summary.json").read_text())["reason"]


def test_quick_coverage_is_derived_from_the_ruleset_directory(tmp_path: Path) -> None:
    shipped = alerts.quick_languages()
    assert {"python", "javascript", "typescript", "java", "c", "groovy", "php"} <= shipped, "PHP has quick rules"
    assert "php" in alerts.engine_languages(), "the engine's semantic models cover PHP"
    rules = tmp_path / "ruleset" / "php"
    rules.mkdir(parents=True)
    rule = 'rule_id = "php-x"\ntitle = "x"\nlanguages = ["php"]\ncwe = "CWE-89"\ntags = []\npattern = "x"\n'
    (rules / "rules.toml").write_text(f"[[rule]]\n{rule}")
    assert alerts.quick_languages(tmp_path / "ruleset") == {"php"}, "a ruleset added for a language covers it"
    (rules / "rules.toml").write_text(f'[[rule]]\n{rule}status = "disabled"\n')
    assert alerts.quick_languages(tmp_path / "ruleset") == set(), "a disabled rule fires nowhere"


def test_alerts_on_an_uncovered_language_record_coverage_none_not_a_clean_zero(tmp_path: Path) -> None:
    for side in ("v", "f"):
        (tmp_path / side).mkdir()
        (tmp_path / side / "app.rb").write_text('id = params["id"]\nDB.execute("SELECT " + id)\n')
        (tmp_path / side / "app.js").write_text("module.exports = 1;\n")
    out = tmp_path / "out"
    env = {
        "OUSAST_OUTPUT_DIR": str(out), "OUSAST_WORKSPACE_DIR": str(tmp_path / "v"), "OUSAST_FIXED_DIR": str(tmp_path / "f"),
        "OUSAST_VULNERABLE_PIN": VULNERABLE, "OUSAST_FIXED_PIN": FIXED,
    }  # fmt: skip
    assert alerts.main(env) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert (out / "alerts.jsonl").read_text() == "" and summary["alerts"] == {"vulnerable": 0, "fixed": 0}
    assert summary["coverage"] == {
        "javascript": {"coverage": "quick", "files": {"fixed": 1, "vulnerable": 1}},
        "ruby": {"coverage": "none", "files": {"fixed": 1, "vulnerable": 1}},
    }
    assert summary["uncovered"] == ["ruby"] and summary["pins"] == {"vulnerable": VULNERABLE, "fixed": FIXED}


def test_php_is_quick_covered_and_alerts_on_a_php_sink(tmp_path: Path) -> None:
    for side in ("v", "f"):
        (tmp_path / side).mkdir()
        (tmp_path / side / "index.php").write_text('<?php\n$id = $_GET["id"];\nmysqli_query($c, "SELECT " . $id);\n')
    out = tmp_path / "out"
    env = {
        "OUSAST_OUTPUT_DIR": str(out), "OUSAST_WORKSPACE_DIR": str(tmp_path / "v"), "OUSAST_FIXED_DIR": str(tmp_path / "f"),
        "OUSAST_VULNERABLE_PIN": VULNERABLE, "OUSAST_FIXED_PIN": FIXED,
    }  # fmt: skip
    assert alerts.main(env) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["coverage"] == {"php": {"coverage": "quick", "files": {"fixed": 1, "vulnerable": 1}}}
    assert summary["uncovered"] == [] and summary["alerts"] == {"vulnerable": 1, "fixed": 1}
    rows = [json.loads(line) for line in (out / "alerts.jsonl").read_text().splitlines()]
    assert {(r["rule_id"], r["line"]) for r in rows} == {("php-sql-call-composition", 3)}


def test_fix_ranges_new_side_are_the_fixed_pins_lines(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    (repo / "a.py").write_text("a\nb\nc\n")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "v"], check=True)
    old = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    (repo / "a.py").write_text("a\nB1\nB2\nB3\nc\n")
    subprocess.run([*git, "commit", "-qam", "f"], check=True)
    new = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    assert fix_ranges(repo, old, new) == {"a.py": [(2, 2)]}
    assert fix_ranges(repo, old, new, side="new") == {"a.py": [(2, 4)]}


# --- the generator -------------------------------------------------------------------------------------------------


def test_every_case_ends_in_remember_and_the_loop_is_model_free(tmp_path: Path) -> None:
    plain = render([_case()], _templates(), "validation-46", "t", population="population-v2", split="validation")
    run, _ = reconciler.load_run(_write(tmp_path / "plain", plain))
    assert [e.name.removeprefix(f"{CASE}-") for e in run.tasks] == [*CHAIN[:4], "vc", "final", "remember"]
    remember = run.task(f"{CASE}-remember")
    assert remember.inputs["agreed"] == f"{CASE}-final/agreed.json" and "alerts" not in remember.inputs
    assert set(remember.producers) == {f"{CASE}-{step}" for step in ("facts", "va", "vb", "vc", "final")}

    files = render([_case(fixed_ranges={"x.py": [(1, 2)]})], _templates(), "validation-46", "t", population="p", split="s", loop=LOOP)
    run, manifests = reconciler.load_run(_write(tmp_path / "loop", files))
    names = [e.name for e in run.tasks]
    assert names[:6] == [f"{CASE}-{step}" for step in CHAIN] and names[6:] == [f"{CASE}-alerts", f"{CASE}-remember", *LOOP_TASKS]
    assert run.task(f"{CASE}-remember").inputs["alerts"] == f"{CASE}-alerts/alerts.jsonl"
    assert run.task(f"{CASE}-remember").inputs["alerts_summary"] == f"{CASE}-alerts/summary.json", "the coverage travels too"
    measure_inputs = {f"remember_{CASE}": f"{CASE}-remember/memory.jsonl", "snapshot": "memory-snapshot/rows.jsonl"}
    assert run.task("loop-measure").inputs == measure_inputs
    assert run.task("loop-improve").producers == ("loop-propose",)
    assert run.task("loop-propose").producers == ("loop-measure", "memory-snapshot")
    assert run.task(f"{CASE}-alerts").serialize == run.task("loop-improve").serialize == "engine"
    fixed = manifests.workspaces[f"{CASE}-fixed"]
    assert fixed.pins == {"repo": FIXED} and manifests.workspaces["openultrasast-cccccccccccc"].pins == {"repo": "c" * 40}
    for entry in run.tasks[6:]:
        task = manifests.tasks[entry.task]
        assert entry.budget is not None and (entry.budget.usd, entry.budget.calls) == (0, 0), entry.name
        assert reconciler.MODEL_ANNOTATION not in task.metadata.annotations, f"{entry.name} binds no Model"
        docs = reconciler.render_task(run, entry, manifests, "http://127.0.0.1:1/")
        env = {e["name"]: e["value"] for e in docs[-1]["spec"]["env"]}
        assert "OUSAST_MODEL" not in env and float(env["OUSAST_BUDGET_USD"]) == 0 and env["OUSAST_BUDGET_CALLS"] == "0"
    guard = json.loads(manifests.tasks["memory-snapshot"].metadata.annotations[SNAPSHOT_ANNOTATION])
    assert guard == {"catalog": "catalog.toml", "manifest": "bench.toml", "populations": []}
    inputs = yaml.safe_load((tmp_path / "loop" / "workspaces" / f"{CASE}-inputs.yaml").read_text())
    case_json = json.loads(next(f["content"] for f in inputs["spec"]["files"] if f["path"] == "case.json"))
    assert case_json["fixed_ranges"] == {"x.py": [[1, 2]]}


# --- the whole loop through the fake ax ----------------------------------------------------------------------------


def _project(root: Path) -> Path:
    """This repository at the commit under test, cut down: a benchmark whose one expected finding the eval rule
    makes, and an empty pair catalog."""
    (root / "target").mkdir(parents=True)
    (root / "target" / "app.py").write_text("def f(x):\n    return eval(x)\n")
    (root / "bench.toml").write_text(
        'name = "t"\nlanguage = "python_web"\n\n[source]\npath = "target"\n\n[[expected]]\ncwe = "CWE-95"\n'
        f'class = "code injection"\npath = "app.py"\nline = 2\nrule_id = "{EVAL}"\nsink = "eval"\nevidence = "eval"\n'
    )
    (root / "catalog.toml").write_text("")
    (root / "benchmarks" / "pairs").mkdir(parents=True)  # the catalog loader's mechanism vocabulary, by relative path
    shutil.copy(PLANE.parent / "benchmarks" / "pairs" / "mechanisms.toml", root / "benchmarks" / "pairs")
    return root


def _older_run(store: FileStore) -> None:
    """Two false alerts of the eval rule at rejected candidates of another repository, from an earlier run."""
    rows = []
    for fn in ("f1", "f2"):
        base = {"repo": "example.com/other/app", "pin": OTHER, "run": "older", "task": "app-remember", "population": "p", "split": "s"}
        base["image"] = "sha256:" + "0" * 64
        cand = f"app.py::{fn}"
        rows.append({**base, "id": row_id("verdict", "older", "app-remember", cand), "kind": "verdict", "candidate": cand,
                     "family": "code_injection", "final": "rejected", "site_match": False})  # fmt: skip
        rows.append({**base, "id": row_id("alert", "older", "app-remember", fn), "kind": "alert", "rule_id": EVAL,
                     "rule_status": "enabled", "path": "app.py", "line": 3, "function": fn, "pin_role": "vulnerable"})  # fmt: skip
    store.ingest_rows("older", "app-remember", rows)


def test_the_loop_runs_as_one_plane_run_and_the_gate_rejects_a_demotion_that_costs_recall(
    fake: Fake,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project(tmp_path / "project")
    monkeypatch.chdir(project)  # `ousast plane run` from the repository root: the snapshot's guard paths resolve here
    store = FileStore(tmp_path / "memory")
    _older_run(store)
    monkeypatch.setenv("OUSAST_MEMORY", f"file://{store.root}")
    vulnerable, fixed = tmp_path / "checkout-v", tmp_path / "checkout-f"
    for root, body in ((vulnerable, "def load(x):\n    return x\n"), (fixed, "def load(x):\n    return eval(x)\n")):
        (root / "lmdeploy" / "vl" / "media").mkdir(parents=True)
        (root / "lmdeploy" / "vl" / "media" / "other.py").write_text(body)
    case = _case(ranges={"lmdeploy/vl/media/other.py": [(1, 2)]}, fixed_ranges={"lmdeploy/vl/media/other.py": [(1, 2)]})
    files = render([case], _templates(), "validation-46", "t", population="population-v2", split="validation", loop=LOOP)
    manifest = _write(tmp_path / "plane", files)
    inputs = yaml.safe_load((tmp_path / "plane" / "workspaces" / f"{CASE}-inputs.yaml").read_text())
    (tmp_path / "case.json").write_text(next(f["content"] for f in inputs["spec"]["files"] if f["path"] == "case.json"))

    base = reconciler.run_dir("validation-46")  # the recorded chain, done: the loop reuses it and runs only itself
    shutil.copytree(FIXTURE, base)
    state = {"run": "validation-46", "tasks": {f"{CASE}-{s}": {"status": "done"} for s in CHAIN}}
    (base / "state.json").write_text(json.dumps(state))

    project_env = {"PYTHONPATH": SRC, "OUSAST_PROJECT_DIR": str(project)}
    fake.script({
        f"{CASE}-alerts": {"exec": {"env": {"PYTHONPATH": SRC, "OUSAST_WORKSPACE_DIR": str(vulnerable), "OUSAST_FIXED_DIR": str(fixed),
                                            "OUSAST_INPUT_CASE": str(tmp_path / "case.json")}}},
        f"{CASE}-remember": {"exec": {"env": {"PYTHONPATH": SRC}}},
        "loop-measure": {"exec": {"env": {"PYTHONPATH": SRC}}},
        "loop-propose": {"exec": {"env": project_env}},
        "loop-improve": {"exec": {"env": project_env}},
    })  # fmt: skip

    assert cli.main(["plane", "run", str(manifest), "--ax", str(fake.ax)]) == 0, (fake.root / "ax.log").read_text()[-3000:]

    statuses = {name: info["status"] for name, info in json.loads((base / "state.json").read_text())["tasks"].items()}
    assert set(statuses.values()) == {"done"} and len(statuses) == 12
    assert json.loads((base / "memory-snapshot" / "index.json").read_text())["kept"] == 4, "seeded on the host, not run"
    delivered = [name for _, name in fake.events("delivered")]
    assert delivered == [f"{CASE}-alerts", f"{CASE}-remember", "loop-measure", "loop-propose", "loop-improve"]

    measure = json.loads((base / "loop-measure" / "measure.json").read_text())
    assert measure["run_metrics"]["declared_sites_agreed"] == 1 and measure["run_metrics"]["candidates"] == 1
    assert measure["run_metrics"]["alerts"] == {EVAL: {"vulnerable": 0, "fixed": 1, "fixed_in_fix_range": 1}}
    assert measure["union_metrics"]["rejected"] == 2 and measure["rows"]["snapshot"] == 4

    [proposal] = [json.loads(line) for line in (base / "loop-propose" / "proposals.jsonl").read_text().splitlines()]
    assert proposal["edit"]["rule_id"] == EVAL and (proposal["edit"]["from_status"], proposal["edit"]["to_status"]) == ("enabled", "shadow")
    assert proposal["provenance"]["counts"] == {"false_alerts": 3, "repos": 2, "agreed_hits": 0}
    cited = {(e["kind"], e["repo"], e["pin"]) for e in proposal["provenance"]["evidence"]}
    assert ("alert", "example.com/reserved/lmdeploy", FIXED) in cited, "the fixed-pin alert inside the fix is evidence"
    assert (base / "loop-propose" / "memory_proposals.jsonl").read_text().count("\n") == 1

    gate = json.loads((base / "loop-improve" / "gate.json").read_text())
    assert gate["memory_edits"] == [f"rule:{EVAL}:enabled->shadow"] and gate["accepted"] is False and gate["reason"] == "reverted"
    assert gate["outcome"]["recall_after"] < gate["outcome"]["recall_before"], "demoting the eval rule loses the benchmark's finding"
    assert not (base / "loop-improve" / "rule_policy.json").exists(), "a ledger only when the gate accepts"
    assert json.loads((base / "loop-improve" / "journal.json").read_text())[0]["outcome"] == "reverted"
    assert not (project / "target" / ".openultrasast").exists(), "the repository's own ledger is never touched"

    report = reconciler.attribution("validation-46")
    for row in report["tasks"]:
        if row["task"] in (f"{CASE}-alerts", f"{CASE}-remember", *LOOP_TASKS):
            assert row["model"] is None and row["usd"] in (0, None) and row["calls"] in (0, None), row
    ingested = FileStore(store.root)
    outcomes = ingested.rows(kind="proposal_outcome")
    assert {r.row["outcome"] for r in outcomes} == {"reverted"} and len(outcomes) == 2, "one per (repo, pin) of the evidence"
    [fixed_alert] = ingested.rows(repo="example.com/reserved/lmdeploy", pin=FIXED, kind="alert")
    assert fixed_alert.row["in_fix_range"] is True and fixed_alert.row["function"] == "load"
