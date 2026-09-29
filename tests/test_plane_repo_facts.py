"""`repo-facts` (ai-service-plane task 5): cross-file callers, product filter, determinism, per-unit resume."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.plane.tasks import repo_facts

HANDLERS = """\
from .db import run_query
from .util import render

def handler(request):
    rows = run_query(request.args["q"])
    return render(rows)

def unrelated():
    return 1

render(None)
"""
DB = """\
import logging

def run_query(sql):
    # run_query(sql) is documented here, not called
    log("query")
    return sql

def helper():
    return log("x")
"""
UTIL = """\
def log(message):
    print(message)

def render(rows):
    return str(rows)

class Probe:
    def check(self):
        return run_query("select 1")
"""
TEST_FILE = "from app.db import run_query\n\ndef test_run_query():\n    assert run_query('x')\n"
VENDOR_FILE = "def run_query(x):\n    return x\n\nrun_query(1)\n"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    workspace = tmp_path / "ws"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "handlers.py").write_text(HANDLERS)
    (workspace / "app" / "db.py").write_text(DB)
    (workspace / "app" / "util.py").write_text(UTIL)
    (workspace / "tests").mkdir()
    (workspace / "tests" / "test_db.py").write_text(TEST_FILE)
    (workspace / "vendor" / "lib").mkdir(parents=True)
    (workspace / "vendor" / "lib" / "shim.py").write_text(VENDOR_FILE)
    (workspace / "node_modules" / "pkg").mkdir(parents=True)
    (workspace / "node_modules" / "pkg" / "index.js").write_text("function run_query() {}\nrun_query();\n")
    (workspace / "app" / "bundle.min.js").write_text("function run_query(){}run_query();")
    (workspace / ".hidden").mkdir()
    (workspace / ".hidden" / "x.py").write_text("run_query(2)\n")
    return workspace


def _run(workspace: Path, out: Path, candidates: list[dict[str, str]] | None = None) -> dict[str, object]:
    repo_facts.run(workspace, out, candidates)
    facts = json.loads((out / "facts.json").read_text())
    assert isinstance(facts, dict)
    return facts


def test_product_files_exclude_tests_vendor_bundles_and_dotdirs(tree: Path) -> None:
    files = [p.relative_to(tree).as_posix() for p in repo_facts.product_files(tree)]
    assert files == ["app/db.py", "app/handlers.py", "app/util.py"]


def test_cross_file_callers_have_line_and_enclosing_function(tree: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    facts = _run(tree, out, [{"path": "app/db.py", "function": "run_query"}, {"path": "app/util.py", "function": "render"}])
    assert facts["files"] == {
        "app/db.py": {"functions": ["run_query", "helper"]},
        "app/handlers.py": {"functions": ["handler", "unrelated"]},
        "app/util.py": {"functions": ["log", "render", "check"]},
    }
    assert facts["callers"]["app/db.py::run_query"] == [
        {"path": "app/handlers.py", "line": 5, "enclosing": "handler"},
        {"path": "app/util.py", "line": 9, "enclosing": "check"},
    ]
    assert facts["callers"]["app/util.py::render"] == [
        {"path": "app/handlers.py", "line": 6, "enclosing": "handler"},
        {"path": "app/handlers.py", "line": 11, "enclosing": "<global>"},
    ]
    assert facts["counts"] == {"files": 3, "functions": 7, "candidates": 2, "callers": 4}
    summary = json.loads((out / "summary.json").read_text())
    assert summary == {"status": "done", "units_done": 3, "units_total": 3, "usd": None, "calls": 0, "usage": {}, "model": None}


def test_same_file_calls_and_declaration_lines_are_not_callers(tree: Path, tmp_path: Path) -> None:
    facts = _run(tree, tmp_path / "out", [{"path": "app/util.py", "function": "log"}])
    # db.py calls log twice (a call and a comment mentioning it); util.py defines it, so its own lines never count.
    assert facts["callers"]["app/util.py::log"] == [
        {"path": "app/db.py", "line": 5, "enclosing": "run_query"},
        {"path": "app/db.py", "line": 9, "enclosing": "helper"},
    ]


def test_every_function_is_a_candidate_when_none_are_given(tree: Path, tmp_path: Path) -> None:
    facts = _run(tree, tmp_path / "out")
    assert sorted(facts["callers"]) == [
        "app/db.py::helper",
        "app/db.py::run_query",
        "app/handlers.py::handler",
        "app/handlers.py::unrelated",
        "app/util.py::check",
        "app/util.py::log",
        "app/util.py::render",
    ]
    assert facts["callers"]["app/handlers.py::handler"] == []


def test_output_is_byte_identical_on_a_second_run(tree: Path, tmp_path: Path) -> None:
    candidates = [{"path": "app/db.py", "function": "run_query"}]
    _run(tree, tmp_path / "a", candidates)
    _run(tree, tmp_path / "b", candidates)
    for name in ("facts.json", "units.jsonl", "summary.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes(), name


def test_callers_are_capped_at_forty_per_function(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "lib.py").write_text("def target():\n    pass\n")
    (workspace / "many.py").write_text("".join(f"target({i})\n" for i in range(60)))
    facts = _run(workspace, tmp_path / "out", [{"path": "lib.py", "function": "target"}])
    sites = facts["callers"]["lib.py::target"]
    assert len(sites) == repo_facts.CALLERS_CAP == 40
    assert [s["line"] for s in sites] == list(range(1, 41))


def test_resume_skips_files_already_in_units(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    candidates = [{"path": "app/db.py", "function": "run_query"}]
    _run(tree, out, candidates)
    first = (out / "facts.json").read_bytes()
    rows_before = (out / "units.jsonl").read_text().splitlines()
    (out / "facts.json").unlink()
    (out / "summary.json").unlink()
    calls: list[str] = []
    real = repo_facts.call_sites

    def counting(lines: list[str], language: str, names: list[str]) -> list[dict[str, object]]:
        calls.append(language)
        return real(lines, language, names)

    monkeypatch.setattr(repo_facts, "call_sites", counting)
    summary = repo_facts.run(tree, out, candidates)
    assert calls == [], "a file already in units.jsonl was recomputed"
    assert summary["status"] == "done"
    assert (out / "facts.json").read_bytes() == first
    assert (out / "units.jsonl").read_text().splitlines() == rows_before


def test_resume_recomputes_only_the_missing_unit(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    candidates = [{"path": "app/db.py", "function": "run_query"}]
    _run(tree, out, candidates)
    rows = (out / "units.jsonl").read_text().splitlines()
    kept = [r for r in rows if json.loads(r)["path"] != "app/util.py"]
    (out / "units.jsonl").write_text("\n".join(kept) + "\n")
    processed: list[str] = []
    real = repo_facts.call_sites

    def counting(lines: list[str], language: str, names: list[str]) -> list[dict[str, object]]:
        processed.append(lines[0])
        return real(lines, language, names)

    monkeypatch.setattr(repo_facts, "call_sites", counting)
    _run(tree, out, candidates)
    assert processed == ["def log(message):"]
    facts = json.loads((out / "facts.json").read_text())
    assert [s["path"] for s in facts["callers"]["app/db.py::run_query"]] == ["app/handlers.py", "app/util.py"]


def test_rows_from_another_candidate_set_are_not_reused(tree: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    _run(tree, out, [{"path": "app/db.py", "function": "run_query"}])
    facts = _run(tree, out, [{"path": "app/util.py", "function": "render"}])
    assert [s["line"] for s in facts["callers"]["app/util.py::render"]] == [6, 11]
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "done" and summary["units_done"] == 3


def test_summary_is_never_done_when_a_unit_is_missing(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    real = repo_facts.call_sites

    def crash_on_util(lines: list[str], language: str, names: list[str]) -> list[dict[str, object]]:
        if lines[0].startswith("def log"):
            raise OSError("disk went away")
        return real(lines, language, names)

    monkeypatch.setattr(repo_facts, "call_sites", crash_on_util)
    env = {"OUSAST_WORKSPACE_DIR": str(tree), "OUSAST_OUTPUT_DIR": str(out)}
    assert repo_facts.main(env) == 2
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "failed"
    assert (summary["units_done"], summary["units_total"]) == (2, 3)
    assert "disk went away" in summary["traceback"]
    assert not (out / "facts.json").exists()
    # the contract itself refuses `done` with a unit missing, whatever the caller claims
    (tmp_path / "forced").mkdir()
    forced = repo_facts.write_summary(tmp_path / "forced", status="done", units_done=2, units_total=3)
    assert forced["status"] == "failed"
    # and a restart finishes only the missing unit
    monkeypatch.setattr(repo_facts, "call_sites", real)
    assert repo_facts.main(env) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "done" and summary["units_done"] == 3
    assert len((out / "units.jsonl").read_text().splitlines()) == 3


def test_main_reads_candidates_from_the_input_env(tree: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    candidates = tmp_path / "candidates.json"
    candidates.write_text(json.dumps({"candidates": [{"path": "app/db.py", "function": "run_query"}]}))
    env = {"OUSAST_WORKSPACE_DIR": str(tree), "OUSAST_OUTPUT_DIR": str(out), "OUSAST_INPUT_CANDIDATES": str(candidates)}
    assert repo_facts.main(env) == 0
    facts = json.loads((out / "facts.json").read_text())
    assert list(facts["callers"]) == ["app/db.py::run_query"]


def test_main_without_a_workspace_fails_with_a_summary(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert repo_facts.main({"OUSAST_WORKSPACE_DIR": str(tmp_path / "missing"), "OUSAST_OUTPUT_DIR": str(out)}) == 2
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "failed" and "OUSAST_WORKSPACE_DIR" in summary["reason"]


@pytest.mark.parametrize(
    ("language", "source", "expected"),
    [
        ("php", "<?php\nclass A {\n  public static function &load($id) {\n  }\n}\nfunction top() {}\n", ["load", "top"]),
        (
            "javascript",
            "export async function fetchAll() {}\nconst handler = async (req, res) => {\n};\n"
            "class K {\n  save(data) {\n  }\n}\nif (x) {\n}\n",
            ["fetchAll", "handler", "save"],
        ),
        ("typescript", "export const route = (req: Req): void => {\n};\nfunction* gen() {}\n", ["route", "gen"]),
        (
            "java",
            "public class A {\n  public static List<String> names(int n) throws IOException {\n  }\n"
            "  private void go() {\n    return foo(1);\n  }\n  else if (x) {\n  }\n}\n",
            ["names", "go"],
        ),
        ("go", "func (r *Repo) Get(id int) error {\n}\nfunc main() {\n}\n", ["Get", "main"]),
        ("ruby", "class A\n  def self.build(x)\n  end\n  def valid?\n  end\nend\n", ["build", "valid?"]),
    ],
)
def test_declaration_patterns_per_language(language: str, source: str, expected: list[str]) -> None:
    assert repo_facts.declared_functions(source.splitlines(), language) == expected


def test_enclosing_function_in_python_respects_indentation() -> None:
    lines = ["def a():", "    x()", "", "def b():", "    def inner():", "        y()", "    z()", "", "w()"]
    assert repo_facts.enclosing(lines, 1, "python") == "a"
    assert repo_facts.enclosing(lines, 5, "python") == "inner"
    assert repo_facts.enclosing(lines, 6, "python") == "b"
    assert repo_facts.enclosing(lines, 8, "python") == "<global>"
