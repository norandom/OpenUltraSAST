"""The hunt program with a scripted model: signature masks, rendering, the answer rules, the program id."""

from __future__ import annotations

import json

import pytest

dspy = pytest.importorskip("dspy")
from dspy.utils import DummyLM  # noqa: E402

from openultrasast.hunt import program as hp  # noqa: E402

CHANGE = {"id": "c1", "kind": "vulnerability", "path": "app.py", "function": "second", "family": "injection"}
ROWS = [
    {
        "change_id": "c1",
        "path": "app.py",
        "line": 5,
        "feature.diff.hunks": [[3, 3]],
        "feature.source.function": "second",
        "feature.source.span": [5, 7],
        "feature.source.callers": [["web.py", 2]],
        "feature.source.entry_points": [],
        "feature.semantic.roles": {"eval": "sink"},
        "feature.semantic.def_use": {"binds": [], "calls": [{"line": 6, "name": "eval"}]},
        "feature.semantic.obligations": [],
        "feature.taxonomy.families": [{"id": "injection", "definition": "untrusted data reaches an interpreter"}],
    }
]
TEXT = {"app.py": ["def first():", "    v = input()", "    return v", "", "def second():", "    return eval(first())", ""]}


def test_signature_drops_masked_inputs_and_keeps_the_order():
    full = hp.signature_for()
    assert list(full.input_fields) == [name for name, _, _ in hp.INPUTS]
    masked = hp.signature_for(["semantic", "callers"])
    assert "roles" not in masked.input_fields and "def_use" not in masked.input_fields and "callers" not in masked.input_fields
    assert list(masked.input_fields) == ["change_summary", "hunks", "function_text", "entry_points", "families"]
    assert "findings" in masked.output_fields


def test_render_rows_numbers_the_function_and_omits_masked_inputs():
    inputs = hp.render_rows(CHANGE, ROWS, TEXT)
    assert inputs["change_summary"] == "app.py::second"
    assert json.loads(inputs["hunks"]) == {"app.py": [[3, 3]]}
    assert "    5  def second():" in inputs["function_text"] and "    6  " in inputs["function_text"]
    assert "input()" not in inputs["function_text"]  # only the span is shown
    assert inputs["families"].startswith("injection: ")
    masked = hp.render_rows(CHANGE, ROWS, TEXT, mask=["diff", "function_text"])
    assert "hunks" not in masked and "function_text" not in masked and "roles" in masked
    assert hp.shown_lines(inputs) == {"app.py": {5, 6, 7}}


def test_check_turns_off_list_families_and_unseen_citations_into_unknown():
    inputs = hp.render_rows(CHANGE, ROWS, TEXT)
    good = {"path": "app.py", "line": 6, "family": "injection", "confidence": 0.9, "rationale": "eval", "cited_lines": [6]}
    bad_family = {**good, "family": "sql-parser"}
    bad_cite = {**good, "cited_lines": [2]}
    out = hp.check([good, bad_family, bad_cite], inputs)
    assert out[0]["family"] == "injection" and "unknown_reason" not in out[0]
    assert out[1]["family"] == "unknown" and out[1]["reported_family"] == "sql-parser" and out[1]["unknown_reason"] == "family_not_in_list"
    assert out[2]["family"] == "unknown" and out[2]["unknown_reason"] == "cited_line_not_shown"


def test_program_without_tools_runs_on_a_scripted_model_and_has_a_stable_id():
    answer = [{"path": "app.py", "line": 6, "family": "injection", "confidence": 0.8, "rationale": "eval of input", "cited_lines": [6]}]
    lm = DummyLM([{"findings": json.dumps(answer)}, {"findings": json.dumps(answer)}])
    dspy.configure(lm=lm, adapter=dspy.ChatAdapter())
    program = hp.HuntProgram(mask=["obligations"])
    inputs = hp.render_rows(CHANGE, ROWS, TEXT, mask=program.mask)
    prediction = program(**inputs)
    assert prediction.findings == [{**answer[0]}]
    assert prediction.findings[0]["family"] == "injection"
    assert hp.program_id(program, mask=program.mask) == hp.program_id(hp.HuntProgram(mask=["obligations"]), mask=["obligations"])
    assert hp.program_id(program) != hp.program_id(program, mask=["obligations"])


def test_tools_are_clamped_to_the_checkout(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    tools = {tool.name: tool for tool in hp.repository_tools(tmp_path)}
    assert set(tools) == {"read_file", "grep_repo", "find_refs"}
    assert "x = 1" in tools["read_file"](path="a.py")
    from openultrasast.hunter_tools import PathEscapesRepo

    with pytest.raises(PathEscapesRepo):
        tools["read_file"](path="../../etc/passwd")
    assert (
        "(no matches)" in tools["grep_repo"](pattern="nothing_here_\\d+")
        or tools["grep_repo"](pattern="nothing_here_\\d+") == "(no matches)"
    )


def test_build_lm_needs_a_key_from_the_environment(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        hp.build_lm()


def test_lines_read_through_a_tool_count_as_shown(tmp_path):
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = eval(input())\n")
    seen: dict[str, set[int]] = {}
    tools = {tool.name: tool for tool in hp.repository_tools(tmp_path, seen=seen)}
    tools["read_file"](path="app.py")
    assert seen["app.py"] >= {1, 2, 3}
    inputs = hp.render_rows(CHANGE, ROWS, TEXT)
    finding = {"path": "app.py", "line": 3, "family": "injection", "confidence": 0.9, "rationale": "eval", "cited_lines": [3]}
    assert hp.check([finding], inputs)[0]["family"] == "unknown"  # line 3 is outside the rendered span 5-7
    assert hp.check([finding], inputs, seen)[0]["family"] == "injection"  # but the model read it through a tool


def test_an_unparseable_answer_is_an_empty_flagged_answer():
    lm = DummyLM([{"findings": "not json at all"}] * 4)
    dspy.configure(lm=lm, adapter=dspy.ChatAdapter())
    program = hp.HuntProgram()
    prediction = program(**hp.render_rows(CHANGE, ROWS, TEXT))
    assert prediction.findings == [] and prediction.parse_failed is True
