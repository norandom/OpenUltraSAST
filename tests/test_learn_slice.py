"""Local slices and zero-cost audit: authored examples only, no memory/network/model."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from openultrasast.learn.slice import Slice, function_slice, render_slice


def sliced(code: str, language: str = "python", family: str = "injection") -> Slice:
    result = function_slice(code, language, family)
    assert result is not None
    return result


def test_learn_slice_def_use_preserves_excerpt_lines_and_ignores_diff() -> None:
    result = sliced(
        '   40  def f():\n   41      x = request.args["x"]\n   42      y = wrap(x)\n   43      execute(y)\ndiff:\n+execute(other)'
    )
    assert [(s.line, s.role) for s in result.steps] == [(41, "source"), (41, "step"), (42, "step"), (43, "sink")]
    assert all(40 <= s.line <= 43 for s in result.steps)


@pytest.mark.parametrize("blank", ["", "    ", "\t"])
@pytest.mark.parametrize("indent", ["    ", "\t"])
def test_learn_slice_numbered_blank_lines_preserve_displayed_lines(blank: str, indent: str) -> None:
    from openultrasast.learn.excerpt import excerpt

    lines = [""] * 10 + ["def f(x):", blank, f"{indent}y = x", blank, f"{indent}execute(y)"]
    rendered = excerpt(lines, "python", "f")
    assert rendered is not None
    assert rendered.text.splitlines()[1] == "   12"
    assert rendered.text.splitlines()[3] == "   14"
    result = sliced(rendered.text)
    assert [(s.line, s.role) for s in result.steps] == [(11, "source"), (13, "step"), (15, "sink")]


@pytest.mark.parametrize("mixed_line", ["    execute(x)", "   12 execute(x)", "   12\texecute(x)"])
def test_learn_slice_mixed_numbering_is_not_analysed(mixed_line: str) -> None:
    assert function_slice(f"   10  def f(x):\n   11\n{mixed_line}", "python", "injection") is None


@pytest.mark.parametrize(
    "code",
    [
        'def f():\n    execute("request.args")',
        'def f():\n    execute(x)\n    x = request.args["x"]',
        'def f(x):\n    x = "safe"\n    execute(x)',
        'def f():\n    x = request.args["x"]\n    execute("safe")',
        'def f():\n    x = request.args["x"]\n    def inner():\n        execute(x)',
    ],
)
def test_learn_slice_no_invented_def_use(code: str) -> None:
    assert sliced(code).steps == ()


def test_learn_slice_parameters_and_nested_returns() -> None:
    assert [(s.line, s.role) for s in sliced("def f(x):\n    return execute(transform(x))").steps] == [(1, "source"), (2, "sink")]


def test_learn_slice_sanitizer_keeps_connectivity_and_does_not_claim_guard() -> None:
    result = sliced("def f(x):\n    y = ast.literal_eval(x)\n    execute(y)\n    ast.literal_eval(other)")
    assert (2, "sanitizer") in [(s.line, s.role) for s in result.steps]
    assert not any(s.line == 4 for s in result.steps)
    checked = sliced("def f(x):\n    if is_safe_url(x):\n        redirect(x)", family="untrusted_destination")
    assert not any(s.role == "guard" for s in checked.steps)  # flat IR cannot prove dominance


def test_learn_slice_parameterized_sink_and_family_routing() -> None:
    result = sliced('def f(x):\n    execute("select ?", [x])')
    assert {s.role for s in result.steps} == {"source", "sanitizer", "sink"}
    assert sliced("def f(x):\n    execute(x)", family="path").steps == ()


@pytest.mark.parametrize(
    "language,code",
    [
        ("javascript", "function f(req) { const x = req.query.x; const y = x; eval(y); }"),
        ("typescript", "function f(req: any) { const x = req.query.x; eval(x); }"),
        ("c", "void f(char *x) { char *y = x; system(y); }"),
        ("java", "class C { void f(String x) { String y = x; exec(y); } }"),
    ],
)
def test_learn_slice_shared_cst_declarations(language: str, code: str) -> None:
    assert any(s.role == "sink" for s in sliced(code, language).steps)


def test_learn_slice_same_line_assignment_order() -> None:
    assert not sliced('function f(x) { x = "safe"; eval(x); }', "javascript").steps
    assert sliced('function f(x) { eval(x); x = "safe"; }', "javascript").steps
    assert sliced("function f() { const x = req.query.x; eval(x); }", "javascript").steps


def test_learn_slice_fixed_framing_redaction_and_unsupported() -> None:
    assert function_slice("<?php function f($x) { exec($x); }", "php", "injection") is None
    assert render_slice(None, "php") == "Data flow inside the function: not analysed (php is not supported)."
    assert render_slice(Slice(), "anything") == "Data flow inside the function: no source reaches a sink of this family."
    assert "CVE" not in render_slice(None, "CVE-2026-1234")
    result = sliced("def f(x):\n    execute(x) # CVE-2026-1234 vulnerable")
    shown = render_slice(result, "python")
    assert shown.startswith("Data flow inside the function:\nL1 source:")
    assert "CVE-2026-1234" not in shown and "vulnerable" not in shown
    assert function_slice("def f(x):\n    execute(", "python", "injection") is None


def test_learn_slice_default_prompt_frozen_before_change() -> None:
    import test_learn_program as baseline

    prompt, _ = baseline.program().prepare(baseline.candidate(), baseline.FOLD)
    assert hashlib.sha256(json.dumps(prompt.messages, sort_keys=True).encode()).hexdigest() == (
        "f6b5cfb5a8b7cb1591d7b4534e254ad2a349452a03e825bdcf250e5f60b4e80b"
    )
    assert baseline.ProgramSpec().slice is False


@pytest.fixture
def audit_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "benchmarks/learn/slice_leak_audit.py"
    spec = importlib.util.spec_from_file_location("slice_leak_audit", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_learn_slice_audit_metrics_ties_and_reverse_leak(audit_module: ModuleType) -> None:
    rows = [
        {"family": "injection", "group": "g", "fold": "f", "pair": str(pair), "label": label, "has_flow": 1 - label, "slice_length": 3}
        for pair in range(10)
        for label in (0, 1)
    ]
    metric = audit_module.metrics(rows, "has_flow")
    assert metric["within_pair_accuracy"] == metric["pooled_auc"] == 0
    assert metric["flagged"] and metric["best_direction_pooled_auc"] == 1
    metric = audit_module.metrics(rows, "slice_length")
    assert metric["within_pair_accuracy"] == metric["pooled_auc"] == 0.5
    assert not metric["flagged"]
    assert audit_module.metrics([], "has_flow")["pooled_auc"] is None


def test_learn_slice_audit_reads_and_never_writes(audit_module: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    from learn_fixtures import corpus

    raw = b"   10  def f(x):\n   11      execute(x)\n"
    digest = hashlib.sha256(raw).hexdigest()
    example = replace(corpus(groups=1)[0], excerpt_sha=digest, source="pairs", language="python", family="injection")
    monkeypatch.setattr(audit_module, "load_examples", lambda store: [example])

    class ReadOnly:
        def get_blob(self, prefix: str, name: str, *, verify: bool = True) -> bytes:
            assert (prefix, name, verify) == ("excerpts", digest, False)
            return raw

    units = [{"family": example.family, "label": example.label, "group": example.group, "unit": example.id, "pair": None, "fold": "f"}]
    report = audit_module.audit(ReadOnly(), units, expected_rows=1, expected_pairs=0)
    assert report["example_rows_read"] == report["matched_rows"] == report["excerpts_read"] == 1
    assert report["excerpt_bytes"] == len(raw)
    assert report["coverage"]["injection"]["flow"] == 1

    class Corrupt(ReadOnly):
        def get_blob(self, prefix: str, name: str, *, verify: bool = True) -> bytes:
            assert not verify
            return b"corrupt"

    with pytest.raises(ValueError, match="corrupt excerpt"):
        audit_module.audit(Corrupt(), units, expected_rows=1, expected_pairs=0)


def test_learn_slice_augmented_assignment_preserves_value() -> None:
    result = sliced('def f(x):\n    x += " suffix"\n    execute(x)')
    assert {s.line for s in result.steps} == {1, 2, 3}
    result = sliced('function f(x) { x += " suffix"; eval(x); }', "javascript")
    assert any(s.role == "sink" for s in result.steps)


def test_learn_slice_python_fallback_order(monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.semantic import cst

    monkeypatch.setattr(cst, "parse_with_cst", lambda *args: None)
    assert sliced("def f():\n    x = input(); execute(x)").steps
    assert not sliced('def f(x):\n    x = "safe"; execute(x)').steps


def test_learn_slice_bare_arrow_parameter() -> None:
    assert sliced("const f = x => eval(x);", "javascript").steps


def test_learn_slice_prompt_flow_examples_citations_and_request_identity() -> None:
    import test_learn_program as baseline

    from openultrasast.learn.program import parse_answer, render, request_key

    example = replace(baseline.EXAMPLES[0], language="python", family="injection")
    code = "   40  def f(x):\n   41      execute(x)\n"
    demo = baseline.Demo(example.id, example.excerpt_sha, 1, "injection", "vulnerable", 0.9, "L41 executes x.", (41,))
    spec = baseline.ProgramSpec(demos=(demo,), slice=True)
    candidate = baseline.candidate(code)
    prompt = render(spec, candidate, [example], [demo], {example.id: example}, lambda _: code)
    block = render_slice(function_slice(code, "python", "injection"), "python")
    assert "L40 source:" in block and "L41 sink:" in block
    assert str(prompt.messages[1]["content"]).count(code.rstrip() + "\n" + block + "\nSignals:") == 2
    assert code.rstrip() + "\n" + block + "\nSignals:" in prompt.prefix
    assert prompt.valid_lines == frozenset({40, 41})
    answer = json.dumps(
        {"verdict": "vulnerable", "confidence": 0.9, "family": "injection", "rationale": "L41 executes x.", "cited_lines": [40, 41]}
    )
    assert parse_answer(answer, prompt.valid_lines).cited_lines == (40, 41)
    default = render(replace(spec, slice=False), candidate, [example], [demo], {example.id: example}, lambda _: code)
    assert request_key(spec.model, "params", prompt.messages, 0.0, "0", True) != request_key(
        spec.model, "params", default.messages, 0.0, "0", True
    )


def test_learn_slice_prompt_not_analysable() -> None:
    import test_learn_program as baseline

    candidate = replace(baseline.candidate(), language="php")
    prompt, _ = baseline.program(slice=True).prepare(candidate, baseline.FOLD)
    tail = str(prompt.messages[1]["content"]).split("Candidate:\n")[1]
    assert candidate.code.rstrip() + "\nData flow inside the function: not analysed (php is not supported).\nSignals:" in tail
