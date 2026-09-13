"""Change evidence informs exact existing scope, never another inclusion rule."""

from dataclasses import replace

import pytest
from test_model_scope import Backend, region, vector

from openultrasast.model.contracts import ChangeContext, ChangedSpan, LineCorrespondence
from openultrasast.model.scan import ScanBudget, scan_repository


def context(path="source.php"):
    return ChangeContext(
        "base",
        "head",
        (path.encode().hex(),),
        (),
        (ChangedSpan(path.encode().hex(), 2, 2, "base"),),
        (),
        (),
        (),
        (),
        "filesystem-bytes-hex",
        (LineCorrespondence(path.encode().hex(), path.encode().hex(), 3, 3, 2),),
    )


def row(path, kind="callee", function="run"):
    return {"kind": "context_method", "path": path, "function": function, "startLine": 1, "endLine": 10, "relationship": kind}


@pytest.mark.parametrize("language,ext", [("php", "php"), ("javascript", "js")])
@pytest.mark.parametrize("kind", ["entry", "callee", "field", "hook", "guard"])
def test_changed_dependency_reaches_unchanged_ranked_question(tmp_path, language, ext, kind):
    source, sink = f"source.{ext}", f"sink.{ext}"
    (tmp_path / source).write_text("source input\nremoved guard\nunchanged operation\n")
    (tmp_path / sink).write_text("unchanged sink(input)\n")
    backend = Backend({sink: vector() + [row(source, kind), {"kind": "context_summary"}]})
    result = scan_repository(tmp_path, [region(sink, language)], backend=backend, change_context=context(source), population_complete=True)
    assert len(result.scope.selected) == 1
    relationship = result.change_context.relationships[0]
    assert relationship.source.path == source
    assert relationship.target == result.scope.selected[0].identity
    assert relationship.kind == kind
    assert any("base_span" in e for e in relationship.evidence)
    assert any("affected_relationship=" in e for e in result.scope.selected[0].evidence)
    assert len(backend.executed) == 1


def test_unavailable_relationships_cannot_be_completed_negative(tmp_path):
    (tmp_path / "sink.php").write_text("readable\n")
    result = scan_repository(
        tmp_path,
        [region("sink.php", "php")],
        backend=Backend({"sink.php": vector(False)}),
        change_context=context(),
        population_complete=True,
    )
    assert not any(q.reason == "tier_zero" for q in result.scope.deferred)
    assert result.question_outcomes[0].status == "unresolved"
    assert any("context_projection_unavailable" in b for b in result.scope.unresolved_boundaries)


def test_change_does_not_replace_ranker_selection(tmp_path):
    for path in ("source.php", "sink.php"):
        (tmp_path / path).write_text("readable\n")
    regions = [region("source.php", "php", rank=0.1), region("sink.php", "php", rank=1)]
    rows = {p: vector() + [row(p), {"kind": "context_summary"}] for p in ("source.php", "sink.php")}
    kwargs = dict(backend=Backend(rows), budget=ScanBudget(max_regions=1), population_complete=True)
    baseline = scan_repository(tmp_path, regions, **kwargs)
    changed = scan_repository(tmp_path, regions, change_context=context(), **kwargs)
    assert [q.identity for q in baseline.scope.selected] == [q.identity for q in changed.scope.selected]
    assert [q.score for q in baseline.scope.selected] == [q.score for q in changed.scope.selected]


def test_global_boundary_survives_answer(tmp_path):
    (tmp_path / "sink.php").write_text("readable\n")
    ctx = replace(context(), unresolved_boundaries=("external summary missing",))
    result = scan_repository(
        tmp_path, [region("sink.php", "php")], backend=Backend({"sink.php": vector() + [{"kind": "context_summary"}]}), change_context=ctx
    )
    assert result.question_outcomes[0].status == "unresolved"
    assert "external summary missing" in result.scope.unresolved_boundaries


@pytest.mark.parametrize("path", ["../external.php", "/outside/missing.php", "missing.php"])
def test_missing_or_external_source_cannot_manufacture_relationship(tmp_path, path):
    (tmp_path / "sink.php").write_text("readable\n")
    result = scan_repository(
        tmp_path,
        [region("sink.php", "php")],
        backend=Backend({"sink.php": vector() + [row(path), {"kind": "context_summary"}]}),
        change_context=context(),
    )
    assert result.change_context.relationships == ()
    assert result.question_outcomes[0].status == "unresolved"


@pytest.mark.parametrize("field", ["deleted_paths", "declaration_paths"])
def test_unexported_configuration_and_deleted_dependencies_are_explicit(tmp_path, field):
    (tmp_path / "source.php").write_text("readable\n")
    ctx = replace(context(), **{field: (b"source.php".hex(),)})
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": vector() + [row("source.php"), {"kind": "context_summary"}]}),
        change_context=ctx,
    )
    assert result.question_outcomes[0].status == "unresolved"
    assert any("dependency_projection_unavailable" in b for b in result.scope.unresolved_boundaries)


def test_failed_build_retains_comparison_and_boundary(tmp_path):
    (tmp_path / "source.php").write_text("readable\n")
    ctx = replace(context(), unresolved_boundaries=("missing base",))
    result = scan_repository(tmp_path, [region("source.php", "php")], backend=Backend(fail=True), change_context=ctx)
    assert result.change_context == ctx
    assert "missing base" in result.scope.unresolved_boundaries


def test_full_paths_do_not_merge_duplicate_basenames(tmp_path):
    (tmp_path / "manifest.txt").write_text("input census\n")
    for directory in ("a", "b"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "source.php").write_text("readable\n")
    result = scan_repository(
        tmp_path,
        [region("b/source.php", "php")],
        backend=Backend({"b/source.php": vector() + [row("b/source.php"), {"kind": "context_summary"}]}),
        change_context=context("a/source.php"),
    )
    assert result.change_context.relationships == ()


def test_context_expansion_uses_transaction_deadline(tmp_path):
    from openultrasast.model.contracts import ExecutionBudget, QuestionIdentity
    from openultrasast.model.regions import affected_context

    (tmp_path / "source.php").write_text("readable\n")
    question = QuestionIdentity("unit", "php", "source.php", "run", "injection")
    enriched, missing = affected_context(
        context(), [question], {question: [row("source.php"), {"kind": "context_summary"}]}, tmp_path, ExecutionBudget(0, 1)
    )
    assert missing == {question}
    assert enriched.relationships == ()
    assert "change_context_deadline_exhausted" in enriched.unresolved_boundaries


def test_empty_method_projection_is_not_complete_negative(tmp_path):
    (tmp_path / "source.php").write_text("readable\n")
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": vector(False) + [{"kind": "context_summary"}]}),
        change_context=context(),
    )
    assert result.scope.selected
    assert result.question_outcomes[0].status == "unresolved"
    assert any("context_scope_empty" in gap for gap in result.scope.unresolved_boundaries)


def test_missing_base_without_adapter_diagnostic_stays_incomplete(tmp_path):
    (tmp_path / "source.php").write_text("readable\n")
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": vector() + [row("source.php"), {"kind": "context_summary"}]}),
        change_context=replace(context(), base_revision=None),
    )
    assert result.question_outcomes[0].status == "unresolved"
    assert "comparison_base_unavailable" in result.scope.unresolved_boundaries
