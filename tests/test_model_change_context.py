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


def test_correspondence_ambiguity_alone_does_not_make_every_question_incomplete(tmp_path):
    """M1b 10.3: repeated unchanged lines in one file no longer invalidate every question."""
    (tmp_path / "source.php").write_text("readable\n")
    ambiguous = replace(context(), unresolved_boundaries=(b"source.php".hex() + ":ambiguous_line_correspondence",))
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": vector() + [row("source.php"), {"kind": "context_summary"}]}),
        change_context=ambiguous,
    )
    assert result.question_outcomes[0].status == "completed"
    # The mapping itself is still withheld and still reported in aggregate coverage.
    assert any("ambiguous_line_correspondence" in gap for gap in result.change_context.unresolved_boundaries)


def test_any_other_inherited_transaction_gap_still_marks_questions_incomplete(tmp_path):
    (tmp_path / "source.php").write_text("readable\n")
    blocked = replace(context(), unresolved_boundaries=("snapshot:lfs_blob_unavailable",))
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": vector() + [row("source.php"), {"kind": "context_summary"}]}),
        change_context=blocked,
    )
    assert result.question_outcomes[0].status == "unresolved"
    assert result.question_outcomes[0].reason == "change_context_incomplete"


def boundary(reason):
    return {"kind": "context_boundary", "reason": reason}


def test_bounded_reachability_is_recorded_without_demoting_an_answered_question(tmp_path):
    """M1b 10.5: the boundary limits which further flows could be seen, not this answer."""
    (tmp_path / "source.php").write_text("readable\n")
    bounded = boundary("dynamic_external_or_depth_context_unresolved:contributor-scan")
    rows = vector() + [row("source.php"), {"kind": "context_summary"}, bounded]
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": rows}),
        change_context=context(),
    )
    assert result.question_outcomes[0].status == "completed"
    # Still reported, bound to the question that owns it, so comparison can consult it.
    owned = [g for g in result.scope.unresolved_boundaries if g.startswith("dynamic_external_or_depth_context_unresolved")]
    assert owned and owned[0].endswith(result.question_outcomes[0].identity.question_id)


def test_an_unresolved_context_projection_still_demotes_the_question(tmp_path):
    (tmp_path / "source.php").write_text("readable\n")
    rows = vector() + [row("source.php"), {"kind": "context_summary"}, boundary("context_location_unavailable")]
    result = scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": rows}),
        change_context=context(),
    )
    assert result.question_outcomes[0].status == "unresolved"
    assert result.question_outcomes[0].reason == "change_context_incomplete"


def scan_with_layout(tmp_path, *, vendor=False, symlink=False, second_language=False):
    """Exercise the real partition boundaries rather than injecting a reason."""
    (tmp_path / "source.php").write_text("readable\n")
    if vendor:
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.php").write_text("third party\n")
    if symlink:
        (tmp_path / "linked.php").symlink_to(tmp_path / "source.php")
    if second_language:
        (tmp_path / "admin.js").write_text("const x = 1;\n")
    rows = vector() + [row("source.php"), {"kind": "context_summary"}]
    return scan_repository(
        tmp_path,
        [region("source.php", "php")],
        backend=Backend({"source.php": rows}),
        change_context=context(),
    )


def test_a_declared_vendor_exclusion_does_not_invalidate_a_first_party_answer(tmp_path):
    """M1b 10.6: every real repository excludes its dependencies; that is a scope choice."""
    result = scan_with_layout(tmp_path, vendor=True)
    assert "vendor_semantics_unresolved" in result.scope.unresolved_boundaries
    assert result.question_outcomes[0].status == "completed"


def test_an_unresolved_symlink_still_demotes_the_answer(tmp_path):
    result = scan_with_layout(tmp_path, symlink=True)
    assert "symlink_context_unresolved" in result.scope.unresolved_boundaries
    assert result.question_outcomes[0].status == "unresolved"
    assert result.question_outcomes[0].reason == "graph_incomplete"


def test_a_declared_exclusion_beside_an_integrity_failure_still_demotes(tmp_path):
    result = scan_with_layout(tmp_path, vendor=True, symlink=True)
    assert {"vendor_semantics_unresolved", "symlink_context_unresolved"} <= set(result.scope.unresolved_boundaries)
    assert result.question_outcomes[0].status == "unresolved"


class FamilyBackend(Backend):
    """A backend that answers each family's own batch, recording what was asked."""

    def __init__(self, evidence, per_kind):
        super().__init__(evidence)
        self.per_kind = per_kind
        self.asked = []

    def build(self, root, **kwargs):
        graph = super().build(root, **kwargs)
        outer = self

        def batch(kind, requests):
            outer.asked.append((kind, tuple(sorted(p.get("contextEvidence", "") for p in requests.values()))))
            if any(p.get("evidenceOnly") == "true" for p in requests.values()):
                return {rid: outer.evidence.get(p["file"], []) for rid, p in requests.items()}
            rows = outer.per_kind.get(kind, [])
            return {"__census__": [{"methods": 1, "files": 1, "file_names": ["source.php"]}], **{rid: list(rows) for rid in requests}}

        graph.run_batch = batch
        return graph


def test_dominance_and_config_questions_get_their_own_change_context(tmp_path):
    """M1b 12.2: the evidence pass asks taint only, so these families never had context at all."""
    from dataclasses import replace as _replace

    (tmp_path / "source.js").write_text("readable\n")
    produced = [row("source.js", kind="operation"), {"kind": "context_summary"}]
    backend = FamilyBackend(
        {"source.js": vector() + [row("source.js"), {"kind": "context_summary"}]},
        {"dominance": produced, "config": produced},
    )
    target = _replace(region("source.js", "javascript"), families=("injection", "access_control", "config_secrets"))
    result = scan_repository(tmp_path, [target], backend=backend, change_context=context("source.js"), population_complete=True)
    asked = {kind for kind, _ in backend.asked}
    assert {"dominance", "config"} <= asked, "both families must be asked for their own context"
    # Each family is asked twice: once for context, once to execute. The context ask must set the flag.
    for family in ("dominance", "config"):
        assert ("true",) in [flags for kind, flags in backend.asked if kind == family], family
    outcomes = {o.identity.family: o for o in result.question_outcomes}
    for family in ("access_control", "config_secrets"):
        assert family in outcomes, family
        assert outcomes[family].reason != "change_context_incomplete", family
    assert not any("context_projection_unavailable" in gap for gap in result.scope.unresolved_boundaries)


def test_a_family_whose_context_query_answers_nothing_stays_unresolved(tmp_path):
    """A family that cannot describe its own scope must not complete on somebody else's context."""
    from dataclasses import replace as _replace

    (tmp_path / "source.js").write_text("readable\n")
    backend = FamilyBackend({"source.js": vector() + [row("source.js"), {"kind": "context_summary"}]}, {})
    target = _replace(region("source.js", "javascript"), families=("injection", "access_control"))
    result = scan_repository(tmp_path, [target], backend=backend, change_context=context("source.js"), population_complete=True)
    outcomes = {o.identity.family: o for o in result.question_outcomes}
    assert "access_control" in outcomes
    assert any("context_projection_unavailable" in gap for gap in result.scope.unresolved_boundaries)


def test_a_question_naming_a_function_the_file_does_not_define_says_so(tmp_path):
    """M1b 12.3: a route-registration file names handlers defined elsewhere; that is not an empty file."""
    from dataclasses import replace as _replace

    (tmp_path / "source.js").write_text("readable\n")
    boundary = {"kind": "context_boundary", "reason": "context_function_unresolved:contributor-scan", "function": "handleUpdate"}
    unresolved = [{"kind": "context_summary"}, boundary]
    backend = FamilyBackend({"source.js": vector() + unresolved}, {"dominance": [], "config": unresolved})
    target = _replace(region("source.js", "javascript"), function="handleUpdate", families=("injection",))
    result = scan_repository(tmp_path, [target], backend=backend, change_context=context("source.js"), population_complete=True)
    outcome = result.question_outcomes[0]
    assert outcome.status == "unresolved" and outcome.reason == "change_context_incomplete"
    gaps = [g for g in result.scope.unresolved_boundaries if "context_function_unresolved" in g]
    assert gaps, "the unresolvable function must be named, not reported as an empty scope"
    # The gap is owned by the question that asked it, so it cannot block another question.
    assert gaps[0].endswith(outcome.identity.question_id)
    assert not any("context_scope_empty" in g for g in result.scope.unresolved_boundaries)


def test_a_second_language_does_not_invalidate_the_first_language_answer(tmp_path):
    """A repository holding two languages must still be able to complete a question.

    Measured 2026-09-21 on a WordPress plugin: PHP with 36 regions of admin JavaScript completed NONE of 520
    questions while establishing 43 findings, because a partition boundary was classified as a graph-integrity
    failure and any such gap demotes every answer in the repository. Admission requires a completed outcome,
    so every multi-language repository was unadmittable by construction -- which is every plugin this product
    was built for.

    A flow this tool cannot follow out of one language can hide a finding and never invent one, so the
    boundary is a declared limit. It stays reported; it no longer demotes.
    """
    result = scan_with_layout(tmp_path, second_language=True)
    assert "cross_partition_semantics_unresolved" in result.scope.unresolved_boundaries, result.scope.unresolved_boundaries
    assert result.question_outcomes[0].status == "completed", result.question_outcomes[0]


def test_a_gap_in_another_partition_does_not_demote_this_one(tmp_path):
    """An integrity gap reaches the questions it can be wrong about, which is its own partition's.

    On that same plugin four JavaScript files -- a webpack build output, a minified select2, a build config and
    one source file -- were absent from the JavaScript graph, and a repository-wide demotion took the
    admissibility of 4,425 PHP regions with them. A missing JavaScript file cannot make a PHP answer wrong.
    """
    from openultrasast.model.scan import GRAPH_INTEGRITY_GAPS, _scan_repository_impl  # noqa: F401

    result = scan_with_layout(tmp_path, second_language=True)
    scoped = [d for d in result.degradations if d.get("census_language")]
    for gap in scoped:
        assert gap["reason"] in GRAPH_INTEGRITY_GAPS, gap
    # Whatever the fake graph reports, a PHP question may only be demoted by a gap from the PHP partition.
    php = [o for o in result.question_outcomes if o.identity.language == "php"]
    assert php, result.question_outcomes
    if all(str(d.get("census_language") or "") != "php" for d in result.degradations):
        assert all(o.status == "completed" for o in php), [(o.status, o.reason) for o in php]


def _summary(rows):
    """What the engine now emits in place of itemised rows for files the change did not touch."""
    unusable = sum(1 for r in rows if int(r["startLine"]) < 1 or int(r["endLine"]) < int(r["startLine"]))
    return {"kind": "context_elsewhere", "locations": len(rows), "unusableExtents": unusable, "paths": sorted({r["path"] for r in rows})}


@pytest.mark.parametrize(
    "elsewhere",
    [
        pytest.param([row("other.php"), row("other.php", "field", "f"), row("lib/deep.php", "hook", "h")], id="valid"),
        pytest.param([row("other.php"), row("missing.php")], id="missing-file"),
        pytest.param([row("other.php"), {**row("other.php", function="g"), "startLine": -1}], id="no-extent"),
        pytest.param([row("../outside.php")], id="outside-root"),
    ],
)
@pytest.mark.parametrize("with_changed_row", [True, False])
def test_summarised_locations_decide_exactly_what_itemised_ones_did(tmp_path, elsewhere, with_changed_row):
    """Summarising unchanged-file locations in the engine must change nothing `affected_context` decides.

    Itemised, one PHP request returned 1,845 locations and a push over a WordPress plugin never finished;
    every location outside the changed files was only ever checked and then discarded, so the summary carries
    exactly what that check reads.
    """
    from openultrasast.model.contracts import QuestionIdentity
    from openultrasast.model.regions import affected_context

    (tmp_path / "source.php").write_text("readable\nchanged\n")
    (tmp_path / "other.php").write_text("unchanged\n")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "deep.php").write_text("unchanged\n")
    (tmp_path.parent / "outside.php").write_text("outside the root\n")
    question = QuestionIdentity("unit", "php", "sink.php", "run", "injection")
    changed = [row("source.php", "callee")] if with_changed_row else []
    head = [{"kind": "context_summary"}]
    itemised = head + changed + elsewhere
    summarised = head + changed + [_summary(elsewhere)]
    old = affected_context(context(), [question], {question: itemised}, tmp_path)
    new = affected_context(context(), [question], {question: summarised}, tmp_path)
    assert new == old


def test_the_evidence_pass_names_the_changed_files_to_the_engine(tmp_path):
    """The engine can only summarise what the driver says is unchanged; with no safe list it itemises all."""
    from openultrasast.model import scan

    asked: list[dict[str, object]] = []

    class Graph:
        cpg_path = tmp_path / "cpg.bin"

        def run_batch(self, kind, requests):
            asked.extend(requests.values())
            return {rid: [] for rid in requests}

    work = scan._collect([region("sink.php", "php")])
    context_rows: dict = {}
    scan._evidence_pass(Graph(), work, "", context_rows=context_rows, context_files=("a.php", "b,c.php"))
    assert asked and all(r["contextFilter"] == "true" and r["contextPaths"] == "a.php\nb,c.php" for r in asked)
    asked.clear()
    scan._evidence_pass(Graph(), work, "", context_rows=context_rows, context_files=None)
    assert asked and all("contextFilter" not in r for r in asked)
    assert scan._changed_files(context("x\ny.php")) is None
    assert scan._changed_files(context("source.php")) == ("source.php",)


def test_attaching_relationships_is_linear_in_what_it_attaches(tmp_path, monkeypatch):
    """Membership went through a list: 8 million comparisons for 4,000 relationships, and a push over a
    WordPress plugin ran 82 minutes past its evidence pass and overran the deadline. Counted, not timed, so the
    control cannot flake under load."""
    from openultrasast.model.contracts import AffectedRelationship, QuestionIdentity
    from openultrasast.model.regions import affected_context

    (tmp_path / "source.php").write_text("x\n" * 400)
    compared = []
    original = AffectedRelationship.__eq__
    monkeypatch.setattr(AffectedRelationship, "__eq__", lambda self, other: compared.append(1) or original(self, other))
    questions = [QuestionIdentity("unit", "php", f"f{i}.php", "run", "injection") for i in range(200)]
    rows = {
        q: [{"kind": "context_summary"}] + [{**row("source.php", function=f"m{j}"), "startLine": 1, "endLine": 400} for j in range(20)]
        for q in questions
    }
    enriched, _ = affected_context(context(), questions, rows, tmp_path)
    assert len(enriched.relationships) == 4000
    assert len(compared) < 4000, f"{len(compared)} comparisons for 4,000 relationships"
