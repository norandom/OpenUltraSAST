from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

from openultrasast.cpg.backend import CpgResult
from openultrasast.model.contracts import (
    ChangeContext,
    ChangedSpan,
    ExecutionBudget,
    LineCorrespondence,
    PathRename,
    QuestionIdentity,
    QuestionOutcome,
    RankedQuestion,
    ScopeDecision,
)
from openultrasast.model.ladder import Rung
from openultrasast.model.pipeline import ModelFinding
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ModelScanResult, ScanBudget
from openultrasast.push.policy import CandidateDelta, compare_evidence, compare_targeted_base


def scan(*, path="a.js", line=4, source="req.body", sanitized=False, findings=True, status="completed", rows=None):
    q = QuestionIdentity("repository", "javascript", path, "handler", "injection")
    row = {
        "sink": "exec(cmd)",
        "sinkFile": path,
        "sinkLine": line,
        "sinkMethod": "handler",
        "source": source,
        "sourceKind": "field",
        "sanitized": sanitized,
        "bounded": False,
        "length": 2,
    }
    return ModelScanResult(
        findings=(
            ModelFinding(f"{path}:{line}:handler", "injection", Rung.ENTAILED, f"{source} -> exec(cmd) in {path} (line {line}, 2 steps)"),
        )
        if findings
        else (),
        scope=ScopeDecision("v1", "static", True, (RankedQuestion(q, 1.0, ()),), (), ()),
        question_outcomes=(
            QuestionOutcome(q, status, "test_answer", json.dumps([row] if rows is None else rows) if status != "unanswered" else None),
        ),
    )


def context(*, rename=False):
    return ChangeContext(
        "base",
        "head",
        ("a.js",),
        (),
        (ChangedSpan("old.js" if rename else "a.js", 2, 2, "base"),),
        (PathRename("old.js", "a.js"),) if rename else (),
        (),
        (),
        (),
        line_correspondences=(LineCorrespondence("old.js" if rename else "a.js", "a.js", 5, 5, 4),),
    )


def delta(head, base, ctx=None, **kwargs):
    return compare_evidence(head, base, context=ctx or context(), head_semantics="same", base_semantics=kwargs.get("semantics", "same"))[0]


def test_removed_discharge_is_worsened_at_unchanged_sink():
    result = delta(scan(), scan(line=5, sanitized=True, findings=False))
    assert result.novelty == "worsened"
    assert result.reason == "discharge_removed"
    assert result.change_evidence == ("base:a.js:2-2",)
    assert CandidateDelta.from_payload(result.to_payload()) == result


def test_unchanged_backlog_and_renamed_movement_stay_unchanged():
    assert delta(scan(), scan(line=5)).novelty == "unchanged"
    renamed = delta(scan(), scan(path="old.js", line=5), context(rename=True))
    assert renamed.novelty == "unchanged"
    baseline = ChangeContext("base", "head", (), (), (), (), (), (), ())
    assert renamed.defect_id == delta(scan(path="old.js", line=5), scan(path="old.js", line=5), baseline).defect_id


def test_changed_source_text_needs_identity_proof_not_a_rename_guess():
    assert delta(scan(), scan(line=5, source="req.query")).reason == "source_correspondence_unresolved"
    assert delta(scan(source="request.body"), scan(line=5)).novelty == "unknown"


def test_failed_truncated_incompatible_base_remains_unknown():
    assert delta(scan(), scan(status="unanswered")).novelty == "unknown"
    assert delta(scan(), replace(scan(), degradations=({"reason": "files_unparsed"},))).novelty == "unknown"
    assert delta(scan(), scan(line=5), semantics="different").reason == "semantics_mismatch"
    assert delta(scan(), None).novelty == "unknown"


def test_unrelated_lexical_guard_removal_does_not_override_same_flow():
    assert delta(scan(), scan(line=5)).reason == "same_supported_mechanism"


def test_missing_anchor_and_ambiguous_witness_do_not_invent_novelty():
    assert delta(scan(), scan(line=5), replace(context(), line_correspondences=())).novelty == "unknown"
    answer = scan().question_outcomes[0]
    ambiguous = replace(scan(), question_outcomes=(replace(answer, raw_rows_json=json.dumps(json.loads(answer.raw_rows_json) * 2)),))
    assert delta(ambiguous, scan()).novelty == "unknown"


def test_targeted_base_uses_real_driver_same_deadline(tmp_path):
    (tmp_path / "a.js").write_text("function handler(req) { exec(req.body); }\n")
    seen = []

    class Backend:
        def build(self, root, *, language, exclude, execution_budget):
            assert (root / "a.js").read_bytes()
            seen.append(execution_budget)
            rows = json.loads(scan(line=5, sanitized=True).question_outcomes[0].raw_rows_json)
            return CpgResult(
                Path("graph"),
                lambda kind, params: rows,
                run_batch=lambda kind, requests: {
                    **{rid: rows for rid in requests},
                    "__census__": [{"methods": 1, "files": 1, "file_names": [str(root / "a.js")]}],
                },
            )

    region = ScanRegion("a.js", "handler", "javascript", ("injection",), 1.0, "entry_point")
    budget = ExecutionBudget(time.monotonic() + 30, 1.0)
    result = compare_targeted_base(
        tmp_path,
        head=scan(),
        head_regions=(region,),
        base_regions=(region,),
        context=context(),
        backend=Backend(),
        execution_budget=budget,
        scan_budget=ScanBudget(tiering=False),
        head_semantics="same",
        base_semantics="same",
    )
    assert seen == [budget]
    assert result.base_scan.question_outcomes[0].status == "completed"
    assert result.candidates[0].novelty == "worsened"


def test_new_source_at_unchanged_operation_needs_complete_base_answer():
    assert delta(scan(), scan(rows=[], findings=False)).novelty == "new"
    assert delta(scan(), scan(rows=[], status="unanswered", findings=False)).novelty == "unknown"


def test_changed_new_operation_in_comparable_existing_file():
    # M1b 10.1 changed the first case: an operation the edit introduced has no base line to
    # map to, so a complete counterpart answer containing no such operation now establishes
    # absence. Before that repair this stayed unknown and no introduced flow could be seen.
    ctx = replace(context(), spans=(ChangedSpan("a.js", 4, 4, "head"),), line_correspondences=())
    assert delta(scan(), scan(rows=inventory_rows(), findings=False), ctx).novelty == "new"
    assert delta(scan(), scan(line=6), ctx).novelty == "unknown"  # movement is not new


def test_other_completed_question_cannot_prove_absence_for_missing_counterpart():
    assert delta(scan(), scan(path="other.js", findings=False)).novelty == "unknown"
    assert delta(scan(), replace(scan(), scope=replace(scan().scope, selected=()))).novelty == "unknown"


def test_head_failure_or_unproven_witness_stays_unknown():
    assert delta(replace(scan(), degradations=({"reason": "cpg_sharded"},)), scan(line=5)).novelty == "unknown"
    finding = replace(scan().findings[0], witness="invented witness")
    assert delta(replace(scan(), findings=(finding,)), scan(line=5)).novelty == "unknown"


def test_string_false_is_not_supported_discharge_evidence():
    base = scan(line=5, sanitized=True)
    row = json.loads(base.question_outcomes[0].raw_rows_json)[0]
    row["sanitized"] = "false"
    result = delta(scan(), scan(line=5, rows=[row]))
    # A malformed returned row must not be reinterpreted as valid negative evidence.
    assert result.novelty == "unknown"


def test_deadline_exhaustion_prevents_any_new_base_build(tmp_path):
    region = ScanRegion("a.js", "handler", "javascript", ("injection",), 1.0, "entry_point")

    class Backend:
        def build(self, *args, **kwargs):
            raise AssertionError("expired budget must prevent build")

    result = compare_targeted_base(
        tmp_path,
        head=scan(),
        head_regions=(region,),
        base_regions=(region,),
        context=context(),
        backend=Backend(),
        execution_budget=ExecutionBudget(0.0, 1.0),
        scan_budget=ScanBudget(),
        head_semantics="same",
        base_semantics="same",
    )
    assert "deadline_exhausted" in result.coverage_reasons
    assert result.candidates[0].novelty == "unknown"


def test_benign_identifier_rename_is_unknown_not_new():
    ctx = replace(context(), spans=(ChangedSpan("a.js", 4, 4, "head"),), line_correspondences=())
    assert delta(scan(source="request.body"), scan(line=4), ctx).novelty == "unknown"


def test_wrong_query_mechanism_cannot_prove_base_absence():
    row = {"operation": "exec(cmd)", "opFile": "a.js", "opLine": 5, "dominatingGuards": []}
    assert delta(scan(), scan(line=5, rows=[row])).novelty == "unknown"


def test_non_string_operation_cannot_prove_base_absence():
    row = json.loads(scan(line=5).question_outcomes[0].raw_rows_json)[0]
    row["sink"] = 42
    assert delta(scan(), scan(line=5, rows=[row])).novelty == "unknown"


def test_unrelated_question_context_gap_does_not_poison_completed_comparison():
    head = scan()
    other = replace(head.scope.selected[0].identity, family="path")
    gap = "dynamic_external_or_depth_context_unresolved:contributor-scan:" + other.question_id
    head = replace(
        head,
        scope=replace(head.scope, selected=(*head.scope.selected, RankedQuestion(other, 0.0, ())), unresolved_boundaries=(gap,)),
        question_outcomes=(*head.question_outcomes, QuestionOutcome(other, "unresolved", "change_context_incomplete", "[]")),
    )
    assert delta(head, scan(rows=[], findings=False)).novelty == "new"
    mine = head.scope.selected[0].identity.question_id
    # M1b 10.5: the question's own bounded reachability can hide further flows, but it cannot
    # invalidate the flow this finding was traced from, so it no longer blocks its own claim.
    own_reachability = gap.rsplit(":", 1)[0] + ":" + mine
    assert (
        delta(replace(head, scope=replace(head.scope, unresolved_boundaries=(own_reachability,))), scan(rows=[], findings=False)).novelty
        == "new"
    )
    # An unavailable context projection is unknown ownership, not bounded reachability, and still blocks.
    own_projection = "context_projection_unavailable:contributor-scan:" + mine
    assert (
        delta(replace(head, scope=replace(head.scope, unresolved_boundaries=(own_projection,))), scan(rows=[], findings=False)).novelty
        == "unknown"
    )
    assert (
        delta(replace(head, scope=replace(head.scope, unresolved_boundaries=("graph_incomplete",))), scan(rows=[], findings=False)).novelty
        == "unknown"
    )


def test_proven_tier_zero_other_families_do_not_invalidate_base_answer():
    from openultrasast.model.contracts import DeferredQuestion

    base = scan(rows=[], findings=False)
    other = replace(base.scope.selected[0].identity, family="path")
    base = replace(base, scope=replace(base.scope, deferred=(DeferredQuestion(other, "tier_zero", ()),)))
    assert delta(scan(), base).novelty == "new"
    base = replace(base, scope=replace(base.scope, deferred=(DeferredQuestion(other, "budget_exhausted", ()),)))
    assert delta(scan(), base).novelty == "unknown"


def test_comparison_cache_reuses_only_completed_compatible_evidence(tmp_path, monkeypatch):
    import openultrasast.push.policy as policy
    from openultrasast.push.cache import ArtifactCache, SemanticKeys

    cache = ArtifactCache(tmp_path / "cache", max_bytes=100000)
    keys = SemanticKeys("facts", "queries", "config", "rank", "admission", "disabled", "empty", "advisory")
    budget = ExecutionBudget(time.monotonic() + 10, 0.2)
    args = dict(context=context(), head_semantics="same", base_semantics="same", execution_budget=budget, cache=cache, cache_semantics=keys)
    expected = policy.compare_evidence(scan(), scan(line=5, sanitized=True, findings=False), **args)
    assert expected[0].novelty == "worsened"
    hits = cache.hits
    assert policy.compare_evidence(scan(), scan(line=5, sanitized=True, findings=False), **args) == expected
    assert cache.hits > hits
    args["cache_semantics"] = replace(keys, admission="changed")
    hits = cache.hits
    policy.compare_evidence(scan(), scan(line=5, sanitized=True, findings=False), **args)
    assert cache.hits == hits
    args["context"] = replace(context(), base_revision="another-base")
    changed = policy.compare_evidence(scan(), scan(line=5, sanitized=True, findings=False), **args)
    assert changed[0].base_revision == "another-base"
    incomplete = policy.compare_evidence(scan(), scan(status="unanswered"), **args)
    assert incomplete[0].novelty == "unknown"
    hits = cache.hits
    policy.compare_evidence(scan(), scan(status="unanswered"), **args)
    assert cache.hits == hits


def changed_line_context(*, ambiguous=False, head_line=4):
    """The head edit covers the operation's line, so no base line can correspond to it."""
    return ChangeContext(
        "base",
        "head",
        ("a.js",),
        (),
        (ChangedSpan("a.js", 2, 2, "base"), ChangedSpan("a.js", head_line, head_line, "head")),
        (),
        (),
        (),
        (),
        line_correspondences=(
            (LineCorrespondence("a.js", "a.js", 9, 9, head_line), LineCorrespondence("a.js", "a.js", 11, 11, head_line))
            if ambiguous
            else ()
        ),
    )


def test_operation_introduced_on_a_changed_line_is_new_against_a_complete_base():
    """M1b 10.1: absence is established over the counterpart answer, not over a line anchor."""
    candidate = delta(scan(), scan(rows=inventory_rows(), findings=False), changed_line_context())
    assert (candidate.novelty, candidate.reason) == ("new", "operation_absent_from_comparable_base")


def test_moved_identical_operation_on_a_changed_line_is_not_new():
    moved = scan(line=9)  # same operation and source, different line in the base
    candidate = delta(scan(), moved, changed_line_context())
    assert candidate.novelty == "unknown" and candidate.reason == "operation_moved_within_change"


def test_changed_line_novelty_still_requires_a_complete_base():
    empty = scan(rows=[], findings=False)
    for base in (scan(rows=[], status="unanswered", findings=False), replace(empty, degradations=({"reason": "cpg_empty"},))):
        assert delta(scan(), base, changed_line_context()).novelty == "unknown"
    assert delta(scan(), None, changed_line_context()).novelty == "unknown"


def test_ambiguous_correspondence_on_a_changed_line_is_never_new():
    candidate = delta(scan(), scan(rows=[], findings=False), changed_line_context(ambiguous=True))
    assert candidate.novelty == "unknown" and candidate.reason != "operation_absent_from_comparable_base"


def test_operation_outside_any_recorded_head_span_is_not_new():
    """An unmapped operation in a changed file is unresolved, not introduced."""
    candidate = delta(scan(), scan(rows=[], findings=False), changed_line_context(head_line=99))
    assert candidate.novelty == "unknown" and candidate.reason == "operation_correspondence_unresolved"


def test_discharged_or_unentailed_operation_on_a_changed_line_is_not_new():
    from openultrasast.model.pipeline import ModelFinding

    assert delta(scan(sanitized=True), scan(rows=[], findings=False), changed_line_context()).novelty != "new"
    weak = scan()
    weak = replace(weak, findings=(replace(weak.findings[0], rung=Rung.CORROBORATED),))
    assert delta(weak, scan(rows=[], findings=False), changed_line_context()).novelty != "new"
    assert isinstance(weak.findings[0], ModelFinding)


def test_renamed_file_keeps_operation_identity_across_a_changed_line():
    spans = (ChangedSpan("old.js", 2, 2, "base"), ChangedSpan("a.js", 4, 4, "head"))
    ctx = replace(changed_line_context(), renames=(PathRename("old.js", "a.js"),), spans=spans)
    # Identical operation carried across the rename is movement, never novelty.
    assert delta(scan(), scan(path="old.js"), ctx).novelty == "unknown"


def with_extra_question(result, *, status="completed", reason="answered", rows="[]", family="config_secrets", deferred=None):
    """Add an unrelated question to a scan, optionally unresolved or deferred."""
    from openultrasast.model.contracts import DeferredQuestion

    other = replace(result.scope.selected[0].identity, family=family)
    scope = replace(
        result.scope,
        selected=(*result.scope.selected, RankedQuestion(other, 0.0, ())) if deferred is None else result.scope.selected,
        deferred=(DeferredQuestion(other, deferred, ()),) if deferred is not None else result.scope.deferred,
    )
    added = QuestionOutcome(other, status, reason, rows)
    outcomes = result.question_outcomes if deferred is not None else (*result.question_outcomes, added)
    return replace(result, scope=scope, question_outcomes=outcomes), other


def test_unrelated_unsupported_family_no_longer_blocks_a_complete_target_comparison():
    """M1b 10.2: completeness is demanded over the required scope, not the whole repository."""
    base, other = with_extra_question(scan(rows=[], findings=False), status="unresolved", reason="unsupported_family", rows="[]")
    owned = "context_projection_unavailable:contributor-scan:" + other.question_id
    base = replace(base, scope=replace(base.scope, unresolved_boundaries=(owned,)))
    assert delta(scan(), base).novelty == "new"


def test_incomplete_counterpart_still_blocks():
    base = scan(rows=[], status="unanswered", findings=False)
    assert delta(scan(), base).novelty == "unknown"
    own = scan(rows=[], findings=False)
    owned = "context_projection_unavailable:contributor-scan:" + own.scope.selected[0].identity.question_id
    own = replace(own, scope=replace(own.scope, unresolved_boundaries=(owned,)))
    assert delta(scan(), own).novelty == "unknown"


def test_unknown_ownership_boundary_stays_inside_the_required_scope():
    base, _ = with_extra_question(scan(rows=[], findings=False))
    base = replace(base, scope=replace(base.scope, unresolved_boundaries=("graph_incomplete",)))
    assert delta(scan(), base).novelty == "unknown"


def test_truncated_base_cannot_establish_absence_wherever_it_was_truncated():
    base, _ = with_extra_question(scan(rows=[], findings=False), deferred="budget_exhausted")
    assert delta(scan(), base).novelty == "unknown"
    base, _ = with_extra_question(scan(rows=[], findings=False), deferred="tier_zero")
    assert delta(scan(), base).novelty == "new"


def test_a_recorded_dependency_of_the_counterpart_must_also_be_complete():
    from openultrasast.model.contracts import AffectedRelationship

    head = scan()
    target = head.scope.selected[0].identity
    helper = replace(target, path="helper.js", function="carry")
    ctx = replace(context(), relationships=(AffectedRelationship(helper, target, "callee", ("head_span:a.js:4-4",)),))
    base = scan(rows=[], findings=False)
    # The dependency is not answered in the base, so the required scope is incomplete.
    assert delta(head, base, ctx).novelty == "unknown"
    extended = replace(
        base,
        scope=replace(base.scope, selected=(*base.scope.selected, RankedQuestion(helper, 0.0, ()))),
        question_outcomes=(*base.question_outcomes, QuestionOutcome(helper, "completed", "answered", "[]")),
    )
    assert delta(head, extended, ctx).novelty == "new"


def test_repeated_unchanged_lines_do_not_invalidate_a_distinct_operation():
    """M1b 10.3: file-wide ambiguity is scoped to the operations whose anchor needs it."""
    ambiguous = "612e6a73:" + "ambiguous_line_correspondence"
    ctx = replace(changed_line_context(), unresolved_boundaries=(ambiguous,))
    assert delta(scan(), scan(rows=inventory_rows(), findings=False), ctx).novelty == "new"


def test_an_operation_needing_an_ambiguous_anchor_is_still_uncomparable():
    ambiguous = "612e6a73:" + "ambiguous_line_correspondence"
    ctx = replace(changed_line_context(ambiguous=True), unresolved_boundaries=(ambiguous,))
    assert delta(scan(), scan(rows=inventory_rows(), findings=False), ctx).novelty == "unknown"


def test_any_other_transaction_context_gap_still_blocks():
    ctx = replace(changed_line_context(), unresolved_boundaries=("snapshot:lfs_blob_unavailable",))
    candidate = delta(scan(), scan(rows=[], findings=False), ctx)
    assert (candidate.novelty, candidate.reason) == ("unknown", "change_context_unresolved")


def inventory_rows(*operations, complete=True, path="a.js", line=4, scope="structural"):
    rows = [
        {"kind": "operation_inventory", "inventory": op, "inventoryFile": path, "inventoryLine": line, "inventoryMethod": "handler"}
        for op in operations
    ]
    marker = {"kind": "operation_inventory_complete", "operations": len(rows), "scope": scope}
    return rows + ([marker] if complete else [])


def test_an_operation_present_in_the_base_inventory_is_not_new():
    """M1b 10.4: no traced flow is a reachability statement, not absence of the operation."""
    base = scan(rows=inventory_rows("exec(cmd)"), findings=False)
    candidate = delta(scan(), base, changed_line_context())
    assert candidate.novelty == "unknown"
    assert candidate.reason == "operation_present_in_base_without_traced_flow"


def test_an_enumerated_base_without_the_operation_establishes_absence():
    base = scan(rows=inventory_rows("query(sql, params)"), findings=False)
    candidate = delta(scan(), base, changed_line_context())
    assert (candidate.novelty, candidate.reason) == ("new", "operation_absent_from_comparable_base")


def test_an_empty_but_enumerated_scope_establishes_absence():
    base = scan(rows=inventory_rows(), findings=False)
    assert delta(scan(), base, changed_line_context()).novelty == "new"


def test_an_unenumerated_base_scope_stays_unresolved():
    base = scan(rows=[], findings=False)
    candidate = delta(scan(), base, changed_line_context())
    assert candidate.novelty == "unknown"
    assert candidate.reason == "base_operation_inventory_unavailable"


def test_a_malformed_inventory_row_is_not_an_empty_inventory():
    broken = [{"kind": "operation_inventory", "inventory": "exec(cmd)", "inventoryFile": "a.js", "inventoryLine": "0"}]
    broken.append({"kind": "operation_inventory_complete", "operations": 1})
    candidate = delta(scan(), scan(rows=broken, findings=False), changed_line_context())
    assert candidate.reason == "base_operation_inventory_unavailable"


def test_inventory_rows_do_not_count_as_unparsed_answer_body():
    """A completed answer carrying an inventory is still a valid answer, not a malformed one."""
    head = scan()
    rows = json.loads(head.question_outcomes[0].raw_rows_json) + inventory_rows("exec(cmd)")
    head = replace(head, question_outcomes=(replace(head.question_outcomes[0], raw_rows_json=json.dumps(rows)),))
    assert delta(head, scan(rows=inventory_rows("query(sql, params)"), findings=False), changed_line_context()).novelty == "new"


def bounded_base(*operations, own_question=True, scope="structural"):
    """A base whose only gap is its own bounded reachability."""
    base = scan(rows=inventory_rows(*operations, scope=scope), findings=False)
    owner = base.scope.selected[0].identity if own_question else replace(base.scope.selected[0].identity, family="path")
    gap = "dynamic_external_or_depth_context_unresolved:contributor-scan:" + owner.question_id
    return replace(base, scope=replace(base.scope, unresolved_boundaries=(gap,)))


def test_absence_from_a_structural_enumeration_survives_bounded_reachability():
    """M1b 10.5: enumeration is structural, so an unresolved destination cannot remove a call."""
    candidate = delta(scan(), bounded_base(), changed_line_context())
    assert (candidate.novelty, candidate.reason) == ("new", "operation_absent_from_comparable_base")


def test_a_traced_flow_absence_still_requires_complete_reachability():
    """The anchored branch rests on no flow having been traced, so the bound still blocks."""
    candidate = delta(scan(), bounded_base(), context())
    assert candidate.novelty == "unknown" and candidate.reason == "base_reachability_bounded"


def test_a_reachability_derived_enumeration_cannot_establish_absence_while_bounded():
    candidate = delta(scan(), bounded_base(scope="reachability"), changed_line_context())
    assert candidate.novelty == "unknown"
    assert candidate.reason == "base_enumeration_scope_reachability_derived"


def test_a_reachability_derived_enumeration_is_usable_when_reachability_is_complete():
    base = scan(rows=inventory_rows(scope="reachability"), findings=False)
    assert delta(scan(), base, changed_line_context()).novelty == "new"


def test_a_non_reachability_base_gap_still_blocks_an_enumerated_absence():
    base = scan(rows=inventory_rows(), findings=False)
    base = replace(base, scope=replace(base.scope, unresolved_boundaries=("graph_incomplete",)))
    assert delta(scan(), base, changed_line_context()).novelty == "unknown"


def test_a_present_operation_still_refuses_novelty_under_bounded_reachability():
    candidate = delta(scan(), bounded_base("exec(cmd)"), changed_line_context())
    assert candidate.reason == "operation_present_in_base_without_traced_flow"


def degraded(result, *reasons):
    return replace(result, degradations=tuple({"stage": "cpg", "reason": r} for r in reasons))


def test_a_declared_exclusion_does_not_block_a_comparison_on_either_side():
    """M1b 10.6 in comparison: the exclusion is a scope choice, not a failed read."""
    head = degraded(scan(), "vendor_semantics_unresolved")
    base = degraded(scan(rows=inventory_rows(), findings=False), "vendor_semantics_unresolved")
    assert delta(head, base, changed_line_context()).novelty == "new"


def test_an_integrity_degradation_still_blocks_a_comparison():
    head = degraded(scan(), "vendor_semantics_unresolved", "cpg_empty")
    base = scan(rows=inventory_rows(), findings=False)
    assert delta(head, base, changed_line_context()).reason == "head_context_incomplete"
    assert delta(scan(), degraded(base, "cpg_empty"), changed_line_context()).novelty == "unknown"


def test_a_declared_exclusion_boundary_does_not_block_either():
    base = scan(rows=inventory_rows(), findings=False)
    base = replace(base, scope=replace(base.scope, unresolved_boundaries=("vendor_semantics_unresolved",)))
    assert delta(scan(), base, changed_line_context()).novelty == "new"


def test_dependency_gaps_are_bound_to_the_candidate():
    """M1b 10.7: an unrelated question's gap is not this claim's unresolved dependency."""
    from openultrasast.push.policy import dependency_gaps

    head = scan()
    mine = head.scope.selected[0].identity
    other = replace(mine, family="path")
    head = replace(
        head,
        scope=replace(
            head.scope,
            selected=(*head.scope.selected, RankedQuestion(other, 0.0, ())),
            unresolved_boundaries=(
                "context_projection_unavailable:contributor-scan:" + other.question_id,
                "context_projection_unavailable:contributor-scan:" + mine.question_id,
                "dynamic_external_or_depth_context_unresolved:contributor-scan:" + mine.question_id,
                "vendor_semantics_unresolved",
                "612e6a73:ambiguous_line_correspondence",
                "snapshot:lfs_blob_unavailable",
            ),
        ),
        question_outcomes=(*head.question_outcomes, QuestionOutcome(other, "unresolved", "unsupported_family", "[]")),
    )
    candidate = delta(head, scan(rows=inventory_rows(), findings=False), changed_line_context())
    gaps = dependency_gaps(candidate, context=changed_line_context(), head=head)
    assert "context_projection_unavailable:contributor-scan:" + mine.question_id in gaps
    assert "snapshot:lfs_blob_unavailable" in gaps
    # Another question's problem, a scope choice, a per-operation decision and a weighed bound.
    assert "context_projection_unavailable:contributor-scan:" + other.question_id not in gaps
    assert "vendor_semantics_unresolved" not in gaps
    assert not any(g.endswith("ambiguous_line_correspondence") for g in gaps)
    assert not any(g.startswith("dynamic_external_or_depth") for g in gaps)


def test_an_integrity_degradation_is_this_candidate_s_dependency():
    from openultrasast.push.policy import dependency_gaps

    head = degraded(scan(), "cpg_sharded", "vendor_semantics_unresolved")
    candidate = delta(scan(), scan(rows=inventory_rows(), findings=False), changed_line_context())
    gaps = dependency_gaps(candidate, context=changed_line_context(), head=head)
    assert "cpg_sharded" in gaps and "vendor_semantics_unresolved" not in gaps


def test_a_candidate_without_an_operation_reports_no_dependency_gaps():
    """Witness resolution is its own admission reason; this one has nothing to attribute gaps to."""
    from openultrasast.push.policy import dependency_gaps

    candidate = replace(delta(scan(), scan(rows=inventory_rows(), findings=False), changed_line_context()), head_operation=None)
    assert dependency_gaps(candidate, context=changed_line_context(), head=scan()) == ()


def test_a_gap_from_another_language_partition_does_not_block_admission():
    """A JavaScript file missing from the JavaScript graph cannot make a PHP answer wrong.

    A partitioned scan records a gap per graph, and treating one partition's gap as evidence against every
    claim left a WordPress plugin -- PHP plus its admin JavaScript, which is every plugin -- unable to admit a
    finding it had already established. Measured 2026-09-21: four build artefacts against 4,425 PHP regions.
    """
    from openultrasast.push.policy import _blocking_degradations

    elsewhere = {"stage": "model", "reason": "partition_file_census_incomplete", "census_language": "javascript"}
    here = {"stage": "model", "reason": "partition_file_census_incomplete", "census_language": "php"}
    unplaced = {"stage": "model", "reason": "partition_file_census_incomplete"}

    def scan(*degradations):
        return ModelScanResult(findings=(), degradations=tuple(degradations))

    assert _blocking_degradations(scan(elsewhere), language="php") == ()
    assert _blocking_degradations(scan(here), language="php") == ("partition_file_census_incomplete",)
    # Unknown scope is not evidence of independence, in either direction.
    assert _blocking_degradations(scan(unplaced), language="php") == ("partition_file_census_incomplete",)
    assert _blocking_degradations(scan(elsewhere), language="") == ("partition_file_census_incomplete",)
