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
            return CpgResult(Path("graph"), lambda kind, params: rows)

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
    ctx = replace(context(), spans=(ChangedSpan("a.js", 4, 4, "head"),), line_correspondences=())
    assert delta(scan(), scan(rows=[], findings=False), ctx).novelty == "unknown"
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
    own_gap = gap.rsplit(":", 1)[0] + ":" + head.scope.selected[0].identity.question_id
    assert (
        delta(replace(head, scope=replace(head.scope, unresolved_boundaries=(own_gap,))), scan(rows=[], findings=False)).novelty
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
