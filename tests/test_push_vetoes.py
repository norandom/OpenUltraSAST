"""M1a recorded-veto evaluation: vetoes are recorded beside the production result, never applied."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from test_push_policy import context, scan

from openultrasast.cpg.backend import NullBackend
from openultrasast.model.contracts import QuestionOutcome
from openultrasast.push.contracts import PushComparison
from openultrasast.push.policy import _compare_evidence, admit_candidates
from openultrasast.push.report import PushReport, render_report
from openultrasast.push.vetoes import FLAG, LABEL, RecordedVetoReport, boundary_kind, record_vetoes

COMPARISON = PushComparison("head", "base", "explicit", ("refs/heads/main",))


def vetoed(result, reason, *, boundaries=(), vendor=True):
    outcome = result.question_outcomes[0]
    demoted = replace(outcome, status="unresolved", reason=reason)
    return replace(
        result,
        question_outcomes=(demoted,),
        degradations=({"stage": "cpg", "reason": "vendor_semantics_unresolved"},) if vendor else (),
        scope=replace(result.scope, unresolved_boundaries=(*boundaries, *(("vendor_semantics_unresolved",) if vendor else ()))),
    )


def production(head, base, ctx):
    candidates = _compare_evidence(head, base, context=ctx, head_semantics="same", base_semantics="same")
    return candidates, {c.defect_id: ("capability_unavailable",) for c in candidates}


def test_recognized_vetoes_are_lifted_recorded_and_never_applied():
    head = scan()
    question = head.scope.selected[0].identity
    owned = "context_projection_unavailable:contributor-scan:" + question.question_id
    head = vetoed(head, "change_context_incomplete", boundaries=(owned,))
    base = vetoed(scan(rows=[], findings=False), "graph_incomplete")
    ctx = replace(context(), unresolved_boundaries=("612e6a73:ambiguous_line_correspondence",))
    applied, admission = production(head, base, ctx)
    assert applied[0].novelty == "unknown" and applied[0].reason == "witness_identity_unresolved"

    report = record_vetoes(
        head=head,
        base=base,
        context=ctx,
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=("vendor_semantics_unresolved", "612e6a73:ambiguous_line_correspondence", "deadline_exhausted"),
    )
    assert report.label == LABEL and report.flag == FLAG and report.label.startswith("EXPERIMENTAL")
    finding = report.findings[0]
    assert (finding.production_novelty, finding.production_reason) == ("unknown", "witness_identity_unresolved")
    assert (finding.recorded_novelty, finding.recorded_reason) == ("new", "source_connection_absent_from_comparable_base")
    assert finding.question == question and finding.operation is not None and finding.base_location == "a.js:5"
    lifted = {(v.stage, v.veto) for v in finding.vetoes if v.lifted}
    assert lifted == {
        ("head_question", "change_context_incomplete"),
        ("head_scan", "context_projection_unavailable"),
        ("head_scan", "vendor_semantics_unresolved"),
        ("head_scan", "degradation:vendor_semantics_unresolved"),
        ("base_question", "graph_incomplete"),
        ("base_scan", "vendor_semantics_unresolved"),
        ("base_scan", "degradation:vendor_semantics_unresolved"),
        ("change_context", "ambiguous_line_correspondence"),
    }
    remaining = {(v.stage, v.veto) for v in finding.vetoes if not v.lifted}
    # The unlifted deadline reason still reaches admission as a dependency gap.
    assert remaining == {("admission", "capability_unavailable"), ("admission", "dependency_unresolved")}
    assert finding.recorded_admission == ("capability_unavailable", "dependency_unresolved")
    assert report.lifted_coverage_reasons == ("vendor_semantics_unresolved", "612e6a73:ambiguous_line_correspondence")
    assert report.remaining_coverage_reasons == ("deadline_exhausted",)
    assert {(c.status, c.reason) for c in report.head.lifted} == {
        ("question", "change_context_incomplete"),
        ("degradation", "vendor_semantics_unresolved"),
    }
    assert ("question", "graph_incomplete") in {(c.status, c.reason) for c in report.base.lifted}
    assert report.head.changed_path_questions[0].lifted and report.head.changed_path_questions[0].rows == 1
    # Round trip and the production evidence are untouched.
    assert RecordedVetoReport.from_payload(json.loads(json.dumps(report.to_payload()))) == report
    assert head.question_outcomes[0].status == "unresolved" and base.question_outcomes[0].status == "unresolved"


def test_failures_and_unrecognized_boundaries_are_never_lifted():
    head = replace(scan(), degradations=({"stage": "cpg", "reason": "cpg_empty"},))
    base = scan(rows=[], status="unanswered", findings=False)
    applied, admission = production(head, base, context())
    report = record_vetoes(
        head=head,
        base=base,
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=("cpg_empty",),
    )
    finding = report.findings[0]
    assert finding.recorded_novelty == "unknown" and finding.recorded_reason == "head_context_incomplete"
    assert not any(v.lifted for v in finding.vetoes)
    assert ("head_scan", "degradation:cpg_empty") in {(v.stage, v.veto) for v in finding.vetoes}
    assert ("base_question", "test_answer") in {(v.stage, v.veto) for v in finding.vetoes}
    assert report.remaining_coverage_reasons == ("cpg_empty",) and report.lifted_coverage_reasons == ()
    assert boundary_kind("deadline_exhausted") is None and boundary_kind("snapshot:unreadable") is None


def test_unanswered_lifted_reason_without_rows_stays_applied():
    head = scan()
    outcome = QuestionOutcome(head.question_outcomes[0].identity, "unanswered", "graph_incomplete", None)
    head = replace(head, question_outcomes=(outcome,))
    applied, admission = production(head, scan(rows=[], findings=False), context())
    report = record_vetoes(
        head=head,
        base=scan(rows=[], findings=False),
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=(),
    )
    assert report.head.lifted == () and report.findings[0].recorded_novelty == "unknown"
    assert report.findings[0].operation is None


def test_quiet_fixed_twin_reports_base_only_finding_with_answered_head_counterpart():
    head = scan(rows=[], findings=False)
    base = scan()
    applied, admission = production(head, base, context())
    report = record_vetoes(
        head=head,
        base=base,
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=(),
    )
    assert report.findings == ()
    only = report.base_only_findings[0]
    assert only.site == "a.js:4:handler" and only.head_counterparts[0].status == "completed" and only.head_counterparts[0].rows == 0


def test_query_identity_difference_is_recorded_not_applied():
    head = scan()
    question = replace(head.scope.selected[0].identity, function=None)
    rows = json.loads(head.question_outcomes[0].raw_rows_json)
    rows[0]["sinkMethod"] = "<lambda>2"
    head = replace(
        head,
        scope=replace(head.scope, selected=(replace(head.scope.selected[0], identity=question),)),
        question_outcomes=(QuestionOutcome(question, "completed", "test_answer", json.dumps(rows)),),
        findings=(replace(head.findings[0], site="a.js:4:<lambda>2"),),
    )
    base = scan(rows=[], findings=False)
    base = replace(
        base,
        scope=replace(base.scope, selected=(replace(base.scope.selected[0], identity=question),)),
        question_outcomes=(QuestionOutcome(question, "completed", "test_answer", "[]"),),
    )
    applied, admission = production(head, base, context())
    report = record_vetoes(
        head=head,
        base=base,
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=(),
    )
    finding = report.findings[0]
    identity = [v for v in finding.vetoes if v.stage == "identity"]
    assert identity and identity[0].veto == "query_identity_differs_from_witness" and "<lambda>2" in identity[0].detail
    assert finding.operation_method == "<lambda>2" and finding.recorded_novelty == "new"


def test_recorded_report_never_admits_even_when_lifted_candidate_would_pass():
    from test_push_admission import control

    candidate, capability, _ = control()
    head = scan()
    base = scan(rows=[], findings=False)
    applied, admission = production(head, base, context())
    report = record_vetoes(
        head=head,
        base=base,
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=(),
        capabilities=(capability,),
    )
    assert admit_candidates((candidate,), capabilities=(capability,)).defects  # the control itself admits
    payload = report.to_payload()
    assert "defects" not in payload and all("admitted" not in f for f in payload["findings"])


def test_report_requires_label_and_renders_experimental_line(tmp_path):
    from test_push_report import report_with

    base = report_with()
    with pytest.raises(ValueError, match="experimental label"):
        replace(base, experimental={"status": "evaluated"})
    section = {"label": LABEL, "flag": FLAG, "status": "evaluated", "findings": [{"vetoes": [{}, {}]}], "evaluation": [{}]}
    labeled = replace(base, experimental=section)
    text = render_report(labeled, artifact=None)
    assert "Experimental: recorded-veto evaluation retained 1 raw finding(s) with 2 recorded veto(es)" in text
    assert "1 change-attributed evaluation finding(s)" in text
    assert "not an alert" in text
    pending = replace(base, experimental={"label": LABEL, "flag": FLAG, "status": "not_evaluated", "reason": "head_failed:TimeoutError"})
    assert "was not produced (head_failed:TimeoutError)" in render_report(pending, artifact=None)
    assert "Experimental:" not in render_report(base, artifact=None)
    assert isinstance(base, PushReport)


def test_replay_flag_is_off_by_default_and_labels_its_artifact(tmp_path):
    from test_push_runner import history

    from openultrasast.push.runner import replay

    root, base, head, _ = history(tmp_path)
    plain = tmp_path / "plain.json"
    replay(root, base=base, head=head, artifact=plain, backend=NullBackend())
    assert json.loads(plain.read_text())["experimental"] == {}
    recorded = tmp_path / "recorded.json"
    delivery = replay(root, base=base, head=head, artifact=recorded, backend=NullBackend(), record_vetoes=True)
    data = json.loads(recorded.read_text())
    assert data["experimental"]["label"] == LABEL and data["experimental"]["flag"] == FLAG
    assert data["experimental"]["status"] in ("evaluated", "not_evaluated")
    assert data["result"]["finding_status"] == "none" and data["admission"]["defects"] == []
    assert "Experimental:" in delivery.text and delivery.exit_code == 0


def test_cli_refuses_the_flag_outside_explicit_replay(tmp_path, capsys):
    from test_push_runner import history

    from openultrasast.cli import main

    root, base, head, _ = history(tmp_path)
    with pytest.raises(SystemExit):
        main(["pre-push", str(root), "--remote", "origin", "/x", "--artifact", str(tmp_path / "x.json"), "--experimental-record-vetoes"])
    assert "requires explicit --base/--head replay" in capsys.readouterr().err
    code = main(
        [
            "pre-push",
            str(root),
            "--base",
            base,
            "--head",
            head,
            "--artifact",
            str(tmp_path / "cli.json"),
            "--deadline",
            "20",
            "--experimental-record-vetoes",
        ]
    )
    assert code == 0 and "Experimental:" in capsys.readouterr().out


def declaration(*, symbols=("eval",), consequence="Input reaching {operation} is evaluated in {context}.", verdict="experimental"):
    from openultrasast.push.policy import CapabilityAdmission, CapabilityKey

    key = CapabilityKey("javascript", "unspecified", "unspecified", "injection", "taint", "unreviewed", "same")
    return CapabilityAdmission(
        key,
        "unreviewed-demonstration-v1",
        "experimental://unreviewed",
        verdict,
        consequence,
        "At {operation}, convert the value before use in {context}.",
        operation_symbols=symbols,
    )


def rendered(*, declarations=(), base=None):
    head = scan()
    base = base if base is not None else scan(rows=[], findings=False)
    applied, admission = production(head, base, context())
    return record_vetoes(
        head=head,
        base=base,
        context=context(),
        comparison=COMPARISON,
        semantics="same",
        production=applied,
        production_admission=admission,
        coverage_reasons=(),
        declarations=declarations,
    )


def test_evaluation_renders_consequence_and_repair_from_a_declaration():
    """M1b 10.10: the explanation comes from a declaration's templates, never from invented prose."""
    report = rendered(declarations=(declaration(),))
    item = report.evaluation[0]
    assert item.novelty == "new" and item.family == "injection" and (item.path, item.line) == ("a.js", 4)
    assert item.witness == "req.body -> exec(cmd) in a.js (line 4, 2 steps)"
    assert item.change_evidence and item.provenance == "exact" and item.engine_method == "handler"
    assert item.consequence == "Input reaching exec(cmd) is evaluated in unreviewed."
    assert item.repair == "At exec(cmd), convert the value before use in unreviewed."
    assert item.declaration == "unreviewed-demonstration-v1"
    assert item.declaration_verdict == "experimental" and item.declaration_enabled is False


def test_evaluation_states_why_an_explanation_is_unavailable():
    report = rendered()
    item = report.evaluation[0]
    assert item.consequence is None and item.repair is None
    assert item.unavailable == ("no_matching_declaration",)


def test_an_ungrounded_template_is_refused_rather_than_rendered():
    report = rendered(declarations=(declaration(consequence="Sanitize your input."),))
    item = report.evaluation[0]
    assert item.consequence is None and "consequence_template_ungrounded" in item.unavailable
    assert item.repair is not None


def test_a_declaration_not_covering_the_operation_symbol_says_so():
    report = rendered(declarations=(declaration(symbols=("query",)),))
    assert "declaration_does_not_cover_operation_symbol" in report.evaluation[0].unavailable
    assert report.evaluation[0].operation_symbol == "exec"


def test_only_a_change_attributed_finding_is_rendered():
    # The anchor maps head line 4 to base line 5, so this base carries the same operation.
    unchanged = rendered(declarations=(declaration(),), base=scan(line=5))
    assert unchanged.findings[0].production_novelty == "unchanged"
    assert unchanged.evaluation == ()


def test_an_enabled_passing_declaration_here_still_admits_nothing():
    """The rendering path is outside admission, so no supplied declaration can emit an alert."""
    report = rendered(declarations=(declaration(verdict="PASS"),))
    assert report.evaluation[0].declaration_verdict == "PASS"
    payload = report.to_payload()
    assert "defects" not in payload
    assert all("admitted" not in item for item in payload["evaluation"])
