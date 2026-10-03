"""A file new in head is `new`, not `comparison unknown` (task 17.4, Requirement 9.4)."""

from __future__ import annotations

from dataclasses import replace

from test_push_admission import control
from test_push_policy import delta, scan
from test_push_report import budget, report_with

from openultrasast.model.contracts import ChangeContext, ChangedSpan
from openultrasast.push.policy import admit_candidates
from openultrasast.push.report import deliver_report


def added(*, boundaries=(), listed=True):
    return ChangeContext(
        "base",
        "head",
        ("a.js",),
        (),
        (ChangedSpan("a.js", 1, 6, "head"),),
        (),
        (),
        (),
        tuple(boundaries),
        added_paths=("a.js",) if listed else (),
    )


def test_snapshot_records_added_paths_and_not_modified_ones(tmp_path):
    import json

    from test_push_runner import history

    from openultrasast.cpg.backend import NullBackend
    from openultrasast.push.runner import replay

    root, _, base, git = history(tmp_path)
    (root / "debug.js").write_text("eval(x)\n")
    (root / "api.js").write_text("changed\n")
    git("add", "debug.js", "api.js")
    git("commit", "-m", "add and modify")
    head = git("rev-parse", "HEAD")
    replay(root, base=base, head=head, artifact=tmp_path / "r.json", backend=NullBackend())
    context = json.loads((tmp_path / "r.json").read_text())["change_context"]
    assert context["added_paths"] == [b"debug.js".hex()]


def test_operation_in_an_added_file_is_new_without_any_base_answer():
    result = delta(scan(), None, added())
    assert (result.novelty, result.reason) == ("new", "file_added_in_head")
    assert result.change_evidence == ("head:a.js:1-6",)


def test_the_same_shape_without_the_added_fact_keeps_its_veto():
    assert delta(scan(), None, added(listed=False)).novelty == "unknown"


def test_unpaired_add_and_delete_stays_unknown():
    result = delta(scan(), None, added(boundaries=("unmatched_added_deleted_path_correspondence",)))
    assert (result.novelty, result.reason) == ("unknown", "change_context_unresolved")


def test_an_operation_already_in_the_base_elsewhere_is_movement_not_new():
    result = delta(scan(), scan(path="b.js", line=9), added())
    assert (result.novelty, result.reason) == ("unknown", "operation_moved_within_change")


def test_unentailed_or_discharged_claims_in_added_files_are_not_new():
    assert delta(scan(sanitized=True), None, added()).novelty == "unknown"


def test_admission_accepts_the_added_file_reason():
    candidate, capability, _ = control()
    new_file = replace(candidate, delta=replace(candidate.delta, reason="file_added_in_head"))
    assert len(admit_candidates((new_file,), capabilities=(capability,)).defects) == 1
    unqualified = admit_candidates((new_file,))
    assert unqualified.dispositions[0].reasons == ("capability_unavailable",)


def test_unqualified_new_engine_finding_is_shown_as_advisory_not_alert(tmp_path):
    report = report_with(1, admitted=False)
    delivered = deliver_report(report, tmp_path / "r.json", execution_budget=budget())
    assert delivered.exit_code == 0 and delivered.result.actionable_defect_ids == ()
    assert "Engine: 1 finding(s) this push introduced. Advisory" in delivered.text
    assert "- injection at handler.src:4 (new): request.input -> exec(command)" in delivered.text


def test_a_comparison_veto_keeps_an_engine_finding_out_of_the_terminal(tmp_path):
    report = report_with(1, admitted=False)
    disposition = report.admission.dispositions[0]
    vetoed = replace(disposition, reasons=(*disposition.reasons, "comparison_unknown"))
    report = replace(report, admission=replace(report.admission, dispositions=(vetoed,)))
    delivered = deliver_report(report, tmp_path / "r.json", execution_budget=budget())
    assert "Engine:" not in delivered.text
