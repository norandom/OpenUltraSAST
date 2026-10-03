"""Plain-language skip lines (pre-push 17.2, Requirement 9.2): nothing hidden, nothing opaque."""

import re
from dataclasses import replace

from test_push_report import budget, report_with

from openultrasast.push.explain import explain, language_reason
from openultrasast.push.report import deliver_report

# Coverage reasons recorded by the 2026-10-02 audit's live runs, verbatim in shape.
AUDIT = (
    "7265636f7264732e7079:ambiguous_line_correspondence",
    "base_counterpart_unresolved",
    "cpg_build_failed",
    "frontend_unsupported",
    "analysis_incomplete",
    "base_comparison_unavailable",
    "eligibility:eligibility_provenance_mismatch",
    *(f"dynamic_external_or_depth_context_unresolved:contributor-scan:{i:064x}" for i in range(20)),
    "resolution:missing_base",
    "admission_failed:TimeoutError",
    "base_incomplete",
    "comparison_unknown",
)


def test_audit_reasons_become_one_plain_line_each():
    lines = explain(AUDIT, deadline=30)
    text = "\n".join(lines)
    assert "records.py" in text and "7265636f7264732e7079" not in text
    assert not re.search(r"[0-9a-f]{64}", text)
    assert "20 engine check(s) depend on dynamic or external code" in text
    assert "Joern" in text and "new branch: the remote has no base" in text
    assert "the admission step failed (TimeoutError)" in text
    assert "analysis_incomplete" not in text and "analysis incomplete" not in text
    # One line per distinct kind: twenty hashed reasons are one line, comparison_unknown folds into its cause.
    assert len(lines) == 10
    assert sum("could not be established" in line for line in lines) == 1


def test_every_glossary_reason_is_documented_for_users():
    """17.6: the skip-reason glossary in docs/scanning.md names every reason the terminal explains."""
    from pathlib import Path

    from openultrasast.push.explain import _NOVELTY_REASONS, _RESOLUTION, GLOSSARY

    docs = (Path(__file__).resolve().parents[1] / "docs" / "scanning.md").read_text()
    missing = [key for key in GLOSSARY if key not in docs]
    missing += [f"resolution:{key}" for key in _RESOLUTION if f"`resolution:{key}`" not in docs]
    assert not missing, missing
    assert "base_incomplete" in docs and _NOVELTY_REASONS


def test_unknown_reason_is_still_printed():
    assert explain(("some_future_reason",)) == ["some future reason (see the details file)"]


def test_deadline_line_names_the_deadline_and_the_background_option():
    (line,) = explain(("deadline_exhausted",), deadline=30)
    assert "30 s" in line and "background" in line


def test_language_not_covered_is_named_with_counts():
    (line,) = explain((language_reason("go", 1, 12),))
    assert line.startswith("language not covered: go (1 changed file(s), 12 in the repository)")


def test_terminal_shows_skip_lines_while_artifact_keeps_raw_reasons(tmp_path):
    import json

    report = report_with(0)
    raw = ("7265636f7264732e7079:ambiguous_line_correspondence", f"dynamic_external_or_depth_context_unresolved:contributor-scan:{1:064x}")
    report = replace(
        report,
        admission=replace(report.admission, coverage_reasons=raw),
        result=replace(report.result, coverage_status="incomplete"),
    )
    delivered = deliver_report(report, tmp_path / "run.json", execution_budget=budget())
    assert "Skipped: changed lines could not be matched one-to-one to base lines in records.py" in delivered.text
    assert "7265636f" not in delivered.text and f"{1:064x}" not in delivered.text
    assert delivered.text.count("Notice:") == 1
    assert tuple(json.loads(delivered.artifact.read_text())["admission"]["coverage_reasons"]) == raw


def test_replay_names_a_changed_language_nothing_covers(tmp_path):
    import json

    from test_push_runner import history

    from openultrasast.cpg.backend import NullBackend
    from openultrasast.push.runner import replay

    root, base, _, git = history(tmp_path)
    (root / "run.go").write_text("package main\n")
    git("add", "run.go")
    git("commit", "-m", "go")
    head = git("rev-parse", "HEAD")
    delivery = replay(root, base=base, head=head, artifact=tmp_path / "r.json", backend=NullBackend())
    assert "Skipped: language not covered: go (1 changed file(s), 1 in the repository)" in delivery.text
    assert "language_not_covered:go:1:1" in json.loads((tmp_path / "r.json").read_text())["admission"]["coverage_reasons"]
