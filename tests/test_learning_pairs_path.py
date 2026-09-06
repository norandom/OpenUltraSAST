"""learning-harness task 3.2: family scoring on the pairs hunter path (offline)."""

from __future__ import annotations

from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.pairs import PairCase, evaluate_pair

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "from flask import request\nimport subprocess\n\n\ndef run():\n    subprocess.run(['echo', request.args.get('cmd')], check=False)\n"


def _case(tmp_path: Path, *, family: str | None = "injection", unscorable: str | None = None) -> PairCase:
    (tmp_path / "v.py").write_text(VULN)
    (tmp_path / "f.py").write_text(FIXED)
    return PairCase(
        name="p",
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / "v.py",
        fixed_file=tmp_path / "f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other", family=family
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        unscorable=unscorable,
    )


def _finding(family: str, line: int) -> StaticFinding:
    return StaticFinding(
        finding_id=f"detector:app.py:{line}",
        path="app.py",
        title="t",
        severity="high",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=line,
        function_name="run",
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[f"family:{family}", "detector:injection@1"],
        ranking_priority=0.0,
    )


def _hunter(vuln: list[StaticFinding], fixed: list[StaticFinding]):  # type: ignore[no-untyped-def]
    seen: list[Path] = []

    def scan(root: Path) -> list[StaticFinding]:
        seen.append(root)
        return vuln if root.name == "vuln" else fixed

    scan.seen = seen  # type: ignore[attr-defined]
    return scan


def test_the_hunter_path_scores_by_family_and_function_not_by_text(tmp_path: Path) -> None:
    right = evaluate_pair(_case(tmp_path), hunter=_hunter([_finding("injection", 6)], []))
    assert right.detected_vuln and right.silent_fix and right.pair_correct
    assert right.detection_kinds == ("hunter",) and right.family == "injection"
    wrong_family = evaluate_pair(_case(tmp_path), hunter=_hunter([_finding("access_control", 6)], []))
    assert not wrong_family.detected_vuln  # the right place, the wrong family
    loud = StaticFinding(**{**_finding("access_control", 6).__dict__, "title": "CWE-78 command injection in run"})
    assert not evaluate_pair(_case(tmp_path), hunter=_hunter([loud], [])).detected_vuln  # the words never count


def test_a_finding_of_another_family_on_the_fixed_side_is_not_a_leak(tmp_path: Path) -> None:
    outcome = evaluate_pair(_case(tmp_path), hunter=_hunter([_finding("injection", 6)], [_finding("access_control", 6)]))
    assert outcome.pair_correct and outcome.silent_fix
    assert outcome.fix_findings == 1 and outcome.fix_leaks == 0  # counted, never charged
    leaked = evaluate_pair(_case(tmp_path), hunter=_hunter([_finding("injection", 6)], [_finding("injection", 6)]))
    assert leaked.detected_vuln and not leaked.silent_fix and leaked.fix_leaks == 1


def test_an_unscorable_pair_is_reported_as_such_and_never_run(tmp_path: Path) -> None:
    hunter = _hunter([_finding("injection", 6)], [])
    outcome = evaluate_pair(_case(tmp_path, unscorable="identical_twin"), hunter=hunter)
    assert outcome.unscorable == "identical_twin" and not outcome.detected_vuln
    assert hunter.seen == []  # type: ignore[attr-defined]


def test_a_pair_with_no_family_label_falls_back_to_the_classifier(tmp_path: Path) -> None:
    outcome = evaluate_pair(_case(tmp_path, family=None), hunter=_hunter([_finding("injection", 6)], []))
    assert outcome.family == "injection" and outcome.pair_correct  # CWE-78 classifies as injection


def test_the_overlay_path_is_untouched_by_the_family_scorer(tmp_path: Path) -> None:
    overlay = evaluate_pair(_case(tmp_path))
    assert overlay.detection_kinds != ("hunter",) and overlay.family == ""


def test_the_scoreboard_carries_the_family_block(tmp_path: Path) -> None:
    from openultrasast.pairs import evaluate_catalog, result_payload

    result = evaluate_catalog([_case(tmp_path)], hunter=_hunter([_finding("injection", 6)], []), inventory_sidecar=False)
    payload = result_payload(result)
    assert "per_family" in payload and payload["per_family"]["injection"]["scorable"] == 1
    assert payload["per_family"]["injection"]["recall"] == 1.0
    assert payload["per_family"]["injection"]["hierarchical_credit"] is False
    assert payload["per_family"]["injection"]["taxonomy_version"]
