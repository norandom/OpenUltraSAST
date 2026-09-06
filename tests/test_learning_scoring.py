"""learning-harness task 2.3: per-pair family scoring (offline)."""

from __future__ import annotations

from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.pairs import PairCase

RANGES = {"app.py": (("leaky", 10, 13), ("guarded", 4, 7))}


def _finding(family: str, line: int, path: str = "app.py") -> StaticFinding:
    return StaticFinding(
        finding_id=f"detector:{path}:{line}",
        path=path,
        title="t",
        severity="medium",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=line,
        function_name=None,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[f"family:{family}", "detector:x@1"],
        ranking_priority=0.0,
    )


def _case(tmp_path: Path, *, family: str = "access_control", unscorable: str | None = None) -> PairCase:
    (tmp_path / "v.py").write_text("x = 1\n")
    (tmp_path / "f.py").write_text("x = 2\n")
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
                cwe="CWE-639", vulnerability_class="x", path="app.py", evidence="", function="leaky", mechanism="other", family=family
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        unscorable=unscorable,
    )


def test_detection_needs_the_labeled_family_inside_the_labeled_function(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    case = _case(tmp_path)
    hit = score_pair_family(case, "access_control", [[_finding("access_control", 12)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert hit.outcome == "pair_correct" and hit.runs == ("pair_correct",)
    outside = score_pair_family(case, "access_control", [[_finding("access_control", 5)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert outside.outcome == "both_silent"  # the right family in the wrong function is not a detection
    other_file = score_pair_family(
        case, "access_control", [[_finding("access_control", 12, "other.py")]], [[]], ranges=RANGES, taxonomy=taxonomy
    )
    assert other_file.outcome == "both_silent"
    wrong_family = score_pair_family(case, "access_control", [[_finding("injection", 12)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert wrong_family.outcome == "both_silent" and wrong_family.other_findings_vuln == 1


def test_a_fabricated_family_never_counts_and_is_recorded(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    score = score_pair_family(_case(tmp_path), "access_control", [[_finding("sql_injection", 12)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert score.outcome == "both_silent" and score.fabricated_vuln == 1
    assert score.other_findings_vuln == 0  # a fabricated id is not another family, it is noise


def test_silence_ignores_findings_of_other_families_and_never_calls_them_leaks(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    case = _case(tmp_path)
    quiet = score_pair_family(
        case,
        "access_control",
        [[_finding("access_control", 12)]],
        [[_finding("injection", 12), _finding("access_control", 5)]],
        ranges=RANGES,
        taxonomy=taxonomy,
    )
    assert quiet.outcome == "pair_correct" and quiet.other_findings_fixed == 2
    leaked = score_pair_family(
        case, "access_control", [[_finding("access_control", 12)]], [[_finding("access_control", 13)]], ranges=RANGES, taxonomy=taxonomy
    )
    assert leaked.outcome == "both_flagged"
    reversed_pair = score_pair_family(case, "access_control", [[]], [[_finding("access_control", 12)]], ranges=RANGES, taxonomy=taxonomy)
    assert reversed_pair.outcome == "reversed"


def test_the_outcome_of_several_runs_is_their_majority(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    case = _case(tmp_path)
    hit = [_finding("access_control", 12)]
    score = score_pair_family(case, "access_control", [hit, [], hit], [[], [], []], ranges=RANGES, taxonomy=taxonomy)
    assert score.runs == ("pair_correct", "both_silent", "pair_correct") and score.outcome == "pair_correct"
    flaky = score_pair_family(case, "access_control", [hit, [], []], [[], [], []], ranges=RANGES, taxonomy=taxonomy)
    assert flaky.outcome == "both_silent" and flaky.flips == 1  # a run that disagrees with the majority is a flip


def test_an_unscorable_pair_is_never_run_and_keeps_its_reason(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    case = _case(tmp_path, unscorable="identical_twin")
    score = score_pair_family(case, "access_control", [[_finding("access_control", 12)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert score.outcome == "unscorable" and score.unscorable_reason == "identical_twin" and score.runs == ()


def test_a_pair_with_no_parsed_function_range_is_unscorable_not_a_miss(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    score = score_pair_family(_case(tmp_path), "access_control", [[]], [[]], ranges={}, taxonomy=taxonomy)
    assert score.outcome == "unscorable" and score.unscorable_reason == "unresolved_label"


def test_scoring_never_reads_the_text_of_a_finding(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    shouting = _finding("injection", 12)
    loud = StaticFinding(**{**shouting.__dict__, "title": "CWE-639 broken object level authorization", "rationale": "IDOR in leaky"})
    score = score_pair_family(_case(tmp_path), "access_control", [[loud]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert score.outcome == "both_silent"  # the words say access control; the family tag says injection, and only that counts


def test_the_rung_is_the_best_verifier_outcome_among_the_detections(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    taxonomy = load_families()
    corroborated = _finding("access_control", 12)
    corroborated.tags.append("verifier:static_corroboration")
    score = score_pair_family(_case(tmp_path), "access_control", [[corroborated]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert score.outcome == "pair_correct" and score.rung == "static_corroboration"
    plain = score_pair_family(_case(tmp_path), "access_control", [[_finding("access_control", 12)]], [[]], ranges=RANGES, taxonomy=taxonomy)
    assert plain.rung == "suspicion"
