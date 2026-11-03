"""Task 13.4 admission measurement unit tests (Reqs 12.1-12.9).

The admission runner consumes a reviewed upstream manifest for the untouched
pilot population, proves both sides of every vulnerable/fixed twin and every
reviewed ordinary change, maps per-site prover evidence onto the three-way
judgment vocabulary and returns the paired admission report.
"""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid.admission_run import (  # noqa: E402
    admission_ordinary,
    admission_pair_cases,
    classify_fixed_site,
    coverage_share,
    fixed_side_change,
    locate_function,
    site_judgment,
)

SITE = ("src/app.py", 30, 40)


def _trace(path: str, line: int, judgment: str, *, complete: bool = True) -> dict[str, object]:
    return {
        "fact_id": f"obligation:protected_read:{path}:{line}:identity_constraint",
        "abstract_state": {
            "path_judgment": {
                "judgment": judgment,
                "completeness": {"is_complete": complete, "reasons": [] if complete else ["deadline"]},
            }
        },
    }


def _finding(path: str, line: int, family: str = "access_control") -> dict[str, object]:
    return {"path": path, "line": line, "family": family, "id": f"obligation:{path}:{line}"}


def _record(record_id: str, **over: object) -> dict[str, Any]:
    record = {
        "id": record_id,
        "repo": "example/project",
        "kind": "vulnerability",
        "path": "src/app.py",
        "function_lines": [30, 40],
        "findings": [],
        "traces": [],
        "degradations": [],
        "stage_funnel": {"judgment": {"unguarded": 0, "discharged": 0, "indeterminate": 0}},
        "instrument": {"hook_bytes_read": 10, "changed_bytes": {"src/app.py": 10}, "file_bytes": {"src/app.py": 10}},
        "status": "prover_covered",
        "seconds": 1.0,
    }
    record.update(over)
    return record


def test_site_judgment_unguarded_when_finding_in_range() -> None:
    record = _record("v1", findings=[_finding("src/app.py", 35)])
    assert site_judgment(record, path=SITE[0], start=SITE[1], end=SITE[2]) == "unguarded"


def test_site_judgment_ignores_finding_outside_site() -> None:
    record = _record("v1", findings=[_finding("src/other.py", 35), _finding("src/app.py", 200)])
    assert site_judgment(record, path=SITE[0], start=SITE[1], end=SITE[2]) == "discharged"


def test_site_judgment_indeterminate_on_incomplete_trace() -> None:
    record = _record("v1", traces=[_trace("src/app.py", 33, "indeterminate", complete=False)])
    assert site_judgment(record, path=SITE[0], start=SITE[1], end=SITE[2]) == "indeterminate"


def test_site_judgment_discharged_on_completed_trace() -> None:
    record = _record("v1", traces=[_trace("src/app.py", 33, "discharged", complete=True)])
    assert site_judgment(record, path=SITE[0], start=SITE[1], end=SITE[2]) == "discharged"


def test_site_judgment_quiet_without_traces_is_discharged() -> None:
    assert site_judgment(_record("v1"), path=SITE[0], start=SITE[1], end=SITE[2]) == "discharged"


def test_site_judgment_indeterminate_on_degraded_site_file() -> None:
    record = _record("v1", degradations=[{"path": "src/app.py", "reason": "parse_failed"}])
    assert site_judgment(record, path=SITE[0], start=SITE[1], end=SITE[2]) == "indeterminate"


def test_locate_function_by_name() -> None:
    functions = [("helper", 1, 10, "function"), ("target", 30, 40, "function")]
    assert locate_function(functions, name="target") == (30, 40)
    assert locate_function(functions, name="absent") is None


def test_fixed_side_change_swaps_revisions() -> None:
    change = {
        "id": "case-1",
        "base": "fixcommit",
        "head": "vulnparent",
        "files": [{"path": "src/app.py", "head_lines": [[30, 40]]}],
        "kind": "vulnerability",
    }
    fixed = fixed_side_change(change, fixed_lines=(31, 42), fixed_operation="located")
    assert fixed["head"] == "fixcommit"
    assert fixed["base"] == "vulnparent"
    assert fixed["files"] == [{"path": "src/app.py", "head_lines": [[31, 42]]}]
    assert fixed["kind"] == "vulnerability"
    assert fixed["fixed_lines"] == [31, 42]


def test_classify_fixed_site_missed_vs_removed() -> None:
    # const-arrow / getter / moved-import: name present, locator failed.
    assert classify_fixed_site(None, name_in_text=True) == "missed"
    assert classify_fixed_site(None, name_in_text=False) == "removed"
    assert classify_fixed_site((31, 42), name_in_text=True) == "located"


def test_pair_case_correct_uses_site_judgments_and_sums_seconds() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)], seconds=2.0, family="access_control")
    fixed = _record(
        "case-1",
        kind="vulnerability",
        fixed_lines=(31, 42),
        traces=[_trace("src/app.py", 33, "discharged")],
        seconds=3.0,
    )
    cases = admission_pair_cases((vulnerable,), (fixed,))
    assert len(cases) == 1
    assert cases[0].case_id == "case-1"
    assert cases[0].vulnerable_judgment == "unguarded"
    assert cases[0].fixed_judgment == "discharged"
    assert cases[0].location_verified is True
    assert cases[0].seconds == 5.0


def test_pair_case_wrong_family_is_not_location_verified() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35, family="output_encoding")])
    fixed = _record("case-1", fixed_lines=(31, 42))
    cases = admission_pair_cases((vulnerable,), (fixed,))
    assert cases[0].vulnerable_judgment == "unguarded"
    assert cases[0].location_verified is False


def test_removed_fixed_operation_is_quiet() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)])
    fixed = _record("case-1", fixed_operation="removed")
    cases = admission_pair_cases((vulnerable,), (fixed,))
    assert cases[0].fixed_judgment == "discharged"


def test_locator_miss_fixed_operation_is_never_clean() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)])
    fixed = _record("case-1", fixed_operation="missed")
    cases = admission_pair_cases((vulnerable,), (fixed,))
    assert cases[0].fixed_judgment == "indeterminate"


def test_unreadable_fixed_operation_is_indeterminate() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)])
    fixed = _record("case-1")
    cases = admission_pair_cases((vulnerable,), (fixed,))
    assert cases[0].fixed_judgment == "indeterminate"


def test_ordinary_change_flagged_on_any_finding() -> None:
    record = _record("ord-1", kind="ordinary", findings=[_finding("src/any.py", 5)])
    changes = admission_ordinary((record,))
    assert changes[0].judgment == "unguarded"
    assert changes[0].mislabeled_defect is False


def test_ordinary_change_quiet_and_indeterminate() -> None:
    quiet = admission_ordinary((_record("ord-1", kind="ordinary"),))[0]
    assert quiet.judgment == "discharged"
    funnel = {"judgment": {"unguarded": 0, "discharged": 0, "indeterminate": 2}}
    undecided = admission_ordinary((_record("ord-2", kind="ordinary", stage_funnel=funnel),))[0]
    assert undecided.judgment == "indeterminate"


def test_coverage_share_over_repositories() -> None:
    covered = _record("a", repo="repo-a", stage_funnel={"entry_recognition": {"frameworks_recognised": {"jenkins": 1}}})
    bare = _record("b", repo="repo-b", stage_funnel={"entry_recognition": {"frameworks_recognised": {}}})
    other = _record("a", repo="repo-a", stage_funnel={"entry_recognition": {"frameworks_recognised": {"jenkins": 2}}})
    assert coverage_share((covered, bare, other)) == 0.5
