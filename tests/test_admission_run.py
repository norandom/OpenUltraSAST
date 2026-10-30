"""Task 13.4 admission measurement unit tests (Reqs 12.1-12.9).

The admission runner consumes a reviewed upstream manifest for the untouched
pilot population, proves both sides of every vulnerable/fixed twin and every
reviewed ordinary change, maps per-site prover evidence onto the three-way
judgment vocabulary and returns the paired admission report.
"""

import hashlib
import json
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.unseen.replay import canonical  # noqa: E402
from benchmarks.valid.admission_run import (  # noqa: E402
    admission_ordinary,
    admission_pair_cases,
    assemble_admission_report,
    classify_fixed_site,
    coverage_share,
    fixed_side_change,
    load_admission_population,
    locate_function,
    site_judgment,
)
from benchmarks.valid.admission_scoring import AdmissionScoringError  # noqa: E402
from benchmarks.valid.prover_admission import AdmissionManifest, AdmissionManifestError  # noqa: E402

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


def _manifest_payload(**over: object) -> dict[str, object]:
    payload = {
        "produced_by": "valid-detection-benchmark",
        "reviewed": True,
        "label_isolated": True,
        "spent": False,
        "population_role": "admission",
        "analyzer_revision": "d063167",
        "fact_set_digest": "3eb5bf699434",
        "acquisition_record_digest": "none",
        "configuration_digest": "be6d0f688598",
        "population_digest": "0" * 64,
        "labels": [],
    }
    payload.update(over)
    return payload


POOL_TOML = (
    'status = "frozen"\n'
    'pool = "valid"\n'
    "seed = 0\n"
    "\n"
    "[[repository]]\n"
    'id = "example/project"\n'
    'repository = "example/project"\n'
    'url = "https://github.com/example/project.git"\n'
    "slice = 1\n"
    "changes = [\n"
    '  {base = "fixcommit", head = "vulnparent", case_id = "example-project-vuln-1", '
    'id = "example-project-vuln-1", repo = "example/project", kind = "vulnerability", '
    'path = "src/app.py", function = "handler", function_lines = [30, 40], '
    'files = [{path = "src/app.py", head_lines = [[30, 40]]}], family = "access_control"},\n'
    '  {base = "parent1", head = "ordinary1", case_id = "example-project-ordinary-1", '
    'id = "example-project-ordinary-1", repo = "example/project", kind = "ordinary", '
    'files = [{path = "src/lib.py", head_lines = [[1, 5]]}]},\n'
    "]\n"
)


def _population_files(root: Path, *, freeze_digest: str | None = None, guard_result: int = 0) -> tuple[Path, Path, str]:
    root.mkdir(parents=True, exist_ok=True)
    pool_path = root / "pool.toml"
    pool_path.write_text(POOL_TOML, encoding="utf-8")
    pool = tomllib.loads(pool_path.read_text(encoding="utf-8"))
    digest = freeze_digest if freeze_digest is not None else hashlib.sha256(canonical(pool)).hexdigest()
    freeze_path = root / "freeze.json"
    freeze_path.write_text(json.dumps({"freeze_digest": digest, "guard_result": guard_result}), encoding="utf-8")
    return pool_path, freeze_path, digest


def test_load_population_verifies_freeze_digest_and_guard() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        pool_path, freeze_path, digest = _population_files(root)
        payload = _manifest_payload(population_digest=digest)
        vulnerable, ordinary = load_admission_population(payload, pool_path, freeze_path)
        assert [change["kind"] for change in (*vulnerable, *ordinary)] == ["vulnerability", "ordinary"]
        assert all(len(change["id"]) == 64 for change in (*vulnerable, *ordinary))
        tampered = _manifest_payload(population_digest="f" * 64)
        try:
            load_admission_population(tampered, pool_path, freeze_path)
            raise AssertionError("population digest mismatch must be refused")
        except ValueError as error:
            assert "population" in str(error)
        guarded = _population_files(root / "g", guard_result=1)
        payload_guarded = _manifest_payload(population_digest=guarded[2])
        try:
            load_admission_population(payload_guarded, guarded[0], guarded[1])
            raise AssertionError("held-out guard failure must be refused")
        except ValueError as error:
            assert "guard" in str(error)


def test_load_population_validates_manifest_before_labels() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        pool_path, freeze_path, _ = _population_files(root)
        spent = _manifest_payload(spent=True)
        try:
            load_admission_population(spent, pool_path, freeze_path)
            raise AssertionError("spent population must be refused")
        except AdmissionManifestError:
            pass


def _admission_manifest(digest: str = "0" * 64) -> AdmissionManifest:
    from benchmarks.valid.prover_admission import validate_admission_manifest

    return validate_admission_manifest(_manifest_payload(population_digest=digest))


def test_assemble_report_returns_go_without_failed_gates() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)], family="access_control")
    fixed = _record("case-1", fixed_lines=(31, 42), traces=[_trace("src/app.py", 33, "discharged")])
    ordinary = _record("ord-1", kind="ordinary")
    manifest = _admission_manifest()
    report = assemble_admission_report(
        manifest,
        (vulnerable,),
        (fixed,),
        (ordinary,),
        criteria={"min_fix_recall": 1.0, "max_flagged_ordinary_per_100": 0.0},
    )
    assert report["decision"] == "GO"
    assert report["fix_recall"]["count"] == 1
    assert report["pairs"] == {"n": 1, "correct": 1}
    assert report["flagged_ordinary_per_100"]["count"] == 0


def test_assemble_report_no_go_on_ordinary_overrun() -> None:
    vulnerable = _record("case-1", findings=[_finding("src/app.py", 35)])
    fixed = _record("case-1", fixed_lines=(31, 42), traces=[_trace("src/app.py", 33, "discharged")])
    slow = _record("ord-1", kind="ordinary", seconds=300.0)
    report = assemble_admission_report(_admission_manifest(), (vulnerable,), (fixed,), (slow,), criteria=None, budget_seconds=120.0)
    assert report["decision"] == "NO-GO"
    assert any(gate.startswith("budget:ord-1:") for gate in report["failed_gates"])


def test_assemble_report_no_go_on_budget_and_criteria() -> None:
    vulnerable = _record("case-1", seconds=200.0)
    fixed = _record("case-1", fixed_lines=(31, 42), seconds=1.0)
    ordinary = _record("ord-1", kind="ordinary", findings=[_finding("src/x.py", 3)])
    manifest = _admission_manifest()
    report = assemble_admission_report(
        manifest,
        (vulnerable,),
        (fixed,),
        (ordinary,),
        criteria={"min_fix_recall": 0.9, "max_flagged_ordinary_per_100": 0.0},
    )
    assert report["decision"] == "NO-GO"
    assert any(gate.startswith("budget:case-1:") for gate in report["failed_gates"])
    assert any("min_fix_recall" in gate for gate in report["failed_gates"])
    assert any("max_flagged_ordinary_per_100" in gate for gate in report["failed_gates"])


def test_assemble_report_counts_instrument_failures() -> None:
    vulnerable = _record("case-1", status="instrument_failure")
    fixed = _record("case-1", fixed_lines=(31, 42), status="instrument_failure")
    manifest = _admission_manifest()
    report = assemble_admission_report(manifest, (vulnerable,), (fixed,), (), criteria=None)
    assert report["instrument_failures"] == 2
    assert report["decision"] == "NO-GO"


def test_assemble_report_refuses_development_role() -> None:
    manifest = _admission_manifest()
    object.__setattr__(manifest, "population_role", "development")
    try:
        assemble_admission_report(manifest, (), (), (), criteria=None)
        raise AssertionError("development population must be refused for admission")
    except AdmissionScoringError:
        pass
