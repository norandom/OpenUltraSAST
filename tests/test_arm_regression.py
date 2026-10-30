"""Task 13.3 -- four-arm development regression (Reqs 5.1-5.7, 6.1, 7.3, 11.8, 12.9).

The regression runner proves nonzero input reads, writes resumable per-change
records with bundle digests, adapts the immutable 2026-10-28 baseline records
honestly (binary vocabulary marker), registers input-identical cross arms only
on digest proof, masks repository identities in shared summaries, and never
makes an admission claim.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import arm_regression  # noqa: E402


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler(event):\n    return event\n")
    (repo / "ruleset").mkdir()
    (repo / "ruleset" / "facts.toml").write_text("[entry]\nids = ['a']\n")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "first")
    return repo


def _change(repo: Path) -> dict[str, object]:
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return {
        "id": "sample-repo-ordinary-abc",
        "case_id": "sample-repo-ordinary-abc",
        "repo": "sample/repo",
        "kind": "ordinary",
        "base": head,
        "head": head,
        "method": "first_parent",
        "files": [{"path": "app.py", "head_lines": [[1, 2]]}],
    }


def _bundle() -> arm_regression.BundleDigests:
    return arm_regression.BundleDigests(
        analyzer_revision="f" * 12,
        fact_set_digest="a" * 12,
        acquisition_record_digest="none",
        configuration_digest="c" * 12,
    )


def test_fact_manifest_ref_matches_clean_disk(sample_repo: Path) -> None:
    manifest = arm_regression.fact_manifest_disk(sample_repo / "ruleset")
    assert manifest == arm_regression.fact_manifest_ref(sample_repo, "HEAD", "ruleset")


def test_fact_manifest_detects_disk_drift(sample_repo: Path) -> None:
    before = arm_regression.fact_manifest_ref(sample_repo, "HEAD", "ruleset")
    (sample_repo / "ruleset" / "facts.toml").write_text("[entry]\nids = ['a', 'b']\n")
    _git(sample_repo, "add", ".")
    _git(sample_repo, "commit", "-qm", "drift")
    assert arm_regression.manifest_digest(before) != arm_regression.manifest_digest(
        arm_regression.fact_manifest_ref(sample_repo, "HEAD", "ruleset")
    )


def test_fact_identity_alias_requires_equal_digests() -> None:
    left = {"src/ruleset/a.toml": "0" * 64}
    right = {"src/ruleset/a.toml": "0" * 64}
    alias = arm_regression.fact_identity(left, right)
    assert alias["identical"] is True
    with pytest.raises(arm_regression.FactIdentityMismatch):
        arm_regression.fact_identity(left, {"src/ruleset/a.toml": "1" * 64})


def test_adapt_baseline_record_maps_binary_vocabulary() -> None:
    record = {
        "case_id": "c1",
        "repo": "a/b",
        "kind": "ordinary",
        "findings": [{"id": "f1"}, {"id": "f2"}],
        "coverage": {"entry_points": 5, "operations_checked": 4, "operations_discharged": 1},
        "seconds": 3.5,
        "instrument": {"hook_bytes_read": 100},
    }
    adapted = arm_regression.adapt_baseline_record(record)
    judgment = adapted["stage_funnel"]["judgment"]
    assert judgment == {"unguarded": 2, "discharged": 1, "indeterminate": 0}
    assert adapted["vocabulary"] == "binary"
    assert adapted["seconds"] == 3.5


def test_adapt_baseline_record_refuses_incomplete_record() -> None:
    with pytest.raises(ValueError):
        arm_regression.adapt_baseline_record({"case_id": "c1", "coverage": {}})


def test_run_arm_writes_resumable_record_with_digests(sample_repo: Path, tmp_path: Path) -> None:
    change = _change(sample_repo)
    out = tmp_path / "arm"
    records = arm_regression.run_arm(
        arm_name="candidate-analyzer/candidate-facts",
        bundle=_bundle(),
        changes=(change,),
        repos={"sample/repo": str(sample_repo)},
        out_dir=out,
    )
    assert len(records) == 1
    record = records[0]
    assert record["fact_set_digest"] == "a" * 12
    assert record["analyzer_revision"] == "f" * 12
    assert record["instrument"]["hook_bytes_read"] > 0
    assert record["instrument"]["base_verified"] is True
    assert record["instrument"]["hook_exit"] == 0
    assert isinstance(record["push"], dict)
    assert record["push"]["admission"]["defects"] == []
    assert record["method"] == "first_parent"
    assert (out / "sample-repo-ordinary-abc.json").is_file()
    first_mtime = (out / "sample-repo-ordinary-abc.json").stat().st_mtime_ns
    arm_regression.run_arm(
        arm_name="candidate-analyzer/candidate-facts",
        bundle=_bundle(),
        changes=(change,),
        repos={"sample/repo": str(sample_repo)},
        out_dir=out,
    )
    assert (out / "sample-repo-ordinary-abc.json").stat().st_mtime_ns == first_mtime


def test_run_arm_allows_legitimately_empty_tracked_file(sample_repo: Path, tmp_path: Path) -> None:
    (sample_repo / "empty.py").write_text("")
    (sample_repo / "app.py").write_text("def handler(event):\n    return 2\n")
    _git(sample_repo, "add", ".")
    _git(sample_repo, "commit", "-qm", "empty sibling")
    change = _change(sample_repo)
    change["files"] = [
        {"path": "app.py", "head_lines": [[1, 2]]},
        {"path": "empty.py", "head_lines": [[1, 1]]},
    ]
    records = arm_regression.run_arm(
        arm_name="candidate-analyzer/candidate-facts",
        bundle=_bundle(),
        changes=(change,),
        repos={"sample/repo": str(sample_repo)},
        out_dir=tmp_path / "arm",
    )
    assert records[0]["status"] == "prover_covered"
    assert records[0]["instrument"]["empty_files"] == 1
    assert records[0]["instrument"]["file_bytes"]["app.py"] > 0


def test_summarize_arm_refuses_zero_byte_summary(tmp_path: Path) -> None:
    record = {
        "id": "c1",
        "case_id": "c1",
        "repo": "a/b",
        "kind": "ordinary",
        "status": "instrument_failure",
        "instrument": {"file_bytes": {"app.py": 0}, "hook_bytes_read": 0},
        "stage_funnel": {"judgment": {"unguarded": 0, "discharged": 0, "indeterminate": 0}},
        "seconds": 1.0,
    }
    (tmp_path / "c1.json").write_text(json.dumps(record))
    with pytest.raises(arm_regression.InstrumentFailure):
        arm_regression.summarize_arm((record,))


def test_summarize_arm_publishes_budget_result_and_masks_repositories() -> None:
    base = {
        "id": "c1",
        "case_id": "c1",
        "repo": "private/name",
        "kind": "ordinary",
        "status": "prover_covered",
        "instrument": {"file_bytes": {"app.py": 10}, "hook_bytes_read": 10},
        "stage_funnel": {
            "entry_recognition": {"entry_points": 1, "frameworks_recognised": {"web": 1}},
            "resolution": {"resolved": 1},
            "judgment": {"unguarded": 0, "discharged": 1, "indeterminate": 0},
        },
        "seconds": 121.0,
        "fact_set_digest": "a" * 12,
        "analyzer_revision": "f" * 12,
    }
    summary = arm_regression.summarize_arm((base,))
    assert summary["budget"]["gate"] == "failed"
    assert summary["budget"]["overruns"][0]["id"] == "c1"
    assert summary["budget"]["overruns"][0]["seconds"] == 121.0
    assert "private/name" not in json.dumps(summary)
    assert all(len(key) == 12 for key in summary["per_repository"])
    assert summary["population_role"] == "development"
    assert summary["development_only"] is True


def test_four_arm_development_has_no_admission_language() -> None:
    from benchmarks.valid import development_runner

    def rec(unguarded: int) -> development_runner.DevelopmentRecord:
        return development_runner.DevelopmentRecord(
            change_id="c1",
            analyzer_revision="f" * 12,
            fact_set_digest="a" * 12,
            acquisition_record_digest="none",
            configuration_digest="c" * 12,
            population_digest="d" * 12,
            input_digest="e" * 12,
            stage_funnel={"judgment": {"unguarded": unguarded, "discharged": 0, "indeterminate": 0}},
            judgment_transition="same",
            seconds=1.0,
        )

    report = arm_regression.four_arm_development(
        bab=(rec(1),),
        bacf=(rec(0),),
        cabf=(rec(0),),
        cacfon=(rec(0),),
        fact_identity={"identical": True},
    )
    text = repr(report)
    for word in ("admission", "vulnerable", "ordinary", "label"):
        assert word not in text.lower()
    assert report["fact_inputs_identical"] is True
    assert report["attribution"]["judgment_delta_analyzer_only"]["unguarded"] == -1


def test_summarize_arm_reports_uncovered_repository_separately() -> None:
    record = {
        "id": "c2",
        "case_id": "c2",
        "repo": "hidden/other",
        "kind": "vulnerability",
        "status": "prover_covered",
        "instrument": {"file_bytes": {"app.py": 10}, "hook_bytes_read": 10},
        "stage_funnel": {
            "entry_recognition": {"entry_points": 0, "frameworks_recognised": {}},
            "resolution": {},
            "judgment": {"unguarded": 0, "discharged": 0, "indeterminate": 0},
        },
        "seconds": 2.0,
        "fact_set_digest": "a" * 12,
        "analyzer_revision": "f" * 12,
    }
    summary = arm_regression.summarize_arm((record,))
    masked = list(summary["per_repository"])[0]
    assert summary["per_repository"][masked]["status"] == "uncovered"
    assert summary["uncovered_repositories"] == [masked]
