"""A report added later must exclude every run that used its repositories."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime

import pytest

pytest.importorskip("dspy")
pytest.importorskip("pandas")
from test_hunt_ablation import finding, write_records  # noqa: E402
from test_hunt_ablation import population as population  # noqa: E402

from openultrasast.hunt import ablation as ab  # noqa: E402
from openultrasast.hunt import contamination as ct  # noqa: E402
from openultrasast.hunt import runner  # noqa: E402


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_report_repositories_reads_all_sources_and_normalizes(tmp_path):
    pilot = tmp_path / "benchmarks/valid/pilot/pool-valid.toml"
    pilot.parent.mkdir(parents=True)
    pilot.write_text(
        '[[repository]]\nid = "Owner/Pilot-ID"\nrepository = "Owner/Pilot-Name.git"\n'
        'url = "https://github.com/Owner/Pilot-URL.git"\n'
        'advisory = "https://github.com/ignore/advisory"\nlabel = "https://github.com/ignore/label"\n'
    )
    measurements = tmp_path / "benchmarks/measurements"
    write_json(measurements / "first/accepted_repos.json", ["Owner/Accepted.git", "https://github.com/Owner/Accepted/"])
    write_json(measurements / "second/accepted_repos.json", ["Other/Accepted"])
    (measurements / "first/NOTES.md").write_text("[source](https://github.com/Owner/Noted.git/tree/main) and github.com/Other/Plain.\n")
    (measurements / "second/NOTES.md").write_text("See https://GITHUB.COM/Owner/Second#readme\n")
    write_json(measurements / "first/labels.json", {"repo": "ignore/labels"})
    assert ct.report_repositories(tmp_path) == {
        "owner/pilot-id",
        "owner/pilot-name",
        "owner/pilot-url",
        "owner/accepted",
        "other/accepted",
        "owner/noted",
        "other/plain",
        "owner/second",
    }


def record_run(path, repo="Owner/Training.git"):
    for change_id in ("first", "second"):
        write_json(runner.record_path(path, change_id), {"id": change_id, "done": True, "push": {}})
    write_json(
        path / "inputs.json",
        [
            {"item_id": change_id, "change": {"repo": repo, "label": "ignore/label", "advisory": "ignore/advisory"}}
            for change_id in ("first", "second")
        ]
        + [{"item_id": "not-run", "change": {"repo": "unused/input"}}],
    )
    return path


def test_run_becomes_contaminated_after_report_is_added(tmp_path):
    run_dir = record_run(tmp_path / "run")
    accepted = tmp_path / "benchmarks/measurements/new/accepted_repos.json"
    write_json(accepted, ["Other/Repo", "Another/Repo"])
    assert ct.run_repositories(run_dir) == {"owner/training"}
    clean = ct.check(run_dir, ct.report_repositories(tmp_path))
    assert clean["contaminated"] is False and clean["repositories"] == []
    assert json.loads((run_dir / "contamination.json").read_text()) == clean
    assert clean["reports_digest"] == hashlib.sha256(b"another/repo\nother/repo").hexdigest()
    assert datetime.fromisoformat(clean["checked_at"]).tzinfo is not None
    assert ct.clean_runs([run_dir]) == [run_dir]

    write_json(accepted, ["Other/Repo", "https://github.com/OWNER/Training.git"])
    contaminated = ct.check(run_dir, ct.report_repositories(tmp_path))
    assert contaminated["contaminated"] is True
    assert contaminated["repositories"] == ["owner/training"]
    assert contaminated["reports_digest"] != clean["reports_digest"]
    assert json.loads((run_dir / "contamination.json").read_text()) == contaminated
    assert not (run_dir / "contamination.json.partial").exists()
    assert ct.clean_runs([run_dir]) == []


def test_run_repositories_uses_direct_fields_and_study_first(tmp_path):
    write_json(tmp_path / "record.json", {"id": "change", "repo": "Owner/Direct.git"})
    write_json(tmp_path / "inputs.json", [{"item_id": "change", "change": {"repo": "unused/fallback"}}])
    assert ct.run_repositories(tmp_path) == {"owner/direct"}
    write_json(tmp_path / "study.json", {"changes": [{"id": "change", "repo": "https://github.com/Owner/Study.git"}]})
    assert ct.run_repositories(tmp_path) == {"owner/study"}


@pytest.mark.parametrize("contents", [{}, {"id": "unresolved"}])
def test_run_repositories_refuses_missing_repository(tmp_path, contents):
    write_json(tmp_path / "record.json", contents)
    with pytest.raises(ValueError, match="repository"):
        ct.check(tmp_path, set())
    assert not (tmp_path / "contamination.json").exists()


def test_run_repositories_refuses_partly_resolved_run(tmp_path):
    record_run(tmp_path)
    write_json(tmp_path / "unresolved.json", {"id": "missing"})
    with pytest.raises(ValueError, match="missing"):
        ct.run_repositories(tmp_path)


def test_mark_all_checks_records_and_studies_but_not_metadata(tmp_path):
    record_run(tmp_path / "records")
    write_json(tmp_path / "study/study.json", {"changes": [{"repo": "OWNER/Training"}]})
    write_json(tmp_path / "other/study.json", {"changes": [{"repo": "Other/Repo"}]})
    write_json(tmp_path / "metadata/artifact.json", {"artifact_id": "artifact"})
    result = ct.mark_all(tmp_path, {"owner/training"})
    assert set(result) == {"records", "study", "other"}
    assert result["records"]["contaminated"] is result["study"]["contaminated"] is True
    assert result["other"]["contaminated"] is False
    assert not (tmp_path / "metadata/contamination.json").exists()


def test_clean_runs_refuses_all_unchecked_names(tmp_path):
    clean = record_run(tmp_path / "clean")
    ct.check(clean, set())
    with pytest.raises(ValueError, match="unchecked.*first.*second"):
        ct.clean_runs([clean, tmp_path / "first", tmp_path / "second"])


@pytest.mark.parametrize("value", [None, 0, "false"])
def test_clean_runs_refuses_invalid_check(tmp_path, value):
    write_json(tmp_path / "contamination.json", {"contaminated": value})
    with pytest.raises(ValueError, match="contamination"):
        ct.clean_runs([tmp_path])


def test_ablation_preserves_analysis_but_excludes_contaminated_gain(population, tmp_path):
    _, _, changes, _, original = population
    manifest = replace(original, sample={**original.sample, "repeats": 1})
    out = tmp_path / "ablation"
    write_records(out, manifest, changes, {"full": [[finding()]] * len(changes), "without-roles": [[]] * len(changes)})
    write_json(out / "study.json", {"manifest_id": ab.manifest_id(manifest), "changes": changes})
    ct.check(out, set())
    clean = ab.analyse(out, manifest, changes)
    assert clean["contaminated"] is False and clean["contaminating_repositories"] == []
    assert not clean.get("excluded_from_gain", False)
    importance = json.loads((out / "importance.json").read_text())
    decisions = json.loads((out / "decisions.json").read_text())

    write_json(tmp_path / "benchmarks/measurements/later/accepted_repos.json", [changes[0]["repo"]])
    ct.check(out, ct.report_repositories(tmp_path))
    result = ab.analyse(out, manifest, changes)
    assert result["contaminated"] is True and result["excluded_from_gain"] is True
    assert result["contaminating_repositories"] == [changes[0]["repo"]]
    assert result["heldout"] == clean["heldout"]
    assert json.loads((out / "analysis.json").read_text())["excluded_from_gain"] is True
    assert json.loads((out / "importance.json").read_text()) == importance
    assert json.loads((out / "decisions.json").read_text()) == {**decisions, "excluded_from_gain": True}
