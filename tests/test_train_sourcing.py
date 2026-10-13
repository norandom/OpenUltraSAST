"""Offline tests for family-specific training sources."""

import importlib
import json
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sourcing = importlib.import_module("benchmarks.valid.train.sourcing")
source = importlib.import_module("benchmarks.unseen.source")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network or subprocess call")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.fixture
def environment(tmp_path, monkeypatch):
    root = tmp_path / "root"
    here = root / "benchmarks/valid/train"
    work = tmp_path / "work"
    pilot = root / "benchmarks/pilot"
    dumps = tmp_path / "dumps"
    for directory in (here, work, pilot, dumps):
        directory.mkdir(parents=True)
    for name, value in (("ROOT", root), ("HERE", here), ("WORK", work), ("PILOT", pilot)):
        monkeypatch.setattr(sourcing, name, value)
    (work / "used_strict.json").write_text(json.dumps(["fixture/used"]))
    (pilot / "accepted_repos.json").write_text("[]")
    (here / "sources.json").write_text('[{"repository": "fixture/earlier"}]\n')
    (work / "sources.json").write_text("[]\n")

    def record(name, cwes):
        return {
            "id": f"GHSA-{name}",
            "published": "2025-01-01T00:00:00Z",
            "database_specific": {"github_reviewed": True, "cwe_ids": cwes},
            "affected": [{"package": {"ecosystem": "PyPI", "name": name}}],
            "references": [{"url": f"https://github.com/fixture/{name}/commit/" + "a" * 40}],
        }

    records = [record("allowed", ["CWE-862"]), record("injection", ["CWE-89"]), record("no-cwe", []), record("used", ["CWE-862"])]

    def write_dumps(rows):
        for ecosystem in sourcing.OSV_ECOSYSTEMS:
            with zipfile.ZipFile(dumps / f"{ecosystem}.zip", "w") as archive:
                for row in rows if ecosystem == "PyPI" else []:
                    archive.writestr(row["id"] + ".json", json.dumps(row))

    write_dumps(records)
    return here, work, pilot, dumps, records, record, write_dumps


@pytest.fixture
def github(monkeypatch):
    class GitHub:
        calls = 0
        repositories = []

        def __init__(self, token):
            assert token == "fixture-token"

        def get_repo(self, name):
            self.calls += 1
            self.repositories.append(name)
            return {"private": False, "size": 100, "clone_url": f"https://github.com/{name}.git", "full_name": name}

        def get_commit(self, name, sha):
            self.calls += 1
            return {"sha": sha, "parents": [{"sha": "b" * 40}]}

        def get_license(self, name, ref):
            self.calls += 1
            return {"spdx_id": "MIT", "path": "LICENSE"}

    def token(argv, **kwargs):
        assert argv == ["gh", "auth", "token"]
        return subprocess.CompletedProcess(argv, 0, stdout="fixture-token\n")

    monkeypatch.setattr(subprocess, "run", token)
    monkeypatch.setattr(source, "GitHub", GitHub)
    return GitHub


def run_sources(dumps, *extra):
    return sourcing.main(["sources", "--family", "access_control", "--osv-dir", str(dumps), *extra])


def test_family_filters_zip_and_preserves_sources(environment, github, capsys):
    here, work, _, dumps, *_ = environment
    original = (here / "sources.json").read_bytes()
    work_original = (work / "sources.json").read_bytes()
    assert run_sources(dumps) == 0
    rows = json.loads((here / "sources_access_control.json").read_text())
    assert [(row["repository"], row["family"], row["cwe"]) for row in rows] == [("fixture/allowed", "access_control", "CWE-862")]
    assert github.repositories == ["fixture/allowed"]
    assert (here / "sources.json").read_bytes() == original
    assert (work / "sources.json").read_bytes() == work_original
    counts = json.loads((here / "sources_access_control_log.json").read_text())
    assert counts["osv:pip:ghsa_records"] == 4
    assert counts["osv:pip:prefilter_pass"] == counts["accepted"] == 1
    assert counts["osv:pip:family"] == counts["osv:pip:family_mismatch"] == counts["osv:pip:excluded_named_elsewhere"] == 1
    assert counts["target"] == 120
    assert counts["github_api_calls"] == 3
    output = capsys.readouterr().out
    assert "bytes" in output and '"osv:pip:ghsa_records": 4' in output


def test_unknown_family_fails_before_io(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        sourcing.main(["sources", "--family", "not-a-family", "--osv-dir", str(tmp_path)])
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_prefilter_only_never_accepts_or_calls_github(environment, capsys):
    here, _, _, dumps, *_ = environment
    assert run_sources(dumps, "--prefilter-only", "--target", "120") == 0
    assert json.loads((here / "sources_access_control.json").read_text()) == []
    counts = json.loads((here / "sources_access_control_log.json").read_text())
    assert counts["osv:pip:prefilter_pass"] == 1
    assert counts["accepted"] == counts["github_api_calls"] == counts["osv_api_calls"] == counts["github_checks_run"] == 0
    assert "GitHub checks did not run" in capsys.readouterr().out


def test_all_exclusions_apply_before_github(environment, github):
    here, work, pilot, dumps, records, record, write_dumps = environment
    (pilot / "accepted_repos.json").write_text('["FIXTURE/Held-out"]')
    (pilot / "named.md").write_text("https://github.com/fixture/named\n")
    (work / "sources.json").write_text('[{"repository": "fixture/work-source"}]')
    (work / "sources_batch1.json").write_text('[{"repository": "FIXTURE/Batch"}]')
    (work / "sources_batch1_log.json").write_text('{"accepted": 1}')
    records += [record(name, ["CWE-862"]) for name in ("held-out", "named", "earlier", "work-source", "batch")]
    records.append(record("mixed", ["CWE-862", "CWE-89"]))
    write_dumps(records)
    assert run_sources(dumps) == 0
    assert github.repositories == ["fixture/allowed"]
    counts = json.loads((here / "sources_access_control_log.json").read_text())
    assert counts["osv:pip:excluded_pilot"] == 1
    assert counts["osv:pip:excluded_named_elsewhere"] == 2
    assert counts["osv:pip:excluded_already_sourced"] == 3
    assert counts["osv:pip:family"] == 2


def test_target_counts_accepts_after_github_rejection(environment, github, monkeypatch):
    here, _, _, dumps, records, record, write_dumps = environment
    records.extend(record(f"extra-{i}", ["CWE-862"]) for i in range(3))
    write_dumps(records)
    attempts = []

    def license_record(self, name, ref):
        attempts.append(name)
        return {"spdx_id": "NONE" if len(attempts) == 1 else "MIT", "path": "LICENSE"}

    monkeypatch.setattr(github, "get_license", license_record)
    assert run_sources(dumps, "--target", "2") == 0
    assert len(attempts) == 3
    counts = json.loads((here / "sources_access_control_log.json").read_text())
    assert counts["accepted"] == counts["target"] == 2
    assert counts["osv:check:licence_not_permissive"] == 1


def test_family_overlap_and_merge_keep_batches_separate(environment):
    here, work, _, _, *_ = environment
    original = (here / "sources.json").read_bytes()
    batch = [{"repository": "fixture/new", "advisory": "GHSA-new", "origin": "osv", "family": "access_control"}]
    (work / "new.json").write_text(json.dumps(batch))
    assert sourcing.main(["overlap", "--family", "access_control", "new.json"]) == 0
    assert json.loads((here / "sources_access_control.json").read_text()) == batch
    (work / "named_elsewhere.json").write_text("{}")
    (work / "catalog.toml").write_text("case = []\n")
    (work / "verification.json").write_text('{"cases": []}')
    (here / "catalog.toml").write_text("original catalog")
    (here / "verification.json").write_text("original verification")
    assert sourcing.main(["merge", "--family", "access_control", "--catalogs", "catalog.toml", "--verifications", "verification.json"]) == 0
    assert (here / "catalog_access_control.toml").is_file()
    assert (here / "verification_access_control.json").is_file()
    assert (here / "sources.json").read_bytes() == original
    assert (here / "catalog.toml").read_text() == "original catalog"
    assert (here / "verification.json").read_text() == "original verification"
