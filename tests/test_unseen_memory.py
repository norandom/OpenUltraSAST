"""Offline memory and semantic regression checks using synthetic identities only."""

import importlib
import json
import sys
import tracemalloc
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
d = importlib.import_module("benchmarks.unseen.draft")
s = importlib.import_module("benchmarks.unseen.source")
j = importlib.import_module("benchmarks.unseen.journal")
storage = importlib.import_module("benchmarks.unseen.storage")


def advisory(index):
    return {
        "ghsa_id": f"GHSA-test-{index:08d}",
        "published_at": "2026-06-02T00:00:00Z" if index % 3 else "2025-01-01T00:00:00Z",
        "type": "reviewed",
        "withdrawn_at": None,
        "description": "An affected handler accepts untrusted input. " * 400,
        "cwes": [{"cwe_id": "CWE-89", "name": "SQL injection"}],
        "references": [
            {"url": f"https://github.com/fixture/project{index}/commit/{index:040x}"},
            *[{"url": f"https://example.invalid/details/{n}"} for n in range(30)],
        ],
        "vulnerabilities": [
            {
                "package": {"ecosystem": s.ECOSYSTEMS[index % 4], "name": f"package-{n}"},
                "vulnerable_version_range": ", ".join(f">= {v}.0, < {v}.9" for v in range(50)),
                "first_patched_version": "50.0",
            }
            for n in range(8)
        ],
    }


class OfflineAPI:
    def advisory_page(self, page):
        pytest.fail("A complete journal must not fetch advisories")

    def get_repo(self, name):
        return {"full_name": name}


def test_replay_20000_advisories_has_bounded_peak_memory(tmp_path):
    path = tmp_path / "journal"
    path.mkdir()
    (path / "inputs.json").write_text('{"seed": 19}')
    journal_file = path / "advisories.jsonl"
    # Write old, unprojected REST pages without ever building the entire fixture in RAM.
    with journal_file.open("w") as handle:
        for page in range(200):
            json.dump(
                {
                    "id": str(page + 1),
                    "value": {"rows": [advisory(i) for i in range(page * 100, (page + 1) * 100)], "done": page == 199},
                    "elapsed_seconds": page,
                    "rate_limit": {"remaining": "10"},
                },
                handle,
            )
            handle.write("\n")
    with journal_file.open("rb") as handle:
        first_line = handle.readline()
        assert len(json.loads(first_line)["value"]["rows"]) == 100
        assert len(first_line) > 2 * 1024 * 1024
    del first_line
    input_bytes = journal_file.stat().st_size
    assert input_bytes > 400 * 1024 * 1024
    print(f"journal_bytes_read={input_bytes}")
    tracemalloc.start()
    try:
        with j.Journal(path).open({"seed": 19}) as journal:
            assert len(journal.rows["advisories"]) == 200
            assert journal.elapsed_before == 199
            rows = d.enumerate_advisories(OfflineAPI(), journal)
            assert len(rows) == 20_000
            index = d.advisory_index(rows, OfflineAPI(), db=journal.db)
            assert index.get("fixture/project19999") == {f"{19999:040x}"}
            count = 0
            for row in s.ordered_advisories(rows, 19):
                assert "description" not in row
                assert all(set(v) == {"package"} for v in row["vulnerabilities"])
                count += 1
            assert count == 20_000
            assert journal.last == {"stage": "advisories", "id": "200"}
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    print(f"replay_enumeration_order_index_peak_bytes={peak}")
    assert peak < 64 * 1024 * 1024
    assert not list(path.glob("sourcing-*"))


def test_disk_order_matches_original_seeded_order_and_duplicate_last_wins(tmp_path):
    raw = [advisory(i) for i in range(93)]
    raw[0]["vulnerabilities"] = [{"package": {"ecosystem": "other", "name": "fixture"}}]
    # One advisory lists multiple ecosystems; retain the original ecosystem priority.
    raw[1]["vulnerabilities"].append({"package": {"ecosystem": "pip", "name": "extra"}})
    expected = [s.compact_advisory(row) for row in raw]
    with storage.working_store(tmp_path) as db:
        rows = storage.AdvisoryRows(db, "advisories")
        for row in reversed(expected):
            rows[row["ghsa_id"]] = row
        rows[expected[2]["ghsa_id"]] = expected[2]
        assert len(rows) == len(expected)
        assert list(s.ordered_advisories(rows, 17)) == s.ordered_advisories(expected, 17)


def test_compaction_preserves_candidate_and_all_fix_links():
    fixtures = importlib.import_module("test_unseen_source")
    row = fixtures.advisory()
    assert s.candidate(s.compact_advisory(row), fixtures.API(), fixtures.OSV()) == s.candidate(row, fixtures.API(), fixtures.OSV())
    row["references"] += [
        "https://github.com/fixture/old/commit/ABCDEF1#diff",
        {"url": "https://github.com/fixture/other/commit/" + "b" * 40},
    ]
    assert s.fix_links(s.compact_advisory(row)) == s.fix_links(row)
    repo = {
        "full_name": "fixture/new",
        "private": False,
        "size": 10,
        "clone_url": "https://github.com/fixture/new",
        "source": {"full_name": "fixture/source", "description": "large"},
        "parent": {"full_name": "fixture/parent", "description": "large"},
        "former_names": ["fixture/old"],
    }
    eligibility = importlib.import_module("benchmarks.unseen.eligibility")

    class API:
        def __init__(self, data):
            self.data = data

        def get_repo(self, name):
            return self.data

    assert eligibility.resolve("fixture/old", API(repo)) == eligibility.resolve("fixture/old", API(s.compact_repository(repo)))


def test_legacy_journal_migration_keeps_payload_and_refuses_changed_parameters(tmp_path):
    fixtures = importlib.import_module("test_unseen_draft")
    used = fixtures.e.UsedSet()
    parameters = d.inputs(used, 19, set(used.sources), fixtures.FakeClones())
    legacy = d.legacy_inputs(parameters)
    path = tmp_path / "journal"
    with j.Journal(path).open(legacy) as journal:
        journal.put("advisories", "1", {"rows": [advisory(1)], "done": True})
    original = (path / "advisories.jsonl").read_bytes()
    for changed in ({**parameters, "seed": 20}, {**parameters, "design_taxonomy": "different"}):
        with pytest.raises(j.ResumeMismatch), j.Journal(path).open(changed, compatible_parameters=d.legacy_inputs(changed)):
            pass
    with j.Journal(path).open(parameters, compatible_parameters=legacy) as journal:
        assert journal.rows["advisories"]["1"]["rows"][0]["ghsa_id"] == advisory(1)["ghsa_id"]
    assert json.loads((path / "inputs.json").read_text()) == parameters
    assert json.loads((path / "inputs-before-memory-fix.json").read_text()) == legacy
    assert (path / "advisories.jsonl").read_bytes() == original


def test_replay_duplicate_torn_and_oversized_records_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "journal"
    with j.Journal(path).open({}) as journal:
        journal.put("advisories", "1", {"rows": [], "done": True})
    record = (path / "advisories.jsonl").read_bytes()
    for data, reason in ((record * 2, "duplicate_unit"), (record[:-1], "incomplete_record")):
        (path / "advisories.jsonl").write_bytes(data)
        with pytest.raises(ValueError, match=reason), j.Journal(path).open({}):
            pass
        assert not list(path.glob("sourcing-*"))
    monkeypatch.setattr(j, "MAX_RECORD_BYTES", 16)
    (path / "advisories.jsonl").write_bytes(record)
    with pytest.raises(ValueError, match="record_size_cap"), j.Journal(path).open({}):
        pass


def test_ordinary_sampling_streams_payloads_and_preserves_frozen_draw():
    fixtures = importlib.import_module("test_unseen_extract")
    extract = fixtures.e
    rows = [fixtures.ordinary(i) for i in range(120)]
    for i, row in enumerate(rows):
        row["files"][0]["added"] = [5, 20, 100, 500][i % 4]
    # Captured from the pre-memory-fix implementation, not a second copy of its algorithm.
    drawn, counts = extract.draw_ordinary(iter(rows), set(), set(), seed=19)
    assert [int(row["head"], 16) for row in drawn] == [0, 33, 6, 35, 52, 65, 62, 75, 96, 117, 90, 119]
    assert counts == {"eligible": 120}

    def history():
        for i in range(20_000):
            row = fixtures.ordinary(i)
            row["message"] = "ordinary change " * 1500
            yield row

    tracemalloc.start()
    try:
        drawn, counts = extract.draw_ordinary(history(), set(), set(), seed=19)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert counts == {"eligible": 20_000}
    assert len(drawn) == 12
    assert peak < 16 * 1024 * 1024


def test_git_spools_large_output_and_refuses_large_blob_before_reading(tmp_path):
    import subprocess

    extract = importlib.import_module("benchmarks.unseen.extract")

    def runner(argv, **kwargs):
        assert kwargs["stdout"] != subprocess.PIPE
        assert kwargs["stderr"] != subprocess.PIPE
        for _ in range(9):
            kwargs["stdout"].write(b"x" * 1024 * 1024)
        return subprocess.CompletedProcess(argv, 0)

    with pytest.raises(extract.InstrumentFailure, match="git_output_size_cap"):
        extract.Git(tmp_path, runner=runner).run("log")
    calls = []
    git = extract.Git(tmp_path)

    def run(*args):
        calls.append(args[0])
        return "app.py" if args[0] == "ls-tree" else str(512 * 1024 + 1)

    git.run = run
    with pytest.raises(extract.InstrumentFailure, match="source_blob_size_cap"):
        git.blob("a" * 40, "app.py")
    assert calls == ["ls-tree", "cat-file"]
    assert git.bytes_read == git.files_read == 0


def test_repository_cache_is_bounded_and_drops_payloads():
    class Transport:
        def get(self, url, headers):
            return {"full_name": url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1], "description": "large" * 1000}

    github = s.GitHub("offline", transport=Transport())
    for i in range(200):
        github.get_repo(f"fixture/project{i}")
    assert len(github.repos) == 128
    assert all("description" not in row for row in github.repos.values())
