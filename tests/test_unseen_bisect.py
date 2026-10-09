"""Offline guard controls: the hidden reservation exists only inside the fake runner."""

import importlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
d = importlib.import_module("benchmarks.unseen.draft")
b = importlib.import_module("benchmarks.unseen.bisect_guard")


def draft_pair(tmp_path, count=9):
    root, cache = tmp_path / "tree", tmp_path / "cache"
    root.mkdir()
    cache.mkdir()
    rows = []
    for i in range(count):
        changes = [{"kind": "vulnerability", "method": "introducing", "base": "a" * 40, "head": "b" * 40}]
        changes[0]["label_check"] = ("confirmed", "refactor", "unclear")[i % 3]
        changes += [{"kind": "ordinary", "base": f"{j:040x}", "head": f"{j + 20:040x}"} for j in range(12)]
        rows.append(
            {
                "repository": f"synthetic/candidate-{i}",
                "url": "https://" + f"github.com/synthetic/candidate-{i}",
                "license_class": "private" if i % 2 else "permissive",
                "license_spdx": "GPL-3.0" if i % 2 else "MIT",
                "slice": i % 3 + 1,
                "changes": changes,
            }
        )
        rows[-1]["id"] = "r-" + d.private_digest(rows[-1])[:24]
    public, private = [], []
    for row in rows:
        if row["license_class"] == "private":
            private.append(row)
            public.append({"id": row["id"], "slice": row["slice"], "private": True, "sha256": d.private_digest(row)})
        else:
            public.append(row)
    draft = cache / "draft-p1.toml"
    draft.write_text(d.manifest(public, 19))
    (cache / "private-draft-p1.toml").write_text(d.manifest(private, 19))
    return root, draft, rows


def staged(root):
    directory = root / "benchmarks/unseen"
    public = tomllib.loads((directory / "draft-p1.toml").read_text())
    private = tomllib.loads((directory / "private/draft-p1.toml").read_text())
    hidden = {row["id"]: row for row in private.get("repository", [])}
    rows = [hidden[row["id"]] if row.get("private") else row for row in public.get("repository", [])]
    assert set(hidden) == {row["id"] for row in public.get("repository", []) if row.get("private")}
    return rows


@pytest.mark.parametrize("members", [(), (0,), (1, 4, 7), tuple(range(9))])
def test_bisects_hidden_members_only(tmp_path, capsys, caplog, members):
    root, draft, rows = draft_pair(tmp_path)
    original = draft.read_bytes()
    reserved = {rows[i]["repository"] for i in members}
    calls = []

    def guard(root):
        names = {row["repository"] for row in staged(root)}
        calls.append(names)
        return int(bool(names & reserved))

    result = b.run(root, draft, guard_runner=guard)
    assert result["dropped_count"] == len(members)
    assert result["guard_result"] == 0
    assert {r["repository"] for r in staged(root)} == {r["repository"] for r in rows} - reserved
    assert calls[0] == set() and not (calls[-1] & reserved)
    assert draft.read_bytes() == original
    assert capsys.readouterr() == ("", "") and not caplog.records
    receipt = (root / "benchmarks/unseen/bisect-p1.json").read_text()
    for row in rows:
        assert row["repository"] not in receipt and row["url"] not in receipt
    assert json.loads(receipt) == result


@pytest.mark.parametrize("code", [-9, 2, 3, 4, 5, 127])
def test_unknown_exit_aborts_and_removes_staging(tmp_path, code):
    root, draft, _ = draft_pair(tmp_path)
    calls = 0

    def guard(root):
        nonlocal calls
        calls += 1
        return 0 if calls == 1 else code

    with pytest.raises(b.InstrumentFailure, match="guard_exit"):
        b.run(root, draft, guard_runner=guard)
    assert not list((root / "benchmarks/unseen").rglob("*.toml"))
    assert not (root / "benchmarks/unseen/bisect-p1.json").exists()


def test_red_empty_baseline_is_not_candidate_rejection(tmp_path):
    root, draft, _ = draft_pair(tmp_path)
    with pytest.raises(b.InstrumentFailure, match="guard_baseline"):
        b.run(root, draft, guard_runner=lambda root: 1)


def test_final_combination_is_checked(tmp_path):
    root, draft, _ = draft_pair(tmp_path)
    codes = iter([0, 0, 1])
    with pytest.raises(b.InstrumentFailure, match="guard_final"):
        b.run(root, draft, guard_runner=lambda root: next(codes))


def test_guard_subprocess_is_exact_and_discards_both_streams(tmp_path, monkeypatch):
    calls = []

    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(b.subprocess, "run", fake)
    assert b.pytest_guard(tmp_path) == 1
    argv, kwargs = calls[0]
    assert argv == [".venv/bin/pytest", "-q", "-p", "no:cacheprovider", "tests/test_independent_population.py", "-k", "referenced"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL


def test_existing_staging_is_never_overwritten(tmp_path):
    root, draft, _ = draft_pair(tmp_path)
    path = root / "benchmarks/unseen/draft-p1.toml"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        b.run(root, draft, guard_runner=lambda root: pytest.fail("guard should not run"))
    assert path.read_bytes() == b"preserve"


def test_cli_outputs_dropped_count_only(tmp_path, monkeypatch, capsys):
    root, draft, _ = draft_pair(tmp_path)
    monkeypatch.setattr(b, "pytest_guard", lambda root: 0)
    assert b.main(["--root", str(root), "--draft", str(draft)]) == 0
    assert json.loads(capsys.readouterr().out) == {"dropped_count": 0}


def test_cli_failure_does_not_echo_exception(tmp_path, monkeypatch, capsys):
    root, draft, rows = draft_pair(tmp_path)

    def guard(root):
        raise OSError(rows[0]["url"])

    monkeypatch.setattr(b, "pytest_guard", guard)
    assert b.main(["--root", str(root), "--draft", str(draft)]) == 1
    assert capsys.readouterr() == ('{"status": "instrument_failure"}\n', "")


@pytest.mark.parametrize("problem", ["empty_file", "empty_pool", "missing_private", "bad_pointer", "private_in_public"])
def test_invalid_draft_never_runs_guard(tmp_path, problem):
    root, draft, rows = draft_pair(tmp_path)
    private = draft.with_name("private-draft-p1.toml")
    if problem == "empty_file":
        draft.write_bytes(b"")
    elif problem == "empty_pool":
        draft.write_text(d.manifest([], 19))
        private.write_text(d.manifest([], 19))
    elif problem == "missing_private":
        private.unlink()
    elif problem == "bad_pointer":
        data = tomllib.loads(draft.read_text())
        data["repository"][1]["sha256"] = "0" * 64
        draft.write_text(d.manifest(data["repository"], 19))
    else:
        draft.write_text(d.manifest(rows, 19))
    with pytest.raises(b.InstrumentFailure):
        b.run(root, draft, guard_runner=lambda root: pytest.fail("guard should not run"))
    assert not (root / "benchmarks/unseen/draft-p1.toml").exists()


def test_interrupt_removes_partial_subset(tmp_path):
    root, draft, _ = draft_pair(tmp_path)
    calls = 0

    def guard(root):
        nonlocal calls
        calls += 1
        if calls > 2:
            raise KeyboardInterrupt
        return 0 if calls == 1 else 1

    with pytest.raises(KeyboardInterrupt):
        b.run(root, draft, guard_runner=guard)
    assert not list((root / "benchmarks/unseen").rglob("*.toml"))
