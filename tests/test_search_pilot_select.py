"""Offline pilot selection: synthetic repositories only."""

import json
from pathlib import Path

import pytest

with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    from benchmarks.search import pilot_select as pilot


def pair(i, language="python", family="injection", **extra):
    return {
        "repo": f"https://github.com/synthetic/project-{i}",
        "parent": "a" * 40,
        "commit": "b" * 40,
        "language": language,
        "family": family,
        "split": "train",
        "path": "src/main.py",
        "expected": [{"function": "handler"}],
        **extra,
    }


def test_balanced_unique_deterministic_selection():
    rows = [pair(f"{lang}-{i}", lang, pilot.FAMILIES[i % 4]) for lang in pilot.LANGUAGES for i in range(8)]
    candidates, rejected = pilot.candidates(rows, set())
    selected = pilot.select(candidates, seed=17)
    assert len(selected) == len({r["repo"] for r in selected}) == 20
    assert all(sum(r["language"] == lang for r in selected) >= 3 for lang in pilot.LANGUAGES)
    assert set(r["family"] for r in selected) == set(pilot.FAMILIES)
    assert selected == pilot.select(list(reversed(candidates)), seed=17)
    assert selected != pilot.select(candidates, seed=18)
    assert not rejected


def test_filter_non_development_bad_commits_families_and_used():
    rows = [
        pair(1),
        pair(2, split="holdout"),
        pair(3, family="access_control"),
        pair(4, parent="b" * 40),
        pair(5),
        pair(6, parent="bad"),
        pair(7, repo="http://github.com/synthetic/no"),
    ]
    selected, rejected = pilot.candidates(rows, {"synthetic/project-5"})
    assert len(selected) == 1
    assert sum(rejected.values()) == 6


def test_prefer_evidenced_test_suite_and_manifest_and_unique_repos():
    rows = [pair(1), pair(2, files=["pyproject.toml", "tests/test_main.py"]), pair(2, family="path")]
    selected = pilot.select(pilot.candidates(rows, set())[0], seed=2, count=2)
    assert selected[0]["repo"].endswith("project-2")
    assert len({row["repo"] for row in selected}) == 2
    assert selected[0]["has_tests"] and selected[0]["manifest"] == "pip"


def test_unseen_local_pool_used_and_ledger(tmp_path):
    unseen = tmp_path / "benchmarks/unseen"
    unseen.mkdir(parents=True)
    (unseen / "pool-p1.toml").write_text('[[repository]]\nrepo="https://github.com/synthetic/project-1"\n')
    (unseen / "used.json").write_text(json.dumps({"repo": "synthetic/project-2"}))
    names, report = pilot.exclusions(tmp_path)
    assert names == {"synthetic/project-1", "synthetic/project-2"}
    assert report["files"] == 2 and report["bytes"] > 0
    (unseen / "usage.jsonl").write_text('{"bad":true}\n')
    with pytest.raises(ValueError, match="broken_digest_chain"):
        pilot.exclusions(tmp_path)


def test_never_open_reserved_or_symlink_catalogs(tmp_path):
    root = tmp_path / "benchmarks/pairs"
    root.mkdir(parents=True)
    (root / "catalog.toml").write_text('[[pair]]\nrepo="synthetic/one"\n')
    hidden = root / "population-v3"
    hidden.mkdir()
    (hidden / "catalog.toml").write_bytes(b"not toml")
    (root / "alias").symlink_to(hidden, target_is_directory=True)
    rows, counts = pilot.load_catalogs(tmp_path)
    assert len(rows) == 1 and counts["files"] == 1
    assert counts["bytes"] > 0


def test_summary_contains_counts_and_digests_not_names():
    selected = pilot.select(pilot.candidates([pair(1)], set())[0], seed=1)
    summary = pilot.summary(selected, seed=1, manifest=b"private")
    assert summary["selected"] == 1 and summary["gap_to_target"] == 19
    assert "synthetic" not in json.dumps(summary)
    assert summary["unknown_test_suite"] == 1


def test_bare_used_names_and_repository_alias_fields(tmp_path):
    unseen = tmp_path / "benchmarks/unseen"
    unseen.mkdir(parents=True)
    (unseen / "used.json").write_text(json.dumps({"used": ["synthetic/project-1"]}))
    assert pilot.exclusions(tmp_path)[0] == {"synthetic/project-1"}


def test_cross_repository_and_noncanonical_urls_rejected():
    rows = [
        pair(1, fix_repo="synthetic/other"),
        pair(2, repo="https://user:secret@github.com/synthetic/project-2"),
        pair(3, repo="https://github.com/synthetic/project-3?query=1"),
        pair(4, repo="https://github.com/synthetic/project-4/extra"),
    ]
    assert not pilot.candidates(rows, set())[0]


def test_metadata_from_matching_local_checkout_only(tmp_path):
    checkout = tmp_path / "project-1"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git/config").write_text('[remote "origin"]\nurl=https://github.com/synthetic/project-1\n')
    (checkout / "pyproject.toml").write_text('[project]\nname="synthetic"\n')
    (checkout / "tests").mkdir()
    (checkout / "tests/test_main.py").write_text("def test_smoke(): assert True\n")
    rows = [pair(1), pair(2)]
    counts = pilot.enrich(rows, (tmp_path,))
    assert counts["matched_checkouts"] == 1
    selected = pilot.candidates(rows, set())[0]
    assert selected[0]["manifest"] == "pip" and selected[0]["has_tests"] is True
    assert selected[1]["manifest"] is None


def test_cache_enrichment_never_follows_reserved_paths(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    checkout = cache / "project-1"
    (checkout / ".git").mkdir(parents=True)
    reserved = tmp_path / "population-v3"
    reserved.mkdir()
    config = reserved / "config"
    config.write_text('[remote "origin"]\nurl=https://github.com/synthetic/project-1\n')
    (checkout / ".git/config").symlink_to(config)
    original = Path.read_bytes

    def guarded(path):
        if "population-v3" in path.resolve().parts:
            pytest.fail("reserved file opened")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    assert pilot.enrich([pair(1)], (cache,))["matched_checkouts"] == 0
    (checkout / ".git/config").unlink()
    (checkout / ".git/config").write_text(config.read_text())
    (checkout / "tests").symlink_to(reserved, target_is_directory=True)
    (checkout / "pyproject.toml").symlink_to(config)
    rows = [pair(1)]
    pilot.enrich(rows, (cache,))
    assert not rows[0]["files"]


def test_enrichment_skips_unseen_before_opening_cache(tmp_path, monkeypatch):
    def fail(*args):
        pytest.fail("unseen cache read")

    monkeypatch.setattr(Path, "read_bytes", fail)
    assert pilot.enrich([pair(1)], (tmp_path,), excluded={"synthetic/project-1"})["matched_checkouts"] == 0


def test_cache_enrichment_refuses_ancestor_symlinks(tmp_path, monkeypatch):
    reserved = tmp_path / "population-v3"
    checkout = reserved / "project-1"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git/config").write_text('[remote "origin"]\nurl=https://github.com/synthetic/project-1\n')
    alias = tmp_path / "alias"
    alias.symlink_to(reserved, target_is_directory=True)

    def fail(*args):
        pytest.fail("reserved ancestor opened")

    monkeypatch.setattr(Path, "read_bytes", fail)
    assert pilot.enrich([pair(1)], (alias,))["matched_checkouts"] == 0
