"""The advisory-fix pair catalog: real fixes only, read by the label builder, recorded as verified, never a repeat.

Offline. The two sides live in the pair cache (``benchmarks/pairs/advisory-fixes/materialize.py --fetch``); what is
committed is the catalog and ``verification.json``, the per-pair record of that script's check (the function is
declared on both sides, its body changed, bytes read). These tests hold the catalog to that record.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter
from pathlib import Path

import pytest

from openultrasast.learn.labels import DEFAULT_SOURCES, load_sources, repo_name
from openultrasast.model.taxonomy import load_families
from openultrasast.pairs import load_pair_catalog

ROOT = Path(__file__).resolve().parents[1]
PAIRS = ROOT / "benchmarks" / "pairs"
# batch 1 (2026-10-01), batches 2 (2026-10-03) and 3 (2026-10-04, functions that survive the fix): one source each,
# same rules
BATCHES = {name: PAIRS / name for name in ("advisory-fixes", "advisory-fixes-2", "advisory-fixes-3")}
SHA = re.compile(r"[0-9a-f]{40}")
PERMISSIVE_OR_COPYLEFT = re.compile(
    r"^(MIT|BSD-[23]-Clause|Apache-2\.0|ISC|Zlib|0BSD|Unlicense|MPL-[12]\.[01]"
    r"|(L|A)?GPL-[23]\.0(-only|-or-later)?|EPL-2\.0)$"
)
GITHUB = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.IGNORECASE)


def _raw(folder: Path) -> list[dict]:
    return list(tomllib.loads((folder / "catalog.toml").read_text())["pair"])


batches = pytest.mark.parametrize("source_id", sorted(BATCHES))


@batches
def test_every_pair_is_a_real_fix_with_its_function_licence_and_advisory(source_id: str) -> None:
    folder = BATCHES[source_id]
    families = {family.id for family in load_families().families}
    for item in _raw(folder):
        name = item["name"]
        assert SHA.fullmatch(item["commit"]) and SHA.fullmatch(item["parent"]), name
        assert item["commit"] != item["parent"], f"{name}: the fix commit is its own parent"
        assert item["commit_url"] == f"https://github.com/{item['repo']}/commit/{item['commit']}", name
        assert PERMISSIVE_OR_COPYLEFT.match(item["license"]), f"{name}: licence {item['license']!r} is not an SPDX id"
        assert re.search(r"CVE-\d{4}-\d+|GHSA-", item["cve"]), f"{name}: no advisory id"
        (row,) = item["expected"]
        assert row["function"] and row["path"] == item["path"] and row["family"] in families, name
        assert item["vendored"] is False and item["slice"] == "advisory-fixes", name


@batches
def test_the_catalog_loads_as_pointer_pairs_one_repository_each(source_id: str) -> None:
    folder = BATCHES[source_id]
    cases = load_pair_catalog(folder / "catalog.toml")
    assert len(cases) == len(_raw(folder)) and all(not case.vendored for case in cases)
    repos = Counter(repo_name(case.repo) for case in cases)
    assert [repo for repo, n in repos.items() if n > 1] == [], "one pair per repository"


@batches
def test_the_label_builder_lists_the_catalog_as_a_source(source_id: str) -> None:
    sources = load_sources(DEFAULT_SOURCES)
    source = sources.get(source_id)
    assert source.kind == "pairs" and source.files == (f"benchmarks/pairs/{source_id}/catalog.toml",)
    assert all((ROOT / path).is_file() for path in source.evaluation)


@batches
def test_every_pair_was_verified_on_both_sides(source_id: str) -> None:
    folder = BATCHES[source_id]
    record = json.loads((folder / "verification.json").read_text())
    rows = {row["name"]: row for row in record["pairs"]}
    for item in _raw(folder):
        row = rows.get(item["name"])
        assert row is not None and row["ok"], f"{item['name']}: not verified ({row and row.get('reason')})"
        assert row["bytes_read"] > 0, f"{item['name']}: verified without reading anything"
    assert set(rows) == {item["name"] for item in _raw(folder)}


@batches
def test_no_pair_repeats_a_repository_the_benchmarks_already_name(source_id: str) -> None:
    """A repository group is counted once: no catalog repository appears anywhere else under benchmarks/ (files the
    label sources exclude, the reserved v3 population among them, are skipped by name and never opened)."""
    folder = BATCHES[source_id]
    excluded = load_sources(DEFAULT_SOURCES).excluded
    ours = {repo_name(item["repo"]) for item in _raw(folder)}
    elsewhere: set[str] = set()
    for path in (ROOT / "benchmarks").rglob("*"):
        if not path.is_file() or folder in path.parents or path.name in excluded or path.suffix in {".pyc", ".bin", ".gz", ".jsonl"}:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        elsewhere |= {repo_name(match) for match in GITHUB.findall(text)}
        elsewhere |= {repo_name(m) for m in re.findall(r'^\s*(?:repo|fix_repo)\s*=\s*"([^"]+)"', text, re.MULTILINE)}
    assert sorted(ours & elsewhere) == []


PERMISSIVE = {"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "MPL-2.0", "Unlicense"}


@pytest.mark.parametrize(("source_id", "batch"), [("advisory-fixes-2", "2026-10-03"), ("advisory-fixes-3", "2026-10-04")])
def test_later_batches_are_permissive_and_dated_against_the_cutoff(source_id: str, batch: str) -> None:
    """Batches 2 and 3 publish permissive licences only and record each advisory's publication against the 2026-06-01
    cutoff, so memorisation can be measured on the post-cutoff pairs."""
    for item in _raw(BATCHES[source_id]):
        assert item["license"] in PERMISSIVE, item["name"]
        assert item["batch"] == batch, item["name"]
        assert item["post_cutoff"] is (item["published_at"][:10] >= "2026-06-01"), item["name"]


def test_no_repository_repeats_across_batches() -> None:
    seen: Counter[str] = Counter()
    for folder in BATCHES.values():
        seen.update({repo_name(item["repo"]) for item in _raw(folder)})
    assert [repo for repo, n in seen.items() if n > 1] == []
