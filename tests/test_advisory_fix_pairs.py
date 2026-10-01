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

from openultrasast.learn.labels import DEFAULT_SOURCES, load_sources, repo_name
from openultrasast.model.taxonomy import load_families
from openultrasast.pairs import load_pair_catalog

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "benchmarks" / "pairs" / "advisory-fixes"
CATALOG = FOLDER / "catalog.toml"
SHA = re.compile(r"[0-9a-f]{40}")
PERMISSIVE_OR_COPYLEFT = re.compile(
    r"^(MIT|BSD-[23]-Clause|Apache-2\.0|ISC|Zlib|0BSD|Unlicense|MPL-[12]\.[01]"
    r"|(L|A)?GPL-[23]\.0(-only|-or-later)?|EPL-2\.0)$"
)
GITHUB = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.IGNORECASE)


def _raw() -> list[dict]:
    return list(tomllib.loads(CATALOG.read_text())["pair"])


def test_every_pair_is_a_real_fix_with_its_function_licence_and_advisory() -> None:
    families = {family.id for family in load_families().families}
    for item in _raw():
        name = item["name"]
        assert SHA.fullmatch(item["commit"]) and SHA.fullmatch(item["parent"]), name
        assert item["commit"] != item["parent"], f"{name}: the fix commit is its own parent"
        assert item["commit_url"] == f"https://github.com/{item['repo']}/commit/{item['commit']}", name
        assert PERMISSIVE_OR_COPYLEFT.match(item["license"]), f"{name}: licence {item['license']!r} is not an SPDX id"
        assert re.search(r"CVE-\d{4}-\d+|GHSA-", item["cve"]), f"{name}: no advisory id"
        (row,) = item["expected"]
        assert row["function"] and row["path"] == item["path"] and row["family"] in families, name
        assert item["vendored"] is False and item["slice"] == "advisory-fixes", name


def test_the_catalog_loads_as_pointer_pairs_one_repository_each() -> None:
    cases = load_pair_catalog(CATALOG)
    assert len(cases) == len(_raw()) and all(not case.vendored for case in cases)
    repos = Counter(repo_name(case.repo) for case in cases)
    assert [repo for repo, n in repos.items() if n > 1] == [], "one pair per repository"


def test_the_label_builder_lists_the_catalog_as_a_source() -> None:
    sources = load_sources(DEFAULT_SOURCES)
    source = sources.get("advisory-fixes")
    assert source.kind == "pairs" and source.files == ("benchmarks/pairs/advisory-fixes/catalog.toml",)
    assert all((ROOT / path).is_file() for path in source.evaluation)


def test_every_pair_was_verified_on_both_sides() -> None:
    record = json.loads((FOLDER / "verification.json").read_text())
    rows = {row["name"]: row for row in record["pairs"]}
    for item in _raw():
        row = rows.get(item["name"])
        assert row is not None and row["ok"], f"{item['name']}: not verified ({row and row.get('reason')})"
        assert row["bytes_read"] > 0, f"{item['name']}: verified without reading anything"
    assert set(rows) == {item["name"] for item in _raw()}


def test_no_pair_repeats_a_repository_the_benchmarks_already_name() -> None:
    """A repository group is counted once: no catalog repository appears anywhere else under benchmarks/ (files the
    label sources exclude, the reserved v3 population among them, are skipped by name and never opened)."""
    excluded = load_sources(DEFAULT_SOURCES).excluded
    ours = {repo_name(item["repo"]) for item in _raw()}
    elsewhere: set[str] = set()
    for path in (ROOT / "benchmarks").rglob("*"):
        if not path.is_file() or FOLDER in path.parents or path.name in excluded or path.suffix in {".pyc", ".bin", ".gz", ".jsonl"}:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        elsewhere |= {repo_name(match) for match in GITHUB.findall(text)}
        elsewhere |= {repo_name(m) for m in re.findall(r'^\s*(?:repo|fix_repo)\s*=\s*"([^"]+)"', text, re.MULTILINE)}
    assert sorted(ours & elsewhere) == []
