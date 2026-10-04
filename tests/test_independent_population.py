"""The independent population is reserved, well formed, and untouched by anything in the development tree.

Every rule this project has learned was learned on its development subjects, so those can no longer measure
whether the rules generalise. This reservation is the population that can -- until something scans it. The
check below fails the moment a reserved repository is referenced by a recipe, catalog, manifest or measurement
anywhere else, which is how an evaluation set quietly becomes a development one.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POPULATIONS = sorted((ROOT / "benchmarks" / "independent").glob("population-v*.toml"))
POPULATION = POPULATIONS[0]
# v1 and v2 score injection, untrusted_destination and config_secrets; v3 (PHP) adds the other four families that
# protocol-v3.md pre-registers matching rules for.
FAMILIES = {"injection", "untrusted_destination", "config_secrets", "path", "output_encoding", "access_control", "deserialization"}
SHA = re.compile(r"[0-9a-f]{40}")


def _population(path: Path = POPULATION) -> dict:
    return tomllib.loads(path.read_text())


@pytest.mark.parametrize("path", POPULATIONS, ids=lambda p: p.stem)
def test_the_reservation_is_well_formed(path: Path) -> None:
    data = _population(path)
    assert data["status"] in {"reserved-unscanned", "reserved", "frozen"}
    cases = data["case"]
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids)) >= 10
    for case in cases:
        assert case["family"] in FAMILIES, case["id"]
        assert SHA.fullmatch(case["vulnerable"]) and SHA.fullmatch(case["fixed"]), case["id"]
        assert case["vulnerable"] != case["fixed"], case["id"]
        assert case["repo"].startswith("https://github.com/"), case["id"]
        assert case["advisory"] and case["sink"] and case["privilege"], case["id"]
    if data["status"] == "frozen":
        # Frozen means every case carries its benign control: a change from the same history, reviewed as not a
        # security change, whose two sides a correct analyzer must not tell apart.
        for case in cases:
            benign = case.get("benign") or {}
            assert SHA.fullmatch(benign.get("base", "")) and SHA.fullmatch(benign.get("tip", "")), case["id"]
        assert (path.parent / data["freeze_record"]).is_file()
    languages = {case["language"] for case in cases}
    if "language" in data:
        # A single-language population (v3: PHP) declares its language, and every case is in it.
        assert languages == {data["language"]}
    else:
        assert {"php", "python"} <= languages and languages & {"javascript", "typescript"}


@pytest.mark.parametrize("path", POPULATIONS, ids=lambda p: p.stem)
def test_a_multi_language_repository_is_reserved(path: Path) -> None:
    """The declared v0.1 target is a WordPress plugin: PHP plus its admin JavaScript (task 13.4)."""
    data = _population(path)
    by_id = {case["id"]: case for case in data["case"]}
    members = data["multi_language_members"]
    assert members and all(by_id[m]["language"] == "php" and "javascript" in by_id[m].get("also", []) for m in members)


def _pool_manifests() -> list[Path]:
    directory = ROOT / "benchmarks/unseen"
    return sorted([*directory.glob("*.toml"), *directory.glob("private/*.toml")])


def _pool_names() -> set[str]:
    names = set()
    for path in _pool_manifests():
        text = path.read_text().lower()
        names.update(m.rstrip("/").removesuffix(".git") for m in re.findall(r"github\.com/([\w.-]+/[\w.-]+)", text))
    return names


def _population_names() -> set[str]:
    reserved = {case["repo"].rstrip("/").lower() for path in POPULATIONS for case in _population(path)["case"]}
    return {url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1] for url in reserved}


def test_no_reserved_repository_is_referenced_by_the_development_tree() -> None:
    reservations = [(ROOT / "benchmarks/independent", _population_names()), (ROOT / "benchmarks/unseen", _pool_names())]
    offenders = 0
    counts = {}
    for top in ("benchmarks", "src", "tests", "plane"):
        for path in (ROOT / top).rglob("*"):
            if not path.is_file() or path == Path(__file__) or path.suffix in {".pyc", ".bin", ".gz"}:
                continue
            # Preserve the population guard's existing scope; plane is newly reserved for pools.
            active = [
                (directory, names)
                for directory, names in reservations
                if directory not in path.parents and names and not (top == "plane" and directory == ROOT / "benchmarks/independent")
            ]
            if not active:
                continue
            try:
                text = path.read_text(errors="ignore").lower()
            except OSError:
                continue
            count = sum(1 for _, names in active for name in names if f"github.com/{name}" in text)
            offenders += count
            counts[top] = counts.get(top, 0) + count
    assert not offenders, f"reserved repository referenced outside its reservation: count={offenders}, sources={counts}"


def test_pool_and_population_names_are_disjoint() -> None:
    count = len(_population_names() & _pool_names())
    assert not count, f"overlapping reservations: count={count}"


def manifest_digest(path: Path) -> str:
    """Canonical parsed TOML, UTF-8 JSON with sorted keys and compact separators.

    Private entries are covered by their opaque pointers' digests in the public manifest.
    The freeze writer must use the same encoding (task 3.2).
    """
    raw = json.dumps(tomllib.loads(path.read_text()), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def check_pool_digest(path: Path) -> None:
    record = path.with_name("freeze-" + path.stem.removeprefix("pool-") + ".json")
    expected = json.loads(record.read_text())["freeze_digest"]
    assert manifest_digest(path) == expected, "frozen pool digest mismatch"


def test_frozen_pool_manifest_digest() -> None:
    pools = sorted((ROOT / "benchmarks/unseen").glob("pool-p*.toml"))
    if not pools:
        pytest.skip("no pool frozen")
    for path in pools:
        check_pool_digest(path)


def test_pool_guard_controls(tmp_path, monkeypatch) -> None:
    """A synthetic reservation proves green, then red outside its own directory."""
    population = tmp_path / "benchmarks/independent/population-v1.toml"
    pool = tmp_path / "benchmarks/unseen/pool-p1.toml"
    population.parent.mkdir(parents=True)
    pool.parent.mkdir(parents=True)
    prefix = "https://" + "github.com/"
    population.write_text('[[case]]\nrepo = "' + prefix + 'synthetic/population"\n')
    pool.write_text('[[repository]]\nrepo = "' + prefix + 'synthetic/pool"\n')
    monkeypatch.setattr(__import__(__name__), "ROOT", tmp_path)
    monkeypatch.setattr(__import__(__name__), "POPULATIONS", [population])
    test_no_reserved_repository_is_referenced_by_the_development_tree()
    leak = tmp_path / "benchmarks/measurements/fixture.txt"
    leak.parent.mkdir(parents=True)
    leak.write_text(prefix + "synthetic/pool")
    with pytest.raises(AssertionError, match="count=1"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()
    leak.unlink()
    plane = tmp_path / "plane/fixture.txt"
    plane.parent.mkdir()
    plane.write_text(prefix + "synthetic/pool")
    with pytest.raises(AssertionError, match="count=1"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()
    plane.write_text(prefix + "synthetic/population")
    test_no_reserved_repository_is_referenced_by_the_development_tree()
    plane.unlink()
    private = pool.parent / "private/draft-p1.toml"
    private.parent.mkdir()
    private.write_text('[[repository]]\nrepo = "' + prefix + 'synthetic/population"\n')
    with pytest.raises(AssertionError, match="count=2"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()


def test_pool_digest_control(tmp_path) -> None:
    pool = tmp_path / "pool-p1.toml"
    pool.write_text('status = "frozen"\n[[repository]]\nid = "opaque"\n')
    record = tmp_path / "freeze-p1.json"
    record.write_text(json.dumps({"freeze_digest": manifest_digest(pool)}))
    check_pool_digest(pool)
    pool.write_text(pool.read_text() + "slice = 2\n")
    with pytest.raises(AssertionError, match="digest"):
        check_pool_digest(pool)


def test_frozen_pool_discovery_cannot_be_disabled(tmp_path, monkeypatch) -> None:
    pool = tmp_path / "benchmarks/unseen/pool-p1.toml"
    pool.parent.mkdir(parents=True)
    pool.write_text('status = "frozen"\n')
    record = pool.with_name("freeze-p1.json")
    record.write_text(json.dumps({"freeze_digest": manifest_digest(pool)}))
    monkeypatch.setattr(__import__(__name__), "ROOT", tmp_path)
    test_frozen_pool_manifest_digest()
    pool.write_text('status = "draft"\n')
    with pytest.raises(AssertionError, match="digest"):
        test_frozen_pool_manifest_digest()
