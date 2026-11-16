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
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import historical_authorization as historical
from benchmarks.valid import reservation, reservation_guard
from benchmarks.valid.replacement_artifact_contract import canonical_json_bytes
from openultrasast.core.canonical import content_digest

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
    names: set[str] = set()
    for path in _pool_manifests():
        data = tomllib.loads(path.read_text())
        for row in data.get("repository", []):
            value = row.get("repository")
            if isinstance(value, str) and value:
                names.add(value.lower().removeprefix("https://github.com/").rstrip("/").removesuffix(".git"))
    return names


def _population_names() -> set[str]:
    reserved = {case["repo"].rstrip("/").lower() for path in POPULATIONS for case in _population(path)["case"]}
    return {url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1] for url in reserved}


def _source_repositories() -> dict[Path, set[str]]:
    sources: dict[Path, set[str]] = {}
    for path in POPULATIONS:
        sources[path] = {case["repo"].lower() for case in _population(path)["case"]}
    for path in _pool_manifests():
        data = tomllib.loads(path.read_text())
        names = {
            value.lower().removeprefix("https://github.com/").rstrip("/").removesuffix(".git")
            for row in data.get("repository", [])
            if isinstance((value := row.get("repository")), str) and value
        }
        if names:
            sources[path] = {f"https://github.com/{name}" for name in names}
    reserved = {repository for values in sources.values() for repository in values}
    for relative, expected_digest in reservation_guard.PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS.items():
        path = ROOT / relative
        if not path.is_file():
            continue
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_digest
        names = {
            match.rstrip("/").removesuffix(".git")
            for match in re.findall(r"github\.com/([\w.-]+/[\w.-]+)", path.read_text(errors="ignore").lower())
            if f"https://github.com/{match.rstrip('/').removesuffix('.git')}" in reserved
        }
        if names:
            sources[path] = {f"https://github.com/{name}" for name in names}
    return sources


def _reviewed_history() -> historical.HistoricalWithdrawalV1:
    inventory = historical.pinned_historical_inventory(ROOT)
    candidate = historical.build_withdrawal_candidate(inventory)
    value: dict[str, object] = {
        "schema_version": historical.HISTORICAL_REVIEW_SCHEMA,
        "subject_digest": candidate.candidate_digest,
        "decision": "authorize_exact_historical_audit",
        "producer_identity": "benchmark-custodian",
        "reviewer_identity": "independent-guard-reviewer",
        "conflict_disclosed": True,
        "policy_digest": content_digest({"policy": "permanent-reservation-guard-v1"}),
    }
    value["review_digest"] = content_digest(value)
    return historical.accept_reviewed_withdrawal(candidate, canonical_json_bytes(value))


def _production_guard_report() -> reservation_guard.ReservationGuardReportV1:
    sources = _source_repositories()
    repositories = sorted({repository for values in sources.values() for repository in values})
    networks = tuple(reservation.build_network_identity(repository) for repository in repositories)
    resolver = reservation.RepositoryIdentityResolver(networks)
    legacy_by_path: dict[Path, tuple[reservation.LegacyReservationSourceV1, ...]] = {}
    all_legacy: list[reservation.LegacyReservationSourceV1] = []
    source_owner: dict[str, str] = {}
    for path, values in sources.items():
        owner = "independent" if ROOT / "benchmarks/independent" in path.parents else "unseen"
        relative = path.relative_to(ROOT).as_posix()
        pinned_source = relative in reservation_guard.PINNED_LEGACY_RESERVATION_SOURCE_DIGESTS
        source_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records = tuple(
            reservation.legacy_reservation_source(resolver, repository=repository, source_digest=source_digest)
            for repository in sorted(values)
            if pinned_source or source_owner.get(repository, owner) == owner
        )
        for repository in values:
            source_owner.setdefault(repository, owner)
        if records:
            legacy_by_path[path] = records
        all_legacy.extend(records)
    authority = reservation.ReservationAuthority(resolver, legacy_sources=all_legacy)
    census = authority.project_census(())
    exact_sources = tuple(
        reservation_guard.exact_reservation_source(
            ROOT,
            path.relative_to(ROOT).as_posix(),
            tuple(record.legacy_source_digest for record in records),
        )
        for path, records in sorted(legacy_by_path.items())
    )
    return reservation_guard.scan_permanent_reservations(
        ROOT,
        scan_roots=tuple(name for name in ("benchmarks", "src", "tests", "plane") if (ROOT / name).is_dir()),
        authority=authority,
        census=census,
        reservation_sources=exact_sources,
        historical_withdrawal=(
            _reviewed_history() if all((ROOT / relative).is_file() for relative in historical.PINNED_HISTORICAL_DIGESTS) else None
        ),
    )


def test_no_reserved_repository_is_referenced_by_the_development_tree() -> None:
    report = _production_guard_report()
    reservation_guard.require_clean_guard(report)
    assert report.files_read > 0 and report.bytes_read > 0 and report.reserved_network_count > 0


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
    for name in reservation_guard.PRODUCTION_GUARD_SCAN_ROOTS:
        (tmp_path / name).mkdir(exist_ok=True)
    prefix = "https://" + "github.com/"
    population.write_text('[[case]]\nrepo = "' + prefix + 'synthetic/population"\n')
    pool.write_text('[[repository]]\nrepository = "synthetic/pool"\n')
    monkeypatch.setattr(__import__(__name__), "ROOT", tmp_path)
    monkeypatch.setattr(__import__(__name__), "POPULATIONS", [population])
    test_no_reserved_repository_is_referenced_by_the_development_tree()
    leak = tmp_path / "benchmarks/measurements/fixture.txt"
    leak.parent.mkdir(parents=True)
    leak.write_text(prefix + "synthetic/pool")
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()
    leak.unlink()
    plane = tmp_path / "plane/fixture.txt"
    plane.parent.mkdir(exist_ok=True)
    plane.write_text(prefix + "synthetic/pool")
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()
    plane.write_text(prefix + "synthetic/population")
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
        test_no_reserved_repository_is_referenced_by_the_development_tree()
    plane.unlink()
    private = pool.parent / "private/draft-p1.toml"
    private.parent.mkdir()
    private.write_text('[[repository]]\nrepo = "' + prefix + 'synthetic/population"\n')
    with pytest.raises(reservation_guard.ReservationGuardError, match="count=1"):
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
