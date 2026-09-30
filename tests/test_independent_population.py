"""The independent population is reserved, well formed, and untouched by anything in the development tree.

Every rule this project has learned was learned on its development subjects, so those can no longer measure
whether the rules generalise. This reservation is the population that can -- until something scans it. The
check below fails the moment a reserved repository is referenced by a recipe, catalog, manifest or measurement
anywhere else, which is how an evaluation set quietly becomes a development one.
"""

from __future__ import annotations

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


def test_no_reserved_repository_is_referenced_by_the_development_tree() -> None:
    reserved = {case["repo"].rstrip("/").lower() for path in POPULATIONS for case in _population(path)["case"]}
    names = {url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1] for url in reserved}
    offenders = []
    for top in ("benchmarks", "src", "tests"):
        for path in (ROOT / top).rglob("*"):
            if not path.is_file() or POPULATION.parent in path.parents or path == Path(__file__) or path.suffix in {".pyc", ".bin", ".gz"}:
                continue
            try:
                text = path.read_text(errors="ignore").lower()
            except OSError:
                continue
            offenders += [f"{path.relative_to(ROOT)}: {name}" for name in names if f"github.com/{name}" in text]
    assert not offenders, "a reserved repository is referenced outside the reservation: " + "; ".join(offenders[:10])
