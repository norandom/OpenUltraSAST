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

ROOT = Path(__file__).resolve().parents[1]
POPULATION = ROOT / "benchmarks" / "independent" / "population-v1.toml"
FAMILIES = {"injection", "untrusted_destination", "config_secrets"}
SHA = re.compile(r"[0-9a-f]{40}")


def _population() -> dict:
    return tomllib.loads(POPULATION.read_text())


def test_the_reservation_is_well_formed() -> None:
    data = _population()
    assert data["status"] in {"reserved-unscanned", "frozen"}
    cases = data["case"]
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids)) >= 10
    for case in cases:
        assert case["family"] in FAMILIES, case["id"]
        assert SHA.fullmatch(case["vulnerable"]) and SHA.fullmatch(case["fixed"]), case["id"]
        assert case["vulnerable"] != case["fixed"], case["id"]
        assert case["repo"].startswith("https://github.com/"), case["id"]
        assert case["advisory"] and case["sink"] and case["privilege"], case["id"]
    languages = {case["language"] for case in cases}
    assert {"php", "python"} <= languages and languages & {"javascript", "typescript"}


def test_a_multi_language_repository_is_reserved() -> None:
    """The declared v0.1 target is a WordPress plugin: PHP plus its admin JavaScript (task 13.4)."""
    data = _population()
    by_id = {case["id"]: case for case in data["case"]}
    members = data["multi_language_members"]
    assert members and all(by_id[m]["language"] == "php" and "javascript" in by_id[m].get("also", []) for m in members)


def test_no_reserved_repository_is_referenced_by_the_development_tree() -> None:
    reserved = {case["repo"].rstrip("/").lower() for case in _population()["case"]}
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
