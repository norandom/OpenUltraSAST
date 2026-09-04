"""Maintainer VFC harvest stays offline in CI: extract and reject, no HTTP."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

HARVEST = Path("benchmarks/pairs/vfc/harvest.py")


def _harvest() -> dict[str, object]:
    return runpy.run_path(str(HARVEST))


def test_extract_function_round_trips_perl_sub_without_parens() -> None:
    harvest = _harvest()
    source = """
sub other { return 0; }
sub link_hash_cert {
    my ($hash, $fprint) = `"$openssl" x509 -in "$fname"`;
}
sub later { return 1; }
"""
    body = harvest["extract_function"](source, "link_hash_cert")
    assert "sub link_hash_cert {" in body
    assert "`\"$openssl\" x509" in body
    assert "sub other" not in body
    assert "sub later" not in body


def test_extract_function_round_trips_a_local_body() -> None:
    harvest = _harvest()
    source = """
int before(void) { return 0; }

int target_fn(char *name, int namelen) {
    memcpy(name, name, namelen + 1);
    return namelen;
}

int after(void) { return 1; }
"""
    body = harvest["extract_function"](source, "target_fn")
    assert "int target_fn(char *name, int namelen)" in body
    assert "memcpy(name, name, namelen + 1);" in body
    assert "int before" not in body
    assert "int after" not in body


def test_extract_function_skips_prototype_before_definition() -> None:
    harvest = _harvest()
    source = """
class Loader {
 public:
    char *ArrayBufferResult();
};

char *Loader::ArrayBufferResult() {
    return raw_data_->ToArrayBuffer();
}
"""
    body = harvest["extract_function"](source, "ArrayBufferResult")
    assert "Loader::ArrayBufferResult" in body
    assert "return raw_data_->ToArrayBuffer();" in body
    assert "class Loader" not in body


def test_validate_recipe_rejects_advisory_only_and_fixfox() -> None:
    harvest = _harvest()
    validate = harvest["validate_recipe"]
    with pytest.raises(harvest["RecipeError"], match="advisory-only"):
        validate({"name": "mfsa-only", "cve": "CVE-2019-11730"})
    with pytest.raises(harvest["RecipeError"], match="embargoed"):
        validate(
            {
                "name": "fixfox",
                "parent": "abc",
                "commit": "def",
                "path": "a.c",
                "function": "f",
                "license": "MIT",
                "url": "https://zenodo.org/record/fixfox",
            }
        )


def test_harvest_dry_run_accepts_seed_recipes() -> None:
    harvest = _harvest()
    recipes = {str(item["name"]): item for item in harvest["load_recipes"](Path("benchmarks/pairs/vfc/recipes.toml"))}
    assert {"openssl-cve-2014-0160", "firefox-cve-2020-15667", "chromium-cve-2019-5786"} <= set(recipes)
    for recipe in recipes.values():
        harvest["validate_recipe"](recipe)
    assert harvest["main"](["--name", "openssl-cve-2014-0160"]) == 0
