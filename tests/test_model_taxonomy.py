"""learning-harness task 1.1: the closed family taxonomy with a verifier per family (offline)."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

GOOD = (
    'version = "1"\n\n'
    '[[family]]\nid = "injection"\ndescription = "x"\ncwes = ["CWE-89"]\nmechanisms = ["source_reaches_sink"]\nverifier = "canary"\n'
)


def test_taxonomy_loads_ten_families_each_with_a_verifier() -> None:
    from openultrasast.model.taxonomy import FAMILY_IDS, VERIFIER_KINDS, load_families

    taxonomy = load_families()
    assert len(FAMILY_IDS) == 10 and FAMILY_IDS[-1] == "unknown"
    assert tuple(family.id for family in taxonomy.families) == FAMILY_IDS
    assert taxonomy.version and all(family.verifier in VERIFIER_KINDS for family in taxonomy.families)
    assert {family.id for family in taxonomy.families if family.verifier == "canary"} == {"injection", "path", "deserialization"}
    assert taxonomy.by_id("access_control").verifier == "static"
    assert taxonomy.by_id("memory").verifier == "none"  # measured on the vendored slice, never proven by us
    assert taxonomy.by_id("unknown").verifier == "none" and all(family.description for family in taxonomy.families)


def test_every_mechanism_id_resolves_to_exactly_one_family() -> None:
    from openultrasast.model.taxonomy import load_families
    from openultrasast.pairs import load_mechanisms

    taxonomy = load_families()
    _, mechanism_ids = load_mechanisms()
    for mechanism in sorted(mechanism_ids):
        owners = [family.id for family in taxonomy.families if mechanism in family.mechanisms]
        assert len(owners) == 1, (mechanism, owners)
    assert taxonomy.family_of_mechanism("missing_auth_guard").id == "access_control"
    assert taxonomy.family_of_mechanism("unchecked_length_copy").id == "memory"
    # a mechanism that spans families names none of them; the labeled CWE decides those rows
    assert taxonomy.family_of_mechanism("source_reaches_sink").id == "unknown"
    assert taxonomy.family_of_mechanism("not_a_mechanism") is None


def test_every_labeled_corpus_cwe_resolves_and_no_cwe_is_claimed_twice() -> None:
    from openultrasast.model.taxonomy import load_families

    taxonomy = load_families()
    seen: dict[str, str] = {}
    for family in taxonomy.families:
        for cwe in family.cwes:
            assert cwe not in seen, (cwe, seen.get(cwe), family.id)
            seen[cwe] = family.id
    labeled: set[str] = set()
    for catalog in sorted(Path("benchmarks/pairs").rglob("catalog.toml")):
        for pair in tomllib.loads(catalog.read_text()).get("pair", []):
            labeled |= {str(row["cwe"]) for row in pair.get("expected", []) if row.get("cwe")}
    assert sorted(cwe for cwe in labeled if taxonomy.family_of_cwe(cwe) is None) == []
    assert taxonomy.family_of_cwe("cwe-89").id == "injection"  # case and spacing tolerant
    assert taxonomy.family_of_cwe("CWE-601").id == "untrusted_destination"  # 34 open-redirect rows
    assert taxonomy.family_of_cwe("CWE-835").id == "unknown"  # considered and out of scope, not unresolved
    assert taxonomy.family_of_cwe("CWE-99999") is None


def test_relation_answers_same_lateral_fabricated_and_parent_child_when_declared(tmp_path: Path) -> None:
    from openultrasast.model.taxonomy import load_families

    taxonomy = load_families()
    assert taxonomy.related("injection", "injection") == "same"
    assert taxonomy.related("injection", "access_control") == "lateral"
    assert taxonomy.related("injection", "not_a_family") == "fabricated"
    assert taxonomy.related("unknown", "injection") == "lateral"  # abstention earns no partial credit
    assert all(family.parent is None for family in taxonomy.families)  # the shipped taxonomy is flat
    (tmp_path / "families.toml").write_text(
        GOOD + '\n[[family]]\nid = "path"\nparent = "injection"\ndescription = "y"\ncwes = []\nmechanisms = []\nverifier = "canary"\n'
    )
    scoped = load_families(tmp_path / "families.toml", require_all=False)
    assert scoped.related("path", "injection") == "parent_child" and scoped.related("injection", "path") == "parent_child"


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (GOOD + 'color = "blue"\n', "color"),
        (GOOD.replace('verifier = "canary"\n', ""), "verifier"),
        (GOOD.replace('verifier = "canary"', 'verifier = "maybe"'), "maybe"),
        (GOOD.replace('id = "injection"', 'id = "sql_injection"'), "sql_injection"),
        (GOOD.replace('cwes = ["CWE-89"]', 'cwes = ["CWE-89", "CWE-89"]'), "CWE-89"),
        (GOOD.replace('description = "x"\n', ""), "description"),
        (GOOD + '\n[[family]]\nid = "path"\ndescription = "y"\ncwes = ["CWE-89"]\nmechanisms = []\nverifier = "canary"\n', "CWE-89"),
        (
            GOOD + '\n[[family]]\nid = "path"\ndescription = "y"\ncwes = []\nmechanisms = ["source_reaches_sink"]\nverifier = "canary"\n',
            "source_reaches_sink",
        ),
        (GOOD.replace('version = "1"\n', ""), "version"),
        (GOOD + '\n[[family]]\nid = "path"\nparent = "nope"\ndescription = "y"\ncwes = []\nmechanisms = []\nverifier = "none"\n', "nope"),
    ],
    ids=[
        "unknown_field",
        "missing_verifier",
        "bad_verifier",
        "fabricated_family",
        "duplicate_cwe",
        "no_description",
        "cwe_claimed_twice",
        "mechanism_claimed_twice",
        "no_version",
        "unknown_parent",
    ],
)
def test_loader_rejects_data_bugs_by_name(tmp_path: Path, text: str, needle: str) -> None:
    from openultrasast.model.taxonomy import FamiliesError, load_families

    (tmp_path / "families.toml").write_text(text)
    with pytest.raises(FamiliesError, match=needle):
        load_families(tmp_path / "families.toml", require_all=False)


def test_the_shipped_file_must_declare_the_whole_closed_set_in_order(tmp_path: Path) -> None:
    from openultrasast.model.taxonomy import FamiliesError, load_families

    (tmp_path / "families.toml").write_text(GOOD)
    with pytest.raises(FamiliesError, match="in that order"):
        load_families(tmp_path / "families.toml")
