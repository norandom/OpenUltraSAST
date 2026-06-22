"""Trail of Bits skill index + router (Phase 14)."""

from openultrasast.preprocess import FileTarget
from openultrasast.skills import (
    SKILL_INVENTORY,
    route_skill_ids,
    route_skills,
    route_skills_for_target,
    select_skill_context,
    skill_chunks,
)


def _target(language: str, tags: list[str]) -> FileTarget:
    return FileTarget(path="t", absolute_path="/repo/t", language=language, loc=10, tags=tags, has_fuzz_entry_point=False)


# ---- routing by language / tags / vulnerability class -----------------------


def test_c_parser_target_routes_to_memory_and_fuzzing_skills() -> None:
    ids = route_skill_ids(_target("c", ["memory_unsafe", "parser"]))
    assert {"address-sanitizer", "harness-writing"} <= set(ids)  # memory + fuzzing
    assert "libfuzzer" in ids


def test_crypto_target_routes_to_constant_time_and_vector_skills() -> None:
    ids = route_skill_ids(_target("python", ["crypto"]))
    assert "constant-time-analysis" in ids
    assert "vector-forge" in ids


def test_language_mismatch_excludes_other_language_skills() -> None:
    # A C target must not pull Python-only (atheris) or Rust-only (cargo-fuzz) skills.
    ids = route_skill_ids(_target("c", ["memory_unsafe", "parser", "fuzzable"]))
    assert "atheris" not in ids
    assert "cargo-fuzz" not in ids


def test_language_only_match_does_not_select() -> None:
    # python + crypto must not surface atheris (python but no crypto signal).
    ids = route_skills_for_target(_target("python", ["crypto"]), max_snippets=10)
    assert "atheris" not in [skill.id for skill in ids]


# ---- routing by stage -------------------------------------------------------


def test_stage_filter_restricts_to_stage_skills() -> None:
    # fuzzing-dictionary is verify-only; at the map stage it must not appear, while a
    # map-stage skill (semgrep) does for an injection signal.
    verify = route_skills(tags=("parser",), vulnerability_classes=("parsing",), stage="verify", max_snippets=10)
    mapped = route_skills(tags=("parser",), vulnerability_classes=("parsing",), stage="map", max_snippets=10)
    assert "fuzzing-dictionary" in {s.id for s in verify}
    assert "fuzzing-dictionary" not in {s.id for s in mapped}


# ---- prompt budget caps -----------------------------------------------------


def test_select_skill_context_respects_budget() -> None:
    target = _target("c", ["memory_unsafe", "parser"])
    full = select_skill_context(target, budget_chars=10_000)
    capped = select_skill_context(target, budget_chars=80)
    assert len(capped) <= 80
    assert len(full) > len(capped)


def test_zero_budget_yields_no_context() -> None:
    assert select_skill_context(_target("c", ["memory_unsafe"]), budget_chars=0) == ""


# ---- retrieval-namespace chunking + inventory integrity ---------------------


def test_skill_chunks_land_in_the_skills_namespace() -> None:
    chunks = skill_chunks()
    assert chunks
    assert all(chunk.namespace == "skills" for chunk in chunks)
    assert any(chunk.metadata.get("skill_id") == "address-sanitizer" for chunk in chunks)


def test_inventory_ids_are_unique() -> None:
    ids = [skill.id for skill in SKILL_INVENTORY]
    assert len(ids) == len(set(ids))
