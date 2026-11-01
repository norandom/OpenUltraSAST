"""Core-only acceptance of a downstream reviewed fact-adapter handoff."""

from __future__ import annotations

import ast
import os
import shutil
from pathlib import Path

import pytest
from core_fact_adapter_acceptance import (
    CORE_ENTRY_POINTS,
    EXPECTED_CASES,
    FIXTURE_ROOT,
    freeze,
    run_isolated_replay,
    validate_manifest_bytes,
    validated_manifest,
    verify_replay,
)

from openultrasast.core import canonical

CORE_ROOT = Path(__file__).parents[1] / "src" / "openultrasast" / "core"


def test_handoff_manifest_names_the_exact_generic_acceptance_matrix() -> None:
    _, manifest = validated_manifest(FIXTURE_ROOT)
    cases = manifest["cases"]
    assert tuple(manifest["core_entry_points"]) == CORE_ENTRY_POINTS
    assert [case["case_id"] for case in cases] == sorted(EXPECTED_CASES)
    assert {case["case_id"]: (case["expected_status"], case["reason"]) for case in cases} == EXPECTED_CASES
    assert all(row["name"] not in CORE_ENTRY_POINTS for case in cases for row in case["downstream_validators"])


def test_handoff_names_one_replay_envelope_and_exact_artifact_census() -> None:
    _, manifest = validated_manifest(FIXTURE_ROOT)
    artifacts = [artifact for case in manifest["cases"] for artifact in case["artifacts"]]
    replay_envelopes = {artifact["path"] for artifact in artifacts if artifact["kind"] == "core-replay-envelope"}
    declared = {artifact["path"] for artifact in artifacts}
    materialized = {path.relative_to(FIXTURE_ROOT).as_posix() for path in (FIXTURE_ROOT / "artifacts" / "sha256").iterdir()}
    assert len(replay_envelopes) == 1
    assert materialized == declared


def test_handoff_replays_semantic_outcomes_through_real_core_apis() -> None:
    output = run_isolated_replay(FIXTURE_ROOT, Path(__file__).parent)
    verify_replay(output["results"], output["trace"])


def test_core_import_and_vocabulary_census_remains_target_neutral() -> None:
    forbidden_imports: list[tuple[str, str]] = []
    for path in CORE_ROOT.rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        assert all(term not in content for term in ("entry:express", "express_application", "express_router", "legacy_projection_only"))
        for node in ast.walk(ast.parse(content, filename=str(path))):
            names: tuple[str, ...] = ()
            if isinstance(node, ast.Import):
                names = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = (node.module,)
            forbidden_imports.extend(
                (path.relative_to(CORE_ROOT).as_posix(), name)
                for name in names
                if name.startswith(("openultrasast.mapping", "openultrasast.semantic"))
            )
    assert forbidden_imports == []


def test_acceptance_rejects_a_noop_consumer_even_when_outcomes_are_claimed() -> None:
    claimed = {case_id: list(result) for case_id, result in EXPECTED_CASES.items()}
    with pytest.raises(AssertionError, match="core API trace"):
        verify_replay(claimed, [])


def test_acceptance_rejects_redigested_incomplete_complete_validator_matrix() -> None:
    _, manifest = validated_manifest(FIXTURE_ROOT)
    complete = next(case for case in manifest["cases"] if case["case_id"] == "complete")
    complete["validators"] = complete["validators"][:1]
    payload = {
        "schema_version": manifest["schema_version"],
        "core_entry_points": tuple(manifest["core_entry_points"]),
        "cases": tuple(freeze(case) for case in manifest["cases"]),
    }
    manifest["handoff_digest"] = canonical.content_digest(payload)
    with pytest.raises(AssertionError, match="validator matrix"):
        validate_manifest_bytes(canonical.canonical_bytes(freeze(manifest)), FIXTURE_ROOT)


@pytest.mark.parametrize("mutation", ("missing", "extra", "symlink", "directory", "unreadable", "zero"))
def test_acceptance_refuses_unsafe_or_unaccounted_source_inputs(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / mutation
    shutil.copytree(FIXTURE_ROOT, root)
    source = root / "sources" / "partial.js"
    if mutation == "missing":
        source.unlink()
    elif mutation == "extra":
        (root / "sources" / "extra.js").write_bytes(b"extra")
    elif mutation == "symlink":
        external = tmp_path / "external.js"
        external.write_bytes(source.read_bytes())
        source.unlink()
        os.symlink(external, source)
    elif mutation == "directory":
        source.unlink()
        source.mkdir()
    elif mutation == "unreadable":
        source.chmod(0)
    else:
        source.write_bytes(b"")
    with pytest.raises(AssertionError, match="source"):
        validated_manifest(root)


def test_acceptance_rejects_fake_consumer_that_counts_caught_typeerrors(tmp_path: Path) -> None:
    fake = tmp_path / "fake_typeerror_consumer.py"
    fake.write_text(_FAKE_CONSUMER, encoding="utf-8")
    output = run_isolated_replay(FIXTURE_ROOT, Path(__file__).parent, "fake_typeerror_consumer", tmp_path)
    with pytest.raises(AssertionError, match="core API trace"):
        verify_replay(output["results"], output["trace"])


@pytest.mark.parametrize(
    "mutation",
    ("missing", "extra", "symlink", "directory", "unreadable", "zero", "artifacts_redirect", "sha256_redirect"),
)
def test_acceptance_refuses_unsafe_or_unaccounted_artifacts(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / mutation
    shutil.copytree(FIXTURE_ROOT, root)
    artifact_root = root / "artifacts" / "sha256"
    artifact = next(artifact_root.iterdir())
    if mutation == "missing":
        artifact.unlink()
    elif mutation == "extra":
        (artifact_root / "extra").write_bytes(b"extra")
    elif mutation == "symlink":
        external = tmp_path / "external-artifact"
        external.write_bytes(artifact.read_bytes())
        artifact.unlink()
        os.symlink(external, artifact)
    elif mutation == "directory":
        artifact.unlink()
        artifact.mkdir()
    elif mutation == "unreadable":
        artifact.chmod(0)
    elif mutation == "zero":
        artifact.write_bytes(b"")
    else:
        target = root / ("artifacts" if mutation == "artifacts_redirect" else "artifacts/sha256")
        external = tmp_path / f"external-{mutation}"
        shutil.copytree(target, external)
        shutil.rmtree(target)
        os.symlink(external, target)
    with pytest.raises(AssertionError, match="artifact"):
        validated_manifest(root)


_FAKE_CONSUMER = """from openultrasast.core.factapply import apply_fact
from openultrasast.core.factmatch import validate_fact_match
from openultrasast.core.factpack import validate_fact_pack
from openultrasast.core.factvalidate import validate_fact_relations
def _run_case(case_id):
    for function in (validate_fact_pack, validate_fact_match, apply_fact, validate_fact_relations):
        try:
            function()
        except BaseException:
            pass
def replay_all(root):
    _run_case('complete')
    return {
        'authority_substitution': ('refused', 'match_pack_identity_substituted'),
        'complete': ('passed', None),
        'custody_contamination': ('refused', 'protected_population_contamination'),
        'deterministic_replay': ('passed', None),
        'legacy_projection_only': ('refused', 'name_only_match'),
        'lineage_omission': ('refused', 'matcher_lineage_omitted'),
        'name_only': ('refused', 'missing_observation:receiver'),
        'partial': ('refused', 'missing_observation:arguments'),
        'producer_reviewer_conflict': ('refused', 'self_authored_review_evidence'),
        'resolver_byte_substitution': ('refused', 'resolver_byte_substitution'),
    }
"""
