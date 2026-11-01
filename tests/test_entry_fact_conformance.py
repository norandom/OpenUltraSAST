"""Immutable downstream conformance handoff for detection-core Task 9.4."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from openultrasast.core import canonical
from openultrasast.mapping.entry_fact_conformance import (
    ENTRY_FACT_CONFORMANCE_SCHEMA,
    EntryFactConformanceError,
    build_entry_fact_conformance,
    write_entry_fact_conformance,
)
from openultrasast.mapping.entry_fact_conformance_manifest import validate_entry_fact_conformance

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "access_control" / "conformance" / "v1"
EXPECTED_CASES = {
    "complete",
    "name_only",
    "partial",
    "authority_substitution",
    "producer_reviewer_conflict",
    "resolver_byte_substitution",
    "lineage_omission",
    "custody_contamination",
    "legacy_projection_only",
    "deterministic_replay",
}
EXPECTED_VALIDATORS = {
    "openultrasast.core.factpack.validate_fact_pack",
    "openultrasast.core.factmatch.validate_fact_match",
    "openultrasast.core.factapply.apply_fact",
    "openultrasast.core.factvalidate.validate_fact_relations",
}


def _freeze(value: object) -> object:
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, dict):
        return {key: _freeze(item) for key, item in value.items()}
    return value


def _parsed(content: bytes) -> dict[str, object]:
    parsed = json.loads(content)
    assert isinstance(parsed, dict)
    assert (
        canonical.canonical_record_bytes(
            _freeze(parsed),
            known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,),
        )
        == content
    )
    return parsed


def _assert_materialized(cases: list[dict[str, object]], root: Path) -> None:
    for case in cases:
        content = (FIXTURE_ROOT / case["fixture_path"]).read_bytes()
        assert len(content) == case["fixture_byte_length"] > 0
        assert canonical.bytes_digest(content) == case["fixture_digest"]
        assert case["validators"]
        for artifact in case["artifacts"]:
            artifact_content = (root / artifact["path"]).read_bytes()
            assert len(artifact_content) == artifact["byte_length"] > 0
            assert canonical.bytes_digest(artifact_content) == artifact["content_digest"]
    declared = {artifact["path"] for case in cases for artifact in case["artifacts"]}
    materialized = {path.relative_to(root).as_posix() for path in (root / "artifacts" / "sha256").iterdir()}
    assert declared == materialized


def _assert_downstream_results(cases: list[dict[str, object]]) -> None:
    authority = next(case for case in cases if case["case_id"] == "authority_substitution")
    conflict = next(case for case in cases if case["case_id"] == "producer_reviewer_conflict")
    name = "openultrasast.mapping.fact_authority.authenticate_entry_fact_authority"
    assert authority["downstream_validators"] == [{"name": name, "status": "refused", "reason": "authority_bundle_digest_substituted"}]
    assert conflict["downstream_validators"] == [{"name": name, "status": "refused", "reason": "producer_reviewer_conflict"}]
    excluded = {"authority_substitution", "producer_reviewer_conflict"}
    assert all(not case["downstream_validators"] for case in cases if case["case_id"] not in excluded)


def test_handoff_is_canonical_complete_and_reproducible(tmp_path: Path) -> None:
    first = build_entry_fact_conformance(FIXTURE_ROOT, tmp_path / "first")
    second = build_entry_fact_conformance(FIXTURE_ROOT, tmp_path / "second")

    assert first == second
    manifest = _parsed(first)
    assert set(manifest) == {
        "schema_version",
        "handoff_digest",
        "core_entry_points",
        "cases",
    }
    assert set(manifest["core_entry_points"]) == EXPECTED_VALIDATORS
    cases = manifest["cases"]
    assert isinstance(cases, list)
    assert {case["case_id"] for case in cases} == EXPECTED_CASES
    assert (
        canonical.content_digest(
            {
                "schema_version": manifest["schema_version"],
                "core_entry_points": tuple(manifest["core_entry_points"]),
                "cases": _freeze(cases),
            }
        )
        == manifest["handoff_digest"]
    )
    _assert_materialized(cases, tmp_path / "first")
    complete = next(case for case in cases if case["case_id"] == "complete")
    assert {row["name"] for row in complete["validators"]} == EXPECTED_VALIDATORS
    assert {row["status"] for row in complete["validators"]} == {"passed"}
    assert complete["reason"] is None
    _assert_downstream_results(cases)
    refused = [case for case in cases if case["case_id"] not in {"complete", "deterministic_replay"}]
    assert all(case["expected_status"] == "refused" and case["reason"] for case in refused)


def test_checked_in_handoff_equals_fresh_generation(tmp_path: Path) -> None:
    generated = write_entry_fact_conformance(FIXTURE_ROOT, tmp_path / "fresh")
    checked_in = FIXTURE_ROOT / "manifest.json"

    assert generated.read_bytes() == checked_in.read_bytes()
    validate_entry_fact_conformance(checked_in.read_bytes(), FIXTURE_ROOT)
    manifest = _parsed(checked_in.read_bytes())
    declared = {artifact["path"] for case in manifest["cases"] for artifact in case["artifacts"]}
    materialized = {path.relative_to(FIXTURE_ROOT).as_posix() for path in (FIXTURE_ROOT / "artifacts" / "sha256").iterdir()}
    assert declared == materialized


def test_manifest_refuses_open_schema_and_digest_substitution(tmp_path: Path) -> None:
    content = build_entry_fact_conformance(FIXTURE_ROOT, tmp_path / "output")
    manifest = json.loads(content)
    manifest["cases"][0]["artifacts"][0]["unexpected"] = True
    opened = canonical.canonical_record_bytes(
        _freeze(manifest),
        known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,),
    )
    with pytest.raises(EntryFactConformanceError, match="unknown or missing fields"):
        validate_entry_fact_conformance(opened)

    manifest = json.loads(content)
    manifest["handoff_digest"] = "0" * 64
    substituted = canonical.canonical_record_bytes(
        _freeze(manifest),
        known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,),
    )
    with pytest.raises(EntryFactConformanceError, match="cannot be re-derived"):
        validate_entry_fact_conformance(substituted)


def test_manifest_refuses_bogus_entry_point_and_fabricated_case_result(tmp_path: Path) -> None:
    content = build_entry_fact_conformance(FIXTURE_ROOT, tmp_path / "output")

    def redigest(manifest: dict[str, object]) -> bytes:
        manifest["handoff_digest"] = canonical.content_digest(
            {
                "schema_version": manifest["schema_version"],
                "core_entry_points": tuple(manifest["core_entry_points"]),
                "cases": _freeze(manifest["cases"]),
            }
        )
        return canonical.canonical_record_bytes(_freeze(manifest), known_schema_versions=(ENTRY_FACT_CONFORMANCE_SCHEMA,))

    bogus = json.loads(content)
    bogus["core_entry_points"][0] = "openultrasast.core.fake.accept_everything"
    with pytest.raises(EntryFactConformanceError, match="exact replay set"):
        validate_entry_fact_conformance(redigest(bogus))

    fabricated = json.loads(content)
    complete = next(case for case in fabricated["cases"] if case["case_id"] == "complete")
    complete["expected_status"] = "refused"
    complete["reason"] = "fabricated"
    complete["validators"][0]["status"] = "refused"
    complete["validators"][0]["reason"] = "fabricated"
    with pytest.raises(EntryFactConformanceError, match="matrix|enclosing case"):
        validate_entry_fact_conformance(redigest(fabricated))

    downstream = json.loads(content)
    authority = next(case for case in downstream["cases"] if case["case_id"] == "authority_substitution")
    authority["downstream_validators"][0]["reason"] = "fabricated"
    with pytest.raises(EntryFactConformanceError, match="downstream validator matrix"):
        validate_entry_fact_conformance(redigest(downstream))


@pytest.mark.parametrize("mutation", ("extra", "extra_directory", "missing", "non_file"))
def test_manifest_requires_exact_regular_source_census(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / mutation
    shutil.copytree(FIXTURE_ROOT, root)
    if mutation == "extra":
        (root / "sources" / "undeclared.js").write_text("export const extra = true;\n", encoding="utf-8")
    elif mutation == "extra_directory":
        (root / "sources" / "undeclared").mkdir()
    elif mutation == "missing":
        (root / "sources" / "partial.js").unlink()
    else:
        target = root / "sources" / "partial.js"
        target.unlink()
        target.mkdir()

    with pytest.raises(EntryFactConformanceError, match="source filesystem census"):
        validate_entry_fact_conformance((root / "manifest.json").read_bytes(), root)


@pytest.mark.parametrize("declared", (False, True))
def test_manifest_refuses_source_symlinks(tmp_path: Path, declared: bool) -> None:
    root = tmp_path / "source-symlink"
    shutil.copytree(FIXTURE_ROOT, root)
    external = tmp_path / "external.js"
    external.write_bytes((root / "sources" / "partial.js").read_bytes())
    target = root / "sources" / ("partial.js" if declared else "undeclared.js")
    if declared:
        target.unlink()
    os.symlink(external, target)

    with pytest.raises(EntryFactConformanceError, match="source filesystem census"):
        validate_entry_fact_conformance((root / "manifest.json").read_bytes(), root)


@pytest.mark.parametrize("entry_kind", ("directory", "symlink"))
def test_manifest_refuses_extra_artifact_entries(tmp_path: Path, entry_kind: str) -> None:
    root = tmp_path / "artifact-entry"
    shutil.copytree(FIXTURE_ROOT, root)
    target = root / "artifacts" / "sha256" / "unexpected"
    if entry_kind == "directory":
        target.mkdir()
    else:
        external = tmp_path / "external-artifact"
        external.write_bytes(b"external")
        os.symlink(external, target)

    with pytest.raises(EntryFactConformanceError, match="artifact filesystem census"):
        validate_entry_fact_conformance((root / "manifest.json").read_bytes(), root)


def test_manifest_refuses_declared_artifact_symlink_to_identical_bytes(tmp_path: Path) -> None:
    root = tmp_path / "artifact-symlink"
    shutil.copytree(FIXTURE_ROOT, root)
    manifest = json.loads((root / "manifest.json").read_bytes())
    relative = manifest["cases"][0]["artifacts"][0]["path"]
    target = root / relative
    external = tmp_path / "identical-artifact"
    external.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(external, target)

    with pytest.raises(EntryFactConformanceError, match="artifact filesystem census"):
        validate_entry_fact_conformance((root / "manifest.json").read_bytes(), root)


@pytest.mark.parametrize("directory", ("sources", "artifacts", "artifacts/sha256"))
def test_manifest_refuses_symlinked_census_root(tmp_path: Path, directory: str) -> None:
    root = tmp_path / "redirected-root"
    shutil.copytree(FIXTURE_ROOT, root)
    target = root / directory
    external = tmp_path / directory.replace("/", "-")
    shutil.copytree(target, external)
    shutil.rmtree(target)
    os.symlink(external, target)
    reason = "source filesystem census" if directory == "sources" else "artifact filesystem census"

    with pytest.raises(EntryFactConformanceError, match=reason):
        validate_entry_fact_conformance((root / "manifest.json").read_bytes(), root)


def test_builder_refuses_declared_source_symlink(tmp_path: Path) -> None:
    root = tmp_path / "builder-source"
    shutil.copytree(FIXTURE_ROOT, root)
    target = root / "sources" / "complete.js"
    external = tmp_path / "builder-external.js"
    external.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(external, target)

    with pytest.raises(EntryFactConformanceError, match="nonempty readable fixture"):
        build_entry_fact_conformance(root, tmp_path / "builder-output")


def test_builder_refuses_symlinked_source_root(tmp_path: Path) -> None:
    root = tmp_path / "builder-source-root"
    shutil.copytree(FIXTURE_ROOT, root)
    external = tmp_path / "external-sources"
    shutil.copytree(root / "sources", external)
    shutil.rmtree(root / "sources")
    os.symlink(external, root / "sources")

    with pytest.raises(EntryFactConformanceError, match="real non-symlink directory"):
        build_entry_fact_conformance(root, tmp_path / "builder-output")


def test_builder_refuses_existing_digest_symlink(tmp_path: Path) -> None:
    output = tmp_path / "builder-artifacts"
    build_entry_fact_conformance(FIXTURE_ROOT, output)
    target = next((output / "artifacts" / "sha256").iterdir())
    external = tmp_path / "builder-identical-artifact"
    external.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(external, target)

    with pytest.raises(EntryFactConformanceError, match="artifact.*regular|unsafe"):
        build_entry_fact_conformance(FIXTURE_ROOT, output)


def test_builder_refuses_symlinked_artifact_root(tmp_path: Path) -> None:
    output = tmp_path / "builder-artifact-root"
    (output / "artifacts").mkdir(parents=True)
    external = tmp_path / "external-artifacts"
    external.mkdir()
    os.symlink(external, output / "artifacts" / "sha256")

    with pytest.raises(EntryFactConformanceError, match="artifact.*regular|unsafe"):
        build_entry_fact_conformance(FIXTURE_ROOT, output)


def test_builder_refuses_symlinked_artifacts_directory(tmp_path: Path) -> None:
    output = tmp_path / "builder-artifacts-directory"
    output.mkdir()
    external = tmp_path / "external-artifacts-directory"
    (external / "sha256").mkdir(parents=True)
    os.symlink(external, output / "artifacts")

    with pytest.raises(EntryFactConformanceError, match="artifact.*regular|unsafe"):
        build_entry_fact_conformance(FIXTURE_ROOT, output)


def test_unreadable_or_empty_fixture_fails_before_validator_results(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixtures"
    sources = fixture_root / "sources"
    sources.mkdir(parents=True)
    for name in ("complete.js", "name-only.js", "partial.js", "legacy-only.js"):
        (sources / name).write_bytes(b"" if name == "complete.js" else b"x")

    with pytest.raises(EntryFactConformanceError, match="nonempty readable fixture"):
        build_entry_fact_conformance(fixture_root, tmp_path / "output")


def test_isolated_consumer_replays_without_mapping_or_target_imports() -> None:
    script = """
import importlib.abc
import pathlib
import sys
class BlockTargetImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('openultrasast.mapping', 'openultrasast.semantic')):
            raise ImportError(f'forbidden target import: {fullname}')
        return None
sys.meta_path.insert(0, BlockTargetImports())
sys.path.insert(0, sys.argv[2])
sys.path.insert(0, sys.argv[3])
from entry_fact_core_consumer import replay_all
results = replay_all(pathlib.Path(sys.argv[1]))
assert len(results) == 10
print('isolated-core-replay=10')
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(FIXTURE_ROOT),
            str(Path(__file__).parent),
            str(Path(__file__).parents[1] / "src"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "isolated-core-replay=10"
