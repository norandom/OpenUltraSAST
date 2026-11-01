"""Canonical persistence for structural observations and completed fact matches."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.core import canonical
from openultrasast.core.factmatch import (
    FactMatchEvidence,
    StructuralObservation,
    derive_fact_match_digest,
    fact_match_bytes,
    structural_observation_bytes,
)
from openultrasast.core.semantics import SourceLocation
from openultrasast.mapping import fact_match_store
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter, FactMatchStoreError


def _provisional_reference() -> canonical.ContentRef:
    return canonical.ContentRef("provisional", "0" * 64, "application/json", 0, "0" * 64, "0" * 64)


def _observation() -> StructuralObservation:
    return StructuralObservation(
        "call-target",
        SourceLocation("src/routes.ts", 12, 4, "registerRoute"),
        {"callee": "router.get", "arguments": ("path", "handler")},
        _provisional_reference(),
    )


def _writer(tmp_path: Path) -> FactMatchArtifactWriter:
    return FactMatchArtifactWriter(
        root=tmp_path,
        store_identity="test-fact-match-store",
        retention_policy_digest=canonical.content_digest("retain-reviewed-fact-matches"),
    )


def _match(observation: StructuralObservation) -> FactMatchEvidence:
    provisional = FactMatchEvidence(
        canonical.content_digest("pack"),
        "entry:express:router-call",
        observation.location,
        (observation,),
        "matcher-v2",
        canonical.content_digest("matcher-behavior"),
        canonical.content_digest("matcher-lineage"),
        "0" * 64,
    )
    return replace(provisional, match_digest=derive_fact_match_digest(provisional))


def _digest_path(root: Path, digest: str) -> Path:
    return root / "artifacts" / "sha256" / digest


def test_writer_persists_canonical_observation_and_match_bytes(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    observation_bytes = structural_observation_bytes(provisional)
    assert len(observation_bytes) > 0  # Prove the persistence instrument received nonzero input.

    observation_ref = writer.persist_observation(provisional)
    observation = replace(provisional, evidence=observation_ref)
    match = _match(observation)
    match_ref = writer.persist_match(match)

    assert writer.resolver.resolve(observation_ref).content == structural_observation_bytes(observation)
    assert writer.resolver.resolve(match_ref).content == fact_match_bytes(match)
    assert observation_ref.content_digest == canonical.bytes_digest(observation_bytes)
    assert match_ref.content_digest == match.match_digest
    assert _digest_path(tmp_path, observation_ref.content_digest).read_bytes() == observation_bytes
    assert _digest_path(tmp_path, match_ref.content_digest).read_bytes() == fact_match_bytes(match)


def test_match_reference_is_not_inserted_into_its_own_digest(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    observation = replace(provisional, evidence=writer.persist_observation(provisional))
    match = _match(observation)

    match_ref = writer.persist_match(match)

    assert derive_fact_match_digest(match) == match.match_digest
    assert canonical.bytes_digest(fact_match_bytes(match)) == match_ref.content_digest
    assert match_ref.artifact_id.encode() not in fact_match_bytes(match)


def test_match_is_refused_until_observation_reference_exists(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    content = structural_observation_bytes(_observation())
    digest = canonical.bytes_digest(content)
    receipt = canonical.derive_storage_receipt_digest(
        store_identity=writer.store_identity,
        content_digest=digest,
        byte_length=len(content),
        retention_policy_digest=writer.retention_policy_digest,
    )
    missing = canonical.ContentRef(
        f"structural-observation:{digest}",
        digest,
        "application/json",
        len(content),
        writer.retention_policy_digest,
        receipt,
    )

    with pytest.raises(FactMatchStoreError, match="observation reference cannot be validated"):
        writer.persist_match(_match(replace(_observation(), evidence=missing)))


def test_writer_refuses_substituted_observation_bytes(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    observation_ref = writer.persist_observation(provisional)
    _digest_path(tmp_path, observation_ref.content_digest).write_bytes(b'{"substituted":true}')

    with pytest.raises(FactMatchStoreError, match="observation reference cannot be validated"):
        writer.persist_match(_match(replace(provisional, evidence=observation_ref)))
    with pytest.raises(FactMatchStoreError, match="digest path contains substituted bytes"):
        writer.persist_observation(provisional)


def test_writer_refuses_substituted_observation_reference(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    observation_ref = writer.persist_observation(provisional)
    substituted_ref = replace(observation_ref, storage_receipt_digest="f" * 64)
    substituted = replace(provisional, evidence=substituted_ref)

    with pytest.raises(FactMatchStoreError, match="does not equal canonical persisted reference"):
        writer.persist_match(_match(substituted))


def _replace_reference_field(reference: canonical.ContentRef, field: str) -> canonical.ContentRef:
    replacements: dict[str, object] = {
        "artifact_id": "structural-observation:substituted",
        "media_type": "application/octet-stream",
        "content_digest": canonical.content_digest("substituted-content"),
        "byte_length": reference.byte_length + 1,
        "retention_policy_digest": canonical.content_digest("substituted-retention"),
        "storage_receipt_digest": canonical.content_digest("substituted-receipt"),
    }
    return replace(reference, **{field: replacements[field]})


@pytest.mark.parametrize(
    "field",
    (
        "artifact_id",
        "media_type",
        "content_digest",
        "byte_length",
        "retention_policy_digest",
        "storage_receipt_digest",
    ),
)
def test_writer_refuses_every_observation_reference_field_substitution(tmp_path: Path, field: str) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    reference = writer.persist_observation(provisional)
    substituted = replace(provisional, evidence=_replace_reference_field(reference, field))
    redigested_match = _match(substituted)

    with pytest.raises(FactMatchStoreError, match="does not equal canonical persisted reference"):
        writer.persist_match(redigested_match)


def test_writer_refuses_reference_to_other_valid_observation(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    expected = _observation()
    other = replace(expected, observed={"callee": "router.post"})
    other_ref = writer.persist_observation(other)
    substituted = replace(expected, evidence=other_ref)

    with pytest.raises(FactMatchStoreError, match="does not equal canonical persisted reference"):
        writer.persist_match(_match(substituted))


def test_writer_refuses_noncanonical_match_identity(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    provisional = _observation()
    observation = replace(provisional, evidence=writer.persist_observation(provisional))
    match = replace(_match(observation), match_digest="f" * 64)

    with pytest.raises(FactMatchStoreError, match="match digest cannot be re-derived"):
        writer.persist_match(match)


def test_content_path_uses_digest_and_not_artifact_id(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    reference = writer.persist_observation(_observation())

    assert reference.artifact_id.startswith("structural-observation:")
    assert _digest_path(tmp_path, reference.content_digest).is_file()
    assert not (tmp_path / reference.artifact_id).exists()


def test_concurrent_writers_install_one_complete_same_digest_artifact(tmp_path: Path) -> None:
    provisional = _observation()
    expected = structural_observation_bytes(provisional)

    def persist(_: int) -> canonical.ContentRef:
        return _writer(tmp_path).persist_observation(provisional)

    with ThreadPoolExecutor(max_workers=8) as executor:
        references = tuple(executor.map(persist, range(32)))

    assert len(set(references)) == 1
    reference = references[0]
    store = tmp_path / "artifacts" / "sha256"
    assert _digest_path(tmp_path, reference.content_digest).read_bytes() == expected
    assert tuple(store.iterdir()) == (_digest_path(tmp_path, reference.content_digest),)


@pytest.mark.parametrize("failure_point", ("write", "link"))
def test_atomic_install_cleans_temporary_file_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    writer = _writer(tmp_path)
    content = structural_observation_bytes(_observation())
    target = _digest_path(tmp_path, canonical.bytes_digest(content))

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"injected {failure_point} failure")

    attribute = "fsync" if failure_point == "write" else "link"
    monkeypatch.setattr(fact_match_store.os, attribute, fail)

    with pytest.raises(FactMatchStoreError, match="canonical artifact could not be persisted"):
        writer.persist_observation(_observation())

    store = target.parent
    assert not target.exists()
    assert not store.exists() or tuple(store.iterdir()) == ()
