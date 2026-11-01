"""Closed installed-authority wire and digest-addressed resolver tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.core import canonical, provenance, semantics
from openultrasast.core.factpack import (
    FACT_PACK_SCHEMA,
    FactPack,
    IndependenceAttestation,
    KnowledgeEvidence,
    KnowledgeEvidenceKind,
    RelationEffect,
    ReviewIndependencePolicy,
    SemanticFact,
    StructuralRequirement,
    StructuralRequirementKind,
)
from openultrasast.core.family import family_contract_digest
from openultrasast.mapping.fact_authority import (
    EntryAuthorityBootstrapPolicy,
    EntryFactAuthorityBundle,
    derive_entry_authority_bootstrap_policy_digest,
)
from openultrasast.mapping.installed_fact_authority import (
    DigestDirectoryResolver,
    InstalledAuthorityWireError,
    bootstrap_bytes,
    decode_bootstrap_bytes,
    decode_fact_pack_bytes,
    decode_installed_authority_bytes,
    fact_pack_bytes,
    installed_authority_bytes,
)
from openultrasast.semantic.obligations.core_contract import production_access_control_contract


def _reference(label: str = "artifact") -> canonical.ContentRef:
    digest = canonical.content_digest(label)
    retention = canonical.content_digest("retain")
    receipt = canonical.derive_storage_receipt_digest(
        store_identity="installed-store",
        content_digest=digest,
        byte_length=len(label),
        retention_policy_digest=retention,
    )
    return canonical.ContentRef(label, digest, "application/json", len(label), retention, receipt)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _pack(language: str) -> FactPack:
    contract = production_access_control_contract()
    producer = canonical.content_digest(f"producer:{language}")
    reviewer = canonical.content_digest("reviewer")
    content = _reference(f"evidence:{language}")
    attestation = IndependenceAttestation(
        content.content_digest,
        producer,
        reviewer,
        _reference(f"disclosure:{language}"),
        canonical.content_digest(f"attestation:{language}"),
    )
    evidence = KnowledgeEvidence(
        KnowledgeEvidenceKind.SOURCE_CODE,
        content,
        producer,
        reviewer,
        attestation,
        canonical.content_digest(f"lineage:{language}"),
    )
    fact = SemanticFact(
        f"entry:test:{language}",
        "entry_registration",
        (StructuralRequirement("target", StructuralRequirementKind.QUALIFIED_NAME, "target", ("app", "get")),),
        (RelationEffect(semantics.RelationKind.REGISTRATION, "entry_registration", "framework_instance", "entry_handler", ()),),
    )
    return FactPack(
        FACT_PACK_SCHEMA,
        family_contract_digest(contract),
        contract.family_id,
        "express",
        language,
        (fact,),
        canonical.content_digest(f"pack:{language}"),
        reviewer,
        (evidence,),
        canonical.content_digest(f"review-evidence:{language}"),
        canonical.content_digest("review-policy"),
    )


def _bootstrap() -> EntryAuthorityBootstrapPolicy:
    reviewer = (canonical.content_digest("reviewer"),)
    forbidden = ((canonical.content_digest("bad-producer"), reviewer[0]),)
    stores = ("installed-store",)
    digest = derive_entry_authority_bootstrap_policy_digest(reviewer, forbidden, stores, 4096)
    return EntryAuthorityBootstrapPolicy(reviewer, forbidden, stores, 4096, digest)


def _bundle(packs: tuple[FactPack, ...]) -> EntryFactAuthorityBundle:
    subject = canonical.content_digest("matcher")
    use = provenance.LineageUse(
        provenance.LineagePurpose.MATCHING_BEHAVIOR,
        canonical.content_digest("population"),
        False,
        subject,
        canonical.content_digest("receipt"),
    )
    manifest = provenance.LineageManifest(
        "matcher",
        subject,
        (use,),
        provenance.derive_lineage_manifest_digest("matcher", subject, (use,)),
    )
    custodian = (canonical.content_digest("custodian"),)
    custody = provenance.PopulationCustodyPolicy(
        custodian,
        provenance.derive_population_custody_policy_digest(custodian),
    )
    reviewer = (canonical.content_digest("reviewer"),)
    review_policy = ReviewIndependencePolicy(reviewer, (), ("installed-store",), 4096, canonical.content_digest("policy"))
    review = IndependenceAttestation(
        canonical.content_digest("bundle"),
        canonical.content_digest("producer"),
        reviewer[0],
        _reference("disclosure"),
        canonical.content_digest("attestation"),
    )
    return EntryFactAuthorityBundle(
        production_access_control_contract(),
        packs,
        _reference("projection"),
        (manifest,),
        custody,
        review_policy,
        "matcher-v1",
        subject,
        manifest.manifest_digest,
        review,
        canonical.content_digest("bundle"),
    )


def test_closed_codecs_round_trip_typed_values() -> None:
    packs = (_pack("javascript"), _pack("typescript"))
    bootstrap = _bootstrap()
    bundle = _bundle(packs)

    assert decode_bootstrap_bytes(bootstrap_bytes(bootstrap)) == bootstrap
    assert tuple(decode_fact_pack_bytes(fact_pack_bytes(pack)) for pack in packs) == packs
    encoded = installed_authority_bytes(bundle)
    assert decode_installed_authority_bytes(encoded, packs, bundle.contract) == bundle


@pytest.mark.parametrize("kind", ("unknown", "missing", "noncanonical"))
def test_bootstrap_decoder_refuses_open_or_noncanonical_json(kind: str) -> None:
    content = bootstrap_bytes(_bootstrap())
    raw = json.loads(content)
    if kind == "unknown":
        raw["extra"] = True
        content = _canonical_json(raw)
    elif kind == "missing":
        del raw["policy_digest"]
        content = _canonical_json(raw)
    else:
        content = json.dumps(raw, indent=2).encode()

    with pytest.raises(InstalledAuthorityWireError):
        decode_bootstrap_bytes(content)


def test_pack_decoder_refuses_unknown_nested_fields() -> None:
    content = fact_pack_bytes(_pack("javascript"))
    raw = json.loads(content)
    raw["facts"][0]["structural_requirements"][0]["extra"] = "forbidden"

    with pytest.raises(InstalledAuthorityWireError):
        decode_fact_pack_bytes(_canonical_json(raw))


def test_authority_decoder_requires_fixed_pack_file_order() -> None:
    packs = (_pack("javascript"), _pack("typescript"))
    bundle = _bundle(packs)
    raw = json.loads(installed_authority_bytes(bundle))
    raw["pack_files"].reverse()

    with pytest.raises(InstalledAuthorityWireError, match="pack_files"):
        decode_installed_authority_bytes(_canonical_json(raw), packs, bundle.contract)


def test_resolver_ignores_traversal_like_artifact_id_and_uses_digest(tmp_path: Path) -> None:
    content = b'{"reviewed":true}'
    digest = canonical.bytes_digest(content)
    store = tmp_path / "artifacts" / "sha256"
    store.mkdir(parents=True)
    (store / digest).write_bytes(content)
    retention = canonical.content_digest("retain")
    receipt = canonical.derive_storage_receipt_digest(
        store_identity="installed-store",
        content_digest=digest,
        byte_length=len(content),
        retention_policy_digest=retention,
    )
    reference = canonical.ContentRef("../../outside", digest, "application/json", len(content), retention, receipt)

    resolved = DigestDirectoryResolver(tmp_path, "installed-store").resolve(reference)

    assert resolved.content == content
    assert resolved.receipt.receipt_digest == receipt


def test_resolver_rejects_traversal_like_content_digest_before_read(tmp_path: Path) -> None:
    reference = _reference("logical")
    object.__setattr__(reference, "content_digest", "../../outside")

    with pytest.raises(canonical.ArtifactResolutionError, match="lowercase SHA-256"):
        DigestDirectoryResolver(tmp_path, "installed-store").resolve(reference)


@pytest.mark.parametrize("mutation", ("missing", "bytes", "digest-path"))
def test_resolver_refuses_missing_or_substituted_digest_content(tmp_path: Path, mutation: str) -> None:
    content = b"trusted"
    digest = canonical.bytes_digest(content)
    store = tmp_path / "artifacts" / "sha256"
    store.mkdir(parents=True)
    retention = canonical.content_digest("retain")
    receipt = canonical.derive_storage_receipt_digest(
        store_identity="installed-store",
        content_digest=digest,
        byte_length=len(content),
        retention_policy_digest=retention,
    )
    reference = canonical.ContentRef("logical", digest, "application/json", len(content), retention, receipt)
    if mutation == "bytes":
        (store / digest).write_bytes(b"changed")
    elif mutation == "digest-path":
        (store / digest.upper()).write_bytes(content)

    with pytest.raises(canonical.ArtifactResolutionError):
        DigestDirectoryResolver(tmp_path, "installed-store").resolve(reference)
