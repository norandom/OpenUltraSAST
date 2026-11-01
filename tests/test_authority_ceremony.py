"""Approved repo-local identities for installed entry-fact authority."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_fact_authority import _case

from openultrasast.core import canonical, provenance
from openultrasast.core.factpack import (
    derive_review_evidence_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.mapping.authority_ceremony import (
    APPROVED_IDENTITY_MANIFESTS,
    INSTALLED_ARTIFACT_STORE_IDENTITY,
    AuthorityCeremonyError,
    InstalledAuthorityCeremony,
    decode_identity_manifest_bytes,
    identity_manifest_bytes,
    load_installed_authority_ceremony,
    validate_authority_ceremony_bindings,
)
from openultrasast.mapping.fact_authority import EntryFactAuthorityBundle
from openultrasast.mapping.installed_fact_authority import decode_bootstrap_bytes

_ENTRIES = Path(__file__).parents[1] / "src" / "openultrasast" / "ruleset" / "entries"


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _bound_bundle(ceremony: InstalledAuthorityCeremony) -> EntryFactAuthorityBundle:
    bundle = _case().bundle
    producer = ceremony.producer.identity_digest
    reviewer = ceremony.reviewer.identity_digest
    custodian = ceremony.custodian.identity_digest
    packs = []
    for pack in bundle.packs:
        evidence = tuple(
            replace(
                item,
                producer_identity=producer,
                reviewer_identity=reviewer,
                independence=replace(
                    item.independence,
                    producer_identity=producer,
                    reviewer_identity=reviewer,
                ),
            )
            for item in pack.review_evidence
        )
        packs.append(
            replace(
                pack,
                review_identity=reviewer,
                review_evidence=evidence,
                review_evidence_digest=derive_review_evidence_digest(evidence),
            )
        )
    custody = provenance.PopulationCustodyPolicy(
        (custodian,),
        provenance.derive_population_custody_policy_digest((custodian,)),
    )
    stores = ceremony.bootstrap.trusted_store_identities
    policy = replace(
        bundle.review_policy,
        reviewed_reviewer_digests=(reviewer,),
        trusted_store_identities=stores,
    )
    policy = replace(
        policy,
        policy_digest=derive_review_independence_policy_digest(
            policy.reviewed_reviewer_digests,
            policy.forbidden_identity_pairs,
            policy.trusted_store_identities,
            policy.maximum_evidence_bytes,
        ),
    )
    packs = [replace(pack, review_policy_digest=policy.policy_digest) for pack in packs]
    return replace(
        bundle,
        packs=tuple(packs),
        custody_policy=custody,
        review_policy=policy,
        authority_review=replace(
            bundle.authority_review,
            producer_identity=producer,
            reviewer_identity=reviewer,
        ),
    )


def test_installed_ceremony_loads_canonical_nonempty_records() -> None:
    paths = (
        _ENTRIES / "identities" / "generator.json",
        _ENTRIES / "identities" / "maintainer-reviewer.json",
        _ENTRIES / "identities" / "custodian.json",
        _ENTRIES / "bootstrap.json",
    )
    assert all(path.stat().st_size > 0 for path in paths)

    ceremony = load_installed_authority_ceremony(_ENTRIES)

    assert (ceremony.producer, ceremony.reviewer, ceremony.custodian) == APPROVED_IDENTITY_MANIFESTS
    assert ceremony.bootstrap == decode_bootstrap_bytes((_ENTRIES / "bootstrap.json").read_bytes())
    assert ceremony.bootstrap.reviewed_bundle_reviewer_digests == (ceremony.reviewer.identity_digest,)
    assert ceremony.bootstrap.trusted_store_identities == (INSTALLED_ARTIFACT_STORE_IDENTITY,)


@pytest.mark.parametrize("mutation", ("unknown", "missing", "whitespace"))
def test_identity_decoder_rejects_open_or_noncanonical_records(mutation: str) -> None:
    raw = json.loads(identity_manifest_bytes(APPROVED_IDENTITY_MANIFESTS[0]))
    if mutation == "unknown":
        raw["extra"] = "not-approved"
        content = _canonical_json(raw)
    elif mutation == "missing":
        del raw["approval_basis"]
        content = _canonical_json(raw)
    else:
        content = json.dumps(raw, indent=2).encode()

    with pytest.raises(AuthorityCeremonyError):
        decode_identity_manifest_bytes(content)


def test_identity_decoder_rejects_changed_schema_field() -> None:
    raw = json.loads(identity_manifest_bytes(APPROVED_IDENTITY_MANIFESTS[0]))
    raw["schema_version"] = "openultrasast.access-control.authority-identity.changed"

    with pytest.raises(AuthorityCeremonyError):
        decode_identity_manifest_bytes(_canonical_json(raw))


def test_synthetic_authority_and_pack_identities_bind_to_ceremony() -> None:
    ceremony = load_installed_authority_ceremony(_ENTRIES)

    validate_authority_ceremony_bindings(ceremony, _bound_bundle(ceremony))


@pytest.mark.parametrize(
    ("part", "field"),
    (
        ("producer", "name"),
        ("producer", "role"),
        ("producer", "approval_basis"),
        ("reviewer", "name"),
        ("reviewer", "role"),
        ("reviewer", "approval_basis"),
        ("custodian", "name"),
        ("custodian", "role"),
        ("custodian", "approval_basis"),
    ),
)
def test_changed_identity_field_changes_digest_and_invalidates_binding(part: str, field: str) -> None:
    ceremony = load_installed_authority_ceremony(_ENTRIES)
    bundle = _bound_bundle(ceremony)
    manifest = getattr(ceremony, part)
    changed = replace(manifest, **{field: f"changed-{getattr(manifest, field)}"})
    decoded = decode_identity_manifest_bytes(identity_manifest_bytes(changed))
    changed_ceremony = replace(ceremony, **{part: decoded})

    assert decoded.identity_digest != manifest.identity_digest
    with pytest.raises(AuthorityCeremonyError, match="identity binding"):
        validate_authority_ceremony_bindings(changed_ceremony, bundle)


@pytest.mark.parametrize(
    "binding",
    (
        "bootstrap",
        "bootstrap-store",
        "review-policy-reviewer",
        "review-policy-store",
        "custody",
        "authority-producer",
        "authority-reviewer",
        "pack-producer",
        "pack-reviewer",
    ),
)
def test_every_ceremony_binding_is_required(binding: str) -> None:
    ceremony = load_installed_authority_ceremony(_ENTRIES)
    bundle = _bound_bundle(ceremony)
    other = canonical.content_digest(f"other-{binding}")
    if binding == "bootstrap":
        changed = replace(ceremony.bootstrap, reviewed_bundle_reviewer_digests=(other,))
        ceremony = replace(ceremony, bootstrap=changed)
    elif binding == "bootstrap-store":
        changed = replace(ceremony.bootstrap, trusted_store_identities=("other-store",))
        ceremony = replace(ceremony, bootstrap=changed)
    elif binding == "review-policy-reviewer":
        bundle = replace(bundle, review_policy=replace(bundle.review_policy, reviewed_reviewer_digests=(other,)))
    elif binding == "review-policy-store":
        bundle = replace(bundle, review_policy=replace(bundle.review_policy, trusted_store_identities=("other-store",)))
    elif binding == "custody":
        bundle = replace(bundle, custody_policy=replace(bundle.custody_policy, reviewed_custodian_digests=(other,)))
    elif binding.startswith("authority-"):
        field = binding.removeprefix("authority-") + "_identity"
        bundle = replace(bundle, authority_review=replace(bundle.authority_review, **{field: other}))
    else:
        field = binding.removeprefix("pack-") + "_identity"
        pack = bundle.packs[0]
        evidence = replace(pack.review_evidence[0], **{field: other})
        bundle = replace(bundle, packs=(replace(pack, review_evidence=(evidence,)), *bundle.packs[1:]))

    with pytest.raises(AuthorityCeremonyError, match="identity binding"):
        validate_authority_ceremony_bindings(ceremony, bundle)
