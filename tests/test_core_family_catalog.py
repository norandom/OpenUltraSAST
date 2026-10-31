"""Exact family-catalog resolution and capability declaration contracts."""

from dataclasses import replace
from typing import cast

import pytest

import openultrasast.core.canonical as canonical
import openultrasast.core.evidence as evidence
import openultrasast.core.family as family
import openultrasast.core.family_catalog as catalog
import openultrasast.core.semantics as semantics


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _contract(
    family_id: str = "obligation",
    family_version: str = "1.0.0",
    schema_version: str = evidence.EVIDENCE_PACKET_SCHEMA,
    ecosystems: tuple[str, ...] = ("python",),
) -> family.FamilyContract:
    role = family.RoleSpec(
        "operation",
        (family.FieldSpec("operation", semantics.FieldKind.TEXT, True),),
        (semantics.RelationKind.OPERATION_EFFECT,),
        family.RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
    )
    return family.FamilyContract(
        family_id,
        family_version,
        schema_version,
        ecosystems,
        family.ObjectSpec(
            "operation",
            (family.FieldSpec("operation", semantics.FieldKind.TEXT, True),),
            ("operation",),
        ),
        (role,),
        (
            family.DecisionRule(
                "unsafe",
                evidence.NeutralOutcome.VIOLATION,
                ("operation",),
                (semantics.RelationStatus.COMPLETE,),
            ),
            family.DecisionRule(
                "unknown",
                evidence.NeutralOutcome.INDETERMINATE,
                ("operation",),
                (
                    semantics.RelationStatus.COMPLETE,
                    semantics.RelationStatus.INCOMPLETE,
                    semantics.RelationStatus.UNRESOLVED,
                ),
            ),
        ),
        (family.ResidualQuestion("operation-known", ("operation",), ("unsafe", "unknown")),),
        ("missing_operation", "unsupported_scope"),
    )


def _entry(contract: family.FamilyContract) -> catalog.FamilyCatalogEntry:
    return catalog.FamilyCatalogEntry(contract, family.family_contract_digest(contract))


def _catalog(*contracts: family.FamilyContract) -> catalog.FamilyCatalog:
    entries = tuple(sorted((_entry(contract) for contract in contracts), key=catalog.catalog_entry_key))
    return catalog.FamilyCatalog(entries, catalog.derive_catalog_digest(entries))


def _capability(contract: family.FamilyContract) -> catalog.FamilyCapabilityDeclaration:
    return catalog.FamilyCapabilityDeclaration(
        "obligation-arm",
        family.family_contract_digest(contract),
        _digest("readiness fixtures"),
        _digest("development population"),
        _digest("admission boundary"),
    )


def test_catalog_rederives_contract_and_catalog_digests() -> None:
    contract = _contract()
    value = _catalog(contract)
    catalog.validate_catalog(value)
    assert value.entries[0].contract_digest == family.family_contract_digest(contract)
    assert value.catalog_digest == catalog.derive_catalog_digest(value.entries)


def test_catalog_requires_canonical_entry_order() -> None:
    first = _contract("alpha")
    second = _contract("zeta")
    entries = (_entry(second), _entry(first))
    with pytest.raises(catalog.FamilyCatalogError, match="canonical order"):
        catalog.FamilyCatalog(entries, catalog.derive_catalog_digest(tuple(reversed(entries))))


def test_catalog_refuses_duplicate_contract_identity_and_digest() -> None:
    contract = _contract()
    entry = _entry(contract)
    with pytest.raises(catalog.FamilyCatalogError, match="duplicate family contract identity"):
        catalog.FamilyCatalog((entry, entry), _digest("catalog"))
    duplicate_digest = _entry(_contract("other"))
    object.__setattr__(duplicate_digest, "contract_digest", entry.contract_digest)
    entries = tuple(sorted((entry, duplicate_digest), key=catalog.catalog_entry_key))
    with pytest.raises(catalog.FamilyCatalogError, match="duplicate contract digest"):
        catalog.FamilyCatalog(entries, _digest("catalog"))


def test_catalog_refuses_substituted_contract_and_catalog_digest() -> None:
    contract = _contract()
    with pytest.raises(catalog.FamilyCatalogError, match="contract digest"):
        catalog.FamilyCatalogEntry(contract, _digest("substituted"))
    value = _catalog(contract)
    with pytest.raises(catalog.FamilyCatalogError, match="catalog digest"):
        catalog.FamilyCatalog(value.entries, _digest("substituted catalog"))


def test_catalog_identity_includes_family_version_and_schema() -> None:
    contracts = (
        _contract(family_version="1.0.0"),
        _contract(family_version="2.0.0"),
        _contract(family_version="3.0.0", schema_version="evidence-v3"),
    )
    value = _catalog(*contracts)
    assert len(value.entries) == 3
    catalog.validate_catalog(value)


def test_catalog_collections_are_immutable_tuples() -> None:
    value = _catalog(_contract())
    with pytest.raises(catalog.FamilyCatalogError, match="entries"):
        replace(value, entries=cast(tuple[catalog.FamilyCatalogEntry, ...], list(value.entries)))


def test_resolve_contract_requires_exact_family_digest_and_ecosystem() -> None:
    python = _contract("obligation", ecosystems=("python",))
    java = _contract("taint", ecosystems=("java",))
    value = _catalog(python, java)
    assert catalog.resolve_contract(value, "obligation", family.family_contract_digest(python), "python") is python
    for family_id, digest, ecosystem in (
        ("missing", family.family_contract_digest(python), "python"),
        ("obligation", family.family_contract_digest(java), "python"),
        ("obligation", family.family_contract_digest(python), "java"),
    ):
        with pytest.raises(catalog.FamilyCatalogResolutionError, match="exact"):
            catalog.resolve_contract(value, family_id, digest, ecosystem)


def test_resolution_never_falls_back_to_another_version() -> None:
    first = _contract(family_version="1.0.0")
    second = _contract(family_version="2.0.0")
    value = _catalog(first, second)
    assert (
        catalog.resolve_contract(
            value,
            first.family_id,
            family.family_contract_digest(second),
            "python",
        )
        is second
    )
    with pytest.raises(catalog.FamilyCatalogResolutionError, match="exact"):
        catalog.resolve_contract(value, first.family_id, _digest("unknown version"), "python")


def test_capability_names_exact_catalog_contract_and_boundaries() -> None:
    contract = _contract()
    value = _catalog(contract)
    capability = _capability(contract)
    catalog.validate_capability(capability, value)
    assert capability.family_contract_digest == value.entries[0].contract_digest


@pytest.mark.parametrize(
    "field",
    (
        "family_contract_digest",
        "readiness_fixture_digest",
        "development_population_digest",
        "admission_boundary_digest",
    ),
)
@pytest.mark.parametrize("bad", ("", "not-a-digest", "A" * 64, None))
def test_capability_refuses_every_missing_or_corrupt_digest(field: str, bad: object) -> None:
    capability = _capability(_contract())
    with pytest.raises((catalog.FamilyCapabilityError, canonical.DigestFormatError), match="digest"):
        _replace_capability_digest(capability, field, cast(str, bad))


def _replace_capability_digest(
    capability: catalog.FamilyCapabilityDeclaration,
    field: str,
    value: str,
) -> catalog.FamilyCapabilityDeclaration:
    if field == "family_contract_digest":
        return replace(capability, family_contract_digest=value)
    if field == "readiness_fixture_digest":
        return replace(capability, readiness_fixture_digest=value)
    if field == "development_population_digest":
        return replace(capability, development_population_digest=value)
    return replace(capability, admission_boundary_digest=value)


@pytest.mark.parametrize("bad", ("", 7, None))
def test_capability_requires_nonempty_text_arm_id(bad: object) -> None:
    capability = _capability(_contract())
    with pytest.raises(catalog.FamilyCapabilityError, match="arm_id"):
        replace(capability, arm_id=cast(str, bad))


def test_capability_refuses_contract_substitution() -> None:
    contract = _contract()
    other = _contract("other")
    value = _catalog(contract, other)
    capability = _capability(contract)
    catalog.validate_capability(capability, value)
    substituted = replace(capability, family_contract_digest=_digest("not in catalog"))
    with pytest.raises(catalog.FamilyCapabilityError, match="catalog"):
        catalog.validate_capability(substituted, value)


@pytest.mark.parametrize("bad", ("", 7, None))
def test_capability_validator_rechecks_tampered_arm_id(bad: object) -> None:
    contract = _contract()
    value = _catalog(contract)
    capability = _capability(contract)
    object.__setattr__(capability, "arm_id", bad)
    with pytest.raises(catalog.FamilyCapabilityError, match="arm_id"):
        catalog.validate_capability(capability, value)


@pytest.mark.parametrize(
    "field",
    (
        "family_contract_digest",
        "readiness_fixture_digest",
        "development_population_digest",
        "admission_boundary_digest",
    ),
)
@pytest.mark.parametrize("bad", ("", 7, None, "not-a-digest", "A" * 64))
def test_capability_validator_rechecks_every_tampered_digest(field: str, bad: object) -> None:
    contract = _contract()
    value = _catalog(contract)
    capability = _capability(contract)
    object.__setattr__(capability, field, bad)
    with pytest.raises(catalog.FamilyCapabilityError, match="digest"):
        catalog.validate_capability(capability, value)


def test_catalog_digest_covers_contract_identity_and_content() -> None:
    contract = _contract()
    changed = replace(contract, indeterminate_reasons=contract.indeterminate_reasons + ("new_reason",))
    assert _catalog(contract).catalog_digest != _catalog(changed).catalog_digest
