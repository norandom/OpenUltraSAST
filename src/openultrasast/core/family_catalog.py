"""Exact immutable family catalogs and capability declarations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from openultrasast.core import canonical
from openultrasast.core.family import FamilyContract, family_contract_digest, validate_contract

FAMILY_CATALOG_SCHEMA = "openultrasast.detection-core.family-catalog.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class FamilyCatalogError(ValueError):
    """A family catalog violates its canonical closed-set contract."""


class FamilyCatalogResolutionError(FamilyCatalogError, LookupError):
    """No exact family, digest, and ecosystem catalog entry exists."""


class FamilyCapabilityError(FamilyCatalogError):
    """A family capability declaration is incomplete or substituted."""


def _text(value: object, field: str, error: type[FamilyCatalogError] = FamilyCatalogError) -> None:
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be nonempty text")


def _digest(value: object, field: str, error: type[FamilyCatalogError] = FamilyCatalogError) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise error(f"{field} must be a full lowercase SHA-256 digest")


@dataclass(frozen=True)
class FamilyCatalogEntry:
    contract: FamilyContract
    contract_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.contract, FamilyContract):
            raise FamilyCatalogError("entry contract must be a FamilyContract")
        _digest(self.contract_digest, "contract digest")
        validate_contract(self.contract)
        if self.contract_digest != family_contract_digest(self.contract):
            raise FamilyCatalogError("contract digest does not match contract content")


def catalog_entry_key(entry: FamilyCatalogEntry) -> tuple[str, str, str, str]:
    if not isinstance(entry, FamilyCatalogEntry):
        raise FamilyCatalogError("catalog entry must be a FamilyCatalogEntry")
    contract = entry.contract
    return (contract.family_id, contract.family_version, contract.schema_version, entry.contract_digest)


def _entry_value(entry: FamilyCatalogEntry) -> canonical.JsonValue:
    contract = entry.contract
    return {
        "family_id": contract.family_id,
        "family_version": contract.family_version,
        "schema_version": contract.schema_version,
        "ecosystems": contract.ecosystems,
        "contract_digest": entry.contract_digest,
    }


def derive_catalog_digest(entries: tuple[FamilyCatalogEntry, ...]) -> str:
    if not isinstance(entries, tuple) or not entries:
        raise FamilyCatalogError("entries must be a nonempty tuple")
    if not all(isinstance(entry, FamilyCatalogEntry) for entry in entries):
        raise FamilyCatalogError("entries must contain FamilyCatalogEntry values")
    return canonical.content_digest({"schema_version": FAMILY_CATALOG_SCHEMA, "entries": tuple(_entry_value(entry) for entry in entries)})


@dataclass(frozen=True)
class FamilyCatalog:
    entries: tuple[FamilyCatalogEntry, ...]
    catalog_digest: str

    def __post_init__(self) -> None:
        validate_catalog(self)


def _validate_unique_entries(entries: tuple[FamilyCatalogEntry, ...]) -> None:
    identities = tuple((item.contract.family_id, item.contract.family_version, item.contract.schema_version) for item in entries)
    if len(set(identities)) != len(identities):
        raise FamilyCatalogError("duplicate family contract identity")
    digests = tuple(item.contract_digest for item in entries)
    if len(set(digests)) != len(digests):
        raise FamilyCatalogError("duplicate contract digest")


def validate_catalog(value: FamilyCatalog) -> None:
    if not isinstance(value, FamilyCatalog):
        raise FamilyCatalogError("catalog must be a FamilyCatalog")
    if not isinstance(value.entries, tuple) or not value.entries:
        raise FamilyCatalogError("entries must be a nonempty tuple")
    if not all(isinstance(entry, FamilyCatalogEntry) for entry in value.entries):
        raise FamilyCatalogError("entries must contain FamilyCatalogEntry values")
    _digest(value.catalog_digest, "catalog digest")
    if value.entries != tuple(sorted(value.entries, key=catalog_entry_key)):
        raise FamilyCatalogError("catalog entries must be in canonical order")
    _validate_unique_entries(value.entries)
    for entry in value.entries:
        validate_contract(entry.contract)
        if entry.contract_digest != family_contract_digest(entry.contract):
            raise FamilyCatalogError("contract digest does not match contract content")
    if value.catalog_digest != derive_catalog_digest(value.entries):
        raise FamilyCatalogError("catalog digest does not match canonical entries")


def resolve_contract(
    value: FamilyCatalog,
    family_id: str,
    contract_digest: str,
    ecosystem: str,
) -> FamilyContract:
    validate_catalog(value)
    _text(family_id, "family_id", FamilyCatalogResolutionError)
    _digest(contract_digest, "contract digest", FamilyCatalogResolutionError)
    _text(ecosystem, "ecosystem", FamilyCatalogResolutionError)
    matches = tuple(
        entry.contract
        for entry in value.entries
        if entry.contract.family_id == family_id and entry.contract_digest == contract_digest and ecosystem in entry.contract.ecosystems
    )
    if len(matches) != 1:
        raise FamilyCatalogResolutionError("family, digest, and ecosystem must resolve one exact contract")
    return matches[0]


@dataclass(frozen=True)
class FamilyCapabilityDeclaration:
    arm_id: str
    family_contract_digest: str
    readiness_fixture_digest: str
    development_population_digest: str
    admission_boundary_digest: str

    def __post_init__(self) -> None:
        _validate_capability_fields(self)


def _validate_capability_fields(declaration: FamilyCapabilityDeclaration) -> None:
    _text(declaration.arm_id, "arm_id", FamilyCapabilityError)
    for value, field in (
        (declaration.family_contract_digest, "family contract digest"),
        (declaration.readiness_fixture_digest, "readiness fixture digest"),
        (declaration.development_population_digest, "development population digest"),
        (declaration.admission_boundary_digest, "admission boundary digest"),
    ):
        _digest(value, field, FamilyCapabilityError)


def validate_capability(declaration: FamilyCapabilityDeclaration, value: FamilyCatalog) -> None:
    if not isinstance(declaration, FamilyCapabilityDeclaration):
        raise FamilyCapabilityError("declaration must be a FamilyCapabilityDeclaration")
    _validate_capability_fields(declaration)
    validate_catalog(value)
    matches = tuple(entry for entry in value.entries if entry.contract_digest == declaration.family_contract_digest)
    if len(matches) != 1:
        raise FamilyCapabilityError("capability contract digest must identify one exact catalog entry")


__all__ = [
    "FAMILY_CATALOG_SCHEMA",
    "FamilyCapabilityDeclaration",
    "FamilyCapabilityError",
    "FamilyCatalog",
    "FamilyCatalogEntry",
    "FamilyCatalogError",
    "FamilyCatalogResolutionError",
    "catalog_entry_key",
    "derive_catalog_digest",
    "resolve_contract",
    "validate_capability",
    "validate_catalog",
]
