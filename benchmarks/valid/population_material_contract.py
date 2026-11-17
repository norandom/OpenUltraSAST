"""Canonical contracts for public, private, and sealed population material."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import StrEnum

from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes, content_digest

PUBLIC_MANIFEST_SCHEMA = "openultrasast.valid-detection-benchmark.public-material-manifest.v1"
PUBLIC_SOURCE_OBJECT_SCHEMA = "openultrasast.valid-detection-benchmark.public-source-object.v1"
PRIVATE_OBJECT_SCHEMA = "openultrasast.valid-detection-benchmark.private-material-object.v1"
SEALED_LABEL_SCHEMA = "openultrasast.valid-detection-benchmark.sealed-label-object.v1"
MATERIAL_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.material-access-authority.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
PERMISSIVE_PUBLIC_LICENSES = frozenset(
    {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "ISC", "MIT", "Python-2.0", "Unlicense"}
)


class PopulationMaterialError(ValueError):
    """Population material violates its access or identity contract."""


class PopulationMaterialConflict(PopulationMaterialError):
    """An existing material identity resolves to different bytes."""


class LicenseClass(StrEnum):
    PERMISSIVE = "permissive"
    NON_PERMISSIVE = "non_permissive"
    UNCERTAIN = "uncertain"


class MaterialActorRole(StrEnum):
    CUSTODIAN = "custodian"
    DETECTOR = "detector"
    PRESENTER = "presenter"
    OPERATOR = "operator"


class MaterialPermission(StrEnum):
    PRIVATE_SOURCE = "private_source"
    SEALED_LABELS = "sealed_labels"


@dataclass(frozen=True)
class PopulationMaterialInputV1:
    change_digest: str
    license_class: LicenseClass
    license_expression: str
    source_content: bytes
    label_content: bytes
    review_judgment_content: bytes
    public_distribution_approved: bool


@dataclass(frozen=True, order=True)
class PublicSourceRecordV1:
    change_digest: str
    license_class: LicenseClass
    license_expression: str
    source_digest: str
    byte_length: int
    object_digest: str


@dataclass(frozen=True, order=True)
class PublicSourceObjectV1:
    change_digest: str
    source_digest: str
    source_content: bytes


@dataclass(frozen=True, order=True)
class OpaquePrivateMaterialRefV1:
    change_digest: str
    license_class: LicenseClass
    source_digest: str
    byte_length: int


@dataclass(frozen=True, order=True)
class PrivateSourceRecordV1:
    change_digest: str
    source_digest: str
    source_content: bytes


@dataclass(frozen=True, order=True)
class SealedLabelRecordV1:
    change_digest: str
    label_digest: str
    judgment_digest: str
    label_content: bytes
    judgment_content: bytes


@dataclass(frozen=True)
class PublicPopulationMaterialManifestV1:
    population_digest: str
    freeze_digest: str
    positive_change_digests: tuple[str, ...]
    public_sources: tuple[PublicSourceRecordV1, ...]
    private_refs: tuple[OpaquePrivateMaterialRefV1, ...]
    private_object_digest: str
    sealed_label_digest: str
    license_partitions: tuple[tuple[LicenseClass, int], ...]
    exclusion_counts: tuple[tuple[str, int], ...]
    public_count: int
    private_count: int
    partition_policy_digest: str
    manifest_digest: str


@dataclass(frozen=True)
class PopulationMaterialPartitionV1:
    manifest: PublicPopulationMaterialManifestV1
    public_source_objects: tuple[PublicSourceObjectV1, ...]
    private_records: tuple[PrivateSourceRecordV1, ...]
    sealed_label_records: tuple[SealedLabelRecordV1, ...]


@dataclass(frozen=True)
class MaterialAccessAuthorityV1:
    population_digest: str
    freeze_digest: str
    manifest_digest: str
    partition_policy_digest: str
    private_object_digest: str
    sealed_label_digest: str
    actor_role: MaterialActorRole
    permissions: tuple[MaterialPermission, ...]
    policy_digest: str
    authority_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PopulationMaterialError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PopulationMaterialError(f"{field} must be nonempty text")
    return value.strip()


def _nonempty_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise PopulationMaterialError(f"{field} bytes must be nonempty")
    return value


def _positive_length(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise PopulationMaterialError(f"{field} byte length must be positive")
    return value


def _public_value(record: PublicSourceRecordV1) -> dict[str, JsonValue]:
    if LicenseClass(record.license_class) is not LicenseClass.PERMISSIVE:
        raise PopulationMaterialError("public source must be permissively licensed")
    expression = _text(record.license_expression, "license expression")
    if expression not in PERMISSIVE_PUBLIC_LICENSES:
        raise PopulationMaterialError("public source license is outside the closed permissive policy")
    return {
        "change_digest": _digest(record.change_digest, "public change"),
        "license_class": LicenseClass.PERMISSIVE.value,
        "license_expression": expression,
        "source_digest": _digest(record.source_digest, "public source"),
        "byte_length": _positive_length(record.byte_length, "public source"),
        "object_digest": _digest(record.object_digest, "public source object"),
    }


def _public_object_value(record: PublicSourceObjectV1) -> dict[str, JsonValue]:
    content = _nonempty_bytes(record.source_content, "public source")
    if bytes_digest(content) != _digest(record.source_digest, "public source"):
        raise PopulationMaterialError("public source digest does not match bytes")
    return {
        "schema_version": PUBLIC_SOURCE_OBJECT_SCHEMA,
        "change_digest": _digest(record.change_digest, "public change"),
        "source_digest": record.source_digest,
        "byte_length": len(content),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }


def public_source_record_bytes(record: PublicSourceObjectV1) -> bytes:
    """Serialize one typed public source object independently of its manifest."""
    return canonical_bytes(_public_object_value(record))


def _private_ref_value(record: OpaquePrivateMaterialRefV1) -> dict[str, JsonValue]:
    return {
        "change_digest": _digest(record.change_digest, "private change"),
        "license_class": LicenseClass(record.license_class).value,
        "source_digest": _digest(record.source_digest, "private source"),
        "byte_length": _positive_length(record.byte_length, "private source"),
    }


def _private_record_value(record: PrivateSourceRecordV1) -> dict[str, JsonValue]:
    content = _nonempty_bytes(record.source_content, "private source")
    if bytes_digest(content) != _digest(record.source_digest, "private source"):
        raise PopulationMaterialError("private source digest does not match bytes")
    return {
        "change_digest": _digest(record.change_digest, "private change"),
        "source_digest": record.source_digest,
        "byte_length": len(content),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }


def _label_record_value(record: SealedLabelRecordV1) -> dict[str, JsonValue]:
    label = _nonempty_bytes(record.label_content, "label")
    judgment = _nonempty_bytes(record.judgment_content, "review judgment")
    if bytes_digest(label) != _digest(record.label_digest, "label"):
        raise PopulationMaterialError("label digest does not match bytes")
    if bytes_digest(judgment) != _digest(record.judgment_digest, "review judgment"):
        raise PopulationMaterialError("review judgment digest does not match bytes")
    return {
        "change_digest": _digest(record.change_digest, "sealed change"),
        "label_digest": record.label_digest,
        "judgment_digest": record.judgment_digest,
        "label_base64": base64.b64encode(label).decode("ascii"),
        "judgment_base64": base64.b64encode(judgment).decode("ascii"),
    }


def private_object_bytes(partition: PopulationMaterialPartitionV1) -> bytes:
    if partition.private_records != tuple(sorted(set(partition.private_records))):
        raise PopulationMaterialError("private records are not canonical")
    records = tuple(_private_record_value(record) for record in partition.private_records)
    return canonical_bytes({"schema_version": PRIVATE_OBJECT_SCHEMA, "records": records})


def sealed_label_object_bytes(partition: PopulationMaterialPartitionV1) -> bytes:
    if partition.sealed_label_records != tuple(sorted(set(partition.sealed_label_records))):
        raise PopulationMaterialError("sealed label records are not canonical")
    records = tuple(_label_record_value(record) for record in partition.sealed_label_records)
    return canonical_bytes({"schema_version": SEALED_LABEL_SCHEMA, "records": records})


def _manifest_value(manifest: PublicPopulationMaterialManifestV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": PUBLIC_MANIFEST_SCHEMA,
        "population_digest": _digest(manifest.population_digest, "population"),
        "freeze_digest": _digest(manifest.freeze_digest, "freeze"),
        "positive_change_digests": tuple(_digest(item, "positive change") for item in manifest.positive_change_digests),
        "public_sources": tuple(_public_value(record) for record in manifest.public_sources),
        "private_refs": tuple(_private_ref_value(record) for record in manifest.private_refs),
        "private_object_digest": _digest(manifest.private_object_digest, "private object"),
        "sealed_label_digest": _digest(manifest.sealed_label_digest, "sealed label object"),
        "license_partitions": tuple((item.value, count) for item, count in manifest.license_partitions),
        "exclusion_counts": manifest.exclusion_counts,
        "public_count": manifest.public_count,
        "private_count": manifest.private_count,
        "partition_policy_digest": _digest(manifest.partition_policy_digest, "partition policy"),
    }
    if include_digest:
        value["manifest_digest"] = _digest(manifest.manifest_digest, "public manifest")
    return value


def _validate_manifest_counts(manifest: PublicPopulationMaterialManifestV1) -> None:
    expected_licenses = tuple(sorted(set(manifest.license_partitions), key=lambda item: item[0].value))
    if manifest.license_partitions != expected_licenses:
        raise PopulationMaterialError("license partitions are not canonical")
    if any(type(count) is not int or count <= 0 for _, count in manifest.license_partitions):
        raise PopulationMaterialError("license partition counts must be positive")
    exclusion_identities = tuple(reason for reason, _ in manifest.exclusion_counts)
    if len(exclusion_identities) != len(set(exclusion_identities)):
        raise PopulationMaterialError("exclusion reason identities must be unique")
    expected_exclusions = tuple(sorted(manifest.exclusion_counts))
    if manifest.exclusion_counts != expected_exclusions:
        raise PopulationMaterialError("exclusion counts are not canonical")
    for reason, count in manifest.exclusion_counts:
        _digest(reason, "exclusion reason")
        if type(count) is not int or count < 0:
            raise PopulationMaterialError("exclusion counts must be nonnegative")
    if any(type(count) is not int or count < 0 for count in (manifest.public_count, manifest.private_count)):
        raise PopulationMaterialError("public/private counts must be nonnegative integers")
    if manifest.public_count != len(manifest.public_sources) or manifest.private_count != len(manifest.private_refs):
        raise PopulationMaterialError("public/private counts do not match records")
    if sum(count for _, count in manifest.license_partitions) != len(manifest.positive_change_digests):
        raise PopulationMaterialError("license partitions do not cover exact positive set")


def _public_manifest_bytes(partition: PopulationMaterialPartitionV1) -> bytes:
    manifest = partition.manifest
    if manifest.public_sources != tuple(sorted(set(manifest.public_sources))):
        raise PopulationMaterialError("public sources are not canonical")
    if manifest.private_refs != tuple(sorted(set(manifest.private_refs))):
        raise PopulationMaterialError("private references are not canonical")
    if manifest.positive_change_digests != tuple(sorted(set(manifest.positive_change_digests))):
        raise PopulationMaterialError("positive identities are not canonical")
    _validate_manifest_counts(manifest)
    value = _manifest_value(manifest, include_digest=False)
    if content_digest(value) != manifest.manifest_digest:
        raise PopulationMaterialError("public manifest digest does not match")
    return canonical_bytes(_manifest_value(manifest, include_digest=True))


def _authority_value(authority: MaterialAccessAuthorityV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": MATERIAL_AUTHORITY_SCHEMA,
        "population_digest": _digest(authority.population_digest, "authority population"),
        "freeze_digest": _digest(authority.freeze_digest, "authority freeze"),
        "manifest_digest": _digest(authority.manifest_digest, "authority manifest"),
        "partition_policy_digest": _digest(authority.partition_policy_digest, "authority partition policy"),
        "private_object_digest": _digest(authority.private_object_digest, "authority private object"),
        "sealed_label_digest": _digest(authority.sealed_label_digest, "authority sealed label object"),
        "actor_role": MaterialActorRole(authority.actor_role).value,
        "permissions": tuple(MaterialPermission(item).value for item in authority.permissions),
        "policy_digest": _digest(authority.policy_digest, "access policy"),
    }
    if include_digest:
        value["authority_digest"] = _digest(authority.authority_digest, "material authority")
    return value


def validate_material_authority(
    authority: MaterialAccessAuthorityV1,
    *,
    expected_access_policy_digest: str,
) -> None:
    permissions = tuple(sorted(set(authority.permissions), key=lambda item: item.value))
    if authority.permissions != permissions:
        raise PopulationMaterialError("material permissions are not canonical")
    if authority.actor_role is not MaterialActorRole.CUSTODIAN and permissions:
        raise PopulationMaterialError("non-custodian material permissions are forbidden")
    expected = _digest(expected_access_policy_digest, "expected access policy")
    if authority.policy_digest != expected:
        raise PopulationMaterialError("material access is not authorized: access policy mismatch")
    if content_digest(_authority_value(authority, include_digest=False)) != authority.authority_digest:
        raise PopulationMaterialError("material authority digest does not match")


__all__ = [
    "LicenseClass",
    "MaterialAccessAuthorityV1",
    "MaterialActorRole",
    "MaterialPermission",
    "OpaquePrivateMaterialRefV1",
    "PERMISSIVE_PUBLIC_LICENSES",
    "PopulationMaterialConflict",
    "PopulationMaterialError",
    "PopulationMaterialInputV1",
    "PopulationMaterialPartitionV1",
    "PrivateSourceRecordV1",
    "PublicPopulationMaterialManifestV1",
    "PublicSourceObjectV1",
    "PublicSourceRecordV1",
    "SealedLabelRecordV1",
    "_authority_value",
    "_manifest_value",
    "private_object_bytes",
    "public_source_record_bytes",
    "sealed_label_object_bytes",
    "validate_material_authority",
]
