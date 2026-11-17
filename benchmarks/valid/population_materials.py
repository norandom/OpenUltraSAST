"""Partition frozen population material into public, private, and sealed bytes."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace
from typing import Protocol

from benchmarks.valid.population_freeze_contract import PopulationFreezeV3, population_freeze_bytes
from benchmarks.valid.population_material_contract import (
    PERMISSIVE_PUBLIC_LICENSES,
    LicenseClass,
    MaterialAccessAuthorityV1,
    MaterialActorRole,
    MaterialPermission,
    OpaquePrivateMaterialRefV1,
    PopulationMaterialConflict,
    PopulationMaterialError,
    PopulationMaterialInputV1,
    PopulationMaterialPartitionV1,
    PrivateSourceRecordV1,
    PublicPopulationMaterialManifestV1,
    PublicSourceObjectV1,
    PublicSourceRecordV1,
    SealedLabelRecordV1,
    _authority_value,
    _manifest_value,
    _public_manifest_bytes,
    private_object_bytes,
    public_source_record_bytes,
    sealed_label_object_bytes,
    validate_material_authority,
)
from openultrasast.core.canonical import JsonValue, bytes_digest, canonical_bytes, content_digest

MATERIAL_SUMMARY_SCHEMA = "openultrasast.valid-detection-benchmark.material-summary.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class PopulationFreezeValidator(Protocol):
    def validate(self, freeze: PopulationFreezeV3) -> bytes: ...


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PopulationMaterialError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _validate_freeze(freeze: PopulationFreezeV3, validator: PopulationFreezeValidator) -> None:
    try:
        validated = validator.validate(freeze)
        canonical = population_freeze_bytes(freeze)
    except (TypeError, ValueError) as error:
        raise PopulationMaterialError("freeze does not replay from exact authorities") from error
    if not isinstance(validated, bytes) or not validated or validated != canonical:
        raise PopulationMaterialError("freeze validator did not return exact canonical bytes")


def _material(item: PopulationMaterialInputV1) -> PopulationMaterialInputV1:
    change = _digest(item.change_digest, "material change")
    try:
        license_class = LicenseClass(item.license_class)
    except (TypeError, ValueError) as error:
        raise PopulationMaterialError("license class is unsupported") from error
    if not isinstance(item.license_expression, str) or not item.license_expression.strip():
        raise PopulationMaterialError("license expression must be nonempty")
    for content, field in (
        (item.source_content, "source"),
        (item.label_content, "label"),
        (item.review_judgment_content, "review judgment"),
    ):
        if not isinstance(content, bytes) or not content:
            raise PopulationMaterialError(f"{field} bytes must be nonempty")
    if type(item.public_distribution_approved) is not bool:
        raise PopulationMaterialError("public distribution approval must be boolean")
    return PopulationMaterialInputV1(
        change,
        license_class,
        item.license_expression.strip(),
        item.source_content,
        item.label_content,
        item.review_judgment_content,
        item.public_distribution_approved,
    )


def _safe_public(item: PopulationMaterialInputV1) -> bool:
    return (
        item.license_class is LicenseClass.PERMISSIVE
        and item.public_distribution_approved
        and item.license_expression in PERMISSIVE_PUBLIC_LICENSES
    )


def _public_changes(items: tuple[PopulationMaterialInputV1, ...]) -> frozenset[str]:
    return frozenset(item.change_digest for item in items if _safe_public(item))


def _records(
    items: tuple[PopulationMaterialInputV1, ...],
) -> tuple[
    tuple[PublicSourceRecordV1, ...],
    tuple[PublicSourceObjectV1, ...],
    tuple[OpaquePrivateMaterialRefV1, ...],
    tuple[PrivateSourceRecordV1, ...],
    tuple[SealedLabelRecordV1, ...],
]:
    public: list[PublicSourceRecordV1] = []
    public_objects: list[PublicSourceObjectV1] = []
    refs: list[OpaquePrivateMaterialRefV1] = []
    private: list[PrivateSourceRecordV1] = []
    labels: list[SealedLabelRecordV1] = []
    public_changes = _public_changes(items)
    for item in items:
        source_digest = bytes_digest(item.source_content)
        labels.append(
            SealedLabelRecordV1(
                item.change_digest,
                bytes_digest(item.label_content),
                bytes_digest(item.review_judgment_content),
                item.label_content,
                item.review_judgment_content,
            )
        )
        if item.change_digest in public_changes:
            public_object = PublicSourceObjectV1(item.change_digest, source_digest, item.source_content)
            public_objects.append(public_object)
            public.append(
                PublicSourceRecordV1(
                    item.change_digest,
                    item.license_class,
                    item.license_expression,
                    source_digest,
                    len(item.source_content),
                    bytes_digest(public_source_record_bytes(public_object)),
                )
            )
        else:
            refs.append(OpaquePrivateMaterialRefV1(item.change_digest, item.license_class, source_digest, len(item.source_content)))
            private.append(PrivateSourceRecordV1(item.change_digest, source_digest, item.source_content))
    return (
        tuple(sorted(public)),
        tuple(sorted(public_objects)),
        tuple(sorted(refs)),
        tuple(sorted(private)),
        tuple(sorted(labels)),
    )


def _draft_manifest(
    freeze: PopulationFreezeV3,
    items: tuple[PopulationMaterialInputV1, ...],
    public: tuple[PublicSourceRecordV1, ...],
    refs: tuple[OpaquePrivateMaterialRefV1, ...],
    private_digest: str,
    label_digest: str,
    policy: str,
) -> PublicPopulationMaterialManifestV1:
    counts = Counter(item.license_class for item in items)
    exclusions = tuple(sorted((content_digest({"exclusion_reason": reason}), count) for reason, count in freeze.exclusion_counts))
    return PublicPopulationMaterialManifestV1(
        freeze.population_digest,
        freeze.freeze_digest,
        freeze.positive_change_digests,
        public,
        refs,
        private_digest,
        label_digest,
        tuple((item, counts[item]) for item in sorted(counts, key=lambda value: value.value)),
        exclusions,
        len(public),
        len(refs),
        _digest(policy, "partition policy"),
        "",
    )


def _shell(private: tuple[PrivateSourceRecordV1, ...], labels: tuple[SealedLabelRecordV1, ...]) -> PopulationMaterialPartitionV1:
    zero = "0" * 64
    manifest = PublicPopulationMaterialManifestV1(zero, zero, (), (), (), zero, zero, (), (), 0, 0, zero, "")
    return PopulationMaterialPartitionV1(manifest, (), private, labels)


def build_population_material_partition(
    freeze: PopulationFreezeV3,
    inputs: Iterable[PopulationMaterialInputV1],
    *,
    freeze_validator: PopulationFreezeValidator,
    partition_policy_digest: str,
) -> PopulationMaterialPartitionV1:
    """Partition exact frozen positives without exposing private bytes publicly."""
    _validate_freeze(freeze, freeze_validator)
    items = tuple(sorted((_material(item) for item in inputs), key=lambda item: item.change_digest))
    changes = tuple(item.change_digest for item in items)
    if changes != freeze.positive_change_digests or len(changes) != len(set(changes)):
        raise PopulationMaterialError("material inputs do not match exact positive set")
    public, public_objects, refs, private, labels = _records(items)
    shell = _shell(private, labels)
    private_digest = bytes_digest(private_object_bytes(shell))
    label_digest = bytes_digest(sealed_label_object_bytes(shell))
    draft = _draft_manifest(freeze, items, public, refs, private_digest, label_digest, partition_policy_digest)
    manifest = replace(draft, manifest_digest=content_digest(_manifest_value(draft, include_digest=False)))
    partition = PopulationMaterialPartitionV1(manifest, public_objects, private, labels)
    _validate_partition(partition)
    return partition


def _validate_partition(partition: PopulationMaterialPartitionV1) -> None:
    manifest = partition.manifest
    if partition.public_source_objects != tuple(sorted(set(partition.public_source_objects))):
        raise PopulationMaterialError("public source objects are not canonical")
    private_content = private_object_bytes(partition)
    label_content = sealed_label_object_bytes(partition)
    if bytes_digest(private_content) != manifest.private_object_digest:
        raise PopulationMaterialError("private object digest does not match manifest")
    if bytes_digest(label_content) != manifest.sealed_label_digest:
        raise PopulationMaterialError("sealed label digest does not match manifest")
    sealed_changes = tuple(item.change_digest for item in partition.sealed_label_records)
    if sealed_changes != manifest.positive_change_digests:
        raise PopulationMaterialError("sealed labels do not cover exact positive set")
    public_changes = {item.change_digest for item in manifest.public_sources}
    private_changes = {item.change_digest for item in manifest.private_refs}
    if public_changes & private_changes or public_changes | private_changes != set(manifest.positive_change_digests):
        raise PopulationMaterialError("public/private partitions do not cover exact positive set")
    object_bindings = {
        (item.change_digest, item.source_digest, len(item.source_content), bytes_digest(public_source_record_bytes(item)))
        for item in partition.public_source_objects
    }
    public_bindings = {(item.change_digest, item.source_digest, item.byte_length, item.object_digest) for item in manifest.public_sources}
    if public_bindings != object_bindings or len(public_bindings) != len(partition.public_source_objects):
        raise PopulationMaterialError("public source references do not match typed objects")
    refs = {(item.change_digest, item.source_digest, item.byte_length) for item in manifest.private_refs}
    records = {(item.change_digest, item.source_digest, len(item.source_content)) for item in partition.private_records}
    if refs != records:
        raise PopulationMaterialError("opaque private references do not match private object")
    actual_licenses = Counter(item.license_class for item in manifest.private_refs)
    if manifest.public_sources:
        actual_licenses[LicenseClass.PERMISSIVE] += len(manifest.public_sources)
    expected_licenses = tuple((item, actual_licenses[item]) for item in sorted(actual_licenses, key=lambda value: value.value))
    if manifest.license_partitions != expected_licenses:
        raise PopulationMaterialError("license partitions do not match material records")
    _public_manifest_bytes(partition)


def public_manifest_bytes(partition: PopulationMaterialPartitionV1) -> bytes:
    """Serialize a public manifest only after validating every bound object."""
    _validate_partition(partition)
    return _public_manifest_bytes(partition)


def public_source_object_bytes(
    partition: PopulationMaterialPartitionV1,
    reference: PublicSourceRecordV1,
) -> bytes:
    """Resolve one exact public reference to its typed content-addressed object."""
    _validate_partition(partition)
    if reference not in partition.manifest.public_sources:
        raise PopulationMaterialError("public source reference is not authorized")
    for record in partition.public_source_objects:
        if (record.change_digest, record.source_digest) == (reference.change_digest, reference.source_digest):
            serialized = public_source_record_bytes(record)
            if bytes_digest(serialized) != reference.object_digest or len(record.source_content) != reference.byte_length:
                raise PopulationMaterialError("public source reference does not match object")
            return serialized
    raise PopulationMaterialError("public source reference is unresolved")


def public_source_object_bytes_set(partition: PopulationMaterialPartitionV1) -> tuple[bytes, ...]:
    """Return public objects in canonical manifest-reference order."""
    _validate_partition(partition)
    return tuple(public_source_object_bytes(partition, reference) for reference in partition.manifest.public_sources)


def resolve_public_source(partition: PopulationMaterialPartitionV1, reference: PublicSourceRecordV1) -> bytes:
    """Return exact public source bytes after validating their typed object."""
    public_source_object_bytes(partition, reference)
    for record in partition.public_source_objects:
        if (record.change_digest, record.source_digest) == (reference.change_digest, reference.source_digest):
            return record.source_content
    raise PopulationMaterialError("public source reference is unresolved")


def material_access_authority(
    partition: PopulationMaterialPartitionV1,
    actor_role: MaterialActorRole | str,
    permissions: Iterable[MaterialPermission | str],
    policy_digest: str,
    *,
    expected_access_policy_digest: str,
) -> MaterialAccessAuthorityV1:
    _validate_partition(partition)
    try:
        role = MaterialActorRole(actor_role)
        granted = tuple(sorted({MaterialPermission(item) for item in permissions}, key=lambda item: item.value))
    except (TypeError, ValueError) as error:
        raise PopulationMaterialError("material authority values are unsupported") from error
    access_policy = _digest(policy_digest, "access policy")
    expected_policy = _digest(expected_access_policy_digest, "expected access policy")
    if access_policy != expected_policy:
        raise PopulationMaterialError("material access is not authorized: access policy mismatch")
    manifest = partition.manifest
    draft = MaterialAccessAuthorityV1(
        manifest.population_digest,
        manifest.freeze_digest,
        manifest.manifest_digest,
        manifest.partition_policy_digest,
        manifest.private_object_digest,
        manifest.sealed_label_digest,
        role,
        granted,
        access_policy,
        "",
    )
    authority = replace(draft, authority_digest=content_digest(_authority_value(draft, include_digest=False)))
    validate_material_authority(authority, expected_access_policy_digest=expected_policy)
    return authority


def _require_permission(
    partition: PopulationMaterialPartitionV1,
    authority: MaterialAccessAuthorityV1,
    permission: MaterialPermission,
    expected_access_policy_digest: str,
) -> None:
    expected_policy = _digest(expected_access_policy_digest, "expected access policy")
    validate_material_authority(authority, expected_access_policy_digest=expected_policy)
    manifest = partition.manifest
    if (
        authority.population_digest != manifest.population_digest
        or authority.freeze_digest != manifest.freeze_digest
        or authority.manifest_digest != manifest.manifest_digest
        or authority.partition_policy_digest != manifest.partition_policy_digest
        or authority.private_object_digest != manifest.private_object_digest
        or authority.sealed_label_digest != manifest.sealed_label_digest
        or authority.actor_role is not MaterialActorRole.CUSTODIAN
        or permission not in authority.permissions
    ):
        raise PopulationMaterialError("material access is not authorized")


def resolve_private_material(
    partition: PopulationMaterialPartitionV1,
    reference: OpaquePrivateMaterialRefV1,
    authority: MaterialAccessAuthorityV1,
    *,
    expected_access_policy_digest: str,
) -> bytes:
    _validate_partition(partition)
    _require_permission(
        partition,
        authority,
        MaterialPermission.PRIVATE_SOURCE,
        expected_access_policy_digest,
    )
    if reference not in partition.manifest.private_refs:
        raise PopulationMaterialError("opaque private reference is not authorized")
    for record in partition.private_records:
        if (record.change_digest, record.source_digest) == (reference.change_digest, reference.source_digest):
            return record.source_content
    raise PopulationMaterialError("opaque private reference is unresolved")


def resolve_sealed_labels(
    partition: PopulationMaterialPartitionV1,
    authority: MaterialAccessAuthorityV1,
    *,
    expected_access_policy_digest: str,
) -> bytes:
    _validate_partition(partition)
    _require_permission(
        partition,
        authority,
        MaterialPermission.SEALED_LABELS,
        expected_access_policy_digest,
    )
    return sealed_label_object_bytes(partition)


def operator_material_summary(partition: PopulationMaterialPartitionV1) -> bytes:
    _validate_partition(partition)
    manifest = partition.manifest
    value: JsonValue = {
        "schema_version": MATERIAL_SUMMARY_SCHEMA,
        "status": "partitioned",
        "population_digest": manifest.population_digest,
        "freeze_digest": manifest.freeze_digest,
        "manifest_digest": manifest.manifest_digest,
        "private_object_digest": manifest.private_object_digest,
        "sealed_label_digest": manifest.sealed_label_digest,
        "public_count": manifest.public_count,
        "private_count": manifest.private_count,
        "reason_codes": ("private_material_opaque", "labels_custodian_sealed"),
    }
    return canonical_bytes(value)


def accept_population_material_partition(
    partition: PopulationMaterialPartitionV1,
    *,
    existing: tuple[bytes, ...] | None = None,
) -> PopulationMaterialPartitionV1:
    _validate_partition(partition)
    current = material_artifact_bytes(partition)
    if existing is not None and existing != current:
        raise PopulationMaterialConflict("same material identity resolves to different bytes")
    return partition


def material_artifact_bytes(partition: PopulationMaterialPartitionV1) -> tuple[bytes, ...]:
    """Return manifest, public sources, private material, and labels in canonical order."""
    _validate_partition(partition)
    return (
        public_manifest_bytes(partition),
        *public_source_object_bytes_set(partition),
        private_object_bytes(partition),
        sealed_label_object_bytes(partition),
    )


__all__ = [
    "LicenseClass",
    "MaterialAccessAuthorityV1",
    "MaterialActorRole",
    "MaterialPermission",
    "OpaquePrivateMaterialRefV1",
    "PopulationFreezeValidator",
    "PopulationMaterialConflict",
    "PopulationMaterialError",
    "PopulationMaterialInputV1",
    "PopulationMaterialPartitionV1",
    "accept_population_material_partition",
    "build_population_material_partition",
    "material_artifact_bytes",
    "material_access_authority",
    "operator_material_summary",
    "private_object_bytes",
    "public_manifest_bytes",
    "public_source_object_bytes",
    "public_source_object_bytes_set",
    "resolve_public_source",
    "resolve_private_material",
    "resolve_sealed_labels",
    "sealed_label_object_bytes",
]
