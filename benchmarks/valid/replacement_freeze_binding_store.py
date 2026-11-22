"""Durable persistence, hostile decode, and replay for the replacement binding.

The binding record, the freeze, the reviewed label-blind manifest, the
partitioned material objects, and the lifecycle events persist under the
committed artifact-access conventions: public metadata is PUBLIC, private
source material is PRIVATE, sealed labels are CUSTODIAN_SEALED, and operator
records are OPERATOR_SAFE. Every durable decode is hostile: no constants,
finite floats, bounded recursion, and canonical bytes only.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from benchmarks.valid.artifact_repository import ArtifactReadAuthority, S3ArtifactRepository
from benchmarks.valid.lifecycle import decode_lifecycle_event
from benchmarks.valid.population_freeze import PopulationFreezeV3, population_freeze_bytes
from benchmarks.valid.population_label_blind import (
    LabelBlindPopulationManifestV3,
    label_blind_population_manifest_bytes,
)
from benchmarks.valid.population_materials import (
    PopulationMaterialPartitionV1,
    private_object_bytes,
    public_manifest_bytes,
    sealed_label_object_bytes,
)
from benchmarks.valid.replacement_artifact_contract import (
    ArtifactAccessClass,
    ArtifactKind,
    ArtifactReference,
    artifact_reference,
    canonical_artifact_bytes,
)
from benchmarks.valid.replacement_freeze_binding import (
    REPLACEMENT_BASELINE_BINDING_SCHEMA,
    ReplacementBaselineBindingV1,
    ReplacementBindingStateError,
    ReplacementBindingStateReason,
    replacement_baseline_binding_bytes,
)
from openultrasast.core.canonical import canonical_bytes

_BINDING_KEYS = frozenset({*("schema_version", "binding_digest"), *ReplacementBaselineBindingV1.__dataclass_fields__})


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(text)
    return value


def _converted(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_converted(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _converted(item) for key, item in value.items()}
    return value


def _decoded_mapping(content: bytes) -> dict[str, Any]:
    """Hostile decode: no constants, finite floats, bounded recursion, canonical bytes."""
    if not isinstance(content, bytes) or not content:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_UNREADABLE)
    try:
        parsed = json.loads(content, parse_constant=_reject_constant, parse_float=_finite_float)
        value = _converted(parsed)
        canonical = canonical_bytes(value)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_UNREADABLE) from None
    if not isinstance(value, dict) or canonical != content:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_UNREADABLE)
    return value


def decode_replacement_baseline_binding(content: bytes) -> ReplacementBaselineBindingV1:
    """Rebuild one binding record only from canonical, digest-consistent bytes."""
    value = _decoded_mapping(content)
    if set(value) != _BINDING_KEYS or value["schema_version"] != REPLACEMENT_BASELINE_BINDING_SCHEMA:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_MISMATCH)
    try:
        binding = ReplacementBaselineBindingV1(*(value[field] for field in ReplacementBaselineBindingV1.__dataclass_fields__))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_MISMATCH) from error
    if replacement_baseline_binding_bytes(binding) != content:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_MISMATCH)
    return binding


@dataclass(frozen=True)
class ReplacementBaselineReferencesV1:
    """Durable references for every persisted replacement-baseline artifact."""

    freeze: ArtifactReference
    manifest: ArtifactReference
    public_manifest: ArtifactReference
    private_object: ArtifactReference
    sealed_labels: ArtifactReference
    lifecycle_events: tuple[ArtifactReference, ...]
    binding: ArtifactReference


def _persist(
    store: S3ArtifactRepository,
    content: bytes,
    *,
    kind: ArtifactKind,
    access: ArtifactAccessClass,
    provenance_digest: str,
) -> ArtifactReference:
    payload = _decoded_mapping(content)
    artifact = canonical_artifact_bytes(kind, payload, access_class=access, provenance_digest=provenance_digest)
    return store.put_if_absent(artifact, reference=artifact_reference(artifact))


def _persist_event(store: S3ArtifactRepository, content: bytes) -> ArtifactReference:
    try:
        event = decode_lifecycle_event(content)
    except (AttributeError, TypeError, ValueError) as error:
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_MISMATCH) from error
    return _persist(
        store,
        content,
        kind=ArtifactKind.LIFECYCLE,
        access=ArtifactAccessClass.OPERATOR_SAFE,
        provenance_digest=event.event_digest,
    )


def persist_replacement_baseline(
    store: S3ArtifactRepository,
    *,
    binding: ReplacementBaselineBindingV1,
    freeze: PopulationFreezeV3,
    manifest: LabelBlindPopulationManifestV3,
    partition: PopulationMaterialPartitionV1,
    lifecycle_events: Sequence[bytes],
) -> ReplacementBaselineReferencesV1:
    """Persist the bound baseline under exact public/private/sealed access classes."""
    material = partition.manifest
    return ReplacementBaselineReferencesV1(
        _persist(
            store,
            population_freeze_bytes(freeze),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.OPERATOR_SAFE,
            provenance_digest=freeze.freeze_digest,
        ),
        _persist(
            store,
            label_blind_population_manifest_bytes(manifest),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.OPERATOR_SAFE,
            provenance_digest=manifest.manifest_digest,
        ),
        _persist(
            store,
            public_manifest_bytes(partition),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.PUBLIC,
            provenance_digest=material.manifest_digest,
        ),
        _persist(
            store,
            private_object_bytes(partition),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.PRIVATE,
            provenance_digest=material.private_object_digest,
        ),
        _persist(
            store,
            sealed_label_object_bytes(partition),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.CUSTODIAN_SEALED,
            provenance_digest=material.sealed_label_digest,
        ),
        tuple(_persist_event(store, event) for event in lifecycle_events),
        _persist(
            store,
            replacement_baseline_binding_bytes(binding),
            kind=ArtifactKind.POPULATION,
            access=ArtifactAccessClass.OPERATOR_SAFE,
            provenance_digest=binding.binding_digest,
        ),
    )


def resume_replacement_baseline_binding(
    store: S3ArtifactRepository,
    reference: ArtifactReference,
    *,
    authority: ArtifactReadAuthority,
    expected_access_policy_digest: str,
) -> ReplacementBaselineBindingV1:
    """Resume one replacement binding from the durable store after restart."""
    accepted = store.get(
        reference,
        expected_kind=ArtifactKind.POPULATION,
        authority=authority,
        expected_access_policy_digest=expected_access_policy_digest,
    )
    try:
        content = canonical_bytes(_converted(accepted.artifact.payload))
    except (TypeError, ValueError, RecursionError):
        raise ReplacementBindingStateError(ReplacementBindingStateReason.STATE_UNREADABLE) from None
    return decode_replacement_baseline_binding(content)


__all__ = [
    "ReplacementBaselineReferencesV1",
    "decode_replacement_baseline_binding",
    "persist_replacement_baseline",
    "resume_replacement_baseline_binding",
]
