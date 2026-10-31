"""Deterministic content-resolver fixtures shared by detection-core contract tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from openultrasast.core import canonical


@dataclass(frozen=True)
class InMemoryContentResolver:
    """Read-only resolver keyed by opaque artifact identity."""

    artifacts: Mapping[str, canonical.ResolvedContent]

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", MappingProxyType(dict(self.artifacts)))

    def resolve(self, reference: canonical.ContentRef) -> canonical.ResolvedContent:
        artifact_id = reference.artifact_id
        try:
            return self.artifacts[artifact_id]
        except KeyError as exc:
            raise canonical.ArtifactResolutionError(f"artifact not found: {artifact_id}") from exc


def stored_artifact(
    content: bytes,
    *,
    artifact_id: str = "artifact-1",
    store_identity: str = "trusted-store",
    retention_policy_digest: str | None = None,
) -> tuple[canonical.ContentRef, InMemoryContentResolver]:
    """Create a reference and resolver whose receipt identities are reproducible."""
    retention = retention_policy_digest or canonical.content_digest("retain-30-days")
    digest = canonical.bytes_digest(content)
    receipt_digest = canonical.derive_storage_receipt_digest(
        store_identity=store_identity,
        content_digest=digest,
        byte_length=len(content),
        retention_policy_digest=retention,
    )
    receipt = canonical.StorageReceipt(
        store_identity=store_identity,
        content_digest=digest,
        byte_length=len(content),
        retention_policy_digest=retention,
        receipt_digest=receipt_digest,
    )
    reference = canonical.ContentRef(
        artifact_id=artifact_id,
        content_digest=digest,
        media_type="application/json",
        byte_length=len(content),
        retention_policy_digest=retention,
        storage_receipt_digest=receipt_digest,
    )
    resolver = InMemoryContentResolver({artifact_id: canonical.ResolvedContent(content=content, receipt=receipt)})
    return reference, resolver
