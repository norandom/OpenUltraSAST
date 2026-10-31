"""Deterministic content-resolver fixtures shared by detection-core contract tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from types import MappingProxyType

from openultrasast.core import canonical, provenance


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


class InMemoryPopulationCustody:
    """Deterministic compare-and-swap fixture; production persistence stays external."""

    def __init__(self, initial: provenance.PopulationCustodyLog, policy: provenance.PopulationCustodyPolicy) -> None:
        provenance.validate_population_custody_log(initial, policy)
        self._log = initial
        self._policy = policy
        self._lock = Lock()

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        if population_digest != self._log.population_digest:
            raise provenance.PopulationCustodyError("population custody log not found")
        return self._log

    def append(self, request: provenance.PopulationUseRequest, custodian: str) -> provenance.PopulationUseReceipt:
        with self._lock:
            receipt = provenance.record_population_use(request, self._log, custodian, self._policy)
            self._log = provenance.append_population_use(self._log, receipt, self._policy)
            return receipt


def custody_contract() -> tuple[
    provenance.PopulationCustodyLog,
    provenance.PopulationCustodyPolicy,
    str,
]:
    """Create one reviewed custodian and an empty reproducible population log."""
    population = canonical.content_digest("population")
    custodian = canonical.content_digest("reviewed-custodian")
    reviewed = (custodian,)
    policy = provenance.PopulationCustodyPolicy(
        reviewed_custodian_digests=reviewed,
        policy_digest=provenance.derive_population_custody_policy_digest(reviewed),
    )
    return provenance.empty_population_custody_log(population, custodian), policy, custodian
