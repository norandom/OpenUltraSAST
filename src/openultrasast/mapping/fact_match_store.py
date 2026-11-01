"""Canonical digest-addressed persistence for fact-match artifacts."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from openultrasast.core import canonical
from openultrasast.core.factmatch import (
    FactMatchEvidence,
    StructuralObservation,
    derive_fact_match_digest,
    fact_match_bytes,
    structural_observation_bytes,
)
from openultrasast.mapping.installed_fact_authority import DigestDirectoryResolver

_MEDIA_TYPE = "application/json"
_ZERO_DIGEST = "0" * 64


class FactMatchStoreError(ValueError):
    """Canonical evidence could not be safely persisted or reproduced."""


@dataclass(frozen=True)
class FactMatchArtifactWriter:
    """Write canonical artifacts while exposing only the read-only resolver."""

    root: Path
    store_identity: str
    retention_policy_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        try:
            canonical.derive_storage_receipt_digest(
                store_identity=self.store_identity,
                content_digest=_ZERO_DIGEST,
                byte_length=0,
                retention_policy_digest=self.retention_policy_digest,
            )
        except (TypeError, ValueError) as exc:
            raise FactMatchStoreError(f"invalid artifact store configuration: {exc}") from exc

    @property
    def resolver(self) -> DigestDirectoryResolver:
        """Return the read-only resolver for references produced by this writer."""
        return DigestDirectoryResolver(self.root, self.store_identity)

    def persist_observation(self, value: StructuralObservation) -> canonical.ContentRef:
        """Persist the payload of one typed structural observation."""
        if not isinstance(value, StructuralObservation):
            raise TypeError("value must be a StructuralObservation")
        return self._persist(structural_observation_bytes(value), "structural-observation")

    def persist_match(self, value: FactMatchEvidence) -> canonical.ContentRef:
        """Persist a completed match after reproducing all observation references."""
        if not isinstance(value, FactMatchEvidence):
            raise TypeError("value must be FactMatchEvidence")
        if value.match_digest != derive_fact_match_digest(value):
            raise FactMatchStoreError("match digest cannot be re-derived")
        for observation in value.observations:
            self._validate_observation(observation)
        content = fact_match_bytes(value)
        if canonical.bytes_digest(content) != value.match_digest:
            raise FactMatchStoreError("canonical match bytes do not reproduce match digest")
        return self._persist(content, "fact-match")

    def _validate_observation(self, observation: StructuralObservation) -> None:
        observation_bytes = structural_observation_bytes(observation)
        reference = observation.evidence
        expected_reference = self._reference_for(observation_bytes, "structural-observation")
        if reference != expected_reference:
            raise FactMatchStoreError("observation reference does not equal canonical persisted reference")
        try:
            content = canonical.resolve_content(
                reference,
                self.resolver,
                trusted_store_identities=(self.store_identity,),
                maximum_bytes=reference.byte_length,
            )
        except (canonical.ArtifactResolutionError, canonical.ArtifactValidationError) as exc:
            raise FactMatchStoreError(f"observation reference cannot be validated: {exc}") from exc
        if content != observation_bytes:
            raise FactMatchStoreError("observation reference does not resolve to canonical observation bytes")

    def _persist(self, content: bytes, artifact_kind: str) -> canonical.ContentRef:
        digest = canonical.bytes_digest(content)
        target = self.root / "artifacts" / "sha256" / digest
        self._install_atomically(target, content)
        return self._reference_for(content, artifact_kind)

    def _reference_for(self, content: bytes, artifact_kind: str) -> canonical.ContentRef:
        digest = canonical.bytes_digest(content)
        receipt_digest = canonical.derive_storage_receipt_digest(
            store_identity=self.store_identity,
            content_digest=digest,
            byte_length=len(content),
            retention_policy_digest=self.retention_policy_digest,
        )
        return canonical.ContentRef(
            f"{artifact_kind}:{digest}",
            digest,
            _MEDIA_TYPE,
            len(content),
            self.retention_policy_digest,
            receipt_digest,
        )

    @staticmethod
    def _install_atomically(target: Path, content: bytes) -> None:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                _require_exact_existing(target, content)
                return
            descriptor, temporary_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
            temporary = Path(temporary_name)
            try:
                _write_and_link(descriptor, temporary, target, content)
            finally:
                temporary.unlink(missing_ok=True)
        except FactMatchStoreError:
            raise
        except OSError as exc:
            raise FactMatchStoreError("canonical artifact could not be persisted") from exc


def _write_and_link(descriptor: int, temporary: Path, target: Path, content: bytes) -> None:
    with os.fdopen(descriptor, "wb") as sink:
        sink.write(content)
        sink.flush()
        os.fsync(sink.fileno())
    try:
        os.link(temporary, target)
    except FileExistsError:
        _require_exact_existing(target, content)


def _require_exact_existing(target: Path, content: bytes) -> None:
    try:
        existing = target.read_bytes()
    except OSError as exc:
        raise FactMatchStoreError("digest-addressed artifact cannot be read") from exc
    if existing != content:
        raise FactMatchStoreError("digest path contains substituted bytes")


__all__ = ["FactMatchArtifactWriter", "FactMatchStoreError"]
