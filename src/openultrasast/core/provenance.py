"""Legacy stamps and strict v2 input/decision provenance contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from enum import Enum

from openultrasast.core import canonical
from openultrasast.core.canonical import ContentRef, ContentResolver
from openultrasast.core.custody import (
    CUSTODY_LOG_SCHEMA,
    CUSTODY_POLICY_SCHEMA,
    CUSTODY_RECEIPT_SCHEMA,
    CUSTODY_REQUEST_SCHEMA,
    LineagePurpose,
    PopulationCustodyError,
    PopulationCustodyLog,
    PopulationCustodyPolicy,
    PopulationCustodyPort,
    PopulationStatus,
    PopulationUseReceipt,
    PopulationUseRequest,
    append_population_use,
    derive_population_custody_policy_digest,
    derive_population_use_receipt_digest,
    derive_population_use_request_digest,
    empty_population_custody_log,
    record_population_use,
    validate_population_custody_log,
)
from openultrasast.core.lineage import (
    LINEAGE_DECISION_SCHEMA,
    LINEAGE_MANIFEST_SCHEMA,
    LineageDecision,
    LineageExpectation,
    LineageManifest,
    LineageUse,
    LineageValidationError,
    derive_lineage_decision_digest,
    derive_lineage_manifest_digest,
    validate_lineage,
)

NAMED_INPUTS_SCHEMA = "openultrasast.detection-core.named-inputs.v2"
PROVENANCE_POLICY_SCHEMA = "openultrasast.detection-core.provenance-policy.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ProvenanceValidationError(ValueError):
    """A provenance identity cannot be reproduced from its named inputs."""


class ProvenanceInputRole(Enum):
    ANALYZER = "analyzer"
    FAMILY_CONTRACT = "family_contract"
    FACT_SET = "fact_set"
    ACQUISITION = "acquisition"
    CONFIGURATION = "configuration"
    POPULATION = "population"
    CHANGE_INPUT = "change_input"


def _require_digest(value: object, field_name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise canonical.DigestFormatError(f"{field_name} must be a full lowercase SHA-256 digest")


def _require_text(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be nonempty text")


def _require_maximum(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("maximum_input_bytes must be a positive integer")


def _require_stores(stores: object) -> None:
    if not isinstance(stores, tuple) or not stores:
        raise ValueError("trusted_store_identities must be a nonempty tuple")
    for store in stores:
        _require_text(store, "trusted_store_identity")
    if len(set(stores)) != len(stores):
        raise ValueError("trusted_store_identities must be unique")


@dataclass(frozen=True)
class ProvenanceStamp:
    analyzer_revision: str
    family_contract_digest: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
    population_digest: str
    change_input_digest: str

    def __post_init__(self) -> None:
        for item in fields(self):
            _require_digest(getattr(self, item.name), item.name)


@dataclass(frozen=True)
class ProvenanceTrustPolicy:
    trusted_store_identities: tuple[str, ...]
    maximum_input_bytes: int
    policy_digest: str

    def __post_init__(self) -> None:
        _require_stores(self.trusted_store_identities)
        _require_maximum(self.maximum_input_bytes)
        _require_digest(self.policy_digest, "policy_digest")


@dataclass(frozen=True)
class NamedInput:
    role: ProvenanceInputRole
    identity: str
    content: ContentRef

    def __post_init__(self) -> None:
        _require_digest(self.identity, "named input identity")
        if not isinstance(self.content, ContentRef):
            raise TypeError("named input content must be a ContentRef")


@dataclass(frozen=True)
class NamedInputs:
    inputs: tuple[NamedInput, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.inputs, tuple) or not all(isinstance(item, NamedInput) for item in self.inputs):
            raise TypeError("named inputs must be a tuple of NamedInput values")
        _require_digest(self.manifest_digest, "manifest_digest")


@dataclass(frozen=True)
class ModelCallIdentity:
    provider: str
    model: str
    program_digest: str
    prompt_digest: str
    configuration_digest: str
    adapter_revision: str

    def __post_init__(self) -> None:
        for field_name in ("provider", "model", "adapter_revision"):
            _require_text(getattr(self, field_name), field_name)
        for field_name in ("program_digest", "prompt_digest", "configuration_digest"):
            _require_digest(getattr(self, field_name), field_name)


@dataclass(frozen=True)
class DecisionProvenance:
    model_identity: ModelCallIdentity | None
    model_result_digest: str | None
    model_declaration_digest: str | None
    proof_record_digest: str | None
    proof_producer_digest: str | None
    lineage_manifest_digest: str | None

    def __post_init__(self) -> None:
        if self.model_identity is not None and not isinstance(self.model_identity, ModelCallIdentity):
            raise TypeError("model_identity must be a ModelCallIdentity")
        for item in fields(self)[1:]:
            value = getattr(self, item.name)
            if value is not None:
                _require_digest(value, item.name)


def _content_ref_value(reference: ContentRef) -> canonical.JsonValue:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _input_value(item: NamedInput) -> canonical.JsonValue:
    if not isinstance(item.role, ProvenanceInputRole):
        raise ProvenanceValidationError(f"unknown named input role: {item.role!r}")
    return {"role": item.role.value, "identity": item.identity, "content": _content_ref_value(item.content)}


def derive_named_inputs_digest(inputs: tuple[NamedInput, ...]) -> str:
    """Derive an order-independent identity over every named input reference."""
    ordered = tuple(sorted(inputs, key=lambda item: item.role.value))
    payload: canonical.JsonValue = {
        "schema_version": NAMED_INPUTS_SCHEMA,
        "inputs": tuple(_input_value(item) for item in ordered),
    }
    return canonical.content_digest(payload)


def derive_trust_policy_digest(trusted_store_identities: tuple[str, ...], maximum_input_bytes: int) -> str:
    """Derive the trust and size policy identity."""
    _require_stores(trusted_store_identities)
    _require_maximum(maximum_input_bytes)
    payload: canonical.JsonValue = {
        "schema_version": PROVENANCE_POLICY_SCHEMA,
        "trusted_store_identities": tuple(sorted(trusted_store_identities)),
        "maximum_input_bytes": maximum_input_bytes,
    }
    return canonical.content_digest(payload)


_STAMP_FIELD = {
    ProvenanceInputRole.ANALYZER: "analyzer_revision",
    ProvenanceInputRole.FAMILY_CONTRACT: "family_contract_digest",
    ProvenanceInputRole.FACT_SET: "fact_set_digest",
    ProvenanceInputRole.ACQUISITION: "acquisition_record_digest",
    ProvenanceInputRole.CONFIGURATION: "configuration_digest",
    ProvenanceInputRole.POPULATION: "population_digest",
    ProvenanceInputRole.CHANGE_INPUT: "change_input_digest",
}


def _index_inputs(inputs: tuple[NamedInput, ...]) -> dict[ProvenanceInputRole, NamedInput]:
    indexed: dict[ProvenanceInputRole, NamedInput] = {}
    for item in inputs:
        if not isinstance(item.role, ProvenanceInputRole):
            raise ProvenanceValidationError(f"unknown named input role: {item.role!r}")
        if item.role in indexed:
            raise ProvenanceValidationError(f"duplicate named input role: {item.role.value}")
        indexed[item.role] = item
    missing = set(ProvenanceInputRole) - set(indexed)
    if missing:
        names = ", ".join(sorted(role.value for role in missing))
        raise ProvenanceValidationError(f"missing named input roles: {names}")
    return indexed


def _validate_policy(trust: ProvenanceTrustPolicy) -> None:
    expected = derive_trust_policy_digest(trust.trusted_store_identities, trust.maximum_input_bytes)
    if trust.policy_digest != expected:
        raise ProvenanceValidationError("provenance trust policy digest cannot be re-derived")


def _validate_manifest(named_inputs: NamedInputs) -> None:
    expected = derive_named_inputs_digest(named_inputs.inputs)
    if named_inputs.manifest_digest != expected:
        raise ProvenanceValidationError("named input manifest digest cannot be re-derived")


def validate_provenance(
    stamp: ProvenanceStamp,
    named_inputs: NamedInputs,
    resolver: ContentResolver,
    trust: ProvenanceTrustPolicy,
) -> None:
    """Resolve every closed-role input and reproduce each immutable stamp identity."""
    _validate_policy(trust)
    indexed = _index_inputs(named_inputs.inputs)
    _validate_manifest(named_inputs)
    mismatches: list[str] = []
    for role in ProvenanceInputRole:
        item = indexed[role]
        canonical.resolve_content(
            item.content,
            resolver,
            trusted_store_identities=trust.trusted_store_identities,
            maximum_bytes=trust.maximum_input_bytes,
        )
        if item.identity != item.content.content_digest:
            raise ProvenanceValidationError(f"{role.value} named identity does not match resolved content")
        field_name = _STAMP_FIELD[role]
        if getattr(stamp, field_name) != item.identity:
            mismatches.append(field_name)
    if mismatches:
        raise ProvenanceValidationError(f"stamp identities do not match named inputs: {', '.join(mismatches)}")


__all__ = [
    "CUSTODY_LOG_SCHEMA",
    "CUSTODY_POLICY_SCHEMA",
    "CUSTODY_RECEIPT_SCHEMA",
    "CUSTODY_REQUEST_SCHEMA",
    "LineagePurpose",
    "LINEAGE_DECISION_SCHEMA",
    "LINEAGE_MANIFEST_SCHEMA",
    "LineageDecision",
    "LineageExpectation",
    "LineageManifest",
    "LineageUse",
    "LineageValidationError",
    "PopulationCustodyError",
    "PopulationCustodyLog",
    "PopulationCustodyPolicy",
    "PopulationCustodyPort",
    "PopulationStatus",
    "PopulationUseReceipt",
    "PopulationUseRequest",
    "append_population_use",
    "derive_population_custody_policy_digest",
    "derive_population_use_receipt_digest",
    "derive_population_use_request_digest",
    "empty_population_custody_log",
    "record_population_use",
    "validate_population_custody_log",
    "DecisionProvenance",
    "ModelCallIdentity",
    "NAMED_INPUTS_SCHEMA",
    "NamedInput",
    "NamedInputs",
    "PROVENANCE_POLICY_SCHEMA",
    "ProvenanceInputRole",
    "ProvenanceStamp",
    "ProvenanceTrustPolicy",
    "ProvenanceValidationError",
    "derive_named_inputs_digest",
    "derive_lineage_decision_digest",
    "derive_lineage_manifest_digest",
    "derive_trust_policy_digest",
    "validate_provenance",
    "validate_lineage",
]
