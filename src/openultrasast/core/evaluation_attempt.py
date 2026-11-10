"""Immutable reviewed attempt-history contracts for evaluation admission V3."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, cast

from openultrasast.core import canonical
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_version import (
    EVALUATION_ADMISSION_V3_SCHEMA,
    EvaluationV3Contract,
    NonAuthorizingV3,
    require_exact_v3_contract,
)
from openultrasast.core.factpack import IndependenceAttestation, ReviewIndependencePolicy

_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTITY_SCHEMA = "openultrasast.detection-core.evaluation-attempt-identity.v3"
_ACCESS_SCHEMA = "openultrasast.detection-core.evaluation-observation-access-policy.v3"
_PAYLOAD_SCHEMA = "openultrasast.detection-core.evaluation-attempt-payload.v3"
_EVENT_SCHEMA = "openultrasast.detection-core.evaluation-attempt-event.v3"
_REFERENCE_SCHEMA = "openultrasast.detection-core.evaluation-attempt-reference.v3"
_HISTORY_SCHEMA = "openultrasast.detection-core.evaluation-attempt-history.v3"
_PUBLIC_STATUS_SCHEMA = "openultrasast.detection-core.evaluation-public-status.v3"
_CONTENT_REF_FIELDS = frozenset(
    {"artifact_id", "content_digest", "media_type", "byte_length", "retention_policy_digest", "storage_receipt_digest"}
)
_REVIEW_FIELDS = frozenset({"subject_digest", "producer_identity", "reviewer_identity", "conflict_disclosure", "attestation_digest"})
_IDENTITY_FIELDS = frozenset(
    {
        "population_digest",
        "plan_declaration_digest",
        "baseline_digests",
        "input_set_digest",
        "configuration_digests",
        "registered_budget_digests",
        "execution_identities",
        "retry_identity_digest",
    }
)
_ACCESS_FIELDS = frozenset(
    {"allowed_public_fields", "raw_observation_access_allowed", "population_diagnostic_access_allowed", "policy_digest"}
)
_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_identity",
        "disposition",
        "access_policy",
        "raw_observation_access_count",
        "population_diagnostic_access_count",
        "public_status_projection",
        "predecessor_event_digest",
        "payload_digest",
        "review",
        "event_digest",
    }
)


class EvaluationAttemptError(ValueError):
    """A V3 attempt history is malformed, exposed, or ineligible for admission."""


class PreSpendDispositionV3(Enum):
    SEALED = "sealed"
    DEVELOPMENT_OPENED = "development_opened"
    SPENT = "spent"


class PublicStatusFieldV3(Enum):
    STATUS_CODE = "status_code"
    COUNT = "count"
    DIGEST = "digest"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvaluationAttemptError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _digest_tuple(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise EvaluationAttemptError(f"{field} must be a nonempty tuple")
    for item in value:
        _digest(item, field)
    return value


def _text_tuple(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value or any(type(item) is not str or not item for item in value):
        raise EvaluationAttemptError(f"{field} must be a nonempty exact-text tuple")
    return value


def _bind(value: object, field: str, expected: str) -> None:
    actual = getattr(value, field)
    if actual == "":
        object.__setattr__(value, field, expected)
    elif _digest(actual, field) != expected:
        raise EvaluationAttemptError(f"{field} does not match canonical content")


def _content_ref_value(value: canonical.ContentRef) -> dict[str, canonical.JsonValue]:
    return {
        "artifact_id": value.artifact_id,
        "content_digest": value.content_digest,
        "media_type": value.media_type,
        "byte_length": value.byte_length,
        "retention_policy_digest": value.retention_policy_digest,
        "storage_receipt_digest": value.storage_receipt_digest,
    }


def _review_value(value: IndependenceAttestation) -> dict[str, canonical.JsonValue]:
    return {
        "subject_digest": value.subject_digest,
        "producer_identity": value.producer_identity,
        "reviewer_identity": value.reviewer_identity,
        "conflict_disclosure": _content_ref_value(value.conflict_disclosure),
        "attestation_digest": value.attestation_digest,
    }


def _identity_value(value: AttemptIdentityV3) -> dict[str, canonical.JsonValue]:
    return {
        "population_digest": value.population_digest,
        "plan_declaration_digest": value.plan_declaration_digest,
        "baseline_digests": value.baseline_digests,
        "input_set_digest": value.input_set_digest,
        "configuration_digests": value.configuration_digests,
        "registered_budget_digests": value.registered_budget_digests,
        "execution_identities": value.execution_identities,
        "retry_identity_digest": value.retry_identity_digest,
    }


@dataclass(frozen=True)
class AttemptIdentityV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    population_digest: str
    plan_declaration_digest: str
    baseline_digests: tuple[str, ...]
    input_set_digest: str
    configuration_digests: tuple[str, ...]
    registered_budget_digests: tuple[str, ...]
    execution_identities: tuple[str, ...]
    retry_identity_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AttemptIdentityV3, field="attempt identity")
        _digest(self.population_digest, "attempt population digest")
        _digest(self.plan_declaration_digest, "attempt plan declaration digest")
        baselines = _digest_tuple(self.baseline_digests, "attempt baseline digest")
        _digest(self.input_set_digest, "attempt input set digest")
        configurations = _digest_tuple(self.configuration_digests, "attempt configuration digest")
        budgets = _digest_tuple(self.registered_budget_digests, "attempt registered budget digest")
        executions = _text_tuple(self.execution_identities, "attempt execution identities")
        if len({len(baselines), len(configurations), len(budgets), len(executions)}) != 1:
            raise EvaluationAttemptError("attempt arm identity columns must have equal length")
        payload = dict(_identity_value(self))
        payload.pop("retry_identity_digest")
        _bind(self, "retry_identity_digest", canonical.content_digest({"schema_version": _IDENTITY_SCHEMA, **payload}))


def _access_value(value: ObservationAccessPolicyV3) -> dict[str, canonical.JsonValue]:
    return {
        "allowed_public_fields": tuple(item.value for item in value.allowed_public_fields),
        "raw_observation_access_allowed": value.raw_observation_access_allowed,
        "population_diagnostic_access_allowed": value.population_diagnostic_access_allowed,
        "policy_digest": value.policy_digest,
    }


@dataclass(frozen=True)
class ObservationAccessPolicyV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    allowed_public_fields: tuple[PublicStatusFieldV3, ...]
    raw_observation_access_allowed: bool
    population_diagnostic_access_allowed: bool
    policy_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, ObservationAccessPolicyV3, field="observation access policy")
        if type(self.allowed_public_fields) is not tuple or not self.allowed_public_fields:
            raise EvaluationAttemptError("allowed public fields must be a nonempty canonical tuple")
        if any(type(item) is not PublicStatusFieldV3 for item in self.allowed_public_fields):
            raise EvaluationAttemptError("allowed public fields must use the closed PublicStatusFieldV3 enum")
        canonical_fields = tuple(item for item in PublicStatusFieldV3 if item in self.allowed_public_fields)
        if self.allowed_public_fields != canonical_fields:
            raise EvaluationAttemptError("allowed public fields must be unique and canonical")
        if type(self.raw_observation_access_allowed) is not bool or type(self.population_diagnostic_access_allowed) is not bool:
            raise EvaluationAttemptError("observation access flags must be exact booleans")
        payload = dict(_access_value(self))
        payload.pop("policy_digest")
        _bind(self, "policy_digest", canonical.content_digest({"schema_version": _ACCESS_SCHEMA, **payload}))


def _event_payload_value(value: AttemptEventV3) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": _PAYLOAD_SCHEMA,
        "attempt_identity": _identity_value(value.attempt_identity),
        "disposition": value.disposition.value,
        "access_policy": _access_value(value.access_policy),
        "raw_observation_access_count": value.raw_observation_access_count,
        "population_diagnostic_access_count": value.population_diagnostic_access_count,
        "public_status_projection": _content_ref_value(value.public_status_projection),
        "predecessor_event_digest": value.predecessor_event_digest,
    }


def _event_value(value: AttemptEventV3) -> dict[str, canonical.JsonValue]:
    payload = dict(_event_payload_value(value))
    payload["schema_version"] = _EVENT_SCHEMA
    return {**payload, "payload_digest": value.payload_digest, "review": _review_value(value.review), "event_digest": value.event_digest}


@dataclass(frozen=True)
class AttemptEventV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    attempt_identity: AttemptIdentityV3
    disposition: PreSpendDispositionV3
    access_policy: ObservationAccessPolicyV3
    raw_observation_access_count: int
    population_diagnostic_access_count: int
    public_status_projection: canonical.ContentRef
    predecessor_event_digest: str | None
    payload_digest: str
    review: IndependenceAttestation
    event_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AttemptEventV3, field="attempt event")
        if type(self.attempt_identity) is not AttemptIdentityV3 or type(self.access_policy) is not ObservationAccessPolicyV3:
            raise EvaluationAttemptError("attempt event identity and access policy must use exact V3 values")
        self.attempt_identity.__post_init__()
        self.access_policy.__post_init__()
        if type(self.disposition) is not PreSpendDispositionV3:
            raise EvaluationAttemptError("attempt disposition must use the closed PreSpendDispositionV3 enum")
        for count, field in (
            (self.raw_observation_access_count, "raw observation access count"),
            (self.population_diagnostic_access_count, "population diagnostic access count"),
        ):
            if type(count) is not int or count < 0:
                raise EvaluationAttemptError(f"{field} must be a non-negative integer")
        if type(self.public_status_projection) is not canonical.ContentRef:
            raise EvaluationAttemptError("public status projection must use exact ContentRef")
        self.public_status_projection.__post_init__()
        if self.predecessor_event_digest is not None:
            _digest(self.predecessor_event_digest, "predecessor event digest")
        if type(self.review) is not IndependenceAttestation:
            raise EvaluationAttemptError("attempt review must use exact IndependenceAttestation")
        self.review.__post_init__()
        _bind(self, "payload_digest", canonical.content_digest(_event_payload_value(self)))
        _bind(
            self,
            "event_digest",
            canonical.content_digest(
                {"schema_version": _EVENT_SCHEMA, "payload_digest": self.payload_digest, "review": _review_value(self.review)}
            ),
        )


def _reference_value(value: AttemptEventRefV3) -> dict[str, canonical.JsonValue]:
    return {"schema_version": _REFERENCE_SCHEMA, "event": _content_ref_value(value.event), "event_digest": value.event_digest}


@dataclass(frozen=True)
class AttemptEventRefV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    event: canonical.ContentRef
    event_digest: str
    ref_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AttemptEventRefV3, field="attempt event reference")
        if type(self.event) is not canonical.ContentRef:
            raise EvaluationAttemptError("attempt event reference must use exact ContentRef")
        self.event.__post_init__()
        _digest(self.event_digest, "referenced attempt event digest")
        _bind(self, "ref_digest", canonical.content_digest(_reference_value(self)))


def _history_value(value: AttemptHistoryV3) -> dict[str, canonical.JsonValue]:
    return {
        "schema_version": _HISTORY_SCHEMA,
        "population_digest": value.population_digest,
        "event_ref_digests": tuple(item.ref_digest for item in value.events),
        "head_event_digest": value.head_event_digest,
    }


@dataclass(frozen=True)
class AttemptHistoryV3(EvaluationV3Contract, NonAuthorizingV3):
    __evaluation_v3_contract_schema__: ClassVar[str] = EVALUATION_ADMISSION_V3_SCHEMA
    population_digest: str
    events: tuple[AttemptEventRefV3, ...]
    head_event_digest: str
    history_digest: str

    def __post_init__(self) -> None:
        require_exact_v3_contract(self, AttemptHistoryV3, field="attempt history")
        _digest(self.population_digest, "attempt history population digest")
        if type(self.events) is not tuple or not self.events or any(type(item) is not AttemptEventRefV3 for item in self.events):
            raise EvaluationAttemptError("attempt history events must be a nonempty tuple of exact references")
        for item in self.events:
            item.__post_init__()
        _digest(self.head_event_digest, "attempt history head digest")
        _bind(self, "history_digest", canonical.content_digest(_history_value(self)))


def derive_attempt_identity(manifest: EvaluationPlanManifestV3) -> AttemptIdentityV3:
    """Derive the complete collision-resistant retry identity from one reviewed plan shape."""
    if type(manifest) is not EvaluationPlanManifestV3:
        raise EvaluationAttemptError("attempt identity requires exact EvaluationPlanManifestV3")
    manifest.__post_init__()
    declaration = manifest.declaration
    configurations = declaration.arm_configurations
    return AttemptIdentityV3(
        declaration.population_digest,
        declaration.declaration_digest,
        tuple(item.baseline_digest for item in manifest.baselines),
        declaration.input_set_digest,
        tuple(item.configuration_identity_digest for item in configurations),
        tuple(item.registered_budget_digest for item in configurations),
        tuple(item.execution_identity for item in configurations),
        "",
    )


def encode_attempt_event(value: AttemptEventV3) -> bytes:
    if type(value) is not AttemptEventV3:
        raise EvaluationAttemptError("attempt event must use exact AttemptEventV3")
    value.__post_init__()
    return canonical.canonical_bytes(_event_value(value))


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationAttemptError(f"duplicate attempt event field: {key}")
        result[key] = value
    return result


def _document(content: bytes) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise EvaluationAttemptError("attempt event bytes must be nonzero exact bytes")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationAttemptError("attempt event bytes must contain valid UTF-8 JSON") from exc
    if type(value) is not dict or frozenset(value) != _EVENT_FIELDS or value["schema_version"] != _EVENT_SCHEMA:
        raise EvaluationAttemptError("attempt event document must use the exact V3 field set and schema")
    return value


def _decode_ref(value: object) -> canonical.ContentRef:
    if type(value) is not dict or frozenset(value) != _CONTENT_REF_FIELDS:
        raise EvaluationAttemptError("content reference must use the exact canonical field set")
    try:
        return canonical.ContentRef(**value)
    except (TypeError, ValueError) as exc:
        raise EvaluationAttemptError("content reference is malformed") from exc


def _decode_identity(value: object) -> AttemptIdentityV3:
    if type(value) is not dict or frozenset(value) != _IDENTITY_FIELDS:
        raise EvaluationAttemptError("attempt identity must use the exact canonical field set")
    try:
        return AttemptIdentityV3(
            value["population_digest"],
            value["plan_declaration_digest"],
            tuple(value["baseline_digests"]),
            value["input_set_digest"],
            tuple(value["configuration_digests"]),
            tuple(value["registered_budget_digests"]),
            tuple(value["execution_identities"]),
            value["retry_identity_digest"],
        )
    except (TypeError, ValueError) as exc:
        raise EvaluationAttemptError("attempt identity is malformed") from exc


def _decode_access(value: object) -> ObservationAccessPolicyV3:
    if type(value) is not dict or frozenset(value) != _ACCESS_FIELDS:
        raise EvaluationAttemptError("access policy must use the exact canonical field set")
    try:
        fields = tuple(PublicStatusFieldV3(item) for item in value["allowed_public_fields"])
        return ObservationAccessPolicyV3(
            fields, value["raw_observation_access_allowed"], value["population_diagnostic_access_allowed"], value["policy_digest"]
        )
    except (TypeError, ValueError) as exc:
        raise EvaluationAttemptError("access policy is malformed") from exc


def _decode_review(value: object) -> IndependenceAttestation:
    if type(value) is not dict or frozenset(value) != _REVIEW_FIELDS:
        raise EvaluationAttemptError("attempt review must use the exact canonical field set")
    try:
        return IndependenceAttestation(
            value["subject_digest"],
            value["producer_identity"],
            value["reviewer_identity"],
            _decode_ref(value["conflict_disclosure"]),
            value["attestation_digest"],
        )
    except (TypeError, ValueError) as exc:
        raise EvaluationAttemptError("attempt review is malformed") from exc


def decode_attempt_event(content: bytes) -> AttemptEventV3:
    """Decode only the exact canonical reviewed attempt-event representation."""
    value = _document(content)
    try:
        predecessor = value["predecessor_event_digest"]
        if predecessor is not None:
            predecessor = _digest(predecessor, "predecessor event digest")
        event = AttemptEventV3(
            _decode_identity(value["attempt_identity"]),
            PreSpendDispositionV3(value["disposition"]),
            _decode_access(value["access_policy"]),
            cast(int, value["raw_observation_access_count"]),
            cast(int, value["population_diagnostic_access_count"]),
            _decode_ref(value["public_status_projection"]),
            predecessor,
            _digest(value["payload_digest"], "attempt payload digest"),
            _decode_review(value["review"]),
            _digest(value["event_digest"], "attempt event digest"),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EvaluationAttemptError):
            raise
        raise EvaluationAttemptError("attempt event document contains malformed values") from exc
    if encode_attempt_event(event) != content:
        raise EvaluationAttemptError("attempt event document is not canonical JSON")
    return event


def validate_evaluation_attempt_history(
    manifest: EvaluationPlanManifestV3,
    history: AttemptHistoryV3,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[AttemptEventV3, ...]:
    """Resolve a reviewed chain and return it only when every exact retry remains sealed."""
    from openultrasast.core._evaluation_attempt_validation import validate_attempt_history

    return validate_attempt_history(manifest, history, review_policy, resolver)


__all__ = [
    "AttemptEventRefV3",
    "AttemptEventV3",
    "AttemptHistoryV3",
    "AttemptIdentityV3",
    "EvaluationAttemptError",
    "ObservationAccessPolicyV3",
    "PreSpendDispositionV3",
    "PublicStatusFieldV3",
    "decode_attempt_event",
    "derive_attempt_identity",
    "encode_attempt_event",
    "validate_evaluation_attempt_history",
]
