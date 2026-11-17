"""Reviewed strategy-decision authority for parked benchmark arms."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum

from openultrasast.core import canonical
from openultrasast.core.canonical import ContentRef, JsonValue
from openultrasast.core.evaluation_measurement import ArmConfigurationV3
from openultrasast.core.factpack import (
    FactPackValidationError,
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)

STRATEGY_DECISION_SCHEMA = "openultrasast.valid-detection-benchmark.strategy-decision.v1"
STRATEGY_DECISION_AUTHORITY_SCHEMA = "openultrasast.valid-detection-benchmark.strategy-decision-authority.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class ArmRegistryError(ValueError):
    """An arm registration or strategy-decision authority is invalid."""


class StrategyDecisionDisposition(StrEnum):
    """The only strategy decision that can admit a parked arm to a plan."""

    ADMIT_TO_PLAN = "admit_to_plan"


def _digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ArmRegistryError(f"{field} must be a full lowercase SHA-256 digest")
    return value


def _reference_value(reference: ContentRef) -> dict[str, JsonValue]:
    return {
        "artifact_id": reference.artifact_id,
        "content_digest": reference.content_digest,
        "media_type": reference.media_type,
        "byte_length": reference.byte_length,
        "retention_policy_digest": reference.retention_policy_digest,
        "storage_receipt_digest": reference.storage_receipt_digest,
    }


def _strategy_decision_value(
    arm_id: str,
    configuration_identity_digest: str,
    decision: StrategyDecisionDisposition,
) -> dict[str, JsonValue]:
    return {
        "schema_version": STRATEGY_DECISION_SCHEMA,
        "kind": "reviewed_strategy_decision",
        "arm_id": arm_id,
        "configuration_identity_digest": configuration_identity_digest,
        "decision": decision.value,
    }


def strategy_decision_artifact_bytes(
    arm_id: str,
    configuration_identity_digest: str,
    decision: StrategyDecisionDisposition,
) -> bytes:
    """Create the exact review subject for one parked-arm lifecycle decision."""
    if type(arm_id) is not str or not arm_id:
        raise ArmRegistryError("strategy decision arm identity must be nonempty text")
    _digest(configuration_identity_digest, "strategy decision configuration identity")
    if type(decision) is not StrategyDecisionDisposition:
        raise ArmRegistryError("strategy decision must use the closed disposition enum")
    return canonical.canonical_bytes(_strategy_decision_value(arm_id, configuration_identity_digest, decision))


def _review_value(review: IndependenceAttestation) -> dict[str, JsonValue]:
    return {
        "subject_digest": review.subject_digest,
        "producer_identity": review.producer_identity,
        "reviewer_identity": review.reviewer_identity,
        "conflict_disclosure": _reference_value(review.conflict_disclosure),
        "attestation_digest": review.attestation_digest,
    }


def _authority_value(authority: StrategyDecisionAuthorityV1, *, include_digest: bool) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": STRATEGY_DECISION_AUTHORITY_SCHEMA,
        "arm_id": authority.arm_id,
        "configuration_identity_digest": authority.configuration_identity_digest,
        "decision": authority.decision.value,
        "decision_ref": _reference_value(authority.decision_ref),
        "review": _review_value(authority.review),
        "review_policy_digest": authority.review_policy_digest,
    }
    if include_digest:
        value["authority_digest"] = authority.authority_digest
    return value


@dataclass(frozen=True)
class StrategyDecisionAuthorityV1:
    """Independently reviewed authority over one exact parked-arm configuration."""

    arm_id: str
    configuration_identity_digest: str
    decision: StrategyDecisionDisposition
    decision_ref: ContentRef
    review: IndependenceAttestation
    review_policy_digest: str
    authority_digest: str

    def __post_init__(self) -> None:
        if type(self) is not StrategyDecisionAuthorityV1:
            raise ArmRegistryError("strategy decision authority must use exact StrategyDecisionAuthorityV1")
        if type(self.arm_id) is not str or not self.arm_id:
            raise ArmRegistryError("strategy decision arm identity must be nonempty text")
        _digest(self.configuration_identity_digest, "strategy decision configuration identity")
        if type(self.decision) is not StrategyDecisionDisposition:
            raise ArmRegistryError("strategy decision must use the closed disposition enum")
        if type(self.decision_ref) is not ContentRef or type(self.review) is not IndependenceAttestation:
            raise ArmRegistryError("strategy decision must use exact reference and review contracts")
        _digest(self.review_policy_digest, "strategy decision review policy digest")
        expected = canonical.content_digest(_authority_value(self, include_digest=False))
        if self.authority_digest == "":
            object.__setattr__(self, "authority_digest", expected)
        elif _digest(self.authority_digest, "strategy decision authority digest") != expected:
            raise ArmRegistryError("strategy decision authority digest does not match canonical content")


def _validated_review_policy(policy: object) -> ReviewIndependencePolicy:
    if type(policy) is not ReviewIndependencePolicy:
        raise ArmRegistryError("strategy review policy must use exact ReviewIndependencePolicy")
    try:
        policy.__post_init__()
        expected = derive_review_independence_policy_digest(
            policy.reviewed_reviewer_digests,
            policy.forbidden_identity_pairs,
            policy.trusted_store_identities,
            policy.maximum_evidence_bytes,
        )
    except (FactPackValidationError, TypeError, ValueError):
        raise ArmRegistryError("strategy review policy is invalid") from None
    if policy.policy_digest != expected:
        raise ArmRegistryError("strategy review policy digest cannot be re-derived")
    return policy


def _resolve_nonempty(
    reference: ContentRef,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
    field: str,
) -> bytes:
    failed = False
    try:
        content = canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
    except (AttributeError, TypeError, ValueError, LookupError):
        content = b""
        failed = True
    if failed or not content:
        raise ArmRegistryError(f"{field} cannot be resolved")
    return content


def _decode_strategy_decision(content: bytes) -> dict[str, object]:
    try:
        decoded = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    if type(decoded) is not dict:
        raise ArmRegistryError("strategy decision artifact must be a canonical object")
    expected_keys = {"schema_version", "kind", "arm_id", "configuration_identity_digest", "decision"}
    if set(decoded) != expected_keys or canonical.canonical_bytes(decoded) != content:
        raise ArmRegistryError("strategy decision artifact is non-canonical or has unknown fields")
    if decoded["schema_version"] != STRATEGY_DECISION_SCHEMA:
        raise ArmRegistryError("strategy decision schema version is unsupported")
    if decoded["kind"] != "reviewed_strategy_decision":
        raise ArmRegistryError("strategy decision artifact kind is invalid")
    return decoded


def _validate_strategy_review(
    authority: StrategyDecisionAuthorityV1,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    review = authority.review
    if type(review) is not IndependenceAttestation or type(review.conflict_disclosure) is not ContentRef:
        raise ArmRegistryError("strategy decision review must use exact independence contracts")
    try:
        review.__post_init__()
        review.conflict_disclosure.__post_init__()
    except (FactPackValidationError, TypeError, ValueError):
        raise ArmRegistryError("strategy decision review is invalid") from None
    if review.subject_digest != authority.decision_ref.content_digest:
        raise ArmRegistryError("strategy decision review subject does not match artifact bytes")
    if review.producer_identity == review.reviewer_identity:
        raise ArmRegistryError("strategy decision review must be independent")
    if review.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise ArmRegistryError("strategy decision reviewer is not admitted by policy")
    if (review.producer_identity, review.reviewer_identity) in policy.forbidden_identity_pairs:
        raise ArmRegistryError("strategy decision producer/reviewer pair is forbidden")
    if review.attestation_digest != derive_independence_attestation_digest(review):
        raise ArmRegistryError("strategy decision review digest cannot be re-derived")
    _resolve_nonempty(review.conflict_disclosure, policy, resolver, "strategy conflict disclosure")


def validate_strategy_decision_authority(
    authority: StrategyDecisionAuthorityV1,
    configuration: ArmConfigurationV3,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    """Re-resolve one reviewed strategy decision against its exact arm configuration."""
    if type(authority) is not StrategyDecisionAuthorityV1:
        raise ArmRegistryError("strategy decision must use exact StrategyDecisionAuthorityV1")
    if type(configuration) is not ArmConfigurationV3:
        raise ArmRegistryError("strategy decision configuration must use exact ArmConfigurationV3")
    authority.__post_init__()
    configuration.__post_init__()
    policy = _validated_review_policy(policy)
    if authority.review_policy_digest != policy.policy_digest:
        raise ArmRegistryError("strategy decision review policy identity does not match")
    content = _resolve_nonempty(authority.decision_ref, policy, resolver, "strategy decision artifact")
    decoded = _decode_strategy_decision(content)
    expected = _strategy_decision_value(authority.arm_id, authority.configuration_identity_digest, authority.decision)
    if decoded != expected:
        raise ArmRegistryError("strategy decision artifact does not match its authority")
    if authority.arm_id != configuration.arm_id:
        raise ArmRegistryError("strategy decision arm identity does not match registration")
    if authority.configuration_identity_digest != configuration.configuration_identity_digest:
        raise ArmRegistryError("strategy decision configuration identity does not match registration")
    _validate_strategy_review(authority, policy, resolver)


def review_strategy_decision_authority(
    configuration: ArmConfigurationV3,
    decision_ref: ContentRef,
    review: IndependenceAttestation,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> StrategyDecisionAuthorityV1:
    """Accept an independently reviewed lifecycle decision over one exact arm."""
    if type(configuration) is not ArmConfigurationV3 or type(decision_ref) is not ContentRef:
        raise ArmRegistryError("strategy decision requires exact configuration and content reference")
    draft = StrategyDecisionAuthorityV1(
        configuration.arm_id,
        configuration.configuration_identity_digest,
        StrategyDecisionDisposition.ADMIT_TO_PLAN,
        decision_ref,
        review,
        policy.policy_digest,
        "",
    )
    validate_strategy_decision_authority(draft, configuration, policy, resolver)
    return draft


__all__ = [
    "STRATEGY_DECISION_AUTHORITY_SCHEMA",
    "STRATEGY_DECISION_SCHEMA",
    "ArmRegistryError",
    "StrategyDecisionAuthorityV1",
    "StrategyDecisionDisposition",
    "review_strategy_decision_authority",
    "strategy_decision_artifact_bytes",
    "validate_strategy_decision_authority",
]
