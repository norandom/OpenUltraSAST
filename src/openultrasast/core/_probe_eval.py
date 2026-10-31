"""Validation and evaluation helpers for canonical reversed-surface probes."""

from __future__ import annotations

from decimal import Decimal

from openultrasast.core import canonical
from openultrasast.core.factpack import (
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.family import FamilyContract, family_contract_digest
from openultrasast.core.probes import (
    ProbeObservation,
    ProbeResult,
    ProbeValidationError,
    ReversedPairProbe,
    SemanticProjection,
    _probe_digest,
    derive_equivalence_subject_digest,
    project_semantics,
)


def _validate_policy(policy: ReviewIndependencePolicy) -> None:
    if not isinstance(policy, ReviewIndependencePolicy):
        raise ProbeValidationError("review policy has the wrong type")
    policy.__post_init__()
    expected = derive_review_independence_policy_digest(
        policy.reviewed_reviewer_digests,
        policy.forbidden_identity_pairs,
        policy.trusted_store_identities,
        policy.maximum_evidence_bytes,
    )
    if policy.policy_digest != expected:
        raise ProbeValidationError("review policy digest cannot be re-derived")


def _resolve_inputs(
    probe: ReversedPairProbe,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> None:
    surfaces = tuple(
        canonical.resolve_content(
            reference,
            resolver,
            trusted_store_identities=policy.trusted_store_identities,
            maximum_bytes=policy.maximum_evidence_bytes,
        )
        for reference in (probe.forward_surface, probe.reversed_surface)
    )
    if not all(surfaces):
        raise ProbeValidationError("surface artifacts must be nonempty")
    if surfaces[0] == surfaces[1]:
        raise ProbeValidationError("probe requires distinct surface artifact bytes")
    disclosure = canonical.resolve_content(
        probe.equivalence.independence.conflict_disclosure,
        resolver,
        trusted_store_identities=policy.trusted_store_identities,
        maximum_bytes=policy.maximum_evidence_bytes,
    )
    if not disclosure:
        raise ProbeValidationError("equivalence conflict disclosure must be nonempty")


def _validate_review(
    probe: ReversedPairProbe,
    forward_digest: str,
    reversed_digest: str,
    policy: ReviewIndependencePolicy,
) -> None:
    review = probe.equivalence
    review.__post_init__()
    attestation = review.independence
    attestation.__post_init__()
    if (review.forward_projection_digest, review.reversed_projection_digest) != (forward_digest, reversed_digest):
        raise ProbeValidationError("review projection digests do not match derived semantics")
    expected_subject = derive_equivalence_subject_digest(
        forward_digest,
        reversed_digest,
        probe.family_contract_digest,
        probe.forward_surface,
        probe.reversed_surface,
    )
    if attestation.subject_digest != expected_subject:
        raise ProbeValidationError("equivalence attestation subject does not match canonical probe inputs")
    if attestation.attestation_digest != derive_independence_attestation_digest(attestation):
        raise ProbeValidationError("equivalence attestation digest cannot be re-derived")
    if attestation.reviewer_identity not in policy.reviewed_reviewer_digests:
        raise ProbeValidationError("equivalence reviewer is not trusted")
    if attestation.producer_identity == attestation.reviewer_identity:
        raise ProbeValidationError("equivalence review must be independent")
    if (attestation.producer_identity, attestation.reviewer_identity) in policy.forbidden_identity_pairs:
        raise ProbeValidationError("equivalence producer/reviewer pair is forbidden")


def _validate_inputs(
    probe: ReversedPairProbe,
    observation: ProbeObservation,
    contract: FamilyContract,
    policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> tuple[SemanticProjection, SemanticProjection]:
    if not isinstance(probe, ReversedPairProbe) or not isinstance(observation, ProbeObservation):
        raise ProbeValidationError("probe and observation must use v2 probe types")
    probe.__post_init__()
    observation.__post_init__()
    _validate_policy(policy)
    expected_contract = family_contract_digest(contract)
    if probe.family_contract_digest != expected_contract:
        raise ProbeValidationError("probe family contract does not match supplied contract")
    if probe.probe_id != _probe_digest(probe) or observation.probe_digest != probe.probe_id:
        raise ProbeValidationError("observation probe identity does not match canonical probe")
    decisions = {item.family_code for item in contract.decisions}
    if observation.forward_decision not in decisions or observation.reversed_decision not in decisions:
        raise ProbeValidationError("observation decision is not declared by the family")
    forward = project_semantics(probe.forward_record, contract)
    reversed_projection = project_semantics(probe.reversed_record, contract)
    _validate_review(probe, forward.projection_digest, reversed_projection.projection_digest, policy)
    _resolve_inputs(probe, policy, resolver)
    return forward, reversed_projection


def _result_reasons(
    probe: ReversedPairProbe,
    observation: ProbeObservation,
    expected_decision: str,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if observation.forward_decision != observation.reversed_decision:
        reasons.append("decision_changed_under_reversed_surface")
    if expected_decision not in (observation.forward_decision, observation.reversed_decision) or (
        observation.forward_decision == observation.reversed_decision != expected_decision
    ):
        reasons.append("component_decision_mismatch")
    if (
        observation.forward_score is not None
        and observation.reversed_score is not None
        and abs(Decimal(str(observation.forward_score)) - Decimal(str(observation.reversed_score)))
        > Decimal(str(probe.maximum_score_delta))
    ):
        reasons.append("score_delta_exceeds_tolerance")
    return tuple(reasons)


def evaluate_probe(
    probe: ReversedPairProbe,
    observation: ProbeObservation,
    contract: FamilyContract,
    review_policy: ReviewIndependencePolicy,
    resolver: canonical.ContentResolver,
) -> ProbeResult:
    """Re-derive semantic equivalence and evaluate one frozen component observation."""
    try:
        forward, reversed_projection = _validate_inputs(probe, observation, contract, review_policy, resolver)
    except ProbeValidationError:
        raise
    except (TypeError, ValueError) as exc:
        raise ProbeValidationError(f"probe input cannot be validated: {exc}") from exc
    semantic_equal = forward == reversed_projection
    if not semantic_equal:
        invalid_reasons = ["semantic_projection_mismatch"]
        if forward.family_decision != reversed_projection.family_decision:
            invalid_reasons.append("family_decision_mismatch")
        return ProbeResult(probe.probe_id, observation.component_digest, False, False, tuple(invalid_reasons), "")
    reasons = _result_reasons(probe, observation, forward.family_decision)
    return ProbeResult(probe.probe_id, observation.component_digest, True, not reasons, reasons, "")


__all__ = ["evaluate_probe"]
