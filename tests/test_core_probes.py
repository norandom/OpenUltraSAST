"""Independently reviewed equal-semantics reversed-surface probes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

import openultrasast.core as public_core
from openultrasast.core import canonical, evidence, probes, provenance, semantics
from openultrasast.core.factpack import (
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.family import (
    DecisionRule,
    FamilyContract,
    FieldSpec,
    ObjectSpec,
    RelationOriginPolicy,
    ResidualQuestion,
    RoleSpec,
    derive_security_object_id,
    family_contract_digest,
)


@dataclass(frozen=True)
class ProbeCase:
    probe: probes.ReversedPairProbe
    observation: probes.ProbeObservation
    contract: FamilyContract
    policy: ReviewIndependencePolicy
    resolver: InMemoryContentResolver


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _contract() -> FamilyContract:
    return FamilyContract(
        "probe-family",
        "1",
        evidence.EVIDENCE_PACKET_SCHEMA,
        ("python",),
        ObjectSpec(
            "resource",
            (FieldSpec("operation", semantics.FieldKind.TEXT, True),),
            ("operation",),
        ),
        (
            RoleSpec(
                "flow",
                (),
                (semantics.RelationKind.CALL,),
                RelationOriginPolicy.PRODUCT_OR_REVIEWED_FACT,
            ),
        ),
        (
            DecisionRule(
                "unsafe",
                evidence.NeutralOutcome.VIOLATION,
                ("flow",),
                (semantics.RelationStatus.COMPLETE,),
            ),
            DecisionRule(
                "safe",
                evidence.NeutralOutcome.SATISFIED,
                ("flow",),
                (semantics.RelationStatus.COMPLETE,),
            ),
        ),
        (ResidualQuestion("classify", ("flow",), ("unsafe", "safe")),),
        ("missing",),
    )


def _record(contract: FamilyContract, path: str, *, operation: str = "read", decision: str = "unsafe") -> evidence.EvidenceRecord:
    location = semantics.SourceLocation(path, 7, 2, "run")
    product = semantics.EvidenceProvenance(
        semantics.ProvenanceKind.PRODUCT_CODE,
        _digest(f"source:{path}"),
        None,
        None,
        None,
    )
    relation = semantics.make_relation(
        kind=semantics.RelationKind.CALL,
        role="flow",
        source=semantics.SemanticNode(f"source:{path}", "source", location),
        target=semantics.SemanticNode(f"target:{path}", "target", location),
        location=location,
        status=semantics.RelationStatus.COMPLETE,
        conditions=("reachable",),
        reasons=(),
        provenance=product,
    )
    fields = (semantics.FieldValue("operation", semantics.FieldKind.TEXT, operation),)
    scope = evidence.AnalyzedScope("base", "head", _digest(f"change:{path}"), (evidence.SourceRegion(path, 1, 20),))
    stamp = provenance.ProvenanceStamp(
        _digest("analyzer"),
        family_contract_digest(contract),
        _digest("facts"),
        _digest("acquisition"),
        _digest("configuration"),
        _digest("population"),
        _digest(f"input:{path}"),
    )
    packet = evidence.EvidencePacket(
        evidence.EVIDENCE_PACKET_SCHEMA,
        contract.family_id,
        family_contract_digest(contract),
        derive_security_object_id(contract.security_object, fields),
        "python",
        scope,
        (relation,),
        (),
        fields,
        (),
        stamp,
    )
    outcome = evidence.NeutralOutcome.VIOLATION if decision == "unsafe" else evidence.NeutralOutcome.SATISFIED
    derived = evidence.Decision(
        decision,
        outcome,
        evidence.EvidenceBasis.DETERMINISTIC,
        scope,
        (),
        evidence.derive_packet_digest(packet),
        provenance.DecisionProvenance(None, None, None, None, None, None),
    )
    return evidence.EvidenceRecord(packet, derived, "")


def _policy(reviewer: str) -> ReviewIndependencePolicy:
    reviewers = (reviewer,)
    stores = ("trusted-store",)
    digest = derive_review_independence_policy_digest(reviewers, (), stores, 4096)
    return ReviewIndependencePolicy(reviewers, (), stores, 4096, digest)


def _review(
    forward: probes.SemanticProjection,
    reversed_projection: probes.SemanticProjection,
    contract: FamilyContract,
    forward_surface: canonical.ContentRef,
    reversed_surface: canonical.ContentRef,
    disclosure: canonical.ContentRef,
    *,
    producer: str,
    reviewer: str,
) -> probes.SemanticEquivalenceReview:
    subject = probes.derive_equivalence_subject_digest(
        forward.projection_digest,
        reversed_projection.projection_digest,
        family_contract_digest(contract),
        forward_surface,
        reversed_surface,
    )
    provisional = IndependenceAttestation(subject, producer, reviewer, disclosure, "0" * 64)
    attestation = replace(
        provisional,
        attestation_digest=derive_independence_attestation_digest(provisional),
    )
    return probes.SemanticEquivalenceReview(
        forward.projection_digest,
        reversed_projection.projection_digest,
        attestation,
        "",
    )


def _case(
    *,
    reversed_operation: str = "read",
    reversed_decision: str = "unsafe",
    forward_surface_bytes: bytes = b"- old\n+ new\n",
    reversed_surface_bytes: bytes = b"+ old\n- new\n",
    same_reviewer: bool = False,
) -> ProbeCase:
    contract = _contract()
    forward_record = _record(contract, "src/forward.py")
    reversed_record = _record(
        contract,
        "src/reversed.py",
        operation=reversed_operation,
        decision=reversed_decision,
    )
    forward_surface, forward_resolver = stored_artifact(forward_surface_bytes, artifact_id="forward-surface")
    reversed_surface, reversed_resolver = stored_artifact(reversed_surface_bytes, artifact_id="reversed-surface")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="review-disclosure")
    producer = _digest("fixture-producer")
    reviewer = producer if same_reviewer else _digest("independent-reviewer")
    forward_projection = probes.project_semantics(forward_record, contract)
    reversed_projection = probes.project_semantics(reversed_record, contract)
    review = _review(
        forward_projection,
        reversed_projection,
        contract,
        forward_surface,
        reversed_surface,
        disclosure,
        producer=producer,
        reviewer=reviewer,
    )
    probe = probes.ReversedPairProbe(
        "",
        family_contract_digest(contract),
        forward_record,
        reversed_record,
        forward_surface,
        reversed_surface,
        review,
        0.05,
    )
    observation = probes.ProbeObservation(
        probe.probe_id,
        _digest("relation-component"),
        "unsafe",
        "unsafe",
        0.50,
        0.52,
    )
    artifacts = {
        **forward_resolver.artifacts,
        **reversed_resolver.artifacts,
        **disclosure_resolver.artifacts,
    }
    return ProbeCase(probe, observation, contract, _policy(reviewer), InMemoryContentResolver(artifacts))


def test_projection_excludes_paths_and_surface_presentation() -> None:
    case = _case()
    forward = probes.project_semantics(case.probe.forward_record, case.contract)
    reversed_projection = probes.project_semantics(case.probe.reversed_record, case.contract)

    assert forward == reversed_projection
    assert forward.family_decision == "unsafe"
    assert forward.roles[0].relation_kinds == (semantics.RelationKind.CALL,)
    assert forward.security_object_fields[0].value == "read"


def test_relation_component_passes_equal_semantics_within_registered_tolerance() -> None:
    case = _case()

    result = probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)
    repeated = probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)

    assert result.valid is True
    assert result.passed is True
    assert result.reasons == ()
    assert repeated == result


def test_surface_shape_score_gap_is_detected() -> None:
    case = _case()
    shaped = replace(case.observation, component_digest=_digest("surface-component"), reversed_score=0.90)

    result = probes.evaluate_probe(case.probe, shaped, case.contract, case.policy, case.resolver)

    assert result.valid is True
    assert result.passed is False
    assert result.reasons == ("score_delta_exceeds_tolerance",)


def test_score_delta_at_registered_tolerance_boundary_passes() -> None:
    case = _case()
    boundary = replace(case.observation, forward_score=0.50, reversed_score=0.55)

    result = probes.evaluate_probe(case.probe, boundary, case.contract, case.policy, case.resolver)

    assert result.valid is True
    assert result.passed is True


def test_score_delta_just_above_registered_tolerance_boundary_fails() -> None:
    case = _case()
    above = replace(case.observation, forward_score=0.50, reversed_score=0.550000000001)

    result = probes.evaluate_probe(case.probe, above, case.contract, case.policy, case.resolver)

    assert result.valid is True
    assert result.passed is False
    assert result.reasons == ("score_delta_exceeds_tolerance",)


def test_unequal_derived_semantics_make_probe_invalid() -> None:
    case = _case(reversed_operation="write")

    result = probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)

    assert result.valid is False
    assert result.passed is False
    assert "semantic_projection_mismatch" in result.reasons


def test_different_declared_family_decisions_make_probe_invalid() -> None:
    case = _case(reversed_decision="safe")

    result = probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)

    assert result.valid is False
    assert result.reasons == ("semantic_projection_mismatch", "family_decision_mismatch")


def test_constant_but_wrong_component_decision_does_not_pass() -> None:
    case = _case()
    wrong = replace(case.observation, forward_decision="safe", reversed_decision="safe")

    result = probes.evaluate_probe(case.probe, wrong, case.contract, case.policy, case.resolver)

    assert result.valid is True
    assert result.passed is False
    assert result.reasons == ("component_decision_mismatch",)


def test_digest_only_equivalence_claim_is_refused() -> None:
    case = _case()
    fake = _digest("caller-claimed-projection")
    attestation = case.probe.equivalence.independence
    subject = probes.derive_equivalence_subject_digest(
        fake,
        fake,
        family_contract_digest(case.contract),
        case.probe.forward_surface,
        case.probe.reversed_surface,
    )
    provisional = replace(attestation, subject_digest=subject, attestation_digest="0" * 64)
    signed = replace(provisional, attestation_digest=derive_independence_attestation_digest(provisional))
    review = probes.SemanticEquivalenceReview(fake, fake, signed, "")
    substituted = replace(case.probe, equivalence=review, probe_id="")
    observation = replace(case.observation, probe_digest=substituted.probe_id)

    with pytest.raises(probes.ProbeValidationError, match="projection"):
        probes.evaluate_probe(substituted, observation, case.contract, case.policy, case.resolver)


@pytest.mark.parametrize("tolerance", [float("nan"), float("inf"), -0.01])
def test_tolerance_must_be_finite_and_nonnegative(tolerance: float) -> None:
    case = _case()

    with pytest.raises(probes.ProbeValidationError, match="finite non-negative"):
        replace(case.probe, maximum_score_delta=tolerance, probe_id="")


def test_surface_artifacts_must_resolve_to_distinct_bytes() -> None:
    case = _case(reversed_surface_bytes=b"- old\n+ new\n")

    with pytest.raises(probes.ProbeValidationError, match="distinct surface"):
        probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)


def test_equivalence_review_must_be_independent() -> None:
    case = _case(same_reviewer=True)

    with pytest.raises(probes.ProbeValidationError, match="independent"):
        probes.evaluate_probe(case.probe, case.observation, case.contract, case.policy, case.resolver)


def test_fabricated_passed_summary_is_refused_by_re_evaluation() -> None:
    case = _case()
    shaped = replace(case.observation, component_digest=_digest("surface-component"), reversed_score=0.90)
    forged = probes.ProbeResult(case.probe.probe_id, shaped.component_digest, True, True, (), "")

    with pytest.raises(probes.ProbeValidationError, match="claimed probe result"):
        probes.validate_probe_result(
            probes.ProbeEvaluationInput(case.probe, shaped),
            forged,
            case.contract,
            case.policy,
            case.resolver,
        )


def test_observation_for_another_probe_is_refused() -> None:
    case = _case()
    substituted = replace(case.observation, probe_digest=_digest("another-probe"))

    with pytest.raises(probes.ProbeValidationError, match="probe identity"):
        probes.evaluate_probe(case.probe, substituted, case.contract, case.policy, case.resolver)


def test_legacy_reversed_pair_probe_remains_compatible() -> None:
    forward: dict[str, Any] = {"lines": 10}
    reversed_change: dict[str, Any] = {"lines": 50}

    def shape_score(change: Mapping[str, Any]) -> float:
        return float(change["lines"])

    result = probes.reversed_pair_probe(shape_score, forward, reversed_change)
    assert result.separated is True
    with pytest.raises(probes.ShortcutDetected):
        probes.assert_no_shortcut(shape_score, forward, reversed_change)

    assert public_core.ProbeResult is probes.LegacyProbeResult


def test_legacy_admission_guard_remains_compatible() -> None:
    probes.require_admission_evidence(holdout_passed=True, admission_decision="GO")
    with pytest.raises(probes.FittedComponentBlocked):
        probes.require_admission_evidence(holdout_passed=False, admission_decision="GO")
