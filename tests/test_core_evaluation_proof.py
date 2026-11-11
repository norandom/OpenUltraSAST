"""Released proof-candidate continuity for evaluation admission V3."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_evaluation_case_validation import _bundle
from test_core_evaluation_combination import _valid_bindings
from test_core_evaluation_plan import _declaration
from test_core_evaluation_plan_review import _attestation
from test_core_proof import _case as _proof_case
from test_core_proof import _claim

from openultrasast.core import canonical, provenance, validation
from openultrasast.core._proof_attestation import proof_attestation_bytes
from openultrasast.core.admission_case import AdmissionCaseRole, derive_admission_case_result_digest
from openultrasast.core.admission_context import AdmissionValidationContext, make_admission_validation_context
from openultrasast.core.evaluation_authority import EvaluationAdmissionAuthorityV3
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionPolicyV3,
    CaseOutcomeProjectionV3,
    derive_case_input_digest,
    derive_component_case_outcome_projection,
)
from openultrasast.core.evaluation_combination import derive_combination_lineages_v3
from openultrasast.core.evaluation_measurement import ArmKindV3, ArmScopeKey, ScopeKey
from openultrasast.core.evaluation_plan import EvaluationPlanManifestV3
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ProofCandidateIdentityV3,
    ReleasedArmCaseBindingV3,
    _legacy_case,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_proof_candidate_identity_digest,
)
from openultrasast.core.evidence import EvidenceBasis, EvidenceRecord, derive_packet_digest
from openultrasast.core.proof import ProofOutcome
from openultrasast.core.semantics import SourceLocation


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _adapt_proof_family(proof, family_id):
    packet = replace(proof.record.packet, family_id=family_id)
    decision = replace(proof.record.decision, packet_digest=derive_packet_digest(packet))
    record = EvidenceRecord(packet, decision, "")
    attachment = replace(
        proof.attachment,
        family_id=family_id,
        packet_digest=derive_packet_digest(packet),
        proof_id="",
    )
    return replace(proof, record=record, attachment=attachment)


def _proof_evidence_input(proof, template):
    change = proof.record.packet.provenance.change_input_digest
    inputs = tuple(
        replace(item, identity=change) if item.role is provenance.ProvenanceInputRole.CHANGE_INPUT else item
        for item in template.evidence_inputs[0].named_inputs.inputs
    )
    named = provenance.NamedInputs(inputs, provenance.derive_named_inputs_digest(inputs))
    return validation.make_evidence_validation_input(record=proof.record, named_inputs=named)


def _proof_candidate(configuration, scope, observation_digest, claim, change):
    from openultrasast.core.evaluation_proof import derive_finding_location_digest

    draft = ProofCandidateIdentityV3(
        configuration.arm_id,
        observation_digest,
        scope.family_id,
        scope,
        derive_finding_location_digest(claim.location),
        change,
        "0" * 64,
    )
    return replace(draft, candidate_digest=derive_proof_candidate_identity_digest(draft))


def _proof_binding(case, candidate, evidence_input, change, plan, arm_id):
    return ReleasedArmCaseBindingV3(
        case.key,
        _baseline(plan, arm_id),
        case.observation_slot_digest,
        case.observation_digest,
        case.underlying_push_digest,
        case.case_id_digest,
        case.case_input_digest,
        case.outcome_projection,
        case.role,
        case.pair_id_digest,
        case.result_digest,
        (evidence_input.input_digest,),
        (change,),
        case.input_manifest.manifest_digest,
        candidate.candidate_digest,
        "",
    )


def _proof_case_and_binding(proof, template, plan, configuration):
    scope = configuration.exact_scopes[0]
    claim = _claim(proof.record)
    change = proof.record.packet.provenance.change_input_digest
    evidence_input = _proof_evidence_input(proof, template)
    observation_digest = _digest("proof-observation")
    candidate = _proof_candidate(configuration, scope, observation_digest, claim, change)
    provisional = ArmAdmissionCaseResultV3(
        ArmScopeKey(configuration.arm_id, scope),
        _digest("proof-slot"),
        observation_digest,
        _digest("proof-push"),
        _digest("proof-case"),
        derive_case_input_digest((proof.record,)),
        derive_component_case_outcome_projection((proof.record,)),
        AdmissionCaseRole.VULNERABLE,
        _digest("proof-pair"),
        (evidence_input,),
        (claim,),
        (),
        (),
        candidate,
        (proof.attachment,),
        template.coverage,
        template.input_manifest,
        template.input_receipts,
        template.complexity,
        template.budget,
        template.total_reply_ms,
        "0" * 64,
    )
    case = replace(provisional, result_digest=derive_admission_case_result_digest(_legacy_case(provisional)))
    return case, _proof_binding(case, candidate, evidence_input, change, plan, configuration.arm_id)


def _proof_release(binding, release_template, authority):
    review = release_template.review
    disclosure = review.conflict_disclosure
    draft = AdmissionCaseReleaseV3(
        authority.plan_manifest_digest,
        authority.admission_manifest_digest,
        authority.authority_digest,
        release_template.preparation_digest,
        release_template.spend_binding_digest,
        (binding,),
        "0" * 64,
        _attestation("0" * 64, review.producer_identity, review.reviewer_identity, disclosure),
        "0" * 64,
    )
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(payload, review.producer_identity, review.reviewer_identity, disclosure),
    )
    return replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))


def _released_proof_case():
    bundle = _bundle()
    plan = bundle[3].plan_manifest
    configuration = next(item for item in plan.declaration.arm_configurations if item.kind is ArmKindV3.COMPONENT)
    proof = _adapt_proof_family(_proof_case(), configuration.exact_scopes[0].family_id)
    case, binding = _proof_case_and_binding(proof, bundle[2][0].cases[0], plan, configuration)
    base_context = bundle[5][0].context
    context = make_admission_validation_context(
        evidence=base_context.evidence,
        admission_review_policy=base_context.admission_review_policy,
        proof_trust_policy=proof.policy,
    )
    authority = replace(bundle[6], validation_context_digest=context.context_digest, authority_digest="")
    release = _proof_release(binding, bundle[1], authority)
    resolver = InMemoryContentResolver({**bundle[4].artifacts, **proof.resolver.artifacts})
    return case, binding, release, plan, context, authority, resolver


def _inconclusive(case: ArmAdmissionCaseResultV3, resolver: InMemoryContentResolver):
    attachment = case.proof_attachments[0]
    proof = replace(attachment.proof, outcome=ProofOutcome.INCONCLUSIVE, record_digest="")
    attestation, extra = stored_artifact(
        proof_attestation_bytes(
            attachment.verification.producer_identity_digest,
            proof.record_digest,
            proof.affected.result_digest,
            proof.safe.result_digest,
            proof.witness.content_digest,
        ),
        artifact_id="inconclusive-attestation",
    )
    verification = replace(
        attachment.verification,
        proof_record_digest=proof.record_digest,
        attestation=attestation,
        receipt_digest="",
    )
    changed = replace(attachment, proof=proof, verification=verification, proof_id="")
    merged = InMemoryContentResolver({**resolver.artifacts, **extra.artifacts})
    return _resign(replace(case, proof_attachments=(changed,), result_digest="0" * 64)), merged


def _resign(case: ArmAdmissionCaseResultV3) -> ArmAdmissionCaseResultV3:
    provisional = replace(case, result_digest="0" * 64)
    return replace(provisional, result_digest=derive_admission_case_result_digest(_legacy_case(provisional)))


def _rebind(binding: ReleasedArmCaseBindingV3, case: ArmAdmissionCaseResultV3) -> ReleasedArmCaseBindingV3:
    return replace(binding, case_result_digest=case.result_digest, binding_digest="")


def _rerelease(
    release: AdmissionCaseReleaseV3,
    binding: ReleasedArmCaseBindingV3 | tuple[ReleasedArmCaseBindingV3, ...],
    authority: EvaluationAdmissionAuthorityV3 | None = None,
) -> AdmissionCaseReleaseV3:
    if authority is not None:
        release = replace(
            release,
            plan_manifest_digest=authority.plan_manifest_digest,
            admission_manifest_digest=authority.admission_manifest_digest,
            authority_digest=authority.authority_digest,
        )
    bindings = binding if type(binding) is tuple else (binding,)
    draft = replace(
        release,
        bindings=bindings,
        payload_digest="0" * 64,
        release_digest="0" * 64,
    )
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(
            payload,
            release.review.producer_identity,
            release.review.reviewer_identity,
            release.review.conflict_disclosure,
        ),
    )
    return replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))


def _baseline(plan: EvaluationPlanManifestV3, arm_id: str) -> str:
    return next(item.baseline_digest for item in plan.baselines if item.arm_id == arm_id)


def _second_component_binding(component_a, plan, arm_id):
    return replace(
        component_a,
        key=ArmScopeKey(arm_id, component_a.key.scope),
        baseline_digest=_baseline(plan, arm_id),
        observation_slot_digest=_digest("proof-slot-b"),
        observation_digest=_digest("proof-observation-b"),
        case_id_digest=_digest("proof-case-b"),
        proof_candidate_digest=None,
        binding_digest="",
    )


def _combined_case_binding(case, component_a, component_b, plan, rule):
    outcomes = (component_a.outcome_projection.normalized_outcome, component_b.outcome_projection.normalized_outcome)
    row = next(item for item in rule.decision_rows if item.component_outcomes == outcomes)
    projection = CaseOutcomeProjectionV3(
        case.case_input_digest,
        CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        (component_a.outcome_projection.projection_digest, component_b.outcome_projection.projection_digest),
        row.combined_outcome,
        "",
    )
    combined_arm = next(item.arm_id for item in plan.declaration.arm_configurations if item.kind is ArmKindV3.COMBINED)
    combined_case = _resign(
        replace(
            case,
            key=ArmScopeKey(combined_arm, case.key.scope),
            observation_slot_digest=_digest("proof-slot-combined"),
            observation_digest=_digest("proof-observation-combined"),
            case_id_digest=_digest("proof-case-combined"),
            outcome_projection=projection,
        )
    )
    binding = ReleasedArmCaseBindingV3(
        combined_case.key,
        _baseline(plan, combined_arm),
        combined_case.observation_slot_digest,
        combined_case.observation_digest,
        combined_case.underlying_push_digest,
        combined_case.case_id_digest,
        combined_case.case_input_digest,
        combined_case.outcome_projection,
        combined_case.role,
        combined_case.pair_id_digest,
        combined_case.result_digest,
        component_a.evidence_input_digests,
        component_a.change_input_digests,
        combined_case.input_manifest.manifest_digest,
        combined_case.proof_candidate.candidate_digest,
        "",
    )
    return combined_case, binding


def _combined_proof_fixture():
    case, component_a, release, plan, context, authority, resolver = _released_proof_case()
    rule = next(item.combination_rule for item in plan.declaration.arm_configurations if item.kind is ArmKindV3.COMBINED)
    assert rule is not None
    component_b = _second_component_binding(component_a, plan, rule.component_arm_ids[1])
    combined_case, combined_binding = _combined_case_binding(case, component_a, component_b, plan, rule)
    bindings = tuple(sorted((component_a, component_b, combined_binding), key=lambda item: item.key.arm_id))
    combined_release = _rerelease(release, bindings)
    return combined_case, combined_binding, combined_release, plan, context, authority, resolver


def test_combined_only_release_cannot_upgrade_proof() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _combined_proof_fixture()
    with pytest.raises(EvaluationProofContinuityError, match="complete reviewed plan"):
        apply_released_case_proof_v3(
            case,
            binding,
            _rerelease(release, binding),
            plan,
            context,
            authority,
            resolver,
        )


def test_complete_plan_derived_combination_retains_exact_component_candidate() -> None:
    from openultrasast.core.evaluation_proof import apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _combined_proof_fixture()
    (derived,) = apply_released_case_proof_v3(case, binding, release, plan, context, authority, resolver)
    assert derived.basis is EvidenceBasis.EXECUTION_BACKED


def test_valid_released_candidate_attaches_exactly_once_through_trusted_validator() -> None:
    from openultrasast.core.evaluation_proof import apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    (derived,) = apply_released_case_proof_v3(case, binding, release, plan, context, authority, resolver)
    assert derived.basis is EvidenceBasis.EXECUTION_BACKED
    assert derived.location == case.claims[0].location
    assert derived.record.decision.provenance.proof_record_digest == case.proof_attachments[0].proof.record_digest


def test_absent_and_valid_inconclusive_proof_preserve_not_demonstrated_status() -> None:
    from openultrasast.core.evaluation_proof import apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    absent = _resign(replace(case, proof_attachments=()))
    absent_binding = _rebind(binding, absent)
    assert (
        apply_released_case_proof_v3(
            absent,
            absent_binding,
            _rerelease(release, absent_binding),
            plan,
            context,
            authority,
            resolver,
        )
        == absent.claims
    )

    inconclusive, inconclusive_resolver = _inconclusive(case, resolver)
    inconclusive_binding = _rebind(binding, inconclusive)
    assert (
        apply_released_case_proof_v3(
            inconclusive,
            inconclusive_binding,
            _rerelease(release, inconclusive_binding),
            plan,
            context,
            authority,
            inconclusive_resolver,
        )
        == inconclusive.claims
    )


def test_inconclusive_proof_still_validates_receipt_identity() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    inconclusive, inconclusive_resolver = _inconclusive(case, resolver)
    attachment = inconclusive.proof_attachments[0]
    receipt = replace(
        attachment.verification,
        affected_result_digest=_digest("unrelated-inconclusive-result"),
        receipt_digest="",
    )
    malformed = _resign(
        replace(
            inconclusive,
            proof_attachments=(replace(attachment, verification=receipt, proof_id=""),),
        )
    )
    malformed_binding = _rebind(binding, malformed)
    with pytest.raises(EvaluationProofContinuityError, match="invalid"):
        apply_released_case_proof_v3(
            malformed,
            malformed_binding,
            _rerelease(release, malformed_binding),
            plan,
            context,
            authority,
            inconclusive_resolver,
        )


def test_candidate_or_attachment_without_the_other_is_refused() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    without_candidate = replace(case, proof_candidate=None)
    without_binding_candidate = replace(binding, proof_candidate_digest=None, binding_digest="")
    with pytest.raises(EvaluationProofContinuityError, match="candidate"):
        apply_released_case_proof_v3(
            without_candidate,
            without_binding_candidate,
            _rerelease(release, without_binding_candidate),
            plan,
            context,
            authority,
            resolver,
        )
    no_material = _resign(replace(without_candidate, proof_attachments=()))
    no_material_binding = _rebind(without_binding_candidate, no_material)
    assert (
        apply_released_case_proof_v3(
            no_material,
            no_material_binding,
            _rerelease(release, no_material_binding),
            plan,
            context,
            authority,
            resolver,
        )
        == no_material.claims
    )
    duplicated = _resign(replace(case, proof_attachments=case.proof_attachments * 2))
    duplicated_binding = _rebind(binding, duplicated)
    with pytest.raises(EvaluationProofContinuityError, match="exactly one"):
        apply_released_case_proof_v3(
            duplicated,
            duplicated_binding,
            _rerelease(release, duplicated_binding),
            plan,
            context,
            authority,
            resolver,
        )


def _candidate_transfer_mutation(mutation, case, binding):
    if mutation == "role":
        return case, replace(binding, role=AdmissionCaseRole.FIXED, binding_digest="")
    if mutation == "pair":
        return case, replace(binding, pair_id_digest=_digest("other-pair"), binding_digest="")
    candidate = case.proof_candidate
    assert candidate is not None
    changes = {
        "arm": {"component_arm_id": "other-arm"},
        "observation": {"observation_digest": _digest("other-observation")},
        "family": {"family_id": "other-family"},
        "scope": {"scope": ScopeKey(case.key.scope.family_id, "javascript")},
        "location": {"finding_location_digest": _digest("other-location")},
        "input": {"change_input_digest": _digest("other-input")},
    }
    changed = replace(candidate, **changes[mutation], candidate_digest="0" * 64)
    changed = replace(changed, candidate_digest=derive_proof_candidate_identity_digest(changed))
    changed_case = replace(case, proof_candidate=changed)
    changed_binding = replace(binding, proof_candidate_digest=changed.candidate_digest, binding_digest="")
    return changed_case, changed_binding


def _attachment_transfer_mutation(mutation, case, binding):
    attachment = case.proof_attachments[0]
    if mutation == "attachment_family":
        changed = replace(attachment, family_id="other-family", proof_id="")
    elif mutation == "attachment_location":
        changed = replace(attachment, location=replace(attachment.location, column=999), proof_id="")
    elif mutation == "receipt":
        receipt = replace(attachment.verification, affected_result_digest=_digest("other-result"), receipt_digest="")
        changed = replace(attachment, verification=receipt, proof_id="")
    else:
        control = replace(attachment.proof.control, safe_input_digest=_digest("other-safe"), binding_digest="")
        proof = replace(attachment.proof, control=control, record_digest="")
        receipt = replace(attachment.verification, proof_record_digest=proof.record_digest, receipt_digest="")
        changed = replace(attachment, proof=proof, verification=receipt, proof_id="")
    changed_case = _resign(replace(case, proof_attachments=(changed,)))
    return changed_case, _rebind(binding, changed_case)


def _context_transfer_mutation(mutation, context, authority):
    policy = context.proof_trust_policy
    assert policy is not None
    if mutation == "producer":
        policy = replace(policy, reviewed_producer_digests=(_digest("other-producer"),), policy_digest="")
    else:
        policy = replace(policy, trusted_store_identities=("other-store",), policy_digest="")
    changed = make_admission_validation_context(
        evidence=context.evidence,
        admission_review_policy=context.admission_review_policy,
        proof_trust_policy=policy,
    )
    return changed, replace(authority, validation_context_digest=changed.context_digest, authority_digest="")


@pytest.mark.parametrize(
    "mutation",
    (
        "role",
        "pair",
        "arm",
        "observation",
        "family",
        "attachment_family",
        "scope",
        "location",
        "attachment_location",
        "input",
        "control",
        "producer",
        "receipt",
        "trust",
    ),
)
def test_release_and_proof_transfer_mismatch_matrix_is_refused(mutation: str) -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    if mutation in {"role", "pair", "arm", "observation", "family", "scope", "location", "input"}:
        case, binding = _candidate_transfer_mutation(mutation, case, binding)
    elif mutation in {"attachment_family", "attachment_location", "control", "receipt"}:
        case, binding = _attachment_transfer_mutation(mutation, case, binding)
    else:
        context, authority = _context_transfer_mutation(mutation, context, authority)
    with pytest.raises((EvaluationProofContinuityError, ValueError)):
        apply_released_case_proof_v3(
            case,
            binding,
            _rerelease(release, binding, authority),
            plan,
            context,
            authority,
            resolver,
        )


def test_combined_retention_requires_identical_named_component_candidate() -> None:
    from openultrasast.core.evaluation_proof import (
        EvaluationProofContinuityError,
        validate_combined_proof_retention_v3,
    )

    lineage = derive_combination_lineages_v3(_declaration(), _valid_bindings())[0]
    combined = lineage.combined_cases[0]
    component = combined.components[0]
    candidate = ProofCandidateIdentityV3(
        component.component_arm_id,
        component.observation_digest,
        component.scope.family_id,
        component.scope,
        _digest("combined-location"),
        _digest("combined-change"),
        "0" * 64,
    )
    candidate = replace(candidate, candidate_digest=derive_proof_candidate_identity_digest(candidate))
    retained_component = replace(component, proof_candidate_digest=candidate.candidate_digest, component_digest="")
    retained = replace(
        combined,
        components=(retained_component, *combined.components[1:]),
        retained_proof_candidate_digest=candidate.candidate_digest,
    )
    validate_combined_proof_retention_v3(retained, candidate)
    validate_combined_proof_retention_v3(replace(retained, retained_proof_candidate_digest=None), None)

    transferred = replace(
        candidate,
        component_arm_id=combined.components[1].component_arm_id,
        candidate_digest="0" * 64,
    )
    transferred = replace(transferred, candidate_digest=derive_proof_candidate_identity_digest(transferred))
    with pytest.raises(EvaluationProofContinuityError):
        validate_combined_proof_retention_v3(retained, transferred)
    with pytest.raises(EvaluationProofContinuityError):
        validate_combined_proof_retention_v3(replace(retained, retained_proof_candidate_digest=_digest("fabricated")), candidate)


def test_exact_root_types_and_combined_lineage_are_required() -> None:
    from openultrasast.core.evaluation_case_outcome import CaseOutcomeProjectionPolicyV3
    from openultrasast.core.evaluation_proof import (
        EvaluationProofContinuityError,
        apply_released_case_proof_v3,
        derive_finding_location_digest,
    )

    class DerivedLocation(SourceLocation):
        pass

    with pytest.raises(EvaluationProofContinuityError, match="exact SourceLocation"):
        derive_finding_location_digest(DerivedLocation("src/app.py", 1, 0, "entry"))

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    combined_projection = replace(
        case.outcome_projection,
        policy=CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
        projection_digest="",
    )
    combined_case = _resign(replace(case, outcome_projection=combined_projection))
    combined_binding = replace(
        binding,
        outcome_projection=combined_projection,
        case_result_digest=combined_case.result_digest,
        binding_digest="",
    )
    with pytest.raises(EvaluationProofContinuityError, match="reviewed plan"):
        apply_released_case_proof_v3(
            combined_case,
            combined_binding,
            _rerelease(release, combined_binding),
            plan,
            context,
            authority,
            resolver,
        )


def test_proof_continuity_values_are_not_authorization_artifacts() -> None:
    from openultrasast.core.evaluation_proof import apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    claims = apply_released_case_proof_v3(case, binding, release, plan, context, authority, resolver)
    assert type(claims) is tuple
    assert not hasattr(claims, "authorize")


@pytest.mark.parametrize(
    "field",
    ("authority_digest", "plan_manifest_digest", "admission_manifest_digest"),
)
def test_reviewed_release_must_match_every_authority_root(field: str) -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    changed = replace(
        release,
        **{field: _digest(f"other-{field}")},
        payload_digest="0" * 64,
        release_digest="0" * 64,
    )
    changed = _rerelease(changed, binding)

    with pytest.raises(EvaluationProofContinuityError, match="roots"):
        apply_released_case_proof_v3(case, binding, changed, plan, context, authority, resolver)


def test_release_review_exact_type_and_binding_membership_are_required() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    malformed = replace(
        release,
        payload_digest=_digest("unreviewed-release-payload"),
    )
    with pytest.raises(EvaluationProofContinuityError, match="review"):
        apply_released_case_proof_v3(case, binding, malformed, plan, context, authority, resolver)

    class DerivedRelease(AdmissionCaseReleaseV3):
        pass

    derived = object.__new__(DerivedRelease)
    for field in fields(release):
        object.__setattr__(derived, field.name, getattr(release, field.name))
    with pytest.raises(EvaluationProofContinuityError, match="exact AdmissionCaseReleaseV3"):
        apply_released_case_proof_v3(case, binding, derived, plan, context, authority, resolver)

    class DerivedPlan(EvaluationPlanManifestV3):
        pass

    derived_plan = object.__new__(DerivedPlan)
    for field in fields(plan):
        object.__setattr__(derived_plan, field.name, getattr(plan, field.name))
    with pytest.raises(EvaluationProofContinuityError, match="exact EvaluationPlanManifestV3"):
        apply_released_case_proof_v3(case, binding, release, derived_plan, context, authority, resolver)

    other_binding = replace(binding, baseline_digest=_digest("other-baseline"), binding_digest="")
    other_release = _rerelease(release, other_binding)
    with pytest.raises(EvaluationProofContinuityError, match="exactly once"):
        apply_released_case_proof_v3(case, binding, other_release, plan, context, authority, resolver)


def _expanded_proof_context(context):
    policy = context.proof_trust_policy
    assert policy is not None
    expanded_policy = replace(
        policy,
        reviewed_producer_digests=(*policy.reviewed_producer_digests, _digest("extra-producer")),
        reviewed_control_reviewer_digests=(
            *policy.reviewed_control_reviewer_digests,
            _digest("extra-control-reviewer"),
        ),
        trusted_store_identities=(*policy.trusted_store_identities, "extra-store"),
        policy_digest="",
    )
    return make_admission_validation_context(
        evidence=context.evidence,
        admission_review_policy=context.admission_review_policy,
        proof_trust_policy=expanded_policy,
    )


def _assert_derived_contexts_refused(case, binding, release, plan, context, authority, resolver):
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    class DerivedContext(AdmissionValidationContext):
        pass

    derived_context = DerivedContext(
        context.evidence,
        context.admission_review_policy,
        context.proof_trust_policy,
        context.context_digest,
    )
    with pytest.raises(EvaluationProofContinuityError, match="exact AdmissionValidationContext"):
        apply_released_case_proof_v3(case, binding, release, plan, derived_context, authority, resolver)

    class DerivedAuthority(EvaluationAdmissionAuthorityV3):
        pass

    derived_authority = object.__new__(DerivedAuthority)
    for field in fields(authority):
        object.__setattr__(derived_authority, field.name, getattr(authority, field.name))
    with pytest.raises(EvaluationProofContinuityError, match="exact AdmissionValidationContext"):
        apply_released_case_proof_v3(case, binding, release, plan, context, derived_authority, resolver)


def test_proof_policy_must_be_the_exact_authority_bound_context_policy() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    expanded_context = _expanded_proof_context(context)
    with pytest.raises(EvaluationProofContinuityError, match="validation context"):
        apply_released_case_proof_v3(case, binding, release, plan, expanded_context, authority, resolver)

    no_policy = make_admission_validation_context(
        evidence=context.evidence,
        admission_review_policy=context.admission_review_policy,
        proof_trust_policy=None,
    )
    no_policy_authority = replace(authority, validation_context_digest=no_policy.context_digest, authority_digest="")
    with pytest.raises(EvaluationProofContinuityError, match="proof trust policy"):
        apply_released_case_proof_v3(
            case,
            binding,
            _rerelease(release, binding, no_policy_authority),
            plan,
            no_policy,
            no_policy_authority,
            resolver,
        )
    _assert_derived_contexts_refused(case, binding, release, plan, context, authority, resolver)


def test_paired_context_and_authority_substitution_cannot_upgrade_proof() -> None:
    from openultrasast.core.evaluation_proof import EvaluationProofContinuityError, apply_released_case_proof_v3

    case, binding, release, plan, context, authority, resolver = _released_proof_case()
    policy = context.proof_trust_policy
    assert policy is not None
    expanded_policy = replace(
        policy,
        reviewed_producer_digests=(*policy.reviewed_producer_digests, _digest("extra-producer")),
        reviewed_control_reviewer_digests=(
            *policy.reviewed_control_reviewer_digests,
            _digest("extra-control-reviewer"),
        ),
        trusted_store_identities=(*policy.trusted_store_identities, "extra-store"),
        policy_digest="",
    )
    expanded_context = make_admission_validation_context(
        evidence=context.evidence,
        admission_review_policy=context.admission_review_policy,
        proof_trust_policy=expanded_policy,
    )
    substituted_authority = replace(
        authority,
        validation_context_digest=expanded_context.context_digest,
        authority_digest="",
    )

    with pytest.raises(EvaluationProofContinuityError):
        apply_released_case_proof_v3(
            case,
            binding,
            release,
            plan,
            expanded_context,
            substituted_authority,
            resolver,
        )
