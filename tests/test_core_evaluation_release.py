"""Arm-aware reviewed case release for evaluation admission V3."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest
from test_core_admission_release import _setup as _v2_setup
from test_core_evaluation_authority import _authority_case
from test_core_evaluation_plan import _digest
from test_core_evaluation_plan_review import _attestation
from test_core_evaluation_spend import _bind, _prepare, _spend

from openultrasast.core.admission_case import AdmissionCaseRelease, AdmissionCaseRole
from openultrasast.core.evaluation_measurement import ArmScopeKey
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    EvaluationReleaseError,
    ProofCandidateIdentityV3,
    ReleasedArmCaseBindingV3,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_released_arm_case_binding,
    validate_admission_case_release_v3,
)
from openultrasast.core.evaluation_version import NonAuthorizingV3
from openultrasast.core.evidence import NeutralOutcome


def _release_case():
    case = _authority_case()
    authority, preparation = _prepare(case)
    receipt = _spend(case, preparation)
    spend = _bind(case, preparation, receipt)
    manifest = case[1]
    observations = case[4]
    templates = _v2_setup().cases
    configurations = {item.arm_id: item for item in manifest.plan_manifest.declaration.arm_configurations}
    results_by_arm = {item.arm_id: [] for item in manifest.plan_manifest.declaration.arm_configurations}
    bindings = []
    template_index = 0
    for observation in observations:
        for observed in observation.cases:
            template = templates[template_index]
            template_index += 1
            scope = configurations[observation.arm_id].exact_scopes[0]
            key = ArmScopeKey(observation.arm_id, scope)
            proof = ProofCandidateIdentityV3(
                observation.arm_id,
                observation.observation_digest,
                scope.family_id,
                scope,
                _digest(f"location-{template_index}"),
                _digest(f"change-{template_index}"),
                observed.proof_candidate_digest or _digest(f"candidate-{template_index}"),
            )
            result = ArmAdmissionCaseResultV3(
                key,
                observation.slot_digest,
                observation.observation_digest,
                observed.underlying_push_digest,
                observed.case_id_digest,
                observed.case_input_digest,
                observed.outcome_projection,
                template.role,
                template.pair_id_digest,
                template.evidence_inputs,
                template.defect_claims,
                template.satisfactions,
                template.silence,
                proof,
                template.proof_attachments,
                template.coverage,
                template.input_manifest,
                template.input_receipts,
                template.complexity,
                template.budget,
                template.total_reply_ms,
                observed.result_digest,
            )
            results_by_arm[observation.arm_id].append(result)
            bindings.append(derive_released_arm_case_binding(result, manifest.plan_manifest))
    arm_results = tuple(
        ArmAdmissionCasesV3(
            arm_id,
            next(item.baseline_digest for item in manifest.plan_manifest.baselines if item.arm_id == arm_id),
            tuple(sorted(results, key=lambda item: (item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest))),
            "",
        )
        for arm_id, results in sorted(results_by_arm.items())
    )
    bindings = tuple(sorted(bindings, key=lambda item: (item.key.arm_id, item.case_id_digest)))
    producer = _digest("v3-release-producer")
    reviewer = case[0].context.admission_review_policy.reviewed_reviewer_digests[0]
    disclosure = manifest.review.conflict_disclosure
    provisional = _attestation("0" * 64, producer, reviewer, disclosure)
    draft = AdmissionCaseReleaseV3(
        manifest.plan_manifest.manifest_digest,
        manifest.manifest_digest,
        authority.authority_digest,
        preparation.preparation_digest,
        spend.binding_digest,
        bindings,
        "0" * 64,
        provisional,
        "0" * 64,
    )
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(draft, payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    release = replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))
    return case, authority, preparation, receipt, spend, arm_results, release


def _validate(bundle, *, release=None, arms=None):
    case, authority, preparation, receipt, spend, arm_results, value = bundle
    return validate_admission_case_release_v3(
        case[1], authority, preparation, receipt, spend, release or value, arms or arm_results, case[0].context, case[0].port, case[5]
    )


def _resign(release):
    draft = replace(release, payload_digest="0" * 64, release_digest="0" * 64)
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


def test_complete_reviewed_v3_release_validates_every_planned_arm() -> None:
    bundle = _release_case()
    assert _validate(bundle) == bundle[-1]
    assert {item.arm_id for item in bundle[-2]} == {item.arm_id for item in bundle[0][1].plan_manifest.declaration.arm_configurations}


def test_release_contracts_are_exact_v3_non_authorizing_values() -> None:
    expected = {
        ProofCandidateIdentityV3: {
            "component_arm_id",
            "observation_digest",
            "family_id",
            "scope",
            "finding_location_digest",
            "change_input_digest",
            "candidate_digest",
        },
        ArmAdmissionCaseResultV3: {
            "key",
            "observation_slot_digest",
            "observation_digest",
            "underlying_push_digest",
            "case_id_digest",
            "case_input_digest",
            "outcome_projection",
            "role",
            "pair_id_digest",
            "evidence_inputs",
            "claims",
            "satisfactions",
            "silence",
            "proof_candidate",
            "proof_attachments",
            "coverage",
            "input_manifest",
            "input_receipts",
            "complexity",
            "budget",
            "total_reply_ms",
            "result_digest",
        },
        ArmAdmissionCasesV3: {"arm_id", "baseline_digest", "cases", "cases_digest"},
        ReleasedArmCaseBindingV3: {
            "key",
            "baseline_digest",
            "observation_slot_digest",
            "observation_digest",
            "underlying_push_digest",
            "case_id_digest",
            "case_input_digest",
            "outcome_projection",
            "role",
            "pair_id_digest",
            "case_result_digest",
            "evidence_input_digests",
            "change_input_digests",
            "input_manifest_digest",
            "proof_candidate_digest",
            "binding_digest",
        },
        AdmissionCaseReleaseV3: {
            "plan_manifest_digest",
            "admission_manifest_digest",
            "authority_digest",
            "preparation_digest",
            "spend_binding_digest",
            "bindings",
            "payload_digest",
            "review",
            "release_digest",
        },
    }
    for kind, names in expected.items():
        assert {item.name for item in fields(kind)} == names
        assert issubclass(kind, NonAuthorizingV3)


@pytest.mark.parametrize("mutation", ("missing_arm", "duplicate_case", "wrong_spend", "copied_review"))
def test_incomplete_or_cross_bound_release_fails_before_metrics(mutation: str) -> None:
    bundle = _release_case()
    arms = bundle[-2]
    release = bundle[-1]
    if mutation == "missing_arm":
        arms = arms[:-1]
    elif mutation == "duplicate_case":
        with pytest.raises(EvaluationReleaseError, match="unique"):
            replace(arms[0], cases=arms[0].cases + arms[0].cases, cases_digest="")
        return
    elif mutation == "wrong_spend":
        release = _resign(replace(release, spend_binding_digest=_digest("wrong-spend")))
    else:
        release = replace(release, review=bundle[0][1].review)
    with pytest.raises((EvaluationReleaseError, ValueError)):
        _validate(bundle, release=release, arms=arms)


def test_v2_release_and_subclasses_are_refused() -> None:
    bundle = _release_case()
    with pytest.raises(EvaluationReleaseError):
        _validate(bundle, release=object.__new__(AdmissionCaseRelease))

    class Derived(AdmissionCaseReleaseV3):
        pass

    with pytest.raises((EvaluationReleaseError, TypeError, ValueError)):
        _validate(bundle, release=object.__new__(Derived))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("baseline_digest", _digest("other-baseline")),
        ("observation_slot_digest", _digest("other-slot")),
        ("observation_digest", _digest("other-observation")),
        ("underlying_push_digest", _digest("other-push")),
        ("role", AdmissionCaseRole.FIXED),
        ("case_result_digest", _digest("other-result")),
        ("evidence_input_digests", (_digest("other-evidence"),)),
        ("input_manifest_digest", _digest("other-manifest")),
        ("proof_candidate_digest", _digest("other-candidate")),
    ),
)
def test_each_released_binding_association_is_exact(field: str, value: object) -> None:
    bundle = _release_case()
    release = bundle[-1]
    changed_binding = replace(release.bindings[0], **{field: value}, binding_digest="")
    changed = _resign(replace(release, bindings=(changed_binding,) + release.bindings[1:]))
    with pytest.raises(EvaluationReleaseError, match="binding|canonical|case"):
        _validate(bundle, release=changed)


def test_release_binding_case_input_and_projection_are_exact() -> None:
    bundle = _release_case()
    release = bundle[-1]
    binding = release.bindings[0]
    with pytest.raises(EvaluationReleaseError, match="input identity"):
        replace(binding, case_input_digest=_digest("other-case-input"), binding_digest="")

    outcome = (
        NeutralOutcome.VIOLATION
        if binding.outcome_projection.normalized_outcome is not NeutralOutcome.VIOLATION
        else NeutralOutcome.SATISFIED
    )
    projection = replace(binding.outcome_projection, normalized_outcome=outcome, projection_digest="")
    changed_binding = replace(binding, outcome_projection=projection, binding_digest="")
    changed = _resign(replace(release, bindings=(changed_binding,) + release.bindings[1:]))
    with pytest.raises(EvaluationReleaseError, match="binding|canonical|case"):
        _validate(bundle, release=changed)


def test_zero_byte_or_unopened_case_inputs_are_refused() -> None:
    bundle = _release_case()
    arms = bundle[-2]
    case = arms[0].cases[0]
    bad = replace(case.input_receipts[0], opened=False, byte_count=0, content_digest=None)
    with pytest.raises((EvaluationReleaseError, ValueError), match="read|input|instrument|opened"):
        replace(case, input_receipts=(bad,))
