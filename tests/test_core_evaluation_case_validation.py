"""Exact released-case association validation for evaluation admission V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
import test_core_evaluation_authority as authority_fixtures
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_release import _setup
from test_core_evaluation_authority import _authority_case
from test_core_evaluation_observation import _seal
from test_core_evaluation_plan import _digest
from test_core_evaluation_plan_review import _attestation
from test_core_evaluation_spend import _bind, _prepare, _spend

from openultrasast.core import canonical, evidence, provenance, validation
from openultrasast.core.admission_case import AdmissionCaseRole, derive_admission_case_result_digest
from openultrasast.core.evaluation_authority import (
    derive_evaluation_admission_manifest_digest,
    derive_evaluation_admission_manifest_payload_digest,
)
from openultrasast.core.evaluation_case_outcome import (
    CaseOutcomeProjectionV3,
    derive_component_case_outcome_projection,
)
from openultrasast.core.evaluation_case_validation import _canonical_binding, validate_released_case_associations_v3
from openultrasast.core.evaluation_measurement import (
    ArmKindV3,
    ArmScopeKey,
    CaseOutcomeProjectionPolicyV3,
    ScopeKey,
)
from openultrasast.core.evaluation_observation import ArmObservationSetV3, ObservationCaseRefV3
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
)
from openultrasast.core.evaluation_release import (
    AdmissionCaseReleaseV3,
    ArmAdmissionCaseResultV3,
    ArmAdmissionCasesV3,
    EvaluationReleaseError,
    ProofCandidateIdentityV3,
    _legacy_case,
    derive_admission_case_release_digest_v3,
    derive_admission_case_release_payload_digest_v3,
    derive_proof_candidate_identity_digest,
    derive_released_arm_case_binding,
    validate_admission_case_release_v3,
)
from openultrasast.core.evidence import NeutralOutcome
from openultrasast.core.measurement import ScopeKey as LegacyScopeKey


def _distinct_evidence_input(value, case_index: int):
    content = canonical.canonical_bytes(f"v3-case-input-{case_index}")
    reference, resolver = stored_artifact(content, artifact_id=f"v3-case-input-{case_index}")
    stamp = replace(value.record.packet.provenance, change_input_digest=reference.content_digest)
    packet = replace(value.record.packet, provenance=stamp)
    decision = replace(value.record.decision, packet_digest=evidence.derive_packet_digest(packet))
    record = evidence.EvidenceRecord(packet, decision, "")
    inputs = tuple(
        replace(item, identity=reference.content_digest, content=reference)
        if item.role is provenance.ProvenanceInputRole.CHANGE_INPUT
        else item
        for item in value.named_inputs.inputs
    )
    named = provenance.NamedInputs(inputs, provenance.derive_named_inputs_digest(inputs))
    return validation.make_evidence_validation_input(record=record, named_inputs=named), resolver.artifacts


def _rekey_configuration(configuration, scope: ScopeKey):
    key = ArmScopeKey(configuration.arm_id, scope)
    policies = tuple(
        replace(
            policy,
            key=key,
            rules=tuple(replace(rule, key=key, rule_digest="") for rule in policy.rules),
            policy_digest="",
        )
        for policy in configuration.denominator_policies
    )
    thresholds = tuple(replace(row, key=key, threshold_digest="") for row in configuration.thresholds)
    sufficiency = tuple(replace(row, key=key, rule_digest="") for row in configuration.sufficiency_rules)
    return replace(
        configuration,
        exact_scopes=(scope,),
        denominator_policies=policies,
        thresholds=thresholds,
        sufficiency_rules=sufficiency,
        configuration_identity_digest="",
    )


def _multi_scope_authority_case():
    context_case, plan, readiness = authority_fixtures._reviewed_plan()
    scopes = {
        "arm-a": ScopeKey("access_control", "python"),
        "arm-b": ScopeKey("access_control", "javascript"),
        "arm-combined": ScopeKey("access_control", "python"),
    }
    configurations = tuple(_rekey_configuration(row, scopes[row.arm_id]) for row in plan.declaration.arm_configurations)
    inputs = tuple(sorted({slot.input_identity_digest for slot in plan.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=plan.declaration.population_digest,
        freeze_digest=plan.declaration.freeze_digest,
        input_set_digest=plan.declaration.input_set_digest,
        arm_configurations=configurations,
        input_identity_digests=inputs,
    )
    python_row = plan.census.scope_rows[0]
    scope_rows = tuple(sorted((replace(python_row, scope=scopes["arm-a"]), replace(python_row, scope=scopes["arm-b"]))))
    ordinary_count = plan.census.whole_underlying_push_count // 2
    ordinary_rows = (
        EcosystemOrdinaryCensusV3("javascript", ordinary_count),
        EcosystemOrdinaryCensusV3("python", ordinary_count),
    )
    census_draft = replace(
        plan.census,
        scope_rows=scope_rows,
        ordinary_rows=ordinary_rows,
        payload_digest="0" * 64,
        census_digest="0" * 64,
    )
    census_payload = derive_evaluation_census_payload_digest(census_draft)
    census_reviewed = replace(
        census_draft,
        payload_digest=census_payload,
        review=_attestation(
            census_payload,
            plan.census.review.producer_identity,
            plan.census.review.reviewer_identity,
            plan.census.review.conflict_disclosure,
        ),
    )
    census = replace(census_reviewed, census_digest=derive_evaluation_census_digest(census_reviewed))
    plan_draft = replace(
        plan,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        census=census,
        payload_digest="0" * 64,
        manifest_digest="0" * 64,
    )
    payload = derive_evaluation_plan_manifest_payload_digest(plan_draft)
    plan_reviewed = replace(
        plan_draft,
        payload_digest=payload,
        review=_attestation(
            payload,
            plan.review.producer_identity,
            plan.review.reviewer_identity,
            plan.review.conflict_disclosure,
        ),
    )
    multi_plan = replace(plan_reviewed, manifest_digest=derive_evaluation_plan_manifest_digest(plan_reviewed))
    original = authority_fixtures._reviewed_plan
    authority_fixtures._reviewed_plan = lambda: (context_case, multi_plan, readiness)
    try:
        return authority_fixtures._authority_case()
    finally:
        authority_fixtures._reviewed_plan = original


def _bundle(*, authority_case=None, projection_mutation: str | None = None):
    setup = _setup()
    authority_case = authority_case or _authority_case()
    manifest = authority_case[1]
    configurations = {item.arm_id: item for item in manifest.plan_manifest.declaration.arm_configurations}
    first_component_arm = next(item.arm_id for item in configurations.values() if item.kind is ArmKindV3.COMPONENT)
    draft_cases = {}
    extra_artifacts = {}
    for arm_id, configuration in configurations.items():
        scope = configuration.exact_scopes[0]
        cases = []
        for index, original in enumerate(setup.cases):
            evidence_input, input_artifacts = _distinct_evidence_input(original.evidence_inputs[0], index)
            extra_artifacts.update(input_artifacts)
            legacy = replace(
                original,
                case_id_digest=_digest(f"v3-association-{arm_id}-{index}"),
                scope=LegacyScopeKey(scope.family_id, scope.ecosystem),
                pair_id_digest=None if original.role is AdmissionCaseRole.ORDINARY else _digest(f"v3-pair-{arm_id}"),
                evidence_inputs=(evidence_input,),
                result_digest="0" * 64,
            )
            legacy = replace(legacy, result_digest=derive_admission_case_result_digest(legacy))
            component_projection = derive_component_case_outcome_projection((evidence_input.record,))
            projection = component_projection
            if configuration.kind is ArmKindV3.COMBINED:
                assert configuration.combination_rule is not None
                projection = CaseOutcomeProjectionV3(
                    component_projection.case_input_digest,
                    CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
                    tuple(component_projection.projection_digest for _ in configuration.combination_rule.component_arm_ids),
                    component_projection.normalized_outcome,
                    "",
                )
            elif arm_id == first_component_arm and index == 0 and projection_mutation is not None:
                case_input = projection.case_input_digest
                outcome = projection.normalized_outcome
                sources = projection.source_outcome_digests
                if projection_mutation == "case_input":
                    case_input = _digest("coordinated-other-case-input")
                elif projection_mutation == "outcome":
                    outcome = NeutralOutcome.VIOLATION if outcome is not NeutralOutcome.VIOLATION else NeutralOutcome.SATISFIED
                elif projection_mutation == "source":
                    sources = (_digest("coordinated-other-record"),)
                else:  # pragma: no cover - fixture misuse
                    raise AssertionError(f"unknown projection mutation: {projection_mutation}")
                projection = CaseOutcomeProjectionV3(
                    case_input,
                    CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE,
                    sources,
                    outcome,
                    "",
                )
            change = legacy.evidence_inputs[0].record.packet.provenance.change_input_digest
            candidate = ProofCandidateIdentityV3(
                arm_id,
                _digest(f"pre-observation-{arm_id}"),
                scope.family_id,
                scope,
                _digest(f"association-location-{arm_id}-{index}"),
                change,
                "0" * 64,
            )
            candidate = replace(candidate, candidate_digest=derive_proof_candidate_identity_digest(candidate))
            cases.append(
                ArmAdmissionCaseResultV3(
                    ArmScopeKey(arm_id, scope),
                    _digest(f"pre-slot-{arm_id}"),
                    candidate.observation_digest,
                    _digest(f"underlying-push-{arm_id}-{index}"),
                    legacy.case_id_digest,
                    projection.case_input_digest,
                    projection,
                    legacy.role,
                    legacy.pair_id_digest,
                    legacy.evidence_inputs,
                    legacy.defect_claims,
                    legacy.satisfactions,
                    legacy.silence,
                    candidate,
                    legacy.proof_attachments,
                    legacy.coverage,
                    legacy.input_manifest,
                    legacy.input_receipts,
                    legacy.complexity,
                    legacy.budget,
                    legacy.total_reply_ms,
                    legacy.result_digest,
                )
            )
        draft_cases[arm_id] = tuple(cases)

    sealed = []
    observations = []
    artifacts = {**authority_case[5].artifacts, **setup.resolver.artifacts, **extra_artifacts}
    observation_by_arm = {}
    seen_arms = set()
    for index, slot in enumerate(manifest.plan_manifest.declaration.expected_observation_slots):
        cases = ()
        if slot.arm_id not in seen_arms:
            seen_arms.add(slot.arm_id)
            cases = tuple(
                sorted(
                    (
                        ObservationCaseRefV3(
                            case.case_id_digest,
                            case.case_input_digest,
                            case.underlying_push_digest,
                            case.result_digest,
                            case.outcome_projection,
                            case.proof_candidate.candidate_digest if case.proof_candidate is not None else None,
                        )
                        for case in draft_cases[slot.arm_id]
                    ),
                    key=lambda item: item.case_id_digest,
                )
            )
        configuration = configurations[slot.arm_id]
        observation = ArmObservationSetV3(
            slot.slot_digest,
            slot.arm_id,
            slot.input_identity_digest,
            slot.execution_identity,
            configuration.registered_budget_digest,
            configuration.configuration_identity_digest,
            _digest(f"association-read-{index}"),
            _digest(f"association-stage-{index}"),
            cases,
            "",
        )
        reference, resolved = _seal(observation, f"association-observation-{index}")
        observations.append(observation)
        sealed.append(reference)
        artifacts[reference.observation.artifact_id] = resolved
        if cases:
            observation_by_arm[slot.arm_id] = observation

    manifest_draft = replace(manifest, observations=tuple(sealed), payload_digest="0" * 64, manifest_digest="0" * 64)
    manifest_payload = derive_evaluation_admission_manifest_payload_digest(manifest_draft)
    manifest_review = _attestation(
        manifest_payload,
        setup.release.review.producer_identity,
        setup.release.review.reviewer_identity,
        setup.release.review.conflict_disclosure,
    )
    manifest_reviewed = replace(manifest_draft, payload_digest=manifest_payload, review=manifest_review)
    manifest = replace(manifest_reviewed, manifest_digest=derive_evaluation_admission_manifest_digest(manifest_reviewed))
    resolver = InMemoryContentResolver(artifacts)
    reviewed_case = (
        authority_case[0],
        manifest,
        authority_case[2],
        authority_case[3],
        tuple(observations),
        resolver,
    )
    authority, preparation = _prepare(reviewed_case)
    receipt = _spend(reviewed_case, preparation)
    spend = _bind(reviewed_case, preparation, receipt)

    groups = []
    for arm_id, cases in draft_cases.items():
        observation = observation_by_arm[arm_id]
        finalized = []
        for case in cases:
            candidate = replace(case.proof_candidate, observation_digest=observation.observation_digest)
            finalized.append(
                replace(
                    case,
                    observation_slot_digest=observation.slot_digest,
                    observation_digest=observation.observation_digest,
                    proof_candidate=candidate,
                )
            )
        baseline = next(item.baseline_digest for item in manifest.plan_manifest.baselines if item.arm_id == arm_id)
        groups.append(ArmAdmissionCasesV3(arm_id, baseline, tuple(sorted(finalized, key=lambda item: item.case_id_digest)), ""))
    groups = tuple(sorted(groups, key=lambda item: item.arm_id))
    bindings = tuple(
        sorted(
            (derive_released_arm_case_binding(case, manifest.plan_manifest) for group in groups for case in group.cases),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    release_draft = AdmissionCaseReleaseV3(
        manifest.plan_manifest.manifest_digest,
        manifest.manifest_digest,
        authority.authority_digest,
        preparation.preparation_digest,
        spend.binding_digest,
        bindings,
        "0" * 64,
        _attestation(
            "0" * 64,
            setup.release.review.producer_identity,
            setup.release.review.reviewer_identity,
            setup.release.review.conflict_disclosure,
        ),
        "0" * 64,
    )
    release_payload = derive_admission_case_release_payload_digest_v3(release_draft)
    release_reviewed = replace(
        release_draft,
        payload_digest=release_payload,
        review=_attestation(
            release_payload,
            setup.release.review.producer_identity,
            setup.release.review.reviewer_identity,
            setup.release.review.conflict_disclosure,
        ),
    )
    release = replace(release_reviewed, release_digest=derive_admission_case_release_digest_v3(release_reviewed))
    return setup, release, groups, manifest, resolver, reviewed_case, authority, preparation, receipt, spend


def _validate(bundle, *, release=None, groups=None, resolver=None):
    _, value, arm_groups, manifest, default_resolver = bundle[:5]
    reviewed_case = bundle[5]
    return validate_released_case_associations_v3(
        manifest,
        release or value,
        groups or arm_groups,
        reviewed_case[0].context,
        reviewed_case[0].port,
        resolver or default_resolver,
    )


def _resign_release(bundle, bindings):
    setup, release = bundle[:2]
    draft = replace(release, bindings=bindings, payload_digest="0" * 64, release_digest="0" * 64)
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(
            payload,
            release.review.producer_identity,
            release.review.reviewer_identity,
            setup.release.review.conflict_disclosure,
        ),
    )
    return replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))


def _replace_case_and_release(bundle, changed):
    groups = bundle[2]
    changed_groups = tuple(
        replace(
            group,
            cases=tuple(changed if case.case_id_digest == changed.case_id_digest else case for case in group.cases),
            cases_digest="",
        )
        if group.arm_id == changed.key.arm_id
        else group
        for group in groups
    )
    changed_group = next(group for group in changed_groups if group.arm_id == changed.key.arm_id)
    changed_binding = derive_released_arm_case_binding(changed, bundle[3].plan_manifest)
    bindings = tuple(
        sorted(
            (
                changed_binding if (item.key.arm_id, item.case_id_digest) == (changed.key.arm_id, changed.case_id_digest) else item
                for item in bundle[1].bindings
            ),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    return changed_groups, _resign_release(bundle, bindings), changed_group


def test_canonical_scoped_pair_and_ordinary_case_validate() -> None:
    bundle = _bundle()
    assert _validate(bundle) == bundle[1].bindings


@pytest.mark.parametrize(
    ("kind", "substituted_policy"),
    (
        (ArmKindV3.COMPONENT, CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE),
        (ArmKindV3.COMBINED, CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE),
    ),
)
def test_canonical_release_binding_requires_planned_projection_policy(
    kind: ArmKindV3,
    substituted_policy: CaseOutcomeProjectionPolicyV3,
) -> None:
    bundle = _bundle()
    configurations = {item.arm_id: item for item in bundle[3].plan_manifest.declaration.arm_configurations}
    configuration = next(item for item in configurations.values() if item.kind is kind)
    group = next(item for item in bundle[2] if item.arm_id == configuration.arm_id)
    case = group.cases[0]
    sources = case.outcome_projection.source_outcome_digests
    if substituted_policy is CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE:
        sources = tuple(dict.fromkeys(sources))
    projection = CaseOutcomeProjectionV3(
        case.case_input_digest,
        substituted_policy,
        sources,
        case.outcome_projection.normalized_outcome,
        "",
    )
    changed = replace(case, outcome_projection=projection)
    reviewed_case = bundle[5][0]

    with pytest.raises(EvaluationReleaseError, match="policy"):
        _canonical_binding(
            changed,
            group.baseline_digest,
            configuration,
            reviewed_case.context,
            reviewed_case.port,
            bundle[4],
        )


@pytest.mark.parametrize("mutation", ("case_input", "outcome", "source"))
def test_coordinated_observation_release_projection_rehash_cannot_replace_validated_evidence(mutation: str) -> None:
    bundle = _bundle(projection_mutation=mutation)
    with pytest.raises(EvaluationReleaseError, match="component outcome projection|validated evidence"):
        _validate(bundle)


def test_released_arm_scope_case_input_identity_is_unique() -> None:
    bundle = _bundle()
    group = next(item for item in bundle[2] if len(item.cases) > 1)
    donor, target = group.cases[:2]
    duplicate = replace(
        target,
        case_input_digest=donor.case_input_digest,
        outcome_projection=donor.outcome_projection,
    )
    with pytest.raises(EvaluationReleaseError, match="case input identities must be unique"):
        replace(group, cases=(donor, duplicate) + group.cases[2:], cases_digest="")


def test_release_review_is_subject_bound_and_resolves_nonzero_disclosure() -> None:
    bundle = _bundle()
    copied = replace(bundle[1], review=bundle[3].review)
    with pytest.raises(EvaluationReleaseError, match="review|subject"):
        _validate(bundle, release=copied)

    disclosure_id = bundle[1].review.conflict_disclosure.artifact_id
    missing = InMemoryContentResolver({key: value for key, value in bundle[4].artifacts.items() if key != disclosure_id})
    with pytest.raises(canonical.ArtifactResolutionError):
        _validate(bundle, resolver=missing)


@pytest.mark.parametrize(
    "mutation",
    ("arm", "role", "pair", "scope", "observation", "result", "input", "manifest", "location", "change", "push"),
)
def test_each_released_case_association_mutation_is_invalid(mutation: str) -> None:
    bundle = _bundle()
    groups = bundle[2]
    case = groups[0].cases[0]
    if mutation == "arm":
        changed = replace(case, key=ArmScopeKey("other-arm", case.key.scope))
    elif mutation == "role":
        changed = replace(case, role=AdmissionCaseRole.ORDINARY)
    elif mutation == "pair":
        changed = replace(case, pair_id_digest=_digest("wrong-pair"))
    elif mutation == "scope":
        changed = replace(case, key=ArmScopeKey(case.key.arm_id, ScopeKey(case.key.scope.family_id, "other")))
    elif mutation == "observation":
        changed = replace(case, observation_digest=_digest("wrong-observation"))
    elif mutation == "result":
        changed = replace(case, result_digest=_digest("wrong-result"))
    elif mutation == "input":
        changed = replace(case, evidence_inputs=(replace(case.evidence_inputs[0], input_digest=_digest("wrong-input")),))
    elif mutation == "manifest":
        changed = replace(case.input_manifest, manifest_digest=_digest("wrong-manifest"))
        with pytest.raises((EvaluationReleaseError, ValueError)):
            replace(case, input_manifest=changed)
        return
    elif mutation == "location":
        changed = replace(case.proof_candidate, finding_location_digest=_digest("wrong-location"))
        changed = replace(case, proof_candidate=changed)
    elif mutation == "change":
        changed = replace(case.proof_candidate, change_input_digest=_digest("wrong-change"))
        changed = replace(case, proof_candidate=changed)
    else:
        changed = replace(case, underlying_push_digest=_digest("wrong-push"))
    if mutation == "arm":
        with pytest.raises((EvaluationReleaseError, ValueError)):
            replace(groups[0], cases=(changed,) + groups[0].cases[1:], cases_digest="")
        return
    changed_group = replace(groups[0], cases=(changed,) + groups[0].cases[1:], cases_digest="")
    with pytest.raises((EvaluationReleaseError, ValueError)):
        _validate(bundle, groups=(changed_group,))


@pytest.mark.parametrize("mutation", ("missing_pair", "ordinary_pair", "two_vulnerable"))
def test_pair_roles_are_exact_within_each_arm_scope(mutation: str) -> None:
    bundle = _bundle()
    group = bundle[2][0]
    cases = list(group.cases)
    vulnerable = next(index for index, case in enumerate(cases) if case.role is AdmissionCaseRole.VULNERABLE)
    fixed = next(index for index, case in enumerate(cases) if case.role is AdmissionCaseRole.FIXED)
    ordinary = next(index for index, case in enumerate(cases) if case.role is AdmissionCaseRole.ORDINARY)
    if mutation == "missing_pair":
        cases[vulnerable] = replace(cases[vulnerable], pair_id_digest=None)
    elif mutation == "ordinary_pair":
        cases[ordinary] = replace(cases[ordinary], pair_id_digest=_digest("ordinary-pair"))
    else:
        cases[fixed] = replace(cases[fixed], role=AdmissionCaseRole.VULNERABLE)
    changed = replace(group, cases=tuple(cases), cases_digest="")
    with pytest.raises((EvaluationReleaseError, ValueError), match="pair|ordinary|role"):
        _validate(bundle, groups=(changed,) + bundle[2][1:])


def test_self_consistent_caller_summary_cannot_replace_canonical_case_result() -> None:
    """A rehashed case/release must still be checked against its evidence-derived result."""
    bundle = _bundle()
    groups = bundle[2]
    original = groups[0].cases[0]
    changed_coverage = replace(original.coverage, sites_considered=original.coverage.sites_considered + 1)
    draft = replace(original, coverage=changed_coverage, result_digest="0" * 64)
    changed = replace(draft, result_digest=derive_admission_case_result_digest(_legacy_case(draft)))
    changed_group = replace(groups[0], cases=(changed,) + groups[0].cases[1:], cases_digest="")
    changed_groups = (changed_group,) + groups[1:]
    changed_binding = derive_released_arm_case_binding(changed, bundle[3].plan_manifest)
    bindings = tuple(
        sorted(
            (
                changed_binding if (item.key.arm_id, item.case_id_digest) == (changed.key.arm_id, changed.case_id_digest) else item
                for item in bundle[1].bindings
            ),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    changed_release = _resign_release(bundle, bindings)
    with pytest.raises(EvaluationReleaseError, match="observation|canonical|coverage|evidence|result"):
        _validate(bundle, release=changed_release, groups=changed_groups)


def test_self_consistent_underlying_push_swap_is_rejected_by_sealed_observation() -> None:
    bundle = _bundle()
    groups = bundle[2]
    original = groups[0].cases[0]
    changed = replace(original, underlying_push_digest=_digest("self-consistent-other-push"))
    changed_group = replace(groups[0], cases=(changed,) + groups[0].cases[1:], cases_digest="")
    changed_groups = (changed_group,) + groups[1:]
    changed_binding = derive_released_arm_case_binding(changed, bundle[3].plan_manifest)
    bindings = tuple(
        sorted(
            (
                changed_binding if (item.key.arm_id, item.case_id_digest) == (changed.key.arm_id, changed.case_id_digest) else item
                for item in bundle[1].bindings
            ),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )
    changed_release = _resign_release(bundle, bindings)
    with pytest.raises(EvaluationReleaseError, match="sealed observation|exact sealed|observation"):
        _validate(bundle, release=changed_release, groups=changed_groups)


def test_reviewed_multi_scope_release_passes_the_public_validation_boundary() -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case())
    scopes = {case.key.scope for group in bundle[2] for case in group.cases}
    assert scopes == {ScopeKey("access_control", "javascript"), ScopeKey("access_control", "python")}
    assert _validate(bundle) == bundle[1].bindings

    reviewed_case, authority, preparation, receipt, spend = bundle[5:]
    assert (
        validate_admission_case_release_v3(
            bundle[3],
            authority,
            preparation,
            receipt,
            spend,
            bundle[1],
            bundle[2],
            reviewed_case[0].context,
            reviewed_case[0].port,
            bundle[4],
        )
        == bundle[1]
    )


def test_cross_scope_pair_substitution_is_rejected_after_full_rehash() -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case())
    python_case = next(
        case
        for group in bundle[2]
        for case in group.cases
        if case.key.scope.ecosystem == "python" and case.role is AdmissionCaseRole.VULNERABLE
    )
    javascript_case = next(
        case
        for group in bundle[2]
        for case in group.cases
        if case.key.scope.ecosystem == "javascript" and case.role is AdmissionCaseRole.FIXED
    )
    draft = replace(javascript_case, pair_id_digest=python_case.pair_id_digest, result_digest="0" * 64)
    changed = replace(draft, result_digest=derive_admission_case_result_digest(_legacy_case(draft)))
    changed_groups, changed_release, _ = _replace_case_and_release(bundle, changed)
    with pytest.raises(EvaluationReleaseError, match="pair|sealed observation|exact sealed"):
        _validate(bundle, release=changed_release, groups=changed_groups)


@pytest.mark.parametrize("association", ("input", "push"))
def test_cross_arm_scope_input_and_push_substitutions_are_rejected(association: str) -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case())
    original = next(case for group in bundle[2] for case in group.cases if case.key.scope.ecosystem == "javascript")
    donor = next(
        case
        for group in bundle[2]
        for case in group.cases
        if case.key.scope.ecosystem == "python" and case.evidence_inputs != original.evidence_inputs
    )
    if association == "input":
        draft = replace(original, evidence_inputs=donor.evidence_inputs, result_digest="0" * 64)
        changed = replace(draft, result_digest=derive_admission_case_result_digest(_legacy_case(draft)))
    else:
        changed = replace(original, underlying_push_digest=donor.underlying_push_digest)
    changed_groups, changed_release, _ = _replace_case_and_release(bundle, changed)
    with pytest.raises(EvaluationReleaseError, match="observation|evidence|provenance|association"):
        _validate(bundle, release=changed_release, groups=changed_groups)
