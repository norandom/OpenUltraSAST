"""Exact released-case association validation for evaluation admission V3."""

from __future__ import annotations

from dataclasses import replace

import pytest
import test_core_evaluation_authority as authority_fixtures
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_release import _setup
from test_core_evaluation_observation import _seal
from test_core_evaluation_plan import _digest
from test_core_evaluation_plan_review import _attestation
from test_core_evaluation_spend import _bind, _prepare, _spend
from test_core_model import _application_case

from openultrasast.core import admission_context, canonical, evidence, family, model_apply, provenance, validation
from openultrasast.core._admission_funnel import derive_case_funnel
from openultrasast.core.admission_case import (
    AdmissionCaseRole,
    derive_admission_case_result_digest,
    derive_case_coverage_digest,
)
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
from openultrasast.core.family_catalog import (
    FamilyCatalog,
    FamilyCatalogEntry,
    catalog_entry_key,
    derive_catalog_digest,
)
from openultrasast.core.measurement import ScopeKey as LegacyScopeKey
from openultrasast.core.verdict import BoundedSilence, derive_verdict_outputs


def _model_evidence_input(record, named, contract, model_context, model_programs, model_lineages):
    application = _application_case(contract=contract, record=record)
    derived = model_apply.apply_model_result(
        record,
        contract,
        application.request,
        application.result,
        application.resolver,
        model_context.port,
        model_context.context.evidence.custody_policy,
    )
    model_programs[application.request.program.declaration_digest] = application.request.program
    model_lineages[application.request.lineage.manifest_digest] = application.request.lineage
    return validation.make_evidence_validation_input(
        record=derived,
        named_inputs=named,
        model_request=application.request,
        model_result=application.result,
    )


def _rebind_named_inputs(value, reference, contract_reference, contract_digest):
    inputs = []
    for item in value.named_inputs.inputs:
        if item.role is provenance.ProvenanceInputRole.CHANGE_INPUT:
            item = replace(item, identity=reference.content_digest, content=reference)
        elif item.role is provenance.ProvenanceInputRole.FAMILY_CONTRACT:
            item = replace(item, identity=contract_digest, content=contract_reference)
        inputs.append(item)
    exact = tuple(inputs)
    return provenance.NamedInputs(exact, provenance.derive_named_inputs_digest(exact))


def _distinct_evidence_input(
    value,
    case_index: int,
    contract,
    ecosystem: str,
    *,
    suffix: str = "",
    outcome: NeutralOutcome | None = None,
    shared_change: bool = False,
    model_context=None,
    model_programs=None,
    model_lineages=None,
):
    label = f"v3-case-input-{case_index}" if shared_change else f"v3-case-input-{case_index}{suffix}"
    content = canonical.canonical_bytes(label)
    reference, change_resolver = stored_artifact(content, artifact_id=label)
    contract_content = canonical.canonical_bytes(family._contract_value(contract))
    contract_reference, contract_resolver = stored_artifact(contract_content, artifact_id=f"v3-contract-{case_index}{suffix}")
    contract_digest = family.family_contract_digest(contract)
    stamp = replace(
        value.record.packet.provenance,
        family_contract_digest=contract_digest,
        change_input_digest=reference.content_digest,
    )
    packet = replace(
        value.record.packet,
        family_id=contract.family_id,
        family_contract_digest=contract_digest,
        ecosystem=ecosystem,
        provenance=stamp,
    )
    decision = replace(
        value.record.decision,
        family_code="safe" if outcome is NeutralOutcome.SATISFIED else value.record.decision.family_code,
        outcome=outcome or value.record.decision.outcome,
        reasons=() if outcome is not None else value.record.decision.reasons,
        packet_digest=evidence.derive_packet_digest(packet),
    )
    record = evidence.EvidenceRecord(packet, decision, "")
    named = _rebind_named_inputs(value, reference, contract_reference, contract_digest)
    artifacts = {**change_resolver.artifacts, **contract_resolver.artifacts}
    if model_context is None:
        return validation.make_evidence_validation_input(record=record, named_inputs=named), artifacts
    return _model_evidence_input(record, named, contract, model_context, model_programs, model_lineages), artifacts


def _contract_catalog_context(context_case):
    template = context_case.context.evidence.family_catalog.entries[0].contract
    contracts = (
        template,
        replace(template, family_version="2", ecosystems=("javascript",)),
        replace(template, family_id="other-family"),
        replace(template, family_version="3"),
    )
    entries = tuple(
        sorted(
            (FamilyCatalogEntry(contract, family.family_contract_digest(contract)) for contract in contracts),
            key=catalog_entry_key,
        )
    )
    catalog = FamilyCatalog(entries, derive_catalog_digest(entries))
    old = context_case.context.evidence
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=catalog,
        fact_packs=old.fact_packs,
        model_programs=old.model_programs,
        lineages=old.lineages,
        fact_review_policy=old.fact_review_policy,
        provenance_trust_policy=old.provenance_trust_policy,
        custody_policy=old.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=context_case.context.admission_review_policy,
        proof_trust_policy=context_case.context.proof_trust_policy,
    )
    return replace(context_case, context=context)


def _rekey_configuration(
    configuration,
    scope: ScopeKey,
    *,
    minimum_pairs=None,
    minimum_ordinary_pushes=None,
    relaxed_precision=False,
):
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
    sufficiency = tuple(
        replace(
            row,
            key=key,
            minimum_pairs=(row.minimum_pairs if minimum_pairs is None else minimum_pairs),
            minimum_ordinary_pushes=(row.minimum_ordinary_pushes if minimum_ordinary_pushes is None else minimum_ordinary_pushes),
            precision_rules=tuple(
                replace(
                    precision,
                    maximum_wilson_width=100.0 if relaxed_precision else precision.maximum_wilson_width,
                    minimum_denominator=1 if relaxed_precision else precision.minimum_denominator,
                    rule_digest="",
                )
                for precision in row.precision_rules
            ),
            rule_digest="",
        )
        for row in configuration.sufficiency_rules
    )
    return replace(
        configuration,
        exact_scopes=(scope,),
        denominator_policies=policies,
        thresholds=thresholds,
        sufficiency_rules=sufficiency,
        configuration_identity_digest="",
    )


def _reviewed_scoped_census(plan, scopes, *, ordinary_count=None, whole_count=None, scope_counts=None):
    template_row = plan.census.scope_rows[0]
    scope_rows = tuple(replace(template_row, scope=scope) for scope in sorted(set(scopes.values())))
    if scope_counts is not None:
        pairs, vulnerable, fixed, sites, model_calls = scope_counts
        scope_rows = tuple(
            replace(
                row,
                pair_count=pairs,
                vulnerable_side_count=vulnerable,
                fixed_side_count=fixed,
                semantic_site_capacity=sites,
                model_call_capacity=model_calls,
            )
            for row in scope_rows
        )
    ecosystems = tuple(sorted({scope.ecosystem for scope in scopes.values()}))
    per_ecosystem = plan.census.whole_underlying_push_count // len(ecosystems) if ordinary_count is None else ordinary_count
    ordinary_rows = tuple(EcosystemOrdinaryCensusV3(ecosystem, per_ecosystem) for ecosystem in ecosystems)
    census_draft = replace(
        plan.census,
        scope_rows=scope_rows,
        ordinary_rows=ordinary_rows,
        whole_underlying_push_count=(plan.census.whole_underlying_push_count if whole_count is None else whole_count),
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
    return replace(census_reviewed, census_digest=derive_evaluation_census_digest(census_reviewed))


def _scoped_configurations(plan, scopes, minimum_pairs, minimum_ordinary_pushes, relaxed_precision):
    return tuple(
        _rekey_configuration(
            row,
            scopes[row.arm_id],
            minimum_pairs=minimum_pairs,
            minimum_ordinary_pushes=minimum_ordinary_pushes,
            relaxed_precision=relaxed_precision,
        )
        for row in plan.declaration.arm_configurations
    )


def _review_plan_draft(plan_draft, review):
    payload = derive_evaluation_plan_manifest_payload_digest(plan_draft)
    reviewed = replace(
        plan_draft,
        payload_digest=payload,
        review=_attestation(payload, review.producer_identity, review.reviewer_identity, review.conflict_disclosure),
    )
    return replace(reviewed, manifest_digest=derive_evaluation_plan_manifest_digest(reviewed))


def _reviewed_scoped_plan(
    plan,
    scopes,
    *,
    ordinary_count=None,
    whole_count=None,
    scope_counts=None,
    minimum_pairs=None,
    minimum_ordinary_pushes=None,
    relaxed_precision=False,
):
    configurations = _scoped_configurations(
        plan,
        scopes,
        minimum_pairs,
        minimum_ordinary_pushes,
        relaxed_precision,
    )
    inputs = tuple(sorted({slot.input_identity_digest for slot in plan.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=plan.declaration.population_digest,
        freeze_digest=plan.declaration.freeze_digest,
        input_set_digest=plan.declaration.input_set_digest,
        arm_configurations=configurations,
        input_identity_digests=inputs,
    )
    plan_draft = replace(
        plan,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        census=_reviewed_scoped_census(
            plan,
            scopes,
            ordinary_count=ordinary_count,
            whole_count=whole_count,
            scope_counts=scope_counts,
        ),
        payload_digest="0" * 64,
        manifest_digest="0" * 64,
    )
    return _review_plan_draft(plan_draft, plan.review)


def _scoped_authority_case(
    scopes,
    *,
    ordinary_count=None,
    whole_count=None,
    scope_counts=None,
    minimum_pairs=None,
    minimum_ordinary_pushes=None,
    relaxed_precision=False,
):
    context_case, plan, readiness = authority_fixtures._reviewed_plan()
    context_case = _contract_catalog_context(context_case)
    multi_plan = _reviewed_scoped_plan(
        plan,
        scopes,
        ordinary_count=ordinary_count,
        whole_count=whole_count,
        scope_counts=scope_counts,
        minimum_pairs=minimum_pairs,
        minimum_ordinary_pushes=minimum_ordinary_pushes,
        relaxed_precision=relaxed_precision,
    )
    original = authority_fixtures._reviewed_plan
    authority_fixtures._reviewed_plan = lambda: (context_case, multi_plan, readiness)
    try:
        return authority_fixtures._authority_case()
    finally:
        authority_fixtures._reviewed_plan = original


def _reference_authority_case():
    scope = ScopeKey("reference-family", "python")
    return _scoped_authority_case({"arm-a": scope, "arm-b": scope, "arm-combined": scope})


def _multi_scope_authority_case():
    return _scoped_authority_case(
        {
            "arm-a": ScopeKey("reference-family", "python"),
            "arm-b": ScopeKey("reference-family", "javascript"),
            "arm-combined": ScopeKey("reference-family", "python"),
        }
    )


def _ordinary_projection_authority_case():
    return _scoped_authority_case(
        {
            "arm-a": ScopeKey("reference-family", "python"),
            "arm-b": ScopeKey("reference-family", "javascript"),
            "arm-combined": ScopeKey("reference-family", "python"),
        },
        ordinary_count=1,
        whole_count=6,
        minimum_ordinary_pushes=1,
        relaxed_precision=True,
    )


def _contract_for_scope(context_case, scope: ScopeKey, *, family_version: str | None = None, family_id: str | None = None):
    selected_family = family_id or scope.family_id
    selected_version = family_version or ("2" if scope.ecosystem == "javascript" else "1")
    matches = tuple(
        entry.contract
        for entry in context_case.context.evidence.family_catalog.entries
        if entry.contract.family_id == selected_family
        and scope.ecosystem in entry.contract.ecosystems
        and entry.contract.family_version == selected_version
    )
    assert len(matches) == 1
    return matches[0]


def _case_evidence_inputs(
    original,
    index,
    arm_id,
    scope,
    context_case,
    evidence_mutation,
    summary_mutation,
    aligned_combination_cases,
    model_evidence,
    model_programs,
    model_lineages,
):
    contract = _contract_for_scope(context_case, scope)
    ecosystem = scope.ecosystem
    if evidence_mutation == "python_under_javascript" and arm_id == "arm-b" and index == 0:
        contract = _contract_for_scope(context_case, ScopeKey(scope.family_id, "python"), family_version="1")
        ecosystem = "python"
    elif evidence_mutation == "other_family_same_ecosystem" and arm_id == "arm-a" and index == 0:
        contract = _contract_for_scope(context_case, scope, family_id="other-family")
    satisfied = summary_mutation in {"omitted_satisfaction", "substituted_satisfaction"} and arm_id == "arm-a" and index == 0
    outcome = NeutralOutcome.SATISFIED if satisfied else None
    evidence_input, artifacts = _distinct_evidence_input(
        original.evidence_inputs[0],
        index,
        contract,
        ecosystem,
        suffix=f"-{arm_id}",
        outcome=outcome,
        shared_change=aligned_combination_cases,
        model_context=context_case if model_evidence else None,
        model_programs=model_programs,
        model_lineages=model_lineages,
    )
    evidence_inputs = (evidence_input,)
    if evidence_mutation == "mixed_contracts" and arm_id == "arm-a" and index == 0:
        alternate = _contract_for_scope(context_case, scope, family_version="3")
        extra_input, extra = _distinct_evidence_input(
            original.evidence_inputs[0], index, alternate, ecosystem, suffix=f"-{arm_id}-alternate"
        )
        evidence_inputs += (extra_input,)
        artifacts.update(extra)
    return evidence_inputs, artifacts, contract


def _case_projection(configuration, component, arm_id, index, first_component_arm, mutation):
    if configuration.kind is ArmKindV3.COMBINED:
        assert configuration.combination_rule is not None
        return CaseOutcomeProjectionV3(
            component.case_input_digest,
            CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
            tuple(component.projection_digest for _ in configuration.combination_rule.component_arm_ids),
            component.normalized_outcome,
            "",
        )
    if arm_id != first_component_arm or index != 0 or mutation is None:
        return component
    case_input = _digest("coordinated-other-case-input") if mutation == "case_input" else component.case_input_digest
    outcome = component.normalized_outcome
    if mutation == "outcome":
        outcome = NeutralOutcome.VIOLATION if outcome is not NeutralOutcome.VIOLATION else NeutralOutcome.SATISFIED
    sources = (_digest("coordinated-other-record"),) if mutation == "source" else component.source_outcome_digests
    if mutation not in {"case_input", "outcome", "source"}:  # pragma: no cover - fixture misuse
        raise AssertionError(f"unknown projection mutation: {mutation}")
    return CaseOutcomeProjectionV3(case_input, CaseOutcomeProjectionPolicyV3.UNANIMOUS_EVIDENCE, sources, outcome, "")


def _canonical_legacy_case(legacy, contract, records):
    pending = canonical.content_digest("admission-coverage-pending")
    base_outputs = derive_verdict_outputs(records, contract, pending)
    funnel = derive_case_funnel(legacy, records, len(base_outputs.defects))
    coverage_digest = derive_case_coverage_digest(legacy.case_id_digest, legacy.scope, funnel)
    outputs = derive_verdict_outputs(records, contract, coverage_digest)
    draft = replace(
        legacy,
        defect_claims=outputs.defects,
        satisfactions=outputs.satisfactions,
        silence=outputs.silence,
        coverage=funnel,
        result_digest="0" * 64,
    )
    return replace(draft, result_digest=derive_admission_case_result_digest(draft))


def _draft_case(
    original,
    index,
    arm_id,
    configuration,
    authority_case,
    first_component_arm,
    projection_mutation,
    evidence_mutation,
    summary_mutation,
    aligned_combination_cases,
    model_evidence,
    model_programs,
    model_lineages,
):
    scope = configuration.exact_scopes[0]
    evidence_inputs, artifacts, contract = _case_evidence_inputs(
        original,
        index,
        arm_id,
        scope,
        authority_case[0],
        evidence_mutation,
        summary_mutation,
        aligned_combination_cases,
        model_evidence,
        model_programs,
        model_lineages,
    )
    legacy = replace(
        original,
        case_id_digest=_digest(f"v3-association-{arm_id}-{index}"),
        scope=LegacyScopeKey(scope.family_id, scope.ecosystem),
        pair_id_digest=None if original.role is AdmissionCaseRole.ORDINARY else _digest(f"v3-pair-{arm_id}"),
        evidence_inputs=evidence_inputs,
        complexity=replace(
            original.complexity,
            transition_count=sum(len(item.record.packet.transitions) for item in evidence_inputs),
        ),
        result_digest="0" * 64,
    )
    verdict_records = tuple(item.record for item in evidence_inputs[:1] if evidence_mutation == "mixed_contracts")
    if not verdict_records:
        verdict_records = tuple(item.record for item in evidence_inputs)
    legacy = _canonical_legacy_case(legacy, contract, verdict_records)
    component = derive_component_case_outcome_projection(tuple(item.record for item in evidence_inputs))
    projection = _case_projection(configuration, component, arm_id, index, first_component_arm, projection_mutation)
    candidate = _proof_candidate(legacy, arm_id, scope, index)
    return _arm_case_result(legacy, candidate, configuration, projection, arm_id, index), artifacts


def _proof_candidate(legacy, arm_id, scope, index):
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
    return replace(candidate, candidate_digest=derive_proof_candidate_identity_digest(candidate))


def _arm_case_result(legacy, candidate, configuration, projection, arm_id, index):
    scope = configuration.exact_scopes[0]
    return ArmAdmissionCaseResultV3(
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


def _mutated_summary_case(draft_cases, mutation):
    if mutation is None:
        return draft_cases
    target = draft_cases["arm-a"][0]
    if mutation == "cross_ecosystem_claim":
        changed = replace(target, claims=draft_cases["arm-b"][0].claims)
    elif mutation == "unrelated_same_scope_claim":
        changed = replace(target, claims=draft_cases["arm-combined"][0].claims)
    elif mutation == "omitted_satisfaction":
        changed = replace(target, satisfactions=())
    elif mutation == "substituted_satisfaction":
        substituted = replace(target.satisfactions[0], question_ids=("unrelated-question",))
        changed = replace(target, satisfactions=(substituted,))
    elif mutation in {"extra_silence", "wrong_silence_coverage"}:
        coverage = _digest("wrong-silence-coverage") if mutation == "wrong_silence_coverage" else target.result_digest
        silence = BoundedSilence(("unrelated-question",), ("unrelated-reason",), (target.evidence_inputs[0].record.record_id,), coverage)
        changed = replace(target, silence=(silence,))
    elif mutation in {"findings_emitted", "sites_considered"}:
        field = mutation
        value = 0 if mutation == "findings_emitted" else getattr(target.coverage, field) + 1
        changed_coverage = replace(target.coverage, **{field: value})
        changed = replace(target, coverage=changed_coverage)
    else:  # pragma: no cover - fixture misuse
        raise AssertionError(f"unknown summary mutation: {mutation}")
    draft = replace(changed, result_digest="0" * 64)
    changed = replace(draft, result_digest=derive_admission_case_result_digest(_legacy_case(draft)))
    return {**draft_cases, "arm-a": (changed,) + draft_cases["arm-a"][1:]}


def _draft_cases(
    setup,
    authority_case,
    configurations,
    projection_mutation,
    evidence_mutation,
    summary_mutation,
    aligned_combination_cases,
    model_evidence,
):
    first_component_arm = next(item.arm_id for item in configurations.values() if item.kind is ArmKindV3.COMPONENT)
    draft_cases = {}
    extra_artifacts = {}
    model_programs = {}
    model_lineages = {}
    for arm_id, configuration in configurations.items():
        cases = []
        for index, original in enumerate(setup.cases):
            case, artifacts = _draft_case(
                original,
                index,
                arm_id,
                configuration,
                authority_case,
                first_component_arm,
                projection_mutation,
                evidence_mutation,
                summary_mutation,
                aligned_combination_cases,
                model_evidence,
                model_programs,
                model_lineages,
            )
            cases.append(case)
            extra_artifacts.update(artifacts)
        draft_cases[arm_id] = tuple(cases)
    return (
        _mutated_summary_case(draft_cases, summary_mutation),
        extra_artifacts,
        tuple(model_programs[key] for key in sorted(model_programs)),
        tuple(model_lineages[key] for key in sorted(model_lineages)),
    )


def _align_combined_case_projections(draft_cases, configurations):
    aligned = dict(draft_cases)
    for configuration in configurations.values():
        if configuration.kind is not ArmKindV3.COMBINED:
            continue
        rule = configuration.combination_rule
        assert rule is not None
        combined = []
        for index, case in enumerate(draft_cases[configuration.arm_id]):
            components = tuple(draft_cases[arm_id][index] for arm_id in rule.component_arm_ids)
            case_inputs = {item.case_input_digest for item in (*components, case)}
            assert len(case_inputs) == 1
            outcomes = tuple(item.outcome_projection.normalized_outcome for item in components)
            row = next(item for item in rule.decision_rows if item.component_outcomes == outcomes)
            projection = CaseOutcomeProjectionV3(
                case.case_input_digest,
                CaseOutcomeProjectionPolicyV3.DECLARATIVE_COMBINATION_TABLE,
                tuple(item.outcome_projection.projection_digest for item in components),
                row.combined_outcome,
                "",
            )
            combined.append(replace(case, outcome_projection=projection))
        aligned[configuration.arm_id] = tuple(combined)
    return aligned


def _shared_underlying_digests(draft_cases):
    return {
        arm_id: tuple(
            replace(case, underlying_push_digest=_digest(f"underlying-push-{case.key.scope.ecosystem}-{index}"))
            for index, case in enumerate(cases)
        )
        for arm_id, cases in draft_cases.items()
    }


def _case_refs(cases):
    return tuple(
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
                for case in cases
            ),
            key=lambda item: item.case_id_digest,
        )
    )


def _reviewed_manifest(manifest, sealed, setup):
    draft = replace(manifest, observations=tuple(sealed), payload_digest="0" * 64, manifest_digest="0" * 64)
    payload = derive_evaluation_admission_manifest_payload_digest(draft)
    review = _attestation(
        payload,
        setup.release.review.producer_identity,
        setup.release.review.reviewer_identity,
        setup.release.review.conflict_disclosure,
    )
    reviewed = replace(draft, payload_digest=payload, review=review)
    return replace(reviewed, manifest_digest=derive_evaluation_admission_manifest_digest(reviewed))


def _released_groups(draft_cases, observation_by_arm, manifest):
    groups = []
    for arm_id, cases in draft_cases.items():
        observation = observation_by_arm[arm_id]
        finalized = tuple(
            replace(
                case,
                observation_slot_digest=observation.slot_digest,
                observation_digest=observation.observation_digest,
                proof_candidate=replace(case.proof_candidate, observation_digest=observation.observation_digest),
            )
            for case in cases
        )
        baseline = next(item.baseline_digest for item in manifest.plan_manifest.baselines if item.arm_id == arm_id)
        ordered = tuple(sorted(finalized, key=lambda item: item.case_id_digest))
        groups.append(ArmAdmissionCasesV3(arm_id, baseline, ordered, ""))
    return tuple(sorted(groups, key=lambda item: item.arm_id))


def _release_bindings(groups, manifest):
    return tuple(
        sorted(
            (derive_released_arm_case_binding(case, manifest.plan_manifest) for group in groups for case in group.cases),
            key=lambda item: (item.key.arm_id, item.key.scope.family_id, item.key.scope.ecosystem, item.case_id_digest),
        )
    )


def _reviewed_release(manifest, authority, preparation, spend, bindings, review):
    draft = AdmissionCaseReleaseV3(
        manifest.plan_manifest.manifest_digest,
        manifest.manifest_digest,
        authority.authority_digest,
        preparation.preparation_digest,
        spend.binding_digest,
        bindings,
        "0" * 64,
        _attestation("0" * 64, review.producer_identity, review.reviewer_identity, review.conflict_disclosure),
        "0" * 64,
    )
    payload = derive_admission_case_release_payload_digest_v3(draft)
    reviewed = replace(
        draft,
        payload_digest=payload,
        review=_attestation(payload, review.producer_identity, review.reviewer_identity, review.conflict_disclosure),
    )
    return replace(reviewed, release_digest=derive_admission_case_release_digest_v3(reviewed))


def _sealed_observations(manifest, configurations, draft_cases, artifacts):
    sealed = []
    observations = []
    observation_by_arm = {}
    seen_arms = set()
    for index, slot in enumerate(manifest.plan_manifest.declaration.expected_observation_slots):
        cases = ()
        if slot.arm_id not in seen_arms:
            seen_arms.add(slot.arm_id)
            cases = _case_refs(draft_cases[slot.arm_id])
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
    return tuple(sealed), tuple(observations), observation_by_arm


def _with_model_context(authority_case, model_programs, model_lineages):
    context_case = authority_case[0]
    old = context_case.context.evidence
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=old.family_catalog,
        fact_packs=old.fact_packs,
        model_programs=tuple(sorted({*old.model_programs, *model_programs}, key=lambda item: item.declaration_digest)),
        lineages=tuple(sorted({*old.lineages, *model_lineages}, key=lambda item: item.manifest_digest)),
        fact_review_policy=old.fact_review_policy,
        provenance_trust_policy=old.provenance_trust_policy,
        custody_policy=old.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=context_case.context.admission_review_policy,
        proof_trust_policy=context_case.context.proof_trust_policy,
    )
    return (replace(context_case, context=context), *authority_case[1:])


def _reviewed_case(authority_case, manifest, observations, resolver):
    return authority_case[0], manifest, authority_case[2], authority_case[3], observations, resolver


def _bundle(
    *,
    authority_case=None,
    projection_mutation: str | None = None,
    evidence_mutation: str | None = None,
    summary_mutation: str | None = None,
    shared_underlying_by_ecosystem: bool = False,
    aligned_combination_cases: bool = False,
    model_evidence: bool = False,
):
    setup = _setup()
    authority_case = authority_case or _reference_authority_case()
    manifest = authority_case[1]
    configurations = {item.arm_id: item for item in manifest.plan_manifest.declaration.arm_configurations}
    draft_cases, extra_artifacts, model_programs, model_lineages = _draft_cases(
        setup,
        authority_case,
        configurations,
        projection_mutation,
        evidence_mutation,
        summary_mutation,
        aligned_combination_cases,
        model_evidence,
    )
    if model_evidence:
        authority_case = _with_model_context(authority_case, model_programs, model_lineages)
    if aligned_combination_cases:
        draft_cases = _align_combined_case_projections(draft_cases, configurations)
    if shared_underlying_by_ecosystem:
        draft_cases = _shared_underlying_digests(draft_cases)

    artifacts = {**authority_case[5].artifacts, **setup.resolver.artifacts, **extra_artifacts}
    sealed, observations, observation_by_arm = _sealed_observations(manifest, configurations, draft_cases, artifacts)

    manifest = _reviewed_manifest(manifest, sealed, setup)
    resolver = InMemoryContentResolver(artifacts)
    reviewed_case = _reviewed_case(authority_case, manifest, observations, resolver)
    authority, preparation = _prepare(reviewed_case)
    receipt = _spend(reviewed_case, preparation)
    spend = _bind(reviewed_case, preparation, receipt)

    groups = _released_groups(draft_cases, observation_by_arm, manifest)
    bindings = _release_bindings(groups, manifest)
    release = _reviewed_release(manifest, authority, preparation, spend, bindings, setup.release.review)
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


def _mutated_case(case, mutation):
    simple = {
        "arm": lambda: replace(case, key=ArmScopeKey("other-arm", case.key.scope)),
        "role": lambda: replace(case, role=AdmissionCaseRole.ORDINARY),
        "pair": lambda: replace(case, pair_id_digest=_digest("wrong-pair")),
        "scope": lambda: replace(case, key=ArmScopeKey(case.key.arm_id, ScopeKey(case.key.scope.family_id, "other"))),
        "observation": lambda: replace(case, observation_digest=_digest("wrong-observation")),
        "result": lambda: replace(case, result_digest=_digest("wrong-result")),
        "input": lambda: replace(case, evidence_inputs=(replace(case.evidence_inputs[0], input_digest=_digest("wrong-input")),)),
        "push": lambda: replace(case, underlying_push_digest=_digest("wrong-push")),
    }
    if mutation in simple:
        return simple[mutation]()
    if mutation == "manifest":
        changed = replace(case.input_manifest, manifest_digest=_digest("wrong-manifest"))
        with pytest.raises((EvaluationReleaseError, ValueError)):
            replace(case, input_manifest=changed)
        return None
    candidate_field = "finding_location_digest" if mutation == "location" else "change_input_digest"
    candidate = replace(case.proof_candidate, **{candidate_field: _digest(f"wrong-{mutation}")})
    return replace(case, proof_candidate=candidate)


@pytest.mark.parametrize(
    "mutation",
    ("arm", "role", "pair", "scope", "observation", "result", "input", "manifest", "location", "change", "push"),
)
def test_each_released_case_association_mutation_is_invalid(mutation: str) -> None:
    bundle = _bundle()
    groups = bundle[2]
    changed = _mutated_case(groups[0].cases[0], mutation)
    if changed is None:
        return
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
    assert scopes == {ScopeKey("reference-family", "javascript"), ScopeKey("reference-family", "python")}
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


@pytest.mark.parametrize(
    "mutation",
    ("python_under_javascript", "other_family_same_ecosystem", "mixed_contracts"),
)
def test_resealed_reviewed_release_refuses_evidence_outside_exact_case_scope_or_contract(mutation: str) -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case(), evidence_mutation=mutation)

    with pytest.raises(EvaluationReleaseError, match="family|ecosystem|contract|scope"):
        _validate(bundle)


@pytest.mark.parametrize(
    "mutation",
    (
        "cross_ecosystem_claim",
        "unrelated_same_scope_claim",
        "omitted_satisfaction",
        "substituted_satisfaction",
        "extra_silence",
        "wrong_silence_coverage",
        "findings_emitted",
        "sites_considered",
    ),
)
def test_resealed_reviewed_release_refuses_noncanonical_case_verdict_or_funnel(mutation: str) -> None:
    bundle = _bundle(authority_case=_multi_scope_authority_case(), summary_mutation=mutation)

    with pytest.raises(EvaluationReleaseError, match="verdict|claim|satisfaction|silence|coverage|funnel"):
        _validate(bundle)


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
