"""Synthetic multi-arm, multi-family V3 evaluation through one shared spend."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import test_core_evaluation_authority as authority_fixtures
import test_core_evaluation_case_validation as case_fixtures
from test_core_admission_fitted import _fitted_case, _population_manifest
from test_core_evaluation_case_validation import (
    _bundle,
    _contract_catalog_context,
    _rekey_configuration,
    _review_plan_draft,
    _reviewed_scoped_census,
)
from test_core_evaluation_fitted import _fitted_program, _holdout, _merge, _probe, _with_program
from test_core_evaluation_plan import _digest

from openultrasast.core import admission_context, custody, factpack
from openultrasast.core.admission_fitted import FittedComponentEvidence
from openultrasast.core.evaluation_measurement import ArmScopeKey, Comparator, MetricId, ScopeKey
from openultrasast.core.evaluation_plan import create_evaluation_plan_declaration, derive_evaluation_baselines
from openultrasast.core.evaluation_report import AdmissionDecision
from openultrasast.core.lineage import LineageManifest, derive_lineage_manifest_digest


def _expanded_configuration(configuration, scopes, fitted_configuration_digest):
    source = (
        replace(
            configuration,
            configuration_digest=fitted_configuration_digest,
            configuration_identity_digest="",
        )
        if configuration.arm_id == "arm-a"
        else configuration
    )
    scoped = tuple(
        _rekey_configuration(
            source,
            scope,
            minimum_pairs=1,
            minimum_ordinary_pushes=1,
            relaxed_precision=True,
        )
        for scope in scopes
    )
    thresholds = tuple(
        replace(
            threshold,
            target=0.0 if threshold.comparator is Comparator.AT_LEAST else 100.0,
            threshold_digest="",
        )
        for item in scoped
        for threshold in item.thresholds
    )
    return replace(
        source,
        exact_scopes=scopes,
        denominator_policies=tuple(row for item in scoped for row in item.denominator_policies),
        thresholds=thresholds,
        sufficiency_rules=tuple(row for item in scoped for row in item.sufficiency_rules),
        configuration_identity_digest="",
    )


def _multi_family_plan(plan, scopes, fitted_configuration_digest):
    configurations = tuple(
        _expanded_configuration(configuration, scopes, fitted_configuration_digest) for configuration in plan.declaration.arm_configurations
    )
    inputs = tuple(sorted({slot.input_identity_digest for slot in plan.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=plan.declaration.population_digest,
        freeze_digest=plan.declaration.freeze_digest,
        input_set_digest=plan.declaration.input_set_digest,
        arm_configurations=configurations,
        input_identity_digests=inputs,
    )
    census = _reviewed_scoped_census(
        plan,
        {f"scope-{index}": scope for index, scope in enumerate(scopes)},
        ordinary_count=1,
        whole_count=6,
        scope_counts=(1, 1, 1, 6, 3),
    )
    draft = replace(
        plan,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        census=census,
        payload_digest="0" * 64,
        manifest_digest="0" * 64,
    )
    return _review_plan_draft(draft, plan.review)


def _authority_case(plan, context_case, readiness):
    original = authority_fixtures._reviewed_plan
    authority_fixtures._reviewed_plan = lambda: (context_case, plan, readiness)
    try:
        return authority_fixtures._authority_case()
    finally:
        authority_fixtures._reviewed_plan = original


def _expanded_review_capacity(context_case):
    old = context_case.context.admission_review_policy
    maximum_bytes = 16_384
    policy = replace(
        old,
        maximum_evidence_bytes=maximum_bytes,
        policy_digest=factpack.derive_review_independence_policy_digest(
            old.reviewed_reviewer_digests,
            old.forbidden_identity_pairs,
            old.trusted_store_identities,
            maximum_bytes,
        ),
    )
    context = admission_context.make_admission_validation_context(
        evidence=context_case.context.evidence,
        admission_review_policy=policy,
        proof_trust_policy=context_case.context.proof_trust_policy,
    )
    return replace(context_case, context=context)


def _public_bundle(monkeypatch, authority_case):
    from openultrasast.core import evaluation_admission

    def prepare(reviewed_case):
        context_case, manifest, expected_feasibility, readiness, _, resolver = reviewed_case
        feasibility = evaluation_admission.preflight_evaluation(manifest.plan_manifest, context_case.context, resolver)
        assert feasibility == expected_feasibility
        preparation = evaluation_admission.authorize_evaluation(
            manifest,
            feasibility,
            readiness,
            context_case.context,
            context_case.port,
            resolver,
        )
        return preparation.authority, preparation

    def bind(reviewed_case, preparation, receipt):
        context_case, manifest = reviewed_case[:2]
        return evaluation_admission.validate_shared_spend(
            manifest,
            preparation,
            receipt,
            context_case.context,
            context_case.port,
        )

    monkeypatch.setattr(case_fixtures, "_prepare", prepare)
    monkeypatch.setattr(case_fixtures, "_bind", bind)
    return _bundle(
        authority_case=authority_case,
        aligned_combination_cases=True,
        shared_underlying_by_ecosystem=True,
        model_evidence=True,
        all_configuration_scopes=True,
    )


def _fitted_inputs(bundle, program, program_lineage, training_ref, training_resolver, key):
    probe_input, probe_resolver = _probe(bundle, program, key)
    fitted_use = next(item for item in program_lineage.uses if item.purpose is custody.LineagePurpose.FITTED_MODEL)
    fitting_lineage = LineageManifest(
        program_lineage.arm_id,
        program.fitted_component_digest,
        (fitted_use,),
        derive_lineage_manifest_digest(program_lineage.arm_id, program.fitted_component_digest, (fitted_use,)),
    )
    holdout, holdout_resolver = _holdout(
        _fitted_case(),
        program,
        fitting_lineage,
        training_ref,
        training_resolver,
        bundle[5][0].context,
    )
    return probe_input, fitting_lineage, holdout, _merge(bundle[4], probe_resolver, holdout_resolver)


def _complete_replay(monkeypatch):
    from openultrasast.core import evaluation_admission

    context_case, plan, readiness = authority_fixtures._reviewed_plan()
    context_case = _contract_catalog_context(context_case)
    training_repositories = (_digest("fitted-v3-training-repository"),)
    training_ref, training_resolver = _population_manifest(training_repositories, "e2e-training-population")
    program, program_lineage = _fitted_program(context_case, training_ref)
    context_case = _with_program(context_case, program, program_lineage)
    context_case = _expanded_review_capacity(context_case)
    scopes = tuple(sorted((ScopeKey("reference-family", "python"), ScopeKey("other-family", "javascript"))))
    reviewed_plan = _multi_family_plan(plan, scopes, program.configuration_digest)
    bundle = _public_bundle(monkeypatch, _authority_case(reviewed_plan, context_case, readiness))

    reviewed_case = bundle[5]
    readiness_by_digest = {item.result_digest: item for item in reviewed_case[3]}
    ordered_readiness = tuple(readiness_by_digest[digest] for digest in bundle[3].plan_manifest.readiness_digests)
    feasibility = evaluation_admission.preflight_evaluation(
        bundle[3].plan_manifest,
        reviewed_case[0].context,
        bundle[4],
    )
    replay = evaluation_admission.score_and_replay(
        bundle[3],
        feasibility,
        bundle[7],
        bundle[8],
        bundle[9],
        bundle[1],
        bundle[2],
        ordered_readiness,
        reviewed_case[0].context,
        reviewed_case[0].port,
        bundle[4],
    )
    assert (
        evaluation_admission.validate_evaluation_replay(
            replay,
            reviewed_case[0].context,
            reviewed_case[0].port,
            bundle[4],
        )
        == replay.reports
    )
    return bundle, replay, program, program_lineage, training_ref, training_resolver, training_repositories, scopes


def _assert_reviewed_control_plane(bundle, replay) -> None:
    resolver = bundle[4]
    plan = replay.plan_manifest
    assert plan.review.producer_identity != plan.review.reviewer_identity
    assert plan.census.review.producer_identity != plan.census.review.reviewer_identity
    assert replay.feasibility.may_spend
    assert replay.admission_manifest.feasibility_digest == replay.feasibility.feasibility_digest
    sealed = replay.admission_manifest.observations
    assert sealed and all(item.observation.byte_length > 0 for item in sealed)
    assert all(resolver.resolve(item.observation).content for item in sealed)
    attempts = replay.admission_manifest.attempt_history.events
    assert attempts and all(item.event.byte_length > 0 for item in attempts)
    assert all(resolver.resolve(item.event).content for item in attempts)
    receipts = tuple(receipt for group in replay.cases_by_arm for case in group.cases for receipt in case.input_receipts)
    assert receipts and all(receipt.opened and receipt.byte_count > 0 for receipt in receipts)


def _assert_conformance(bundle, replay, scopes) -> None:
    _assert_reviewed_control_plane(bundle, replay)
    expected_keys = {ArmScopeKey(arm_id, scope) for arm_id in ("arm-a", "arm-b", "arm-combined") for scope in scopes}
    actual_keys = {result.key for report in replay.reports for result in report.scoped_results}
    assert actual_keys == expected_keys
    assert all(result.decision is AdmissionDecision.GO for report in replay.reports for result in report.scoped_results)
    assert len(replay.combination_lineages) == 1
    assert {row.key.scope for row in replay.combination_lineages[0].combined_cases} == set(scopes)
    assert all(len(row.components) == 2 for row in replay.combination_lineages[0].combined_cases)
    assert all(
        observation.input_read_evidence_digest != "0" * 64 and observation.stage_execution_evidence_digest != "0" * 64
        for observation in replay.report_source.observations
    )
    assert replay.admission_manifest.review.producer_identity != replay.admission_manifest.review.reviewer_identity
    assert replay.preparation.preparation_digest == bundle[7].preparation_digest
    assert replay.receipt.receipt_digest == bundle[8].receipt_digest
    assert replay.spend_binding.binding_digest == bundle[9].binding_digest
    assert replay.whole_population_coverage.underlying_push_count == 6
    assert replay.report_source.whole_projection.underlying_push_count == 6
    ordinary_metrics = tuple(
        metric for metric in replay.report_source.metrics if metric.metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100
    )
    assert len(ordinary_metrics) == 6
    assert all(metric.denominator == 1 for metric in ordinary_metrics)


def _trusted_probe_result(bundle, program, probe_input, fitted_resolver):
    from openultrasast.core import probes

    context = bundle[5][0].context
    contract = next(
        entry.contract for entry in context.evidence.family_catalog.entries if entry.contract_digest == program.family_contract_digest
    )
    return probes.evaluate_probe(
        probe_input.probe,
        probe_input.observation,
        contract,
        context.evidence.fact_review_policy,
        fitted_resolver,
    )


def _authorize_fitted_selection(
    bundle,
    replay,
    program,
    program_lineage,
    training_ref,
    training_resolver,
    training_repositories,
) -> None:
    from openultrasast.core.evaluation_fitted import authorize_fitted_component_v3

    reviewed_case = bundle[5]
    selected_key = ArmScopeKey("arm-a", ScopeKey("reference-family", "python"))
    selected_report = next(report for report in replay.reports if report.baseline.arm_id == selected_key.arm_id)
    probe_input, fitting_lineage, holdout, fitted_resolver = _fitted_inputs(
        bundle,
        program,
        program_lineage,
        training_ref,
        training_resolver,
        selected_key,
    )
    # The probe result digest is rederived from the trusted probe input, never from a caller summary.
    probe_result = _trusted_probe_result(bundle, program, probe_input, fitted_resolver)
    evidence = FittedComponentEvidence(
        program.fitted_component_digest,
        (probe_result.result_digest,),
        fitting_lineage.manifest_digest,
        training_ref,
        training_repositories,
        holdout.report_digest,
        selected_report.report_digest,
    )
    authorize_fitted_component_v3(
        evidence,
        (probe_input,),
        fitting_lineage,
        holdout,
        replay,
        selected_key,
        reviewed_case[0].context,
        reviewed_case[0].port,
        fitted_resolver,
    )


def test_public_v3_facade_completes_multi_family_multi_ecosystem_shared_spend_and_fitted_selection(monkeypatch) -> None:
    fixture_bytes = Path(__file__).read_bytes()
    assert fixture_bytes and len(fixture_bytes) > 100
    completed = _complete_replay(monkeypatch)
    bundle, replay, program, program_lineage, training_ref, training_resolver, training_repositories, scopes = completed
    _assert_conformance(bundle, replay, scopes)
    _authorize_fitted_selection(
        bundle,
        replay,
        program,
        program_lineage,
        training_ref,
        training_resolver,
        training_repositories,
    )
