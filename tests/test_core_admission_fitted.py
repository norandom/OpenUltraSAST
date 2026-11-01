"""Fitted components require replayed admission, holdout and probe evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_context import _resign_manifest
from test_core_admission_metrics import _case_result, _MetricSetup, _resign_census_rows, _run, _setup
from test_core_admission_report import _failed_quality_bundle
from test_core_probes import _review
from test_core_readiness import _chain

from openultrasast.core import admission_context, canonical, custody, model, model_apply, probes, semantics, validation
from openultrasast.core.admission_case import AdmissionCaseRole
from openultrasast.core.admission_fitted import (
    REPOSITORY_POPULATION_MANIFEST_SCHEMA,
    FittedComponentAuthorizationError,
    FittedComponentEvidence,
    authorize_fitted_component,
)
from openultrasast.core.admission_report import AdmissionDecision, AdmissionReplay, score_admission
from openultrasast.core.admission_review import AdmissionThreshold, derive_threshold_set_digest
from openultrasast.core.lineage import LineageManifest, LineageUse, derive_lineage_manifest_digest
from openultrasast.core.measurement import Comparator, MetricId, Statistic, derive_identity_set_digest
from openultrasast.core.measurement_factory import create_measurement_record, create_repository_holdout_report
from openultrasast.core.measurement_record import RepositoryHoldoutReport
from openultrasast.core.readiness import ReadinessEvidenceUse


@dataclass(frozen=True)
class FittedCase:
    evidence: FittedComponentEvidence
    probes: tuple[probes.ProbeEvaluationInput, ...]
    lineage: LineageManifest
    holdout: RepositoryHoldoutReport
    replay: AdmissionReplay
    setup: _MetricSetup
    resolver: InMemoryContentResolver


def _digest(value: str) -> str:
    return canonical.content_digest(value)


def _merge(*resolvers: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for resolver in resolvers:
        artifacts.update(resolver.artifacts)
    return InMemoryContentResolver(artifacts)


def _append_use(
    setup: _MetricSetup,
    *,
    arm: str,
    purpose: custody.LineagePurpose,
    artifact: str,
    population_digest: str | None = None,
) -> LineageUse:
    population = population_digest or setup.cases[0].evidence_inputs[0].record.packet.provenance.population_digest
    current = setup.custody.current_log(population)
    request = custody.PopulationUseRequest(population, arm, purpose, False, artifact, current.log_digest)
    receipt = setup.custody.append(request, current.custodian_identity)
    return LineageUse(purpose, population, False, artifact, receipt.receipt_digest)


def _model_program(setup: _MetricSetup) -> tuple[model.ModelProgramDeclaration, LineageManifest]:
    record = setup.cases[0].evidence_inputs[0].record
    contract = setup.context.evidence.family_catalog.entries[0].contract
    question = contract.residual_questions[0]
    bundle = model.derive_model_input_bundle_digest(record, contract, question, model.completeness_snapshot(record, contract))
    component = _digest("fitted-component-v2")
    training_ref, _ = _population_manifest((_digest("repo-training"),), "training-population")
    source = setup.custody.current_log(record.packet.provenance.population_digest)
    setup.custody.logs[training_ref.content_digest] = custody.empty_population_custody_log(
        training_ref.content_digest,
        source.custodian_identity,
    )
    artifacts = (
        (custody.LineagePurpose.PROMPT, _digest("fitted-prompt")),
        (custody.LineagePurpose.EXAMPLE, _digest("fitted-examples")),
        (custody.LineagePurpose.FITTED_MODEL, component),
        (custody.LineagePurpose.DECISION_MAPPING, _digest("fitted-mapping")),
    )
    uses = tuple(
        _append_use(
            setup,
            arm="fitted-arm",
            purpose=purpose,
            artifact=artifact,
            population_digest=training_ref.content_digest if purpose is custody.LineagePurpose.FITTED_MODEL else None,
        )
        for purpose, artifact in artifacts
    )
    lineage = LineageManifest("fitted-arm", bundle, uses, derive_lineage_manifest_digest("fitted-arm", bundle, uses))
    return (
        model.make_model_program_declaration(
            family_contract_digest=setup.context.evidence.family_catalog.entries[0].contract_digest,
            provider="provider",
            model_name="fitted-model-v2",
            program_digest=_digest("fitted-program"),
            prompt_digest=artifacts[0][1],
            example_set_digest=artifacts[1][1],
            fitted_component_digest=component,
            configuration_digest=_digest("fitted-configuration"),
            adapter_revision="fitted-adapter-v2",
            decision_mapping_digest=artifacts[3][1],
            input_bundle_digest=bundle,
            lineage_manifest_digest=lineage.manifest_digest,
        ),
        lineage,
    )


def _model_input(
    setup: _MetricSetup,
    program: model.ModelProgramDeclaration,
    lineage: LineageManifest,
) -> validation.EvidenceValidationInput:
    supplied = setup.cases[0].evidence_inputs[0]
    contract = setup.context.evidence.family_catalog.entries[0].contract
    request = model.make_model_request(
        record=supplied.record,
        contract=contract,
        residual_question_id=contract.residual_questions[0].question_id,
        program=program,
        lineage=lineage,
        custody_policy_digest=setup.context.evidence.custody_policy.policy_digest,
        proposal_program_digests=(_digest("independent-proposer"),),
        trusted_response_store_identities=("trusted-store",),
        maximum_response_bytes=256,
    )
    response = model.make_preserved_model_response(
        normalized_fields=(semantics.FieldValue("decision", semantics.FieldKind.TEXT, "unsafe"),),
        inline_redacted_text="[redacted] unsafe",
        artifact=None,
        redaction_policy_digest=_digest("redaction-policy"),
    )
    result = model.make_model_result(
        request=request,
        status=model.ModelStatus.SUCCEEDED,
        response=response,
        family_decision="unsafe",
        failure_reason=None,
    )
    derived = model_apply.apply_model_result(
        supplied.record,
        contract,
        request,
        result,
        setup.resolver,
        setup.custody,
        setup.context.evidence.custody_policy,
    )
    return validation.make_evidence_validation_input(
        record=derived,
        named_inputs=supplied.named_inputs,
        model_request=request,
        model_result=result,
    )


def _fitted_setup() -> _MetricSetup:
    setup = _setup()
    program, program_lineage = _model_program(setup)
    model_input = _model_input(setup, program, program_lineage)
    original = setup.cases
    vulnerable, resolver = _case_result(
        model_input,
        AdmissionCaseRole.VULNERABLE,
        original[0].pair_id_digest,
        setup.resolver,
        setup.context.evidence.family_catalog.entries[0].contract,
    )
    cases = (vulnerable, *original[1:])
    row = replace(setup.manifest.census.rows[0], model_call_capacity=1)
    census = _resign_census_rows(setup.manifest.census, (row,), setup.manifest.identity.population_digest)
    model_threshold = AdmissionThreshold(MetricId.MODEL_SUCCESS_RATE, Statistic.COUNT, Comparator.AT_LEAST, 1.0)
    thresholds = tuple(sorted((*setup.manifest.thresholds, model_threshold), key=lambda item: (item.metric_id.value, item.statistic.value)))
    threshold_digest = derive_threshold_set_digest(thresholds)
    threshold_use = _append_use(
        setup,
        arm=setup.manifest.identity.arm_id,
        purpose=custody.LineagePurpose.THRESHOLD,
        artifact=threshold_digest,
    )
    threshold_lineage = LineageManifest(
        setup.manifest.identity.arm_id,
        threshold_digest,
        (threshold_use,),
        derive_lineage_manifest_digest(setup.manifest.identity.arm_id, threshold_digest, (threshold_use,)),
    )
    old_program = setup.context.evidence.model_programs[0]
    excluded = {old_program.lineage_manifest_digest, setup.manifest.threshold_lineage_manifest_digest}
    lineages = tuple(item for item in setup.context.evidence.lineages if item.manifest_digest not in excluded)
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=setup.context.evidence.family_catalog,
        fact_packs=setup.context.evidence.fact_packs,
        model_programs=(program,),
        lineages=(*lineages, program_lineage, threshold_lineage),
        fact_review_policy=setup.context.evidence.fact_review_policy,
        provenance_trust_policy=setup.context.evidence.provenance_trust_policy,
        custody_policy=setup.context.evidence.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=setup.context.admission_review_policy,
        proof_trust_policy=setup.context.proof_trust_policy,
    )
    identity = replace(
        setup.manifest.identity,
        model_program_digests=(program.declaration_digest,),
        model_program_set_digest=derive_identity_set_digest("model_program", (program.declaration_digest,)),
        threshold_set_digest=threshold_digest,
    )
    scope = identity.claimed_scopes[0]
    analysis = admission_context.derive_analysis_identity(identity, evidence_context.family_catalog, scope, program.declaration_digest)
    readiness = _chain(identity=analysis)[:6]
    manifest = _resign_manifest(
        replace(
            setup.manifest,
            identity=identity,
            census=census,
            readiness_digests=tuple(sorted(item.result_digest for item in readiness)),
            thresholds=thresholds,
            threshold_set_digest=threshold_digest,
            threshold_lineage_manifest_digest=threshold_lineage.manifest_digest,
            validation_context_digest=context.context_digest,
        ),
        setup.manifest.review.conflict_disclosure,
    )
    return _MetricSetup(manifest, setup.denominator, cases, context, setup.custody, resolver, readiness)


def _population_manifest(repositories: tuple[str, ...], artifact_id: str) -> tuple[canonical.ContentRef, InMemoryContentResolver]:
    content = canonical.canonical_bytes({"schema_version": REPOSITORY_POPULATION_MANIFEST_SCHEMA, "repository_digests": repositories})
    return stored_artifact(content, artifact_id=artifact_id)


def _probe(setup: _MetricSetup, component: str) -> tuple[probes.ProbeEvaluationInput, InMemoryContentResolver]:
    request = setup.cases[0].evidence_inputs[0].model_request
    assert request is not None
    record = request.record
    contract = setup.context.evidence.family_catalog.entries[0].contract
    forward, forward_resolver = stored_artifact(b"- old\n+ new\n", artifact_id="fitted-forward")
    reversed_ref, reversed_resolver = stored_artifact(b"+ old\n- new\n", artifact_id="fitted-reversed")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="fitted-probe-disclosure")
    projection = probes.project_semantics(record, contract)
    reviewer = setup.context.evidence.fact_review_policy.reviewed_reviewer_digests[0]
    review = _review(
        projection,
        projection,
        contract,
        forward,
        reversed_ref,
        disclosure,
        producer=_digest("probe-producer"),
        reviewer=reviewer,
    )
    probe = probes.ReversedPairProbe(
        "",
        setup.context.evidence.model_programs[0].family_contract_digest,
        record,
        record,
        forward,
        reversed_ref,
        review,
        0.05,
    )
    observation = probes.ProbeObservation(probe.probe_id, component, "unsafe", "unsafe", 0.50, 0.52)
    return probes.ProbeEvaluationInput(probe, observation), _merge(forward_resolver, reversed_resolver, disclosure_resolver)


def _fitted_case() -> FittedCase:
    setup = _fitted_setup()
    run = _run(setup)
    replay = score_admission(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        run.preparation,
        run.receipt,
        run.release,
        setup.cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    assert replay.report.decision is AdmissionDecision.GO
    program = setup.context.evidence.model_programs[0]
    assert program.fitted_component_digest is not None
    component = program.fitted_component_digest
    probe_input, probe_resolver = _probe(setup, component)
    probe_result = probes.evaluate_probe(
        probe_input.probe,
        probe_input.observation,
        setup.context.evidence.family_catalog.entries[0].contract,
        setup.context.evidence.fact_review_policy,
        probe_resolver,
    )
    training_repositories = (_digest("repo-training"),)
    holdout_repositories = (_digest("repo-holdout"),)
    training_ref, training_resolver = _population_manifest(training_repositories, "training-population")
    holdout_ref, holdout_resolver = _population_manifest(holdout_repositories, "holdout-population")
    measurement = replay.report.measurement
    holdout_identity = replace(
        measurement.identity,
        population_digest=holdout_ref.content_digest,
        model_program_digests=(component,),
        model_program_set_digest=derive_identity_set_digest("model_program", (component,)),
    )
    holdout_measurement = create_measurement_record(
        identity=holdout_identity,
        family_decision_vocabulary=measurement.family_decision_vocabulary,
        family_decision_counts=measurement.family_decision_counts,
        neutral_outcome_counts=measurement.neutral_outcome_counts,
        evidence_basis_counts=measurement.evidence_basis_counts,
        metrics=measurement.metrics,
        stage_funnel=measurement.stage_funnel,
        instrument_failures=measurement.instrument_failures,
        model_outcome_counts=measurement.model_outcome_counts,
        model_failures=measurement.model_failures,
        runtime_ms=measurement.runtime_ms,
        prerequisite_readiness=measurement.prerequisite_readiness,
    )
    program_lineage = next(item for item in setup.context.evidence.lineages if item.manifest_digest == program.lineage_manifest_digest)
    use = next(item for item in program_lineage.uses if item.purpose is custody.LineagePurpose.FITTED_MODEL)
    lineage = LineageManifest(
        program_lineage.arm_id,
        component,
        (use,),
        derive_lineage_manifest_digest(program_lineage.arm_id, component, (use,)),
    )
    holdout = create_repository_holdout_report(
        component_digest=component,
        role=ReadinessEvidenceUse.REPOSITORY_HOLDOUT,
        training_population_manifest=training_ref,
        holdout_population_manifest=holdout_ref,
        training_repository_digests=training_repositories,
        holdout_repository_digests=holdout_repositories,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        measurement=holdout_measurement,
    )
    evidence = FittedComponentEvidence(
        component,
        (probe_result.result_digest,),
        lineage.manifest_digest,
        training_ref,
        training_repositories,
        holdout.report_digest,
        replay.report.report_digest,
    )
    resolver = _merge(setup.resolver, probe_resolver, training_resolver, holdout_resolver)
    return FittedCase(evidence, (probe_input,), lineage, holdout, replay, setup, resolver)


def _authorize(case: FittedCase, **changes: object) -> None:
    authorize_fitted_component(
        changes.get("evidence", case.evidence),  # type: ignore[arg-type]
        changes.get("probes", case.probes),  # type: ignore[arg-type]
        case.setup.context,
        changes.get("lineage", case.lineage),  # type: ignore[arg-type]
        changes.get("holdout", case.holdout),  # type: ignore[arg-type]
        changes.get("replay", case.replay),  # type: ignore[arg-type]
        case.setup.custody,
        changes.get("resolver", case.resolver),  # type: ignore[arg-type]
    )


def _holdout_with_identity(case: FittedCase, **changes: object) -> tuple[RepositoryHoldoutReport, FittedComponentEvidence]:
    measurement = case.holdout.measurement
    identity = replace(measurement.identity, **changes)
    changed_measurement = create_measurement_record(
        identity=identity,
        family_decision_vocabulary=measurement.family_decision_vocabulary,
        family_decision_counts=measurement.family_decision_counts,
        neutral_outcome_counts=measurement.neutral_outcome_counts,
        evidence_basis_counts=measurement.evidence_basis_counts,
        metrics=measurement.metrics,
        stage_funnel=measurement.stage_funnel,
        instrument_failures=measurement.instrument_failures,
        model_outcome_counts=measurement.model_outcome_counts,
        model_failures=measurement.model_failures,
        runtime_ms=measurement.runtime_ms,
        prerequisite_readiness=measurement.prerequisite_readiness,
    )
    holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=case.holdout.training_population_manifest,
        holdout_population_manifest=case.holdout.holdout_population_manifest,
        training_repository_digests=case.holdout.training_repository_digests,
        holdout_repository_digests=case.holdout.holdout_repository_digests,
        fitting_lineage_manifest_digest=case.holdout.fitting_lineage_manifest_digest,
        measurement=changed_measurement,
    )
    evidence = replace(case.evidence, repository_holdout_report_digest=holdout.report_digest)
    return holdout, evidence


def test_complete_fitted_component_authorization_replays_every_evidence_layer() -> None:
    _authorize(_fitted_case())


def test_raw_report_and_no_go_admission_are_refused() -> None:
    case = _fitted_case()
    with pytest.raises(FittedComponentAuthorizationError, match="replay"):
        _authorize(case, replay=case.replay.report)
    failed = _failed_quality_bundle()
    with pytest.raises(FittedComponentAuthorizationError, match="not GO"):
        authorize_fitted_component(
            case.evidence,
            case.probes,
            failed.setup.context,
            case.lineage,
            case.holdout,
            failed.replay,
            failed.setup.custody,
            failed.setup.resolver,
        )


def test_holdout_unreadable_manifest_and_identity_mismatch_are_refused() -> None:
    case = _fitted_case()
    unreadable = InMemoryContentResolver(
        {key: value for key, value in case.resolver.artifacts.items() if key != case.holdout.holdout_population_manifest.artifact_id}
    )
    with pytest.raises(FittedComponentAuthorizationError, match="artifact|authorization refused"):
        _authorize(case, resolver=unreadable)
    wrong = replace(case.evidence, repository_holdout_report_digest=_digest("wrong-holdout"))
    with pytest.raises(FittedComponentAuthorizationError, match="holdout report"):
        _authorize(case, evidence=wrong)

    mismatched_ref, mismatched_resolver = _population_manifest((_digest("repo-substituted"),), "holdout-substituted")
    mismatched_holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=case.holdout.training_population_manifest,
        holdout_population_manifest=mismatched_ref,
        training_repository_digests=case.holdout.training_repository_digests,
        holdout_repository_digests=case.holdout.holdout_repository_digests,
        fitting_lineage_manifest_digest=case.holdout.fitting_lineage_manifest_digest,
        measurement=case.holdout.measurement,
    )
    mismatched_evidence = replace(
        case.evidence,
        repository_holdout_report_digest=mismatched_holdout.report_digest,
    )
    with pytest.raises(FittedComponentAuthorizationError, match="holdout population|resolved population"):
        _authorize(
            case,
            evidence=mismatched_evidence,
            holdout=mismatched_holdout,
            resolver=_merge(case.resolver, mismatched_resolver),
        )


def test_digest_valid_holdout_for_unrelated_family_contract_is_refused() -> None:
    case = _fitted_case()
    holdout, evidence = _holdout_with_identity(
        case,
        family_contract_digests=(_digest("unrelated-contract"),),
        family_contract_set_digest=_digest("unrelated-contract-set"),
        outcome_mapping_digest=_digest("unrelated-outcome-mapping"),
    )

    with pytest.raises(FittedComponentAuthorizationError, match="holdout.*contract|family contract"):
        _authorize(case, evidence=evidence, holdout=holdout)


def test_digest_valid_holdout_measurement_for_another_population_is_refused() -> None:
    case = _fitted_case()
    repositories = (_digest("repo-substituted-holdout"),)
    holdout_ref, holdout_resolver = _population_manifest(repositories, "substituted-holdout-population")
    measurement = case.holdout.measurement
    changed_measurement = create_measurement_record(
        identity=replace(measurement.identity, population_digest=_digest("unrelated-holdout-population")),
        family_decision_vocabulary=measurement.family_decision_vocabulary,
        family_decision_counts=measurement.family_decision_counts,
        neutral_outcome_counts=measurement.neutral_outcome_counts,
        evidence_basis_counts=measurement.evidence_basis_counts,
        metrics=measurement.metrics,
        stage_funnel=measurement.stage_funnel,
        instrument_failures=measurement.instrument_failures,
        model_outcome_counts=measurement.model_outcome_counts,
        model_failures=measurement.model_failures,
        runtime_ms=measurement.runtime_ms,
        prerequisite_readiness=measurement.prerequisite_readiness,
    )
    holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=case.holdout.training_population_manifest,
        holdout_population_manifest=holdout_ref,
        training_repository_digests=case.holdout.training_repository_digests,
        holdout_repository_digests=repositories,
        fitting_lineage_manifest_digest=case.holdout.fitting_lineage_manifest_digest,
        measurement=changed_measurement,
    )
    evidence = replace(case.evidence, repository_holdout_report_digest=holdout.report_digest)

    with pytest.raises(FittedComponentAuthorizationError, match="holdout population"):
        _authorize(
            case,
            evidence=evidence,
            holdout=holdout,
            resolver=_merge(case.resolver, holdout_resolver),
        )


def test_digest_valid_holdout_measurement_with_extra_component_is_refused() -> None:
    case = _fitted_case()
    components = tuple(sorted((case.evidence.component_digest, _digest("unrelated-component"))))
    holdout, evidence = _holdout_with_identity(
        case,
        model_program_digests=components,
        model_program_set_digest=derive_identity_set_digest("model_program", components),
    )

    with pytest.raises(FittedComponentAuthorizationError, match="component set|model component"):
        _authorize(case, evidence=evidence, holdout=holdout)


def test_digest_valid_fitting_lineage_for_another_training_population_is_refused() -> None:
    case = _fitted_case()
    population = case.setup.cases[0].evidence_inputs[0].record.packet.provenance.population_digest
    current = case.setup.custody.current_log(population)
    request = custody.PopulationUseRequest(
        population,
        "substituted-fitting-arm",
        custody.LineagePurpose.FITTED_MODEL,
        False,
        case.evidence.component_digest,
        current.log_digest,
    )
    receipt = case.setup.custody.append(request, current.custodian_identity)
    use = LineageUse(
        custody.LineagePurpose.FITTED_MODEL,
        population,
        False,
        case.evidence.component_digest,
        receipt.receipt_digest,
    )
    lineage = LineageManifest(
        request.arm_id,
        case.evidence.component_digest,
        (use,),
        derive_lineage_manifest_digest(request.arm_id, case.evidence.component_digest, (use,)),
    )
    holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=case.holdout.training_population_manifest,
        holdout_population_manifest=case.holdout.holdout_population_manifest,
        training_repository_digests=case.holdout.training_repository_digests,
        holdout_repository_digests=case.holdout.holdout_repository_digests,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        measurement=case.holdout.measurement,
    )
    evidence = replace(
        case.evidence,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        repository_holdout_report_digest=holdout.report_digest,
    )

    with pytest.raises(FittedComponentAuthorizationError, match="program lineage projection|training population"):
        _authorize(case, evidence=evidence, lineage=lineage, holdout=holdout)


def test_coordinated_training_lineage_substitution_is_refused() -> None:
    case = _fitted_case()
    repositories = (_digest("repo-alternate-training"),)
    training_ref, training_resolver = _population_manifest(repositories, "alternate-training-population")
    custodian = case.setup.context.evidence.custody_policy.reviewed_custodian_digests[0]
    case.setup.custody.logs[training_ref.content_digest] = custody.empty_population_custody_log(
        training_ref.content_digest,
        custodian,
    )
    program = case.setup.context.evidence.model_programs[0]
    program_lineage = next(item for item in case.setup.context.evidence.lineages if item.manifest_digest == program.lineage_manifest_digest)
    current = case.setup.custody.current_log(training_ref.content_digest)
    request = custody.PopulationUseRequest(
        training_ref.content_digest,
        program_lineage.arm_id,
        custody.LineagePurpose.FITTED_MODEL,
        False,
        case.evidence.component_digest,
        current.log_digest,
    )
    receipt = case.setup.custody.append(request, current.custodian_identity)
    use = LineageUse(
        request.purpose,
        request.population_digest,
        request.labels_accessed,
        request.influenced_artifact_digest,
        receipt.receipt_digest,
    )
    lineage = LineageManifest(
        request.arm_id,
        case.evidence.component_digest,
        (use,),
        derive_lineage_manifest_digest(request.arm_id, case.evidence.component_digest, (use,)),
    )
    holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=training_ref,
        holdout_population_manifest=case.holdout.holdout_population_manifest,
        training_repository_digests=repositories,
        holdout_repository_digests=case.holdout.holdout_repository_digests,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        measurement=case.holdout.measurement,
    )
    evidence = replace(
        case.evidence,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        training_population_manifest=training_ref,
        training_repository_digests=repositories,
        repository_holdout_report_digest=holdout.report_digest,
    )

    with pytest.raises(FittedComponentAuthorizationError, match="program lineage|fitted-model use"):
        _authorize(
            case,
            evidence=evidence,
            lineage=lineage,
            holdout=holdout,
            resolver=_merge(case.resolver, training_resolver),
        )


def test_fabricated_probe_summary_duplicate_or_failed_probe_is_refused() -> None:
    case = _fitted_case()
    forged = replace(case.evidence, probe_result_digests=(_digest("fabricated-pass"),))
    with pytest.raises(FittedComponentAuthorizationError, match="derived probe"):
        _authorize(case, evidence=forged)
    with pytest.raises(FittedComponentAuthorizationError, match="duplicate"):
        _authorize(case, probes=(case.probes[0], case.probes[0]))
    failed = replace(case.probes[0], observation=replace(case.probes[0].observation, reversed_score=0.90))
    with pytest.raises(FittedComponentAuthorizationError, match="failed.*probe"):
        _authorize(case, probes=(failed,))


def test_component_and_fitting_lineage_substitutions_are_refused() -> None:
    case = _fitted_case()
    wrong = replace(case.probes[0].observation, component_digest=_digest("wrong-component"))
    with pytest.raises(FittedComponentAuthorizationError, match="component"):
        _authorize(case, probes=(replace(case.probes[0], observation=wrong),))
    with pytest.raises(FittedComponentAuthorizationError, match="fitting lineage"):
        _authorize(case, lineage=replace(case.lineage, manifest_digest=_digest("wrong-lineage")))
    contaminated_use = replace(
        case.lineage.uses[0],
        source_population_digest=case.replay.report.identity.population_digest,
    )
    contaminated = LineageManifest(
        case.lineage.arm_id,
        case.lineage.subject_digest,
        (contaminated_use,),
        derive_lineage_manifest_digest(case.lineage.arm_id, case.lineage.subject_digest, (contaminated_use,)),
    )
    contaminated_evidence = replace(case.evidence, fitting_lineage_manifest_digest=contaminated.manifest_digest)
    contaminated_holdout = create_repository_holdout_report(
        component_digest=case.holdout.component_digest,
        role=case.holdout.role,
        training_population_manifest=case.holdout.training_population_manifest,
        holdout_population_manifest=case.holdout.holdout_population_manifest,
        training_repository_digests=case.holdout.training_repository_digests,
        holdout_repository_digests=case.holdout.holdout_repository_digests,
        fitting_lineage_manifest_digest=contaminated.manifest_digest,
        measurement=case.holdout.measurement,
    )
    contaminated_evidence = replace(
        contaminated_evidence,
        repository_holdout_report_digest=contaminated_holdout.report_digest,
    )
    with pytest.raises(FittedComponentAuthorizationError, match="lineage|custody"):
        _authorize(
            case,
            evidence=contaminated_evidence,
            lineage=contaminated,
            holdout=contaminated_holdout,
        )
