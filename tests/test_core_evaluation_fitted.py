"""Fitted components authorize only from one exact completed V3 scope."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
import test_core_evaluation_authority as authority_fixtures
from detection_core_fixtures import InMemoryContentResolver, stored_artifact
from test_core_admission_fitted import _fitted_case, _population_manifest
from test_core_evaluation_case_validation import (
    _bundle,
    _review_plan_draft,
    _reviewed_scoped_census,
    _scoped_authority_case,
    _scoped_configurations,
)
from test_core_evaluation_plan import _digest
from test_core_evaluation_replay import _assemble, _inputs
from test_core_evaluation_replay_validation import _case as _no_go_replay_case
from test_core_probes import _review

from openultrasast.core import admission_context, canonical, custody, model, probes, validation
from openultrasast.core.admission_fitted import FittedComponentEvidence
from openultrasast.core.evaluation_measurement import ArmScopeKey, Comparator, ScopeKey
from openultrasast.core.evaluation_plan import create_evaluation_plan_declaration, derive_evaluation_baselines
from openultrasast.core.evaluation_report import AdmissionDecision
from openultrasast.core.family_catalog import FamilyCatalog, derive_catalog_digest, resolve_contract
from openultrasast.core.lineage import LineageManifest, LineageUse, derive_lineage_manifest_digest
from openultrasast.core.measurement import derive_identity_set_digest
from openultrasast.core.measurement_factory import create_measurement_record, create_repository_holdout_report


@dataclass(frozen=True)
class FittedV3Case:
    evidence: FittedComponentEvidence
    probe_inputs: tuple[probes.ProbeEvaluationInput, ...]
    fitting_lineage: LineageManifest
    holdout: object
    replay: object
    key: ArmScopeKey
    context: admission_context.AdmissionValidationContext
    port: object
    resolver: InMemoryContentResolver


def _merge(*resolvers: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for resolver in resolvers:
        artifacts.update(resolver.artifacts)
    return InMemoryContentResolver(artifacts)


def _unchecked(value, **changes):
    result = object.__new__(type(value))
    for field, current in vars(value).items():
        object.__setattr__(result, field, changes.get(field, current))
    return result


def _injected(value):
    result = _unchecked(value)
    object.__setattr__(result, "unexpected", "field")
    return result


def _fitted_program(context_case, training_ref):
    component = _digest("fitted-v3-component")
    arm_id = "fitted-v3-arm"
    artifacts = (
        (custody.LineagePurpose.PROMPT, _digest("fitted-v3-prompt")),
        (custody.LineagePurpose.EXAMPLE, _digest("fitted-v3-examples")),
        (custody.LineagePurpose.FITTED_MODEL, component),
        (custody.LineagePurpose.DECISION_MAPPING, _digest("fitted-v3-mapping")),
    )
    population = context_case.context.evidence.lineages[0].uses[0].source_population_digest
    source = context_case.port.current_log(population)
    context_case.port.logs[training_ref.content_digest] = custody.empty_population_custody_log(
        training_ref.content_digest, source.custodian_identity
    )
    uses = []
    for purpose, artifact in artifacts:
        current = context_case.port.current_log(training_ref.content_digest)
        request = custody.PopulationUseRequest(training_ref.content_digest, arm_id, purpose, False, artifact, current.log_digest)
        receipt = context_case.port.append(request, current.custodian_identity)
        uses.append(LineageUse(purpose, training_ref.content_digest, False, artifact, receipt.receipt_digest))
    bundle_digest = _digest("fitted-v3-input-bundle")
    lineage = LineageManifest(
        arm_id,
        bundle_digest,
        tuple(uses),
        derive_lineage_manifest_digest(arm_id, bundle_digest, tuple(uses)),
    )
    contract_digest = next(
        item.contract_digest
        for item in context_case.context.evidence.family_catalog.entries
        if item.contract.family_id == "reference-family"
    )
    program = model.make_model_program_declaration(
        family_contract_digest=contract_digest,
        provider="provider",
        model_name="fitted-v3-model",
        program_digest=_digest("fitted-v3-program"),
        prompt_digest=artifacts[0][1],
        example_set_digest=artifacts[1][1],
        fitted_component_digest=component,
        configuration_digest=_digest("fitted-v3-configuration"),
        adapter_revision="fitted-v3-adapter",
        decision_mapping_digest=artifacts[3][1],
        input_bundle_digest=bundle_digest,
        lineage_manifest_digest=lineage.manifest_digest,
    )
    return program, lineage


def _with_program(context_case, program, lineage):
    old = context_case.context.evidence
    evidence = validation.make_evidence_validation_context(
        family_catalog=old.family_catalog,
        fact_packs=old.fact_packs,
        model_programs=tuple(sorted((*old.model_programs, program), key=lambda item: item.declaration_digest)),
        lineages=tuple(sorted((*old.lineages, lineage), key=lambda item: item.manifest_digest)),
        fact_review_policy=old.fact_review_policy,
        provenance_trust_policy=old.provenance_trust_policy,
        custody_policy=old.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=evidence,
        admission_review_policy=context_case.context.admission_review_policy,
        proof_trust_policy=context_case.context.proof_trust_policy,
    )
    return replace(context_case, context=context)


def _permissive_plan(plan, scopes, configuration_digest):
    configurations = []
    scoped = _scoped_configurations(plan, scopes, 1, 1, True)
    for configuration in scoped:
        thresholds = tuple(
            replace(
                threshold,
                target=0.0 if threshold.comparator is Comparator.AT_LEAST else 100.0,
                threshold_digest="",
            )
            for threshold in configuration.thresholds
        )
        configurations.append(
            replace(
                configuration,
                thresholds=thresholds,
                configuration_digest=(configuration_digest if configuration.arm_id == "arm-a" else configuration.configuration_digest),
                configuration_identity_digest="",
            )
        )
    inputs = tuple(sorted({slot.input_identity_digest for slot in plan.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=plan.declaration.population_digest,
        freeze_digest=plan.declaration.freeze_digest,
        input_set_digest=plan.declaration.input_set_digest,
        arm_configurations=tuple(configurations),
        input_identity_digests=inputs,
    )
    draft = replace(
        plan,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        census=_reviewed_scoped_census(plan, scopes, ordinary_count=1, whole_count=3, scope_counts=(1, 1, 1, 6, 3)),
        payload_digest="0" * 64,
        manifest_digest="0" * 64,
    )
    return _review_plan_draft(draft, plan.review)


def _probe(bundle, program):
    supplied = bundle[2][0].cases[0].evidence_inputs[0]
    record = supplied.record
    contract = resolve_contract(
        bundle[5][0].context.evidence.family_catalog,
        record.packet.family_id,
        program.family_contract_digest,
        record.packet.ecosystem,
    )
    forward, forward_resolver = stored_artifact(b"- old\n+ new\n", artifact_id="fitted-v3-forward")
    reversed_ref, reversed_resolver = stored_artifact(b"+ old\n- new\n", artifact_id="fitted-v3-reversed")
    disclosure, disclosure_resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="fitted-v3-disclosure")
    projection = probes.project_semantics(record, contract)
    reviewer = bundle[5][0].context.evidence.fact_review_policy.reviewed_reviewer_digests[0]
    review = _review(
        projection,
        projection,
        contract,
        forward,
        reversed_ref,
        disclosure,
        producer=_digest("fitted-v3-probe-producer"),
        reviewer=reviewer,
    )
    probe = probes.ReversedPairProbe("", program.family_contract_digest, record, record, forward, reversed_ref, review, 0.05)
    observation = probes.ProbeObservation(probe.probe_id, program.fitted_component_digest, "unsafe", "unsafe", 0.50, 0.52)
    item = probes.ProbeEvaluationInput(probe, observation)
    return item, _merge(forward_resolver, reversed_resolver, disclosure_resolver)


def _holdout(v2_case, program, lineage, training_ref, training_resolver, context):
    holdout_repositories = (_digest("fitted-v3-holdout-repository"),)
    holdout_ref, holdout_resolver = _population_manifest(holdout_repositories, "fitted-v3-holdout-population")
    measurement = v2_case.holdout.measurement
    entry = next(item for item in context.evidence.family_catalog.entries if item.contract_digest == program.family_contract_digest)
    selected = FamilyCatalog((entry,), derive_catalog_digest((entry,)))
    identity = replace(
        measurement.identity,
        population_digest=holdout_ref.content_digest,
        claimed_scopes=tuple(
            replace(scope, family_id="reference-family", ecosystem="python") for scope in measurement.identity.claimed_scopes
        ),
        family_contract_digests=(program.family_contract_digest,),
        family_contract_set_digest=selected.catalog_digest,
        model_program_digests=(program.fitted_component_digest,),
        model_program_set_digest=derive_identity_set_digest("model_program", (program.fitted_component_digest,)),
        outcome_mapping_digest=admission_context.derive_outcome_mapping_digest(selected),
    )
    measured = create_measurement_record(
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
    training_repositories = (_digest("fitted-v3-training-repository"),)
    holdout = create_repository_holdout_report(
        component_digest=program.fitted_component_digest,
        role=v2_case.holdout.role,
        training_population_manifest=training_ref,
        holdout_population_manifest=holdout_ref,
        training_repository_digests=training_repositories,
        holdout_repository_digests=holdout_repositories,
        fitting_lineage_manifest_digest=lineage.manifest_digest,
        measurement=measured,
    )
    return holdout, _merge(training_resolver, holdout_resolver)


@pytest.fixture(scope="module")
def fitted_v3_case() -> FittedV3Case:
    training_repositories = (_digest("fitted-v3-training-repository"),)
    training_ref, training_resolver = _population_manifest(training_repositories, "fitted-v3-training-population")
    scope = ScopeKey("reference-family", "python")
    scopes = {"arm-a": scope, "arm-b": scope, "arm-combined": scope}
    base = _scoped_authority_case(
        scopes,
        ordinary_count=1,
        whole_count=3,
        scope_counts=(1, 1, 1, 6, 3),
        minimum_pairs=1,
        minimum_ordinary_pushes=1,
        relaxed_precision=True,
    )
    program, program_lineage = _fitted_program(base[0], training_ref)
    context_case = _with_program(base[0], program, program_lineage)
    plan = _permissive_plan(base[1].plan_manifest, scopes, program.configuration_digest)
    original = authority_fixtures._reviewed_plan
    authority_fixtures._reviewed_plan = lambda: (context_case, plan, base[3])
    try:
        authority_case = authority_fixtures._authority_case()
    finally:
        authority_fixtures._reviewed_plan = original
    bundle = _bundle(
        authority_case=authority_case,
        aligned_combination_cases=True,
        shared_underlying_by_ecosystem=True,
        model_evidence=True,
    )
    replay = _assemble(*_inputs(bundle=bundle, canonical_sources=True))
    selected = next(item for item in replay.reports if item.baseline.arm_id == "arm-a")
    key = ArmScopeKey("arm-a", scope)
    assert next(item for item in selected.scoped_results if item.key == key).decision is AdmissionDecision.GO
    probe_input, probe_resolver = _probe(bundle, program)
    probe_result = probes.evaluate_probe(
        probe_input.probe,
        probe_input.observation,
        resolve_contract(
            bundle[5][0].context.evidence.family_catalog,
            scope.family_id,
            program.family_contract_digest,
            scope.ecosystem,
        ),
        bundle[5][0].context.evidence.fact_review_policy,
        probe_resolver,
    )
    fitted_use = next(item for item in program_lineage.uses if item.purpose is custody.LineagePurpose.FITTED_MODEL)
    fitting_lineage = LineageManifest(
        program_lineage.arm_id,
        program.fitted_component_digest,
        (fitted_use,),
        derive_lineage_manifest_digest(program_lineage.arm_id, program.fitted_component_digest, (fitted_use,)),
    )
    holdout, holdout_resolver = _holdout(_fitted_case(), program, fitting_lineage, training_ref, training_resolver, bundle[5][0].context)
    evidence = FittedComponentEvidence(
        program.fitted_component_digest,
        (probe_result.result_digest,),
        fitting_lineage.manifest_digest,
        training_ref,
        training_repositories,
        holdout.report_digest,
        selected.report_digest,
    )
    resolver = _merge(bundle[4], probe_resolver, holdout_resolver)
    return FittedV3Case(
        evidence,
        (probe_input,),
        fitting_lineage,
        holdout,
        replay,
        key,
        bundle[5][0].context,
        bundle[5][0].port,
        resolver,
    )


def _authorize(case: FittedV3Case, **changes) -> None:
    from openultrasast.core.evaluation_fitted import authorize_fitted_component_v3

    values = {
        "evidence": case.evidence,
        "probe_inputs": case.probe_inputs,
        "fitting_lineage": case.fitting_lineage,
        "repository_holdout": case.holdout,
        "replay": case.replay,
        "key": case.key,
        "context": case.context,
        "custody": case.port,
        "resolver": case.resolver,
    }
    values.update(changes)
    authorize_fitted_component_v3(**values)


def test_matching_fitted_component_authorizes_only_from_exact_go_scope(fitted_v3_case: FittedV3Case) -> None:
    _authorize(fitted_v3_case)


def test_completed_no_go_scope_cannot_authorize(fitted_v3_case: FittedV3Case) -> None:
    replay, context, port, resolver = _no_go_replay_case()
    report = replay.reports[0]
    key = report.scoped_results[0].key

    with pytest.raises(Exception, match="GO|go|scope"):
        _authorize(
            fitted_v3_case,
            replay=replay,
            key=key,
            evidence=replace(fitted_v3_case.evidence, admission_report_digest=report.report_digest),
            context=context,
            custody=port,
            resolver=resolver,
        )


@pytest.mark.parametrize("partial", ("report", "aggregate", "v2"))
def test_partial_or_v2_admission_artifact_cannot_authorize(fitted_v3_case: FittedV3Case, partial: str) -> None:
    if partial == "report":
        replay = fitted_v3_case.replay.reports[0]
    elif partial == "aggregate":
        replay = fitted_v3_case.replay.aggregate
    else:
        replay = _fitted_case().replay

    with pytest.raises(Exception, match="replay|V3|exact|authorization"):
        _authorize(fitted_v3_case, replay=replay)


def test_cross_arm_key_cannot_borrow_a_go_report(fitted_v3_case: FittedV3Case) -> None:
    key = ArmScopeKey("arm-b", fitted_v3_case.key.scope)

    with pytest.raises(Exception, match="GO|go|scope|report"):
        _authorize(fitted_v3_case, key=key)


def test_missing_scope_and_incomplete_replay_fail_before_fitted_authorization(fitted_v3_case: FittedV3Case) -> None:
    missing = ArmScopeKey("arm-a", ScopeKey("reference-family", "javascript"))
    with pytest.raises(Exception, match="scope|planned"):
        _authorize(fitted_v3_case, key=missing)

    incomplete = _unchecked(fitted_v3_case.replay, reports=fitted_v3_case.replay.reports[:-1])
    with pytest.raises(Exception, match="replay|report|complete"):
        _authorize(fitted_v3_case, replay=incomplete)


def test_substituted_fitted_evidence_and_lineage_fail_closed(fitted_v3_case: FittedV3Case) -> None:
    evidence = replace(fitted_v3_case.evidence, component_digest=_digest("substituted-fitted-evidence"))
    with pytest.raises(Exception, match="component|model declaration"):
        _authorize(fitted_v3_case, evidence=evidence)

    lineage = _unchecked(fitted_v3_case.fitting_lineage, subject_digest=_digest("substituted-lineage"))
    with pytest.raises(Exception, match="lineage|projection"):
        _authorize(fitted_v3_case, fitting_lineage=lineage)


def test_closed_boundary_refuses_injected_evidence_field(fitted_v3_case: FittedV3Case) -> None:
    evidence = _unchecked(fitted_v3_case.evidence)
    object.__setattr__(evidence, "unexpected", "field")
    with pytest.raises(Exception, match="declared fields"):
        _authorize(fitted_v3_case, evidence=evidence)


def test_substituted_probe_and_holdout_evidence_fail_closed(fitted_v3_case: FittedV3Case) -> None:
    observation = replace(fitted_v3_case.probe_inputs[0].observation, component_digest=_digest("substituted-component"))
    probe_inputs = (replace(fitted_v3_case.probe_inputs[0], observation=observation),)
    with pytest.raises(Exception, match="probe|component"):
        _authorize(fitted_v3_case, probe_inputs=probe_inputs)

    holdout = _unchecked(
        fitted_v3_case.holdout,
        holdout_repository_digests=(_digest("substituted-holdout"),),
    )
    with pytest.raises(Exception, match="holdout|report|digest|repository"):
        _authorize(fitted_v3_case, repository_holdout=holdout)


def test_fitted_v3_boundary_refuses_subclassed_key(fitted_v3_case: FittedV3Case) -> None:
    class KeySubclass(ArmScopeKey):
        pass

    key = object.__new__(KeySubclass)
    object.__setattr__(key, "arm_id", fitted_v3_case.key.arm_id)
    object.__setattr__(key, "scope", fitted_v3_case.key.scope)
    with pytest.raises(Exception, match="exact|key"):
        _authorize(fitted_v3_case, key=key)


def test_recursive_boundary_refuses_injected_training_content_ref(fitted_v3_case: FittedV3Case) -> None:
    evidence = _unchecked(
        fitted_v3_case.evidence,
        training_population_manifest=_injected(fitted_v3_case.evidence.training_population_manifest),
    )
    with pytest.raises(Exception, match=r"fitted evidence\.training_population_manifest.*declared fields"):
        _authorize(fitted_v3_case, evidence=evidence)


@pytest.mark.parametrize("nested", ("packet_provenance", "model_identity", "equivalence", "attestation"))
def test_recursive_boundary_refuses_injected_probe_graph(fitted_v3_case: FittedV3Case, nested: str) -> None:
    item = fitted_v3_case.probe_inputs[0]
    probe = item.probe
    if nested == "packet_provenance":
        packet = _unchecked(probe.forward_record.packet, provenance=_injected(probe.forward_record.packet.provenance))
        record = _unchecked(probe.forward_record, packet=packet)
        probe = _unchecked(probe, forward_record=record)
    elif nested == "model_identity":
        decision_provenance = probe.forward_record.decision.provenance
        changed = _unchecked(decision_provenance, model_identity=_injected(decision_provenance.model_identity))
        decision = _unchecked(probe.forward_record.decision, provenance=changed)
        record = _unchecked(probe.forward_record, decision=decision)
        probe = _unchecked(probe, forward_record=record)
    elif nested == "equivalence":
        probe = _unchecked(probe, equivalence=_injected(probe.equivalence))
    else:
        equivalence = _unchecked(probe.equivalence, independence=_injected(probe.equivalence.independence))
        probe = _unchecked(probe, equivalence=equivalence)
    changed_input = _unchecked(item, probe=probe)

    with pytest.raises(Exception, match=r"probe inputs\[0\].*declared fields"):
        _authorize(fitted_v3_case, probe_inputs=(changed_input,))


@pytest.mark.parametrize("nested", ("identity", "funnel"))
def test_recursive_boundary_refuses_injected_holdout_measurement_graph(fitted_v3_case: FittedV3Case, nested: str) -> None:
    measurement = fitted_v3_case.holdout.measurement
    if nested == "identity":
        measurement = _unchecked(measurement, identity=_injected(measurement.identity))
    else:
        measurement = _unchecked(measurement, stage_funnel=_injected(measurement.stage_funnel))
    holdout = _unchecked(fitted_v3_case.holdout, measurement=measurement)

    with pytest.raises(Exception, match=r"repository holdout\.measurement.*declared fields"):
        _authorize(fitted_v3_case, repository_holdout=holdout)


def test_recursive_boundary_refuses_injected_lineage_use(fitted_v3_case: FittedV3Case) -> None:
    lineage = _unchecked(fitted_v3_case.fitting_lineage, uses=(_injected(fitted_v3_case.fitting_lineage.uses[0]),))
    with pytest.raises(Exception, match=r"fitting lineage\.uses\[0\].*declared fields"):
        _authorize(fitted_v3_case, fitting_lineage=lineage)
