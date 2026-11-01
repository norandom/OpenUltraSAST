"""Evidence-backed final admission reports."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import replace
from typing import NamedTuple, TypeVar, overload

import pytest
from test_core_admission_context import _resign_manifest
from test_core_admission_metrics import _MetricRun, _MetricSetup, _release_for, _run, _setup, _with_out_of_scope_case
from test_core_readiness import _chain

from openultrasast.core import _admission_gates as admission_gates_module
from openultrasast.core import admission_context, canonical, validation
from openultrasast.core import admission_report as admission_report_module
from openultrasast.core.admission_case import (
    AdmissionCaseRelease,
    AdmissionCaseResult,
    AdmissionCaseRole,
    derive_admission_case_result_digest,
)
from openultrasast.core.admission_report import (
    AdmissionDecision,
    AdmissionReplay,
    AdmissionReportError,
    AdmissionReportV2,
    GateKind,
    GateResult,
    admission_replay_value,
    admission_report_value,
    score_admission,
    validate_admission_replay,
)
from openultrasast.core.admission_review import AdmissionThreshold, derive_threshold_set_digest
from openultrasast.core.coverage import ReasonCount
from openultrasast.core.evidence import EvidenceBasis
from openultrasast.core.measurement import Comparator, MetricId, Statistic, evaluate_metric
from openultrasast.core.measurement_factory import create_measurement_record
from openultrasast.core.readiness import ReadinessResult, ReadinessStage

_T = TypeVar("_T")


class _ScoredAdmission(NamedTuple):
    replay: AdmissionReplay
    setup: _MetricSetup
    run: _MetricRun
    cases: tuple[AdmissionCaseResult, ...]
    readiness: tuple[ReadinessResult, ...]
    release: AdmissionCaseRelease

    @property
    def report(self) -> AdmissionReportV2:
        return self.replay.report


class _SinglePassSequence(Sequence[_T]):
    def __init__(self, values: tuple[_T, ...]) -> None:
        self.values = values
        self.traversals = 0

    def __iter__(self) -> Iterator[_T]:
        self.traversals += 1
        if self.traversals > 1:
            raise AssertionError("caller-controlled sequence traversed twice")
        return iter(self.values)

    def __len__(self) -> int:
        return len(self.values)

    @overload
    def __getitem__(self, index: int) -> _T: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[_T]: ...

    def __getitem__(self, index: int | slice) -> _T | Sequence[_T]:
        return self.values[index]


def _without_models(setup: _MetricSetup) -> _MetricSetup:
    evidence = setup.context.evidence
    model_lineages = {item.lineage_manifest_digest for item in evidence.model_programs}
    model_free_evidence = validation.make_evidence_validation_context(
        family_catalog=evidence.family_catalog,
        fact_packs=evidence.fact_packs,
        model_programs=(),
        lineages=tuple(item for item in evidence.lineages if item.manifest_digest not in model_lineages),
        fact_review_policy=evidence.fact_review_policy,
        provenance_trust_policy=evidence.provenance_trust_policy,
        custody_policy=evidence.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=model_free_evidence,
        admission_review_policy=setup.context.admission_review_policy,
        proof_trust_policy=setup.context.proof_trust_policy,
    )
    identity = replace(
        setup.manifest.identity,
        model_program_digests=(),
        model_program_set_digest=None,
    )
    scope = identity.claimed_scopes[0]
    analysis = admission_context.derive_analysis_identity(identity, evidence.family_catalog, scope, None)
    readiness = _chain(identity=analysis)[:6]
    manifest = _resign_manifest(
        replace(
            setup.manifest,
            identity=identity,
            readiness_digests=tuple(sorted(item.result_digest for item in readiness)),
            validation_context_digest=context.context_digest,
        ),
        setup.manifest.review.conflict_disclosure,
    )
    return setup._replace(manifest=manifest, context=context, readiness=readiness)


def _score(
    setup: _MetricSetup,
    *,
    cases: Sequence[AdmissionCaseResult] | None = None,
    readiness: Sequence[ReadinessResult] | None = None,
) -> AdmissionReportV2:
    return _score_bundle(setup, cases=cases, readiness=readiness).report


def _score_bundle(
    setup: _MetricSetup,
    *,
    cases: Sequence[AdmissionCaseResult] | None = None,
    readiness: Sequence[ReadinessResult] | None = None,
) -> _ScoredAdmission:
    run = _run(setup)
    selected_cases = tuple(setup.cases if cases is None else cases)
    selected_readiness = tuple(setup.readiness if readiness is None else readiness)
    replay = score_admission(
        setup.manifest,
        setup.denominator,
        selected_readiness,
        run.preparation,
        run.receipt,
        run.release,
        selected_cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    return _ScoredAdmission(replay, setup, run, replay.cases, replay.readiness, run.release)


def _validate_authoritatively(replay: AdmissionReplay, scored: _ScoredAdmission) -> None:
    validate_admission_replay(
        replay,
        scored.setup.context,
        scored.setup.custody,
        scored.setup.resolver,
    )


def _rehashed(report: AdmissionReportV2, **changes: object) -> AdmissionReportV2:
    draft = object.__new__(AdmissionReportV2)
    for field in AdmissionReportV2.__dataclass_fields__:
        object.__setattr__(draft, field, changes.get(field, getattr(report, field)))
    object.__setattr__(draft, "report_digest", "0" * 64)
    digest = canonical.content_digest(admission_report_module._report_value(draft))
    object.__setattr__(draft, "report_digest", digest)
    return draft


def _rehashed_replay(replay: AdmissionReplay, **changes: object) -> AdmissionReplay:
    draft = object.__new__(AdmissionReplay)
    for field in AdmissionReplay.__dataclass_fields__:
        object.__setattr__(draft, field, changes.get(field, getattr(replay, field)))
    object.__setattr__(draft, "replay_digest", "0" * 64)
    digest = canonical.content_digest(admission_report_module._replay_value(draft))
    object.__setattr__(draft, "replay_digest", digest)
    return draft


def _mutated(value: _T, **changes: object) -> _T:
    draft = object.__new__(type(value))
    for field in value.__dataclass_fields__:  # type: ignore[attr-defined]
        object.__setattr__(draft, field, changes.get(field, getattr(value, field)))
    return draft


def _failed_quality_bundle() -> _ScoredAdmission:
    setup = _setup()
    vulnerable, fixed, ordinary = setup.cases
    vulnerable = replace(vulnerable, role=AdmissionCaseRole.FIXED, result_digest="0" * 64)
    vulnerable = replace(vulnerable, result_digest=derive_admission_case_result_digest(vulnerable))
    fixed = replace(fixed, role=AdmissionCaseRole.VULNERABLE, result_digest="0" * 64)
    fixed = replace(fixed, result_digest=derive_admission_case_result_digest(fixed))
    cases = (vulnerable, fixed, ordinary)
    run = _run(setup)
    release = _release_for(run, cases)
    replay = score_admission(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        run.preparation,
        run.receipt,
        release,
        cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    return _ScoredAdmission(replay, setup, run, replay.cases, replay.readiness, release)


def _failed_quality_report() -> AdmissionReportV2:
    return _failed_quality_bundle().report


def test_complete_admission_is_reproducible_and_bound_to_exact_evidence() -> None:
    setup = _without_models(_setup())
    run = _run(setup)

    first = score_admission(
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
    second = _score_bundle(_without_models(_setup())).replay

    assert first == second
    assert canonical.canonical_bytes(admission_replay_value(first)) == canonical.canonical_bytes(admission_replay_value(second))
    assert first.replay_digest == canonical.content_digest(admission_replay_value(first))
    report = first.report
    assert report.decision is AdmissionDecision.GO
    assert report.report_digest == canonical.content_digest(admission_report_value(report))
    assert report.census_digest == setup.manifest.census.census_digest
    assert report.validation_context_digest == setup.context.context_digest
    assert report.authorization_digest == run.preparation.authorization.authorization_digest
    assert report.label_release_receipt_digest == run.receipt.receipt_digest
    assert report.case_release_digest == run.release.release_digest
    assert report.case_result_digests == tuple(sorted(case.result_digest for case in setup.cases))
    assert tuple(item.basis for item in report.measurement.evidence_basis_counts) == tuple(EvidenceBasis)
    assert tuple(item.kind for item in report.instrument_results) == (GateKind.INSTRUMENT,)
    assert tuple(item.kind for item in report.budget_results) == (GateKind.BUDGET,)
    assert tuple(item.kind for item in report.readiness_results) == (GateKind.READINESS,)
    assert tuple(item.kind for item in report.quality_results) == (GateKind.QUALITY,)
    assert all(
        gate.passed
        for group in (
            report.instrument_results,
            report.budget_results,
            report.readiness_results,
        )
        for gate in group
    )


def test_score_snapshots_caller_sequences_once_and_records_development_readiness() -> None:
    setup = _setup()
    cases = _SinglePassSequence(setup.cases)
    readiness = _SinglePassSequence(setup.readiness)

    report = _score(setup, cases=cases, readiness=readiness)

    assert (cases.traversals, readiness.traversals) == (1, 1)
    assert tuple(item.stage for item in report.measurement.prerequisite_readiness) == tuple(ReadinessStage)[:6]


def test_score_canonicalizes_case_permutations_after_one_sequence_traversal() -> None:
    setup = _setup()
    run = _run(setup)
    cases = _SinglePassSequence(tuple(reversed(setup.cases)))

    replay = score_admission(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        run.preparation,
        run.receipt,
        run.release,
        cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    canonical_replay = _score_bundle(_setup()).replay

    assert cases.traversals == 1
    assert replay == canonical_replay
    assert replay.replay_digest == canonical_replay.replay_digest
    assert tuple(item.case_id_digest for item in replay.cases) == tuple(sorted(item.case_id_digest for item in setup.cases))


def test_contextual_validator_snapshots_caller_sequences_once() -> None:
    scored = _score_bundle(_setup())
    cases = _SinglePassSequence(scored.cases)
    readiness = _SinglePassSequence(scored.readiness)

    replay = _rehashed_replay(scored.replay, readiness=tuple(readiness), cases=tuple(cases))
    validate_admission_replay(
        replay,
        scored.setup.context,
        scored.setup.custody,
        scored.setup.resolver,
    )

    assert (cases.traversals, readiness.traversals) == (1, 1)


def test_raw_report_is_not_an_authorization_replay() -> None:
    scored = _score_bundle(_setup())

    with pytest.raises(AdmissionReportError, match="exact AdmissionReplay"):
        validate_admission_replay(  # type: ignore[arg-type]
            scored.report,
            scored.setup.context,
            scored.setup.custody,
            scored.setup.resolver,
        )


def test_rehashed_replay_cannot_substitute_readiness_order() -> None:
    scored = _score_bundle(_setup())
    forged = _rehashed_replay(scored.replay, readiness=tuple(reversed(scored.readiness)))

    with pytest.raises(AdmissionReportError, match="readiness"):
        _validate_authoritatively(forged, scored)


def test_replay_digest_mutation_is_refused_before_authoritative_replay() -> None:
    replay = _score_bundle(_setup()).replay

    with pytest.raises(AdmissionReportError, match="replay digest"):
        replace(replay, replay_digest=canonical.content_digest("forged-replay"))


def test_rehashed_replay_cannot_substitute_a_case_payload() -> None:
    scored = _score_bundle(_setup())
    original = scored.replay.cases[0]
    changed = replace(original, total_reply_ms=original.total_reply_ms + 1, result_digest="0" * 64)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    cases = tuple(sorted((changed, *scored.replay.cases[1:]), key=lambda item: item.case_id_digest))
    forged = _rehashed_replay(scored.replay, cases=cases)

    with pytest.raises(AdmissionReportError, match="case|release|binding"):
        _validate_authoritatively(forged, scored)


def test_failed_registered_quality_threshold_is_a_valid_no_go_report() -> None:
    report = _failed_quality_report()

    recall = next(item for item in report.measurement.metrics if item.metric_id is MetricId.VULNERABLE_RECALL)
    assert recall.numerator == 0
    assert report.decision is AdmissionDecision.NO_GO
    assert report.quality_results[0].passed is False
    assert "threshold_failed:vulnerable_recall:count" in report.quality_results[0].reasons


def test_validated_budget_overrun_produces_failed_gate_and_no_go() -> None:
    setup = _setup()
    run = _run(setup)
    original = setup.cases[0]
    changed = replace(original, total_reply_ms=original.budget.budget_ms + 1, result_digest="0" * 64)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    cases = tuple(sorted((changed, *setup.cases[1:]), key=lambda item: item.case_id_digest))
    release = _release_for(run, cases)

    replay = score_admission(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        run.preparation,
        run.receipt,
        release,
        cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )

    report = replay.report
    assert report.decision is AdmissionDecision.NO_GO
    assert not report.budget_results[0].passed
    assert report.budget_results[0].reasons == (f"budget_exceeded:{changed.result_digest}",)
    assert validate_admission_replay(replay, setup.context, setup.custody, setup.resolver) == report


def test_no_go_cannot_be_replaced_by_go_or_lose_a_mandatory_gate() -> None:
    report = _score(_setup())
    with pytest.raises(AdmissionReportError, match="quality gate"):
        replace(report, quality_results=(), report_digest="0" * 64)
    with pytest.raises(AdmissionReportError, match="report digest"):
        replace(report, report_digest=canonical.content_digest("forged"))


def test_configured_model_with_zero_calls_is_canonical_null_and_no_go() -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    model = next(item for item in report.measurement.metrics if item.metric_id is MetricId.MODEL_SUCCESS_RATE)

    assert (model.numerator, model.denominator, model.value) == (0, 0, None)
    assert report.decision is AdmissionDecision.NO_GO
    assert "mandatory_model_success_threshold_missing" in report.quality_results[0].reasons
    assert "mandatory_model_success_has_no_attempted_calls" in report.quality_results[0].reasons
    _validate_authoritatively(scored.replay, scored)


def test_rehashed_failed_quality_gate_cannot_be_promoted_to_go() -> None:
    scored = _failed_quality_bundle()
    report = scored.report
    forged_gate = replace(report.quality_results[0], passed=True, reasons=())
    forged = _rehashed(report, quality_results=(forged_gate,), decision=AdmissionDecision.GO)

    with pytest.raises(AdmissionReportError, match="quality gate"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


@pytest.mark.parametrize("category", ("instrument", "budget", "readiness"))
def test_rehashed_gate_evidence_substitution_is_refused(category: str) -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    field = f"{category}_results"
    gate = getattr(report, field)[0]
    forged_gate = replace(gate, evidence_digests=(canonical.content_digest(f"forged:{category}"),))
    forged = _rehashed(report, **{field: (forged_gate,)})

    with pytest.raises(AdmissionReportError, match=rf"{category} gate"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_rehashed_measurement_readiness_divergence_is_refused() -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    measurement = report.measurement
    changed_reference = replace(
        measurement.prerequisite_readiness[0],
        result_digest=canonical.content_digest("different-readiness-result"),
    )
    changed_measurement = create_measurement_record(
        identity=measurement.identity,
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
        prerequisite_readiness=(changed_reference, *measurement.prerequisite_readiness[1:]),
    )
    evaluations = tuple(_mutated(item, measurement_record_digest=changed_measurement.record_digest) for item in report.quality_evaluations)
    evaluations = tuple(
        _mutated(
            item,
            evaluation_digest=canonical.content_digest(admission_gates_module.threshold_evaluation_value(item)),
        )
        for item in evaluations
    )
    quality = admission_gates_module.quality_gate(report.identity, changed_measurement, evaluations)
    forged = _rehashed(
        report,
        measurement=changed_measurement,
        quality_evaluations=evaluations,
        quality_results=(quality,),
    )

    with pytest.raises(AdmissionReportError, match="readiness gate"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_rehashed_threshold_evaluation_mutations_are_refused() -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    evaluations = report.quality_evaluations
    changed = _mutated(evaluations[0], target=evaluations[0].target + 0.25)
    changed = _mutated(
        changed,
        evaluation_digest=canonical.content_digest(admission_gates_module.threshold_evaluation_value(changed)),
    )

    for forged_evaluations in ((), (evaluations[0], evaluations[0]), (changed,)):
        forged = _rehashed(report, quality_evaluations=forged_evaluations)
        with pytest.raises(AdmissionReportError, match="threshold|quality"):
            _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_rehashed_typed_case_budget_substitution_is_refused() -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    original = report.budget_evaluations[0]
    changed = _mutated(original, budget_derivation_digest=canonical.content_digest("forged-budget"))
    changed = _mutated(
        changed,
        evaluation_digest=canonical.content_digest(admission_gates_module.budget_evaluation_value(changed)),
    )
    forged = _rehashed(report, budget_evaluations=(changed, *report.budget_evaluations[1:]))

    with pytest.raises(AdmissionReportError, match="budget evaluation"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_contextual_validation_refuses_coordinated_threshold_rehash() -> None:
    scored = _failed_quality_bundle()
    report = scored.report
    threshold = AdmissionThreshold(MetricId.VULNERABLE_RECALL, Statistic.COUNT, Comparator.AT_LEAST, 0.0)
    threshold_digest = derive_threshold_set_digest((threshold,))
    identity = replace(
        report.identity,
        model_program_digests=(),
        model_program_set_digest=None,
        threshold_set_digest=threshold_digest,
    )
    measurement = create_measurement_record(
        identity=identity,
        family_decision_vocabulary=report.measurement.family_decision_vocabulary,
        family_decision_counts=report.measurement.family_decision_counts,
        neutral_outcome_counts=report.measurement.neutral_outcome_counts,
        evidence_basis_counts=report.measurement.evidence_basis_counts,
        metrics=report.measurement.metrics,
        stage_funnel=report.measurement.stage_funnel,
        instrument_failures=report.measurement.instrument_failures,
        model_outcome_counts=report.measurement.model_outcome_counts,
        model_failures=report.measurement.model_failures,
        runtime_ms=report.measurement.runtime_ms,
        prerequisite_readiness=report.measurement.prerequisite_readiness,
    )
    evaluations = admission_gates_module.make_threshold_evaluations((threshold,), measurement)
    quality = admission_gates_module.quality_gate(identity, measurement, evaluations)
    forged = _rehashed(
        report,
        identity=identity,
        measurement=measurement,
        quality_evaluations=evaluations,
        quality_results=(quality,),
        decision=AdmissionDecision.GO,
    )

    admission_report_module._validate_report_structure(forged)
    assert forged.authorization_digest == report.authorization_digest
    with pytest.raises(AdmissionReportError, match="authoritative admission inputs"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_contextual_validation_refuses_coordinated_readiness_rehash() -> None:
    scored = _score_bundle(_setup())
    report = scored.report
    references = tuple(
        replace(item, result_digest=canonical.content_digest(f"forged-readiness:{item.stage.value}"))
        for item in report.measurement.prerequisite_readiness
    )
    measurement = create_measurement_record(
        identity=report.identity,
        family_decision_vocabulary=report.measurement.family_decision_vocabulary,
        family_decision_counts=report.measurement.family_decision_counts,
        neutral_outcome_counts=report.measurement.neutral_outcome_counts,
        evidence_basis_counts=report.measurement.evidence_basis_counts,
        metrics=report.measurement.metrics,
        stage_funnel=report.measurement.stage_funnel,
        instrument_failures=report.measurement.instrument_failures,
        model_outcome_counts=report.measurement.model_outcome_counts,
        model_failures=report.measurement.model_failures,
        runtime_ms=report.measurement.runtime_ms,
        prerequisite_readiness=references,
    )
    thresholds = tuple(
        AdmissionThreshold(item.metric_id, item.statistic, item.comparator, item.target) for item in report.quality_evaluations
    )
    evaluations = admission_gates_module.make_threshold_evaluations(thresholds, measurement)
    quality = admission_gates_module.quality_gate(report.identity, measurement, evaluations)
    readiness = admission_gates_module.readiness_gate(references)
    forged = _rehashed(
        report,
        measurement=measurement,
        quality_evaluations=evaluations,
        quality_results=(quality,),
        readiness_results=(readiness,),
    )

    admission_report_module._validate_report_structure(forged)
    with pytest.raises(AdmissionReportError, match="authoritative admission inputs"):
        _validate_authoritatively(_rehashed_replay(scored.replay, report=forged), scored)


def test_out_of_scope_only_model_capacity_does_not_enter_claimed_scope_metric() -> None:
    setup = _with_out_of_scope_case(_setup())
    report = _score(setup)
    claimed = set(setup.manifest.identity.claimed_scopes)
    rows = tuple(replace(row, model_call_capacity=1) if row.scope not in claimed else row for row in setup.manifest.census.rows)
    changed_manifest = replace(setup.manifest, census=replace(setup.manifest.census, rows=rows))

    gate = admission_report_module._quality_gate(changed_manifest, report.measurement)
    model = next(item for item in report.measurement.metrics if item.metric_id is MetricId.MODEL_SUCCESS_RATE)

    assert (model.numerator, model.denominator) == (0, 0)
    assert not gate.passed
    assert report.decision is AdmissionDecision.NO_GO


def _model_quality_gate(
    *,
    numerator: int,
    denominator: int = 1,
    thresholds: tuple[AdmissionThreshold, ...],
) -> GateResult:
    setup = _setup()
    report = _score(setup)
    identity = replace(report.identity, threshold_set_digest=derive_threshold_set_digest(thresholds))
    rule = next(item for item in setup.denominator.rules if item.metric_id is MetricId.MODEL_SUCCESS_RATE)
    model_metric = evaluate_metric(rule, numerator=numerator, denominator=denominator)
    metrics = tuple(model_metric if item.metric_id is MetricId.MODEL_SUCCESS_RATE else item for item in report.measurement.metrics)
    model_outcomes = tuple(
        ReasonCount(name, count) for name, count in (("failure", denominator - numerator), ("success", numerator)) if count
    )
    measurement = create_measurement_record(
        identity=identity,
        family_decision_vocabulary=report.measurement.family_decision_vocabulary,
        family_decision_counts=report.measurement.family_decision_counts,
        neutral_outcome_counts=report.measurement.neutral_outcome_counts,
        evidence_basis_counts=report.measurement.evidence_basis_counts,
        metrics=metrics,
        stage_funnel=report.measurement.stage_funnel,
        instrument_failures=report.measurement.instrument_failures,
        model_outcome_counts=model_outcomes,
        model_failures=() if numerator == denominator else ("provider_timeout",),
        runtime_ms=report.measurement.runtime_ms,
        prerequisite_readiness=report.measurement.prerequisite_readiness,
    )
    evaluations = admission_gates_module.make_threshold_evaluations(thresholds, measurement)
    return admission_gates_module.quality_gate(identity, measurement, evaluations)


def test_applicable_passing_model_requires_and_passes_registered_threshold() -> None:
    base = _setup().manifest.thresholds[0]
    model = AdmissionThreshold(MetricId.MODEL_SUCCESS_RATE, Statistic.COUNT, Comparator.AT_LEAST, 1.0)
    thresholds = tuple(sorted((base, model), key=lambda item: (item.metric_id.value, item.statistic.value)))

    gate = _model_quality_gate(numerator=1, thresholds=thresholds)

    assert gate.passed


def test_applicable_failed_model_or_missing_model_threshold_cannot_go() -> None:
    base = _setup().manifest.thresholds[0]
    missing = _model_quality_gate(numerator=0, thresholds=(base,))
    model = AdmissionThreshold(MetricId.MODEL_SUCCESS_RATE, Statistic.COUNT, Comparator.AT_LEAST, 1.0)
    thresholds = tuple(sorted((base, model), key=lambda item: (item.metric_id.value, item.statistic.value)))
    failed = _model_quality_gate(numerator=0, thresholds=thresholds)

    assert not missing.passed
    assert "mandatory_model_success_threshold_missing" in missing.reasons
    assert not failed.passed
    assert "mandatory_model_call_failed" in failed.reasons


def test_any_failed_declared_model_call_forces_no_go_even_when_threshold_passes() -> None:
    base = _setup().manifest.thresholds[0]
    model = AdmissionThreshold(MetricId.MODEL_SUCCESS_RATE, Statistic.COUNT, Comparator.AT_LEAST, 1.0)
    thresholds = tuple(sorted((base, model), key=lambda item: (item.metric_id.value, item.statistic.value)))

    gate = _model_quality_gate(numerator=1, denominator=2, thresholds=thresholds)

    assert not gate.passed
    assert "mandatory_model_call_failed" in gate.reasons
