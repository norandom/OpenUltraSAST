"""Canonical admission cases derive scoped metrics without runner aggregates."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import replace
from typing import NamedTuple, TypeVar

import pytest
from detection_core_fixtures import InMemoryContentResolver
from test_core_admission_context import AdmissionCase, MultiPopulationCustody, _attestation, _resign_manifest
from test_core_admission_release import _binding, _resign_release
from test_core_admission_spend import _feasible_case, _prepare, _spend
from test_core_consumer_v2 import _proof, _request
from test_core_model import _record as model_record
from test_core_readiness import _chain
from test_core_validation_v2 import _named_inputs, _with_fact_set

from openultrasast.core import admission_context, canonical, provenance, validation
from openultrasast.core.admission_case import ADMISSION_CASE_RELEASE_SCHEMA, AdmissionCaseRelease
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_metrics import (
    AdmissionCaseResult,
    AdmissionCaseRole,
    AdmissionMetricsError,
    create_admission_case_result,
    derive_admission_case_result_digest,
    derive_admission_metrics,
    derive_scoped_pair_key,
)
from openultrasast.core.admission_review import (
    AdmissionManifestV2,
    PopulationCensus,
    ScopeCensus,
    derive_census_digest,
    derive_census_payload_digest,
)
from openultrasast.core.admission_spend import AdmissionPreparation
from openultrasast.core.coverage import (
    CoverageFunnel,
    InputManifest,
    InputReadReceipt,
    RelationStatusCount,
    derive_input_manifest_digest,
)
from openultrasast.core.custody import PopulationUseReceipt
from openultrasast.core.evidence import EvidenceBasis, EvidenceRecord, NeutralOutcome, derive_packet_digest
from openultrasast.core.family import FamilyContract, family_contract_digest
from openultrasast.core.family_catalog import FamilyCatalog, FamilyCatalogEntry, catalog_entry_key, derive_catalog_digest
from openultrasast.core.measurement import DenominatorPolicy, IntervalMethod, MetricId, ScopeKey, standard_metric_rules
from openultrasast.core.readiness import ReadinessResult
from openultrasast.core.semantics import RelationStatus
from openultrasast.core.verdict_v2 import derive_verdict_outputs


class _InputManifestSubclass(InputManifest):
    pass


_T = TypeVar("_T")


class _TwoPassSequence(Sequence[_T]):
    def __init__(self, first: tuple[_T, ...], second: tuple[_T, ...]) -> None:
        self.first = first
        self.second = second
        self.traversals = 0

    def __iter__(self) -> Iterator[_T]:
        self.traversals += 1
        return iter(self.first if self.traversals == 1 else self.second)

    def __len__(self) -> int:
        return len(self.first)

    def __getitem__(self, index: int | slice) -> _T | tuple[_T, ...]:
        return self.first[index]


class _MetricSetup(NamedTuple):
    manifest: AdmissionManifestV2
    denominator: DenominatorPolicy
    cases: tuple[AdmissionCaseResult, ...]
    context: AdmissionValidationContext
    custody: MultiPopulationCustody
    resolver: InMemoryContentResolver
    readiness: tuple[ReadinessResult, ...]


class _MetricRun(NamedTuple):
    setup: _MetricSetup
    preparation: AdmissionPreparation
    receipt: PopulationUseReceipt
    release: AdmissionCaseRelease


def _run(setup: _MetricSetup) -> _MetricRun:
    admission = AdmissionCase(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    preparation = _prepare(admission)
    receipt = _spend(admission, preparation)
    bindings = tuple(sorted((_binding(case) for case in setup.cases), key=lambda item: item.case_id_digest))
    draft = AdmissionCaseRelease(
        ADMISSION_CASE_RELEASE_SCHEMA,
        setup.manifest.identity.population_digest,
        setup.manifest.manifest_digest,
        preparation.authorization.authorization_digest,
        preparation.preparation_digest,
        receipt.receipt_digest,
        receipt.custodian_identity,
        bindings,
        "0" * 64,
        setup.manifest.review,
        "0" * 64,
    )
    release = _resign_release(draft, admission, receipt)
    return _MetricRun(setup, preparation, receipt, release)


def _derive(
    run: _MetricRun,
    *,
    cases: tuple[AdmissionCaseResult, ...] | None = None,
    release: AdmissionCaseRelease | None = None,
) -> object:
    setup = run.setup
    selected_cases = setup.cases if cases is None else cases
    selected_release = run.release if release is None else release
    return derive_admission_metrics(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        run.preparation,
        run.receipt,
        selected_release,
        selected_cases,
        setup.context,
        setup.custody,
        setup.resolver,
    )


def _release_for(run: _MetricRun, cases: tuple[AdmissionCaseResult, ...]) -> AdmissionCaseRelease:
    setup = run.setup
    bindings = tuple(sorted((_binding(case) for case in cases), key=lambda item: item.case_id_digest))
    draft = replace(run.release, bindings=bindings, release_payload_digest="0" * 64, release_digest="0" * 64)
    admission = AdmissionCase(
        setup.manifest,
        setup.denominator,
        setup.readiness,
        setup.context,
        setup.custody,
        setup.resolver,
    )
    return _resign_release(draft, admission, run.receipt)


def _resolver(*values: InMemoryContentResolver) -> InMemoryContentResolver:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    for value in values:
        artifacts.update(value.artifacts)
    return InMemoryContentResolver(artifacts)


def _rename_named_inputs(
    named: provenance.NamedInputs,
    resolver: InMemoryContentResolver,
    prefix: str,
) -> tuple[provenance.NamedInputs, InMemoryContentResolver]:
    artifacts: dict[str, canonical.ResolvedContent] = {}
    items: list[provenance.NamedInput] = []
    for item in named.inputs:
        artifact_id = f"{prefix}-{item.content.artifact_id}"
        reference = replace(item.content, artifact_id=artifact_id)
        artifacts[artifact_id] = resolver.artifacts[item.content.artifact_id]
        items.append(replace(item, content=reference))
    values = tuple(items)
    return provenance.NamedInputs(values, provenance.derive_named_inputs_digest(values)), InMemoryContentResolver(artifacts)


def _coverage(*, violation: bool) -> CoverageFunnel:
    return CoverageFunnel(
        1,
        1,
        2,
        2,
        1,
        1,
        1,
        1,
        int(violation),
        (
            RelationStatusCount(RelationStatus.COMPLETE, 1),
            RelationStatusCount(RelationStatus.INCOMPLETE, 0),
            RelationStatusCount(RelationStatus.UNRESOLVED, 0),
        ),
        (),
    )


def _instrument(name: str) -> tuple[InputManifest, tuple[InputReadReceipt, ...]]:
    manifest = InputManifest((name,), derive_input_manifest_digest((name,)))
    receipt = InputReadReceipt(name, f"/{name}.py", True, 10, canonical.content_digest(name))
    return manifest, (receipt,)


def _case_result(
    value: validation.EvidenceValidationInput,
    role: AdmissionCaseRole,
    pair: str | None,
    resolver: InMemoryContentResolver,
    contract: FamilyContract,
) -> tuple[AdmissionCaseResult, InMemoryContentResolver]:
    request, combined = _request(value, resolver)
    coverage = _coverage(violation=value.record.decision.outcome is NeutralOutcome.VIOLATION)
    outputs = derive_verdict_outputs((value.record,), contract, canonical.content_digest("case-coverage"))
    manifest, receipts = _instrument(role.value + (pair or ""))
    result = create_admission_case_result(
        case_id_digest=canonical.content_digest(role.value + (pair or "ordinary")),
        scope=ScopeKey(value.record.packet.family_id, value.record.packet.ecosystem),
        role=role,
        pair_id_digest=pair,
        evidence_inputs=(value,),
        defect_claims=outputs.defects,
        satisfactions=outputs.satisfactions,
        silence=outputs.silence,
        proof_attachments=(),
        coverage=coverage,
        input_manifest=manifest,
        input_receipts=receipts,
        complexity=request.complexity,
        budget=request.budget,
        total_reply_ms=10,
    )
    return result, combined


def _resign_census(census: PopulationCensus, row: ScopeCensus, population_digest: str) -> PopulationCensus:
    return _resign_census_rows(census, (row,), population_digest)


def _resign_census_rows(
    census: PopulationCensus,
    rows: tuple[ScopeCensus, ...],
    population_digest: str,
) -> PopulationCensus:
    changed = replace(
        census,
        population_digest=population_digest,
        rows=rows,
        census_payload_digest="0" * 64,
        census_digest="0" * 64,
    )
    payload = derive_census_payload_digest(changed)
    old = census.review
    review = _attestation(payload, old.producer_identity, old.reviewer_identity, old.conflict_disclosure)
    changed = replace(changed, census_payload_digest=payload, review=review)
    return replace(changed, census_digest=derive_census_digest(changed))


def _setup() -> _MetricSetup:
    admission = _feasible_case()
    contract = admission.context.evidence.family_catalog.entries[0].contract
    vulnerable_record = _with_fact_set(model_record(contract), ())
    vulnerable_named, vulnerable_resolver = _named_inputs(vulnerable_record, contract, ())
    vulnerable = validation.make_evidence_validation_input(record=vulnerable_record, named_inputs=vulnerable_named)
    safe_decision = replace(vulnerable_record.decision, family_code="safe", outcome=NeutralOutcome.SATISFIED)
    safe_record = EvidenceRecord(vulnerable_record.packet, safe_decision, "")
    safe_named, safe_resolver = _named_inputs(safe_record, contract, ())
    safe = validation.make_evidence_validation_input(record=safe_record, named_inputs=safe_named)
    ordinary_region = replace(safe_record.packet.scope.regions[0], end_line=19)
    ordinary_scope = replace(safe_record.packet.scope, regions=(ordinary_region,))
    ordinary_packet = replace(safe_record.packet, scope=ordinary_scope)
    ordinary_decision = replace(
        safe_record.decision,
        bounded_scope=ordinary_scope,
        packet_digest=derive_packet_digest(ordinary_packet),
    )
    ordinary_record = EvidenceRecord(ordinary_packet, ordinary_decision, "")
    ordinary_named, ordinary_resolver = _named_inputs(ordinary_record, contract, ())
    ordinary = validation.make_evidence_validation_input(record=ordinary_record, named_inputs=ordinary_named)
    resolver = _resolver(admission.resolver, vulnerable_resolver, safe_resolver, ordinary_resolver)

    pair = canonical.content_digest("pair-1")
    vulnerable_case, resolver = _case_result(vulnerable, AdmissionCaseRole.VULNERABLE, pair, resolver, contract)
    fixed_case, resolver = _case_result(safe, AdmissionCaseRole.FIXED, pair, resolver, contract)
    ordinary_case, resolver = _case_result(ordinary, AdmissionCaseRole.ORDINARY, None, resolver, contract)

    scope = vulnerable_case.scope
    policy = DenominatorPolicy(standard_metric_rules((scope,)), IntervalMethod.WILSON_95, "")
    row = ScopeCensus(scope, 3, 1, 1, 1, 1, 6, 0)
    cases = (vulnerable_case, fixed_case, ordinary_case)
    population_digest = admission.manifest.census.population_digest
    census = _resign_census(admission.manifest.census, row, population_digest)
    identity = replace(admission.manifest.identity, population_digest=population_digest)
    manifest = _resign_manifest(
        replace(admission.manifest, identity=identity, census=census),
        census.review.conflict_disclosure,
    )
    return _MetricSetup(manifest, policy, cases, admission.context, admission.port, resolver, admission.readiness)


def test_metrics_are_derived_from_validated_cases_and_reviewed_counts() -> None:
    run = _run(_setup())

    result = _derive(run)

    by_metric = {item.metric_id: item for item in result.metrics}
    assert (result.in_scope_case_count, result.whole_population_case_count) == (3, 3)
    assert by_metric[MetricId.PAIRED_CORRECTNESS].numerator == 1
    assert by_metric[MetricId.VULNERABLE_RECALL].numerator == 1
    assert by_metric[MetricId.FIXED_FALSE_ALARM_RATE].numerator == 0
    assert by_metric[MetricId.ORDINARY_FALSE_ALARMS_PER_100].value == 0.0
    assert by_metric[MetricId.PRECISION].value == 1.0
    assert by_metric[MetricId.SEMANTIC_STAGE_COVERAGE].numerator == 6
    assert by_metric[MetricId.MODEL_SUCCESS_RATE].value is None
    assert result.family_decision_vocabulary == ("unsafe", "safe")
    assert tuple((item.reason, item.count) for item in result.family_decision_counts) == (("unsafe", 1), ("safe", 2))
    assert result.neutral_outcome_counts[0].count == 1
    assert result.evidence_basis_counts[tuple(EvidenceBasis).index(EvidenceBasis.DETERMINISTIC)].count == 1


def test_caller_case_sequence_is_snapshotted_before_release_validation() -> None:
    run = _run(_setup())
    original = run.setup.cases
    substituted = replace(original[0], total_reply_ms=original[0].total_reply_ms + 1)
    substituted = replace(substituted, result_digest=derive_admission_case_result_digest(substituted))
    switching = _TwoPassSequence(original, (substituted, *original[1:]))

    result = derive_admission_metrics(
        run.setup.manifest,
        run.setup.denominator,
        run.setup.readiness,
        run.preparation,
        run.receipt,
        run.release,
        switching,
        run.setup.context,
        run.setup.custody,
        run.setup.resolver,
    )

    assert switching.traversals == 1
    assert result.runtime_ms == sum(item.total_reply_ms for item in original)
    assert result.case_result_digests == tuple(sorted(item.result_digest for item in original))


def test_caller_readiness_sequence_is_snapshotted_once() -> None:
    run = _run(_setup())
    switching = _TwoPassSequence(run.setup.readiness, run.setup.readiness[:-1])

    result = derive_admission_metrics(
        run.setup.manifest,
        run.setup.denominator,
        switching,
        run.preparation,
        run.receipt,
        run.release,
        run.setup.cases,
        run.setup.context,
        run.setup.custody,
        run.setup.resolver,
    )

    assert switching.traversals == 1
    assert result.in_scope_case_count == len(run.setup.cases)


def test_case_count_and_pair_drift_fail_before_metric_production() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    with pytest.raises(AdmissionMetricsError, match="release|binding|case population"):
        _derive(run, cases=cases[:-1])

    run = _run(_setup())
    cases = run.setup.cases
    changed = replace(cases[0], pair_id_digest=None)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    with pytest.raises(AdmissionMetricsError, match="release|binding|pair"):
        _derive(run, cases=(changed, *cases[1:]))


def test_supplied_verdict_and_instrument_are_not_trusted() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    forged = replace(cases[0], defect_claims=())
    forged = replace(forged, result_digest=derive_admission_case_result_digest(forged))
    forged_cases = (forged, *cases[1:])
    with pytest.raises(AdmissionMetricsError, match="verdict"):
        _derive(run, cases=forged_cases, release=_release_for(run, forged_cases))

    run = _run(_setup())
    cases = run.setup.cases
    unread = replace(cases[0].input_receipts[0], opened=False)
    broken = replace(cases[0], input_receipts=(unread,))
    broken = replace(broken, result_digest=derive_admission_case_result_digest(broken))
    broken_cases = (broken, *cases[1:])
    with pytest.raises(AdmissionMetricsError, match="instrument|tracked input"):
        _derive(run, cases=broken_cases, release=_release_for(run, broken_cases))


def test_forged_evidence_and_budget_fail_before_metric_production() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    forged_input = replace(cases[0].evidence_inputs[0], input_digest="0" * 64)
    forged = replace(cases[0], evidence_inputs=(forged_input,))
    forged = replace(forged, result_digest=derive_admission_case_result_digest(forged))
    forged_cases = (forged, *cases[1:])
    with pytest.raises(AdmissionMetricsError, match="evidence"):
        _derive(run, cases=forged_cases, release=_release_for(run, forged_cases))

    run = _run(_setup())
    cases = run.setup.cases
    over_budget = replace(cases[0], total_reply_ms=cases[0].budget.budget_ms + 1)
    over_budget = replace(over_budget, result_digest=derive_admission_case_result_digest(over_budget))
    budget_cases = (over_budget, *cases[1:])
    with pytest.raises(AdmissionMetricsError, match="budget"):
        _derive(run, cases=budget_cases, release=_release_for(run, budget_cases))


def test_runner_case_digest_is_rederived() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    forged = replace(cases[0], result_digest="0" * 64)
    with pytest.raises(AdmissionMetricsError, match="case result digest"):
        _derive(run, cases=(forged, *cases[1:]))


def test_proof_attachments_are_revalidated_with_the_context_policy() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    attachment, _, proof_resolver = _proof(cases[0].evidence_inputs[0].record)
    changed = replace(cases[0], proof_attachments=(attachment,))
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    changed_cases = (changed, *cases[1:])
    proof_run = run._replace(setup=run.setup._replace(resolver=_resolver(run.setup.resolver, proof_resolver)))

    with pytest.raises(AdmissionMetricsError, match="proof.*trust policy"):
        _derive(proof_run, cases=changed_cases, release=_release_for(proof_run, changed_cases))


def test_semantic_site_coverage_is_rederived_from_case_evidence() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    changed_coverage = replace(cases[0].coverage, sites_recognized=1)
    changed = replace(cases[0], coverage=changed_coverage)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))
    changed_cases = (changed, *cases[1:])

    with pytest.raises(AdmissionMetricsError, match="coverage aggregate"):
        _derive(run, cases=changed_cases, release=_release_for(run, changed_cases))


def test_nested_case_graph_refuses_substituted_contract_types() -> None:
    run = _run(_setup())
    cases = run.setup.cases
    original = cases[0].input_manifest
    substituted = _InputManifestSubclass(original.tracked_input_ids, original.manifest_digest)
    changed = replace(cases[0], input_manifest=substituted)
    changed = replace(changed, result_digest=derive_admission_case_result_digest(changed))

    with pytest.raises(AdmissionMetricsError, match="closed admission case"):
        _derive(run, cases=(changed, *cases[1:]))


def test_pair_identity_is_namespaced_by_family_and_ecosystem() -> None:
    digest = canonical.content_digest("shared-pair")
    python = derive_scoped_pair_key(ScopeKey("family", "python"), digest)
    javascript = derive_scoped_pair_key(ScopeKey("family", "javascript"), digest)

    assert python != javascript


def _with_out_of_scope_case(setup: _MetricSetup) -> _MetricSetup:
    contract = setup.context.evidence.family_catalog.entries[0].contract
    expanded_contract = replace(contract, family_version="1-js", ecosystems=("javascript",))
    javascript_entry = FamilyCatalogEntry(expanded_contract, family_contract_digest(expanded_contract))
    entries = tuple(sorted((*setup.context.evidence.family_catalog.entries, javascript_entry), key=catalog_entry_key))
    catalog = FamilyCatalog(entries, derive_catalog_digest(entries))
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=catalog,
        fact_packs=setup.context.evidence.fact_packs,
        model_programs=setup.context.evidence.model_programs,
        lineages=setup.context.evidence.lineages,
        fact_review_policy=setup.context.evidence.fact_review_policy,
        provenance_trust_policy=setup.context.evidence.provenance_trust_policy,
        custody_policy=setup.context.evidence.custody_policy,
    )
    context = admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=setup.context.admission_review_policy,
        proof_trust_policy=None,
    )
    outside_record = _with_fact_set(model_record(expanded_contract), ())
    outside_packet = replace(outside_record.packet, ecosystem="javascript")
    outside_decision = replace(outside_record.decision, packet_digest=derive_packet_digest(outside_packet))
    outside_record = EvidenceRecord(outside_packet, outside_decision, "")
    outside_named, outside_resolver = _named_inputs(outside_record, expanded_contract, ())
    outside_named, outside_resolver = _rename_named_inputs(outside_named, outside_resolver, "javascript")
    outside_input = validation.make_evidence_validation_input(record=outside_record, named_inputs=outside_named)
    resolver = _resolver(setup.resolver, outside_resolver)
    outside, resolver = _case_result(outside_input, AdmissionCaseRole.ORDINARY, None, resolver, expanded_contract)
    outside = replace(outside, case_id_digest=canonical.content_digest("outside-javascript-case"))
    outside = replace(outside, result_digest=derive_admission_case_result_digest(outside))
    cases = (*setup.cases, outside)
    population_digest = setup.manifest.census.population_digest
    row = setup.manifest.census.rows[0]
    outside_row = ScopeCensus(outside.scope, 1, 0, 0, 0, 1, 2, 0)
    rows = tuple(sorted((row, outside_row), key=lambda item: item.scope))
    census = _resign_census_rows(setup.manifest.census, rows, population_digest)
    contract_digests = tuple(sorted(entry.contract_digest for entry in catalog.entries))
    identity = replace(
        setup.manifest.identity,
        population_digest=population_digest,
        family_contract_digests=contract_digests,
        family_contract_set_digest=catalog.catalog_digest,
        outcome_mapping_digest=admission_context.derive_outcome_mapping_digest(catalog),
    )
    program_digest = context.evidence.model_programs[0].declaration_digest
    current_identity = admission_context.derive_analysis_identity(identity, catalog, identity.claimed_scopes[0], program_digest)
    readiness = _chain(identity=current_identity)[:6]
    manifest = _resign_manifest(
        replace(
            setup.manifest,
            identity=identity,
            census=census,
            readiness_digests=tuple(sorted(item.result_digest for item in readiness)),
            validation_context_digest=context.context_digest,
        ),
        census.review.conflict_disclosure,
    )
    return _MetricSetup(manifest, setup.denominator, cases, context, setup.custody, resolver, readiness)


def test_whole_population_coverage_and_runtime_retain_out_of_scope_cases() -> None:
    run = _run(_with_out_of_scope_case(_setup()))

    result = _derive(run)

    assert (result.in_scope_case_count, result.whole_population_case_count) == (3, 4)
    assert (result.stage_funnel.questions_formed, result.whole_population_funnel.questions_formed) == (3, 4)
    assert (result.runtime_ms, result.whole_population_runtime_ms) == (30, 40)
    ordinary = next(item for item in result.metrics if item.metric_id is MetricId.ORDINARY_FALSE_ALARMS_PER_100)
    assert ordinary.denominator == 1


def _with_census_rows(setup: _MetricSetup, rows: tuple[ScopeCensus, ...]) -> _MetricSetup:
    census = _resign_census_rows(setup.manifest.census, rows, setup.manifest.census.population_digest)
    manifest = _resign_manifest(
        replace(setup.manifest, census=census),
        census.review.conflict_disclosure,
    )
    return setup._replace(manifest=manifest)


def test_claimed_scope_must_have_a_reviewed_census_row() -> None:
    setup = _setup()
    unknown = ScopeCensus(ScopeKey("unknown-family", "ruby"), 1, 0, 0, 0, 1, 1, 0)

    with pytest.raises(ValueError, match="claimed scope.*census row"):
        _run(_with_census_rows(setup, (unknown,)))


def test_every_additional_census_scope_must_resolve_in_the_catalog() -> None:
    setup = _setup()
    unknown = ScopeCensus(ScopeKey("unknown-family", "ruby"), 1, 0, 0, 0, 1, 1, 0)
    rows = tuple(sorted((*setup.manifest.census.rows, unknown), key=lambda item: item.scope))

    with pytest.raises(ValueError, match="resolve one exact family contract"):
        _run(_with_census_rows(setup, rows))


def test_released_case_without_a_census_row_is_refused_before_metrics() -> None:
    setup = _with_out_of_scope_case(_setup())
    claimed = tuple(row for row in setup.manifest.census.rows if row.scope in setup.manifest.identity.claimed_scopes)
    run = _run(_with_census_rows(setup, claimed))

    with pytest.raises(AdmissionMetricsError, match="case scope.*census row"):
        _derive(run)


@pytest.mark.parametrize("field", ("semantic_site_capacity", "model_call_capacity"))
def test_released_case_aggregates_must_match_every_census_capacity(field: str) -> None:
    setup = _setup()
    row = setup.manifest.census.rows[0]
    changed = replace(row, **{field: getattr(row, field) + 1})
    run = _run(_with_census_rows(setup, (changed,)))

    with pytest.raises(AdmissionMetricsError, match="case counts.*census"):
        _derive(run)
