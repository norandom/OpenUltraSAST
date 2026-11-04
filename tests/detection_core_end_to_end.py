"""Test-owned composition of the production detection-core readiness contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from detection_core_fixtures import InMemoryContentResolver
from detection_core_source_authority import SourceAuthority, bind_source_inputs, bind_source_record, load_source_authority
from test_core_admission_context import _resign_manifest
from test_core_admission_metrics import (
    _case_result,
    _MetricSetup,
    _rename_named_inputs,
    _resign_census,
    _resolver,
    _setup,
)
from test_core_reference_families import _contract, _record
from test_core_validation_v2 import _catalog, _named_inputs, _with_fact_set
from test_detection_core_admission_adapter import _custodian, _reviewer, _Store

from benchmarks.valid import readiness_contract
from benchmarks.valid.admission_run import V2AdmissionRunInput, run_v2_admission
from benchmarks.valid.population_custody import AdmissionSpendAuthority
from openultrasast.core import admission_context, canonical, consumer, evidence, family, validation
from openultrasast.core._admission_funnel import derive_case_funnel
from openultrasast.core._admission_replay import AdmissionReplay
from openultrasast.core.admission_case import derive_admission_case_result_digest, derive_case_coverage_digest
from openultrasast.core.admission_context import AdmissionValidationContext
from openultrasast.core.admission_metrics import AdmissionCaseResult, AdmissionCaseRole
from openultrasast.core.admission_report import AdmissionDecision
from openultrasast.core.admission_review import ScopeCensus
from openultrasast.core.coverage import InputManifest, InputReadReceipt, validate_instrument
from openultrasast.core.custody import PopulationStatus
from openultrasast.core.family_catalog import FamilyCatalog
from openultrasast.core.measurement import BaselineIdentity, DenominatorPolicy, IntervalMethod, ScopeKey, standard_metric_rules
from openultrasast.core.readiness import (
    AnalysisIdentity,
    FixtureResult,
    FixtureRole,
    ReadinessResult,
    ReadinessStage,
    StageResult,
)
from openultrasast.core.verdict import derive_verdict_outputs


@dataclass(frozen=True)
class ReferencePathResult:
    family_id: str
    ecosystem: str
    repository_bytes: int
    opened_input_count: int
    source_authority_digest: str
    source_content_digests: tuple[str, ...]
    inputs: tuple[validation.EvidenceValidationInput, ...]
    readiness: tuple[ReadinessResult, ...]
    admission: AdmissionReplay
    verdicts: tuple[consumer.PushVerdict, ...]
    population_status_at_label_read: PopulationStatus
    label_read_count: int


@dataclass(frozen=True)
class _PreparedFamily:
    contract: family.FamilyContract
    ecosystem: str
    inputs: tuple[validation.EvidenceValidationInput, ...]
    resolver: InMemoryContentResolver
    manifest: InputManifest
    receipts: tuple[InputReadReceipt, ...]
    authority: SourceAuthority


def _load_object(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    if not payload:
        raise ValueError(f"zero-byte fixture: {path}")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"fixture is not an object: {path}")
    return cast(dict[str, object], value)


def _prepare_family(fixture_root: Path, family_file: str, cases_file: str, repository: str) -> _PreparedFamily:
    contract = _contract(_load_object(fixture_root / family_file))
    raw_cases = cast(list[dict[str, object]], _load_object(fixture_root / cases_file)["cases"])
    expected_cases = tuple((str(item["case_id"]), str(item["path"])) for item in raw_cases)
    authority = load_source_authority(fixture_root / repository, repository, expected_cases)
    inputs: list[validation.EvidenceValidationInput] = []
    resolvers: list[InMemoryContentResolver] = []
    tracked: list[tuple[str, Path]] = []
    for raw, source in zip(raw_cases, authority.sources, strict=True):
        case_id = str(raw["case_id"])
        raw_record = _with_fact_set(_record(contract, raw), ())
        base_record = bind_source_record(
            raw_record,
            canonical.content_digest("acquisition"),
            canonical.content_digest("change-input"),
        )
        named, resolver = _named_inputs(base_record, contract, ())
        named, resolver = _rename_named_inputs(named, resolver, case_id)
        record = bind_source_record(base_record, authority.authority_digest, source.content_digest)
        named, resolver = bind_source_inputs(named, resolver, authority.manifest_content, source)
        inputs.append(validation.make_evidence_validation_input(record=record, named_inputs=named))
        resolvers.append(resolver)
        tracked.append((case_id, fixture_root / repository / source.path))
    manifest, receipts = readiness_contract.read_tracked_inputs(tuple(tracked))
    validate_instrument(manifest, receipts)
    expected_reads = tuple((item.case_id, len(item.content), item.content_digest) for item in authority.sources)
    actual_reads = tuple((item.input_id, item.byte_count, item.content_digest) for item in receipts)
    if actual_reads != expected_reads:
        raise ValueError("source authority does not match instrument read receipts")
    ecosystem = inputs[0].record.packet.ecosystem
    return _PreparedFamily(contract, ecosystem, tuple(inputs), _resolver(*resolvers), manifest, receipts, authority)


def _evidence_context(base: _MetricSetup, catalog: FamilyCatalog) -> AdmissionValidationContext:
    program_lineages = {item.lineage_manifest_digest for item in base.context.evidence.model_programs}
    lineages = tuple(item for item in base.context.evidence.lineages if item.manifest_digest not in program_lineages)
    evidence_context = validation.make_evidence_validation_context(
        family_catalog=catalog,
        fact_packs=(),
        model_programs=(),
        lineages=lineages,
        fact_review_policy=base.context.evidence.fact_review_policy,
        provenance_trust_policy=base.context.evidence.provenance_trust_policy,
        custody_policy=base.context.evidence.custody_policy,
    )
    return admission_context.make_admission_validation_context(
        evidence=evidence_context,
        admission_review_policy=base.context.admission_review_policy,
        proof_trust_policy=None,
    )


def _baseline(
    base: _MetricSetup,
    catalog: FamilyCatalog,
    scope: ScopeKey,
    denominator: DenominatorPolicy,
    acquisition_record_digest: str,
) -> BaselineIdentity:
    entry = catalog.entries[0]
    return replace(
        base.manifest.identity,
        claimed_scopes=(scope,),
        family_contract_digests=(entry.contract_digest,),
        family_contract_set_digest=catalog.catalog_digest,
        fact_schema_digest=admission_context.derive_fact_schema_digest(),
        fact_set_digest=validation.derive_fact_set_digest(()),
        acquisition_record_digest=acquisition_record_digest,
        analyzer_revision="reference-analyzer@v1",
        configuration_digest=canonical.content_digest("configuration"),
        model_program_digests=(),
        model_program_set_digest=None,
        denominator_policy_digest=denominator.policy_digest,
        outcome_mapping_digest=admission_context.derive_outcome_mapping_digest(catalog),
    )


def _fixtures(inputs: tuple[validation.EvidenceValidationInput, ...]) -> tuple[FixtureResult, ...]:
    return tuple(FixtureResult(role, item.record.record_id, True, ()) for role, item in zip(FixtureRole, inputs, strict=True))


def _measurement(stage: ReadinessStage, prepared: _PreparedFamily) -> str:
    records = tuple(item.record for item in prepared.inputs)
    if stage is ReadinessStage.INSTRUMENT:
        validate_instrument(prepared.manifest, prepared.receipts)
        return canonical.content_digest(
            {
                "stage": stage.value,
                "manifest": prepared.manifest.manifest_digest,
                "source_authority": prepared.authority.authority_digest,
                "reads": tuple((item.input_id, item.byte_count, item.content_digest) for item in prepared.receipts),
            }
        )
    for record in records:
        family.validate_record(prepared.contract, record)
    if stage is ReadinessStage.RECOGNITION and any(not item.packet.security_object_id for item in records):
        raise ValueError("reference recognition did not construct every security object")
    if stage is ReadinessStage.TRANSITIONS and any(not item.packet.transitions for item in records):
        raise ValueError("reference transition stage produced an empty relation set")
    if stage is ReadinessStage.CONSTRAINTS and any(not item.packet.observations for item in records):
        raise ValueError("reference constraint stage produced no observation")
    outcomes = tuple(item.decision.outcome.value for item in records)
    if stage is ReadinessStage.PAIRS and outcomes != ("violation", "satisfied", "indeterminate"):
        raise ValueError("reference pair stage did not preserve the outcome triplet")
    return canonical.content_digest({"stage": stage.value, "records": tuple(item.record_id for item in records)})


def _prerequisite_chain(prepared: _PreparedFamily, identity: AnalysisIdentity) -> tuple[ReadinessResult, ...]:
    results: list[ReadinessResult] = []
    fixtures = _fixtures(prepared.inputs)
    for stage in tuple(ReadinessStage)[:5]:
        if results:
            readiness_contract.require_stage_authorized(stage, tuple(results), identity)
        measurement = _measurement(stage, prepared)
        results.append(
            readiness_contract.build_readiness_result(
                arm_id="reference-arm",
                family_id=prepared.contract.family_id,
                ecosystem=prepared.ecosystem,
                stage=stage,
                result=StageResult.PASSED,
                identity=identity,
                predecessor_digests=tuple(item.result_digest for item in results),
                fixture_results=fixtures,
                measurement_digest=measurement,
                correction_lever=None,
                population_digest=None,
                population_freeze_digest=None,
                population_use_receipt_digests=(),
            )
        )
    return tuple(results)


def _development(
    prepared: _PreparedFamily,
    identity: AnalysisIdentity,
    prior: tuple[ReadinessResult, ...],
) -> ReadinessResult:
    readiness_contract.require_stage_authorized(ReadinessStage.DEVELOPMENT, prior, identity)
    observation = readiness_contract.build_development_observation(
        arm_id="reference-arm",
        family_id=prepared.contract.family_id,
        ecosystem=prepared.ecosystem,
        identity=identity,
        population_digest=canonical.content_digest(f"{prepared.contract.family_id}:development"),
        population_freeze_digest=canonical.content_digest(f"{prepared.contract.family_id}:development-freeze"),
        population_use_receipt_digests=(canonical.content_digest(f"{prepared.contract.family_id}:development-use"),),
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=_fixtures(prepared.inputs),
        input_manifest=prepared.manifest,
        input_read_receipts=prepared.receipts,
    )
    return observation.readiness_result


def _canonical_case(
    value: AdmissionCaseResult,
    record: evidence.EvidenceRecord,
    contract: family.FamilyContract,
) -> AdmissionCaseResult:
    pending = derive_verdict_outputs((record,), contract, canonical.content_digest("admission-coverage-pending"))
    funnel = derive_case_funnel(value, (record,), len(pending.defects))
    coverage_digest = derive_case_coverage_digest(value.case_id_digest, value.scope, funnel)
    outputs = derive_verdict_outputs((record,), contract, coverage_digest)
    changed = replace(
        value,
        defect_claims=outputs.defects,
        satisfactions=outputs.satisfactions,
        silence=outputs.silence,
        coverage=funnel,
        result_digest="0" * 64,
    )
    return replace(changed, result_digest=derive_admission_case_result_digest(changed))


def _admission_setup(prepared: _PreparedFamily) -> _MetricSetup:
    base = _setup()
    catalog = _catalog(prepared.contract)
    context = _evidence_context(base, catalog)
    scope = ScopeKey(prepared.contract.family_id, prepared.ecosystem)
    denominator = DenominatorPolicy(standard_metric_rules((scope,)), IntervalMethod.WILSON_95, "")
    identity = _baseline(base, catalog, scope, denominator, prepared.authority.authority_digest)
    current = admission_context.derive_analysis_identity(identity, catalog, scope, None)
    prior = _prerequisite_chain(prepared, current)
    readiness = (*prior, _development(prepared, current, prior))
    resolver = _resolver(base.resolver, prepared.resolver)
    pair = canonical.content_digest(f"{prepared.contract.family_id}:pair")
    roles = (AdmissionCaseRole.VULNERABLE, AdmissionCaseRole.FIXED, AdmissionCaseRole.ORDINARY)
    pairs = (pair, pair, None)
    cases = []
    for value, role, pair_id in zip(prepared.inputs, roles, pairs, strict=True):
        case, resolver = _case_result(value, role, pair_id, resolver, prepared.contract)
        cases.append(_canonical_case(case, value.record, prepared.contract))
    semantic_sites = sum(item.coverage.sites_considered for item in cases)
    row = ScopeCensus(scope, 3, 1, 1, 1, 1, semantic_sites, 0)
    census = _resign_census(base.manifest.census, row, base.manifest.identity.population_digest)
    manifest = _resign_manifest(
        replace(
            base.manifest,
            identity=identity,
            census=census,
            readiness_digests=tuple(sorted(item.result_digest for item in readiness)),
            denominator_policy_digest=denominator.policy_digest,
            validation_context_digest=context.context_digest,
        ),
        census.review.conflict_disclosure,
    )
    return _MetricSetup(manifest, denominator, tuple(cases), context, base.custody, resolver, readiness)


def _run_admission(setup: _MetricSetup, scratch: Path) -> tuple[AdmissionReplay, PopulationStatus, int]:
    readiness_contract.require_stage_authorized(ReadinessStage.ADMISSION, setup.readiness, setup.readiness[0].identity)
    population = setup.manifest.identity.population_digest
    store = _Store(setup.custody.current_log(population))
    custodian = _custodian(setup, store)
    label_path = scratch / f"{setup.manifest.identity.claimed_scopes[0].family_id}-labels.json"
    label_path.write_bytes(b'{"roles":["vulnerable","fixed","ordinary"]}')
    status_at_read: list[PopulationStatus] = []

    def load_labels() -> bytes:
        status_at_read.append(store.log.status)
        return label_path.read_bytes()

    value = V2AdmissionRunInput(
        AdmissionSpendAuthority(setup.manifest, setup.denominator, setup.readiness, setup.context, setup.resolver),
        custodian,
        load_labels,
        lambda _labels: setup.cases,
        _reviewer(setup),
    )
    replay = run_v2_admission(value)
    if replay.report.decision is not AdmissionDecision.GO:
        raise ValueError("synthetic reference admission did not pass its reviewed threshold")
    return replay, status_at_read[0], len(status_at_read)


def _admission_result(
    setup: _MetricSetup,
    replay: AdmissionReplay,
    prior: tuple[ReadinessResult, ...],
) -> ReadinessResult:
    baseline = setup.manifest.identity
    return readiness_contract.build_readiness_result(
        arm_id=baseline.arm_id,
        family_id=baseline.claimed_scopes[0].family_id,
        ecosystem=baseline.claimed_scopes[0].ecosystem,
        stage=ReadinessStage.ADMISSION,
        result=StageResult.PASSED,
        identity=prior[0].identity,
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=prior[0].fixture_results,
        measurement_digest=replay.report.report_digest,
        correction_lever=None,
        population_digest=baseline.population_digest,
        population_freeze_digest=baseline.freeze_digest,
        population_use_receipt_digests=(replay.label_release_receipt.receipt_digest,),
    )


def _consume(
    setup: _MetricSetup,
    prepared: _PreparedFamily,
    readiness: tuple[ReadinessResult, ...],
) -> tuple[tuple[consumer.PushVerdict, ...], InMemoryContentResolver]:
    from test_core_consumer_v2 import _request

    readiness_contract.require_stage_authorized(ReadinessStage.INTEGRATION, readiness, readiness[0].identity)
    resolver = setup.resolver
    verdicts = []
    for value in prepared.inputs:
        request, resolver = _request(value, resolver)
        verdicts.append(
            consumer.consume_records(
                request,
                (value,),
                setup.context.evidence,
                setup.custody,
                1,
                resolver,
            )
        )
    return tuple(verdicts), resolver


def _integration_result(
    prior: tuple[ReadinessResult, ...],
    verdicts: tuple[consumer.PushVerdict, ...],
) -> ReadinessResult:
    first = prior[0]
    measurement = canonical.content_digest(
        {"requests": tuple(item.request_digest for item in verdicts), "records": tuple(item.input_record_digests for item in verdicts)}
    )
    return readiness_contract.build_readiness_result(
        arm_id=first.arm_id,
        family_id=first.family_id,
        ecosystem=first.ecosystem,
        stage=ReadinessStage.INTEGRATION,
        result=StageResult.PASSED,
        identity=first.identity,
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=first.fixture_results,
        measurement_digest=measurement,
        correction_lever=None,
        population_digest=None,
        population_freeze_digest=None,
        population_use_receipt_digests=(),
    )


def run_reference_family_path(
    *,
    fixture_root: Path,
    family_file: str,
    cases_file: str,
    repository: str,
    scratch: Path,
) -> ReferencePathResult:
    prepared = _prepare_family(fixture_root, family_file, cases_file, repository)
    setup = _admission_setup(prepared)
    replay, status_at_read, read_count = _run_admission(setup, scratch)
    admission = _admission_result(setup, replay, setup.readiness)
    through_admission = (*setup.readiness, admission)
    verdicts, _resolver_value = _consume(setup, prepared, through_admission)
    integration = _integration_result(through_admission, verdicts)
    readiness = (*through_admission, integration)
    return ReferencePathResult(
        prepared.contract.family_id,
        prepared.ecosystem,
        sum(item.byte_count for item in prepared.receipts),
        sum(item.opened for item in prepared.receipts),
        prepared.authority.authority_digest,
        tuple(item.content_digest for item in prepared.authority.sources),
        prepared.inputs,
        readiness,
        replay,
        verdicts,
        status_at_read,
        read_count,
    )


__all__ = ["ReferencePathResult", "run_reference_family_path"]
