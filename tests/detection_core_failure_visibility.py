"""Test-owned failure injection over the production readiness contracts."""

from __future__ import annotations

import enum
import hashlib
import shutil
from dataclasses import dataclass, replace
from pathlib import Path

from detection_core_end_to_end import (
    _admission_result,
    _admission_setup,
    _baseline,
    _fixtures,
    _measurement,
    _prepare_family,
    _PreparedFamily,
    _run_admission,
    run_reference_family_path,
)
from detection_core_failure_inputs import observe_semantic_failure
from test_core_admission_context import _resign_manifest
from test_core_admission_metrics import _resign_census, _setup
from test_core_consumer_v2 import _request
from test_core_reference_families import _contract
from test_core_validation_v2 import _catalog

from benchmarks.valid import readiness_contract
from openultrasast.core import admission_context, canonical, consumer, family
from openultrasast.core.admission_report import _make_replay, validate_admission_replay
from openultrasast.core.admission_spend import authorize_admission
from openultrasast.core.coverage import (
    InstrumentFailure,
    StageDiagnosis,
    validate_instrument,
)
from openultrasast.core.measurement import DenominatorPolicy, IntervalMethod, ScopeKey, standard_metric_rules
from openultrasast.core.readiness import (
    AnalysisIdentity,
    ReadinessResult,
    ReadinessStage,
    StageAuthorization,
    StageResult,
    authorize_stage,
)


class FailureKind(enum.Enum):
    UNREAD_INPUT = "unread_input"
    ZERO_INPUT = "zero_input"
    MISSING_RECOGNITION = "missing_recognition"
    INCOMPLETE_TRANSITION = "incomplete_transition"
    MISSING_CONSTRAINT = "missing_constraint"
    PAIR_MISMATCH = "pair_mismatch"
    FAILED_DEVELOPMENT = "failed_development"
    CONTAMINATED_ADMISSION = "contaminated_admission"
    REFUSED_INTEGRATION = "refused_integration"


@dataclass(frozen=True)
class FailureTrace:
    failed_stage: ReadinessStage
    reasons: tuple[str, ...]
    correction_lever: str
    completed_stages: tuple[ReadinessStage, ...]
    metric_stages: tuple[ReadinessStage, ...]
    later_metric_stages: tuple[ReadinessStage, ...]
    authorization: StageAuthorization | None
    label_read_count: int
    coverage_diagnosis: StageDiagnosis | None
    source_validator: str


@dataclass(frozen=True)
class IdentityStaleness:
    targets: tuple[ReadinessStage, ...]
    authorizations: tuple[StageAuthorization, ...]
    old_readiness_digests: tuple[str, ...]
    rebuilt_readiness_digests: tuple[str, ...]
    measurement_readiness_digests: tuple[str, ...]
    manifest_readiness_digests: tuple[str, ...]
    authoritative_refusal: str


def _stage_index(stage: ReadinessStage) -> int:
    return tuple(ReadinessStage).index(stage)


def _trace(
    stage: ReadinessStage,
    reasons: tuple[str, ...],
    correction: str,
    receipts: tuple[ReadinessResult, ...],
    authorization: StageAuthorization | None,
    *,
    labels: int = 0,
    diagnosis: StageDiagnosis | None = None,
    source_validator: str,
) -> FailureTrace:
    metrics = tuple(item.stage for item in receipts)
    completed = tuple(item.stage for item in receipts if item.result is StageResult.PASSED)
    later = tuple(item for item in metrics if _stage_index(item) > _stage_index(stage))
    return FailureTrace(stage, reasons, correction, completed, metrics, later, authorization, labels, diagnosis, source_validator)


def _identity(prepared: _PreparedFamily) -> AnalysisIdentity:
    base = _setup()
    contract = prepared.contract
    catalog = _catalog(contract)
    scope = ScopeKey(contract.family_id, prepared.ecosystem)
    denominator = DenominatorPolicy(standard_metric_rules((scope,)), IntervalMethod.WILSON_95, "")
    baseline = _baseline(base, catalog, scope, denominator, prepared.authority.authority_digest)
    return admission_context.derive_analysis_identity(baseline, catalog, scope, None)


def _instrument_identity(fixture_root: Path, family_file: str, authority_manifest: Path) -> AnalysisIdentity:
    contract = _contract(_load_json(fixture_root / family_file))
    catalog = _catalog(contract)
    authority = authority_manifest.read_bytes()
    if not authority:
        raise ValueError("source authority manifest is empty")
    return AnalysisIdentity(
        contract.schema_version,
        admission_context.derive_semantic_vocabulary_digest(),
        "reference-analyzer@v1",
        family.family_contract_digest(contract),
        canonical.content_digest("empty-fact-set"),
        hashlib.sha256(authority).hexdigest(),
        canonical.content_digest("configuration"),
        None,
        admission_context.derive_outcome_mapping_digest(catalog),
    )


def _load_json(path: Path) -> dict[str, object]:
    import json

    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("fixture must contain an object")
    return value


def _instrument_failure(
    fixture_root: Path,
    family_file: str,
    repository: str,
    failure: FailureKind,
    scratch: Path,
) -> FailureTrace:
    repository_root = scratch / f"{repository}-{failure.value}"
    shutil.copytree(fixture_root / repository, repository_root)
    authority_manifest = repository_root / "source_authority.json"
    manifest_value = _load_json(authority_manifest)
    cases = manifest_value.get("cases")
    if not isinstance(cases, list) or not cases or not isinstance(cases[0], dict):
        raise ValueError("source authority must name an authored case")
    input_id = str(cases[0]["case_id"])
    path = repository_root / str(cases[0]["path"])
    if failure is FailureKind.UNREAD_INPUT:
        path.unlink()
    if failure is FailureKind.ZERO_INPUT:
        path.write_bytes(b"")
    manifest, receipts = readiness_contract.read_tracked_inputs(((input_id, path),))
    try:
        validate_instrument(manifest, receipts)
    except InstrumentFailure as exc:
        reason = str(exc)
    else:
        raise AssertionError("injected bad input was accepted")
    identity = _instrument_identity(fixture_root, family_file, authority_manifest)
    authorization = authorize_stage(ReadinessStage.RECOGNITION, (), identity)
    return _trace(
        ReadinessStage.INSTRUMENT,
        (reason,),
        authorization.correction_lever or "repair instrument",
        (),
        authorization,
        source_validator="openultrasast.core.coverage.validate_instrument",
    )


def _semantic_failure(prepared: _PreparedFamily, failure: FailureKind, scratch: Path) -> FailureTrace:
    stage = {
        FailureKind.MISSING_RECOGNITION: ReadinessStage.RECOGNITION,
        FailureKind.INCOMPLETE_TRANSITION: ReadinessStage.TRANSITIONS,
        FailureKind.MISSING_CONSTRAINT: ReadinessStage.CONSTRAINTS,
        FailureKind.PAIR_MISMATCH: ReadinessStage.PAIRS,
        FailureKind.FAILED_DEVELOPMENT: ReadinessStage.DEVELOPMENT,
    }[failure]
    identity = _identity(prepared)
    results: list[ReadinessResult] = []
    for current in tuple(ReadinessStage)[: _stage_index(stage)]:
        if results:
            readiness_contract.require_stage_authorized(current, tuple(results), identity)
        results.append(_passed_result(prepared, identity, current, results))
    reason, diagnosis, validator = observe_semantic_failure(prepared, stage, identity, tuple(results), scratch)
    target = tuple(ReadinessStage)[_stage_index(stage) + 1]
    authorization = authorize_stage(target, tuple(results), identity)
    correction = authorization.correction_lever or "repair readiness failure"
    return _trace(
        stage,
        (reason,),
        correction,
        tuple(results),
        authorization,
        diagnosis=diagnosis,
        source_validator=validator,
    )


def _passed_result(
    prepared: _PreparedFamily,
    identity: AnalysisIdentity,
    stage: ReadinessStage,
    prior: list[ReadinessResult],
) -> ReadinessResult:
    return readiness_contract.build_readiness_result(
        arm_id="reference-arm",
        family_id=prepared.contract.family_id,
        ecosystem=prepared.ecosystem,
        stage=stage,
        result=StageResult.PASSED,
        identity=identity,
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=_fixtures(prepared.inputs),
        measurement_digest=_measurement(stage, prepared),
        correction_lever=None,
        population_digest=None,
        population_freeze_digest=None,
        population_use_receipt_digests=(),
    )


def _contaminated_admission(prepared: _PreparedFamily) -> FailureTrace:
    setup = _admission_setup(prepared)
    exposed = replace(setup.manifest.census, case_labels_exposed=True)
    census = _resign_census(exposed, exposed.rows[0], exposed.population_digest)
    manifest = _resign_manifest(replace(setup.manifest, census=census), census.review.conflict_disclosure)
    try:
        authorize_admission(manifest, setup.denominator, setup.readiness, setup.context, setup.custody, setup.resolver)
    except ValueError as exc:
        reason = str(exc)
    else:
        raise AssertionError("contaminated admission was accepted")
    authorization = authorize_stage(ReadinessStage.INTEGRATION, setup.readiness, setup.readiness[0].identity)
    return _trace(
        ReadinessStage.ADMISSION,
        (reason,),
        authorization.correction_lever or "repair admission",
        setup.readiness,
        authorization,
        source_validator="openultrasast.core.admission_spend.authorize_admission",
    )


def _refused_integration(prepared: _PreparedFamily, scratch: Path) -> FailureTrace:
    setup = _admission_setup(prepared)
    replay, _status, label_reads = _run_admission(setup, scratch)
    admission = _admission_result(setup, replay, setup.readiness)
    prior = (*setup.readiness, admission)
    readiness_contract.require_stage_authorized(ReadinessStage.INTEGRATION, prior, prior[0].identity)
    request, resolver = _request(prepared.inputs[0], setup.resolver)
    try:
        consumer.consume_records(request, (), setup.context.evidence, setup.custody, 1, resolver)
    except ValueError as exc:
        reason = str(exc)
    else:
        raise AssertionError("consumer accepted missing evidence")
    return _trace(
        ReadinessStage.INTEGRATION,
        (reason,),
        "repair consumer evidence binding",
        prior,
        None,
        labels=label_reads,
        source_validator="openultrasast.core.consumer.consume_records",
    )


def run_stage_failure(
    *,
    fixture_root: Path,
    family_file: str,
    cases_file: str,
    repository: str,
    failure: FailureKind,
    scratch: Path,
) -> FailureTrace:
    if failure in (FailureKind.UNREAD_INPUT, FailureKind.ZERO_INPUT):
        return _instrument_failure(fixture_root, family_file, repository, failure, scratch)
    prepared = _prepare_family(fixture_root, family_file, cases_file, repository)
    if failure is FailureKind.CONTAMINATED_ADMISSION:
        return _contaminated_admission(prepared)
    if failure is FailureKind.REFUSED_INTEGRATION:
        return _refused_integration(prepared, scratch)
    return _semantic_failure(prepared, failure, scratch)


def _rebuild(readiness: tuple[ReadinessResult, ...], identity: AnalysisIdentity) -> tuple[ReadinessResult, ...]:
    rebuilt: list[ReadinessResult] = []
    for item in readiness:
        rebuilt.append(
            readiness_contract.build_readiness_result(
                arm_id=item.arm_id,
                family_id=item.family_id,
                ecosystem=item.ecosystem,
                stage=item.stage,
                result=item.result,
                identity=identity,
                predecessor_digests=tuple(value.result_digest for value in rebuilt),
                fixture_results=item.fixture_results,
                measurement_digest=item.measurement_digest,
                correction_lever=item.correction_lever,
                population_digest=item.population_digest,
                population_freeze_digest=item.population_freeze_digest,
                population_use_receipt_digests=item.population_use_receipt_digests,
            )
        )
    return tuple(rebuilt)


def run_identity_staleness(*, fixture_root: Path, family_file: str, cases_file: str, repository: str, scratch: Path) -> IdentityStaleness:
    result = run_reference_family_path(
        fixture_root=fixture_root,
        family_file=family_file,
        cases_file=cases_file,
        repository=repository,
        scratch=scratch,
    )
    current = result.readiness[0].identity
    changed = replace(current, semantic_vocabulary_digest=canonical.content_digest("changed-semantic-vocabulary"))
    targets = tuple(ReadinessStage)[1:]
    authorizations = tuple(authorize_stage(target, result.readiness[: _stage_index(target)], changed) for target in targets)
    rebuilt = _rebuild(result.readiness, changed)
    measurement = result.admission.report.measurement
    replay = _make_replay(
        result.admission.manifest,
        result.admission.denominator,
        rebuilt[:6],
        result.admission.preparation,
        result.admission.label_release_receipt,
        result.admission.case_release,
        result.admission.cases,
        result.admission.report,
    )
    current_setup = _admission_setup(_prepare_family(fixture_root, family_file, cases_file, repository))
    try:
        validate_admission_replay(replay, current_setup.context, current_setup.custody, current_setup.resolver)
    except ValueError as exc:
        refusal = str(exc)
    else:
        raise AssertionError("stale admission measurement was accepted against rebuilt readiness")
    return IdentityStaleness(
        targets,
        authorizations,
        tuple(item.result_digest for item in result.readiness),
        tuple(item.result_digest for item in rebuilt),
        tuple(item.result_digest for item in measurement.prerequisite_readiness),
        result.admission.manifest.readiness_digests,
        refusal,
    )


__all__ = ["FailureKind", "FailureTrace", "IdentityStaleness", "run_identity_staleness", "run_stage_failure"]
