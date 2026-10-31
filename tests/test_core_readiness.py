"""Contract tests for ordered detection readiness evidence."""

from dataclasses import replace

import pytest

import openultrasast.core.canonical as canonical
import openultrasast.core.readiness as readiness


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _identity() -> readiness.AnalysisIdentity:
    return readiness.AnalysisIdentity(
        core_schema_version="detection-core.v2",
        semantic_vocabulary_digest=_digest("semantic-vocabulary"),
        analyzer_revision="analyzer@abc123",
        family_contract_digest=_digest("family-contract"),
        fact_set_digest=_digest("fact-set"),
        acquisition_record_digest=_digest("acquisition"),
        configuration_digest=_digest("configuration"),
        model_program_digest=None,
        outcome_mapping_digest=_digest("outcome-mapping"),
    )


def _fixtures(*, all_passed: bool = True) -> tuple[readiness.FixtureResult, ...]:
    values = []
    for role in readiness.FixtureRole:
        passed = all_passed or role is not readiness.FixtureRole.AMBIGUITY
        values.append(
            readiness.FixtureResult(
                role=role,
                fixture_digest=_digest(f"fixture:{role.value}"),
                passed=passed,
                reasons=() if passed else ("ambiguity fixture failed",),
            )
        )
    return tuple(values)


def _population(stage: readiness.ReadinessStage) -> tuple[str | None, str | None, tuple[str, ...]]:
    if stage in (readiness.ReadinessStage.DEVELOPMENT, readiness.ReadinessStage.ADMISSION):
        return _digest(f"{stage.value}:population"), _digest(f"{stage.value}:freeze"), (_digest(f"{stage.value}:use"),)
    return None, None, ()


def _result(
    stage: readiness.ReadinessStage = readiness.ReadinessStage.INSTRUMENT,
    *,
    evidence_use: readiness.ReadinessEvidenceUse | None = None,
    result: readiness.StageResult = readiness.StageResult.PASSED,
) -> readiness.ReadinessResult:
    use = evidence_use or readiness.required_evidence_use(stage)
    population, freeze, receipts = _population(stage)
    fixtures = _fixtures(all_passed=result is readiness.StageResult.PASSED)
    predecessors = () if stage is readiness.ReadinessStage.INSTRUMENT else (_digest(f"predecessor:{stage.value}"),)
    identity = _identity()
    measurement = _digest(f"measurement:{stage.value}")
    correction = None if result is readiness.StageResult.PASSED else "repair ambiguity handling"
    digest = readiness.derive_readiness_result_digest(
        arm_id="reference-arm",
        family_id="reference-family",
        ecosystem="python",
        stage=stage,
        evidence_use=use,
        population_digest=population,
        population_freeze_digest=freeze,
        population_use_receipt_digests=receipts,
        result=result,
        identity=identity,
        predecessor_digests=predecessors,
        fixture_results=fixtures,
        measurement_digest=measurement,
        correction_lever=correction,
    )
    return readiness.ReadinessResult(
        "reference-arm",
        "reference-family",
        "python",
        stage,
        use,
        population,
        freeze,
        receipts,
        result,
        identity,
        predecessors,
        fixtures,
        measurement,
        correction,
        digest,
    )


def test_stage_order_and_evidence_use_policy_are_closed() -> None:
    assert tuple(readiness.ReadinessStage) == (
        readiness.ReadinessStage.INSTRUMENT,
        readiness.ReadinessStage.RECOGNITION,
        readiness.ReadinessStage.TRANSITIONS,
        readiness.ReadinessStage.CONSTRAINTS,
        readiness.ReadinessStage.PAIRS,
        readiness.ReadinessStage.DEVELOPMENT,
        readiness.ReadinessStage.ADMISSION,
        readiness.ReadinessStage.INTEGRATION,
    )
    expected = {
        readiness.ReadinessStage.INSTRUMENT: readiness.ReadinessEvidenceUse.REGRESSION_FIXTURE,
        readiness.ReadinessStage.RECOGNITION: readiness.ReadinessEvidenceUse.REGRESSION_FIXTURE,
        readiness.ReadinessStage.TRANSITIONS: readiness.ReadinessEvidenceUse.REGRESSION_FIXTURE,
        readiness.ReadinessStage.CONSTRAINTS: readiness.ReadinessEvidenceUse.REGRESSION_FIXTURE,
        readiness.ReadinessStage.PAIRS: readiness.ReadinessEvidenceUse.REGRESSION_FIXTURE,
        readiness.ReadinessStage.DEVELOPMENT: readiness.ReadinessEvidenceUse.DEVELOPMENT_POPULATION,
        readiness.ReadinessStage.ADMISSION: readiness.ReadinessEvidenceUse.FRESH_ADMISSION,
        readiness.ReadinessStage.INTEGRATION: readiness.ReadinessEvidenceUse.CONSUMER_INTEGRATION,
    }
    assert {stage: readiness.required_evidence_use(stage) for stage in readiness.ReadinessStage} == expected


@pytest.mark.parametrize("stage", tuple(readiness.ReadinessStage))
def test_each_stage_accepts_only_its_evidence_use_and_triplet(stage: readiness.ReadinessStage) -> None:
    value = _result(stage)
    readiness.validate_readiness_result(value)
    wrong = next(use for use in readiness.ReadinessEvidenceUse if use is not value.evidence_use)
    with pytest.raises(readiness.ReadinessValidationError, match="evidence use"):
        replace(value, evidence_use=wrong)


def test_repository_holdout_is_not_interchangeable_with_development() -> None:
    with pytest.raises(readiness.ReadinessValidationError, match="evidence use"):
        _result(readiness.ReadinessStage.DEVELOPMENT, evidence_use=readiness.ReadinessEvidenceUse.REPOSITORY_HOLDOUT)


def test_fixture_triplet_must_be_exact_unique_and_passing_for_passed_stage() -> None:
    value = _result()
    with pytest.raises(readiness.ReadinessValidationError, match="fixture roles"):
        replace(value, fixture_results=value.fixture_results[:-1])
    duplicate = (value.fixture_results[0], value.fixture_results[0], value.fixture_results[2])
    with pytest.raises(readiness.ReadinessValidationError, match="fixture roles"):
        replace(value, fixture_results=duplicate)
    failed = replace(value.fixture_results[0], passed=False, reasons=("failed",))
    with pytest.raises(readiness.ReadinessValidationError, match="passed stage"):
        replace(value, fixture_results=(failed, *value.fixture_results[1:]))


def test_fixture_result_reason_contract_and_tamper_revalidation() -> None:
    fixture = _fixtures()[0]
    with pytest.raises(readiness.ReadinessValidationError, match="passed fixture"):
        readiness.FixtureResult(fixture.role, fixture.fixture_digest, True, ("unexpected",))
    with pytest.raises(readiness.ReadinessValidationError, match="failed fixture"):
        readiness.FixtureResult(fixture.role, fixture.fixture_digest, False, ())
    object.__setattr__(fixture, "fixture_digest", "bad")
    value = _result()
    object.__setattr__(value, "fixture_results", (fixture, *value.fixture_results[1:]))
    with pytest.raises(readiness.ReadinessValidationError, match="fixture digest"):
        readiness.validate_readiness_result(value)


def test_failed_stage_requires_failed_fixture_and_correction_lever() -> None:
    value = _result(result=readiness.StageResult.FAILED)
    readiness.validate_readiness_result(value)
    with pytest.raises(readiness.ReadinessValidationError, match="correction lever"):
        replace(value, correction_lever=None)
    with pytest.raises(readiness.ReadinessValidationError, match="failed stage"):
        replace(value, fixture_results=_fixtures())
    passed = _result()
    with pytest.raises(readiness.ReadinessValidationError, match="passed stage"):
        replace(passed, correction_lever="not needed")


@pytest.mark.parametrize("stage", (readiness.ReadinessStage.DEVELOPMENT, readiness.ReadinessStage.ADMISSION))
def test_population_evidence_requires_frozen_population_and_use_receipt(stage: readiness.ReadinessStage) -> None:
    value = _result(stage)
    with pytest.raises(readiness.ReadinessValidationError, match="population"):
        replace(value, population_digest=None)
    with pytest.raises(readiness.ReadinessValidationError, match="population"):
        replace(value, population_freeze_digest=None)
    with pytest.raises(readiness.ReadinessValidationError, match="population"):
        replace(value, population_use_receipt_digests=())


@pytest.mark.parametrize(
    "stage",
    (
        readiness.ReadinessStage.INSTRUMENT,
        readiness.ReadinessStage.RECOGNITION,
        readiness.ReadinessStage.TRANSITIONS,
        readiness.ReadinessStage.CONSTRAINTS,
        readiness.ReadinessStage.PAIRS,
        readiness.ReadinessStage.INTEGRATION,
    ),
)
def test_nonpopulation_evidence_refuses_population_fields(stage: readiness.ReadinessStage) -> None:
    value = _result(stage)
    with pytest.raises(readiness.ReadinessValidationError, match="must not name a population"):
        replace(value, population_digest=_digest("injected"))


def test_instrument_has_no_predecessor_and_later_stages_bind_predecessors() -> None:
    instrument = _result()
    with pytest.raises(readiness.ReadinessValidationError, match="instrument.*predecessor"):
        replace(instrument, predecessor_digests=(_digest("unexpected"),))
    later = _result(readiness.ReadinessStage.RECOGNITION)
    with pytest.raises(readiness.ReadinessValidationError, match="predecessor"):
        replace(later, predecessor_digests=())
    with pytest.raises(readiness.ReadinessValidationError, match="duplicate predecessor"):
        replace(later, predecessor_digests=(later.predecessor_digests[0],) * 2)


@pytest.mark.parametrize(
    "field",
    (
        "semantic_vocabulary_digest",
        "family_contract_digest",
        "fact_set_digest",
        "acquisition_record_digest",
        "configuration_digest",
        "outcome_mapping_digest",
    ),
)
def test_analysis_identity_rejects_every_malformed_digest(field: str) -> None:
    identity = _identity()
    with pytest.raises(readiness.ReadinessValidationError, match=field.replace("_", " ")):
        replace(identity, **{field: "bad"})


def test_model_program_identity_is_optional_but_strict() -> None:
    readiness.validate_analysis_identity(_identity())
    identity = replace(_identity(), model_program_digest=_digest("model"))
    readiness.validate_analysis_identity(identity)
    with pytest.raises(readiness.ReadinessValidationError, match="model program"):
        replace(identity, model_program_digest="BAD")


def test_result_digest_binds_all_fields_and_is_revalidated_after_tamper() -> None:
    value = _result(readiness.ReadinessStage.DEVELOPMENT)
    assert value.result_digest == readiness.derive_readiness_result_digest(
        arm_id=value.arm_id,
        family_id=value.family_id,
        ecosystem=value.ecosystem,
        stage=value.stage,
        evidence_use=value.evidence_use,
        population_digest=value.population_digest,
        population_freeze_digest=value.population_freeze_digest,
        population_use_receipt_digests=value.population_use_receipt_digests,
        result=value.result,
        identity=value.identity,
        predecessor_digests=value.predecessor_digests,
        fixture_results=value.fixture_results,
        measurement_digest=value.measurement_digest,
        correction_lever=value.correction_lever,
    )
    object.__setattr__(value, "measurement_digest", _digest("substituted"))
    with pytest.raises(readiness.ReadinessValidationError, match="result digest"):
        readiness.validate_readiness_result(value)


def test_runtime_shapes_are_strict_and_immutable() -> None:
    value = _result()
    with pytest.raises(readiness.ReadinessValidationError, match="fixture_results.*tuple"):
        replace(value, fixture_results=list(value.fixture_results))  # type: ignore[arg-type]
    with pytest.raises(readiness.ReadinessValidationError, match="arm_id"):
        replace(value, arm_id=1)  # type: ignore[arg-type]
    with pytest.raises(readiness.ReadinessValidationError, match="stage"):
        replace(value, stage="instrument")  # type: ignore[arg-type]
