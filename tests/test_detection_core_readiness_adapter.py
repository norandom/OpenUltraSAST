from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import development_runner, readiness_contract
from openultrasast.core import canonical, coverage, readiness


def _digest(label: str) -> str:
    return canonical.content_digest(label)


def _identity() -> readiness.AnalysisIdentity:
    return readiness.AnalysisIdentity(
        core_schema_version="v2",
        semantic_vocabulary_digest=_digest("semantics"),
        analyzer_revision="analyzer-v2",
        family_contract_digest=_digest("family"),
        fact_set_digest=_digest("facts"),
        acquisition_record_digest=_digest("acquisition"),
        configuration_digest=_digest("configuration"),
        model_program_digest=None,
        outcome_mapping_digest=_digest("mapping"),
    )


def _fixtures(stage: readiness.ReadinessStage) -> tuple[readiness.FixtureResult, ...]:
    return tuple(readiness.FixtureResult(role, _digest(f"{stage.value}:{role.value}"), True, ()) for role in readiness.FixtureRole)


def _result(
    stage: readiness.ReadinessStage,
    identity: readiness.AnalysisIdentity,
    predecessors: tuple[str, ...],
    *,
    result: readiness.StageResult = readiness.StageResult.PASSED,
    correction_lever: str | None = None,
) -> readiness.ReadinessResult:
    population = stage is readiness.ReadinessStage.DEVELOPMENT
    fixtures = _fixtures(stage)
    if result is readiness.StageResult.FAILED:
        fixtures = (*fixtures[:2], replace(fixtures[2], passed=False, reasons=("stage failed",)))
    return readiness_contract.build_readiness_result(
        arm_id="reference-arm",
        family_id="reference-family",
        ecosystem="python",
        stage=stage,
        result=result,
        identity=identity,
        predecessor_digests=predecessors,
        fixture_results=fixtures,
        measurement_digest=_digest(f"measurement:{stage.value}"),
        correction_lever=correction_lever,
        population_digest=_digest("development-population") if population else None,
        population_freeze_digest=_digest("development-freeze") if population else None,
        population_use_receipt_digests=(_digest("development-use"),) if population else (),
    )


def _prior(identity: readiness.AnalysisIdentity) -> tuple[readiness.ReadinessResult, ...]:
    results: list[readiness.ReadinessResult] = []
    for stage in tuple(readiness.ReadinessStage)[:5]:
        results.append(_result(stage, identity, tuple(item.result_digest for item in results)))
    return tuple(results)


def _instrument() -> tuple[coverage.InputManifest, tuple[coverage.InputReadReceipt, ...]]:
    return readiness_contract.read_tracked_inputs((("fixture.py", Path(__file__)),))


def test_instrument_receipt_is_derived_from_an_opened_nonzero_file() -> None:
    manifest, receipts = _instrument()
    assert manifest.tracked_input_ids == ("fixture.py",)
    assert receipts[0].opened is True
    assert receipts[0].byte_count == Path(__file__).stat().st_size
    assert receipts[0].byte_count > 0


def test_development_observation_carries_v2_readiness_and_instrument_evidence() -> None:
    identity = _identity()
    prior = _prior(identity)
    manifest, receipts = _instrument()
    observation = readiness_contract.build_development_observation(
        arm_id="reference-arm",
        family_id="reference-family",
        ecosystem="python",
        identity=identity,
        population_digest=_digest("development-population"),
        population_freeze_digest=_digest("development-freeze"),
        population_use_receipt_digests=(_digest("development-use"),),
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=_fixtures(readiness.ReadinessStage.DEVELOPMENT),
        input_manifest=manifest,
        input_read_receipts=receipts,
    )
    assert observation.readiness_result.stage is readiness.ReadinessStage.DEVELOPMENT
    assert observation.readiness_result.evidence_use is readiness.ReadinessEvidenceUse.DEVELOPMENT_POPULATION
    assert observation.readiness_result.identity == identity
    assert observation.readiness_result.predecessor_digests == tuple(item.result_digest for item in prior)
    assert observation.input_read_receipts == receipts


@pytest.mark.parametrize("failure", ("missing", "failed", "stale"))
def test_runner_stops_before_population_work(failure: str) -> None:
    identity = _identity()
    prior = list(_prior(identity))
    if failure == "missing":
        prior.pop(2)
    elif failure == "failed":
        prior[2] = _result(
            readiness.ReadinessStage.TRANSITIONS,
            identity,
            tuple(item.result_digest for item in prior[:2]),
            result=readiness.StageResult.FAILED,
            correction_lever="repair transitions",
        )
    else:
        stale_identity = replace(identity, semantic_vocabulary_digest=_digest("stale-semantics"))
        prior[2] = _result(
            readiness.ReadinessStage.TRANSITIONS,
            stale_identity,
            tuple(item.result_digest for item in prior[:2]),
        )
    called = False

    def population_work() -> str:
        nonlocal called
        called = True
        return "ran"

    with pytest.raises(readiness_contract.ReadinessBlocked) as caught:
        development_runner.run_development_when_ready(tuple(prior), identity, population_work)
    assert called is False
    expected = {
        "missing": ("missing transitions readiness evidence", "produce transitions readiness evidence"),
        "failed": ("transitions readiness failed", "repair transitions"),
        "stale": ("transitions readiness is stale", "rerun transitions with current analysis identity"),
    }
    reason, correction = expected[failure]
    assert caught.value.failing_stage is readiness.ReadinessStage.TRANSITIONS
    assert caught.value.reasons == (reason,)
    assert caught.value.correction_lever == correction


def test_runner_executes_population_work_after_current_prerequisites() -> None:
    identity = _identity()
    assert development_runner.run_development_when_ready(_prior(identity), identity, lambda: "ran") == "ran"


def test_runner_refuses_wrong_evidence_use_before_population_work() -> None:
    identity = _identity()
    prior = list(_prior(identity))
    malformed = object.__new__(readiness.ReadinessResult)
    for field, value in prior[2].__dict__.items():
        object.__setattr__(malformed, field, value)
    object.__setattr__(malformed, "evidence_use", readiness.ReadinessEvidenceUse.FRESH_ADMISSION)
    prior[2] = malformed
    called = False

    def population_work() -> None:
        nonlocal called
        called = True

    with pytest.raises(readiness_contract.ReadinessBlocked, match="wrong evidence use"):
        development_runner.run_development_when_ready(tuple(prior), identity, population_work)
    assert called is False


def test_semantic_identity_change_prevents_later_admission() -> None:
    identity = _identity()
    prior = _prior(identity)
    manifest, receipts = _instrument()
    development = readiness_contract.build_development_observation(
        arm_id="reference-arm",
        family_id="reference-family",
        ecosystem="python",
        identity=identity,
        population_digest=_digest("development-population"),
        population_freeze_digest=_digest("development-freeze"),
        population_use_receipt_digests=(_digest("development-use"),),
        predecessor_digests=tuple(item.result_digest for item in prior),
        fixture_results=_fixtures(readiness.ReadinessStage.DEVELOPMENT),
        input_manifest=manifest,
        input_read_receipts=receipts,
    ).readiness_result
    changed = replace(identity, semantic_vocabulary_digest=_digest("changed-semantics"))
    with pytest.raises(readiness_contract.ReadinessBlocked, match="stale"):
        readiness_contract.require_stage_authorized(readiness.ReadinessStage.ADMISSION, (*prior, development), changed)


def test_development_observation_refuses_zero_byte_input() -> None:
    identity = _identity()
    prior = _prior(identity)
    manifest, receipts = _instrument()
    zero = (replace(receipts[0], byte_count=0),)
    with pytest.raises(ValueError, match="zero-byte"):
        readiness_contract.build_development_observation(
            arm_id="reference-arm",
            family_id="reference-family",
            ecosystem="python",
            identity=identity,
            population_digest=_digest("development-population"),
            population_freeze_digest=_digest("development-freeze"),
            population_use_receipt_digests=(_digest("development-use"),),
            predecessor_digests=tuple(item.result_digest for item in prior),
            fixture_results=_fixtures(readiness.ReadinessStage.DEVELOPMENT),
            input_manifest=manifest,
            input_read_receipts=zero,
        )
