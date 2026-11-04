"""Every semantic/governance failure stops at its first detection-core stage."""

from __future__ import annotations

from pathlib import Path

import detection_core_failure_visibility as visibility
import pytest
from detection_core_failure_visibility import FailureKind, run_identity_staleness, run_stage_failure

from openultrasast.core.coverage import CoverageStage
from openultrasast.core.readiness import ReadinessStage

FIXTURES = Path(__file__).parent / "fixtures" / "detection_core"

FAMILIES = (
    ("obligation_family.json", "obligation_cases.json", "obligation_repository"),
    ("taint_family.json", "taint_cases.json", "taint_repository"),
)

FAILURES = (
    (FailureKind.UNREAD_INPUT, ReadinessStage.INSTRUMENT),
    (FailureKind.ZERO_INPUT, ReadinessStage.INSTRUMENT),
    (FailureKind.MISSING_RECOGNITION, ReadinessStage.RECOGNITION),
    (FailureKind.INCOMPLETE_TRANSITION, ReadinessStage.TRANSITIONS),
    (FailureKind.MISSING_CONSTRAINT, ReadinessStage.CONSTRAINTS),
    (FailureKind.PAIR_MISMATCH, ReadinessStage.PAIRS),
    (FailureKind.FAILED_DEVELOPMENT, ReadinessStage.DEVELOPMENT),
    (FailureKind.CONTAMINATED_ADMISSION, ReadinessStage.ADMISSION),
    (FailureKind.REFUSED_INTEGRATION, ReadinessStage.INTEGRATION),
)

EXPECTED_FAILURE = {
    FailureKind.UNREAD_INPUT: ("tracked input not opened", "produce instrument readiness evidence"),
    FailureKind.ZERO_INPUT: ("zero-byte tracked input", "produce instrument readiness evidence"),
    FailureKind.MISSING_RECOGNITION: (
        "security object identity does not match",
        "produce recognition readiness evidence",
    ),
    FailureKind.INCOMPLETE_TRANSITION: (
        "non-complete semantics or completeness reasons forbid a determinate outcome",
        "produce transitions readiness evidence",
    ),
    FailureKind.MISSING_CONSTRAINT: ("required role is missing", "produce constraints readiness evidence"),
    FailureKind.PAIR_MISMATCH: (
        "every scoped release pair must contain one vulnerable and one fixed case",
        "produce pairs readiness evidence",
    ),
    FailureKind.FAILED_DEVELOPMENT: ("zero-byte tracked input", "produce development readiness evidence"),
    FailureKind.CONTAMINATED_ADMISSION: ("census must not expose case labels", "produce admission readiness evidence"),
    FailureKind.REFUSED_INTEGRATION: ("push inputs must be nonempty", "repair consumer evidence binding"),
}


@pytest.mark.parametrize(("family_file", "cases_file", "repository"), FAMILIES)
@pytest.mark.parametrize(("failure", "failed_stage"), FAILURES)
def test_each_injected_failure_stops_at_its_first_stage(
    tmp_path: Path,
    family_file: str,
    cases_file: str,
    repository: str,
    failure: FailureKind,
    failed_stage: ReadinessStage,
) -> None:
    trace = run_stage_failure(
        fixture_root=FIXTURES,
        family_file=family_file,
        cases_file=cases_file,
        repository=repository,
        failure=failure,
        scratch=tmp_path,
    )

    assert trace.failed_stage is failed_stage
    reason, correction = EXPECTED_FAILURE[failure]
    assert reason in trace.reasons[0]
    assert trace.correction_lever == correction
    assert trace.later_metric_stages == ()
    stage_index = tuple(ReadinessStage).index(failed_stage)
    assert trace.completed_stages == tuple(ReadinessStage)[:stage_index]
    assert trace.metric_stages == tuple(ReadinessStage)[:stage_index]
    assert trace.label_read_count == (1 if failure is FailureKind.REFUSED_INTEGRATION else 0)
    assert bool(tuple(tmp_path.glob("*-labels.json"))) is (failure is FailureKind.REFUSED_INTEGRATION)
    if failure is FailureKind.REFUSED_INTEGRATION:
        assert trace.authorization is None
    else:
        assert trace.authorization is not None
        assert trace.authorization.authorized is False
        assert trace.authorization.failing_stage is failed_stage
        assert trace.authorization.correction_lever == correction

    if failure is FailureKind.MISSING_RECOGNITION:
        assert trace.coverage_diagnosis is not None
        assert trace.coverage_diagnosis.last_verified_nonzero_stage is CoverageStage.SITES_CONSIDERED
        assert trace.coverage_diagnosis.first_failed_output_stage is CoverageStage.SITES_RECOGNIZED
    elif failure is FailureKind.MISSING_CONSTRAINT:
        assert trace.coverage_diagnosis is not None
        assert trace.coverage_diagnosis.last_verified_nonzero_stage is CoverageStage.SECURITY_OBJECTS
        assert trace.coverage_diagnosis.first_failed_output_stage is CoverageStage.CONSTRAINTS


@pytest.mark.parametrize(("family_file", "cases_file", "repository"), FAMILIES)
@pytest.mark.parametrize(("failure", "failed_stage"), FAILURES)
def test_failure_source_is_a_production_validator_and_later_work_is_not_invoked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    family_file: str,
    cases_file: str,
    repository: str,
    failure: FailureKind,
    failed_stage: ReadinessStage,
) -> None:
    calls: list[tuple[str, object]] = []

    def record(name: str, original: object):
        def wrapped(*args: object, **kwargs: object) -> object:
            calls.append((name, args[0] if args else None))
            return original(*args, **kwargs)  # type: ignore[operator]

        return wrapped

    monkeypatch.setattr(visibility, "_measurement", record("measurement", visibility._measurement))
    monkeypatch.setattr(
        visibility,
        "authorize_admission",
        record("authorize_admission", visibility.authorize_admission),
    )
    monkeypatch.setattr(visibility, "_run_admission", record("run_admission", visibility._run_admission))
    monkeypatch.setattr(
        visibility.consumer,
        "consume_records",
        record("consume_records", visibility.consumer.consume_records),
    )

    trace = visibility.run_stage_failure(
        fixture_root=FIXTURES,
        family_file=family_file,
        cases_file=cases_file,
        repository=repository,
        failure=failure,
        scratch=tmp_path,
    )

    assert trace.source_validator.startswith("openultrasast.") or trace.source_validator.startswith("benchmarks.valid.")
    measurement_stages = tuple(value for name, value in calls if name == "measurement")
    expected_measurements = (
        tuple(ReadinessStage)[: tuple(ReadinessStage).index(failed_stage)]
        if failed_stage.value in {"recognition", "transitions", "constraints", "pairs", "development"}
        else ()
    )
    assert measurement_stages == expected_measurements
    assert sum(name == "authorize_admission" for name, _value in calls) == int(failure is FailureKind.CONTAMINATED_ADMISSION)
    assert sum(name == "run_admission" for name, _value in calls) == int(failure is FailureKind.REFUSED_INTEGRATION)
    assert sum(name == "consume_records" for name, _value in calls) == int(failure is FailureKind.REFUSED_INTEGRATION)


@pytest.mark.parametrize(("family_file", "cases_file", "repository"), FAMILIES)
def test_semantic_identity_change_stales_all_later_readiness_and_measurement(
    tmp_path: Path,
    family_file: str,
    cases_file: str,
    repository: str,
) -> None:
    result = run_identity_staleness(
        fixture_root=FIXTURES,
        family_file=family_file,
        cases_file=cases_file,
        repository=repository,
        scratch=tmp_path,
    )

    assert result.targets == tuple(ReadinessStage)[1:]
    assert all(not item.authorized for item in result.authorizations)
    assert all(item.failing_stage is ReadinessStage.INSTRUMENT for item in result.authorizations)
    assert all(item.correction_lever == "rerun instrument with current analysis identity" for item in result.authorizations)
    assert all(old != new for old, new in zip(result.old_readiness_digests, result.rebuilt_readiness_digests, strict=True))
    assert result.measurement_readiness_digests == result.old_readiness_digests[:6]
    assert result.measurement_readiness_digests != result.rebuilt_readiness_digests[:6]
    assert result.manifest_readiness_digests == tuple(sorted(result.old_readiness_digests[:6]))
    assert result.manifest_readiness_digests != tuple(sorted(result.rebuilt_readiness_digests[:6]))
    assert "authoritative admission replay refused" in result.authoritative_refusal
    assert "readiness" in result.authoritative_refusal
