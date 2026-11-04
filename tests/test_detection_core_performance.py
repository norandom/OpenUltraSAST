"""Measured performance and total consumer deadline validation for detection-core."""

from __future__ import annotations

import json
import math
from dataclasses import replace

import pytest
from detection_core_performance import (
    PERFORMANCE_FIXTURE,
    PerformanceProfile,
    assert_large_set_envelope,
    measured_profile,
    optional_consumer_case,
    read_workload,
    reject_invalid_large_set,
)
from detection_core_scaling import _series

import openultrasast.core.consumer as consumer_module
from openultrasast.core import budget, canonical
from openultrasast.core.consumer import ConsumerContractError, consume_records, make_push_request


def _instrument_optional_path(
    monkeypatch: pytest.MonkeyPatch,
    profile: PerformanceProfile,
) -> tuple[list[str], list[int]]:
    calls: list[str] = []
    clock = [0]
    original_validate = consumer_module.validate_evidence_input
    original_attach = consumer_module.attach_differential_proof
    original_outputs = consumer_module._derive_outputs

    def measured_validate(*args: object, **kwargs: object) -> object:
        result = original_validate(*args, **kwargs)  # type: ignore[arg-type]
        calls.append("model")
        return result

    def measured_attach(*args: object, **kwargs: object) -> object:
        result = original_attach(*args, **kwargs)  # type: ignore[arg-type]
        calls.append("proof")
        return result

    def delayed_outputs(*args: object, **kwargs: object) -> object:
        result = original_outputs(*args, **kwargs)  # type: ignore[arg-type]
        clock[0] += (profile.budget.budget_ms + 1) * 1_000_000
        return result

    monkeypatch.setattr(consumer_module, "validate_evidence_input", measured_validate)
    monkeypatch.setattr(consumer_module, "attach_differential_proof", measured_attach)
    monkeypatch.setattr(consumer_module, "_derive_outputs", delayed_outputs)
    monkeypatch.setattr(consumer_module, "_monotonic_ns", lambda: clock[0])
    return calls, clock


def test_measured_profile_discloses_increasing_workload_and_fixed_budget_contract() -> None:
    workload = read_workload(PERFORMANCE_FIXTURE)
    profile = measured_profile(workload)

    assert workload.bytes_read > 0
    assert len(workload.content_digest) == 64
    assert tuple(point.relation_count for point in profile.points) == workload.sizes
    assert tuple(point.observation_count for point in profile.points) == workload.sizes
    assert tuple(point.receipt_count for point in profile.points) == workload.sizes
    assert tuple(point.case_count for point in profile.points) == workload.sizes
    assert all(
        type(value) is int and value > 0
        for point in profile.points
        for value in (point.elapsed_ns, *point.elapsed_samples_ns, point.peak_bytes, *point.peak_samples_bytes)
    )
    assert profile.sample_bytes > 0
    expected_samples = (len(workload.sizes) + 1) * workload.repeats
    assert profile.budget.sample_count == len(profile.samples) == expected_samples
    assert profile.budget.percentile == workload.percentile
    assert profile.budget.reference_workload == profile.reference_workload
    assert profile.budget.reference_hardware == profile.reference_hardware
    assert profile.budget.budget_ms == max(sample.total_reply_ms for sample in profile.samples)
    assert len(profile.budget.derivation_digest) == 64


def test_large_transition_validation_is_proportional_bounded_and_semantically_strict() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))

    assert_large_set_envelope(profile)
    reject_invalid_large_set(profile.workload, profile.workload.sizes[-1])


def _adversarial_values(profile: PerformanceProfile, shape: str) -> tuple[int, ...]:
    sizes = tuple(point.relation_count for point in profile.points)
    if shape == "quadratic":
        return tuple(size**2 for size in sizes)
    if shape == "fixed-overhead-quadratic":
        return tuple(100_000 + size**2 for size in sizes)
    if shape == "n^1.1":
        return tuple(round(10_000 * size**1.1) for size in sizes)
    if shape == "n^1.25":
        return tuple(round(10_000 * size**1.25) for size in sizes)
    if shape == "mild-superlinear":
        return tuple(round(10_000 * size**1.05) for size in sizes)
    return (1_000, 4_000, 500_000, 502_000)


def _valid_memory_points(profile: PerformanceProfile) -> tuple[object, ...]:
    return tuple(
        replace(
            point,
            peak_bytes=100_000 + point.relation_count * 1_000,
            peak_samples_bytes=(100_000 + point.relation_count * 1_000,) * profile.workload.repeats,
        )
        for point in profile.points
    )


def _adversarial_points(
    profile: PerformanceProfile,
    target: str,
    values: tuple[int, ...],
) -> tuple[object, ...]:
    source = _valid_memory_points(profile) if target == "work" else profile.points
    if target == "work":
        return tuple(replace(point, work=replace(point.work, total_operations=value)) for point, value in zip(source, values, strict=True))
    return tuple(
        replace(point, peak_bytes=value, peak_samples_bytes=(value,) * profile.workload.repeats)
        for point, value in zip(source, values, strict=True)
    )


@pytest.mark.parametrize("target", ("work", "memory"))
@pytest.mark.parametrize(
    "shape",
    ("quadratic", "fixed-overhead-quadratic", "n^1.1", "n^1.25", "mild-superlinear", "penultimate-spike"),
)
def test_adversarial_superlinear_profiles_are_rejected(target: str, shape: str) -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    values = _adversarial_values(profile, shape)
    points = _adversarial_points(profile, target, values)
    with pytest.raises(AssertionError, match=f"incremental validation {target}"):
        assert_large_set_envelope(replace(profile, points=points))


def test_elapsed_samples_are_published_but_not_used_as_deterministic_scaling_oracle() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    values = (1_000, 4_000, 500_000, 502_000)
    points = tuple(
        replace(point, elapsed_ns=value, elapsed_samples_ns=(value,) * profile.workload.repeats)
        for point, value in zip(_valid_memory_points(profile), values, strict=True)
    )

    assert_large_set_envelope(replace(profile, points=points))


@pytest.mark.parametrize("metric", ("elapsed", "memory"))
@pytest.mark.parametrize("invalid", (math.inf, math.nan, 1.5, True, 0, -1))
def test_measurement_series_refuse_non_integer_nonpositive_or_nonfinite_values(metric: str, invalid: object) -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    point = profile.points[-1]
    if metric == "elapsed":
        changed = replace(point, elapsed_samples_ns=(*point.elapsed_samples_ns[:-1], invalid))
    else:
        changed = replace(point, peak_samples_bytes=(*point.peak_samples_bytes[:-1], invalid))
    with pytest.raises(AssertionError, match="positive integer"):
        assert_large_set_envelope(replace(profile, points=(*profile.points[:-1], changed)))


@pytest.mark.parametrize("metric", ("elapsed", "memory"))
def test_measurement_series_refuse_unequal_repeats_and_mismatched_summaries(metric: str) -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    point = profile.points[-1]
    if metric == "elapsed":
        unequal = replace(point, elapsed_samples_ns=point.elapsed_samples_ns[:-1])
        mismatch = replace(point, elapsed_ns=point.elapsed_ns + 1)
    else:
        unequal = replace(point, peak_samples_bytes=point.peak_samples_bytes[:-1])
        mismatch = replace(point, peak_bytes=point.peak_bytes + 1)
    with pytest.raises(AssertionError, match="equal repeat counts"):
        assert_large_set_envelope(replace(profile, points=(*profile.points[:-1], unequal)))
    with pytest.raises(AssertionError, match="summary does not match repeated median"):
        assert_large_set_envelope(replace(profile, points=(*profile.points[:-1], mismatch)))


def test_inflated_repeat_variance_cannot_hide_superlinear_memory() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    values = _adversarial_values(profile, "n^1.25")
    points = tuple(
        replace(
            point,
            peak_bytes=value,
            peak_samples_bytes=(max(1, value // 100), value, value * 100),
        )
        for point, value in zip(profile.points, values, strict=True)
    )
    with pytest.raises(AssertionError, match="incremental validation memory"):
        assert_large_set_envelope(replace(profile, points=points))


def test_huge_work_disagreement_is_a_named_domain_failure() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    point = profile.points[-1]
    changed = replace(point, work=replace(point.work, total_operations=10**400))

    with pytest.raises(AssertionError, match="incremental validation work total disagrees"):
        assert_large_set_envelope(replace(profile, points=(*profile.points[:-1], changed)))


def test_huge_superlinear_memory_is_a_named_domain_failure() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    huge = 10**400
    values = (huge, huge * 2, huge * 8, huge * 64)
    points = tuple(
        replace(point, peak_bytes=value, peak_samples_bytes=(value,) * profile.workload.repeats)
        for point, value in zip(profile.points, values, strict=True)
    )

    with pytest.raises(AssertionError, match="incremental validation memory slope increased"):
        assert_large_set_envelope(replace(profile, points=points))


def test_huge_even_repeat_median_and_elapsed_conversion_remain_exact() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    huge = 10**400
    point = replace(
        profile.points[-1],
        elapsed_ns=huge + 1,
        elapsed_samples_ns=(huge, huge + 2, huge, huge + 2),
    )
    medians, _ = _series((point,), "elapsed_samples_ns", "elapsed_ns", "elapsed")
    assert medians == (huge + 1,)

    point = replace(point, elapsed_ns=huge + 999_999)
    assert point.elapsed_ms == (huge + 1_999_998) // 1_000_000


def test_huge_elapsed_samples_publish_and_derive_without_float_narrowing() -> None:
    from detection_core_performance_reporting import hardware, sample_report, seed_budget

    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    huge = 10**400
    points = tuple(
        replace(
            point,
            elapsed_ns=huge + index,
            elapsed_samples_ns=(huge + index,) * profile.workload.repeats,
        )
        for index, point in enumerate(profile.points)
    )

    report = sample_report(profile.workload, points, ())
    assert str(huge).encode() in report
    derived = seed_budget(profile.workload, points, hardware())
    assert derived.budget_ms == (huge + len(points) - 1 + 999_999) // 1_000_000


@pytest.mark.parametrize("invalid", (math.inf, math.nan, 1.5, True, 0, -1, "1"))
def test_elapsed_conversion_refuses_non_exact_or_nonpositive_values(invalid: object) -> None:
    from detection_core_performance_reporting import nanoseconds_to_milliseconds

    with pytest.raises(ValueError, match="exact positive integer") as caught:
        nanoseconds_to_milliseconds(invalid)
    assert not isinstance(caught.value, OverflowError)


def test_deterministic_work_counts_cover_every_production_validation_boundary() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))

    for point in profile.points:
        assert point.work.canonical_relations == point.relation_count
        assert point.work.validated_relations == point.relation_count
        assert point.work.canonical_observations == point.observation_count
        assert point.work.validated_observations == point.observation_count
        assert point.work.readiness_receipts == point.receipt_count
        assert point.work.admission_cases == point.case_count
        assert point.work.total_operations == (
            2 * point.relation_count + 2 * point.observation_count + point.receipt_count + point.case_count
        )


@pytest.mark.parametrize(
    "field",
    (
        "canonical_relations",
        "validated_relations",
        "canonical_observations",
        "validated_observations",
        "readiness_receipts",
        "admission_cases",
    ),
)
def test_deterministic_work_refuses_disagreement_or_a_missing_dimension(field: str) -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    point = profile.points[-1]
    bad_work = replace(point.work, **{field: 0})
    changed = replace(point, work=bad_work)

    with pytest.raises(AssertionError, match="incremental validation work"):
        assert_large_set_envelope(replace(profile, points=(*profile.points[:-1], changed)))


def test_every_sample_binds_exact_scope_and_measured_change_bytes() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    by_size = {point.relation_count: point for point in profile.points}
    deterministic = (item for item in profile.consumer_samples if item.mode == "deterministic")
    for item in deterministic:
        sample = item.measured
        point = by_size[item.size]
        assert sample.complexity.change_id == point.change_digest == canonical.bytes_digest(point.change_content)
        assert sample.complexity.changed_bytes == point.changed_bytes == len(point.change_content)
        resolved = profile.resolver.resolve(sample.complexity.measurement)
        assert resolved.content == point.changed_bytes_measurement
        assert point.change_content == canonical.canonical_bytes(json.loads(point.change_content))
    for sample in profile.samples:
        parsed = json.loads(profile.resolver.resolve(sample.complexity.measurement).content)
        assert parsed["changed_bytes"] == sample.complexity.changed_bytes


def test_budget_samples_are_complete_consumer_runs_with_optional_work() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))

    assert {sample.mode for sample in profile.consumer_samples} == {"deterministic", "model_and_proof"}
    assert all(sample.total_reply_ms > 0 for sample in profile.consumer_samples)
    assert tuple(item.measured for item in profile.consumer_samples) == profile.samples


def test_measured_samples_fit_derived_envelope_and_excess_names_gate() -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    for sample in profile.samples:
        budget.check_budget(sample.complexity, sample.total_reply_ms, profile.budget, profile.resolver)

    selected = profile.samples[-1].complexity
    with pytest.raises(budget.BudgetGateFailure) as caught:
        budget.check_budget(selected, profile.budget.budget_ms + 1, profile.budget, profile.resolver)
    message = str(caught.value)
    assert selected.change_id in message
    assert f"{profile.budget.budget_ms + 1}ms>{profile.budget.budget_ms}ms" in message
    assert profile.budget.workload_class in message
    assert profile.budget.derivation_digest in message


def test_optional_model_and_proof_processing_share_total_consumer_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = measured_profile(read_workload(PERFORMANCE_FIXTURE))
    case = optional_consumer_case(profile)
    accepted = consume_records(
        case.request,
        (case.value,),
        case.context,
        case.custody,
        0,
        case.resolver,
        attachments=(case.attachment,),
        proof_trust=case.trust,
    )
    assert 0 < accepted.total_reply_ms <= profile.budget.budget_ms
    calls, _ = _instrument_optional_path(monkeypatch, profile)
    request = make_push_request(
        scope=case.request.scope,
        workload_class=profile.budget.workload_class,
        complexity=case.request.complexity,
        budget=profile.budget,
    )

    with pytest.raises(ConsumerContractError, match="measured budget gate failed") as caught:
        consume_records(
            request,
            (case.value,),
            case.context,
            case.custody,
            0,
            case.resolver,
            attachments=(case.attachment,),
            proof_trust=case.trust,
        )

    assert calls == ["model", "proof"]
    assert request.complexity.change_id in str(caught.value)
    assert profile.budget.derivation_digest in str(caught.value)
    assert replace(request.budget, derivation_digest="").derivation_digest == request.budget.derivation_digest
