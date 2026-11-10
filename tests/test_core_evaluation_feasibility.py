"""Per-arm/per-scope V3 pre-spend feasibility."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_core_evaluation_plan_review import _attestation, _case, _policy

from openultrasast.core import canonical
from openultrasast.core.evaluation_feasibility import (
    EvaluationFeasibilityError,
    FeasibilityStatusV3,
    derive_evaluation_feasibility,
    validate_evaluation_feasibility,
)
from openultrasast.core.evaluation_measurement import (
    MetricId,
    ScopeKey,
    Statistic,
)
from openultrasast.core.evaluation_plan import (
    EcosystemOrdinaryCensusV3,
    create_evaluation_plan_declaration,
    derive_evaluation_baselines,
    derive_evaluation_census_digest,
    derive_evaluation_census_payload_digest,
    derive_evaluation_plan_manifest_digest,
    derive_evaluation_plan_manifest_payload_digest,
)


def _rebind_census(manifest, census):
    provisional = replace(
        census,
        payload_digest="0" * 64,
        review=replace(census.review, subject_digest="0" * 64, attestation_digest="0" * 64),
        census_digest="0" * 64,
    )
    payload = derive_evaluation_census_payload_digest(provisional)
    review = _attestation(
        payload,
        census.review.producer_identity,
        census.review.reviewer_identity,
        census.review.conflict_disclosure,
    )
    reviewed = replace(provisional, payload_digest=payload, review=review)
    census = replace(reviewed, census_digest=derive_evaluation_census_digest(reviewed))
    return _rebind_manifest(manifest, census=census)


def _rebind_manifest(manifest, *, census=None, configurations=None):
    declaration = manifest.declaration
    if configurations is not None:
        inputs = tuple(sorted({slot.input_identity_digest for slot in declaration.expected_observation_slots}))
        declaration = create_evaluation_plan_declaration(
            population_digest=declaration.population_digest,
            freeze_digest=declaration.freeze_digest,
            input_set_digest=declaration.input_set_digest,
            arm_configurations=tuple(configurations),
            input_identity_digests=inputs,
        )
    draft = replace(
        manifest,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        census=manifest.census if census is None else census,
        payload_digest="0" * 64,
        review=replace(manifest.review, subject_digest="0" * 64, attestation_digest="0" * 64),
        manifest_digest="0" * 64,
    )
    payload = derive_evaluation_plan_manifest_payload_digest(draft)
    review = _attestation(
        payload,
        manifest.review.producer_identity,
        manifest.review.reviewer_identity,
        manifest.review.conflict_disclosure,
    )
    reviewed = replace(draft, payload_digest=payload, review=review)
    return replace(reviewed, manifest_digest=derive_evaluation_plan_manifest_digest(reviewed))


def _feasible_manifest():
    _, manifest, policy, resolver = _case()
    configurations = []
    for config in manifest.declaration.arm_configurations:
        sufficiency = []
        for rule in config.sufficiency_rules:
            precision = tuple(replace(item, maximum_wilson_width=100.0, rule_digest="") for item in rule.precision_rules)
            sufficiency.append(replace(rule, precision_rules=precision, rule_digest=""))
        configurations.append(replace(config, sufficiency_rules=tuple(sufficiency), configuration_identity_digest=""))
    inputs = tuple(sorted({slot.input_identity_digest for slot in manifest.declaration.expected_observation_slots}))
    declaration = create_evaluation_plan_declaration(
        population_digest=manifest.declaration.population_digest,
        freeze_digest=manifest.declaration.freeze_digest,
        input_set_digest=manifest.declaration.input_set_digest,
        arm_configurations=tuple(configurations),
        input_identity_digests=inputs,
    )
    draft = replace(
        manifest,
        declaration=declaration,
        baselines=derive_evaluation_baselines(declaration),
        payload_digest="0" * 64,
        review=replace(manifest.review, subject_digest="0" * 64, attestation_digest="0" * 64),
        manifest_digest="0" * 64,
    )
    payload = derive_evaluation_plan_manifest_payload_digest(draft)
    review = _attestation(
        payload, manifest.review.producer_identity, manifest.review.reviewer_identity, manifest.review.conflict_disclosure
    )
    reviewed = replace(draft, payload_digest=payload, review=review)
    return replace(reviewed, manifest_digest=derive_evaluation_plan_manifest_digest(reviewed)), policy, resolver


def test_derivation_emits_one_canonical_row_per_arm_scope_without_quality_decisions() -> None:
    _, manifest, policy, resolver = _case()
    result = derive_evaluation_feasibility(manifest, policy, resolver)
    expected_keys = tuple((config.arm_id, scope) for config in manifest.declaration.arm_configurations for scope in config.exact_scopes)
    assert tuple((row.key.arm_id, row.key.scope) for row in result.rows) == expected_keys
    assert result.may_spend is False
    assert all(row.status is FeasibilityStatusV3.INSUFFICIENT for row in result.rows)
    assert not hasattr(result, "decision")
    assert not hasattr(result, "authorize")


def test_threshold_witnesses_use_exact_v2_preserving_capacities() -> None:
    _, manifest, policy, resolver = _case()
    row = derive_evaluation_feasibility(manifest, policy, resolver).rows[0]
    by_metric = dict(zip(tuple(MetricId), row.threshold_witnesses, strict=True))
    assert (by_metric[MetricId.PAIRED_CORRECTNESS].witness_numerator, by_metric[MetricId.PAIRED_CORRECTNESS].witness_denominator) == (4, 4)
    assert (
        by_metric[MetricId.FIXED_FALSE_ALARM_RATE].witness_numerator,
        by_metric[MetricId.FIXED_FALSE_ALARM_RATE].witness_denominator,
    ) == (0, 4)
    assert (
        by_metric[MetricId.ORDINARY_FALSE_ALARMS_PER_100].witness_numerator,
        by_metric[MetricId.ORDINARY_FALSE_ALARMS_PER_100].witness_denominator,
    ) == (0, 12)
    assert (by_metric[MetricId.PRECISION].witness_numerator, by_metric[MetricId.PRECISION].witness_denominator) == (4, 4)


def test_precision_fallback_and_zero_denominator_are_label_blind_and_insufficient() -> None:
    census, manifest, policy, resolver = _case()
    base = census.scope_rows[0]
    fallback = replace(base, pair_count=0, vulnerable_side_count=0, fixed_side_count=0)
    changed = replace(census, scope_rows=(fallback,))
    fallback_manifest = _rebind_census(manifest, changed)
    row = derive_evaluation_feasibility(fallback_manifest, policy, resolver).rows[0]
    precision = row.threshold_witnesses[tuple(MetricId).index(MetricId.PRECISION)]
    assert (precision.witness_numerator, precision.witness_denominator) == (0, 1)

    zero = replace(base, pair_count=0, vulnerable_side_count=0, fixed_side_count=0)
    zero_census = replace(
        census,
        scope_rows=(zero,),
        ordinary_rows=(EcosystemOrdinaryCensusV3("python", 0),),
    )
    zero_manifest = _rebind_census(manifest, zero_census)
    result = derive_evaluation_feasibility(zero_manifest, policy, resolver)
    precision = result.rows[0].threshold_witnesses[tuple(MetricId).index(MetricId.PRECISION)]
    assert (precision.witness_numerator, precision.witness_denominator) == (0, 0)
    assert precision.attainable is False
    assert result.may_spend is False


@pytest.mark.parametrize(
    ("metric_id", "statistic", "target"),
    (
        (MetricId.PAIRED_CORRECTNESS, Statistic.COUNT, 1.0),
        (MetricId.PAIRED_CORRECTNESS, Statistic.RATE, 0.5),
        (MetricId.ORDINARY_FALSE_ALARMS_PER_100, Statistic.PER_100, 1.0),
        (MetricId.PAIRED_CORRECTNESS, Statistic.WILSON_LOWER, 0.0),
        (MetricId.FIXED_FALSE_ALARM_RATE, Statistic.WILSON_UPPER, 1.0),
    ),
)
def test_every_threshold_statistic_uses_the_fixed_comparator(metric_id: MetricId, statistic: Statistic, target: float) -> None:
    _, manifest, policy, resolver = _case()
    configurations = []
    for config in manifest.declaration.arm_configurations:
        thresholds = tuple(
            replace(item, statistic=statistic, target=target, threshold_digest="") if item.metric_id is metric_id else item
            for item in config.thresholds
        )
        configurations.append(replace(config, thresholds=thresholds, configuration_identity_digest=""))
    changed = _rebind_manifest(manifest, configurations=configurations)
    result = derive_evaluation_feasibility(changed, policy, resolver)
    index = tuple(MetricId).index(metric_id)
    assert all(row.threshold_witnesses[index].attainable for row in result.rows)


def test_minimum_denominator_and_wilson_width_fail_independently() -> None:
    _, manifest, policy, resolver = _case()

    def changed_manifest(*, minimum: int, width: float):
        configurations = []
        for config in manifest.declaration.arm_configurations:
            rules = []
            for rule in config.sufficiency_rules:
                precision = tuple(
                    replace(item, minimum_denominator=minimum, maximum_wilson_width=width, rule_digest="") for item in rule.precision_rules
                )
                rules.append(replace(rule, precision_rules=precision, rule_digest=""))
            configurations.append(replace(config, sufficiency_rules=tuple(rules), configuration_identity_digest=""))
        return _rebind_manifest(manifest, configurations=configurations)

    minimum_failure = derive_evaluation_feasibility(changed_manifest(minimum=100, width=100.0), policy, resolver)
    width_failure = derive_evaluation_feasibility(changed_manifest(minimum=1, width=0.0001), policy, resolver)
    assert all(not row.sufficiency_results[0].interval_precision_passed for row in minimum_failure.rows)
    assert all(not row.sufficiency_results[0].interval_precision_passed for row in width_failure.rows)


def test_single_insufficient_row_blocks_shared_spend_and_is_reproducible() -> None:
    _, manifest, policy, resolver = _case()
    first = derive_evaluation_feasibility(manifest, policy, resolver)
    second = derive_evaluation_feasibility(manifest, policy, resolver)
    assert first == second
    assert first.feasibility_digest == second.feasibility_digest
    assert not first.may_spend


def test_complete_feasible_plan_yields_one_reproducible_may_spend_digest() -> None:
    manifest, policy, resolver = _feasible_manifest()
    first = derive_evaluation_feasibility(manifest, policy, resolver)
    second = derive_evaluation_feasibility(manifest, policy, resolver)
    assert first == second
    assert first.may_spend is True
    assert all(row.status is FeasibilityStatusV3.FEASIBLE for row in first.rows)


def test_missing_extra_duplicate_cross_key_and_caller_summaries_are_refused() -> None:
    _, manifest, policy, resolver = _case()
    value = derive_evaluation_feasibility(manifest, policy, resolver)
    mutations = (
        {"rows": value.rows[:-1], "feasibility_digest": ""},
        {"rows": value.rows + (value.rows[0],), "feasibility_digest": ""},
        {"may_spend": not value.may_spend, "feasibility_digest": ""},
        {"plan_manifest_digest": "0" * 64, "feasibility_digest": ""},
    )
    for changes in mutations:
        with pytest.raises(EvaluationFeasibilityError):
            validate_evaluation_feasibility(manifest, replace(value, **changes), policy, resolver)

    with pytest.raises(EvaluationFeasibilityError):
        replace(value, rows=tuple(reversed(value.rows)), feasibility_digest="")
    with pytest.raises(EvaluationFeasibilityError):
        replace(value, rows=(replace(value.rows[0], key=value.rows[1].key, result_digest=""),) + value.rows[1:])

    changed_witness = replace(value.rows[0].threshold_witnesses[0], attainable=False, witness_digest="")
    changed_row = replace(
        value.rows[0],
        threshold_witnesses=(changed_witness,) + value.rows[0].threshold_witnesses[1:],
        status=FeasibilityStatusV3.INSUFFICIENT,
        reasons=("threshold_unreachable",),
        result_digest="",
    )
    rehashed = replace(value, rows=(changed_row,) + value.rows[1:], feasibility_digest="")
    with pytest.raises(EvaluationFeasibilityError):
        validate_evaluation_feasibility(manifest, rehashed, policy, resolver)


def test_review_trust_independence_and_subject_are_revalidated_before_arithmetic() -> None:
    _, manifest, policy, resolver = _case()
    wrong_subject = replace(manifest.review, subject_digest="0" * 64)
    self_review = replace(
        manifest.review,
        producer_identity=manifest.review.reviewer_identity,
        attestation_digest="0" * 64,
    )
    for review in (wrong_subject, self_review):
        with pytest.raises(EvaluationFeasibilityError, match="reviewed plan"):
            derive_evaluation_feasibility(replace(manifest, review=review), policy, resolver)
    with pytest.raises((canonical.ArtifactResolutionError, canonical.ArtifactValidationError)):
        derive_evaluation_feasibility(
            manifest,
            _policy(manifest.review.reviewer_identity, stores=("other-store",)),
            resolver,
        )


def test_scope_and_ecosystem_mismatch_fail_before_lookup_with_controlled_errors() -> None:
    census, manifest, policy, resolver = _case()
    wrong_scope = replace(census.scope_rows[0], scope=ScopeKey("injection", "python"))
    wrong_scope_manifest = _rebind_census(manifest, replace(census, scope_rows=(wrong_scope,)))
    wrong_ecosystem_manifest = _rebind_census(
        manifest,
        replace(census, ordinary_rows=(EcosystemOrdinaryCensusV3("javascript", 12),)),
    )
    for changed in (wrong_scope_manifest, wrong_ecosystem_manifest):
        with pytest.raises(EvaluationFeasibilityError, match="reviewed plan"):
            derive_evaluation_feasibility(changed, policy, resolver)


def test_malformed_manifest_and_feasibility_fail_through_contract_error() -> None:
    _, manifest, policy, resolver = _case()
    with pytest.raises(EvaluationFeasibilityError):
        derive_evaluation_feasibility(None, policy, resolver)  # type: ignore[arg-type]
    with pytest.raises(EvaluationFeasibilityError):
        validate_evaluation_feasibility(manifest, None, policy, resolver)  # type: ignore[arg-type]
