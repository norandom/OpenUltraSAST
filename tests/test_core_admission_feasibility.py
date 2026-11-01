"""Label-blind arithmetic admission feasibility (Requirements 12.3 and 12.4)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from detection_core_fixtures import InMemoryContentResolver, stored_artifact

from openultrasast.core import canonical
from openultrasast.core.admission_feasibility import (
    AdmissionFeasibilityError,
    FeasibleCountAssignment,
    ThresholdFeasibility,
    evaluate_threshold_feasibility,
)
from openultrasast.core.admission_review import (
    AdmissionManifestV2,
    AdmissionThreshold,
    PopulationCensus,
    ScopeCensus,
    derive_census_digest,
    derive_census_payload_digest,
    derive_manifest_digest,
    derive_manifest_payload_digest,
    derive_threshold_set_digest,
)
from openultrasast.core.factpack import (
    IndependenceAttestation,
    ReviewIndependencePolicy,
    derive_independence_attestation_digest,
    derive_review_independence_policy_digest,
)
from openultrasast.core.measurement import (
    BaselineIdentity,
    Comparator,
    DenominatorPolicy,
    IntervalMethod,
    MetricId,
    ScopeKey,
    Statistic,
    standard_metric_rules,
)


def _scope() -> ScopeKey:
    return ScopeKey("access-control", "python")


def _census(
    *,
    pairs: int = 12,
    vulnerable: int = 12,
    fixed: int = 12,
    ordinary: int = 20,
    sites: int = 8,
    calls: int = 5,
) -> PopulationCensus:
    row = ScopeCensus(
        _scope(),
        vulnerable + fixed + ordinary,
        pairs,
        vulnerable,
        fixed,
        ordinary,
        sites,
        calls,
    )
    disclosure, _ = stored_artifact(b'{"conflicts":[]}', artifact_id="feasibility-conflicts")
    producer = canonical.content_digest("benchmark-producer")
    reviewer = canonical.content_digest("independent-reviewer")
    provisional_review = _attestation("0" * 64, producer, reviewer, disclosure)
    provisional = PopulationCensus(canonical.content_digest("population"), (row,), False, "0" * 64, provisional_review, "0" * 64)
    payload = derive_census_payload_digest(provisional)
    reviewed = replace(provisional, census_payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    return replace(reviewed, census_digest=derive_census_digest(reviewed))


def _policy(scope: ScopeKey | None = None) -> DenominatorPolicy:
    rules = standard_metric_rules((scope or _scope(),))
    return DenominatorPolicy(rules, IntervalMethod.WILSON_95, "")


def _with_extra_census_row(census: PopulationCensus) -> PopulationCensus:
    extra = ScopeCensus(ScopeKey("out-of-scope", "javascript"), 300, 100, 100, 100, 100, 500, 200)
    rows = tuple(sorted((*census.rows, extra), key=lambda item: item.scope))
    draft = replace(census, rows=rows, census_payload_digest="0" * 64, census_digest="0" * 64)
    payload = derive_census_payload_digest(draft)
    old = census.review
    review = _attestation(payload, old.producer_identity, old.reviewer_identity, old.conflict_disclosure)
    reviewed = replace(draft, census_payload_digest=payload, review=review)
    return replace(reviewed, census_digest=derive_census_digest(reviewed))


def _thresholds(*values: AdmissionThreshold) -> tuple[AdmissionThreshold, ...]:
    return tuple(sorted(values, key=lambda item: (item.metric_id.value, item.statistic.value)))


def _threshold(
    metric: MetricId,
    statistic: Statistic,
    comparator: Comparator,
    target: float,
) -> AdmissionThreshold:
    return AdmissionThreshold(metric, statistic, comparator, target)


def _attestation(
    subject: str,
    producer: str,
    reviewer: str,
    disclosure: canonical.ContentRef,
) -> IndependenceAttestation:
    provisional = IndependenceAttestation(subject, producer, reviewer, disclosure, "0" * 64)
    return replace(provisional, attestation_digest=derive_independence_attestation_digest(provisional))


def _review_policy(reviewer: str) -> ReviewIndependencePolicy:
    stores = ("trusted-store",)
    digest = derive_review_independence_policy_digest((reviewer,), (), stores, 4096)
    return ReviewIndependencePolicy((reviewer,), (), stores, 4096, digest)


def _baseline(
    census: PopulationCensus,
    denominator: DenominatorPolicy,
    threshold_digest: str,
) -> BaselineIdentity:
    return BaselineIdentity(
        "arm-a",
        census.population_digest,
        canonical.content_digest("freeze"),
        denominator.rules[0].scopes,
        (canonical.content_digest("contract"),),
        canonical.content_digest("catalog"),
        canonical.content_digest("fact-schema"),
        canonical.content_digest("fact-set"),
        canonical.content_digest("acquisition"),
        "analyzer-v2",
        canonical.content_digest("configuration"),
        (),
        None,
        denominator.policy_digest,
        threshold_digest,
        canonical.content_digest("outcomes"),
    )


def _reviewed_manifest(
    census: PopulationCensus,
    denominator: DenominatorPolicy,
    thresholds: tuple[AdmissionThreshold, ...],
) -> tuple[AdmissionManifestV2, ReviewIndependencePolicy, InMemoryContentResolver]:
    disclosure, resolver = stored_artifact(b'{"conflicts":[]}', artifact_id="feasibility-conflicts")
    producer = canonical.content_digest("benchmark-producer")
    reviewer = canonical.content_digest("independent-reviewer")
    threshold_digest = derive_threshold_set_digest(thresholds)
    baseline = _baseline(census, denominator, threshold_digest)
    provisional_review = _attestation("0" * 64, producer, reviewer, disclosure)
    provisional = AdmissionManifestV2(
        "0" * 64,
        provisional_review,
        True,
        False,
        baseline,
        census,
        (canonical.content_digest("readiness"),),
        canonical.content_digest("custody"),
        denominator.policy_digest,
        thresholds,
        threshold_digest,
        canonical.content_digest("threshold-lineage"),
        canonical.content_digest("validation-context"),
        "0" * 64,
    )
    payload = derive_manifest_payload_digest(provisional)
    reviewed = replace(provisional, manifest_payload_digest=payload, review=_attestation(payload, producer, reviewer, disclosure))
    return replace(reviewed, manifest_digest=derive_manifest_digest(reviewed)), _review_policy(reviewer), resolver


def _evaluate(
    census: PopulationCensus,
    denominator: DenominatorPolicy,
    thresholds: tuple[AdmissionThreshold, ...],
) -> ThresholdFeasibility:
    manifest, review_policy, resolver = _reviewed_manifest(census, denominator, thresholds)
    return evaluate_threshold_feasibility(manifest, denominator, review_policy, resolver)


def test_stale_reviewed_census_identity_is_refused_before_capacity_use() -> None:
    thresholds = (_threshold(MetricId.SEMANTIC_STAGE_COVERAGE, Statistic.COUNT, Comparator.AT_LEAST, 50.0),)
    census = _census(sites=12)
    denominator = _policy()
    manifest, review_policy, resolver = _reviewed_manifest(census, denominator, thresholds)
    changed_row = replace(census.rows[0], semantic_site_capacity=99)
    stale_census = replace(census, rows=(changed_row,))
    stale_manifest = replace(manifest, census=stale_census)

    with pytest.raises(AdmissionFeasibilityError, match="census payload"):
        evaluate_threshold_feasibility(stale_manifest, denominator, review_policy, resolver)


def test_enumerates_capacity_witnesses_for_every_metric_family() -> None:
    thresholds = _thresholds(
        _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.COUNT, Comparator.AT_LEAST, 6.0),
        _threshold(MetricId.VULNERABLE_RECALL, Statistic.RATE, Comparator.AT_LEAST, 0.5),
        _threshold(MetricId.FIXED_FALSE_ALARM_RATE, Statistic.RATE, Comparator.AT_MOST, 0.1),
        _threshold(MetricId.FIXED_FALSE_ALARM_RATE, Statistic.WILSON_UPPER, Comparator.AT_MOST, 0.25),
        _threshold(MetricId.ORDINARY_FALSE_ALARMS_PER_100, Statistic.PER_100, Comparator.AT_MOST, 5.0),
        _threshold(MetricId.ORDINARY_FALSE_ALARMS_PER_100, Statistic.WILSON_LOWER, Comparator.AT_MOST, 0.0),
        _threshold(MetricId.PRECISION, Statistic.WILSON_LOWER, Comparator.AT_LEAST, 0.7),
        _threshold(MetricId.SEMANTIC_STAGE_COVERAGE, Statistic.COUNT, Comparator.AT_LEAST, 4.0),
        _threshold(MetricId.MODEL_SUCCESS_RATE, Statistic.WILSON_UPPER, Comparator.AT_LEAST, 0.9),
    )

    result = _evaluate(_census(), _policy(), thresholds)

    witnesses = {item.metric_id: (item.numerator, item.denominator) for item in result.witnesses}
    assert witnesses == {
        MetricId.PAIRED_CORRECTNESS: (12, 12),
        MetricId.VULNERABLE_RECALL: (12, 12),
        MetricId.FIXED_FALSE_ALARM_RATE: (0, 12),
        MetricId.ORDINARY_FALSE_ALARMS_PER_100: (0, 20),
        MetricId.PRECISION: (12, 12),
        MetricId.SEMANTIC_STAGE_COVERAGE: (8, 8),
        MetricId.MODEL_SUCCESS_RATE: (5, 5),
    }
    assert result.census_digest == _census().census_digest
    assert result.denominator_policy_digest == _policy().policy_digest
    assert len(result.threshold_set_digest) == 64
    assert len(result.feasibility_digest) == 64


def test_extra_census_scope_does_not_change_claimed_scope_feasibility() -> None:
    threshold = _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.COUNT, Comparator.AT_LEAST, 12.0)

    result = _evaluate(_with_extra_census_row(_census()), _policy(), (threshold,))

    assert result.witnesses == (FeasibleCountAssignment(MetricId.PAIRED_CORRECTNESS, 12, 12),)


def test_one_assignment_must_jointly_satisfy_grouped_statistics() -> None:
    thresholds = _thresholds(
        _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.COUNT, Comparator.AT_LEAST, 10.0),
        _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.RATE, Comparator.AT_LEAST, 0.8),
        _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.WILSON_LOWER, Comparator.AT_LEAST, 0.5),
        _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.WILSON_UPPER, Comparator.AT_LEAST, 0.8),
    )

    result = _evaluate(_census(), _policy(), thresholds)

    assert [(item.metric_id, item.numerator, item.denominator) for item in result.witnesses] == [(MetricId.PAIRED_CORRECTNESS, 12, 12)]


def test_historical_impossible_denominator_is_configuration_refusal() -> None:
    threshold = _threshold(
        MetricId.VULNERABLE_RECALL,
        Statistic.WILSON_LOWER,
        Comparator.AT_LEAST,
        0.5,
    )

    with pytest.raises(AdmissionFeasibilityError, match="vulnerable_recall.*arithmetically impossible"):
        _evaluate(
            _census(pairs=2, vulnerable=2, fixed=2, ordinary=4),
            _policy(),
            (threshold,),
        )


@pytest.mark.parametrize(
    ("census", "threshold"),
    (
        (
            _census(pairs=0, vulnerable=0, fixed=0, ordinary=4),
            _threshold(MetricId.VULNERABLE_RECALL, Statistic.COUNT, Comparator.AT_LEAST, 0.0),
        ),
        (
            _census(calls=0),
            _threshold(MetricId.MODEL_SUCCESS_RATE, Statistic.RATE, Comparator.AT_LEAST, 0.0),
        ),
        (
            _census(pairs=0, vulnerable=0),
            _threshold(MetricId.PRECISION, Statistic.RATE, Comparator.AT_LEAST, 1.0),
        ),
    ),
)
def test_zero_or_absent_success_capacity_never_becomes_a_clean_zero(
    census: PopulationCensus,
    threshold: AdmissionThreshold,
) -> None:
    with pytest.raises(AdmissionFeasibilityError, match="arithmetically impossible"):
        _evaluate(census, _policy(), (threshold,))


def test_precision_enumerates_a_false_positive_denominator_when_no_true_case_exists() -> None:
    threshold = _threshold(MetricId.PRECISION, Statistic.RATE, Comparator.AT_LEAST, 0.0)

    result = _evaluate(_census(pairs=0, vulnerable=0), _policy(), (threshold,))

    assert [(item.numerator, item.denominator) for item in result.witnesses] == [(0, 1)]


def test_fixed_metric_algebra_rejects_wrong_comparator_or_statistic() -> None:
    reversed_comparator = _threshold(
        MetricId.VULNERABLE_RECALL,
        Statistic.RATE,
        Comparator.AT_MOST,
        1.0,
    )
    wrong_statistic = _threshold(
        MetricId.ORDINARY_FALSE_ALARMS_PER_100,
        Statistic.RATE,
        Comparator.AT_MOST,
        5.0,
    )

    with pytest.raises(AdmissionFeasibilityError, match="comparator direction"):
        _evaluate(_census(), _policy(), (reversed_comparator,))
    with pytest.raises(AdmissionFeasibilityError, match="per_100"):
        _evaluate(_census(), _policy(), (wrong_statistic,))


def test_policy_scope_must_match_the_label_blind_census() -> None:
    threshold = _threshold(MetricId.PAIRED_CORRECTNESS, Statistic.COUNT, Comparator.AT_LEAST, 1.0)

    with pytest.raises(AdmissionFeasibilityError, match="scope"):
        _evaluate(_census(), _policy(ScopeKey("other", "python")), (threshold,))
