"""learning-harness task 2.4: aggregation, noise handling and honest denominators (offline)."""

from __future__ import annotations

import json

from openultrasast.learning.families import load_families
from openultrasast.learning.scoring import FamilyOutcome, PairFamilyScore


def _score(
    pair: str, outcome: FamilyOutcome, *, family: str = "access_control", slice_name: str = "vibe-py", **extra: object
) -> PairFamilyScore:
    runs = () if outcome == "unscorable" else (outcome,)
    return PairFamilyScore(pair=pair, family=family, slice=slice_name, runs=runs, outcome=outcome, **extra)  # type: ignore[arg-type]


def test_rates_use_only_the_scorable_rows_and_the_reasons_are_kept() -> None:
    from openultrasast.learning.scoring import aggregate

    taxonomy = load_families()
    scores = [
        _score("a", "pair_correct"),
        _score("b", "both_silent"),
        _score("c", "unscorable", unscorable_reason="identical_twin"),
        _score("d", "unscorable", unscorable_reason="identical_twin"),
        _score("e", "unscorable", unscorable_reason="unsupported_language"),
    ]
    metrics = aggregate(scores, taxonomy=taxonomy)["access_control"]
    assert metrics.scorable == 2 and metrics.unscorable == {"identical_twin": 2, "unsupported_language": 1}
    assert metrics.recall == 0.5 and metrics.silence == 1.0 and metrics.youden == 0.5
    assert metrics.outcomes == {"pair_correct": 1, "both_silent": 1}
    assert metrics.taxonomy_version == taxonomy.version
    json.dumps(metrics.to_dict())


def test_a_family_with_nothing_scorable_reports_no_rate_rather_than_a_perfect_one() -> None:
    from openultrasast.learning.scoring import aggregate

    metrics = aggregate([_score("a", "unscorable", unscorable_reason="identical_twin")], taxonomy=load_families())["access_control"]
    assert metrics.scorable == 0 and metrics.recall == 0.0 and metrics.silence == 0.0 and metrics.youden == 0.0


def test_directional_bias_separates_flagging_everything_from_saying_everything_is_safe() -> None:
    from openultrasast.learning.scoring import aggregate

    taxonomy = load_families()
    loud = aggregate([_score("a", "both_flagged"), _score("b", "both_flagged")], taxonomy=taxonomy)["access_control"]
    quiet = aggregate([_score("a", "both_silent"), _score("b", "both_silent")], taxonomy=taxonomy)["access_control"]
    assert loud.directional_bias == 1.0 and quiet.directional_bias == -1.0
    assert loud.youden == quiet.youden == 0.0  # the same Youden, opposite failures: the index is what tells them apart


def test_recall_at_a_fixed_false_positive_ceiling_is_forfeited_when_the_family_leaks() -> None:
    from openultrasast.learning.scoring import aggregate

    taxonomy = load_families()
    clean = [_score(str(index), "pair_correct") for index in range(9)] + [_score("x", "both_silent")]
    assert aggregate(clean, taxonomy=taxonomy, fpr_ceiling=0.1)["access_control"].fixed_fpr_recall == 0.9
    leaky = [_score(str(index), "pair_correct") for index in range(8)] + [_score("y", "both_flagged"), _score("z", "reversed")]
    metrics = aggregate(leaky, taxonomy=taxonomy, fpr_ceiling=0.1)["access_control"]
    assert metrics.recall == 0.9 and metrics.fixed_fpr_recall == 0.0  # a 20% leak rate buys no credit at a 10% ceiling


def test_negative_flips_and_the_reliable_change_test_compare_against_a_baseline() -> None:
    from openultrasast.learning.scoring import aggregate

    taxonomy = load_families()
    baseline = [_score(str(index), "pair_correct") for index in range(10)]
    same = aggregate(baseline, taxonomy=taxonomy, baseline=baseline)["access_control"]
    assert same.negative_flips == 0 and same.reliable_change is False
    broke_one = [_score("0", "both_silent")] + [_score(str(index), "pair_correct") for index in range(1, 10)]
    one = aggregate(broke_one, taxonomy=taxonomy, baseline=baseline)["access_control"]
    assert one.negative_flips == 1 and one.reliable_change is False  # one flip in ten is inside the noise
    broke_six = [_score(str(index), "both_silent") for index in range(6)] + [_score(str(index), "pair_correct") for index in range(6, 10)]
    six = aggregate(broke_six, taxonomy=taxonomy, baseline=baseline)["access_control"]
    assert six.negative_flips == 6 and six.reliable_change is True
    assert six.p_value is not None and six.p_value < 0.05


def test_metrics_are_reported_per_slice_when_asked() -> None:
    from openultrasast.learning.scoring import aggregate

    taxonomy = load_families()
    scores = [_score("a", "pair_correct", slice_name="vibe-py"), _score("b", "both_silent", slice_name="agent-vfc")]
    overall = aggregate(scores, taxonomy=taxonomy)
    assert set(overall) == {"access_control"} and overall["access_control"].scorable == 2
    per_slice = aggregate(scores, taxonomy=taxonomy, per_slice=True)
    assert set(per_slice) == {"vibe-py/access_control", "agent-vfc/access_control"}
    assert per_slice["vibe-py/access_control"].recall == 1.0 and per_slice["agent-vfc/access_control"].recall == 0.0


def test_the_sign_test_is_two_sided_and_symmetric() -> None:
    from openultrasast.learning.scoring import sign_test

    assert sign_test(0, 0) == 1.0
    assert sign_test(6, 0) == sign_test(0, 6) < 0.05
    assert sign_test(1, 0) > 0.05 and sign_test(3, 3) == 1.0


def test_every_family_figure_says_when_hierarchical_credit_could_not_apply() -> None:
    """Req 3.7: with a flat taxonomy no answer can earn partial credit, and the number must carry that."""
    from openultrasast.learning.families import Family, FamilyTaxonomy
    from openultrasast.learning.scoring import aggregate

    flat = load_families()
    metrics = aggregate([_score("a", "pair_correct")], taxonomy=flat)["access_control"]
    assert metrics.hierarchical_credit is False and metrics.to_dict()["hierarchical_credit"] is False
    nested = FamilyTaxonomy(
        version="test",
        families=(
            Family(id="injection", description="d", cwes=frozenset(), mechanisms=frozenset(), verifier="none"),
            Family(id="access_control", description="d", cwes=frozenset(), mechanisms=frozenset(), verifier="none", parent="injection"),
        ),
    )
    assert aggregate([_score("a", "pair_correct")], taxonomy=nested)["access_control"].hierarchical_credit is True
