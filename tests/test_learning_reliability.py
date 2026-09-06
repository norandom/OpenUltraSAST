"""Every round says whether its decision was distinguishable from noise (learning-harness, Req 9.5).

The spec built `sign_test` and `reliable_change` and the acceptance rule never calls either: `decide` compares raw
deltas. On a detector where 11 of 20 pairs disagree with themselves between runs, a raw delta is mostly noise, and
a rule that brittle is exactly what makes someone reach for a deterministic decoder to prop it up.

Changing Req 9.5 is a maintainer's call, so this does not change the decision — it records, beside every decision,
the two-sided sign test over the pairs that actually changed. After a few rounds the journal says plainly whether
any of those decisions could be told from a coin flip.
"""

from __future__ import annotations

from openultrasast.learning.acceptance import reliability


def test_a_clean_sweep_of_the_minibatch_is_distinguishable_from_noise() -> None:
    result = reliability(better=8, worse=0)
    assert result.better == 8 and result.worse == 0
    assert result.p_value < 0.05 and result.reliable is True


def test_two_pairs_moving_the_right_way_is_not() -> None:
    """n = 2 cannot reach p < 0.05 whatever it does, and a rule that treats it as evidence is measuring nothing."""
    result = reliability(better=2, worse=0)
    assert result.p_value == 0.5 and result.reliable is False


def test_a_round_that_changed_nothing_reports_no_evidence_rather_than_agreement() -> None:
    result = reliability(better=0, worse=0)
    assert result.p_value == 1.0 and result.reliable is False


def test_an_even_split_is_never_reliable_however_large() -> None:
    assert reliability(better=20, worse=20).reliable is False


def test_the_round_journals_the_reliability_of_its_own_decision() -> None:
    from openultrasast.learning.journal import RoundRecord

    record = RoundRecord(
        round=1,
        family="injection",
        hypothesis="h",
        levers=("checklist",),
        predicted_affected=(),
        predicted_at_risk=(),
        outcome="accepted",
        train_better=8,
        train_worse=0,
        holdout_better=1,
        holdout_worse=0,
    )
    payload = record.to_dict()
    assert payload["train_reliable"] is True and payload["train_p_value"] < 0.05
    assert payload["holdout_reliable"] is False, "one pair is not evidence, and the record says so"
