"""access-control-prover task 7.1: the evidence-relation algebra and completeness value (offline).

Exhaustive join-table tests and algebraic-law tests for every relation pair, per the design's
"Abstract evidence domain" section and Req 11.1, 11.6, 11.7.
"""

from __future__ import annotations

import itertools


def _relations():
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation

    return tuple(EvidenceRelation)


def test_join_alternatives_matches_the_specified_table_for_every_pair() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, join_alternatives

    specified = {
        (EvidenceRelation.MUST, EvidenceRelation.MUST): EvidenceRelation.MUST,
        (EvidenceRelation.MUST, EvidenceRelation.NO): EvidenceRelation.MAY,
        (EvidenceRelation.MUST, EvidenceRelation.MAY): EvidenceRelation.MAY,
        (EvidenceRelation.MUST, EvidenceRelation.UNKNOWN): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.NO, EvidenceRelation.MUST): EvidenceRelation.MAY,
        (EvidenceRelation.NO, EvidenceRelation.NO): EvidenceRelation.NO,
        (EvidenceRelation.NO, EvidenceRelation.MAY): EvidenceRelation.MAY,
        (EvidenceRelation.NO, EvidenceRelation.UNKNOWN): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.MAY, EvidenceRelation.MUST): EvidenceRelation.MAY,
        (EvidenceRelation.MAY, EvidenceRelation.NO): EvidenceRelation.MAY,
        (EvidenceRelation.MAY, EvidenceRelation.MAY): EvidenceRelation.MAY,
        (EvidenceRelation.MAY, EvidenceRelation.UNKNOWN): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.UNKNOWN, EvidenceRelation.MUST): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.UNKNOWN, EvidenceRelation.NO): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.UNKNOWN, EvidenceRelation.MAY): EvidenceRelation.UNKNOWN,
        (EvidenceRelation.UNKNOWN, EvidenceRelation.UNKNOWN): EvidenceRelation.UNKNOWN,
    }
    for left, right in itertools.product(_relations(), repeat=2):
        assert join_alternatives(left, right) == specified[(left, right)], (left, right)


def test_join_alternatives_is_commutative_for_every_pair() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_alternatives

    for left, right in itertools.product(_relations(), repeat=2):
        assert join_alternatives(left, right) == join_alternatives(right, left), (left, right)


def test_join_alternatives_is_associative_for_every_triple() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_alternatives

    for left, middle, right in itertools.product(_relations(), repeat=3):
        left_join = join_alternatives(join_alternatives(left, middle), right)
        right_join = join_alternatives(left, join_alternatives(middle, right))
        assert left_join == right_join, (left, middle, right)


def test_join_alternatives_is_idempotent_for_every_relation() -> None:
    from openultrasast.semantic.obligations.abstract_domain import join_alternatives

    for relation in _relations():
        assert join_alternatives(relation, relation) == relation, relation


def test_join_alternatives_absorbs_every_relation_into_unknown() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, join_alternatives

    for relation in _relations():
        assert join_alternatives(relation, EvidenceRelation.UNKNOWN) is EvidenceRelation.UNKNOWN
        assert join_alternatives(EvidenceRelation.UNKNOWN, relation) is EvidenceRelation.UNKNOWN


def test_join_alternatives_never_manufactures_definite_evidence() -> None:
    # Req 11.6: join can never convert MAY or UNKNOWN (or a definite contradiction) into MUST or NO.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, join_alternatives

    for left, right in itertools.product(_relations(), repeat=2):
        joined = join_alternatives(left, right)
        if joined is EvidenceRelation.MUST:
            assert (left, right) == (EvidenceRelation.MUST, EvidenceRelation.MUST)
        if joined is EvidenceRelation.NO:
            assert (left, right) == (EvidenceRelation.NO, EvidenceRelation.NO)


def test_precision_order_places_definite_below_possible_below_unknown() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, at_least_as_precise

    assert at_least_as_precise(EvidenceRelation.MUST, EvidenceRelation.MUST)
    assert at_least_as_precise(EvidenceRelation.NO, EvidenceRelation.NO)
    assert at_least_as_precise(EvidenceRelation.MAY, EvidenceRelation.MAY)
    assert at_least_as_precise(EvidenceRelation.UNKNOWN, EvidenceRelation.UNKNOWN)
    assert at_least_as_precise(EvidenceRelation.MUST, EvidenceRelation.MAY)
    assert at_least_as_precise(EvidenceRelation.NO, EvidenceRelation.MAY)
    assert at_least_as_precise(EvidenceRelation.MAY, EvidenceRelation.UNKNOWN)
    assert at_least_as_precise(EvidenceRelation.MUST, EvidenceRelation.UNKNOWN)
    assert at_least_as_precise(EvidenceRelation.NO, EvidenceRelation.UNKNOWN)
    # MUST and NO are incomparable: neither order holds.
    assert not at_least_as_precise(EvidenceRelation.MUST, EvidenceRelation.NO)
    assert not at_least_as_precise(EvidenceRelation.NO, EvidenceRelation.MUST)
    # definite evidence never sits above uncertainty.
    assert not at_least_as_precise(EvidenceRelation.MAY, EvidenceRelation.MUST)
    assert not at_least_as_precise(EvidenceRelation.UNKNOWN, EvidenceRelation.MAY)


def test_join_alternatives_is_monotone_over_the_precision_order() -> None:
    # Req 11.6: widening one input along the precision order can only widen (or preserve) the join.
    from openultrasast.semantic.obligations.abstract_domain import at_least_as_precise, join_alternatives

    relations = _relations()
    for precise, wider, other in itertools.product(relations, repeat=3):
        if not at_least_as_precise(precise, wider):
            continue
        assert at_least_as_precise(join_alternatives(precise, other), join_alternatives(wider, other))


def test_conjoin_dimensions_applies_the_specified_priority() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, conjoin_dimensions

    must, no, may, unknown = (
        EvidenceRelation.MUST,
        EvidenceRelation.NO,
        EvidenceRelation.MAY,
        EvidenceRelation.UNKNOWN,
    )
    assert conjoin_dimensions((must, must, must, must, must)) is must
    # any NO produces NO, even beside UNKNOWN or MAY
    assert conjoin_dimensions((no, unknown, may, must)) is no
    # without NO, any UNKNOWN produces UNKNOWN
    assert conjoin_dimensions((unknown, may, must)) is unknown
    # without NO or UNKNOWN, any MAY produces MAY
    assert conjoin_dimensions((may, must, must)) is may


def test_conjoin_dimensions_is_order_and_duplication_invariant_for_every_triple() -> None:
    from openultrasast.semantic.obligations.abstract_domain import conjoin_dimensions

    for triple in itertools.product(_relations(), repeat=3):
        expected = conjoin_dimensions(triple)
        for permutation in itertools.permutations(triple):
            assert conjoin_dimensions(permutation) == expected, permutation
        assert conjoin_dimensions(triple + triple) == expected, triple


def test_conjoin_dimensions_batches_associatively_for_every_triple() -> None:
    from openultrasast.semantic.obligations.abstract_domain import conjoin_dimensions

    for left, middle, right in itertools.product(_relations(), repeat=3):
        batched_first = conjoin_dimensions((conjoin_dimensions((left, middle)), right))
        batched_last = conjoin_dimensions((left, conjoin_dimensions((middle, right))))
        assert batched_first == batched_last, (left, middle, right)


def test_aggregate_witnesses_applies_the_specified_precedence() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, aggregate_witnesses

    must, no, may, unknown = (
        EvidenceRelation.MUST,
        EvidenceRelation.NO,
        EvidenceRelation.MAY,
        EvidenceRelation.UNKNOWN,
    )
    # any MUST produces MUST, regardless of the rest
    assert aggregate_witnesses((must, no, may, unknown), discovery_complete=True) is must
    # without MUST, UNKNOWN takes precedence
    assert aggregate_witnesses((unknown, may, no), discovery_complete=True) is unknown
    # without MUST or UNKNOWN, MAY takes precedence over NO
    assert aggregate_witnesses((may, no, no), discovery_complete=True) is may
    # every witness definitely not governing
    assert aggregate_witnesses((no, no), discovery_complete=True) is no


def test_aggregate_witnesses_empty_set_depends_on_discovery_completeness() -> None:
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, aggregate_witnesses

    assert aggregate_witnesses((), discovery_complete=True) is EvidenceRelation.NO
    assert aggregate_witnesses((), discovery_complete=False) is EvidenceRelation.UNKNOWN


def test_aggregate_witnesses_is_order_invariant_for_every_triple() -> None:
    from openultrasast.semantic.obligations.abstract_domain import aggregate_witnesses

    for triple in itertools.product(_relations(), repeat=3):
        expected = aggregate_witnesses(triple, discovery_complete=False)
        for permutation in itertools.permutations(triple):
            assert aggregate_witnesses(permutation, discovery_complete=False) == expected, permutation


def test_aggregate_witnesses_adding_a_witness_never_weakens_governing_evidence() -> None:
    # Req 11.6/11.2 flavour: along NO < MAY < UNKNOWN < MUST, adding a witness can only move the
    # aggregate up that chain, so added evidence cannot turn a definite state into a weaker one.
    from openultrasast.semantic.obligations.abstract_domain import EvidenceRelation, aggregate_witnesses

    rank = {
        EvidenceRelation.NO: 0,
        EvidenceRelation.MAY: 1,
        EvidenceRelation.UNKNOWN: 2,
        EvidenceRelation.MUST: 3,
    }
    relations = _relations()
    for size in range(4):
        for witness_set in itertools.product(relations, repeat=size):
            before = rank[aggregate_witnesses(witness_set, discovery_complete=True)]
            for added in relations:
                after = rank[aggregate_witnesses(witness_set + (added,), discovery_complete=True)]
                assert after >= before, (witness_set, added)


def test_completeness_deduplicates_reasons_preserving_first_occurrence_order() -> None:
    from openultrasast.semantic.obligations.abstract_domain import Completeness

    completeness = Completeness(
        is_complete=False,
        reasons=("resolution:ambiguous_call", "summary:budget_cutoff", "resolution:ambiguous_call"),
    )
    assert completeness.reasons == ("resolution:ambiguous_call", "summary:budget_cutoff")


def test_completeness_keeps_same_reason_from_different_stages_separate() -> None:
    from openultrasast.semantic.obligations.abstract_domain import Completeness

    completeness = Completeness(
        is_complete=False,
        reasons=("resolution:ambiguous_call", "cfg:ambiguous_call", "resolution:ambiguous_call"),
    )
    assert completeness.reasons == ("resolution:ambiguous_call", "cfg:ambiguous_call")


def test_completeness_is_deterministic_for_equal_constructions() -> None:
    from openultrasast.semantic.obligations.abstract_domain import Completeness

    once = Completeness(is_complete=False, reasons=("a", "b", "a"))
    twice = Completeness(is_complete=False, reasons=("a", "b"))
    assert once == twice
    assert hash(once) == hash(twice)
    assert len({once, twice}) == 1
    assert Completeness(is_complete=True).reasons == ()


def test_join_completeness_is_complete_only_when_both_sides_are_complete() -> None:
    from openultrasast.semantic.obligations.abstract_domain import Completeness, join_completeness

    left = Completeness(is_complete=False, reasons=("resolution:ambiguous_call",))
    right = Completeness(is_complete=True, reasons=("summary:budget_cutoff",))
    joined = join_completeness(left, right)
    assert joined.is_complete is False
    assert joined.reasons == ("resolution:ambiguous_call", "summary:budget_cutoff")

    both_complete = join_completeness(Completeness(is_complete=True, reasons=("a",)), Completeness(is_complete=True, reasons=("a",)))
    assert both_complete.is_complete is True
    assert both_complete.reasons == ("a",)
