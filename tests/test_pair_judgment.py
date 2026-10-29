"""Task 10.4 -- one judgment per path (Reqs 4.1-4.3, 11.2-11.4).

Fixtures build WitnessMatch and DominanceEvidence directly; the truth table
pinned here is the design's: a witness governs only when every dimension is
MUST; one definite NO with the rest definite makes the path unguarded; any
MAY or UNKNOWN among required relations makes it indeterminate.
"""

import pytest

from openultrasast.semantic.obligations.abstract_domain import (
    Completeness,
    EvidenceRelation,
    PairJudgment,
    WitnessMatch,
)
from openultrasast.semantic.obligations.cfg_dominance import DominanceEvidence
from openultrasast.semantic.obligations.judgment import judgment_for_path
from openultrasast.semantic.obligations.operations import Operation

PATH = "src/C.java"


def _operation() -> Operation:
    return Operation(PATH, 4, "handle", "protected_read", "f:op", "book", ("path_guard", "ownership_check"))


def _match(relation: EvidenceRelation) -> WitnessMatch:
    return WitnessMatch(
        relation=relation,
        resource_relation=EvidenceRelation.MUST,
        authority_relation=EvidenceRelation.MUST,
        evidence=("witness:f:guard", "operation:f:op"),
    )


def _dominance(relation: EvidenceRelation) -> DominanceEvidence:
    return DominanceEvidence(relation=relation, guard_effect="throws")


def _complete() -> Completeness:
    return Completeness(is_complete=True)


def _matches_by_kind(
    path_guard: tuple[tuple[WitnessMatch, DominanceEvidence], ...],
    ownership_check: tuple[tuple[WitnessMatch, DominanceEvidence], ...],
) -> dict[str, tuple[tuple[WitnessMatch, DominanceEvidence], ...]]:
    return {"path_guard": path_guard, "ownership_check": ownership_check}


def test_must_and_no_produce_unguarded_with_missing_kind() -> None:
    judgment = judgment_for_path(
        _operation(),
        _matches_by_kind(((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST)),), ()),
        _complete(),
    )
    assert judgment.judgment is PairJudgment.UNGUARDED
    assert judgment.missing == ("ownership_check",)


def test_all_must_produces_discharged() -> None:
    pairs = ((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST)),)
    judgment = judgment_for_path(_operation(), _matches_by_kind(pairs, pairs), _complete())
    assert judgment.judgment is PairJudgment.DISCHARGED
    assert judgment.missing == ()


def test_may_and_no_produce_indeterminate() -> None:
    judgment = judgment_for_path(
        _operation(),
        _matches_by_kind(
            ((_match(EvidenceRelation.MAY), _dominance(EvidenceRelation.MUST)),),
            (),
        ),
        _complete(),
    )
    assert judgment.judgment is PairJudgment.INDETERMINATE


def test_unknown_match_relation_produces_indeterminate() -> None:
    judgment = judgment_for_path(
        _operation(),
        _matches_by_kind(
            ((_match(EvidenceRelation.UNKNOWN), _dominance(EvidenceRelation.MUST)),),
            (),
        ),
        _complete(),
    )
    assert judgment.judgment is PairJudgment.INDETERMINATE


def test_unknown_dominance_produces_indeterminate() -> None:
    judgment = judgment_for_path(
        _operation(),
        _matches_by_kind(
            ((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.UNKNOWN)),),
            (),
        ),
        _complete(),
    )
    assert judgment.judgment is PairJudgment.INDETERMINATE


def test_empty_witnesses_with_complete_discovery_are_unguarded() -> None:
    judgment = judgment_for_path(_operation(), _matches_by_kind((), ()), _complete())
    assert judgment.judgment is PairJudgment.UNGUARDED
    assert judgment.missing == ("ownership_check", "path_guard")


def test_empty_witnesses_without_discovery_are_indeterminate() -> None:
    judgment = judgment_for_path(_operation(), _matches_by_kind((), ()), _complete(), discovery_complete=False)
    assert judgment.judgment is PairJudgment.INDETERMINATE


def test_incomplete_path_completeness_is_indeterminate() -> None:
    pairs = ((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST)),)
    judgment = judgment_for_path(
        _operation(),
        _matches_by_kind(pairs, pairs),
        Completeness(is_complete=False, reasons=("resolution:no_candidate",)),
    )
    assert judgment.judgment is PairJudgment.INDETERMINATE


def test_matches_are_carried_in_the_judgment() -> None:
    must_pair = (_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST))
    judgment = judgment_for_path(_operation(), _matches_by_kind((must_pair,), (must_pair,)), _complete())
    assert judgment.matches == (_match(EvidenceRelation.MUST),)
    assert judgment.matches[0].evidence == ("witness:f:guard", "operation:f:op")


def test_judgment_is_deterministic() -> None:
    pairs = ((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST)),)
    first = judgment_for_path(_operation(), _matches_by_kind(pairs, ()), _complete())
    second = judgment_for_path(_operation(), _matches_by_kind(pairs, ()), _complete())
    assert first == second


def test_empty_requires_with_no_witnesses_is_discharged() -> None:
    operation = Operation(PATH, 4, "handle", "protected_read", "f:op", "book", ())
    judgment = judgment_for_path(operation, {}, _complete())
    assert judgment.judgment is PairJudgment.DISCHARGED


def test_no_witness_for_one_kind_only_reports_that_kind() -> None:
    must_pair = ((_match(EvidenceRelation.MUST), _dominance(EvidenceRelation.MUST)),)
    judgment = judgment_for_path(_operation(), _matches_by_kind(must_pair, ()), _complete())
    assert judgment.judgment is PairJudgment.UNGUARDED
    assert judgment.missing == ("ownership_check",)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
