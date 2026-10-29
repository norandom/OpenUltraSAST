"""Task 10.4 -- one judgment per path (Reqs 4.1-4.3, 11.2-11.4).

A witness governs an obligation only when every required relation is MUST.
With complete evidence and no governing witness for a required kind the path
is unguarded; any MAY or UNKNOWN among required relations, or an incomplete
path enumeration, makes it indeterminate. Engine module: no target names.
"""

from collections.abc import Mapping

from .abstract_domain import (
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    WitnessMatch,
    aggregate_witnesses,
)
from .cfg_dominance import DominanceEvidence
from .operations import Operation


def judgment_for_path(
    operation: Operation,
    matches_by_kind: Mapping[str, tuple[tuple[WitnessMatch, DominanceEvidence], ...]],
    completeness: Completeness,
    *,
    discovery_complete: bool = True,
) -> PathJudgment:
    """Conjoin witness and dominance evidence per kind and judge the path."""
    matches = tuple(dict.fromkeys(match for pairs in matches_by_kind.values() for match, _ in pairs))
    if not completeness.is_complete:
        return PathJudgment(PairJudgment.INDETERMINATE, (), completeness, matches)
    relations_by_kind = {kind: _kind_relation(pairs, discovery_complete) for kind, pairs in matches_by_kind.items()}
    judgment, missing = _mixed_obligation(relations_by_kind)
    return PathJudgment(judgment, missing, completeness, matches)


def _conjoined(pair: tuple[WitnessMatch, DominanceEvidence]) -> EvidenceRelation:
    match, dominance = pair
    if match.relation is EvidenceRelation.NO or dominance.relation is EvidenceRelation.NO:
        return EvidenceRelation.NO
    if match.relation is EvidenceRelation.MUST and dominance.relation is EvidenceRelation.MUST:
        return EvidenceRelation.MUST
    return EvidenceRelation.UNKNOWN


def _kind_relation(pairs: tuple[tuple[WitnessMatch, DominanceEvidence], ...], discovery_complete: bool) -> EvidenceRelation:
    if not pairs:
        return EvidenceRelation.NO if discovery_complete else EvidenceRelation.UNKNOWN
    return aggregate_witnesses(tuple(_conjoined(pair) for pair in pairs), discovery_complete=True)


def _mixed_obligation(
    relations_by_kind: Mapping[str, EvidenceRelation],
) -> tuple[PairJudgment, tuple[str, ...]]:
    absent_kinds = sorted(kind for kind, relation in relations_by_kind.items() if relation is EvidenceRelation.NO)
    undecidable = any(
        relation is not EvidenceRelation.MUST and relation is not EvidenceRelation.NO for relation in relations_by_kind.values()
    )
    if undecidable:
        return PairJudgment.INDETERMINATE, ()
    if absent_kinds:
        return PairJudgment.UNGUARDED, tuple(absent_kinds)
    return PairJudgment.DISCHARGED, ()


__all__ = ["judgment_for_path"]
