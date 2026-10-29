"""Tasks 10.4-10.5 -- per-path judgment and multi-path aggregation (Reqs 4.1-4.5, 11.2-11.5).

A witness governs an obligation only when every required relation is MUST.
With complete evidence and no governing witness for a required kind the path
is unguarded; any MAY or UNKNOWN among required relations, or an incomplete
path enumeration, makes it indeterminate. Aggregation over paths: any
complete unguarded path is unguarded; a complete enumeration with every path
discharged is discharged; otherwise indeterminate. Engine module: no target
names.
"""

from collections.abc import Mapping

from .abstract_domain import (
    Completeness,
    EvidenceRelation,
    PairJudgment,
    PathJudgment,
    WitnessMatch,
    aggregate_witnesses,
    join_completeness,
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


def aggregate_judgments(judgments: tuple[PathJudgment, ...]) -> PathJudgment:
    """Aggregate path judgments: Reqs 3.10, 4.1-4.5, 11.5 (task 10.5).

    Any complete unguarded path decides unguarded; a complete enumeration
    with every path discharged decides discharged; anything else, including
    an empty enumeration, stays indeterminate.
    """
    completeness = _joined_completeness(judgments)
    matches = tuple(dict.fromkeys(match for judgment in judgments for match in judgment.matches))
    for judgment in judgments:
        if judgment.judgment is PairJudgment.UNGUARDED and judgment.completeness.is_complete:
            missing = tuple(
                sorted(
                    {
                        kind
                        for other in judgments
                        if other.judgment is PairJudgment.UNGUARDED and other.completeness.is_complete
                        for kind in other.missing
                    }
                )
            )
            return PathJudgment(PairJudgment.UNGUARDED, missing, completeness, matches)
    if judgments and all(judgment.judgment is PairJudgment.DISCHARGED and judgment.completeness.is_complete for judgment in judgments):
        return PathJudgment(PairJudgment.DISCHARGED, (), completeness, matches)
    return PathJudgment(PairJudgment.INDETERMINATE, (), completeness, matches)


def _joined_completeness(judgments: tuple[PathJudgment, ...]) -> Completeness:
    joined = Completeness(is_complete=True)
    for judgment in judgments:
        joined = join_completeness(joined, judgment.completeness)
    return joined


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


__all__ = ["aggregate_judgments", "judgment_for_path"]
