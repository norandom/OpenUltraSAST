"""Evidence relations and the completeness value (access-control-prover, Req 11.1, 11.6, 11.7).

``EvidenceRelation`` is the abstract evidence domain: definite presence (``MUST``), definite absence
(``NO``), possibility (``MAY``) and unknown (``UNKNOWN``). Three separate operations keep one table
from being used for the wrong quantifier: ``join_alternatives`` merges evidence from alternative call
targets or control paths, ``conjoin_dimensions`` combines one witness's kind, scope, resource, authority
and dominance dimensions, and ``aggregate_witnesses`` asks whether any witness definitely governs one
obligation. Every operation is deterministic, pure and independent of target names; join never converts
``MAY`` or ``UNKNOWN`` into ``MUST`` or ``NO``, so losing precision cannot manufacture a verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum


class EvidenceRelation(Enum):
    MUST = "must"
    MAY = "may"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Completeness:
    """What the analysis could not decide; reasons are stage-prefixed strings, deduplicated in order.

    A reason carries its stage in its text (``"resolution:ambiguous_call"``), so deduplication on the
    full reason preserves stage identity and drops only exact repeats, keeping first occurrence.
    """

    is_complete: bool
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(dict.fromkeys(self.reasons)))


_ALTERNATIVE_JOIN: Mapping[tuple[EvidenceRelation, EvidenceRelation], EvidenceRelation] = {
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

# The precision order: MUST <= MAY <= UNKNOWN and NO <= MAY <= UNKNOWN; MUST and NO are incomparable.
_PRECISION_ORDER: frozenset[tuple[EvidenceRelation, EvidenceRelation]] = frozenset(
    {
        (EvidenceRelation.MUST, EvidenceRelation.MUST),
        (EvidenceRelation.MUST, EvidenceRelation.MAY),
        (EvidenceRelation.MUST, EvidenceRelation.UNKNOWN),
        (EvidenceRelation.NO, EvidenceRelation.NO),
        (EvidenceRelation.NO, EvidenceRelation.MAY),
        (EvidenceRelation.NO, EvidenceRelation.UNKNOWN),
        (EvidenceRelation.MAY, EvidenceRelation.MAY),
        (EvidenceRelation.MAY, EvidenceRelation.UNKNOWN),
        (EvidenceRelation.UNKNOWN, EvidenceRelation.UNKNOWN),
    }
)


def at_least_as_precise(relation: EvidenceRelation, than: EvidenceRelation) -> bool:
    """Whether ``relation`` carries at least as much precision as ``than`` in the design's order."""
    return (relation, than) in _PRECISION_ORDER


def join_alternatives(left: EvidenceRelation, right: EvidenceRelation) -> EvidenceRelation:
    """Join evidence from alternative call targets or control paths using the fixed table."""
    return _ALTERNATIVE_JOIN[(left, right)]


def conjoin_dimensions(dimension_relations: Iterable[EvidenceRelation]) -> EvidenceRelation:
    """Combine one witness's dimensions: any NO wins, then any UNKNOWN, then any MAY; else all MUST.

    An empty dimension vector is vacuously all-``MUST``.
    """
    present = set(dimension_relations)
    for verdict in (EvidenceRelation.NO, EvidenceRelation.UNKNOWN, EvidenceRelation.MAY):
        if verdict in present:
            return verdict
    return EvidenceRelation.MUST


def aggregate_witnesses(witness_relations: Iterable[EvidenceRelation], *, discovery_complete: bool) -> EvidenceRelation:
    """Ask whether any witness definitely governs one obligation.

    Any ``MUST`` wins; otherwise ``UNKNOWN`` takes precedence over ``MAY``, and ``MAY`` over ``NO``.
    An empty witness set is ``NO`` only when discovery and facts are complete; otherwise ``UNKNOWN``.
    """
    relations = tuple(witness_relations)
    if not relations:
        return EvidenceRelation.NO if discovery_complete else EvidenceRelation.UNKNOWN
    present = set(relations)
    for verdict in (EvidenceRelation.MUST, EvidenceRelation.UNKNOWN, EvidenceRelation.MAY):
        if verdict in present:
            return verdict
    return EvidenceRelation.NO


def join_completeness(left: Completeness, right: Completeness) -> Completeness:
    """Merge completeness across stages: complete only when both are complete, every reason kept once."""
    return Completeness(
        is_complete=left.is_complete and right.is_complete,
        reasons=left.reasons + right.reasons,
    )
