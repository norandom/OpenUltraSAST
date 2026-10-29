"""Evidence relations, the completeness value and resource abstract values (access-control-prover).

Covers Req 2.1, 2.5, 2.6, 2.7, 11.1, 11.6, 11.7.

``EvidenceRelation`` is the abstract evidence domain: definite presence (``MUST``), definite absence
(``NO``), possibility (``MAY``) and unknown (``UNKNOWN``). Three separate operations keep one table
from being used for the wrong quantifier: ``join_alternatives`` merges evidence from alternative call
targets or control paths, ``conjoin_dimensions`` combines one witness's kind, scope, resource, authority
and dominance dimensions, and ``aggregate_witnesses`` asks whether any witness definitely governs one
obligation. ``ResourceRef`` abstracts one resource binding into an exact token, a finite alias set,
request-global scope or an unknown value; ``join_resources`` unions alias sets finitely, lets
request-global scope absorb concrete bindings and never lets an unresolvable value resolve. Every
operation is deterministic, pure and independent of target names; join never converts
``MAY`` or ``UNKNOWN`` into ``MUST`` or ``NO``, so losing precision cannot manufacture a verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Literal


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


_RESOURCE_KINDS = ("exact", "aliases", "request_global", "unknown")


@dataclass(frozen=True)
class ResourceRef:
    """The abstract value of one resource binding (design, "Abstract evidence domain"; Req 2.1, 2.5, 2.6, 2.7, 11.1).

    ``exact`` binds one named resource, ``aliases`` binds a finite set of them, ``request_global`` binds the
    whole request without resource equality, and ``unknown`` is an unresolvable or unbounded binding. Values
    are deduplicated and sorted, so equal bindings are equal however they were constructed; a misshapen kind
    or arity fails loud rather than degrading silently.
    """

    kind: Literal["exact", "aliases", "request_global", "unknown"]
    values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in _RESOURCE_KINDS:
            raise ValueError(f"unknown resource kind: {self.kind!r}")
        tokens = sorted(set(self.values))
        if self.kind == "exact" and len(tokens) != 1:
            raise ValueError(f"exact resource needs exactly one token: {self.values!r}")
        if self.kind == "aliases" and not tokens:
            raise ValueError("alias set needs at least one token")
        if self.kind in ("request_global", "unknown") and tokens:
            raise ValueError(f"{self.kind} resource binds no tokens: {self.values!r}")
        object.__setattr__(self, "values", tuple(tokens))


REQUEST_GLOBAL_RESOURCE = ResourceRef(kind="request_global")
UNKNOWN_RESOURCE = ResourceRef(kind="unknown")


def parse_resource(binding: str | Sequence[str] | None) -> ResourceRef:
    """Parse one resource binding from fact or IR evidence into its abstract value.

    A single identifier token is ``exact``, a finite token collection is a finite alias set, and ``None``
    (no binding could be resolved) is ``unknown``; anything misshapen raises instead of quietly degrading.
    """
    if binding is None:
        return UNKNOWN_RESOURCE
    tokens = (binding,) if isinstance(binding, str) else tuple(binding)
    if not tokens or not all(isinstance(token, str) and token for token in tokens):
        raise ValueError(f"misshapen resource binding: {binding!r}")
    kind: Literal["exact", "aliases"] = "exact" if isinstance(binding, str) else "aliases"
    return ResourceRef(kind=kind, values=tokens)


def join_resources(left: ResourceRef, right: ResourceRef) -> ResourceRef:
    """Join resource bindings from alternative paths or call targets.

    Alias sets join by finite union and identical exact tokens stay exact; request-global scope absorbs any
    concrete binding because it already covers every resource in the request (Req 2.6), and an unbounded or
    unresolvable value joins to ``unknown`` so losing precision cannot manufacture an exact match (Req 2.7, 11.1).
    """
    if left.kind == "unknown" or right.kind == "unknown":
        return UNKNOWN_RESOURCE
    if left.kind == "request_global" or right.kind == "request_global":
        return REQUEST_GLOBAL_RESOURCE
    if left.kind == right.kind == "exact" and left.values == right.values:
        return left
    return ResourceRef(kind="aliases", values=left.values + right.values)


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
