"""Evidence relations, the completeness value, resource and authority abstract values (access-control-prover).

Covers Req 2.1, 2.2, 2.5, 2.6, 2.7, 2.8, 11.1, 11.6, 11.7.

``EvidenceRelation`` is the abstract evidence domain: definite presence (``MUST``), definite absence
(``NO``), possibility (``MAY``) and unknown (``UNKNOWN``). Three separate operations keep one table
from being used for the wrong quantifier: ``join_alternatives`` merges evidence from alternative call
targets or control paths, ``conjoin_dimensions`` combines one witness's kind, scope, resource, authority
and dominance dimensions, and ``aggregate_witnesses`` asks whether any witness definitely governs one
obligation. ``ResourceRef`` abstracts one resource binding into an exact token, a finite alias set,
request-global scope or an unknown value; ``join_resources`` unions alias sets finitely, lets
request-global scope absorb concrete bindings and never lets an unresolvable value resolve.
``AuthorityRef`` abstracts one authority holding into an exact name, a finite alternative set or an
unknown value; ``authority_satisfies`` asks whether a held authority satisfies a required one by
folding ``join_alternatives`` over every held-by-required name pair, where a pair is ``MUST`` when a
promoted ``AuthorityImplication`` chain connects them and ``NO`` otherwise, so sufficient authority is
``MUST``, insufficient is ``NO`` and undecidable is ``UNKNOWN`` (Req 2.5, 2.7, 2.8). ``supporting_implications``
returns the implications used with their supporting fact ids, retained for the trace (Req 2.8). Every
operation is deterministic, pure and independent of target names; join never converts
``MAY`` or ``UNKNOWN`` into ``MUST`` or ``NO``, so losing precision cannot manufacture a verdict.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from functools import reduce
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


@dataclass(frozen=True)
class AuthorityRef:
    """The abstract value of one authority holding (design, "Abstract evidence domain"; Req 2.1, 2.2, 2.5, 2.7, 11.1).

    One value is an ``exact`` authority, several values are a ``finite`` alternative set (the authority is
    one of them, not all of them) and ``is_unknown`` marks an unresolvable holding that can neither match
    nor fail. Values are deduplicated and sorted, so equal holdings are equal however they were
    constructed; a misshapen value fails loud rather than degrading silently.
    """

    values: tuple[str, ...]
    is_unknown: bool = False

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in self.values):
            raise ValueError(f"misshapen authority values: {self.values!r}")
        if self.is_unknown and self.values:
            raise ValueError(f"unknown authority binds no values: {self.values!r}")
        if not self.is_unknown and not self.values:
            raise ValueError("authority needs at least one value")
        object.__setattr__(self, "values", tuple(sorted(set(self.values))))


UNKNOWN_AUTHORITY = AuthorityRef(values=(), is_unknown=True)


def parse_authority(binding: str | Sequence[str] | None) -> AuthorityRef:
    """Parse one authority holding from fact or IR evidence into its abstract value.

    A single name is ``exact``, a finite name collection is a finite alternative set, and ``None``
    (no holding could be resolved) is ``unknown``; anything misshapen raises instead of quietly degrading.
    """
    if binding is None:
        return UNKNOWN_AUTHORITY
    names = (binding,) if isinstance(binding, str) else tuple(binding)
    if not names or not all(isinstance(name, str) and name for name in names):
        raise ValueError(f"misshapen authority binding: {binding!r}")
    return AuthorityRef(values=names)


def join_authorities(left: AuthorityRef, right: AuthorityRef) -> AuthorityRef:
    """Join authority holdings from alternative paths or call targets.

    Identical exact holdings stay exact and finite sets join by finite union, mirroring ``join_resources``;
    an unresolvable holding joins to ``unknown`` so losing precision cannot manufacture a match
    (Req 2.7, 11.1).
    """
    if left.is_unknown or right.is_unknown:
        return UNKNOWN_AUTHORITY
    if left.values == right.values:
        return left
    return AuthorityRef(values=left.values + right.values)


@dataclass(frozen=True)
class AuthorityImplication:
    """One promoted implication fact: ``authority`` also covers ``implies`` (Req 2.8).

    ``id`` is the supporting promoted fact row's identifier, retained so the trace can name the
    implication used. The engine bakes in no implication of its own; only these facts connect authorities.
    """

    id: str
    authority: str
    implies: str


def _implication_index(
    implications: Iterable[AuthorityImplication],
) -> dict[str, tuple[AuthorityImplication, ...]]:
    """Group implications by the authority they extend, preserving first-occurrence order."""
    grouped: dict[str, list[AuthorityImplication]] = {}
    for implication in implications:
        grouped.setdefault(implication.authority, []).append(implication)
    return {authority: tuple(edges) for authority, edges in grouped.items()}


def _implication_path(
    source: str,
    target: str,
    index: Mapping[str, tuple[AuthorityImplication, ...]],
) -> tuple[AuthorityImplication, ...] | None:
    """The implications leading from ``source`` to ``target``, or ``None`` when no promoted chain reaches it.

    Breadth-first over the finite edges in fact order, so the returned chain is deterministic and shortest
    by edge count; ``()`` means the names are identical and no implication is needed.
    """
    if source == target:
        return ()
    parents: dict[str, tuple[str, AuthorityImplication] | None] = {source: None}
    frontier: deque[str] = deque([source])
    while frontier:
        current = frontier.popleft()
        for implication in index.get(current, ()):
            reached = implication.implies
            if reached in parents:
                continue
            parents[reached] = (current, implication)
            if reached == target:
                chain: list[AuthorityImplication] = []
                node: str = target
                while True:
                    step = parents[node]
                    if step is None:
                        return tuple(reversed(chain))
                    previous, edge = step
                    chain.append(edge)
                    node = previous
            frontier.append(reached)
    return None


def authority_satisfies(
    held: AuthorityRef,
    required: AuthorityRef,
    implications: Iterable[AuthorityImplication] = (),
) -> EvidenceRelation:
    """Ask whether one held authority value satisfies one required authority value (Req 2.5, 2.7, 2.8, 11.1).

    Each held-by-required name pair is definite: ``MUST`` when the names match or a promoted implication
    chain connects them, ``NO`` otherwise. The aggregate folds ``join_alternatives`` over every pair, so a
    finite holding with one satisfying alternative is ``MAY``; an unresolvable holding or requirement is
    ``UNKNOWN`` and can never match broadly or fail definitely.
    """
    if held.is_unknown or required.is_unknown:
        return EvidenceRelation.UNKNOWN
    index = _implication_index(implications)
    pairs = [
        EvidenceRelation.MUST if _implication_path(held_name, required_name, index) is not None else EvidenceRelation.NO
        for held_name in held.values
        for required_name in required.values
    ]
    return reduce(join_alternatives, pairs)


def supporting_implications(
    held: AuthorityRef,
    required: AuthorityRef,
    implications: Iterable[AuthorityImplication] = (),
) -> tuple[AuthorityImplication, ...]:
    """The implications used on satisfying paths, with supporting fact ids retained for the trace (Req 2.8).

    First-occurrence order over the normalized names, deduplicated; empty when nothing matched or the
    relation could not be decided.
    """
    if held.is_unknown or required.is_unknown:
        return ()
    index = _implication_index(implications)
    used: list[AuthorityImplication] = []
    for held_name in held.values:
        for required_name in required.values:
            chain = _implication_path(held_name, required_name, index)
            if chain is not None:
                used.extend(chain)
    return tuple(dict.fromkeys(used))


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
