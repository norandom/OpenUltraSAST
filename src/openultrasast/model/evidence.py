"""The evidence vector: what a (region, family) pair carries BEFORE any dataflow is asked (flow-aware-ranking).

Tiering is the CPG query without dataflow; arbitration is the query with it. Same graph, same facts, two costs.
This module turns the evidence rows that `taint.sc` emits in `evidenceOnly` mode into one vector per pair,
and assigns the tier. Every field is stated in fact-table terms -- source, sink, sanitizer -- so a heuristic
that mentions a language's own syntax has, by construction, left this module.

Only tier 0 excludes. Its predicate has a proof -- a family with no sink in reach cannot produce a flow, in any
language, under any dataflow model -- and it is the only place exactness is required. Everything above orders,
where being wrong costs position, and `regions_truncated` reports what position cost.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

TIER_EXCLUDE = 0  # no sink of this family in reach: never ask
TIER_NO_SOURCE = 1  # sinks, but nothing untrusted can arrive: ask last
TIER_CLEANSED = 2  # a source exists, but every sink call is bound or cleansed on the call: ask late
TIER_OPEN = 3  # a source exists and some sink call is computed and uncleansed: ask first
TIER_OPEN_PUBLIC = 4  # tier 3 and declared public, or a source on the same statement: ask very first

# The within-tier weights, published here because they are the whole of what "heuristic ranking" means in
# phase 2 and a reader should be able to see every one of them at once. They order, they never exclude.
WEIGHTS: dict[str, float] = {
    "open_sink": 1.0,  # per sink call that is computed, uncleansed and unbound, up to OPEN_SINK_CAP
    "cleansed_sink": -0.5,  # per sink call that is cleansed on the call or bound, up to CLEANSED_SINK_CAP
    "source_local": 2.0,  # a modelled source in the region's own body
    "carried": 1.5,  # stage one of the two-stage join says a field or dispatch value arrives tainted
    "carried_weak": 0.75,  # a field assigned from a parameter of its method: every constructor does it
    "source_near": 1.0,  # a modelled source within the arbiter's callDepth
    "entry": 0.5,  # parameters untrusted by contract
    "access_declared_public": 1.0,
}
OPEN_SINK_CAP = 5
CLEANSED_SINK_CAP = 3


@dataclass(frozen=True)
class SinkEvidence:
    """One sink call of the family, as the graph saw it, with no flow asked."""

    code: str
    line: int
    method: str
    arity: int
    arg0_literal: bool
    cleansed_on_call: bool  # a sanitizer of this family wraps an ARGUMENT -- not merely present in the function

    @property
    def shape(self) -> str:
        """``literal`` cannot carry taint; ``computed`` is the residue that can."""
        return "literal" if self.arg0_literal else "computed"


@dataclass(frozen=True)
class Evidence:
    """The vector for one (region, family) pair."""

    sinks: tuple[SinkEvidence, ...] = ()
    family_in_repo: bool = True  # False is the repository-wide tier 0, exact at every callDepth
    source_local: bool = False  # a modelled source in the region's own body
    source_near: bool = False  # a modelled source within the arbiter's callDepth
    entry: bool = False  # parameters untrusted by contract
    access_declared_public: bool = False  # declared, not inferred -- "no decorator found" is not "public"
    carried: bool | None = None  # stage one of the two-stage join, the STRONG form; None where it was not computed
    carried_weak: bool = False  # the weak form: a field assigned from a parameter of its method. Orders, never promotes.
    bound_names: tuple[str, ...] = field(default=())  # sink names the shape test treats as bound at arity >= 2

    @property
    def any_source(self) -> bool:
        return self.source_local or self.source_near or self.entry or bool(self.carried)

    def is_bound(self, sink: SinkEvidence) -> bool:
        """The safe-shape rule the arbiter already applies: a named sink with two or more arguments binds."""
        return sink.arity >= 2 and any(name in sink.code for name in self.bound_names)

    @property
    def open_sinks(self) -> tuple[SinkEvidence, ...]:
        """Sink calls that could carry an uncleansed, unbound, computed value."""
        return tuple(s for s in self.sinks if s.shape == "computed" and not s.cleansed_on_call and not self.is_bound(s))

    @property
    def tier(self) -> int:
        if not self.family_in_repo or not self.sinks:
            return TIER_EXCLUDE
        if not self.any_source:
            return TIER_NO_SOURCE
        if not self.open_sinks:
            return TIER_CLEANSED
        if self.access_declared_public or self.source_local or self.carried:
            return TIER_OPEN_PUBLIC
        return TIER_OPEN

    @property
    def score(self) -> float:
        """Order WITHIN a tier, by the published weights below. Never across tiers: the tier is the predicate.

        A weighted sum of the same exact facts the tier is made of, so it can rank but cannot manufacture --
        a pair with no sink scores nothing and stays tier 0 whatever its weights. Counts are capped because
        a file-scope region with 346 sinks is not 346 times more likely to hold the bug than one with 5;
        the cap is where the evidence stops saying more. Phase 2 of flow-aware-ranking.
        """
        if self.tier == TIER_EXCLUDE:
            return 0.0  # no sink in reach: nothing to weigh, whatever the sources say
        w = WEIGHTS
        return (
            w["open_sink"] * min(len(self.open_sinks), OPEN_SINK_CAP)
            + w["cleansed_sink"] * min(sum(1 for s in self.sinks if s.cleansed_on_call or self.is_bound(s)), CLEANSED_SINK_CAP)
            + (w["source_local"] if self.source_local else 0.0)
            + (w["carried"] if self.carried else 0.0)
            + (w["carried_weak"] if self.carried_weak and not self.carried else 0.0)
            + (w["source_near"] if self.source_near else 0.0)
            + (w["entry"] if self.entry else 0.0)
            + (w["access_declared_public"] if self.access_declared_public else 0.0)
        )

    @property
    def order_key(self) -> tuple[int, float]:
        """Higher sorts first: ``sorted(..., key=lambda e: e.order_key, reverse=True)``."""
        return (self.tier, self.score)


def evidence_from_rows(
    rows: Sequence[Mapping[str, object]] | None,
    *,
    entry: bool = False,
    access_declared_public: bool = False,
    carried: bool | None = None,
    bound_names: Sequence[str] = (),
) -> Evidence | None:
    """Read the query's evidence rows for one request. ``None`` when the query did not answer.

    A request that answered with no sinks still carries a ``summary`` row -- that is tier 0, and it must be
    distinguishable from a request that failed, which carries nothing.
    """
    if rows is None:
        return None
    summary = next((r for r in rows if isinstance(r, Mapping) and r.get("kind") == "summary"), None)
    if summary is None:
        return None
    sinks = tuple(
        SinkEvidence(
            code=str(r.get("sink", "")),
            line=_as_int(r.get("sinkLine")),
            method=str(r.get("sinkMethod", "")),
            arity=_as_int(r.get("sinkArity")),
            arg0_literal=_as_bool(r.get("sinkArg0Literal")),
            cleansed_on_call=_as_bool(r.get("cleansedOnCall")),
        )
        for r in rows
        if isinstance(r, Mapping) and r.get("kind") == "sink"
    )
    return Evidence(
        sinks=sinks,
        family_in_repo=_as_bool(summary.get("familyInRepo"), default=True),
        source_local=_as_bool(summary.get("sourceLocal")),
        source_near=_as_bool(summary.get("sourceNear")),
        entry=entry,
        access_declared_public=access_declared_public,
        # The query's own answer when it gave one (phase 2: stage one of the two-stage join, reused);
        # the caller's otherwise; None where neither knows, which is not False.
        carried=(str(summary.get("carriedKind", "")) == "source" or (_as_bool(summary["carried"]) and "carriedKind" not in summary))
        if "carried" in summary
        else carried,
        carried_weak=str(summary.get("carriedKind", "")) == "parameter",
        bound_names=tuple(bound_names),
    )


def _as_bool(value: object, *, default: bool = False) -> bool:
    """A JSON boolean, or its string spelling. ``bool("False")`` is True, which would make every unsanitized
    sink read as cleansed the moment a serialiser chose strings -- the kind of silent inversion this project
    has paid for before."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def _as_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return -1


__all__ = [
    "CLEANSED_SINK_CAP",
    "OPEN_SINK_CAP",
    "TIER_CLEANSED",
    "TIER_EXCLUDE",
    "TIER_NO_SOURCE",
    "TIER_OPEN",
    "TIER_OPEN_PUBLIC",
    "WEIGHTS",
    "Evidence",
    "SinkEvidence",
    "evidence_from_rows",
]
