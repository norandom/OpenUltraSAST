"""The repository driver (contributor-scan, Req 3).

Pair scoring built one CPG per pair and asked about one region. A repository has thousands of regions, and the
two costs that were free at pair scale dominate here:

* **CPG construction.** A build takes 5-30 seconds on a forty-line excerpt. One per region would make a
  repository scan unusable, so this builds **one** and reuses it across every region.
* **Model calls.** The enumerator caps candidates at eight per region, which says nothing useful about a scan
  with two thousand regions. The budget is a **total for the run**, spent on the highest-ranked regions first.
  It bounds model calls and nothing else: when it runs out the JUDGE is withheld and the graph keeps deciding,
  because arbitration costs nothing. Those regions are counted into ``regions_unasked``, and anything
  ``max_regions`` cut before arbitration into ``regions_unjudged``. A tool that silently analyses a tenth of a
  repository and reports a clean result is worse than one that says what it did not look at.

Ordering puts rung before rank: what the model established outranks what the LLM merely proposed, whatever
the region's risk score said beforehand.
"""

from __future__ import annotations

import inspect
import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from ..cpg.backend import TIMING, CpgResult
from .candidates import enumerate_candidates
from .config_value import request_params as config_params
from .contracts import (
    ChangeContext,
    DeferredQuestion,
    ExecutionBudget,
    FamilyCoverage,
    QuestionIdentity,
    QuestionOutcome,
    RankedQuestion,
    ScopeDecision,
)
from .dominance import request_params as dominance_params
from .evidence import TIER_EXCLUDE, Evidence, evidence_from_rows
from .ladder import Rung
from .layout import is_vendored, layout_facts, with_layout
from .partitions import PartitionCoverage, build_partitions
from .pipeline import ModelFinding, scan_region
from .regions import MODULE_SCOPE, ScanRegion, affected_context
from .specs import ConfigSpec, DominanceSpec, TaintSpec, config_specs, dominance_specs, taint_specs
from .taint import request_params as taint_params
from .taxonomy import load_families

# The three arbiters a region can be routed to. Naming the union keeps the batcher honest: `object`
# would let a fourth spec kind reach `_grouped` and silently fall through to the taint branch.
ArbiterSpec = TaintSpec | DominanceSpec | ConfigSpec

# How far below an entry point a sink may sit and still be attributed to it.
#
# An entry point is the trust boundary, so its parameters ARE attacker input and a sink it reaches is its
# responsibility -- which is what makes VAmPI's SQL injection askable at all: a request parameter reaches
# `get_by_username`, is passed to `User.get_user` in another module, interpolated there and executed. A
# function-scoped question sees neither end of that.
#
# Bounded, and deliberately shallow. "Every method transitively reachable from a handler" is most of a
# repository: the question stops being about this entry point and the query stops being affordable. Three
# levels covers handler -> service -> data access, which is where these bugs live. Raising it is a
# measurement, not a preference.
ENTRY_POINT_CALL_DEPTH = 3

logger = logging.getLogger(__name__)


_RUNG_ORDER = {Rung.ENTAILED: 0, Rung.CORROBORATED: 1, Rung.SUSPICION: 2, Rung.EXECUTION_CONFIRMED: -1}


@dataclass(frozen=True)
class ScanBudget:
    """A total for the run, not a per-region cap."""

    max_model_calls: int = 200
    max_regions: int = 500
    # Compute the evidence tier of every (region, family) pair and RECORD it. Phase 0 of flow-aware-ranking:
    # the instrument runs on every real scan so later phases are measurable, and it changes nothing about
    # what is asked or in what order. One extra query invocation without dataflow -- a JVM load, then
    # milliseconds per pair.
    tiering: bool = True
    # Phase 1 of flow-aware-ranking: do not ask a taint question whose answer is known in advance. A pair at
    # tier 0 has no sink of its family in reach, and a family with no sink cannot produce a flow -- in any
    # language, under any dataflow model. Skipping it cannot lose a finding. It is the only tier that
    # excludes, which is why it is the only one allowed to act before the ranker is measured.
    prune_tier0: bool = True
    # Phase 2 of flow-aware-ranking: spend the region budget by EVIDENCE, not by static rank. The evidence
    # pass runs over `evidence_regions` regions in static order (0 = every region; it costs milliseconds a
    # pair), each region takes its best pair's (tier, score), and `max_regions` is then cut from that
    # order. Off by default until the position benchmark says where the pinned CVEs land under it.
    order_by_evidence: bool = False
    evidence_regions: int = 0


@dataclass(frozen=True)
class ModelScanResult:
    findings: tuple[ModelFinding, ...] = ()
    by_rung: Mapping[str, int] = field(default_factory=dict)
    regions_scanned: int = 0
    regions_unjudged: int = 0
    # Arbitrated by the graph, but with the judge withheld because the budget was spent. Not the same as
    # unjudged, and not the same as clean.
    regions_unasked: int = 0
    model_calls: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0
    # The split, not just the total. Which stage a scan's wall-clock actually goes to decides real questions
    # -- whether a warm Joern server would buy anything, whether the budget or the CPG is the ceiling -- and
    # a single figure cannot answer any of them.
    build_seconds: float = 0.0
    query_seconds: float = 0.0
    # Per query kind, because the total cannot say whether the cost is JVM startup (which a warm server
    # would remove) or CPGQL evaluation (which it would not). That is the whole of the server-mode decision.
    query_seconds_by_kind: Mapping[str, float] = field(default_factory=dict)
    degradations: tuple[Mapping[str, object], ...] = ()
    # The evidence tier of each (path, function, family) pair the scan collected, and the count per tier.
    # Recorded, not acted on: this is what "the ranker got better" will be measured against.
    tiers: tuple[tuple[str, str, str, int], ...] = ()
    tier_counts: Mapping[int, int] = field(default_factory=dict)
    # Taint requests not issued because their pair was tier 0. Exact, so not a degradation: nothing that
    # could have been found was skipped. Reported so the request count is legible.
    requests_pruned: int = 0

    partitions: tuple[PartitionCoverage, ...] = ()
    change_context: ChangeContext | None = None
    scope: ScopeDecision | None = None
    question_outcomes: tuple[QuestionOutcome, ...] = ()
    family_coverage: tuple[FamilyCoverage, ...] = ()

    @property
    def arbitrate_seconds(self) -> float:
        """What is left once the CPG is built and queried: the judge calls and the arbiters themselves."""
        return round(max(self.seconds - self.build_seconds - self.query_seconds, 0.0), 2)


def scan_repository(
    root: Path,
    regions: Sequence[ScanRegion],
    *,
    backend: Any,
    client: Any | None = None,
    model: str = "",
    budget: ScanBudget | None = None,
    execution_budget: ExecutionBudget | None = None,
    ranking_mode: str | None = None,
    unit: str = "repository",
    population_complete: bool = False,
    change_context: ChangeContext | None = None,
) -> ModelScanResult:
    """Run with an optional transaction deadline; graph ownership ends on every exit."""
    if ranking_mode not in (None, "static", "evidence"):
        raise ValueError("ranking_mode must be static or evidence")
    limits = budget if budget is not None else ScanBudget()
    if ranking_mode is not None:
        limits = replace(limits, order_by_evidence=ranking_mode == "evidence")
    mode = "evidence" if limits.order_by_evidence else "static"
    layout = layout_facts()
    regions = tuple(r for r in regions if not is_vendored(r.path, layout))
    # Reject duplicate canonical questions before any engine work or resource ownership.
    identities = [_identity(unit, r, f) for r in regions for f in r.families]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate question identity")
    started = time.monotonic()
    owned: list[Any] = []
    try:
        result = _scan_repository_impl(
            root,
            regions,
            backend=backend,
            client=client if execution_budget is None else None,
            model=model,
            budget=limits,
            ranking_mode=mode,
            unit=unit,
            population_complete=population_complete,
            change_context=change_context,
            execution_budget=execution_budget,
            owned=owned,
        )
    finally:
        for cpg in owned:
            _dispose(cpg)
        # An engine session belongs to the transaction, so it ends with the transaction. Leaving it
        # open leaks a JVM holding the configured heap, which is how the first session-enabled run
        # exhausted its container and made every later request fail.
        close = getattr(backend, "close_session", None)
        if callable(close):
            try:
                close()
            except Exception as error:  # noqa: BLE001 -- tidying up must not fail a completed scan
                logger.warning("could not end the engine session: %s", error)
    diagnostics = list(result.degradations)
    if execution_budget is not None:
        if client is not None:
            diagnostics.append({"stage": "model", "reason": "model_withheld_execution_budget"})
        reasons = ["deadline_exhausted"] if time.monotonic() >= execution_budget.deadline_monotonic else []
        for cpg in owned:
            read_diagnostics = getattr(cpg, "execution_diagnostics", None)
            if callable(read_diagnostics):
                reasons.extend(read_diagnostics())
        for reason in dict.fromkeys(reasons):
            diagnostics.append({"stage": "model", "reason": reason})
    return replace(result, degradations=tuple(diagnostics), seconds=round(time.monotonic() - started, 2))


def _scan_repository_impl(
    root: Path,
    regions: Sequence[ScanRegion],
    *,
    backend: Any,
    client: Any | None = None,
    model: str = "",
    budget: ScanBudget | None = None,
    execution_budget: ExecutionBudget | None = None,
    owned: list[Any],
    ranking_mode: str,
    unit: str,
    population_complete: bool,
    change_context: ChangeContext | None,
) -> ModelScanResult:
    """Arbitrate a repository's regions under one CPG and one budget."""
    limits = budget if budget is not None else ScanBudget()
    started = time.monotonic()
    degradations: list[Mapping[str, object]] = []

    taxonomy = load_families()
    build_started = time.monotonic()
    # The dominant region language, so a failed `joern-parse` can retry through that frontend directly.
    counts: dict[str, int] = {}
    for region in regions:
        counts[region.language] = counts.get(region.language, 0) + 1
    dominant = max(counts, key=lambda name: (counts[name], name)) if counts else ""
    declarations: dict[str, set[str]] = {}
    for region in regions:
        declarations.setdefault(region.path, set()).add(region.language)
    if root.is_dir():
        cpg = build_partitions(
            root,
            lambda source, language: _build(backend, source, language, execution_budget=execution_budget),
            execution_budget,
            {path: tuple(sorted(languages)) for path, languages in declarations.items()},
        )
        degradations.extend({"stage": "model", "reason": reason} for reason in cpg.boundaries)
    else:
        cpg = _build(backend, root, dominant, execution_budget=execution_budget)
    build_seconds = round(time.monotonic() - build_started, 2)
    if cpg is None or (hasattr(cpg, "graphs") and not cpg.graphs):
        if cpg is not None:
            owned.append(cpg)
        scope, _ = _scope_work(
            regions,
            {},
            limits,
            unit,
            ranking_mode,
            population_complete,
            failure="cpg_build_failed",
            change_context=change_context,
            execution_budget=execution_budget,
        )
        scope = replace(scope, unresolved_boundaries=tuple(dict.fromkeys((*scope.unresolved_boundaries, *getattr(cpg, "boundaries", ())))))
        return ModelScanResult(
            partitions=getattr(cpg, "partitions", ()),
            change_context=change_context,
            scope=scope,
            family_coverage=_family_coverage(scope, ()),
            by_rung=_empty_tally(),
            regions_unjudged=len(regions),
            seconds=round(time.monotonic() - started, 2),
            build_seconds=build_seconds,
            degradations=({"stage": "model", "reason": "cpg_build_failed", "detail": getattr(backend, "last_failure", "")},),
        )

    owned.append(cpg)

    # A CPG the frontend built with files missing is not the repository the caller asked about, and no
    # verdict over it can say anything about the code that was dropped. There is no rung for that, because
    # the ladder labels verdicts and none was ever produced here -- so it is a degradation, named, with the
    # files listed. See `cpg.backend._unparsed_files` for how a frontend drops a file while exiting 0.
    if getattr(cpg, "unparsed", ()):  # a backend need not carry the field
        unparsed = tuple(cpg.unparsed)
        degradations.append(
            {"stage": "model", "reason": "files_unparsed", "count": len(unparsed), "files": [Path(name).name for name in unparsed[:20]]}
        )

    # Count calls here rather than reading a client's own meter: the budget is this driver's contract and
    # must hold for any client, including one that keeps no usage log.
    counted = _CountingClient(client) if client is not None else None
    collected: list[tuple[ModelFinding, float]] = []
    scanned = 0

    # Sort here rather than trusting the caller. The budget decides what goes unexamined, so the order it is
    # spent in belongs to whoever holds the budget.
    ordered_regions = sorted(with_layout(regions), key=lambda r: (not r.shipped, -r.rank, r.path, r.function or ""))

    # The hook link table, built once for the whole scan. It is a property of the repository rather than of
    # any region, and it is read from the source text because the graph does not carry it: php2cpg drops a
    # registration's callback argument, so `add_filter("hook", array($this, "m"))` reaches the CPG as
    # `add_filter("hook", )`. See `mapping.php_hook_callbacks`.
    hooks = _hook_callbacks(root, regions)

    # The region cap is a COVERAGE fact, not a tuning knob nobody needs to hear about. Paid Memberships Pro
    # yields 4,463 regions from 637 files, so a default budget of 500 examines 11% of the repository -- and
    # a report that does not say so invites its silence to be read as a clean bill of health for the other
    # 89%. `budget_exhausted` is a different thing: that is the JUDGE running out, this is the work never
    # being collected at all.
    if len(ordered_regions) > limits.max_regions:
        degradations.append(
            {
                "stage": "model",
                "reason": "regions_truncated",
                "examined": limits.max_regions,
                "total": len(ordered_regions),
            }
        )

    # Phase 1b: the evidence tier of every taint pair, before any dataflow is asked. Same query, `evidenceOnly`,
    # no `reachableByFlows`. Phase 0 recorded it; phase 1 prunes tier 0 on it; phase 2 spends the region
    # budget by it. Under phase 2 the pass runs over MORE regions than the budget, which is the point.
    tiers: list[tuple[str, str, str, int]] = []
    per_kind: dict[str, float] = {}
    evidence_by_pair: dict[tuple[str, str, str], Evidence] = {}
    context_rows: dict[QuestionIdentity, list[Mapping[str, object]]] = {}
    if _within_deadline(execution_budget) and limits.tiering and callable(getattr(cpg, "run_batch", None)):
        evidence_candidates = (
            ordered_regions[: (limits.evidence_regions or len(ordered_regions))]
            if limits.order_by_evidence
            else ordered_regions[: limits.max_regions]
        )
        tier_started = time.monotonic()
        evidence_by_pair, failed = _evidence_pass(
            cpg,
            _collect(evidence_candidates, execution_budget=execution_budget),
            hooks,
            degradations=degradations,
            context_rows=context_rows if change_context is not None else None,
            unit=unit,
        )
        per_kind["evidence"] = round(time.monotonic() - tier_started, 2)
        if failed:
            degradations.append({"stage": "model", "reason": "query_failed", "kind": "evidence", "requests": failed})
        tiers = [(path, function, family, evidence.tier) for (path, function, family), evidence in evidence_by_pair.items()]
        if limits.order_by_evidence and evidence_by_pair:
            ordered_regions = order_by_evidence(ordered_regions, evidence_by_pair)

    context_gaps: set[QuestionIdentity] = set()
    if change_context is not None:
        change_context, context_gaps = affected_context(
            change_context, [_identity(unit, r, f) for r in ordered_regions for f in r.families], context_rows, root, execution_budget
        )

    # Authoritative selection is made once, from the actual final ranker order.
    # Stable question IDs are the IDs sent to every execution request below.
    #
    # A tier-zero vector says no sink of this family is in reach, and a question with no sink cannot produce a
    # flow. Pruning those is what makes a large population affordable: arbitration costs one to two seconds a
    # question and a 673-file plugin asks 2,526 of them, while the structural pass that produced the vectors
    # answered 17,700 requests in 44 s.
    #
    # It is switched off where the graph might be missing the very sink the vector did not see -- an unparsed
    # file, an excluded tree, a shard that cannot see its neighbour. That is right, and it was applied to the
    # whole scan, which is not: a census gap belongs to ONE partition, and a JavaScript file missing from the
    # JavaScript graph is no reason to arbitrate every tier-zero question a PHP family asks. On the measured
    # plugin that single distinction is the difference between 2,526 arbitrated questions and the few hundred
    # that could say anything.
    #
    # `cross_partition_semantics_unresolved` leaves this set entirely, for the reason it left the integrity
    # gaps: a PHP family's sink is PHP, so the existence of a second language cannot be why its vector saw none.
    prune_blockers = {
        "files_unparsed",
        "cpg_empty",
        "partition_file_census_incomplete",
        "partition_file_census_unavailable",
        "cpg_sharded",
        "vendor_semantics_unresolved",
        "symlink_context_unresolved",
        "frontend_unsupported",
        "source_unreadable",
        "ambiguous_frontend_path",
        "typescript_property_support_unvalidated",
    }
    blocking = [d for d in degradations if d.get("reason") in prune_blockers]
    # A blocker that names no partition is about the whole read and stops pruning everywhere.
    scope_limits = replace(limits, prune_tier0=False) if any(not d.get("census_language") for d in blocking) else limits
    unprunable_languages = frozenset(str(d["census_language"]) for d in blocking if d.get("census_language"))
    scope, work = _scope_work(
        ordered_regions,
        evidence_by_pair,
        scope_limits,
        unit,
        ranking_mode,
        population_complete,
        change_context=change_context,
        context_gaps=context_gaps,
        execution_budget=execution_budget,
        unprunable_languages=unprunable_languages,
    )
    outcomes: dict[str, QuestionOutcome] = {}

    # Phase 2: ONE invocation per query kind. JVM startup dominates a repository scan -- a call per region
    # per family put a ten-line file at four minutes and a thousand regions at roughly fifty hours -- while
    # the queries themselves are milliseconds once the CPG is loaded.
    rows_by_id: dict[str, list[object]] = {}
    too_expensive_ids: set[str] = set()
    census_reported = False
    query_started = time.monotonic()
    pruned = sum(q.reason == "tier_zero" for q in scope.deferred)
    # Time the phases AFTER this one need. Querying fills rows; arbitration turns them into findings and the
    # outcomes are assembled from that, and neither costs the engine anything -- so a scan that spends its
    # whole budget on queries reports nothing at all, however many of them answered.
    #
    # Measured 2026-09-22, and by accident. A per-query timeout used to cancel the whole scan, which stopped
    # the query phase early and left time to arbitrate: 78 findings. Removing that cancellation was right on
    # its own terms and made the result worse, 0 of 406 questions completed, because the query phase then ran
    # the full 2,700 s deadline to exhaustion. The cascade had been an accidental budget guard, and this is
    # the deliberate one.
    reserve = _arbitration_reserve(execution_budget)
    for kind, requests in _grouped(work, hook_callbacks=hooks).items():
        if not _within_deadline(execution_budget, reserve=reserve):
            degradations.append({"stage": "model", "reason": "query_budget_reserved", "kind": kind, "requests": len(requests)})
            break
        kind_started = time.monotonic()
        batch = getattr(cpg, "run_batch", None)
        if callable(batch):
            # The portioner is the retry layer, so it asks in SINGLE attempts: a portion timed with
            # `run_batch` folds that method's own split-retry into the number, which once read 953 s for one
            # portion and collapsed the sizer. `run_batch_once` is one invocation whose kill returns what it
            # streamed. A backend without it falls back to `run_batch`, unchanged.
            once = getattr(cpg, "run_batch_once", None)
            expensive: dict[str, float] = {}
            answered_batch = _batched(
                once if callable(once) else batch,
                kind,
                requests,
                weights=_sink_weights(work, evidence_by_pair),
                families=_request_families(work),
                within=lambda: _within_deadline(execution_budget, reserve=reserve),
                too_expensive=expensive,
            )
            if expensive:
                # Asked ALONE and still over the ceiling: this question costs more than one invocation may
                # spend, which is a fact about the question and not a transient failure. Reported apart from
                # `query_failed`, so a reader can tell a scan that ran out of luck from one that met a question
                # it cannot afford.
                too_expensive_ids.update(expensive)
                degradations.append(
                    {
                        "stage": "model",
                        "reason": "query_too_expensive",
                        "kind": kind,
                        "requests": len(expensive),
                        "max_seconds": max(expensive.values()),
                    }
                )
            if answered_batch is None:
                # The engine could not answer. That is NOT an empty result, and recording it is what keeps a
                # failed scan from reading as a clean repository: on a 117k-line PHP checkout every query
                # failed at CPG load and the scan reported 500 regions examined with nothing found.
                degradations.append({"stage": "model", "reason": "query_failed", "kind": kind, "requests": len(requests)})
            else:
                # The graph census rides the batch under a reserved key. A frontend that fails every file
                # still exits 0 with a valid CPG containing nothing, and `joern-parse` does not propagate
                # its warnings, so without this a scan of an EMPTY graph is indistinguishable from a scan
                # that found nothing -- which is how a two-file WordPress slice reported a clean bill of
                # health over a 12KB graph with no methods in it at all.
                census = answered_batch.pop("__census__", None)
                if census and not census_reported:
                    entry = census[0] if isinstance(census[0], Mapping) else {}
                    methods = int(str(entry.get("methods", "0")) or 0)
                    if methods == 0 or entry.get("census_failure"):
                        degradations.append(
                            {
                                "stage": "model",
                                "reason": "cpg_empty" if "methods" in entry and methods == 0 else entry.get("census_failure", "cpg_empty"),
                                **{k: entry[k] for k in ("methods", "files", "missing_file_names", "census_language") if k in entry},
                            }
                        )
                    # More than one graph means some files could only be built apart from the rest, and a
                    # flow whose source is in one shard and whose sink is in another does not exist for any
                    # question we can ask. Reporting the split is the difference between a partial answer and
                    # a partial answer that looks whole.
                    shards = int(str(entry.get("shards", "1")) or 1)
                    if shards > 1:
                        degradations.append({"stage": "model", "reason": "cpg_sharded", "shards": shards})
                    census_reported = True
                valid = {rid: rows for rid, rows in answered_batch.items() if rid in requests and isinstance(rows, list)}
                rows_by_id.update(valid)
                missing = len(requests) - len(valid) - len(expensive)
                if missing:
                    degradations.append({"stage": "model", "reason": "query_failed", "kind": kind, "requests": missing})
        else:  # a backend without batching still works, one call at a time
            for rid, params in requests.items():
                if not _within_deadline(execution_budget):
                    break
                answered = cpg.run(kind, params)
                if isinstance(answered, list):
                    rows_by_id[rid] = list(answered)
                else:
                    degradations.append({"stage": "model", "reason": "query_failed", "kind": kind, "requests": 1})
        per_kind[kind] = round(time.monotonic() - kind_started, 2)
    query_seconds = round(time.monotonic() - query_started, 2)

    # Phase 3: arbitrate from the rows already in hand. The arbiters are unchanged: each is handed a
    # CpgResult that simply returns its own prefetched rows.
    #
    # The budget bounds MODEL CALLS, and nothing else. Arbitration is the CPG alone -- it costs no call, no
    # token and no money -- so an exhausted budget withholds the JUDGE and lets the graph keep deciding. It
    # used to break the loop instead, which spent a paid limit to stop unpaid work: on VAmPI that left 16 of
    # 22 regions unexamined and missed a BOLA the graph entails for free.
    #
    # `judged` counts regions actually ARBITRATED and `unasked` those arbitrated with no judge behind them.
    # Both are reported: a region the graph settled and a region the graph was silent about but nobody could
    # afford to ask are not the same result, and collapsing them is the silent truncation this prevents.
    judged: set[tuple[str, str | None]] = set()
    unasked: set[tuple[str, str | None]] = set()
    for rid, region, spec in work:
        if not _within_deadline(execution_budget):
            break
        # Unanswered requests are never adjudicated from invented empty responses.
        if rid not in rows_by_id:
            continue
        exhausted = counted is not None and counted.calls >= limits.max_model_calls
        family = getattr(spec, "family", "")
        prefetched = CpgResult(cpg_path=cpg.cpg_path, run=_prefetched(rows_by_id.get(rid, [])))
        judge = None if exhausted else counted
        try:
            # Candidates exist to be PUT to the judge, and `scan_region` discards them the moment there is
            # no judge to put them to. Enumerating them anyway costs a parse of the region's file per family
            # per region: on a 637-file plugin that was 2,500 enumerations and 737 SECONDS of arbitration
            # over rows that had already been fetched. Nobody should pay for a question nobody will ask.
            candidates: list[dict[str, object]] = []
            if judge is not None:
                enumerated = enumerate_candidates(root, region, family, taxonomy=taxonomy)
                candidates = [{"id": c.id, "text": c.text, "line": c.line} for c in enumerated.candidates]
            found = scan_region(
                prefetched,
                spec,
                path=region.path,
                function=region.function or "",
                client=judge,
                model=model,
                candidates=candidates,
                # A repository's parameters are not all attacker input -- but an ENTRY POINT's are, by
                # definition. That is the trust boundary, and it is the one place both halves of the old
                # objection stop applying.
                parameter_sources=_is_entry_point(region),
                call_depth=ENTRY_POINT_CALL_DEPTH if _is_entry_point(region) else 0,
            )
        except Exception as exc:  # noqa: BLE001 -- one bad region must not end the scan
            logger.warning("model scan failed for %s: %s", region.path, exc)
            degradations.append({"stage": "model", "reason": "region_failed", "path": region.path})
            outcomes[rid] = QuestionOutcome(
                _identity(unit, region, family), "unresolved", "arbitration_failed", _rows_json(rows_by_id[rid])
            )
            continue
        outcomes[rid] = QuestionOutcome(
            _identity(unit, region, family), "completed", "query_answered_and_arbitrated", _rows_json(rows_by_id[rid])
        )
        judged.add((region.path, region.function))
        if exhausted:
            unasked.add((region.path, region.function))
        collected.extend((finding, region.rank) for finding in found)

    if unasked:
        degradations.append({"stage": "model", "reason": "budget_exhausted", "regions_unasked": len(unasked)})

    graph_gaps = tuple(str(d["reason"]) for d in degradations if d.get("reason") in GRAPH_INTEGRITY_GAPS)
    # An integrity gap reaches the questions it can actually be wrong about, which for a census gap is the
    # ONE partition it came from. A partitioned scan raises a gap per graph, and a repository-wide demotion
    # let four JavaScript files -- a webpack build output, a minified select2, a build config and one source
    # file -- take the admissibility of 4,425 PHP regions with them. Third instance of this shape in one week,
    # after vendor exclusion acting as a global veto and line ambiguity inherited by every question, so the
    # rule is now written in the design: a gap is owned by the narrowest scope that caused it.
    scoped_graph_gaps: dict[str, list[str]] = {}
    unscoped_graph_gaps: list[str] = []
    for item in degradations:
        if item.get("reason") not in GRAPH_INTEGRITY_GAPS:
            continue
        partition = str(item.get("census_language") or "")
        if partition:
            scoped_graph_gaps.setdefault(partition, []).append(str(item["reason"]))
        else:
            unscoped_graph_gaps.append(str(item["reason"]))
    # A declared exclusion is a deliberate scope choice, not a failure to read the graph. It stays
    # in coverage, and whether a particular answer needed the excluded semantics is carried by that
    # question's own unresolved call destinations, not assumed for every answer in the repository.
    declared_gaps = tuple(str(d["reason"]) for d in degradations if d.get("reason") in DECLARED_EXCLUSION_GAPS)
    for question in scope.selected:
        rid = question.identity.question_id
        if rid not in outcomes:
            has_answer = rid in rows_by_id
            outcomes[rid] = QuestionOutcome(
                question.identity,
                "not_arbitrated" if has_answer else "unanswered",
                "query_too_expensive"
                if rid in too_expensive_ids
                else "deadline_exhausted"
                if not _within_deadline(execution_budget)
                else "query_unanswered",
                _rows_json(rows_by_id[rid]) if has_answer else None,
            )
        if question.identity in context_gaps and outcomes[rid].status == "completed":
            outcomes[rid] = replace(outcomes[rid], status="unresolved", reason="change_context_incomplete")
        if outcomes[rid].status == "completed":
            # A gap with no partition is about the whole read and reaches everything. A scoped one reaches its
            # own partition, and a question whose language the scan cannot place is treated as reached: an
            # unplaceable question is not evidence that the gap missed it.
            reached = bool(unscoped_graph_gaps) or bool(scoped_graph_gaps.get(question.identity.language))
            if reached or (scoped_graph_gaps and not question.identity.language):
                outcomes[rid] = replace(outcomes[rid], status="unresolved", reason="graph_incomplete")
    scope = replace(scope, unresolved_boundaries=tuple(dict.fromkeys((*scope.unresolved_boundaries, *graph_gaps, *declared_gaps))))
    ordered_outcomes = tuple(outcomes[q.identity.question_id] for q in scope.selected)
    scanned = len(judged)

    findings = _ordered(_deduplicated(collected))
    # The graph has answered everything it is going to. Its scratch tree holds the CPG, the request files and
    # joern's own working copy -- tens of megabytes per scan -- and nothing else reclaims it.
    return ModelScanResult(
        partitions=getattr(cpg, "partitions", ()),
        findings=findings,
        by_rung=_tally(findings),
        regions_scanned=scanned,
        regions_unjudged=max(len(regions) - scanned, 0),
        regions_unasked=len(unasked),
        model_calls=counted.calls if counted is not None else 0,
        cost_usd=round(_cost(counted), 4),
        seconds=round(time.monotonic() - started, 2),
        build_seconds=build_seconds,
        query_seconds=query_seconds,
        query_seconds_by_kind=per_kind,
        degradations=tuple(degradations),
        tiers=tuple(tiers),
        tier_counts={tier: sum(1 for t in tiers if t[3] == tier) for tier in sorted({t[3] for t in tiers})},
        requests_pruned=pruned,
        scope=scope,
        question_outcomes=ordered_outcomes,
        family_coverage=_family_coverage(scope, ordered_outcomes),
        change_context=change_context,
    )


# Reading the graph failed or produced something incomplete. An answer drawn from it cannot be
# trusted, so a completed outcome is demoted.
#
# The test for membership is whether the gap could make a reported answer WRONG, not whether it cost
# coverage. An unparsed file may hold the sanitizer that would have cleared a flow this scan reports,
# so `files_unparsed` belongs here and demoting is the conservative reading. A missing file the
# partition census expected is the same shape. That is why `cross_partition_semantics_unresolved` is
# NOT here: a flow this tool cannot follow from one language into another can hide a finding, never
# invent one, because a PHP sink is sanitised in PHP. Demoting on it protected nothing and cost
# everything -- measured 2026-09-21, where a WordPress plugin with 36 regions of admin JavaScript
# completed none of 520 questions while establishing 43 findings, and admission requires a completed
# outcome. Every multi-language repository was unadmittable by construction, which is every plugin
# this product was built for.
GRAPH_INTEGRITY_GAPS = frozenset(
    {
        "files_unparsed",
        "cpg_empty",
        "partition_file_census_incomplete",
        "partition_file_census_unavailable",
        "cpg_sharded",
        "symlink_context_unresolved",
        "frontend_unsupported",
        "source_unreadable",
        "ambiguous_frontend_path",
        "typescript_property_support_unvalidated",
    }
)
# Declared, intentional exclusions. The exclusion stays physical and stays reported; it is not
# evidence that any particular first-party answer is wrong. Treating it as one demoted every
# answer on every real repository, because every real repository excludes its dependencies.
# Declared, intentional exclusions. The exclusion stays physical and stays reported -- both classes are
# added to the scope's unresolved boundaries, so a declared gap is still published as unresolved; the class
# decides only whether it demotes every answer in the repository.
#
# `cross_partition_semantics_unresolved` is one of these: analysing each language separately, and not
# modelling a flow that leaves one for another, is a deliberate scope choice of exactly the kind vendor
# exclusion is. It was in the integrity set until 2026-09-21 and the reason for moving it is above.
DECLARED_EXCLUSION_GAPS = frozenset({"vendor_semantics_unresolved", "cross_partition_semantics_unresolved"})


def _identity(unit: str, region: ScanRegion, family: str) -> QuestionIdentity:
    return QuestionIdentity(unit, region.language, region.path, region.function, family)


def _rows_json(rows: object) -> str:
    return json.dumps(rows, sort_keys=True, separators=(",", ":"))


def _scope_work(
    regions: Sequence[ScanRegion],
    evidence: Mapping[tuple[str, str, str], Evidence],
    limits: ScanBudget,
    unit: str,
    mode: str,
    population_complete: bool,
    *,
    failure: str | None = None,
    change_context: ChangeContext | None = None,
    context_gaps: set[QuestionIdentity] | None = None,
    execution_budget: ExecutionBudget | None = None,
    # Languages whose graph might be missing the sink their vectors did not see. Pruning is withheld from
    # their questions and from nobody else's.
    unprunable_languages: frozenset[str] = frozenset(),
) -> tuple[ScopeDecision, list[tuple[str, ScanRegion, ArbiterSpec]]]:
    """Consume the ranker's final order once; the returned work IS selected scope."""
    selected: list[RankedQuestion] = []
    deferred: list[DeferredQuestion] = []
    work: list[tuple[str, ScanRegion, ArbiterSpec]] = []
    boundaries: list[str] = [] if population_complete else ["population_not_asserted_complete"]
    if failure:
        boundaries.append(failure)
    if change_context is not None:
        boundaries.extend(change_context.unresolved_boundaries)
    for index, region in enumerate(regions):
        for family in region.families:
            identity = _identity(unit, region, family)
            if failure is None and not _within_deadline(execution_budget):
                failure = "deadline_exhausted"
                boundaries.append(failure)
            spec = None if failure else _spec_for(family, region.language)
            vector = evidence.get((region.path, region.function or "", family))
            facts: tuple[str, ...] = ("static_rank=" + str(region.rank),)
            if failure:
                facts += ("analysis_not_started=" + failure,)
            elif vector is not None:
                facts += ("normalized_evidence=" + _rows_json(asdict(vector)), "tier=" + str(vector.tier), "score=" + str(vector.score))
            elif isinstance(spec, TaintSpec):
                facts += ("evidence_unknown",)
                boundaries.append("evidence_unknown:" + identity.question_id)
            else:
                facts += ("taint_evidence_not_applicable",)
            if change_context is not None:
                facts += (
                    "change_sites="
                    + _rows_json(
                        {
                            "base_revision": change_context.base_revision,
                            "head_revision": change_context.head_revision,
                            "changed_paths": change_context.changed_paths,
                            "deleted_paths": change_context.deleted_paths,
                            "declaration_paths": change_context.declaration_paths,
                            "path_encoding": change_context.path_encoding,
                        }
                    ),
                )
                facts += tuple(
                    "affected_relationship=" + _rows_json(r.to_payload()) for r in change_context.relationships if r.target == identity
                )
                if identity in (context_gaps or set()):
                    facts += ("change_context_incomplete",)
            reason = (
                failure
                if failure
                else "unsupported_family"
                if spec is None
                else failure
                or (
                    "region_budget"
                    if index >= limits.max_regions
                    else "tier_zero"
                    if limits.prune_tier0
                    and identity.language not in unprunable_languages
                    and identity not in (context_gaps or set())
                    and isinstance(spec, TaintSpec)
                    and vector is not None
                    and vector.tier == TIER_EXCLUDE
                    else None
                )
            )
            if reason:
                deferred.append(DeferredQuestion(identity, reason, facts))
                if reason == "unsupported_family":
                    boundaries.append("unsupported_family:" + identity.question_id)
            else:
                assert spec is not None
                selected.append(
                    RankedQuestion(
                        identity,
                        float(-len(selected)),
                        facts,
                        vector.tier if vector is not None else None,
                        vector.score if vector is not None else None,
                    )
                )
                work.append((identity.question_id, region, spec))
    return ScopeDecision(
        "existing-static-evidence-v1", mode, population_complete, tuple(selected), tuple(deferred), tuple(boundaries)
    ), work


def _family_coverage(scope: ScopeDecision, outcomes: tuple[QuestionOutcome, ...]) -> tuple[FamilyCoverage, ...]:
    population: list[RankedQuestion | DeferredQuestion] = [*scope.selected, *scope.deferred]
    keys = sorted({(q.identity.unit, q.identity.language, q.identity.family) for q in population})

    def matches(identity: QuestionIdentity, key: tuple[str, str, str]) -> bool:
        return (identity.unit, identity.language, identity.family) == key

    return tuple(
        FamilyCoverage(
            *key,
            selected=sum(matches(q.identity, key) for q in scope.selected),
            completed=sum(matches(q.identity, key) and q.status == "completed" for q in outcomes),
            unanswered=sum(matches(q.identity, key) and q.status != "completed" for q in outcomes),
            deferred=sum(matches(q.identity, key) for q in scope.deferred),
            unsupported=sum(matches(q.identity, key) and q.reason == "unsupported_family" for q in scope.deferred),
        )
        for key in keys
    )


# The share of what is left when querying starts that is kept back for arbitration and reporting. A quarter
# with a sixty-second floor: on the measured plugin the phases after querying took roughly 220 s for 400
# questions, and a scan too small for the floor to matter is a scan where the floor costs nothing.
ARBITRATION_RESERVE_SHARE = 0.2
ARBITRATION_RESERVE_FLOOR = 60.0
# A reserve may never take more than half of what is left. Held back without this, the floor swallowed a
# whole small budget and the query loop never ran at all -- a scan with a fifth of a second to spend must
# still spend it, and a control caught exactly that.
ARBITRATION_RESERVE_CAP = 0.5


def _arbitration_reserve(execution_budget: ExecutionBudget | None) -> float:
    if execution_budget is None:
        return 0.0
    remaining = max(0.0, execution_budget.deadline_monotonic - time.monotonic())
    return min(max(ARBITRATION_RESERVE_FLOOR, remaining * ARBITRATION_RESERVE_SHARE), remaining * ARBITRATION_RESERVE_CAP)


def _pair_key(region: ScanRegion, spec: ArbiterSpec) -> tuple[str, str, str]:
    return (region.path, region.function or "", getattr(spec, "family", ""))


# What one arbitration request costs the engine, in the only unit that predicts it: the sink CALLS its
# family matches in scope. `reachableByFlows` is asked per matched sink, so a request whose family is `echo`
# asks a different question from one whose family is `$wpdb->get_var`, at identical request counts.
#
# Measured 2026-09-22 on one WordPress plugin's graph, at a fixed 100 requests each: SQL injection 147 s with
# six declared sinks, path 194 s with sixteen, output encoding 704 s with seven. The declared count does not
# predict cost and the request count does not predict cost. The matched count does.
#
# The budget is in sink visits rather than requests, so a family whose sinks are rare rides in one batch and
# a family whose sinks are everywhere is split until it fits. Splitting by request count, which is what the
# backend's failure retry does, cannot help: every part carries the same everywhere-sinks.
MAX_SINK_VISITS_PER_BATCH = 600


def _sink_weights(
    work: Sequence[tuple[str, ScanRegion, ArbiterSpec]], evidence_by_pair: Mapping[tuple[str, str, str], Any]
) -> dict[str, int]:
    """Sink calls in scope per request id, from the evidence pass that already counted them.

    A request the evidence pass never saw weighs one. That is deliberate: an unknown cost must not make a
    batch look cheap, but neither should it dominate a budget it was never measured against.
    """
    weights: dict[str, int] = {}
    for rid, region, spec in work:
        evidence = evidence_by_pair.get(_pair_key(region, spec))
        sinks = getattr(evidence, "sinks", ()) if evidence is not None else ()
        weights[rid] = max(1, len(sinks))
    return weights


def _request_families(work: Sequence[tuple[str, ScanRegion, ArbiterSpec]]) -> dict[str, str]:
    """The family of each request id: the unit the sizer learns a cost rate for."""
    return {rid: str(getattr(spec, "family", "")) for rid, _region, spec in work}


def _sized_batches(requests: Mapping[str, Mapping[str, object]], weights: Mapping[str, int]) -> list[dict[str, Mapping[str, object]]]:
    """Chunks whose implied sink work stays under the budget, in the order the ranker gave.

    The order is the ranker's and must stay the ranker's. A first attempt packed heaviest-first, which is
    better packing and worse analysis: on the measured plugin the expensive output-encoding chunks ran first,
    spent the deadline, and left injection with 114 questions asked and none answered -- the one family
    holding a true positive on that subject. A deadline always cuts a tail, and the tail it should cut is the
    one the ranker put last.

    One request over the budget on its own gets its own chunk rather than being dropped: the scan's job is to
    report that it is expensive, not to decide it is unaskable.
    """
    ordered = list(requests)
    chunks: list[dict[str, Mapping[str, object]]] = []
    current: dict[str, Mapping[str, object]] = {}
    carried = 0
    for rid in ordered:
        weight = weights.get(rid, 1)
        if current and carried + weight > MAX_SINK_VISITS_PER_BATCH:
            chunks.append(current)
            current, carried = {}, 0
        current[rid] = requests[rid]
        carried += weight
    if current:
        chunks.append(current)
    return chunks


def _batched(
    batch: Any,
    kind: str,
    requests: Mapping[str, Mapping[str, object]],
    *,
    weights: Mapping[str, int],
    families: Mapping[str, str] | None = None,
    within: Callable[[], bool] = lambda: True,
    too_expensive: dict[str, float] | None = None,
) -> dict[str, list[object]] | None:
    """Ask one kind in portions the engine can afford, and merge what answered.

    A portion that fails leaves its own requests unanswered rather than discarding the answers beside it.
    Everything answered is returned; only a kind where no portion answered at all is reported as unavailable.
    A request that could not be answered even alone, and spent more than a portion's target trying, is
    recorded in ``too_expensive`` with the seconds it took -- a different fact from a failure, and reported
    as one.
    """
    chunks = _sized_batches(requests, weights)
    # The cost model is MEASURED, per family. The engine reports what each answer cost, so the sizer learns
    # the fixed start as the wall time the answers do not account for and a seconds-per-sink-visit rate for
    # each family from its own answers. One global rate fitted to whole portions could not tell one 90 s
    # request from thirty 3 s ones: on the plugin it fitted the tail, fell to three visits per portion, and
    # never grew back, because a fast portion under an assumed 70 s start read as no information at all.
    sizer = _PortionSizer(weights, families)
    if len(chunks) > 1:
        logger.info(
            "cpg %s split into %d batches by sink weight (%d request(s), %d sink visit(s))",
            kind,
            len(chunks),
            len(requests),
            sum(weights.get(rid, 1) for rid in requests),
        )
    merged: dict[str, list[object]] = {}
    answered_any = False
    # A QUEUE, not a fixed list, because a killed portion leaves a remainder that must be re-asked rather than
    # dropped. The queue keeps working while there is time and something left to ask; `fit` sizes the head
    # against the current cost model.
    queue: list[dict[str, Mapping[str, object]]] = list(chunks)
    # Requests that were RUNNING when a portion was killed. The engine answers in order and streams each answer
    # as it finishes, so after a kill the first id without an answer is the one that held the process at the
    # ceiling, and every id after it never started. Those are not evidence of anything and go straight back;
    # the culprit is asked alone, after everything else, so an expensive question cannot hold the queue.
    #
    # This is the difference between a TRANSIENT kill and a genuinely expensive question. The earlier queue
    # re-asked the whole remainder at half the size, and on the plugin that meant the same expensive
    # output-encoding request killing portion after portion while the cheap ones behind it waited.
    isolated: list[str] = []
    while queue or isolated:
        # Checked per portion, not per kind: one kind runs every portion inside a single loop iteration, so a
        # per-kind check would let taint spend the whole budget before the reserve looked.
        if not within():
            left = sum(len(c) for c in queue) + len(isolated)
            logger.info("cpg %s: %d request(s) left unasked to keep time for arbitration", kind, left)
            break
        alone = not queue
        chunk = {isolated[0]: requests[isolated.pop(0)]} if alone else sizer.fit(queue.pop(0), pending=queue)
        started = time.monotonic()
        answer = batch(kind, chunk)
        seconds = time.monotonic() - started
        timing = _answer_timing(answer)
        answered_ids = {rid for rid in (answer or ()) if rid in chunk}
        remainder = [rid for rid in chunk if rid not in answered_ids]
        if answer is not None:
            answered_any = True
            merged.update({rid: rows for rid, rows in answer.items() if rid in chunk})
            if "__census__" in answer and "__census__" not in merged:
                merged["__census__"] = answer["__census__"]
        # A kill is a partial answer from an engine that LOADED: the census arrived, so the process was
        # working through requests in order. Nothing at all -- no census -- is a failure to start or a crash,
        # and says nothing about which request was at fault.
        killed = answer is not None and bool(remainder)
        culprit = remainder[0] if killed else None
        sizer.observe(chunk, seconds, answered=answered_ids, timing=timing, culprit=culprit)
        if not remainder:
            continue
        if alone or len(chunk) == 1:
            # Asked alone and still unanswered. Termination rests here: a single request is never re-queued.
            if seconds >= PORTION_TARGET_SECONDS and too_expensive is not None:
                too_expensive[remainder[0]] = round(seconds, 1)
            logger.info("cpg %s: request %s unanswered when asked alone (%.0fs)", kind, remainder[0], seconds)
            continue
        if culprit is not None:
            isolated.append(culprit)
            rest = {rid: chunk[rid] for rid in remainder if rid != culprit}
            logger.info(
                "cpg %s: portion killed on request %s after %d of %d answered; %d re-queued, the culprit asked alone later",
                kind,
                culprit,
                len(answered_ids),
                len(chunk),
                len(rest),
            )
        else:
            # Nothing answered and no census: the sizer has already made this family dearer, so `fit` will cut
            # the portion smaller next time. Heads shrink to single requests, and a single request is dropped.
            rest = {rid: chunk[rid] for rid in remainder}
        if rest:
            queue.insert(0, rest)
    return merged if answered_any else None


def _answer_timing(answer: Mapping[str, object] | None) -> dict[str, float]:
    """Seconds per answered request id, from the engine's own streamed cost; empty when it reported none."""
    timing: dict[str, float] = {}
    raw = answer.get(TIMING) if isinstance(answer, Mapping) else None
    if not isinstance(raw, list):
        return timing
    for entry in raw:
        if isinstance(entry, Mapping) and isinstance(entry.get("ms"), (int, float)):
            rid = str(entry.get("id", ""))
            # Shards each answer the same id; its cost is what all of them spent.
            timing[rid] = timing.get(rid, 0.0) + float(entry["ms"]) / 1000.0
    return timing


# What one portion should take: long enough that the fixed JVM start is a minority of it, short enough that
# a mis-estimate is bounded and a kill costs little.
PORTION_TARGET_SECONDS = 120.0
# A PRIOR for the start-and-load, used until one whole portion has shown the real one: its wall time less the
# time its answers report. Measured 70 s on a 4 MB graph once, and 25 s on the plugin in the trace that
# showed the constant was wrong -- which is why it is a prior and not a fact.
PORTION_FIXED_SECONDS = 70.0
# A family with no answers yet is costed at the dearest rate seen so far, never below this. Pessimism is the
# cheaper mistake: an over-estimate costs one extra JVM start, an under-estimate costs a ceiling.
PORTION_PRIOR_SECONDS_PER_VISIT = (PORTION_TARGET_SECONDS - PORTION_FIXED_SECONDS) / MAX_SINK_VISITS_PER_BATCH
# The least the engine's work may be budgeted per portion, whatever the fixed start is measured at.
PORTION_MIN_WORK_SECONDS = 10.0


class _PortionSizer:
    """Size portions in predicted SECONDS, from what the engine has shown each family costs.

    Every answered request contributes its own reported cost to its family's rate (seconds per sink visit).
    A whole portion also shows the fixed start: its wall time less what its answers account for. A killed
    portion's culprit contributes a LOWER BOUND -- it ran for at least the time the others do not explain --
    so its family becomes dearer and the next portion of that family is cut to fit. An engine that reports no
    costs is costed from the portion's wall time, spread over its requests by prediction.
    """

    def __init__(self, weights: Mapping[str, int], families: Mapping[str, str] | None = None) -> None:
        self.weights = weights
        self.families = families or {}
        self.fixed = PORTION_FIXED_SECONDS
        self._fixed_seen: list[float] = []
        self.spent: dict[str, float] = {}
        self.visited: dict[str, int] = {}
        self.penalty: dict[str, float] = {}

    def weight(self, chunk: Mapping[str, object]) -> int:
        return sum(self.weights.get(rid, 1) for rid in chunk)

    def rate(self, family: str) -> float:
        """Seconds per sink visit for a family: its own, else the dearest known, else the prior."""
        known = [self.spent[f] / self.visited[f] for f in self.visited if self.visited[f] > 0]
        base = self.spent[family] / self.visited[family] if self.visited.get(family) else max([PORTION_PRIOR_SECONDS_PER_VISIT, *known])
        return base * self.penalty.get(family, 1.0)

    def cost(self, rid: str) -> float:
        return self.rate(self.families.get(rid, "")) * self.weights.get(rid, 1)

    @property
    def allowance(self) -> float:
        """Predicted engine seconds one portion may carry, once the fixed start is paid."""
        return max(PORTION_MIN_WORK_SECONDS, PORTION_TARGET_SECONDS - self.fixed)

    def fit(
        self, chunk: dict[str, Mapping[str, object]], *, pending: list[dict[str, Mapping[str, object]]]
    ) -> dict[str, Mapping[str, object]]:
        """Cut this portion to the allowance, or grow it from the ones behind it while it still fits.

        Always at least one request, however dear: the scan's job is to report that it is expensive, not to
        decide it is unaskable. The rest of a cut portion goes to the FRONT of the queue, in ranker order.
        """
        kept: dict[str, Mapping[str, object]] = {}
        carried = 0.0
        for rid, req in chunk.items():
            if kept and carried + self.cost(rid) > self.allowance:
                break
            kept[rid] = req
            carried += self.cost(rid)
        rest = {rid: req for rid, req in chunk.items() if rid not in kept}
        if rest:
            pending.insert(0, rest)
            return kept
        # Grown id by id, not chunk by chunk: the queue's head is often one large chunk -- the remainder of the
        # ranker's first cut -- and waiting for the whole of it to fit kept portions at one request after a
        # collapse even once the engine had shown each costs a fraction of a second.
        while pending:
            head = pending[0]
            taken = []
            for rid in head:
                if carried + self.cost(rid) > self.allowance:
                    break
                taken.append(rid)
                carried += self.cost(rid)
            for rid in taken:
                kept[rid] = head.pop(rid)
            if head:
                break
            pending.pop(0)
        return kept

    def _learn(self, rid: str, seconds: float) -> None:
        family = self.families.get(rid, "")
        self.spent[family] = self.spent.get(family, 0.0) + max(0.0, seconds)
        self.visited[family] = self.visited.get(family, 0) + self.weights.get(rid, 1)

    def observe(
        self,
        chunk: Mapping[str, object],
        seconds: float,
        *,
        answered: set[str] | frozenset[str],
        timing: Mapping[str, float] | None = None,
        culprit: str | None = None,
    ) -> None:
        timing = timing or {}
        done = [rid for rid in chunk if rid in answered]
        whole = len(done) == len(chunk)
        reported = all(rid in timing for rid in done)
        if done and reported:
            for rid in done:
                self._learn(rid, timing[rid])
            explained = sum(timing[rid] for rid in done)
            if whole:
                # The fixed start is what the answers do not explain. The median of what has been seen, so one
                # slow start (a cold page cache, a busy host) does not resize every portion after it.
                self._fixed_seen.append(max(0.0, seconds - explained))
                self.fixed = sorted(self._fixed_seen)[len(self._fixed_seen) // 2]
        elif done:
            # No per-answer costs: spread the portion's work over its requests in proportion to prediction.
            predicted = {rid: self.cost(rid) for rid in done}
            total = sum(predicted.values()) or 1.0
            work = max(0.0, seconds - self.fixed)
            if whole and seconds < self.fixed:
                self.fixed = seconds  # a portion cannot finish before its own start: the prior was too high
            for rid in done:
                self._learn(rid, work * predicted[rid] / total)
            explained = work
        else:
            explained = 0.0
        if culprit is not None:
            # It ran at least as long as nothing else accounts for, and did not finish. A lower bound, which is
            # exactly what the next portion of its family should be sized against.
            self._learn(culprit, seconds - self.fixed - (explained if reported else 0.0))
        elif not done:
            # Nothing answered and no census: the engine said nothing about cost, only that this was too much.
            for family in {self.families.get(rid, "") for rid in chunk}:
                self.penalty[family] = self.penalty.get(family, 1.0) * 2
        logger.info(
            "cpg portion of %d request(s), %d sink visit(s): %d answered in %.0fs; fixed start %.0fs, allowance %.0fs",
            len(chunk),
            self.weight(chunk),
            len(done),
            seconds,
            self.fixed,
            self.allowance,
        )


def _collect(
    regions: Sequence[ScanRegion], *, execution_budget: ExecutionBudget | None = None
) -> list[tuple[str, ScanRegion, ArbiterSpec]]:
    """Every (region, family) question with an arbiter, in the order given, with batch-local ids."""
    work: list[tuple[str, ScanRegion, ArbiterSpec]] = []
    for region in regions:
        for family in region.families:
            if not _within_deadline(execution_budget):
                return work
            spec = _spec_for(family, region.language)
            if spec is None:
                continue
            work.append((f"{len(work)}", region, spec))
    return work


EVIDENCE_PORTION = 4000  # requests per evidence invocation; roughly ten seconds of work behind one JVM start


def _portioned_evidence(cpg: Any, requests: Mapping[str, Mapping[str, object]]) -> dict[str, Any] | None:
    """The evidence pass in portions, merged. ``None`` only when no portion answered.

    Typed as the batch returns it -- rows are the engine's mappings, and the caller reads them as such.
    """
    ids = list(requests)
    if len(ids) <= EVIDENCE_PORTION:
        answered: dict[str, Any] | None = cpg.run_batch("taint", requests)
        return answered
    merged: dict[str, Any] = {}
    answered_any = False
    for start in range(0, len(ids), EVIDENCE_PORTION):
        part = cpg.run_batch("taint", {rid: requests[rid] for rid in ids[start : start + EVIDENCE_PORTION]})
        if part is None:
            continue
        answered_any = True
        census = part.pop("__census__", None)
        if census is not None and "__census__" not in merged:
            merged["__census__"] = census
        merged.update(part)
    return merged if answered_any else None


def _evidence_pass(
    cpg: Any,
    work: Sequence[tuple[str, ScanRegion, ArbiterSpec]],
    hooks: str,
    *,
    degradations: list[Mapping[str, object]] | None = None,
    context_rows: dict[QuestionIdentity, list[Mapping[str, object]]] | None = None,
    unit: str = "repository",
) -> tuple[dict[tuple[str, str, str], Evidence], int]:
    """The evidence vector of every taint pair in ``work``, keyed by (path, function, family).

    Returns the vectors and the number of requests the engine did not answer (0 when it answered), so a
    failed pass is recorded rather than read as "no evidence anywhere".
    """
    grouped_taint = _grouped(list(work), hook_callbacks=hooks).get("taint", {})
    if not grouped_taint:
        return {}, 0
    requests = {
        rid: {**dict(params), "evidenceOnly": "true", **({"contextEvidence": "true"} if context_rows is not None else {})}
        for rid, params in grouped_taint.items()
    }
    # Portioned by request count, because evidence has no per-request weight yet -- it is the pass that
    # PRODUCES the weights. It is cheap per request, 17,700 in 44 s, and it was still one all-or-nothing
    # batch: a 22,125-request evidence pass on a plugin's push transaction exceeded its ceiling under load and
    # cost the whole scan. Streaming keeps what finished when a portion is killed; portioning keeps a single
    # kill from being the whole pass.
    answered = _portioned_evidence(cpg, requests)
    if answered is None:
        return {}, len(requests)
    census = answered.pop("__census__", None)
    if census and degradations is not None:
        entry = census[0] if isinstance(census[0], Mapping) else {}
        try:
            methods = int(str(entry.get("methods", "0")))
            shards = int(str(entry.get("shards", "1")))
        except ValueError:
            methods, shards = 0, 1
        if methods <= 0 or entry.get("census_failure"):
            degradations.append(
                {
                    "stage": "model",
                    "reason": "cpg_empty" if "methods" in entry and methods <= 0 else entry.get("census_failure", "cpg_empty"),
                    # The partition travels here too. This pass raises the same gap as the arbitration pass,
                    # and carrying the language in one place and not the other left an unscoped copy that
                    # demoted every question in the repository -- the scoping fix looked applied and was not.
                    **{k: entry[k] for k in ("methods", "files", "missing_file_names", "census_language") if k in entry},
                }
            )
        if shards > 1:
            degradations.append({"stage": "model", "reason": "cpg_sharded", "shards": shards})
    by_rid = {rid: (region, spec) for rid, region, spec in work}
    out: dict[tuple[str, str, str], Evidence] = {}
    for rid, rows in answered.items():
        pair = by_rid.get(rid)
        if pair is None or rid not in requests or not isinstance(rows, list):
            continue
        region, spec = pair
        if context_rows is not None:
            context_rows[_identity(unit, region, spec.family)] = [r for r in rows if isinstance(r, Mapping)]
        evidence = evidence_from_rows(
            rows,
            entry=_is_entry_point(region),
            # Rank 1.0 is the public tier. Provenance -- declared by a route contract versus inferred from
            # an absent decorator -- is not yet carried on ScanRegion, so this is the proxy phase 0 has;
            # the brief names it as the field to thread through next.
            access_declared_public=region.rank >= 1.0,
            bound_names=getattr(spec, "safe_shape_sinks", ()),
            shipped=bool(getattr(region, "shipped", True)),
        )
        if evidence is not None:
            out[_pair_key(region, spec)] = evidence
    # Legacy ranker keys omit language. An overlapping frontend population cannot
    # borrow another language's vector; partitioned callers retain distinct IDs.
    languages_by_pair: dict[tuple[str, str, str], set[str]] = {}
    for rid, region, spec in work:
        if rid in requests:
            languages_by_pair.setdefault(_pair_key(region, spec), set()).add(region.language)
    for key, languages in languages_by_pair.items():
        if len(languages) > 1:
            out.pop(key, None)
    if context_rows is not None:
        _context_pass(cpg, work, context_rows, unit=unit)
    return out, len(requests) - len(out)


def _context_pass(
    cpg: Any,
    work: Sequence[tuple[str, ScanRegion, ArbiterSpec]],
    context_rows: dict[QuestionIdentity, list[Mapping[str, object]]],
    *,
    unit: str,
) -> None:
    """Collect change context for the families the evidence pass does not ask.

    The evidence pass dispatches taint only, because only taint has an evidence vector to rank by.
    Change context is a different question and every family needs its own: without this, dominance
    and configuration questions reported `context_projection_unavailable` on every repository and
    could never complete, which left 231 of 436 questions unresolved on the measured Node case.

    Each family's own query supplies its own scope. A failure here leaves the family's context
    absent, which the caller already treats as unresolved, so it degrades exactly as before.
    """
    grouped = _grouped(list(work))
    by_rid = {rid: (region, spec) for rid, region, spec in work}
    for kind in ("dominance", "config"):
        requests = {rid: {**dict(params), "contextEvidence": "true"} for rid, params in grouped.get(kind, {}).items()}
        if not requests:
            continue
        answered = cpg.run_batch(kind, requests)
        if answered is None:
            continue
        answered.pop("__census__", None)
        for rid, rows in answered.items():
            pair = by_rid.get(rid)
            if pair is None or not isinstance(rows, list):
                continue
            region, spec = pair
            context_rows[_identity(unit, region, spec.family)] = [r for r in rows if isinstance(r, Mapping)]


def order_by_evidence(regions: Sequence[ScanRegion], evidence: Mapping[tuple[str, str, str], Evidence]) -> list[ScanRegion]:
    """Regions by their best pair's (tier, score), then by the static order they arrived in.

    ONE definition, used by the scan to spend its budget and by `benchmarks/ranking/position.py` to say
    where a pinned CVE lands under it; if they drifted, the benchmark would measure the wrong thing. A
    region with no evidence at all -- no taint family, or a pass that failed -- sorts after every region
    that has some, in static order: the scan does not know it is safe, it knows nothing about it.
    """
    best: dict[tuple[str, str], tuple[int, float]] = {}
    for (path, function, _family), vector in evidence.items():
        key = (path, function)
        best[key] = max(best.get(key, (-1, 0.0)), vector.order_key)
    indexed = list(enumerate(regions))
    return [
        region
        for _, region in sorted(
            indexed,
            key=lambda item: (
                -best.get((item[1].path, item[1].function or ""), (-1, 0.0))[0],
                -best.get((item[1].path, item[1].function or ""), (-1, 0.0))[1],
                item[0],
            ),
        )
    ]


def _dispose(cpg: object) -> None:
    """Release a built CPG's scratch tree. Never raises: cleanup must not turn a good scan into a failure."""
    cleanup = getattr(cpg, "cleanup", None)
    if callable(cleanup):
        try:
            cleanup()
        except Exception as exc:  # noqa: BLE001 -- a scan that found things must not fail while tidying up
            logger.warning("could not remove the cpg scratch directory: %s", exc)


def _within_deadline(budget: ExecutionBudget | None, *, reserve: float = 0.0) -> bool:
    """Is there time left, keeping back `reserve` seconds for whatever must happen after this?

    A reserve of zero is the committed meaning and every caller but the query loop uses it. The query loop
    passes one, because rows the engine returned are worth nothing until something turns them into findings.
    """
    return budget is None or time.monotonic() < budget.deadline_monotonic - reserve


def _build(backend: Any, root: Path, language: str, *, execution_budget: ExecutionBudget | None = None) -> Any:
    """Build through the backend, passing the language and the vendored trees when the backend can use them."""
    from .layout import vendored_directories

    if not _within_deadline(execution_budget):
        return None
    excluded = vendored_directories(root) if root.is_dir() else ()
    if execution_budget is not None:
        try:
            inspect.signature(backend.build).bind(root, language=language, exclude=excluded, execution_budget=execution_budget)
        except (TypeError, ValueError):
            # An old backend cannot silently turn a bounded push into an ordinary scan.
            return None
        if not _within_deadline(execution_budget):
            return None
        return backend.build(root, language=language, exclude=excluded, execution_budget=execution_budget)
    try:
        return backend.build(root, language=language, exclude=excluded)
    except TypeError:  # a backend from before the retry existed, including every test double
        try:
            return backend.build(root, language=language)
        except TypeError:
            return backend.build(root)


def _prefetched(rows: list[object]):  # type: ignore[no-untyped-def]
    """A `run` that ignores the question and returns rows already fetched in the batch."""

    def run(query: str, params: Mapping[str, object]) -> object:
        del query, params
        return rows

    return run


def _grouped(
    work: Sequence[tuple[str, ScanRegion, ArbiterSpec]], *, hook_callbacks: str = ""
) -> dict[str, dict[str, Mapping[str, object]]]:
    """The work, keyed by query kind, with each request built by the arbiter's OWN parameter function.

    Building the parameters here instead would be a second copy that drifts from the arbiter's -- the exact
    shape of the five bugs the predecessor spent a session finding.
    """
    grouped: dict[str, dict[str, Mapping[str, object]]] = {}
    for rid, region, spec in work:
        function = region.function or ""
        entry = _is_entry_point(region)
        if isinstance(spec, DominanceSpec):
            kind, params = "dominance", dominance_params(spec, function=function, file=region.path)
        elif isinstance(spec, ConfigSpec):
            kind, params = "config", config_params(spec, function=function, file=region.path)
        else:
            kind, params = (
                "taint",
                taint_params(
                    spec,
                    function=function,
                    file=region.path,
                    parameter_sources=entry,
                    call_depth=ENTRY_POINT_CALL_DEPTH if entry else 0,
                    hook_callbacks=hook_callbacks,
                ),
            )
        grouped.setdefault(kind, {})[rid] = params
    return grouped


def _hook_callbacks(root: Path, regions: Sequence[ScanRegion]) -> str:
    """``hook:callback;hook:callback`` for the PHP files this scan is about, or ``""``.

    Rendered here rather than in the query because a CPGQL parameter is a string, and rendered from the
    regions rather than by walking the tree because the regions already name every file in scope.
    """
    paths = sorted({region.path for region in regions if region.language == "php" and region.path})
    if not paths:
        return ""
    from ..mapping import php_hook_callbacks
    from ..preprocess import FileTarget

    targets = [
        FileTarget(path=path, absolute_path=str(root / path), language="php", loc=0, tags=[], has_fuzz_entry_point=False) for path in paths
    ]
    table = php_hook_callbacks(root, targets)
    return ";".join(f"{hook}:{name}" for hook, names in table.items() for name in names)


def _is_entry_point(region: ScanRegion) -> bool:
    """Is this region a place untrusted input actually enters?

    A named function the entry-point mapper found, not a file the walker fell back to. The distinction is
    what makes treating parameters as untrusted sound: a handler's parameters carry request data, an
    arbitrary helper's carry whatever its caller had.

    A module body is excluded even when the mapper marked it an entry point: a module has no parameters, so
    there is nothing for the parameter-source rule to mean there.

    So is a file the project does not declare it ships. Every one of libpng's entry points was a `main()` in
    an example program or a test tool, and they carried the whole interprocedural budget with them; a
    library has no entry points, so there was nothing else for it to anchor to. Those regions are still
    arbitrated, function-locally -- not shipped is not unscanned.
    """
    return region.source == "entry_point" and bool(region.function) and region.function != MODULE_SCOPE and region.shipped


def _spec_for(family: str, language: str) -> ArbiterSpec | None:
    """The spec whose arbiter can decide this family. Routing stays a lookup; dispatch stays in `_arbitrate`."""
    if family == "access_control":
        return dominance_specs(language=language).get(family)
    if family == "config_secrets":
        return config_specs(language=language).get(family)
    return taint_specs(language=language).get(family)


def _deduplicated(collected: Sequence[tuple[ModelFinding, float]]) -> list[tuple[ModelFinding, float]]:
    """One finding per (site, family), keeping the strongest rung and counting the regions that reached it.

    Task 2.4 let a region's question follow the call graph, and the moment it did, many entry points could
    reach one shared sink -- libpng reported the same site twenty-six times. A contributor shown the same
    defect twenty-six times learns to scroll past it, and "reached from 26 entry points" is the useful half
    of that observation.

    Two families at one site stay two findings: `echo $_GET[...]` is an injection question and an output
    encoding question, and they have different answers.
    """
    best: dict[tuple[str, str], tuple[ModelFinding, float]] = {}
    for finding, rank in collected:
        key = (finding.site, finding.family)
        current = best.get(key)
        if current is None:
            best[key] = (finding, rank)
            continue
        kept, kept_rank = current
        stronger = finding if _RUNG_ORDER[finding.rung] < _RUNG_ORDER[kept.rung] else kept
        best[key] = (replace(stronger, reached_from=kept.reached_from + finding.reached_from), max(rank, kept_rank))
    return list(best.values())


def _ordered(collected: Sequence[tuple[ModelFinding, float]]) -> tuple[ModelFinding, ...]:
    """Rung first, then the region's rank, then the site — a total order, so two runs agree."""
    return tuple(finding for finding, _ in sorted(collected, key=lambda pair: (_RUNG_ORDER.get(pair[0].rung, 9), -pair[1], pair[0].site)))


def _empty_tally() -> dict[str, int]:
    return {rung.value: 0 for rung in Rung}


def _tally(findings: Sequence[ModelFinding]) -> dict[str, int]:
    tally = _empty_tally()
    for finding in findings:
        tally[finding.rung.value] = tally.get(finding.rung.value, 0) + 1
    return tally


class _CountingClient:
    """Wraps a chat client so the driver counts its own spend, whatever the client records."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls = 0

    def complete(self, **kwargs: Any) -> Any:
        self.calls += 1
        return self._inner.complete(**kwargs)

    def cost_usd(self) -> float:
        meter = getattr(self._inner, "cost_usd", None)
        return float(meter()) if callable(meter) else 0.0


def _cost(client: object | None) -> float:
    meter = getattr(client, "cost_usd", None)
    return float(meter()) if callable(meter) else 0.0


__all__ = ["ModelScanResult", "ScanBudget", "scan_repository"]
