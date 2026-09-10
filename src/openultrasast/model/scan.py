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

import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..cpg.backend import CpgResult
from .evidence import evidence_from_rows
from .candidates import enumerate_candidates
from .config_value import request_params as config_params
from .dominance import request_params as dominance_params
from .ladder import Rung
from .pipeline import ModelFinding, scan_region
from .regions import MODULE_SCOPE, ScanRegion
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
    cpg = _build(backend, root, dominant)
    build_seconds = round(time.monotonic() - build_started, 2)
    if cpg is None:
        return ModelScanResult(
            by_rung=_empty_tally(),
            regions_unjudged=len(regions),
            seconds=round(time.monotonic() - started, 2),
            build_seconds=build_seconds,
            degradations=({"stage": "model", "reason": "cpg_build_failed", "detail": getattr(backend, "last_failure", "")},),
        )

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
    ordered_regions = sorted(regions, key=lambda r: (not r.shipped, -r.rank, r.path, r.function or ""))

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

    # Phase 1: collect the whole scan's questions, for at most `max_regions` regions. Nothing is asked yet.
    work: list[tuple[str, ScanRegion, ArbiterSpec]] = []
    for region in ordered_regions[: limits.max_regions]:
        for family in region.families:
            spec = _spec_for(family, region.language)
            if spec is None:
                continue
            work.append((f"{len(work)}", region, spec))

    # Phase 1b: the evidence tier of every taint pair, before any dataflow is asked. Same query, `evidenceOnly`,
    # no `reachableByFlows`. Recorded on the result and NOT used to reorder or skip anything -- that is a
    # later phase, and it must be measured against this record before it is allowed to change behaviour.
    tiers: list[tuple[str, str, str, int]] = []
    per_kind: dict[str, float] = {}
    if limits.tiering and callable(getattr(cpg, "run_batch", None)):
        grouped_taint = _grouped(work, hook_callbacks=hooks).get("taint", {})
        if grouped_taint:
            evidence_requests = {rid: {**dict(params), "evidenceOnly": "true"} for rid, params in grouped_taint.items()}
            tier_started = time.monotonic()
            answered_evidence = cpg.run_batch("taint", evidence_requests)
            per_kind["evidence"] = round(time.monotonic() - tier_started, 2)
            if answered_evidence is None:
                degradations.append({"stage": "model", "reason": "query_failed", "kind": "evidence", "requests": len(evidence_requests)})
            else:
                answered_evidence.pop("__census__", None)
                by_rid = {rid: (region, spec) for rid, region, spec in work}
                for rid, rows in answered_evidence.items():
                    pair = by_rid.get(rid)
                    if pair is None:
                        continue
                    region, spec = pair
                    evidence = evidence_from_rows(
                        rows,
                        entry=_is_entry_point(region),
                        # Rank 1.0 is the public tier. Provenance -- declared by a route contract versus
                        # inferred from an absent decorator -- is not yet carried on ScanRegion, so this is
                        # the proxy phase 0 has; the brief names it as the field to thread through next.
                        access_declared_public=region.rank >= 1.0,
                        bound_names=getattr(spec, "safe_shape_sinks", ()),
                    )
                    if evidence is not None:
                        tiers.append((region.path, region.function or "", getattr(spec, "family", ""), evidence.tier))

    # Phase 2: ONE invocation per query kind. JVM startup dominates a repository scan -- a call per region
    # per family put a ten-line file at four minutes and a thousand regions at roughly fifty hours -- while
    # the queries themselves are milliseconds once the CPG is loaded.
    rows_by_id: dict[str, list[object]] = {}
    census_reported = False
    query_started = time.monotonic()
    for kind, requests in _grouped(work, hook_callbacks=hooks).items():
        kind_started = time.monotonic()
        batch = getattr(cpg, "run_batch", None)
        if callable(batch):
            answered_batch = batch(kind, requests)
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
                    if methods == 0:
                        degradations.append({"stage": "model", "reason": "cpg_empty", "files": int(str(entry.get("files", "0")) or 0)})
                    # More than one graph means some files could only be built apart from the rest, and a
                    # flow whose source is in one shard and whose sink is in another does not exist for any
                    # question we can ask. Reporting the split is the difference between a partial answer and
                    # a partial answer that looks whole.
                    shards = int(str(entry.get("shards", "1")) or 1)
                    if shards > 1:
                        degradations.append({"stage": "model", "reason": "cpg_sharded", "shards": shards})
                    census_reported = True
                rows_by_id.update(answered_batch)
        else:  # a backend without batching still works, one call at a time
            for rid, params in requests.items():
                answered = cpg.run(kind, params)
                rows_by_id[rid] = list(answered) if isinstance(answered, list) else []
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
            continue
        judged.add((region.path, region.function))
        if exhausted:
            unasked.add((region.path, region.function))
        collected.extend((finding, region.rank) for finding in found)

    if unasked:
        degradations.append({"stage": "model", "reason": "budget_exhausted", "regions_unasked": len(unasked)})

    scanned = len(judged)

    findings = _ordered(_deduplicated(collected))
    # The graph has answered everything it is going to. Its scratch tree holds the CPG, the request files and
    # joern's own working copy -- tens of megabytes per scan -- and nothing else reclaims it.
    _dispose(cpg)
    return ModelScanResult(
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
    )


def _dispose(cpg: object) -> None:
    """Release a built CPG's scratch tree. Never raises: cleanup must not turn a good scan into a failure."""
    cleanup = getattr(cpg, "cleanup", None)
    if callable(cleanup):
        try:
            cleanup()
        except Exception as exc:  # noqa: BLE001 -- a scan that found things must not fail while tidying up
            logger.warning("could not remove the cpg scratch directory: %s", exc)


def _build(backend: Any, root: Path, language: str) -> Any:
    """Build through the backend, passing the language when the backend can use it."""
    try:
        return backend.build(root, language=language)
    except TypeError:  # a backend from before the retry existed, including every test double
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
