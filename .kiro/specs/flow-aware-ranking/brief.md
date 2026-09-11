# Brief: flow-aware-ranking — spend the expensive query where the cheap evidence is strongest

**Status:** brief only, unapproved.

## Why now

> "we need a taint flow aware ranker, that is capable to put high risk areas into tiers"
> "can you engineer a prompt with enough information to steer the llm making ranker decisions"
> "this can be done, but it requires an iterative concept and clear plans"

A taint request costs **6.63 seconds** (contributor-scan 5.13). A 637-file plugin yields **4,463 regions**, and
the current ranker gives 83.8% of them the same rank, ordered alphabetically by path. So the budget is spent
arbitrarily and the scan does not finish.

The ranker is not weak. It is looking at the wrong thing.

## The evidence that this is tractable

Three regions from one plugin, with what the ranker sees today and what is actually in the code:

| region | rank today | sink in scope |
|---|---|---|
| `getMemberOrderByCode` — **holds CVE-2023-23488** | 0.30 | `$wpdb->get_var("... WHERE code = '" . $code . "' LIMIT 1")` |
| `getMemberOrderByID` — sibling | 0.30 | `$wpdb->get_row("... WHERE id = '$id' LIMIT 1")` |
| `pmpro_rest_api_get_membership_level` | **0.80** | none — no SQL sink at all |

A region with no sink outranks two holding raw concatenated SQL. The discriminating signal is in the sink
call's own source text — interpolated versus bound — and nothing in the ranker reads it.

One detail decides whether a keyword rule suffices, and it does not: `esc_sql` IS in scope for the CVE's
function, applied to a different statement. "A sanitizer is present, rank it lower" demotes precisely the
right answer. Knowing which call it wraps is reading, not matching.

## The unit, and the tiers

**Rank (region, family) PAIRS, not regions.** The expensive question is "does a source reach a sink of family
F here"; every cheap approximation of it is free from the fact tables and a text scan.

| tier | evidence | |
|---|---|---|
| **0** | no sink of F in scope | **never ask** — exact, cannot lose a finding |
| 1 | sink present, no source in scope or reachable | ask last |
| 2 | sink and source, a cleansing call on THAT call | may still corroborate |
| 3 | sink and source, interpolated shape, no cleansing on that call, entry point or declared public | ask first |

Tier 0 is the only tier that excludes rather than orders, so it alone must be exact. Above it, being wrong
costs position, not the finding. That bound is what makes a model safe here: **a ranker cannot manufacture a
finding**, it decides what is looked at, and `regions_truncated` already reports what went unexamined.

## The iterative concept

Each phase ships only if it beats the previous one **on a repository the change was not developed against**.
A phase that cannot show that is not an improvement, it is a story.

- **Phase 0 — the oracle and the baseline.** The evidence extractor (no model) and a scoring harness over the
  pinned CVEs, reporting each one's rank position. Gate: reproduces today's numbers — CVE-2023-23488 at
  position 390 of 4,463, 83.8% of regions in one tier. Without a baseline nothing later is measurable.

  **Done 2026-09-10.** `benchmarks/ranking/position.py`, committed as
  `benchmarks/ranking/baselines/2026-09-10-access-rank.json`:

  | repository | regions | largest tier | CVE position | `budget_at_recall` |
  |---|---|---|---|---|
  | `pmpro` | 4,463 | 83.8% at 0.30 | 390 | 391 |
  | `mwwpform` | 983 | 81.7% at 0.30 | **512** | **513** |
  | `wpstatistics` | 1,673 | 75.3% at 0.30 | **503** | **504** |
  | `vampi` | 25 | 36.0% at 1.00 | 15, 10 (SQLI reached transitively) | 16 |

  **And this corrects the cross-assessment above.** "Ranking's job is concentration, not inclusion" was
  measured on `pmpro` alone, where the CVE is inside the budget. On the other two plugins the CVE sits at
  512 and 503 — **outside a 500-region budget** — so the current ranker never examines it at all, and the
  slices found those CVEs only because a slice has too few regions to exclude anything. Both jobs are
  real: inclusion on two repositories, concentration on all three. The single metric `budget_at_recall`
  covers both, which is why it is the one that matters.

  The instrument is `evidenceOnly` mode on the taint query, recorded on every scan as `ModelScanResult.tiers`
  and `tier_counts`, and acted on by nothing — so every later phase is measured against a record made by
  scans that did not know they were being measured.

  **Measured cost of the instrument**, 637-file graph, the scan's own 500-region request set:

      2,500 pairs in 98.9 s including JVM load — about 40 ms per pair
      tier 0 (no sink of that family in reach): 2,161 of 2,500 = 86%

  Two attempts before that ran past an hour each without producing a payload, and the cause was mine both
  times: repository-wide walks — the sink scan, the reachable-method BFS, `familyInRepo` — repeated per
  request. Memoising them across the batch is what made "milliseconds per pair" true rather than claimed.

  **And the same memoisation reaches the dataflow mode.** The identical 250-request set that cost 2,026.3 s
  (8,105 ms per request) with both joins on now costs **287.0 s — 1,148 ms per request — for the same 5,779
  rows.** Most of what contributor-scan 5.13 measured as "the base taint query" was the per-request scans,
  not the dataflow. That correction is recorded there.
- **Phase 1 — tier 0 only, no model.** Exact pruning. Gate: **53% fewer taint requests issued, measured** —
  and nothing more. 1,177 requests at 6.63 s is still 2.2 hours, so this phase does NOT make the scan finish;
  it halves the problem. Claiming completion here would send someone looking for a bug where there is none.

  **Done 2026-09-10, gate exceeded, scan still does not finish — and the reason corrects phase 0's cost
  figure.** On the 637-file plugin: `tier_counts = {0: 2161, 1: 60, 2: 20, 3: 211, 4: 48}`, **2,161 of 2,500
  requests pruned (86%)**, evidence pass 94.5 s. The remaining **339 requests still hit the 2,400 s ceiling**
  — more than 7 s each.

  **The scan finishes, 2026-09-11.** Not because of anything in this spec: contributor-scan 5.13 found
  that every query batch had been recomputing Joern's dataflow overlay at load since PHP builds went
  through php2cpg (54 s fixed cost per batch; an OutOfMemoryError on WP Statistics), that the hook half's
  seeds were repository-wide, and that two vendored data tables were 60% of one graph. With the overlays
  applied once at build time, the seeds scoped to the callback's file, and files over 1 MB excluded as
  data, the same whole-repository scan on the 637-file plugin completes: **build 97 s (overlays included),
  evidence 76 s, taint 4,105 s for 348 real requests (11.8 s each), arbitrate 99 s, total 72 minutes**,
  `tier_counts = {0: 2152, 1: 60, 2: 20, 3: 218, 4: 50}`, peak child RSS 2.4 GB. **CVE-2023-23488 is
  found at `class.memberorder.php:936`**, among 250 entailed findings across 40 files. The 250 is the next
  fact to reckon with -- it is what "500 regions when 50 would do" looks like as output -- and it is phase
  2's material. `callDepth`, measured on the same graph, is a 1.4× time term and a 100× payload term
  (3,838 flow rows for ten requests at depth 3 against 38 at depth 1). Collapsing rows per evidence key
  takes 3.3× of that out (1,155 rows carrying 3,838 paths, exact); the rest is depth 3 naming more
  distinct sources per sink, which is evidence the ranker gets to use.

  Phase 0 reported 1,148 ms per request after memoisation. That was an average over a 250-request set of
  which 88% were tier 0 and returned instantly; the ~30 real requests in it cost about 9.5 s each. Pruning
  removes exactly the cheap questions and keeps the expensive ones, so it cannot make those faster. The
  honest per-request cost of a taint question that *can* have an answer is **7–10 s at `callDepth = 3`**,
  and that is the number phase 2 and 5.13 must work against — not 1.1 s, and not 6.6 s either.
- **Phase 2 — heuristic tiers, still no model.** The vector and tiers defined below, ordered within a tier
  by a published weighted sum. Gate: `budget_at_recall` — the smallest K holding every pinned CVE — **below
  50 on every pinned repository**, and `pmpro`'s taint query completing at that K. This is the phase that
  makes a scan finish, because the job is concentration: the CVE is already inside 500, the question is
  whether it is inside 50. **If this passes, the model is a refinement, not the plan** — and knowing that is
  worth more than assuming it.
  **Implemented 2026-09-11, measurement in flight.** `Evidence.score` is the published weighted sum, and
  every weight is in one table in `model/evidence.py`: per open sink +1.0 (capped at 5), per cleansed or
  bound sink −0.5 (capped at 3), local source +2.0, carried +1.5, near source +1.0, entry +0.5, declared
  public +1.0. A tier-0 pair scores 0 whatever its sources say, so the weights order but cannot
  manufacture. `ScanBudget.order_by_evidence` runs the evidence pass over every region (or
  `evidence_regions` of them), takes each region's best pair's (tier, score), and cuts `max_regions` from
  that order; `order_by_evidence()` is one function used by the scan and by
  `benchmarks/ranking/position.py --evidence`, so the benchmark measures the order the scan spends. Off
  by default until the benchmark says where the pinned CVEs land. A region with no taint family sorts
  after every region with evidence -- the scan does not know it is safe, it knows nothing -- which is a
  known cost of this phase for families like `access_control` and is noted here rather than hidden.

  **Measured 2026-09-11, weights v1** (`benchmarks/ranking/baselines/2026-09-11-evidence-rank.json`), the
  evidence pass over EVERY region of each repository, Joern 4.0.623:

  | repository | pairs | evidence pass | tiers 0 / 1 / 2 / 3 / 4 | `budget_at_recall` static → evidence |
  |---|---|---|---|---|
  | pmpro | 22,315 | 255 s | 21,275 / 74 / 86 / 759 / 121 | **391 → 116** |
  | wpstatistics | 8,359 | 156 s | 7,468 / 77 / 5 / 726 / 83 | **504 → 223** |
  | mwwpform | 4,915 | 68 s | 4,511 / 37 / 0 / 357 / 10 | **513 → 292** |
  | vampi | 125 | 16 s | 123 / 1 / 0 / 0 / 1 | 16 → 16 |

  Concentration of 2.2× to 3.4× on the three PHP repositories, from exact facts and a seven-entry weight
  table; the gate (< 50 everywhere) is not met. Two readings, one per shape of miss: pmpro's CVE is
  INSIDE its 121 tier-4 regions, so what remains there is order within the top tier -- the tie-heavy part
  this brief handed to phase 3. WP Statistics's `record()` and MW WP Form's `_delete_files()` are in
  tier 3, one below where their sources say they belong, because `carried` -- stage one of the two-stage
  join, which the arbiter computes anyway -- was not yet reported by the evidence branch. It is now
  (`taint.sc` reports it only where a sink exists, so tier-0 pairs pay nothing).

  **With `carried` (v2), as they land:** mwwpform **292 → 30** (CVE-2023-6559 at 29, among 37 tier-4
  regions; evidence pass 68 → 84 s) -- the first repository under the gate. vampi unchanged at 16. pmpro's
  v2 pass hit the scan's 300 s default query ceiling (v1 took 255 s; the join facts on its 1,040
  sink-bearing pairs cost more than the 45 s of headroom) and answered nothing, which the benchmark
  reported as `tiers={}` and the static order; the benchmark now sets its own ceiling (1,800 s). WP Statistics's v2 pass went the same way (v1 156 s,
  v2 past 300 s), so both are re-measured under it.

  **Then the flow form was the wall, not the ceiling:** pmpro's v2 pass did not finish in 1,800 s either
  (the arbiter's `carried` is a `reachableByFlows` per candidate assignment, and 1,040 sink-bearing pairs
  of them). So `carried` in evidence mode became STRUCTURE (v3): a field the region reads is assigned, in
  its file, from a source expression, from a parameter of the assigning method, or from a same-file
  method that reads a source; a hook applied in scope has a registered callback holding one of those.
  Milliseconds again (pmpro 266 s, wpstatistics 168 s, mwwpform 69 s):

  | repository | static | v1 (no carried) | v2 (flow carried) | v3 (structural) | tier 4 under v3 |
  |---|---|---|---|---|---|
  | pmpro | 391 | 116 | timed out | **69** | 555 |
  | wpstatistics | 504 | 223 | timed out | **172** | 569 |
  | mwwpform | 513 | 292 | **30** | 68 | 84 |
  | vampi | 16 | 16 | 16 | 16 | 1 |

  The proxy is too loose: folding "assigned from a parameter" in with "assigned from a source" put 555
  and 569 regions in tier 4 -- every constructor assigns a field from a parameter -- and the CVEs sit in
  those tiers on score alone. v4 splits the provenance: source-fed (or fed by a same-file method that
  reads a source) promotes to tier 4; parameter-fed only orders within a tier (weight +0.75).

  **v4, measured:** pmpro 69 and wpstatistics 172, both UNCHANGED with tier 4 still 555 and 569 -- their
  tier-4 members are source-fed under the one-level rule (fields assigned from calls to same-file
  helpers that read `$_REQUEST`, which on those plugins is a real request path, so the tier is roughly
  honest and the CVE's position there is a within-tier question). mwwpform went 68 → **248**: its CVE's
  region is fed by `$this->attachments = $attachments` in a constructor, exactly the parameter-fed shape
  the split demotes, and exactly the shape the exact flow had put at 30. So v5 asks the exact flow for
  precisely the parameter-fed fields a sink-bearing region reads -- memoised per (family, file, field)
  for the batch, which the arbiter's memos were not until today -- and for nothing else.

  **v5, measured, and the phase-2 verdict on it** (`2026-09-11-evidence-rank-v5.json`, with the head of
  each order recorded): pmpro **69**, wpstatistics **172**, mwwpform **68**, vampi 16. The flow confirms
  every parameter-fed field -- a constructor's `$this->x = $x` trivially flows from its parameter -- so
  v5 equals v3 for mwwpform; the v2 "30" came from the older scoping (the region's file, not the
  field's), which happened to fit that one case. 68 is the honest structural number for that shape.

  Reading the heads: every region ahead of a CVE is in the CVE's own tier on a tied or higher score --
  pmpro's CVE scores 7.0 with 23 regions at 10.0, 13 at 8.5, 10 at 8.0 and 14 at 7.0 ahead of it;
  wpstatistics's sits behind 96 regions tied at 7.0. The tiers are done; the ties are the whole of what
  is left, exactly as the cross-assessment said. One exact fact was missing from the vector: `shipped`,
  the build's own word on what is product, was on the region and not in the score, and 10 of the 67
  regions ahead of MW WP Form's CVE were `test-mail.php`. Weight −2.0 for an unshipped file (v6).

  **v6: no change (mwwpform 68), and the reason is a fact the vector does not have.** `declared_sources`
  answers only from a build manifest that lists sources (Makefile.am and kin); a WordPress plugin ships a
  `composer.json` and a `package.json`, neither of which does, so `shipped` is None and every region --
  the 14 test-file regions ahead of the CVE included -- counts as product. Knowing that `tests/`,
  `test-*.php` and `*Test.php` are not product is ecosystem convention, which is to say policy: it
  belongs in a `[[layout]]` fact table per ecosystem, approved like the `[[dispatch]]` facts were, not in
  a constant here. Proposed, not done. After that, within-tier order is phase 3's -- a model reading the code the ties cannot --
  or one more exact path fact (`distance`), and the gate stays unmet until one of them moves it.

- **Phase 3 — the LLM ranker.** Same evidence, ordered by a model. Gate: beats phase 2 leave-one-repository-out.
  If it does not, phase 2 ships and phase 3 does not.
- **Phase 4 — break the closed loop.** An exploration slice (~10% of budget sampled outside the top-K) and
  full labelling on repositories small enough to arbitrate every region. Gate: a measured estimate of the
  selection bias in phase 3's numbers.
- **Phase 5 — prompt optimisation (GEPA / SIMBA / DSPy).** Only after 3 and 4. An optimiser run against a
  censored metric optimises the censorship.

## What the prompt has to carry

The question put to the model is **not** "is this vulnerable" — that is adjudication, it is the arbiter's job,
and it is the one thing a ranker must never be asked. It is:

> Given a fixed budget of expensive dataflow queries, which of these sites are worth spending it on?

and the evidence it needs is textual and already available: the sink calls in scope **with their source
text**, the untrusted-input expressions found, the cleansing calls and **which call each one wraps**, the
sink's shape (bound versus interpolated), the declared access and its provenance, and whether the region is
reachable from a request handler.

## Constraints, from measurement and from prior scars

- **Cost.** One model call per region is 4,463 calls a scan. Batch over a prefilter, or it does not ship.
- **The loop is closed.** A region the ranker excludes is never arbitrated, never labelled, so the ranker
  never learns it was wrong. Every run confirms the ordering it already had.
- **N projects.** Four pinned CVEs is not a training set. This project already has the closed-loop
  train-on-test scar; the reported figure must come from a repository the optimiser never saw.
- **Determinism.** Two runs of one repository must agree or a baseline diff is meaningless. The ranking is
  recorded in the manifest.
- **Degradation.** With no model configured, phases 0–2 still rank, and the report says which ranker ordered
  the scan.

## Cross-assessment against the measurements

Read against what was actually measured today, the plan above has two errors and one gap. They are kept
here, corrected, rather than silently rewritten, because the corrections are themselves results.

**Phase 1's gate is wrong.** It says pruning makes `pmpro`'s taint query complete. It does not. Pruning
removes 53% of requests, and 1,177 × 6.63 s is still **2.2 hours** — nowhere near the 300 s default or the
2,400 s that was tried. Pruning halves the problem; it does not solve it. The honest gate is "53% fewer
requests issued, measured", and completion belongs to phase 2. Stating otherwise would have sent someone
looking for a bug in phase 1 when phase 1 had done exactly what it can.

*Amended 2026-09-11:* completion arrived, and it belonged to neither phase 1 nor phase 2 -- it belonged to
the instrument (contributor-scan 5.13). Pruning was and is exact; what made 339 requests exceed 2,400 s was
a dataflow overlay recomputed per batch and a seed set computed repository-wide, and the scan now completes
in 72 minutes with the CVE found. The paragraph above stands as written because its reasoning was right on
the numbers it had; the numbers were the instrument's.

**Ranking's job is concentration, not inclusion.** The brief implies the CVE is missed because the ranker
excluded it. It did not: CVE-2023-23488's region sits at position 390 of 4,463, inside the 500-region budget,
and was examined. It goes unreported because the budget is spent on 500 regions when 50 would do, and 500
is unaffordable at 6.63 s per family per region. So the ranker's success metric is not "is the CVE in the
budget" — it already is — but **"how small can the budget be while the CVE stays in it"**. That is a
different objective, and it is the one that makes a scan finish.

**The gap: nothing above says what the evidence IS.** "Sink shape" and "cleansing on the call" are named,
not defined, and a heuristic that is not defined cannot be language-agnostic because there is nothing to
check for language leakage. The rest of this brief defines it.

Two things the measurements confirm and the plan should lean on harder:

- **The joins are cheap and must survive any ranker.** 22% of query cost, two of three CVEs. A ranker that
  demotes field- or hook-carried regions because they show no direct source is a ranker that loses those
  CVEs. The evidence vector below therefore carries the join's own stage-one result as a field.
- **84% of regions in one tier means any separation is progress**, and the separation does not need to be
  clever to be large. A tier 0 that is merely exact already reorders the budget more than the current ranker
  ever has.

## The evidence vector, defined

The unit is a **(region, family) pair**. For each, a fixed vector of fields is computed. Every field is
defined in terms of **fact-table categories** — source, sink, sanitizer, dispatch, access — never in terms of
a language's syntax, which is what makes the definition language-agnostic: any language with a fact table
gets the same vector, and a heuristic that mentions `$wpdb` or `wp_ajax_` has by construction left the
vector and must be rejected in review.

**Where it is computed matters as much as what it is.** The graph is already built for the arbiter, at 76 s
for 637 files. Extracting these fields is a CPG query **without dataflow** — call nodes, their arguments,
their enclosing methods, the call graph one hop out — which is milliseconds per call rather than 6.63 s per
request. The extractor is therefore a sibling of `taint.sc` that never calls `reachableByFlows`:

> **Tiering is the CPG query without dataflow. Arbitration is the CPG query with it. Same graph, same
> facts, two costs.**

That is the whole architecture in one line, and it is why the evidence is language-agnostic rather than
merely language-neutral-in-intent: the CPG normalises syntax across frontends, so "the argument of this call
is a literal" means the same thing in PHP, Python and C.

### Sink evidence — from `[[sink]]` facts of family F

| field | definition | exactness |
|---|---|---|
| `sinks` | count of calls in scope matching a sink of F | exact |
| `shape` | per sink call, one of: **`literal`** (the vulnerable-position argument is a constant), **`bound`** (the call is a declared-safe form — a `parameterized` sanitizer fact wraps it, or its arity/shape matches the bound form the taint query already recognises), **`computed`** (the argument is an expression: concatenation, interpolation, a variable, a call result) | exact for `literal` and `bound`; `computed` is the residue |
| `cleansed_on_call` | per sink call, whether a sanitizer of F is an **ancestor of the vulnerable-position argument in the AST** — not merely present in the same function | exact, and this is the field a text scan gets wrong: `esc_sql` in scope on a different statement is `false` here |

### Source evidence — from `[[source]]` facts and the entry-point contract

| field | definition | exactness |
|---|---|---|
| `source_local` | a modelled source expression occurs in the region's own body | exact |
| `source_near` | a modelled source occurs in a method within k call-graph hops of the region (k = the arbiter's `callDepth`) | exact for the graph the arbiter will use |
| `entry` | the region is an entry point per the mapper, so its parameters are untrusted by contract | exact |
| `access` | the declared access level, **with provenance**: `declared` (a registration or route contract says so) or `inferred` (nothing found) — because "public" meaning "no decorator found" is the false positive the project has already paid for | exact |
| `carried` | the region reads a **field** whose assignment is fed by a source anywhere in the file, or a **dispatch** value whose registered producer is — i.e. stage one of the two-stage join, which is already computed and memoised, reused here as evidence | exact where computed; absent (not false) where the join was not run |

### Path evidence — cheap structural proxies for what dataflow would establish

| field | definition |
|---|---|
| `distance` | fewest call-graph hops from any source (local, near, entry parameter, or carried) to any sink of F: 0 = same statement, 1 = same method, 2+ = across calls, ∞ = no source found |
| `cleansing_between` | any sanitizer of F occurs on a call-graph path between a source and a sink — a weaker, cheaper version of `cleansed_on_call` that catches cleansing done in a helper |

### Structural and prior evidence

| field | definition |
|---|---|
| `shipped` | the project's own build declaration names this file (existing `shipped.py`) |
| `family_in_repo` | any sink of F exists **anywhere** in the repository |
| `prior` | a committed baseline recorded a finding at this site, or the site was in an exploration slice before |

## The tiers, defined as predicates over the vector

| tier | predicate | role |
|---|---|---|
| **0** | `sinks == 0` in the reachable scope, **or** `family_in_repo == false` | **exclude** — exact; the only tier that removes work |
| 1 | `sinks > 0` and no `source_local`, `source_near`, `entry`, or `carried` | ask last — nothing untrusted can arrive |
| 2 | a source exists, but **every** sink call is `bound` or `cleansed_on_call` | ask late — a flow may exist and will corroborate, not entail |
| 3 | a source exists and **some** sink call is `computed` and not `cleansed_on_call` | ask first |
| 3★ | tier 3 **and** (`access == declared public` or `distance ≤ 1` or `carried`) | ask very first |

Two properties are load-bearing and must hold in every implementation:

1. **Only tier 0 excludes; every other tier orders.** So the only place exactness is *required* is tier 0,
   and tier 0's predicate has a proof: a family with no sink in reach cannot produce a flow, in any language,
   under any dataflow model. Above tier 0, being wrong costs position, and `regions_truncated` reports what
   position cost.
2. **Tier 0's scope must match the arbiter's.** At `callDepth = 0` the scope is the region; at depth k it is
   the region plus its reachable methods. A tier 0 computed on the file when the arbiter will look k hops
   out is not exact and must not be called so. The repository-wide form (`family_in_repo == false`) is exact
   at every depth and is the cheap first cut — it alone removes all 487 `deserialization` requests on `pmpro`.

**Within a tier**, order by a score. In phase 2 that score is a fixed weighted sum over the vector, published
in the manifest so two runs agree. In phase 3 it is the model's ordering **of the same vector**, which is
what makes the two comparable: same input, different ordering function, one held-out metric.

## Where the model helps, and where it must not be allowed to

The vector above is exact wherever exactness was cheap. What remains genuinely uncertain is narrower than
"ranking":

- **Ambiguous cleansing.** `cleansed_on_call` is exact when the sanitizer wraps the argument directly. It is
  `false` — correctly, but unhelpfully — when cleansing happens two statements earlier into a variable that is
  then interpolated. Deciding whether *that* cleansing reaches *this* call is reading the code, and it is the
  single largest source of tier-2/tier-3 misplacement.
- **Unfamiliar shapes.** A sink call whose form the `bound` rule does not recognise, in a framework with no
  facts yet. The model can say "this looks bound" as an *ordering* opinion; it cannot add a `bound` fact,
  because a fact is policy.
- **Within-tier priority** when the fixed score ties, which on a real repository it will, constantly.

And the boundaries:

- **The model never computes tier 0.** Exclusion is exact or it is a silent miss, and a model's "no sink
  here" is not a proof.
- **The model never sees the question "is this vulnerable".** It sees "which of these is worth an expensive
  query", with the vector and the sink call's source text. Adjudication is the arbiter's, and keeping it
  there is what keeps the gates byte-identical.
- **The model's input is the vector plus text, never the arbiter's verdict** on the same run — that is the
  closed loop feeding on itself.

## Metrics, so every phase can fail

| metric | definition | phase |
|---|---|---|
| `position(cve)` | rank position of each pinned CVE's (region, family) pair | 0 → all |
| `requests_issued` | taint requests after tiering | 1 |
| `budget_at_recall` | the smallest K such that every pinned CVE is in the top K — the concentration metric | 2, 3 |
| `time_to_complete` | wall clock for the taint query at that K | 2, 3 |
| `held_out_position` | `position(cve)` on a repository excluded from development of the change | 2, 3, 5 |
| `exploration_yield` | findings per region in the exploration slice versus in the top-K — the direct measure of what the ranker is missing | 4 |

`budget_at_recall` is the one that decides the release question. Today it is ≥ 390 on `pmpro`. If phase 2
takes it below 50, the scan finishes in minutes and the model is a refinement; if it does not, the model is
the plan.

## Open questions for the design phase

Two of the four questions this brief opened with are answered by the definition above, and are kept so the
answer is visible:

1. ~~Where does the evidence extractor live?~~ **It is a CPG query without dataflow, a sibling of `taint.sc`
   in `cpg/queries/`.** Not the mapper: the mapper reads text and would have to re-derive per language what
   the graph already normalises. The vector is language-agnostic *because* the graph is.
2. ~~Per file or per reachable set?~~ **Both, in that order.** `family_in_repo` first — exact at any depth,
   free, a fifth of the budget on `pmpro` — then the reachable set at the arbiter's own `callDepth`. Never the
   file alone above depth zero, because that is not exact and must not be called tier 0.
3. How many pinned repositories before leave-one-out means anything? Four is not enough. This is the
   corpus ask, and it is the same ask contributor-scan 5.8 made: plugins chosen by installed base, CVEs read
   out of the code.
4. Does the arbiter's verdict feed back as a label? **Only through the exploration slice.** A verdict on a
   region the ranker chose is a label the policy selected, and training on it closes the loop. A verdict on
   an exploration region is the only unbiased label the scan produces, and it is the one worth keeping.
5. **New:** the weighted sum in phase 2 has weights. Where do they come from before any model exists?
   Proposed: set by hand from the tier semantics, published in the manifest, and treated as a baseline for
   phase 3 to beat — not tuned, because tuning four weights on four CVEs is the overfit the plan exists to
   avoid.
