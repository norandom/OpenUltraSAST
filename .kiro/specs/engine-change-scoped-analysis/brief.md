# Engine change-scoped analysis (G2 workstream)

Status: **proposed / in progress** (opened 2026-10-11). Owner: engine. Tracks a concrete lever for the
engine-detection gap found while driving the G0 baseline. This is G2 ("improve what moves the unseen-repo
numbers"), gated on the pool metric; it is NOT part of the G0 record-07 baseline (that runs on the quick-rule tier).

## Problem (measured, not assumed)

On real unseen vulnerability changes the engine produces **no finding** — but the diagnosis (live, 300 s long-deadline
replays) shows it is usually **not a detection-capability gap**:

- **Clean Python injection change** (`aws/bedrock-agentcore-sdk-python`, `install_packages`, introducing, 3-file
  diff): `wall=303 s`, hit the deadline. The ranker found candidates (`static_rank=1.0`) but **`selected: []`** and
  every candidate `deferred` with `reason: deadline_exhausted`, `analysis_not_started=deadline_exhausted`,
  `change_context_incomplete`. **Zero analyses ran.** And the ranked candidates were **repo-wide and unrelated to
  the push** (`auth.py` access_control/config_secrets), not the changed `install_packages`. The engine is trying to
  re-audit the whole repo and runs out of budget before analyzing the change.
- **Noisy last_touch config_secrets change** (`jenkinsci/metrics-plugin`, 14-file diff): finished in 206 s but
  `comparison_unknown` + `capability_unavailable` + `eligibility_provenance_mismatch` +
  `contributor-scan ... projection_unavailable`. Multi-causal; correspondence was one part (fixed separately,
  commit c39fbb8), capability registry is Task 8.3.

## Hypothesis

A pre-push hook should vet **the code this push changed**, not re-scan the whole repository. Seeding/scoping the
engine's analysis to the **changed declarations and their dataflow neighborhood** (the `change_sites` are already in
the replay spec) should let analysis **actually run within budget** instead of being deferred — which is where
detection is being lost, not in Joern's capability.

## Anchors (confirm in increment 1)

- `src/openultrasast/rank.py` — the static-evidence ranker (`ranking_mode="evidence"`, `existing-static-evidence-v1`).
- `src/openultrasast/mapping.py` — builds the `selected`/`deferred` scope + the budget allocation that defers on
  `deadline_exhausted`.
- `src/openultrasast/push/policy.py`, `push/runner.py` — consume the scope; change_sites arrive via the push input.
- `benchmarks/unseen/replay_entry.py` — carries `changed_paths` / `declaration_paths` in the spec.

## Increments (progress tracking)

- [x] **0. Cost split confirmed (2026-10-11, timed live replay).** `build_seconds=66.69` (CPG build is cheap),
  `query_seconds=0.0` (no query ever executed), total 303 s (hit the deadline), **4,095** candidate questions all
  `analysis_not_started=deadline_exhausted`, `selected: []`, `regions_scanned=0`. So of the 303 s, ~67 s built the
  CPG and ~236 s went to enumerating/ranking/preparing 4,095 repo-wide candidate questions for a **3-file** change —
  the budget was spent before a single query ran. The CPG build is NOT the bottleneck; the over-broad candidate set
  is. Change-scoping is confirmed as the right lever, and because per-candidate prep includes the line-correspondence
  work, fewer candidates also cuts that cost (the two fixes compound).
- [x] **1. Located (2026-10-11).** The over-enumeration is upstream of the scan, not inside it:
  - `push/runner.py:345-348` — `head_regions = discovery(tip.root, …)` discovers regions across the **whole head
    tree** (the ~4,095), independent of the change.
  - `push/runner.py:397-407` — those regions are passed wholesale to `scan_repository(..., change_context=context)`;
    `change_context` is threaded in but **never scopes the region set**.
  - `model/scan.py:167` and `:364` — `[_identity(unit, r, f) for r in regions for f in r.families]` enumerates all
    regions × families; with `order_by_evidence=True` (`runner.py:288/403`) the scan evidence-tiers **every** pair
    before analysis — that pre-work is the ~236 s measured in increment 0, so the deadline hits at `query_seconds=0`.
  - Primitive already present: `model/regions.py:279` computes the changed-path set from the context;
    `compare_targeted_base` (`runner.py:411`) is a precedent for change-targeted work.
  - **Fix locus (increment 2):** restrict the *analyzed* region set to the change's declarations + dataflow
    neighbourhood (filter `head_regions` by `context.changed_paths` before the scan, or scope the enumeration inside
    `scan_repository`). Keep the **CPG whole-repo** so taint queries can still trace sources from unchanged code into
    the changed regions — only the question set is change-scoped.

  **Correction (2026-10-11), after a reverted first attempt — two things the naive filter got wrong:**
  - **The engine already reaches into unchanged code by design, and it is tested.** A changed `source` that reaches
    an unchanged `sink` must still select the unchanged sink's question
    (`tests/test_model_change_context.py::test_changed_dependency_reaches_unchanged_ranked_question`;
    `test_change_does_not_replace_ranker_selection` pins that change context must NOT alter the ranker's selection).
    `_changed_files` feeds `_evidence_pass` only as `contextFilter`/`contextPaths` — which locations to itemise vs
    summarise — NOT to shrink the tier population. A "changed files only" scope deletes the reach-into-unchanged
    behaviour. Any scope must keep changed regions **plus the regions they reach** (the affected/`relationships`
    neighbourhood), not changed files alone.
  - **The 236 s is now split (2026-10-11, saved artifacts).** `total=291s build=52s query=0s arbitrate=238.75s`,
    and `query_seconds_by_kind["evidence"]=238.54s` — the evidence-tier pass is **99.9 %** of the arbitrate phase;
    `affected_context` + `_scope_work` are **0.21 s**. The pass tiered 1,015 pairs (`tier_counts 0:1009, 1:6`) at
    **~235 ms/pair** (contended; ~120 ms uncontended) and that alone blew the budget — `selected=0`,
    `deferred=1365` all `deadline_exhausted`. Secondary anomaly: the design assumes ~2.5 ms/pair
    ("17,700 in 44 s"); here it is 50–100× that, i.e. the evidence query is pathologically slow on a cold large
    CPG — a separate optimisation from cutting the pair count.
  - **So increment 2's single target is the evidence pass** (`scan.py:338-359`, `_evidence_pass`). The fork is HOW
    to cut it without deleting reach-into-unchanged:
    - (i) **Scope + bound:** order the evidence candidates change-first and bound the pass to a fraction of the
      budget so analysis queries still run; reached unchanged regions are tiered only while budget lasts.
    - (ii) **Neighbourhood pass:** tier the changed regions, read the reached regions from the context rows the
      pass already returns, tier those in a second small pass — exact reach-into-unchanged, more code.
    - (iii) **Per-pair speedup:** attack the ~235 ms/pair (warm server / batching) rather than the pair count —
      helps every scan but is a deeper engine change and does not by itself bound a huge repo.

  **CORRECTION (2026-10-11, after implementing (i) + four live re-verifies — the cost model was wrong).**
  Scope + bound was built and tested (change-first ordering, adaptive budget-fitted portioning, `_context_pass`
  scoped to changed files, honest `evidence_pass_bounded` degradation; branch `engine-change-scoped-evidence-pass`).
  It correctly cut the tiered pair count — but `query_seconds` stayed **0** every time. The live numbers show why:

  | pairs tiered | run_batch calls | evidence s | build s |
  |---|---|---|---|
  | 1015 | 1 | 238 | 52 |
  | 512 | 1 | 219 | 68 |
  | 64 | 2 | 220 | 68 |
  | 4 (probe) | 1 | 160 | 127 |

  Evidence time is **flat regardless of pair count** → the cost is **per-*call* fixed** (~150–220 s: loading the CPG
  into the query engine + the census the evidenceOnly batch computes), ~85 ms/pair on top. Pair-count scoping
  therefore cannot free budget, and portioning re-pays the fixed cost per call (so (i) can be counterproductive).
  Build is also large and swings 52→127 s — two engines thrashing the 7 GB host (the record-07 baseline shares it).
  The real levers are now (iii)-shaped, not (i): **warm/persistent query engine or a cached census** to kill the
  ~150 s per-call fixed cost, and/or a **bigger engine-arm budget** than 300 s; plus a **clean (uncontended)
  measurement**, because contention alone may be inflating build + fixed cost 2–3×. Scope+bound is NOT merged.

  **UNCONTENDED measurement (2026-10-11, baseline paused via SIGSTOP + container kill, then resumed).** Shipped
  engine, one evidence call over 1,015 pairs: `build=48 s`, `evidence=243.79 s`, `query=0`. The evidence pass is
  **the same ~244 s uncontended as ~238 s contended** → the cost is **INTRINSIC, not contention**; contention only
  inflated `build` (48 → 127 s) and added run-to-run noise. The model is `evidence ≈ 150 s fixed (CPG load into the
  query engine + the census the evidenceOnly batch computes) + ~93 ms/pair` (244 = 150 + 1015×0.093). Consequences:
  - **~200 s of fixed overhead** (`build` + evidence-load) precedes any analysis, so a 300 s budget leaves only
    ~100 s for everything else. This is why `query=0` even on a clean host.
  - **Change-scoping still helps, but only by cutting the per-pair tail** (~1,015×93 ms ≈ 95 s): one evidence call
    over ~30 changed pairs is ~150 s + 3 s instead of 244 s, which would free ~90 s — possibly enough for analysis,
    but marginal.
  - **It must be ONE call, not portioned.** The ~150 s is a first-call load, so the adaptive probe attributed it to
    its 4 probe pairs (per-pair≈37 s), concluded the budget fit ~0 more, and tiered only 4 — the implemented
    scope+bound is doubly wrong for this cost model. The correct shape: change-first candidates, count-capped, ONE
    evidence call, `deadline=None`.
  - **Pre-push viability:** the ~200 s fixed floor means the engine arm cannot be a fast (≤30 s) pre-push check on a
    repo this size without a warm/persistent session or a cached census. A larger budget (e.g. 600 s) makes the
    benchmark arm run but is not a realistic pre-push deadline. The lever that matters for the product is killing
    the ~150 s fixed cost, not scoping pairs.
- [ ] **2. Seed analysis from the change.** Prioritize (or restrict first-pass to) the changed declarations plus
  their call/data neighborhood over repo-wide static rank, within budget.
- [ ] **3. Soundness.** Keep cross-file dataflow INTO the changed function (don't scope to literal changed lines);
  add tests; keep existing push tests green.
- [ ] **4. Live re-test.** Re-run the bedrock change: does analysis now RUN and produce a finding on
  `install_packages` (vs `deferred`)? Re-run metrics-plugin.
- [ ] **5. Measure the delta.** Engine-arm sample on the pool (catch/false-alarm + engine-coverage rate) — needs the
  kube lane (blocked on the AX completion path) for scale.

## Dependencies / notes

- Coverage `complete_within_scope` also needs the capability registry (Task 8.3) regardless of this work; the win
  here is findings moving from `comparison_unknown`/deferred to a decided novelty → advisory engine finding.
- Implement directly and verify on the LIVE instrument (a fake-client/unit pass is not evidence the live engine
  changed); the kube-lane and store endpoints are operator-owned infra, not assumptions to make here.

## Efficiency barrier analysis (post-record-07 priority)

**What the record-07 baseline actually measured (verified on the records): regex only.** The default and
long_deadline replay arms both hardcode `model="disabled"`, `max_model_calls=0`, `cost_usd=0` — **no LLM is
called** — and the engine never completed (`engine_covered=0`, the ~200 s wall). So the measured `catch≈2.5%` is
the **quick pattern-rule tier alone**: essentially grep-with-structure. This is the FLOOR, not the product, and it
confirms the maintainer's point — pattern rules alone will never be enough, or `grep` would do. The product's
detection lives in two tiers that did NOT run:

| Tier | Mechanism | Measured cost (uncontended, mid-size repo) | Ran? | Catch |
|---|---|---|---|---|
| 1 quick rules | regex/pattern over changed lines | ~seconds | yes | 2.5% (floor) |
| 2 engine (Joern) | CPG build + taint/dataflow | build 48 s + evidence (150 s fixed + 93 ms/pair) + analysis (unmeasured) | no (walled) | unknown |
| 3 LLM adjudication | model judgment / search-with-proof (hunter, fusion, decision engine) | model latency + $/call (unmeasured in the push path) | no (disabled) | unknown |

**The barrier:** a releasable net needs tier 2 and/or tier 3 to run and catch within a realistic pre-push window —
target **≤60–120 s** (developer patience), hard ceiling 300 s. The analysis is a budget ledger per tier against
that window, and the measurements each needs:

- **Engine barrier (tier 2).** Fixed floor `build(48) + evidence_fixed(~150) ≈ 198 s` precedes any dataflow answer.
  Measure (clean host): **E1** split the ~150 s into JVM-start / graph-load / census; **E2** does a warm session
  with the graph **preloaded at build** eliminate `evidence_fixed` on the first query (the decisive architectural
  test)?; **E3** analysis (`reachableByFlows`) per-pair cost + warm reuse; **E4** build cost vs repo size.
  Levers in priority order: warm session + graph preload → cached census → change-scope the per-pair tail.
- **LLM barrier (tier 3).** Unmeasured in the push path. Measure: **L1** model round-trip latency per call
  (DeepSeek) and calls needed per push for the decision/proof stage; **L2** the recall LIFT of tier 3 over tiers
  1+2 on the pool — does the LLM catch what regex and dataflow miss, and at what $ and latency per push?
- **Deliverable:** a **barrier table** — for budget ∈ {60, 120, 300, 600} s × each tier combination, does it FIT
  and what is the MEASURED recall/false-alarm on the pool — identifying the minimal viable config for a releasable
  net. 600 s unblocks the benchmark arm but is not a pre-push deadline; the product target is tiers 2+3 under ~120 s.

Sequence: finish G0 (record 07) → **E1/E2 first** (they decide whether the warm session alone crosses the engine
barrier) → E3/E4 → L1/L2. Each on a clean host (the session times out contended). The change-scoped branch
(`engine-change-scoped-evidence-pass`, unmerged) only trims the tier-2 per-pair tail and is a late add-on, not the
lever.

## E1/E2 RESULTS (measured 2026-10-12, CLEAN host, bedrock-agentcore, 3-file change, 300 s budget, head side)

Four clean-host replays settle the engine barrier and **correct the earlier "~200 s graph-load wall"**, which was
conflated with host contention from the running baseline replay:

| Run | build | evidence (taint batch) | dominance | query_s | selected | deferred |
|---|---|---|---|---|---|---|
| contended (prior) | 48–127 | 243.8 | — | **0** | **0** | 1365 |
| disposable (shipped, clean) | 27.9 | 225.1 | 34.8 | 34.8 | **356** | 1009 |
| warm session `SESSION=1` (clean) | 32.9 | 228.6 | 25.9 | 25.9 | **356** | 1009 |
| session + graph preload (clean) | 30.4 | 223.2 | 32.5 | 32.5 | **356** | 1009 |

**Findings (each traced to a measured cause, not assumed):**

1. **The engine arm was walled by CONTENTION, not an intrinsic floor.** The prior `query=0 / selected=0 / all
   1365 deferred` was measured while the slice-1 baseline replay contended for the 7 GB host. On a clean host the
   **shipped (disposable) engine already runs dataflow**: `query_seconds` 0 → ~35 s, `selected` 0 → **356 regions**,
   dominance flow queries complete. This is the first time the engine arm produced analysis on this change.
2. **The evidence/taint batch (~225 s) is INVARIANT to session and to graph preload** (225.1 / 228.6 / 223.2 across
   the three clean runs). Warm session and preload-at-build do **not** reduce it. So the dominant cost is intrinsic
   to the taint batch, not graph I/O.
3. **Graph-load is cheap — it is NOT the wall.** The `dominance` query is a full cold query *including*
   `importCpg`, and it costs only ~35 s. So `importCpg` is tens of seconds, not ~150 s. **This corrects the earlier
   note** that attributed the ~150 s fixed to "first query JVM-start + graph-load + census." The ~160 s fixed lives
   inside `taint.sc`'s own per-batch flow work (seed/sink memo fill over the distinct `(family, file)` combinations
   it walks), paid lazily as the first pairs process — independent of the raw pair count.
4. **The warm session is not the lever.** It starts fine on a clean host (the contended `session_startup_timeout`
   was contention-only), but gives ~no benefit here: subsequent queries (dominance) are already cheap disposable,
   and the evidence pass is a single batch call, so there is nothing for the session to amortise.
5. **The barrier, restated:** `build(~30) + evidence(~225) ≈ 255 s` of a 300 s budget, so 1009/1365 regions defer
   as `deadline_exhausted`; only 356 are analysed. The lever is **reducing the taint batch's work** — change-scope
   the pair/family set so the batch fits budget — NOT session, preload, or a bigger JVM. The parked branch
   (`engine-change-scoped-evidence-pass`) is therefore **relevant after all, on a clean host**, provided it scopes
   the family/file set `taint.sc` walks (not merely the pair list); its adaptive portioning still needs replacing
   with a fixed cap (per-call-fixed cost, not per-pair).
6. **Side note:** the `base`-side CPG build failed (`cpg_build_failed`, 0.9 s) in the preload run — a separate
   intermittent base-revision build issue; the `head` side built and analysed normally. Track separately.

**What E1/E2 did NOT answer (the real G2 question):** on a clean host the engine selects 356 regions — *does it
CATCH vulns regex misses?* That needs an **engine-on unseen pilot** (a handful of pool repos replayed with the
engine arm enabled on a clean host) scored against record 07's regex-only floor (catch 3/92). That is the decisive
next experiment, ahead of E3/E4/L1/L2.
