# Engine change-scoped analysis (G2 workstream)

Status: **proposed / in progress** (opened 2026-10-11). Owner: engine. Tracks work to address the
engine-detection gap found during the G0 baseline run. This is G2 ("improve what moves the unseen-repo
numbers"), gated on the pool metric; it is not part of the G0 record-07 baseline (that runs on the quick-rule tier).

## Problem (measured, not assumed)

The engine produces **no finding** on real unseen vulnerability changes. Live 300 s long-deadline replays show
that the cause is usually not a detection-capability gap:

- Clean Python injection change (`aws/bedrock-agentcore-sdk-python`, `install_packages`, introducing, 3-file
  diff): `wall=303 s`, hit the deadline. The ranker found candidates (`static_rank=1.0`) but **`selected: []`** and
  every candidate `deferred` with `reason: deadline_exhausted`, `analysis_not_started=deadline_exhausted`,
  `change_context_incomplete`. No analyses ran. The ranked candidates were **repo-wide and unrelated to
  the push** (`auth.py` access_control/config_secrets), not the changed `install_packages`. The engine is trying to
  re-audit the whole repo and runs out of budget before analyzing the change.
- Noisy last_touch config_secrets change (`jenkinsci/metrics-plugin`, 14-file diff): finished in 206 s but
  `comparison_unknown` + `capability_unavailable` + `eligibility_provenance_mismatch` +
  `contributor-scan ... projection_unavailable`. This has several causes. Correspondence was one (fixed separately,
  commit c39fbb8); the capability registry is Task 8.3.

## Hypothesis

A pre-push hook should check **the code this push changed**. Starting the engine's analysis from the
**changed declarations and their dataflow neighborhood** should let it run within budget instead of being
deferred. The `change_sites` are already in the replay spec. The missed detection comes from deferral,
rather than a limit in Joern's capability.

## Anchors (confirm in increment 1)

- `src/openultrasast/rank.py` is the static-evidence ranker (`ranking_mode="evidence"`, `existing-static-evidence-v1`).
- `src/openultrasast/mapping.py` builds the `selected`/`deferred` scope + the budget allocation that defers on
  `deadline_exhausted`.
- `src/openultrasast/push/policy.py` and `push/runner.py` consume the scope; change_sites arrive via the push input.
- `benchmarks/unseen/replay_entry.py` carries `changed_paths` / `declaration_paths` in the spec.

## Increments (progress tracking)

- [x] **0. Cost split confirmed (2026-10-11, timed live replay).** `build_seconds=66.69` (CPG build is cheap),
  `query_seconds=0.0` (no query ever executed), total 303 s (hit the deadline), **4,095** candidate questions all
  `analysis_not_started=deadline_exhausted`, `selected: []`, `regions_scanned=0`. So of the 303 s, ~67 s built the
  CPG and ~236 s went to enumerating/ranking/preparing 4,095 repo-wide candidate questions for a **3-file** change.
  The budget was spent before a single query ran. The over-broad candidate set is the bottleneck, rather than the CPG build.
  This confirms change-scoping as the fix. Preparing each candidate includes line-correspondence work,
  so fewer candidates also reduce that cost.
- [x] **1. Located (2026-10-11).** The over-enumeration is upstream of the scan, not inside it:
  - `push/runner.py:345-348`, `head_regions = discovery(tip.root, …)` discovers regions across the **whole head
    tree** (the ~4,095), independent of the change.
  - `push/runner.py:397-407`, those regions are passed wholesale to `scan_repository(..., change_context=context)`;
    `change_context` is threaded in but **never scopes the region set**.
  - `model/scan.py:167` and `:364`, `[_identity(unit, r, f) for r in regions for f in r.families]` enumerates all
    regions × families; with `order_by_evidence=True` (`runner.py:288/403`) the scan evidence-tiers **every** pair
    before analysis. That pre-work is the ~236 s measured in increment 0, so the deadline hits at `query_seconds=0`.
  - Primitive already present: `model/regions.py:279` computes the changed-path set from the context;
    `compare_targeted_base` (`runner.py:411`) is a precedent for change-targeted work.
  - For increment 2, restrict the *analyzed* region set to the change's declarations + dataflow
    neighbourhood (filter `head_regions` by `context.changed_paths` before the scan, or scope the enumeration inside
    `scan_repository`). Keep the **CPG whole-repo** so taint queries can still trace sources from unchanged code into
    the changed regions. Only the question set is change-scoped.

  Correction (2026-10-11), after reverting the first attempt: the filter got two things wrong.
  - **The engine already reaches into unchanged code by design, and it is tested.** A changed `source` that reaches
    an unchanged `sink` must still select the unchanged sink's question
    (`tests/test_model_change_context.py::test_changed_dependency_reaches_unchanged_ranked_question`;
    `test_change_does_not_replace_ranker_selection` pins that change context must not alter the ranker's selection).
    `_changed_files` feeds `_evidence_pass` only as `contextFilter`/`contextPaths`. This controls which locations to itemise vs
    summarise, rather than shrinking the tier population. A "changed files only" scope deletes the reach-into-unchanged
    behaviour. Any scope must keep changed regions **plus the regions they reach** (the affected/`relationships`
    neighbourhood), not changed files alone.
  - **The 236 s is now split (2026-10-11, saved artifacts).** `total=291s build=52s query=0s arbitrate=238.75s`,
    and `query_seconds_by_kind["evidence"]=238.54s`, the evidence-tier pass is **99.9 %** of the arbitrate phase;
    `affected_context` + `_scope_work` are **0.21 s**. The pass tiered 1,015 pairs (`tier_counts 0:1009, 1:6`) at
    **~235 ms/pair** (contended; ~120 ms uncontended) and that alone blew the budget, `selected=0`,
    `deferred=1365` all `deadline_exhausted`. Secondary anomaly: the design assumes ~2.5 ms/pair
    ("17,700 in 44 s"); here it is 50–100× that, i.e. the evidence query is unusually slow on a cold large
    CPG. Fixing that is separate from cutting the pair count.
  - Increment 2 targets the evidence pass (`scan.py:338-359`, `_evidence_pass`). The options must
    reduce its cost while preserving flows into unchanged code:
    - (i) Scope + bound: order the evidence candidates change-first and bound the pass to a fraction of the
      budget so analysis queries still run; reached unchanged regions are tiered only while budget lasts.
    - (ii) Neighbourhood pass: tier the changed regions, read the reached regions from the context rows the
      pass already returns, then tier those in a second small pass. This preserves exact reach-into-unchanged behaviour but needs more code.
    - (iii) Per-pair speedup: reduce the ~235 ms/pair (warm server / batching) rather than the pair count.
      This helps every scan but needs a deeper engine change and does not by itself bound work on a huge repo.

  **CORRECTION (2026-10-11, after implementing (i) + four live re-verifies, the cost model was wrong).**
  Scope + bound was built and tested (change-first ordering, adaptive budget-fitted portioning, `_context_pass`
  scoped to changed files, honest `evidence_pass_bounded` degradation; branch `engine-change-scoped-evidence-pass`).
  It cut the tiered pair count, but `query_seconds` stayed **0** every time. The live numbers show why:

  | pairs tiered | run_batch calls | evidence s | build s |
  |---|---|---|---|
  | 1015 | 1 | 238 | 52 |
  | 512 | 1 | 219 | 68 |
  | 64 | 2 | 220 | 68 |
  | 4 (probe) | 1 | 160 | 127 |

  Evidence time is **flat regardless of pair count** → the cost is **per-*call* fixed** (~150–220 s: loading the CPG
  into the query engine + the census the evidenceOnly batch computes), ~85 ms/pair on top. Pair-count scoping
  therefore cannot free budget, and portioning re-pays the fixed cost per call (so (i) can be counterproductive).
  Build time also varies from 52→127 s. Two engines compete for the 7 GB host, which the record-07 baseline shares.
  The fixes now resemble (iii), rather than (i): a **warm/persistent query engine or a cached census** to remove the
  ~150 s per-call fixed cost, and/or a **bigger engine-arm budget** than 300 s. A **clean (uncontended)
  measurement** is also needed because contention may inflate build + fixed cost 2–3×. Scope+bound is not merged.

  **UNCONTENDED measurement (2026-10-11, baseline paused via SIGSTOP + container kill, then resumed).** Shipped
  engine, one evidence call over 1,015 pairs: `build=48 s`, `evidence=243.79 s`, `query=0`. The evidence pass is
  **the same ~244 s uncontended as ~238 s contended** → the cost is **intrinsic, not contention**; contention only
  inflated `build` (48 → 127 s) and added run-to-run noise. The model is `evidence ≈ 150 s fixed (CPG load into the
  query engine + the census the evidenceOnly batch computes) + ~93 ms/pair` (244 = 150 + 1015×0.093). Consequences:
  - **~200 s of fixed overhead** (`build` + evidence-load) precedes any analysis, so a 300 s budget leaves only
    ~100 s for everything else. This is why `query=0` even on a clean host.
  - **Change-scoping still helps, but only by cutting the per-pair tail** (~1,015×93 ms ≈ 95 s): one evidence call
    over ~30 changed pairs is ~150 s + 3 s instead of 244 s. This would free ~90 s, which might leave enough time
    for analysis, but only just.
  - **It must be ONE call, not portioned.** The ~150 s is a first-call load, so the adaptive probe attributed it to
    its 4 probe pairs (per-pair≈37 s), concluded the budget fit ~0 more, and tiered only 4, the implemented
    scope+bound has both problems under this cost model. The correct shape: change-first candidates, count-capped, ONE
    evidence call, `deadline=None`.
  - Pre-push viability: the ~200 s fixed floor means the engine arm cannot be a fast (≤30 s) pre-push check on a
    repo this size without a warm/persistent session or a cached census. A larger budget (e.g. 600 s) makes the
    benchmark arm run but is not a realistic pre-push deadline. The lever that matters for the product is killing
    the ~150 s fixed cost, not scoping pairs.
- [ ] **2. Seed analysis from the change.** Prioritize (or restrict first-pass to) the changed declarations plus
  their call/data neighborhood over repo-wide static rank, within budget.
- [ ] **3. Soundness.** Keep cross-file dataflow into the changed function (don't scope to literal changed lines);
  add tests; keep existing push tests green.
- [ ] **4. Live re-test.** Re-run the bedrock change: does analysis now run and produce a finding on
  `install_packages` (vs `deferred`)? Re-run metrics-plugin.
- [ ] **5. Measure the delta.** Engine-arm sample on the pool (catch/false-alarm + engine-coverage rate), needs the
  kube lane (blocked on the AX completion path) for scale.

## Dependencies / notes

- Coverage `complete_within_scope` also needs the capability registry (Task 8.3) regardless of this work; this work
  moves findings from `comparison_unknown`/deferred to a decided novelty → advisory engine finding.
- Implement directly and verify on the live instrument (a fake-client/unit pass is not evidence the live engine
  changed); the kube-lane and store endpoints are infrastructure owned by the operator.

## Efficiency barrier analysis (post-record-07 priority)

The records confirm that the record-07 baseline measured regex only. The default and
long_deadline replay arms both hardcode `model="disabled"`, `max_model_calls=0`, `cost_usd=0`. No LLM is
called, and the engine never completed (`engine_covered=0`, the ~200 s wall). The measured `catch≈2.5%` covers
only the quick pattern-rule tier, a structured pattern search. This measures the floor, rather than the product.
It confirms the maintainer's point that pattern rules alone are insufficient; otherwise `grep` would do.
The product's two detection tiers did not run:

| Tier | Mechanism | Measured cost (uncontended, mid-size repo) | Ran? | Catch |
|---|---|---|---|---|
| 1 quick rules | regex/pattern over changed lines | ~seconds | yes | 2.5% (floor) |
| 2 engine (Joern) | CPG build + taint/dataflow | build 48 s + evidence (150 s fixed + 93 ms/pair) + analysis (unmeasured) | no (walled) | unknown |
| 3 LLM adjudication | model judgment / search-with-proof (hunter, fusion, decision engine) | model latency + $/call (unmeasured in the push path) | no (disabled) | unknown |

To be releasable, the net needs tier 2 and/or tier 3 to run and catch within a realistic pre-push window.
The target is **≤60–120 s** (developer patience), hard ceiling 300 s. The analysis records each tier's budget against
that window and identifies the measurements needed:

- Engine barrier (tier 2). Fixed floor `build(48) + evidence_fixed(~150) ≈ 198 s` precedes any dataflow answer.
  Measure (clean host): **E1** split the ~150 s into JVM-start / graph-load / census; **E2** does a warm session
  with the graph **preloaded at build** eliminate `evidence_fixed` on the first query (the architectural
  test)?; **E3** analysis (`reachableByFlows`) per-pair cost + warm reuse; **E4** build cost vs repo size.
  Levers in priority order: warm session + graph preload → cached census → change-scope the per-pair tail.
- LLM barrier (tier 3). Unmeasured in the push path. Measure: **L1** model round-trip latency per call
  (DeepSeek) and calls needed per push for the decision/proof stage; **L2** the recall lift of tier 3 over tiers
  1+2 on the pool, does the LLM catch what regex and dataflow miss, and at what $ and latency per push?
- Produce a **barrier table** for budget ∈ {60, 120, 300, 600} s × each tier combination. Record whether it fits
  and its measured recall/false-alarm on the pool. Use this to identify the minimal viable config for a releasable
  net. 600 s unblocks the benchmark arm but is not a pre-push deadline; the product target is tiers 2+3 under ~120 s.

Sequence: finish G0 (record 07) → **E1/E2 first** (they decide whether the warm session alone crosses the engine
barrier) → E3/E4 → L1/L2. Each on a clean host (the session times out contended). The change-scoped branch
(`engine-change-scoped-evidence-pass`, unmerged) only trims the tier-2 per-pair tail and is a late add-on, not the
lever.

## E1/E2 RESULTS (measured 2026-10-12, CLEAN host, bedrock-agentcore, 3-file change, 300 s budget, head side)

Four clean-host replays **correct the earlier "~200 s graph-load wall"** diagnosis. It had confused graph-load
cost with host contention from the running baseline replay:

| Run | build | evidence (taint batch) | dominance | query_s | selected | deferred |
|---|---|---|---|---|---|---|
| contended (prior) | 48–127 | 243.8 | — | **0** | **0** | 1365 |
| disposable (shipped, clean) | 27.9 | 225.1 | 34.8 | 34.8 | **356** | 1009 |
| warm session `SESSION=1` (clean) | 32.9 | 228.6 | 25.9 | 25.9 | **356** | 1009 |
| session + graph preload (clean) | 30.4 | 223.2 | 32.5 | 32.5 | **356** | 1009 |

The measurements show:

1. Host contention prevented the engine arm from running. The prior `query=0 / selected=0 / all
   1365 deferred` was measured while the slice-1 baseline replay contended for the 7 GB host. On a clean host the
   shipped (disposable) engine already runs dataflow: `query_seconds` 0 → ~35 s, `selected` 0 → **356 regions**,
   dominance flow queries complete. This is the first time the engine arm produced analysis on this change.
2. **The evidence/taint batch (~225 s) is invariant to session and to graph preload** (225.1 / 228.6 / 223.2 across
   the three clean runs). Warm session and preload-at-build do **not** reduce it. So the dominant cost is intrinsic
   to the taint batch, not graph I/O.
3. Graph-load is cheap and does not account for the delay. The `dominance` query is a full cold query *including*
   `importCpg`, and it costs only ~35 s. So `importCpg` is tens of seconds, not ~150 s. **This corrects the earlier
   note** that attributed the ~150 s fixed to "first query JVM-start + graph-load + census." The ~160 s fixed lives
   inside `taint.sc`'s own per-batch flow work (seed/sink memo fill over the distinct `(family, file)` combinations
   it walks). It is paid lazily as the first pairs are processed, independent of the raw pair count.
4. **The warm session is not the lever.** It starts fine on a clean host (the contended `session_startup_timeout`
   was contention-only), but gives ~no benefit here: subsequent queries (dominance) are already cheap disposable,
   and the evidence pass is a single batch call, so there is nothing for the session to amortise.
5. The barrier, restated: `build(~30) + evidence(~225) ≈ 255 s` of a 300 s budget, so 1009/1365 regions defer
   as `deadline_exhausted`; only 356 are analysed. The fix is to **reduce the taint batch's work** by scoping
   the pair/family set to the change so the batch fits the budget. Session reuse, preload, or a bigger JVM will not do this. The parked branch
   (`engine-change-scoped-evidence-pass`) is therefore **relevant after all, on a clean host**, provided it scopes
   the family/file set `taint.sc` walks (not merely the pair list); its adaptive portioning still needs replacing
   with a fixed cap (per-call-fixed cost, not per-pair).
6. Side note: the `base`-side CPG build failed (`cpg_build_failed`, 0.9 s) in the preload run, a separate
   intermittent base-revision build issue; the `head` side built and analysed normally. Track separately.

E1/E2 did not answer the G2 question: does the engine catch vulnerabilities regex misses when it selects 356 regions
on a clean host? That needs an **engine-on unseen pilot** (a handful of pool repos replayed with the
engine arm enabled on a clean host) scored against record 07's regex-only floor (catch 3/92). That is the
next experiment, ahead of E3/E4/L1/L2.

## ENGINE-ON PILOT RESULTS (measured 2026-10-12, CLEAN host, 5 public pool repos, vuln change each, 300 s)

Five public repos were picked for flow-shaped families and small size, giving the engine its best chance to finish and catch:

| repo | fam | size | REGEX on vuln | ENGINE finding | cov | vuln region ranked | best taint | selected/deferred | wall |
|---|---|---|---|---|---|---|---|---|---|
| masci/banks | path | 2f | ✗ | **none** | incomplete | yes | sink found, no source (score 0) | 281 / **0** | 236 s |
| vitejs/launch-editor | injection | 1f | ✗ | **none** | incomplete | yes | tier1 score2.0 sink (wrong fam) | 13 / 38 | 261 s |
| getzep/graphiti | injection | 5f | ✗ | **none** | incomplete | yes | injection score 0 | 882 / **0** | 304 s |
| aws/bedrock-agentcore | injection | 3f | ✗ | **none** | incomplete | yes | — | 356 / 1009 | 305 s |
| miguelgrinberg/python-socketio | deser | 10f | **✓ (n=2)** | **none** | incomplete | yes | **tier1 score2.0 sink found** | 136 / **0** | 257 s |

Result: regex 1/5, engine 0/5. On a clean host, with budget to spare on most, the shipped engine **added no
catches over the regex floor.**

The diagnosis was corrected after inspecting `head.findings` rather than ranker evidence:
1. The budget hypothesis is refuted. banks, graphiti and socketio **finished their region queue** (deferred=0)
   and still emitted no finding. Change-scoping to fit budget would not have changed the outcome.
2. The engine produced no vuln-family findings (path/injection/deser) on any of the 5. Actual `head.findings`:
   banks 1 (config_secrets), socketio 2 (config_secrets), launch-editor / graphiti / bedrock **0 findings each**.
   The dataflow/taint tier traced **no source→sink flow** for the vuln families (`taint_evidence_not_applicable`;
   e.g. banks found the `path.open` sink but **no source reaches it**). Correction: the tier=1 / score=2.0
   "sink" seen in the ranker's `normalized_evidence` is the ranker's static sink candidate, not a confirmed taint
   finding. An earlier draft of this section misread it as detection partially working. It was not.
3. `ambiguous_line_correspondence` does not explain these missed vulnerabilities. It fires on all 5, but there
   are **no vuln-family findings to anchor**, so a region-level witness fallback (the proposed "Option A") would
   change nothing here. Witness/anchoring only touched the config_secrets findings that did appear.
4. **The LLM adjudication tier was disabled** (`model_calls=0`, `cost_usd=0`, `model_assistance={}` on all 5). The
   rungs reached: `suspicion=0, model_corroborated=0, model_entailed=0–2, execution_confirmed=0`. The tier designed
   to confirm a vuln the static dataflow cannot trace **never ran**.
5. **Ranking also under-promotes the vuln region** (tier 0 for most families; banks path family stuck low). So even
   where a sink exists, the region is not analysed deeply enough to attempt a flow.
6. The pool's SZZ last-writer change definition yields large/moved diffs; a cleaner probe
   uses tight vuln-introducing diffs. Secondary to (2)/(4).

Reprioritised engine levers (corrected, anchoring is not the lever):
- #1: the LLM adjudication tier (disabled in the push path) has the highest priority. regex+dataflow = 1/5 with
  the model OFF; the static tiers produce no vuln-family findings on these shapes. The hypothesis
  ([[search-with-proof]]) is that the LLM tier catches what regex+dataflow miss. The pilot supports
  testing it: **L1** model latency + calls/push, **L2** recall lift on the same 5 (and beyond). These calls cost money, so stage
  them (5–10 sizing → ~10–20 pilot → full only on lift).
- #2 taint source/sink coverage + region ranking so the dataflow recognises these vuln sources and promotes the
  vuln region (banks path: sink found, source unrecognised; graphiti injection: score 0).
- #3 change-anchoring robustness matters only after the static/LLM tiers produce vuln-family
  findings to anchor. Deprioritised until (1)/(2) yield findings.

Detection does not meet the pre-push net's release requirements. Clean host, generous budget, LLM off: regex 1/5,
engine 0/5. The static tiers (regex + Joern dataflow) do not detect these unseen vulns; the untested lever
is the **LLM adjudication tier**. Next, run an **LLM-tier pilot (L1/L2)** on these 5 repos to test whether the model
produces vuln-family findings regex+dataflow miss, and measure its $/latency.

## ROOT CAUSE of engine 0/5 + the "#2 guided by #1" workstream (2026-10-12)

Code and evidence show why the taint tier traced no flow. The pilot repos are **libraries**, whose
untrusted input arrives as **public-API function parameters**, not HTTP requests. The Python taint **source**
vocabulary (`ruleset/semantic/python.toml`) is entirely web/CLI: Flask/Django `request.*`, `sys.argv`, `sys.stdin`,
`input(`. There is no source for a library's own API parameter. The engine *does* have a parameter-as-source mode
(`_parameters_are_input`, `scan.py`), but it fires **only for recognised entry points** (`_is_entry_point` and
`entry_kind != "function"`). The pilot vuln regions carry `entry:false`, so their parameters are **deliberately
not** sources. That restriction is intentional: treating every function parameter as a source caused a flood of
false SQL-injections on WordPress/PMPro (documented in the `_parameters_are_input` docstring). The static
engine cannot safely widen its sources to library APIs without reintroducing those false alarms.
For `banks` path: sink `path.open` found, `source_local/near=false`; `graphiti`/`bedrock` injection: no source.

The maintainer's "#2 guided by #1" directive addresses this gap. Static taint cannot *safely*
decide which library parameters are trust boundaries; the **LLM can** reason about which public-API surface is
attacker-reachable (intent, not pattern). So:
- #1 (LLM) guides: on a changed library region the engine ranks but cannot source, the LLM adjudicates whether a
  parameter is an untrusted trust boundary and names the source→sink it believes exists (search-with-proof).
- #2 (taint) traces + proves: the engine then runs the flow from the LLM-named source to the known sink,
  confirming or refuting it with a traced path. The trace provides proof beyond the LLM's judgment. This would avoid the static FP
  increase while giving every catch a dataflow witness.
- Where the LLM repeatedly names the same source shape (e.g. a registry-key → path family), promote it
  to a static fact in `python.toml` guarded by the entry/shape conditions that keep WordPress quiet.

Proposed first increment (pending budget confirmation, LLM calls cost money): wire the disabled LLM tier on the
5 pilot regions in *LLM-guided-source* mode and measure: (a) does it name the right trust-boundary source per vuln,
(b) does the taint engine then trace source→sink and emit a vuln-family finding, (c) catch lift over regex (1/5) and
false-alarm cost on the ordinary changes. Stage it (5–10 sizing → ~10–20 → full on lift). This makes "#2 guided by
#1" the concrete G2 detection workstream; budget/change-scoping and change-anchoring stay deprioritised until it
yields findings.

## BANKS SIZING + "2 guided by 1" validated (2026-10-12, budget-approved, DeepSeek)

Sized the LLM tier on banks (the clearest pilot miss) with the project's own DeepSeek client (`deepseek-flash`).

DeepSeek is reachable, and model id `deepseek-flash` is valid. **~$0.00016–0.00025 per
call, ~1.1 s latency.** This costs less than a cent per push even at 8 candidates × a few regions. The GLM/abliteration fallback
(`ABLITERATION_*`) currently errors `HTTP 422` on the `thinking` request param. A client fix (don't send
`thinking` to that endpoint) is needed before it can be used; DeepSeek works today so it is not blocking.

"2 guided by 1" works in this case: the LLM gives the correct verdict when given the real sink + source
context:
- For `_load` (the pool's SZZ-labelled site, 135–141), the model returned `vulnerable=false`. This is correct: `_load` reconstructs
  paths from its own index, not the sink.
- Asked about the real sink `from_prompt_path`/`set()` line 44 (`path / f"{prompt.name}…"; write_text`) with the
  context that `prompt.name` can be request-derived: **`vulnerable=true`**, *"prompt.name is joined into a
  filesystem path and written without sanitization… path traversal or arbitrary file write."* This is a correct catch.

Two blockers to realising it in the live pipeline (both now concrete):
1. **Context, not single-shot.** The model only catches with the real sink + caller/source context. A single-shot
   question on the ranker's region (which pointed at `_load`, and at the benign local-glob `_scan`) does not. This
   requires the **agentic search-with-proof hunter** (explores callers/entry points to establish the trust
   boundary), not the single CANDIDATE_QUESTION path. That needs more calls → their cost is the next measurement.
2. **Corpus-label soundness.** The pool's banks label is mislocated: `head_lines=[[30],[104],[138–141]]`,
   `function=_load`. The real sink is line **44**, outside head_lines±10 and a different function. So (a) even a
   correct finding at line 44 would not score as a catch under `location_match`, and (b) the sink pre-exists in base
   (the change did not touch it), so a change-scoped pre-push hook **correctly stays quiet**. The pool even
   annotates this bias ("delta hook can correctly stay quiet"). **Part of the pilot's engine 0/5 is this SZZ
   mislocation, not a detection failure.**

The budget is approved. Keep the revised next steps staged:
- Validate the 5 pilot labels first (cheap, LLM-assisted corpus audit): for each, is the real sink inside the
  changed lines, and is it change-introduced vs pre-existing-in-base? Only sound, change-located vulns are fair
  targets. This separates true detection gaps from SZZ artifacts before spending on detection runs.
- Then run the agentic hunter (search-with-proof) on the sound targets and size its per-vuln call count/cost;
  measure catch + false-alarm (on ordinary changes) vs regex 1/5. The single-shot path is insufficient; the hunter
  is the real "#1".
- Feed confirmed source shapes (e.g. library param → path join) back as guarded static facts (#2).

## Prompt evolution is a CORE lever for the LLM arm (maintainer directive 2026-10-12)

**"What is key is that we evolve the prompts as well"**, and **"GEPA or comparable; this is an evolving field."**
The bedrock hunter ran (64 model calls, $0.0076), but its **current prompts** led it to flag adjacent concerns
(network-PUBLIC default, download_file). It never named the `install_packages` command injection. This was a
*prompting/targeting* miss, rather than a cost or capability limit. So the LLM arm needs a **prompt-optimisation loop** that reflects on misses/low-confidence
outputs, updates the prompt, and retries. Build it on **DSPy** (its GEPA / MIPRO optimisers). Keep it **pluggable**
behind an interface because the field changes quickly (GEPA, MIPRO, TextGrad, successors). This aligns with
[[learned-decisions-not-hand-tuning]] (learned decisions + local memory, not hand rules). It applies to both LLM
uses here: the search-with-proof detector and the corpus-label auditor.

The optimisation must learn which hints/annotations the model needs to reach the real sink. Rewording the
prompt alone is insufficient. bedrock needed the hint "`install_packages` runs `pip install` with caller-supplied package
names → command injection"; banks needed "`prompt.name` is request-derived and joined into a filesystem path →
traversal". DSPy optimises which evidence/hints to feed the signature so the model targets the true sink instead of
adjacent noise.

Use the project's existing framework knowledge for those hints. The semantic facts taxonomy
(`ruleset/semantic/*.toml`, `ruleset/frameworks.toml`) encodes sources/sinks/sanitizers per framework without
user annotations ([[php-detection-is-engine-only]] zero-annotation value). Where framework knowledge covers the
API, feed it as a hint. Where it does not (library APIs like banks/bedrock), the LLM proposes the trust boundary,
which becomes a fact after repeated confirmation (the #2 feedback loop). No new annotation burden on the
user. This is now part of the "#2 guided by #1" workstream and must not be deferred. (DeepSeek
`deepseek-flash` is the working default; GLM 5.3 "cyber" model is future-spec.)

## POOL-P1 LABEL AUDIT (LLM, 2026-10-12): 47% of labels are sound

The banks label-location check was extended to all **49 public** pool vulns via DeepSeek (advisory + head code +
pool label → sound/unsound). Full artifact: `benchmarks/measurements/2026-10-12-pool-p1-label-audit/`.
- **label_sound = 23/49 (47%)**; 53% unsound (25 pre-exist in base, 16 sink outside changed lines). Cost $0.038.
- By family (sound/total): injection 10/13, access_control 5/8, untrusted_destination 4/7, deserialization 1/2,
  config_secrets 1/4, **path 1/7, output_encoding 1/8**. Injection labels mostly sound; path/output_encoding mostly
  mislocate or pre-exist.
- Record 07's floor (catch 3/92) is scored against a corpus ~half unfair to a delta hook. On the ~53%
  pre-existing/mislocated vulns a change-scoped hook correctly stays quiet. The honest catchable denominator is the
  sound subset; record 07 needs this caveat + a sound-subset recomputation.
- Only bedrock + graphiti (injection) of the 5 pilot cases have sound labels. The engine missed both, so these
  are detection gaps. The 23 sound targets are the fair local eval set for "#2 guided by #1".
- Next: run the agentic search-with-proof hunter on the sound targets (start bedrock + graphiti), size its
  per-vuln call count/cost, measure catch + false-alarm. Then recompute record 07 on the sound subset.

## MODEL HUNTER on the 2 sound targets (2026-10-12): first LLM catch the static tiers missed

Ran `ousast scan --mode deep` (DeepSeek `deepseek-flash`, model layer + tool_hunter, 60-call/8-hotspot bound) on
bedrock + graphiti, the two sound pilot targets the static engine missed. Artifact:
`benchmarks/measurements/2026-10-12-hunter-sound-targets/`.
- **hunter 1/2 vs static engine 0/2.** graphiti: **HIT**, `falkordb_driver.py:207`, tag `family:cypher-injection`,
  rationale traces `build_fulltext_query` concatenating user input into a Cypher string at line 278 (inside the
  labelled function, location-matches). bedrock: **miss**, 12 suspicions on adjacent concerns, never named the
  `install_packages`→`pip` command injection.
- Cost is low: ~$0.007/repo, 64 model calls for a whole-repo deep scan.
- Everything stopped at `suspicion`. The proof arm did not elevate to corroborated/entailed/execution_confirmed.
  Release-grade BLOCK needs *proven* findings; the next step is to measure the proof arm's lift.
- bedrock's miss is the concrete case for the DSPy prompt/hints loop above.

Next: (a) measure the proof arm (can it elevate graphiti's suspicion to proven?); (b) stand up the DSPy hint loop
and re-run bedrock; (c) widen the hunter to the 23 sound targets for a catch rate; (d) then a change-scoped + proven
run for the release-relevant shape.

## STRATEGIC PIVOT: core problem = unprovable reachability; FIX THE EVALUATION TARGET FIRST (2026-10-12)

The maintainer and team identified the problem: the tool can find dangerous operations but cannot prove
an attacker can reach them. The trust boundary is outside the changed library code, in a caller/application
that a change-scoped scan does not see. The project will not emit unproven alarms. Recall → ~0 from unprovable
reachability, not blindness. Cost/latency/engine-wall/corpus-labels did not explain this problem.

The chosen bet is to fix the evaluation target first. The three options were fix-target / advisory-with-conditions / build-prover.
A pre-push hook runs inside a developer's application (entry points present, request→sink in-repo), but the pool is
library-heavy, so we measured the hardest/wrong case.

Shape classification (LLM, 49 public vulns, $0.033, `benchmarks/measurements/2026-10-12-pool-p1-shape-classification/`):
reachability_in_repo True only 12/49 (24%); 37/49 are pure libraries. A valid catch needs a sound label and
in-repo reachability → 5/49 (~10%): graphiti, desktopcommandermcp, malla, document-merge-service, mcp-remote.
Repository shape predicted the hunter result (graphiti app-shaped→caught; bedrock library→missed). So record-07's 3/92 is
scored against a ~90%-illegitimate denominator. The near-zero catch largely comes from a mismatch between the targets and the tool.

Next: deep scan (regex/engine/hunter) on the 5 fair targets → per-tier catch rate on the corrected set; then
stand up an app-shaped eval set from known-vulnerable apps (VAmPI/NodeGoat/DjanGoat/vibe-py) and recompute the
floor. Revisit the deferred bets (advisory-with-conditions, reachability prover) once the fair-target results are available.

## FAIR-TARGET RESULT: detection 3/5 on app-shaped+sound (vs ~0 library-heavy), target-fix validated (2026-10-12)

Deep scan on the 5 app-shaped+sound targets (`benchmarks/measurements/2026-10-12-hunter-fair-targets/`):
- 3/5 detected: graphiti (hunter, Cypher injection), mcp-remote (hunter, url-scheme injection), dcmcp (ENGINE
  overlay, "outbound.request reached from parameter" on readFileFromUrl; the param-as-source mode fired because an
  entry point is present). 2/5 missed: malla (DOM/template XSS) and dms (Jinja SSTI), both in families
  documented as limited in families.toml (template-mediated escaping).
- The library-heavy pilot found ~0 → this confirms that the target mismatch affected detection. On an app-shaped repo the engine
  itself detects (parameter is a recognized source once the entry point is in-repo).
- Everything stops at `suspicion`/`static_corroboration`. None are proven. Cost ~$0.007/repo.

Bet #1 (fix the eval target) is necessary and improves detection, but is insufficient on its own.
Detection appears on fair targets; release-grade BLOCK still needs (a) proof-arm elevation (suspicion→proven) and
(b) family coverage (template XSS/SSTI) + the DSPy hint loop for misses. Next: recompute a floor on an app-shaped
sound subset / real app corpus (VAmPI, NodeGoat, DjanGoat, vibe-py), and measure the proof arm's suspicion→proven lift.

## PROOF-ARM MEASUREMENT on the 3 fair-target hits (2026-10-12): push-time lift 0/3, structural

Measured whether the proof arm can elevate the 3 fair-target suspicions (graphiti, mcp-remote, dcmcp) to
`exploit_demonstrated`.
- The search arm's `FAMILY_ORACLES` (search/demo.py) differs from families.toml's `verifier`.
  All 3 hits have a runtime oracle: injection→(sql,command), untrusted_destination→(ssrf). (deserialization/
  access_control/config_secrets have none, empty tuple → `no_oracle`.) So dcmcp is provable in principle
  (earlier "unprovable" was a families.toml misread).
- Runtime differential proof through `search/verify.verify()` requires (1) an authored declarative demo
  (start the app on a port, run exploit steps, fill oracle placeholders: sql→database_path, command→marker_dir,
  ssrf→callback_url), (2) both head and base runnable with offline deps (`pip --no-index`, `npm ci --offline`),
  (3) a sandbox differential "owned effect in 3/3 affected runs and 0/3 safe runs". Local host has a sandbox
  (`isolation_mode: userns`); the plane supplies a task-boundary dispatcher.
- The scan/push path reaches only `suspicion`/`static_corroboration` (verification.py levels). There is no code
  path from a scan suspicion to `exploit_demonstrated`, and no caller wires the search Coordinator from the push
  flow. The vulns are real, but proof-arm lift at push time = 0/3 because proving is a
  runtime differential operation with an offline build for each target that cannot run inside a pre-push hook. (Prior
  per-pair demo attempts were mostly inconclusive on this exact wiring, app startup, offline deps, oracle plumbing.)

This resolves the three-bet choice. Proof/BLOCK runs asynchronously (CI / plane / triage
with authored demos + a runnable sandbox). At push time, the strongest available evidence is corroborated
suspicion:
- Bet #2 (advisory-with-conditions) is the honest PRE-PUSH product: surface corroborated suspicions ("change
  introduces a flow that looks like X; reachable if untrusted Y reaches it"), let the dev / coding-agent (who has
  the app context) judge. This matches the "oversee coding agents" purpose and the evidence available at the suspicion rung.
- Bet #3 (the proof arm) is the ASYNC BLOCK lane: run `search/verify` on the plane/CI for the suspicions worth
  proving, with authored (eventually DSPy-authored) demos. Run a bounded, separate test on one tractable target
  (mcp-remote) to confirm that the arm demonstrates a real unseen vuln.

## BANKS FIXED-SEARCH MVP (2026-10-12): "no wrong targets, only wrong searching" demonstrated

Record: `benchmarks/measurements/2026-10-12-banks-fixed-search-mvp/`. Target: banks (the "library" that gave
no engine path findings in the pilot). The target and CPG are unchanged; only the search changes.

- Injected the two annotations a per-target LLM steer would supply: **parameter-as-source**
  (`parameter_sources=True`, so `prompt.name` counts as untrusted) + the **missing file-write sink**
  (`write_text`/`read_text` added to path sinks).
- The shipped search baseline resolved 0 `prompt → write_text` flows. Its 5 flow rows are all census/
  evidence (`sink=None`), matching the pilot's zero path findings.
- Fixed search: the engine resolves `prompt → path-join → prompt_file.write_text(prompt.raw)` in
  `from_prompt_path` (`source=prompt`), plus a second `write_text` sink in `_scan`. These appear only with
  the annotations.
- The banks result supports the hypothesis: the target was valid, but the search lacked annotations. The
  fix needed exactly **two** inputs: the param-source and the file-write sink. These are what the
  per-target LLM steer (DSPy-optimised, framework-seeded) has to learn to supply. This is the first measured
  instance of a complete "#2 guided by #1" loop on an unseen target.
- Caveats: (1) one row shows `source=path` not `prompt`, the param-source fires broadly, the steering loop needs to control that breadth to improve
  precision; (2) this is a trace, not the runtime differential proof (proof stays the async BLOCK lane).

The first MVP used the single-query `cpg.run("taint", …)` path and returned
0/0 because of an instrument failure, rather than producing a valid result (`cpg query taint failed` on every query). Root cause filed in
`bugs/taint-sc-single-query-signature-skew.md`: `request_params()` emits 5 keys (`guards`, `fixedOrigin`,
`originAnchors`, `quotedSanitizers`, `fieldParameterSources`) that `taint.sc`'s `exec` signature does not
declare, so both single-query sub-routes (CLI `--param` and session named-arg) reject them. The batch path
(`run_batch` → `requestsFile` JSON) tolerates them, which is why the pilot scans ran and this MVP used it.
