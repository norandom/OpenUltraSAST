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
</content>
