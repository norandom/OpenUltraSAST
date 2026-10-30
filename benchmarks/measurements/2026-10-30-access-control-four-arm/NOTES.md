# Access-control four-arm development regression (task 13.3)

Date: 2026-10-30. Spec: `.kiro/specs/access-control-prover/` task 13.3 (Reqs 5.1-5.7, 6.1, 7.3, 11.8, 12.9).
Result role: **development regression evidence only** -- population used to choose facts and analyzer
behavior; not an admission claim (Req 5.7, 12.9).

## Setup

- Arms: four registered per Req 5.5 (old/new analyzer crossed with old/new fact set).
  - Baseline bundle: analyzer revision `c5341d79a21bfae49ee157bdac19f967754f0be4` (the 2026-10-28 gate-1
    commit), fact artifact digest `3eb5bf699434`, materialised under
    `~/ousast-results/prover/ac-four-arm-1/bundles/baseline/`.
  - Candidate bundle: analyzer revision `9c95f842f7263710ec7d106794b37eb94a45425d` (HEAD at run time),
    same fact artifact digest `3eb5bf699434`.
- Fact identity, proven before any arm ran: the 18 ruleset TOMLs under `src/openultrasast/ruleset` are
  byte-identical between the baseline revision and HEAD (manifest digest `e7db4031d3d5`, disk == HEAD ==
  baseline ref). The amendment cycle is therefore analyzer-only, and the cross arms are input-identical to
  their parents by digest proof:
  - `baseline-analyzer/candidate-facts` == `baseline-analyzer/baseline-facts` (identical inputs),
  - `candidate-analyzer/baseline-facts` == `candidate-analyzer/candidate-facts` (identical inputs).
  Determinism is spot-verified by re-proving sampled changes and diffing judgments (below).
- Population: `benchmarks/valid/train/pool-train.toml`, freeze-verified through `load_slice` (the same
  frozen 23-repo pool as the 2026-10-28 run; 483 changes = 23 fix pushes + 460 ordinary pushes).
- Clones: `~/ousast-results/valid/train/hist/<owner__name>`, repos mapping
  `~/ousast-results/valid/train/repos_hist_pool23.json`.
- Nonzero input reads: the runner records a byte table per change (`instrument.file_bytes`,
  `changed_bytes`, `hook_bytes_read`), refuses zero-byte reads of tracked files, and allows a file git
  holds empty only as a counted `empty_files` entry -- the same instrument contract as the 2026-10-28 run.
  Every adapted baseline record kept `hook_bytes_read > 0`; the summary refuses on any zero-byte entry.

## Execution

- `baseline-analyzer/baseline-facts`: the immutable 2026-10-28 records themselves
  (`~/ousast-results/prover/ac-train-1/`, 483 records, 0 instrument failures at run time), adapted by
  `benchmarks.valid.arm_regression.adapt_baseline_record` with an explicit `vocabulary: binary` marker:
  unguarded := findings count, discharged := recorded discharge count, indeterminate := 0 (the baseline
  analyzer could not express it). Research decision: the 2026-10-28 numbers remain the immutable baseline;
  a rerun on the same repositories is regression evidence.
- `candidate-analyzer/candidate-facts`: executed 2026-10-30 from the working tree (clean, HEAD), strict
  judgment lane (`judgment_mode=True`, three-way vocabulary), two resumable shards over the sorted change
  ids (round-robin), records under `~/ousast-results/prover/ac-four-arm-1/cacfon/`.
- Cross arms: registered aliases by proven input identity (digest proof above) plus a determinism
  spot-check that re-proves sampled changes (all 23 fix pushes were covered by the executed arm; the
  sample re-proves the judgment lane reproduces identical judgments for identical inputs).
- Summary assembly: `arm_regression.summarize_arm` (masked repository identities, Req 5.4),
  `arm_regression.four_arm_development` over `development_runner.four_arm_report` (Req 11.8), metric
  headline through `benchmarks.valid.metrics` with the same scorer contract as the baseline summary
  (Wilson intervals; `push.admission.defects` derived from strict-lane findings), budget result per
  Req 6.1 published as development evidence (the summary itself refuses only on instrument failure).

## Corrections during the run (instrument honesty)

1. First probe run reported all-zero coverage in 0.0 s: the probe had skipped the sparse-checkout
   disable step, so worktrees contained no files. Fixed by replicating the harness; the probe then read
   4,096-6,170 files per repo and found real entry points.
2. Two shard restarts: the first record shape missed the scorer contract (`instrument.hook_exit`,
   `push.admission.defects`); 35 stale-shape records were deleted rather than patched -- back-filling
   instrument fields into written records would fabricate proof.
3. `tests/test_admission_scoring.py` imported `benchmarks` without the `sys.path.insert` its sibling
   test files have; it had only ever passed when an earlier-collected file fixed the path first. Fixed
   with the sibling pattern.

4. Review round 1 rejected the first summary for a false baseline provenance stamp
   (`bundle_from` stamps the working-tree HEAD, so the baseline bundle claimed revision `9c95f842` instead
   of `c5341d7`), for a missing covered/uncovered recall split, and for shard-scoped population digests.
   Remediated by rebuilding both bundle manifests with explicit revisions and honest lane configurations,
   re-adapting the baseline records from the corrected manifest, publishing the authoritative
   full-population digest (`999594274a4e`, asserted in assembly) with a per-record stamp disclosure, and
   adding the recall split. No arm was re-executed; no written record was back-filled.

## Result

All numbers from `summary.json` (this directory); raw records under `~/ousast-results/prover/ac-four-arm-1/`.
**Development regression evidence only.**

| metric | immutable 2026-10-28 baseline | candidate arm 2026-10-30 |
|---|---|---|
| recall (fix pushes) | 15/23 = 65.2% (Wilson 44.9-81.2) | 8/23 = 34.8% (Wilson 18.8-55.1) |
| covered-repo recall | 15/21 | 8/21 = 38.1% (Wilson 20.8-59.1) |
| uncovered-repo recall | 0/2 | 0/2 (separately reported, Req 7.3) |
| location recall | 55/93 = 59.1% (Wilson 49.0-68.6) | 25/93 = 26.9% (Wilson 18.9-36.7) |
| false alarms / 100 pushes | 69 on 460 = 15.0 (Wilson 12.0-18.6) | 24 on 460 = 5.2 (Wilson 3.5-7.6) |
| precision | 15/84 = 17.9% | 8/32 = 25.0% |
| instrument failures | 0 | 0 |
| per-change seconds | mean 27.9, max 1063 | mean 17.4, median 1.1, max 240 |
| budget gate (120 s) | exceeded (development evidence) | failed: 20 changes over, max 240 s |
| uncovered repositories | 2 | 2 (masked: `1ca62ca671af`, `c92157c966cc`) |

Four-arm attribution (Req 11.8): fact-only lift **0 on every judgment kind** -- the fact inputs are
byte-identical (digest `e7db4031d3d5`), so the entire movement is analyzer-attributed. Pair-level
totals: unguarded 340 -> 94 (-246), discharged 130 -> 0 (-130), indeterminate 0 -> 102 (+102).
Per-change transitions (baseline binary flag -> strict three-way): flagged->unguarded 29,
flagged->indeterminate 25, flagged->none 30 (84 baseline flags reconciled exactly), quiet->unguarded 3,
quiet->indeterminate 8, quiet->none 388. `discharged` is 0 across the whole strict run: on this
population the strict lane never proves a complete-path discharge -- every judged pair is unguarded or
indeterminate.

Reading: the amended analyzer buys judgment honesty at a large recall cost on this development
population. It retracts 55 of 84 binary alarms (25 to indeterminate -- incomplete evidence, visible;
30 to no judged pairs at all), finds 3 new ones, and cuts false alarms roughly threefold
(15.0 -> 5.2 per 100). The stage funnel names the bottleneck: of 4,943,304 recorded call resolutions,
only 589,520 (11.9%) are complete; 1,451,325 are incomplete and 2,908,559 unresolved. Exact, finite
call resolution (task 8.3) starves pair formation upstream of judgment; the strict dominance and
witness rules then never reach a definite discharge. This mirrors the pre-registered risk
("indeterminate inflation ... report the stage funnel and reason distribution; improve the dominant
reason rather than weakening the lattice", research.md) and the 2026-10-28 ablation's levers
(call resolution first). Development-only conclusion for the next amendment cycle: grow entry facts
and call-resolution coverage; the three-way lane itself behaves exactly as specified -- no pair is
ever silently clean, and every refusal is visible in the funnel.

Runtime: the executed arm ran as two resumable shards, 64.2 + 73.9 minutes wall (4 cores, 2 workers),
483/483 records, every record with nonzero-read proof (`hook_bytes_read` > 0, no zero-byte entries,
`hook_exit` 0). Determinism spot-check: 6 sampled changes (3 fix pushes, 3 from the largest
repositories) re-proved to identical judgments, findings and status.

## Reproduction

- Bundles: `/tmp/opencode/bundles_133.py` (fact manifests, identity proof, materialisation through
  `benchmarks.valid.run_manifests`), corrected by `/tmp/opencode/fix_bundles_133.py` (explicit revisions).
- Executed arm: `/tmp/opencode/run_shard_133.py <i> <n>` (shardable, resumable; module:
  `benchmarks.valid.arm_regression.run_arm`, strict judgment lane).
- Baseline adaptation: `/tmp/opencode/adapt_bab_133.py` (`adapt_baseline_record`, binary vocabulary).
- Determinism: `/tmp/opencode/determinism_133.py`.
- Summary: `/tmp/opencode/assemble_133.py` (`summarize_arm`, `four_arm_development`, scorer-compatible
  metrics via `benchmarks.valid.metrics` and `benchmarks.unseen.score`).
