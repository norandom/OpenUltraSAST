# The learned decision engine (in development)

**Status 2026-10-02: in development, not adopted.** No scan, pre-push check or report uses it.
Every user-facing path stays on today's deterministic one until a compiled program is adopted.
The design is the `learned-decision-engine` specification (maintainer tooling). The code is in
`src/openultrasast/learn/`.

## Why

Before the engine, every detection gain was a hand edit. Each edit was tuned on the cases that
exposed the miss. Engine tuning measured on population v1 did not transfer to v2. [Where we
stand](where-we-stand.md#2-our-approach-to-detection-step-by-step) gives the reasoning and the
step-by-step chain that replaced hand edits.

## Design

- **Signals, not verdicts.** Every instrument contributes a feature record per candidate
  `(path, function, family)`. The instruments are quick rules, the Joern engine, model sink and
  role classification, the plane's verify passes and agreement, and repository facts such as
  callers. The record includes an explicit state when an instrument did not run or failed. No
  instrument decides alone.
- **Labels from ground truth.** `ousast learn labels` derives labels only from sources on a
  fail-closed allow-list (`learn/sources.toml`). Fail-closed means a source not on the list is
  never used. The sources are:
  - the vulnerable and fixed sides of pairs;
  - the declared sites and fix ranges of spent populations;
  - benign deltas;
  - recorded adjudications.

  "Rejected by the plane" is never a negative. Reserved populations (v3) are not on the list.
- **An AI classifier with local memory, compiled in house in the DSPy style.** The program has
  an instruction, a few demonstrations and up to six retrieved labelled examples. Then come the
  candidate's code excerpt and signals. The model (`deepseek-flash`) answers vulnerable / not
  vulnerable / unsure with a rationale. It is sampled `k` times, which gives a score `s`.
  Compilation bootstraps demonstrations and searches instructions on a compile split. A
  pre-registered balanced Brier score (`learn/compile.toml`) scores the candidates. The Brier score
  measures how far predicted probabilities are from the true labels.
- **Retrieval** from the memory store works in three steps:
  1. find nearest neighbours by Gower distance (a distance over mixed feature types) on the
     signal profile;
  2. re-rank them by cosine similarity of code embeddings (OpenAI `text-embedding-3-small`
     through OpenRouter, cached by excerpt hash);
  3. apply a label/family/repository balance rule.

  An evaluation-boundary filter keeps a candidate's own repository group out of what it is
  shown.
- **Repository-grouped evaluation.** The compile split (25% of repository groups) is never
  evaluated. The rest is evaluated by outer grouped 5-fold cross-validation:
  - the Platt calibration map (which turns the score into a probability) is cross-fitted on
    the other folds;
  - the operating points are chosen on the other folds (nested).

  There is one compile per profile, not one per fold. Intervals are 95% repository-cluster
  bootstrap.
- **Two operating points.** BLOCK is offered only when both of these hold:
  - calibration holds: slope CI contains 1, intercept CI contains 0, ECE <= 0.05;
  - a fold reaches the required precision.

  Otherwise the engine is ADVISORY only. An `unsure` answer can never BLOCK. ECE (expected
  calibration error) is the average gap between predicted and observed rates.

## First measured slice (2026-10-01)

Record: `benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json` (counts
only). The setup:

- family **injection** only;
- memory of 724 static examples from all families;
- input profile v1, with the engine signals and function length withheld;
- framework priors off.

The signals were withheld because a leak audit found them separating the sides of a pair by
construction (`2026-10-01-decision-engine-leak-audit/`). AUC below is the chance the engine
ranks a real bug above a fixed one.

| Measure | Value (95% repository-cluster CI) |
| --- | --- |
| Candidates evaluated | 110 in 29 repository groups, 58 positive |
| ADVISORY recall | 0.90 (0.82 - 0.97) |
| ADVISORY precision | 0.54 (0.44 - 0.65) |
| AUC of the score `s` | 0.74 (0.65 - 0.85) |
| Majority "vulnerable" verdict | precision 0.86 (0.72 - 1.0), recall 0.43 (0.29 - 0.62) |
| BLOCK | not offered: ECE 0.064 > 0.05, and every fold reported `precision_unreachable` |
| Compiled program | balanced Brier 0.128 on the validation split vs 0.199 for the baseline instruction |
| Canary agreement on re-run | 0.83 (30 candidates) |
| Spend | $0.91 metered at list price for DeepSeek, $0.0040 for embeddings; $0.0032 per evaluated candidate |

## Second slice: six families (2026-10-02)

Record: `benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json` (counts only).
After the advisory-fix harvest, the memory holds 904 static examples (724 before).

One program was compiled per evaluable family. Injection was recompiled, since the memory
changed. Each program was evaluated on its family's own candidates, out of repository as above:

- compile split never evaluated;
- outer grouped 5-fold;
- calibration cross-fitted;
- operating points nested;
- 95% repository-cluster bootstrap intervals (2,000 resamples);
- input profile v1, priors off, k = 5.

| Family | Candidates (groups; positive) | Pooled AUC of `s` (95% CI) | Within-pair AUC (paired groups) | ADVISORY recall / precision | Canary agreement |
| --- | --- | --- | --- | --- | --- |
| access control | 37 (22; 23) | 0.96 (0.90 - 1.0) | 0.93 (14) | 0.91 / 0.91 | 0.83 |
| deserialization | 46 (30; 30) | 0.90 (0.82 - 0.97) | 0.81 (16) | 0.83 / 0.76 | 0.93 |
| injection | 110 (29; 58) | 0.77 (0.67 - 0.88) | 0.72 (22) | 0.88 / 0.57 | 0.77 |
| output encoding | 44 (27; 29) | 0.91 (0.82 - 0.97) | 0.82 (15) | 0.86 / 0.81 | 0.90 |
| path | 35 (21; 21) | 0.89 (0.79 - 0.97) | 0.83 (14) | 0.86 / 0.69 | 0.90 |
| untrusted destination | 62 (37; 38) | 0.85 (0.76 - 0.94) | 0.72 (18) | 0.84 / 0.73 | 0.87 |

- **BLOCK is offered for no family.** Calibration holds only for output encoding (ECE 0.045).
  There, no fold reaches the required precision (`precision_unreachable`: no fold reaches a
  Wilson lower bound of 0.95). For the other five families, calibration does not hold (ECE
  0.071 to 0.119).
- **The pooled AUC is the more favourable number.** Every family's pool includes candidates
  that carry only a positive label, with no fixed-side counterpart (7 to 19 per family; there
  are no single-label negatives). These positives never had to be told apart from their own
  fix, so they inflate the pooled AUC. The within-pair AUC over the paired groups, 0.72 to
  0.93, is the stricter reading (`paired_groups_check` in the record).
- **Re-run agreement (canary, 30 candidates per family) is below 0.9 for three families:**
  injection 0.77, access control 0.83, untrusted destination 0.87.
- **One memory-size point for injection.** This run is paired: the same program, candidates
  and folds, with a retrieval memory of 724 vs 904 examples. AUC was 0.76 vs 0.77, within the
  intervals. No injection example was added. So the new examples reach an injection prompt
  only as contrast.
- **Spend:** $2.88 metered at list price for DeepSeek under an $8 ceiling, and $0.0009 for
  embeddings. That is $0.0027 to $0.0032 per evaluated candidate. The access-control
  evaluation replayed from the response cache at $0 with identical predictions.
- **An instrument fix is recorded.** Compiled demonstrations ignored the near-duplicate rule
  (cosine >= 0.98). The pre-call boundary assertion caught this and stopped the
  untrusted-destination evaluation. Demonstrations are now swapped or dropped like retrieved
  examples. The stopped part was replayed after the fix.

**Not adopted.** [Where we stand](where-we-stand.md#5-open-items) lists, in one place, what is
still ahead.

## Experiments

Changes to prompts, models, pass counts, features or sampling are compared by controlled
experiments. Each experiment comes from a pre-registered manifest
(`plane/experiments/<id>.yaml`). This way nothing is adopted on one run's number.

Four experiments are registered:

- exp-001 (known callers) has not run.
- exp-002 compared a retrieval ensemble against today's temperature sampling. It ran on 160
  paired candidates in 56 repository groups and was **rejected**. Within-pair AUC was 0.815
  against 0.741 and the cost was $0.0021 against $0.0051 per candidate. The record shows re-run agreement
  0.875 against 0.906 and an interval spanning zero
  (`benchmarks/experiments/exp-002-retrieval-ensemble/result.json`).
- exp-003 compared two BLOCK rules on the same scores. It was **inconclusive**. Neither rule flags anything.
- exp-004 tested one pooled BLOCK threshold with a per-family floor. It was **inconclusive**.

### exp-003: precision-bound blocking (2026-10-03)

The question: is the calibration gate what keeps BLOCK out of reach?
Arm A is today's rule: a calibrated probability, offered only when calibration holds.
Arm B picks a raw-score threshold per family, on training folds only.
It takes the lowest threshold whose Wilson 95% lower bound on precision reaches 0.95.
The held-out repository group is then scored with that threshold.
Arm C relaxes the bound to point precision 0.95 over at least 10 flags.
Arm C was registered as secondary and does not decide.

- **Registered first.** The manifest and units were committed and registered before the run.
- **Primary metric:** arm B's held-out Wilson lower bound on flagged precision, per family.
- **Primary population:** paired units only. Positives-only groups are excluded; pooled figures are secondary.
- **Zero cost.** Scores came only from the response cache, behind a zero-ceiling meter.
  The meter recorded 0 client calls and $0.0.
- **Exclusions.** 142 of 353 units had an uncached response and were excluded, not asked.
  Path lost all 39 units. Injection and access control lost none.
- **Evaluated:** 211 units in 89 repository groups, 138 of them paired.

| Family | Evaluated (excluded) | Paired positives | Flagged A / B / C | Coverage A / B / C |
| --- | --- | --- | --- | --- |
| access control | 41 (0) | 16 | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 |
| deserialization | 14 (34) | 2 | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 |
| injection | 119 (0) | 38 | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 |
| output encoding | 24 (21) | 8 | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 |
| path | 0 (39) | 0 | 0 / 0 / 0 | none |
| untrusted destination | 13 (48) | 4 | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 |

No arm chose a threshold on any fold, so flagged precision is undefined everywhere.
Arm A failed calibration where it was checked: ECE 0.077 (access control), 0.1067 (injection).
The other families had too few units for a calibration check.

**Why B flags nothing.** A Wilson lower bound of 0.95 needs 73 flags without one error.
Injection, the largest family, holds 38 paired positives across all five folds.
The registration predicted this zero before the run.
On this data the bound, not the calibration gate, makes BLOCK unreachable.

**The zero is the rule's, not the instrument's.** The scores are real: 48 distinct values for injection.
In access control, the 10 highest-scored paired units are all positive.
In injection, a negative appears at rank 4 of the paired ranking.
Pooled rankings look cleaner because positives-only units fill the top.
Injection answered `unsure` for 42 of 119 units, and `unsure` never blocks.

Record: `benchmarks/experiments/exp-003-precision-bound-blocking/result.json`.

**Supplementary: all 353 units (2026-10-03).** This is not a new decision; exp-003's verdict stands.
The 142 excluded units had their responses filled with the same programs and request keys.
The fill cost 697 client calls and $0.331759 under a $1.00 ceiling.
The replay then decided all 353 units at zero cost: 244 paired, 146 repository groups.

| Family | Paired units (positives) | Flagged A / B / C | ECE (arm A) |
| --- | --- | --- | --- |
| access control | 32 (16) | 0 / 0 / 0 | 0.077 |
| deserialization | 34 (17) | 0 / 0 / 0 | 0.0596 |
| injection | 76 (38) | 0 / 0 / 0 | 0.1067 |
| output encoding | 32 (16) | 0 / 0 / 0 | 0.0761 |
| path | 32 (16) | 0 / 0 / 0 | 0.062 |
| untrusted destination | 38 (19) | 0 / 0 / 0 | 0.0454 |

Still no arm flags any unit, so the registered rule reads inconclusive.
Calibration holds only for untrusted destination.
There arm A still finds no BLOCK point that reaches the bound.
Record: `benchmarks/experiments/exp-003-precision-bound-blocking/result-complete-cache.json`.

### exp-004: pooled block gate (2026-10-03)

The experiment tested one pooled BLOCK threshold across families.
Each family needed at least 10 clean flags to block.
Each family also had its own quiet threshold.
The run evaluated 501 units across 220 repository groups.
Of these, 390 units were paired.
The cache fill cost $1.238223 for 2,073 calls.
The replay cost $0.0 and made 0 client calls.

The verdict was **inconclusive**.
No fold found a `t_block` threshold.
The instrument check confirmed real scores.
The pooled top 30 contained 27 positives.
The first negative appeared at rank 12.
The bound needs 73 clean flags without an error.

A within-pair win means the vulnerable side scored above its fixed counterpart.

| Family | Within-pair wins | Pairs |
| --- | --- | --- |
| access control | 22 | 28 |
| deserialization | 18 | 25 |
| injection | 30 | 53 |
| output encoding | 18 | 28 |
| path | 25 | 29 |
| untrusted destination | 18 | 32 |

Precision at the top of the ranking now limits blocking.
Data volume alone cannot resolve this.
The next levers are graph evidence in the prompt and the combiner.

Records: `benchmarks/experiments/exp-004-pooled-block-gate/record.json` and `benchmarks/experiments/exp-004-pooled-block-gate/result.json`.

### exp-004: pooled block gate with a family floor (registered, not run)

This registration describes the setup before the run reported above.

The maintainer amended the BLOCK rule on 2026-10-03 (requirements, Req 6.4).
Precision is now shown across all families together, not per family.
Each family's score is first mapped by its own Platt fit, on training folds.
One threshold, t_block, then serves every family.
It is the lowest one whose pooled Wilson lower bound reaches 0.95 on training folds.
A family blocks only with at least 10 held-out flags and no error.
Otherwise its flags stay advisory.
Below a per-family t_quiet, which keeps 90% of positives, findings are silent.
No held-out label moves a threshold.

- **Primary metric:** the pooled held-out Wilson lower bound of flagged precision, paired units, before the floor.
- **Decision:** reject below point precision 0.95; adopt if the bound reaches 0.95 and a family passes the floor.
- **Units:** frozen from the memory after the negatives harvest.
- **Cost:** the run replayed the cache after a paid cache fill.

Manifest: `plane/experiments/exp-004-pooled-block-gate.yaml`.

The reading is on [Where we stand](where-we-stand.md#2-our-approach-to-detection-step-by-step).

## Commands

`ousast learn` is a maintainer command group over the engine's data. Paid steps take
`--budget-usd`. `--replay-only` answers every call from the response cache at no cost.

| Command | Does |
| --- | --- |
| `ousast learn labels` | labels from the allow-listed sources (host only); `--snapshot` writes the counts-only record |
| `ousast learn memory build` | label + feature record + excerpt -> `example` rows (no model) |
| `ousast learn memory embed` | embed the stored excerpts (OpenRouter, metered, cached) |
| `ousast learn compile` | compile the program on the compile split |
| `ousast learn evaluate --program ID` | outer-fold evaluation, cross-fitted calibration, nested operating points |
| `ousast learn curve --program ID` | the metric over memory size on a fixed candidate subset |
| `ousast learn audit-leaks` | how well each signal alone separates the sides of a pair (no model) |
| `ousast learn experiment register\|units\|run\|analyse MANIFEST` | A/B experiments from a pre-registered manifest (`plane/experiments/<id>.yaml`): record its digest, freeze the units (no model), run the arms paired (arm A may replay from the cache at $0), analyse (repository bootstrap, exact McNemar, two looks, the adoption verdict) |
| `ousast learn experiment fill MANIFEST --budget-usd X` | Fill missing responses for a registered `kind: rule` experiment's frozen units before its zero-cost run; `--dry-run` inspects and estimates without calls or writes |

`experiment fill` accepts `--memory URL`, `--profile static|plane` (default `static`),
`--manifest-model PATH` (default `plane/models/deepseek-flash.yaml`) and `--out PATH`.
Freeze, commit and register the units first. Fill uses the incumbent programs and the
same retrieval, sampling and cache keys as replay. The first missing request is the
smoke call; a successful smoke response is kept. Any provider failure stops the fill.

The JSON report on stdout gives each family's units, distinct requests, initially
cached and missing responses, newly filled responses and still-missing responses,
plus total client calls and metered USD. `--out` also saves it, except during dry-run,
which writes nothing. Exit codes are 0 for completion or dry-run, 1 for a provider/cache
failure, 2 for invalid setup and 3 for budget exhaustion. Resume a partial fill with a
new invocation and budget; that budget covers only the new invocation, including smoke.

Dry-run uses each family's mean billed cached response cost when recorded usage exists.
Model prices account for cache-hit input, cache-miss input, and output tokens.
Without cached usage, it uses the program's input-token estimate and **300 output tokens**.
Each family's `estimate_method` reports `measured` or `estimated`.
It reports potential retries separately as `conditional_retries`: an unseen answer
may need one parse retry, whose necessity cannot be known without calling the model.
Known invalid cached answers include their retry requests in the inventory.

Fill reserves at least **$0.01** and the largest observed call cost before each call.
For the production client it also reserves a conservative input-byte token bound plus
the program's enforced output-token limit; hidden provider retries are disabled.
Consequently a small budget may stop before making any call, and a fill may finish
with unused budget. Calls without token usage stop as failures, never as free calls.

The memory store is the plane's (`OUSAST_MEMORY`; see [ops/ax/README.md](ops/ax/README.md)).
The harvests that produced the plane signals ran as plane Runs generated by
`ousast plane harvest`. Records: `benchmarks/measurements/2026-10-01-decision-engine-harvest/record.json`
and, for the advisory-fix pairs, `2026-10-02-decision-engine-harvest-advisory/record.json`.
