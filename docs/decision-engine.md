# The learned decision engine (in development)

**Status 2026-10-02: in development, not adopted.** No scan, pre-push check or report uses it;
every user-facing path is today's deterministic one until a compiled program is adopted. The
design is the `learned-decision-engine` specification (maintainer tooling); the code is in
`src/openultrasast/learn/`.

## Why

Every detection gain so far was a hand edit made after a miss: a rule, a taint vocabulary entry,
a guard, a prompt line, a tie-break. Each was tuned on the cases that exposed it, and engine
tuning measured on population v1 did not transfer to v2 (see [evaluation.md](evaluation.md)).
The engine replaces that with a decision learned from labelled outcomes and checked out of
repository.

## Design

- **Signals, not verdicts.** Every instrument (quick rules, the Joern engine, model sink and
  role classification, the plane's verify passes and agreement, repository facts such as
  callers) contributes a feature record per candidate `(path, function, family)`, including an
  explicit state when it did not run or failed. None decides alone.
- **Labels from ground truth.** `ousast learn labels` derives labels only from sources on a
  fail-closed allow-list (`learn/sources.toml`): the vulnerable and fixed sides of pairs, the
  declared sites and fix ranges of spent populations, benign deltas and recorded adjudications.
  "Rejected by the plane" is never a negative. Reserved populations (v3) are not on the list.
- **An AI classifier with local memory, compiled in house in the DSPy style.** The program is an
  instruction, a few demonstrations and up to six retrieved labelled examples, then the
  candidate's code excerpt and signals; the model (`deepseek-flash`) answers
  vulnerable / not vulnerable / unsure with a rationale, sampled `k` times, giving a score `s`.
  Compilation bootstraps demonstrations and searches instructions on a compile split, scored by
  a pre-registered balanced Brier score (`learn/compile.toml`).
- **Retrieval** from the memory store: nearest neighbours by Gower distance on the signal
  profile, re-ranked by cosine similarity of code embeddings (OpenAI `text-embedding-3-small`
  through OpenRouter, cached by excerpt hash), under a label/family/repository balance rule. An
  evaluation-boundary filter keeps a candidate's own repository group out of what it is shown.
- **Repository-grouped evaluation.** The compile split (25% of repository groups) is never
  evaluated. The rest is evaluated by outer grouped 5-fold cross-validation: the Platt
  calibration map is cross-fitted on the other folds and the operating points are chosen on the
  other folds (nested). One compile per profile, not one per fold. Intervals are 95%
  repository-cluster bootstrap.
- **Two operating points.** BLOCK is offered only when calibration holds (slope CI contains 1,
  intercept CI contains 0, ECE <= 0.05) and a fold reaches the required precision; otherwise the
  engine is ADVISORY only. An `unsure` answer can never BLOCK.

## First measured slice (2026-10-01)

Record: `benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json` (counts
only). Family **injection** only; memory of 724 static examples from all families; input profile
v1 with the engine signals and function length withheld (a leak audit found them separating the
sides of a pair by construction: `2026-10-01-decision-engine-leak-audit/`); framework priors off.

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
After the advisory-fix harvest the memory holds 904 static examples (724 before). One program was
compiled per evaluable family (injection recompiled, since the memory changed) and evaluated on
that family's own candidates, out of repository as above: compile split never evaluated, outer
grouped 5-fold, calibration cross-fitted, operating points nested, 95% repository-cluster
bootstrap intervals (2,000 resamples); input profile v1, priors off, k = 5.

| Family | Candidates (groups; positive) | Pooled AUC of `s` (95% CI) | Within-pair AUC (paired groups) | ADVISORY recall / precision | Canary agreement |
| --- | --- | --- | --- | --- | --- |
| access control | 37 (22; 23) | 0.96 (0.90 - 1.0) | 0.93 (14) | 0.91 / 0.91 | 0.83 |
| deserialization | 46 (30; 30) | 0.90 (0.82 - 0.97) | 0.81 (16) | 0.83 / 0.76 | 0.93 |
| injection | 110 (29; 58) | 0.77 (0.67 - 0.88) | 0.72 (22) | 0.88 / 0.57 | 0.77 |
| output encoding | 44 (27; 29) | 0.91 (0.82 - 0.97) | 0.82 (15) | 0.86 / 0.81 | 0.90 |
| path | 35 (21; 21) | 0.89 (0.79 - 0.97) | 0.83 (14) | 0.86 / 0.69 | 0.90 |
| untrusted destination | 62 (37; 38) | 0.85 (0.76 - 0.94) | 0.72 (18) | 0.84 / 0.73 | 0.87 |

- **BLOCK is offered for no family.** Calibration holds only for output encoding (ECE 0.045), and
  there no fold reaches the required precision (`precision_unreachable`: no fold reaches a Wilson
  lower bound of 0.95). For the other five families calibration does not hold (ECE 0.071 to 0.119).
- **The pooled AUC is the more favourable number.** Every family's pool includes candidates that
  carry only a positive label, with no fixed-side counterpart (7 to 19 per family; there are no
  single-label negatives), so the pooled AUC is inflated by positives that never had to be told
  apart from their own fix. The within-pair AUC over the paired groups, 0.72 to 0.93, is the
  stricter reading (`paired_groups_check` in the record).
- **Re-run agreement (canary, 30 candidates per family) is below 0.9 for three families:**
  injection 0.77, access control 0.83, untrusted destination 0.87.
- **One memory-size point for injection** (paired: the same program, candidates and folds, with a
  retrieval memory of 724 vs 904 examples): AUC 0.76 vs 0.77, within the intervals. No injection
  example was added, so the new examples reach an injection prompt only as contrast.
- **Spend:** $2.88 metered at list price for DeepSeek under an $8 ceiling, $0.0009 for
  embeddings; $0.0027 to $0.0032 per evaluated candidate. The access-control evaluation replayed
  from the response cache at $0 with identical predictions.
- **An instrument fix is recorded:** compiled demonstrations ignored the near-duplicate rule
  (cosine >= 0.98) until the pre-call boundary assertion stopped the untrusted-destination
  evaluation; demonstrations are now swapped or dropped like retrieved examples, and the stopped
  part was replayed after the fix.

**Not adopted.** Still ahead: leave-one-source-out, leave-one-framework-out, the remaining
learning-curve points (memory size 0/25/50%, number of sources), integration into scan and
pre-push, adoption, and the one-time v3 check.

## Experiments

Changes to prompts, models, pass counts or features are compared by controlled experiments, so
nothing is adopted on one run's number. One is registered and has not run: exp-002 (variance
reduction of the score). No result exists; this page carries one only once a record under
`benchmarks/measurements/` does.

## Commands

`ousast learn` is a maintainer command group over the engine's data. Paid steps take
`--budget-usd`; `--replay-only` answers every call from the response cache at no cost.

| Command | Does |
| --- | --- |
| `ousast learn labels` | labels from the allow-listed sources (host only); `--snapshot` writes the counts-only record |
| `ousast learn memory build` | label + feature record + excerpt -> `example` rows (no model) |
| `ousast learn memory embed` | embed the stored excerpts (OpenRouter, metered, cached) |
| `ousast learn compile` | compile the program on the compile split |
| `ousast learn evaluate --program ID` | outer-fold evaluation, cross-fitted calibration, nested operating points |
| `ousast learn curve --program ID` | the metric over memory size on a fixed candidate subset |
| `ousast learn audit-leaks` | how well each signal alone separates the sides of a pair (no model) |

The memory store is the plane's (`OUSAST_MEMORY`; see [ops/ax/README.md](ops/ax/README.md)).
The harvests that produced the plane signals ran as plane Runs generated by
`ousast plane harvest` (`benchmarks/measurements/2026-10-01-decision-engine-harvest/record.json`
and, for the advisory-fix pairs, `2026-10-02-decision-engine-harvest-advisory/record.json`).
