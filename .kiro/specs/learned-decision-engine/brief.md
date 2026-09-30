# Brief: a trained decision engine and A/B experiments instead of hand-coded detection

Maintainer, 2026-09-30: "you need to go to a different approach with a b testing to extrapolate detection rather
than hardcoding it and train a decision engine".

## Why

Every detection gain so far was a hand edit made after a miss: regex rules, taint vocabulary, guards, prompt
lines, a tie-break rule. Each edit was tuned on the cases that exposed it and had to be re-qualified on a fresh
population; v1 -> v2 showed engine tuning does not transfer (0/17). The plane changed what is possible: every task
records per-candidate outcomes, costs and repository facts into one memory store, and runs are cheap to repeat.

## Direction

- Instruments become signal producers: quick rules, the Joern engine, model sink classification, verify passes,
  tie-break, repo facts (callers, reachability), triage. None decides alone.
- A decision engine, trained on labelled outcomes, turns the signals for a candidate into a calibrated probability
  that it is a real vulnerability of its family; operating points (block, report, drop) are thresholds on it.
- Changes to the pipeline (prompts, models, pass counts, rule sets, features) are variants compared by A/B
  experiments run as plane Runs with pre-registered metrics and confidence intervals, never adopted on a single
  run's point estimate.
- Detection on unseen code is extrapolated from measured learning curves and leave-one-population-out results,
  reported with uncertainty, and checked once on the frozen v3.

## Data on hand (2026-09-30)

- Pair corpus: 317 vulnerable/fixed pairs, 342 labelled findings (`ousast pairs`), with train/holdout splits.
- Populations: v1 (spent), v2 validation set (46 candidates, 20 declared sites; plane runs recorded), PHP
  development corpus (pmpro, v1 PHP, MediaWiki, WP Statistics). v3 (PHP, 16 cases) is being frozen now and stays
  untouched until the final check.
- Memory store rows: facts, per-pass verdicts, disputes, tie-breaks, costs, alerts, coverage.

## Risks

- Small labelled data: the engine must be simple and calibrated (regularised linear or shallow trees), with
  population-level folds; a deep model would memorise.
- Leakage: labels and features must never come from the population a number is reported on (the train-on-test
  rule; see the closed-loop leak).
- Label quality: "rejected by the plane" is not "safe"; negatives come from fixed and benign pins and adjudicated
  findings, not from absence of an alert.

## Relation to earlier specs

Replaces the hand-edit loop of `improve` for detection decisions (the memory proposer's M1/M2 status edits become
one variant family among others). `learning-harness` and `harnessx-self-improving-rulesets` are retired with
HarnessX. `finding-feedback-loop`, `constrained-detector` and `model-grounded-detection` are inputs to read in
design, not dependencies.
