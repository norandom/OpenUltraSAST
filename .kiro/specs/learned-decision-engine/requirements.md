# Requirements Document

## Introduction

Detection decisions stop being hand-coded. Every instrument becomes a producer of per-candidate signals, a trained
decision engine turns signals into a calibrated probability per candidate and family, pipeline changes are chosen
by A/B experiments run on the plane, and expected detection on unseen code is extrapolated with stated uncertainty.
Maintainer direction and context: `brief.md`.

## Boundary Context

- **In scope**: a feature record per candidate built from every instrument and the memory store; a labelled
  dataset with provenance; training, calibration and versioning of the decision engine; A/B experiments as plane
  Runs; learning curves and leave-one-population-out estimates; the engine's use in `ousast scan`, `ousast
  pre-push` and plane Runs; a final one-time check on frozen population v3.
- **Out of scope**: new instruments (they plug in as signal producers later); deep or large models; any change to
  population v3 or its protocol; publishing results (licences still gate that).
- **Adjacent expectations**: instruments keep working standalone; the memory store (harnessx-removal Req 6) is
  the system of record; the plane attributes every experiment's token spend per task.

## Requirements

### Requirement 1: Instruments emit signals, not verdicts

**User Story:** As the maintainer, I want every detector's output to become evidence for one decision, so that no
single hand-written rule or prompt decides whether code is vulnerable.

#### Acceptance Criteria

1. For each candidate (repository, pin, file, function, family) the system assembles one feature record from every
   instrument that ran: quick-rule hits (rule ids, counts), engine findings and questions completed, model sink
   classification, triage, verify pass verdicts and turns, tie-break, repository facts (callers, entry-point
   distance), coverage, language and family.
2. A missing instrument is recorded as missing, never as a negative signal (coverage `none` stays distinct from
   "ran and found nothing").
3. Feature records are stored in the memory store with the instrument versions and image digests that produced
   them, so any record can be rebuilt.

### Requirement 2: Labels come from ground truth with provenance

**User Story:** As the maintainer, I want the engine to learn only from outcomes we can defend.

#### Acceptance Criteria

1. Positive labels: candidates matching a declared site or fix range on a vulnerable pin (populations, pair
   corpus). Negative labels: the same functions on fixed pins, benign-control pins, and findings adjudicated false
   by the maintainer or a judge task with recorded evidence.
2. A plane verdict alone (agreed, rejected, disputed) is a feature, never a label.
3. Every label records its source (population, pair, adjudication), split, and the date it was created; labels from
   a reserved or frozen population are unusable for training until that population's evaluation is recorded.

### Requirement 3: A trained, calibrated, versioned decision engine

**User Story:** As the maintainer, I want one engine that decides from the signals, retrained as data grows, so
that detection improves without hand edits.

#### Acceptance Criteria

1. The engine is a simple, inspectable model (regularised logistic regression or shallow gradient-boosted trees),
   trained per family where data allows and pooled otherwise; its output is a calibrated probability.
2. Training is reproducible from the memory store and a recorded split: the same inputs give the same model, and
   every model version records its data snapshot, feature set, hyperparameters and metrics.
3. Evaluation uses population-level folds (leave-one-population-out, and pairs grouped by repository): no
   repository appears in both training and evaluation of a reported number.
4. Operating points (block, report, drop) are thresholds chosen on training folds for stated precision targets and
   reported with the recall they give; the M4 gates (>= 95% precision, >= 90% recall) are the targets, not assumed.
5. The engine explains each decision by its top contributing features, stored with the finding.

### Requirement 4: Pipeline changes are chosen by A/B experiments

**User Story:** As the maintainer, I want changes to prompts, models, pass counts, rule sets and features compared
by controlled experiments, so that nothing is adopted on one run's number.

#### Acceptance Criteria

1. An experiment is declared before it runs: arms (variants as plane Run configurations), unit of randomisation
   (candidate, file or repository), metric (detection, precision, cost per candidate), minimum detectable effect,
   sample size or sequential stopping rule, and budget.
2. Arms run on the same units where the design allows (paired), with assignment recorded; results and spend go to
   the memory store per arm.
3. A variant is adopted only when the pre-registered test shows a difference with its confidence interval
   excluding zero, or declared equivalent within a margin for cost-only changes; otherwise the result is recorded
   as inconclusive.
4. The first experiment is the known open question: the known-callers prompt line (17 vs 19 sites flagged in any
   pass), on the development corpus.

### Requirement 5: Detection is extrapolated, with uncertainty

**User Story:** As the maintainer, I want to know how well the system will detect on code nobody has seen, before
and without tuning on it.

#### Acceptance Criteria

1. Learning curves: engine metrics as a function of training data size and number of populations, per family,
   with confidence bands.
2. Expected recall and precision on unseen code are reported per family and language as intervals from the
   population-level folds; a family with too few labels is reported as "insufficient data", never as a number.
3. The extrapolation is checked exactly once against frozen population v3 under protocol v3, after the engine and
   its operating points are fixed; the comparison of predicted and measured intervals is recorded.

### Requirement 6: The engine is what users get

**User Story:** As a user scanning a fresh codebase, I want the decision engine's judgement, not a raw list of
rule hits.

#### Acceptance Criteria

1. `ousast scan`, `ousast pre-push` and plane Runs report findings with the engine's probability, the operating
   point they passed and the top contributing features.
2. Without a trained model available the tools fall back to today's behaviour and say so in the report.
3. Hand-written rules remain as signal producers; changing their enabled/shadow status no longer changes what is
   reported unless the engine's decision changes.

### Requirement 7: Built for unseen repositories -- a repo safety net

**User Story:** As the maintainer, I want the engine judged by how it behaves on repositories it never saw, because
"the tool will never run against the test cases it's being trained with. it's purpose is a repo safety net."
(maintainer, 2026-09-30).

#### Acceptance Criteria

1. Every reported metric comes from folds grouped by repository across all corpora: a repository in an evaluation
   fold contributes no row to training.
2. Features are repository-agnostic by an allow-listed schema (no repository, path, file, function or commit
   identities), enforced by a test.
3. Two operating points serve the safety net: BLOCK, chosen for >= 95% precision on unseen repositories, and
   ADVISORY, trading precision for recall; both reported with out-of-repository intervals. The decision unit is a
   candidate in changed code (`pre-push` delta), with whole-repository scans as a secondary mode.
4. Calibration is checked on held-out repositories; where it does not hold, only ADVISORY is offered for that
   family.
5. Any adaptation to a user's own repository (facts reuse, their dismissals) is opt-in, separate from the
   generalisation model, and never contributes to its reported numbers.

### Requirement 8: No framework or application knowledge as a prerequisite

**User Story:** As the maintainer, I want the safety net to work on any application in a language, because "if
there is hardcoded application specification needed to build trees this is problematic. wordpress isn't the only
php application. same for python, js etc" (maintainer, 2026-09-30).

#### Acceptance Criteria

1. Hand-written knowledge is limited to the language level (built-ins, superglobals, process execution, raw
   database drivers, deserialisers). Roles specific to a framework or application (its request objects, query
   builders, hooks, sanitisers, guards) are inferred per repository at scan time from its own source and its
   dependencies, not required from a hand-written table.
2. Existing framework-specific entries (WordPress, Django, Flask, Express, Spring and others in `ruleset/semantic/`
   and `ruleset/<lang>/`) are tagged with their framework and enter the engine only as optional prior features; a
   prior is kept only if an A/B experiment on held-out repositories shows it helps, and the engine must still work
   with every prior switched off.
3. Evaluation is stratified by framework and includes leave-one-framework-out folds (for example: train without any
   WordPress repository, evaluate on WordPress), so a number never depends on having seen the target's framework;
   results are reported per framework and for "framework unseen in training".
4. The share of each reported result that depends on framework priors is stated (with priors vs without).
