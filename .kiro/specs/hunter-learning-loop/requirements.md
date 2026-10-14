# Requirements Document

## Project Description (Input)

Maintainer, 2026-10-13: "the hunter would then need a dspy process now, so that we iteratively refine our
llm integration. we can distinct positives from false positives. and dspy can mutate prompts with its
statistical tools. the key is to produce enough information for the llm to use it correctly." Then:
"threshold based assessments come later. right now the search is too bad. if I cut a threshold at 50:50
that is coinflip optimization. what we need rather than that is an annotate model for the llm, with
statistical ablation." And: "the answer to our problem is feature engineering + math." Before that:
"proof should be a resort to face with certainty. before our search problem needs to be solved to reduce
what we have to proof."

Who has the problem: the pre-push safety net. The valid benchmark pilot
(`benchmarks/measurements/2026-10-12-valid-benchmark-pilot/NOTES.md`) measured the LLM tool hunter at
5 of 12 verified positives found and 54 false alarms per 100 ordinary pushes after the decision-engine
classifier. The hook as shipped found 0 of 12.

Current situation: the hunter's search prompt is a hand-written string, its family answer is free text,
and it never sees the diff. Of 343 ordinary-push suspicions the classifier called `vulnerable`, 250 sit
more than 10 lines from any changed line: the hunter re-reports the repo's old code on every push. Every
precision gain so far was a hand rule or a threshold picked after looking at the misses, in-sample. A
threshold on today's output is a coin flip dressed as a decision. The learning harness that compiles the
decision-engine classifier (bootstrapped demonstrations, instruction proposals, grouped folds, a leak
audit, paired A/B experiments with cluster bootstrap, a cached and replayable model caller) exists, but
the hunter does not run on it, and the compile step accepts the best score on one validation split with
no train-against-holdout check, no per-family regression check, and no prompt length cap.

What should change: the search gets better before anything is thresholded. The hunter receives an
annotation model: a named, versioned set of facts about the push computed from the repository (changed
hunks with line numbers, the enclosing function and its callers, entry-point evidence, source, sink and
sanitizer roles, framework facts, def-use inside the function, guards and obligations, closed taxonomy
families with the classifier's answer format). Which facts the model needs is decided by statistical
ablation: each annotation is switched on and off in pre-registered, paired experiments over the same
changes, and its effect on search recall over fix sites and on suspicions per ordinary push is reported
per family with intervals. An annotation or a prompt change is kept only when it helps on held-out folds.
Labels come from the benchmark's rule: a suspicion is a true positive when it lands on a verified fix
site, a false positive when it sits on an ordinary push. Training data is sourced separately (about 100
advisories through the fix-site catalog and verifier, about 40 accepted positives) with repository-level
folds and the leak audit; the 252-change pilot stays held out and is only used to report the gain.
Thresholds and operating points come after the search is good; this spec reports the whole recall
against false-alarm curve and sets none. The proof arm runs only on what survives.

## Introduction

This spec turns the LLM hunter from a hand-written prompt into a measured search stage. It owns four
things: the labelled data the loop learns from, the annotation model the hunter is given about a push,
the ablation method that decides which annotations stay, and the rule by which a changed prompt or
annotation set is kept or thrown away. It reports in the benchmark's own terms: recall, false alarms per
100 pushes, precision, per family, with intervals. It sets no threshold.

## Boundary Context

- **In scope**: labelling hunter suspicions from fix-site positives and ordinary pushes; sourcing a
  training set separate from the held-out pilot; the annotation model and its producers; statistical
  ablation of annotations; the hunter as a versioned, replayable compiled program; the acceptance rule
  for a prompt, demonstration or annotation-set change; re-measuring the pilot and reporting the gain.
- **Out of scope**: choosing confidence or scope thresholds and operating points (later, once the search
  is measured good); wiring the compiled hunter into the pre-push hook (`pre-push-safety-net`); the proof
  arm itself (`search-with-proof`, `proof-arm-opencode`); building new deterministic analyses such as a
  whole-repo call graph or taint engine (`engine-change-scoped-analysis` owns those; this spec consumes
  what exists); growing the benchmark beyond what this loop needs (`valid-detection-benchmark`).
- **Adjacent expectations**: the fix-site catalog and verifier produce the labels; the benchmark scorer
  and metrics are the only scorekeepers; the decision-engine classifier stays as the second stage and is
  not retrained here; the earlier freeze on hunter changes ("no hunter prompt, tool or configuration may
  change before that measurement") is lifted by the pilot measurement, which is the baseline.

## Decision strategy, corrected 2026-10-14

The maintainer's finding after the second access-control screen: the annotations this loop selected and
screened were software features, not security features. Counts of callers, entry points, calls, binds,
function length, diff shape, language and framework describe the code around a change; none of them
determines that the code is unsafe, and a decision model fitted on them learns the pool (the deletion count
separates reversed fixes at 0.90) and generalises to nothing. "If you build a safety net and only send
information unrelated to security, the expected result is nothing."

What decides safety for the access-control family is a property of a path, in order: an entry an attacker
can reach, request-derived data reaching a protected operation along that path, and no required check
dominating the operation by control flow. That object, the ordered trace with argument provenance and
control-flow dominance, is specified and built in `access-control-prover` (requirements 9 and 10). From
this date:

1. The hunter's input is the trace, not the feature table. Shape annotations may be rendered for context but
   are not decision features and the ablation shall not credit them as such.
2. The pool measures; it never trains. No model is fitted on the pool's labels, no prompt is compiled on the
   pool, no threshold is tuned on it. The verdict is a rule over the trace, the same on every repository;
   the facts naming entries, operations and checks are closed data with a stated source.
3. Where a judgement remains (is this entry meant to be public; is this operation protected somewhere the
   facts do not model), the judge reads the trace zero-shot with general security knowledge. The pool
   reports how often it is right; the unseen pilot says whether that holds elsewhere.
4. The ablation's remaining use is selection, not fitting: which trace components the judge needs to see,
   with intervals, read with the same suspicion as any in-sample number.
5. Requirements 3.3 and 4 below stand as written for the record of the first round; where they name shape
   annotations as the model's input, this section overrides them.

## Requirements

### Requirement 1: Labels from fix sites and ordinary pushes

**Objective:** As the maintainer, I want every hunter suspicion labelled true or false by the benchmark's
own rule, so that the loop learns from facts and not from my reading of the misses.

#### Acceptance Criteria
1. When a hunter suspicion names a path and line inside a verified fix-site function of a positive change,
   or within the benchmark scorer's location tolerance of it, and its family equals the change's family,
   the Learning Loop shall label it a true positive.
2. When a hunter suspicion is raised on an ordinary push, the Learning Loop shall label it a false positive.
3. When a hunter suspicion is raised on a positive change but outside every verified fix site of that
   change, the Learning Loop shall label it unknown and shall exclude it from training and scoring.
4. The Learning Loop shall label at the level of the suspicion (path, line, family), and shall also derive
   the push-level outcome (caught, alarmed) with the benchmark scorer, so that both the search stage and
   the push-level metric are measurable from the same records.
5. When a positive change is used for training, the Learning Loop shall record its fix-site verification
   record (model checks and human decision) next to the label, so that a label can be traced to its
   evidence.
6. If a label's source cannot be traced to a verified fix site or a frozen ordinary draw, the Learning
   Loop shall reject it.

### Requirement 2: A training set apart from the held-out pilot

**Objective:** As the maintainer, I want the loop to learn on data the benchmark never reports on, so that
the pilot number stays a measurement.

#### Acceptance Criteria
1. The Learning Loop shall source its training positives through the fix-site catalog and verifier from
   advisories and repositories that are not in the held-out pilot, and shall record the sourcing run.
2. The Learning Loop shall draw its training negatives as ordinary pushes from the training repositories
   only, at the benchmark's ratio of at least 20 ordinary pushes per positive change.
3. The training set shall contain at least 40 accepted positive changes across at least two languages
   before the first ablation result is reported; a run on fewer is marked a dry run.
4. While an ablation, compile or evaluation runs, the Learning Loop shall never read the held-out pilot's
   changes, labels or records, and every artifact shall record which data digests it did read.
5. The Learning Loop shall split the training set by repository group into folds, so that no repository
   appears on both sides of a split.
6. Before the first ablation, the Learning Loop shall run the leak audit over every annotation and shall
   report any annotation that separates positives from negatives on its own above the audit's threshold,
   so that an annotation that encodes the label is found before it is credited.
7. If a training repository is later found in the held-out pilot or in any benchmark report, the Learning
   Loop shall mark every run that used it as contaminated and shall exclude those runs from any reported
   gain.

### Requirement 3: The annotation model

**Objective:** As the maintainer, I want the facts the hunter sees about a push to be a named, versioned
set that each can be switched on or off, so that "enough information for the model" is something we can
measure rather than guess.

#### Acceptance Criteria
1. The Learning Loop shall define the annotation model as a versioned schema of named annotations, each
   with a producer, a bound on its size, and a digest, and shall record the schema version on every
   hunter run.
2. The Learning Loop shall compute every annotation from the repository at the push's revisions and from
   the tool's own framework knowledge only; no annotation shall read a label, an advisory, a CVE or GHSA
   identifier, a fix commit, or security-worded commit text.
3. The annotation model shall include at least: the changed hunks with head-side line numbers; the
   enclosing function's full text at head; the names and locations of that function's callers; entry-point
   evidence (an in-repo route, handler, command or public API that reaches the function); source, sink and
   sanitizer roles for the identifiers in the function; the framework facts that apply to the file;
   def-use evidence inside the function; the guards and obligations on the changed path; and the closed
   list of taxonomy families with a one-line definition each.
4. When an annotation's producer cannot compute it for a push, the Learning Loop shall record the
   annotation as absent with the reason, and shall not substitute a default that could be read as a fact.
5. The Learning Loop shall render the enabled annotations into the hunter's input in a fixed order with
   fixed labels, so that two runs with the same annotation set and the same push produce the same input.
6. The Learning Loop shall require the hunter's family answer to come from the closed list; an answer
   outside the list is recorded as `unknown` and counts against the program.
7. The Learning Loop shall require the hunter's answer in the same fixed structure the classifier uses
   (verdict, family, confidence, rationale, cited lines), and shall reject an answer whose cited lines
   fall outside the text it was shown.
8. When the hunter reports a suspicion, the Learning Loop shall record whether it lies on a changed line,
   within 10 lines of one, or farther away, so that scope is a measured property of every suspicion and
   not a filter.

### Requirement 4: Statistical ablation decides what the model needs

**Objective:** As the maintainer, I want each annotation's worth measured by switching it off, so that the
input the hunter gets is built from effects with intervals, not from intuition.

#### Acceptance Criteria
1. Before an ablation runs, the Learning Loop shall register it: the annotation set under test, the
   annotations switched off, the folds, the metric, the sample size, the budget and the decision rule.
2. The Learning Loop shall run every ablation arm over the same changes as its comparison arm, paired by
   change, with the same program, model and sampling, so that the only difference between arms is the
   annotation set.
3. For each ablation, the Learning Loop shall report the paired effect on search recall over fix sites
   and on suspicions per ordinary push, per family and pooled, with a 95% interval from a bootstrap
   clustered by repository and a paired test on the per-change outcomes.
4. The Learning Loop shall report, after a full ablation round, an importance table: for every
   annotation, its effect on recall and on suspicions per ordinary push when removed from the full set and
   when added to the baseline, with intervals and sample counts.
5. The Learning Loop shall keep an annotation in the hunter's input only when its removal lowers search
   recall or raises suspicions per ordinary push on held-out folds with an interval that excludes zero,
   or when its removal has no measurable effect and it is needed by an annotation that does.
6. If an annotation raises suspicions per ordinary push without raising recall, the Learning Loop shall
   drop it and shall record the result where the next round can see it.
7. The Learning Loop shall not use a confidence cut, a scope cut or any other threshold on the hunter's
   output as the quantity being optimised; confidence is reported, not tuned, in this spec.
8. The Learning Loop shall report the full recall against suspicions-per-push curve of each annotation
   set, so that a later operating-point decision has the whole curve and not one point of it.

### Requirement 5: The hunter as a compiled, replayable program

**Objective:** As the maintainer, I want every version of the hunter's prompt, demonstrations and
annotation set to be an artifact I can name, diff, replay and roll back, so that an improvement is a fact
and not a memory.

#### Acceptance Criteria
1. The Learning Loop shall store each compiled hunter as a single content-addressed artifact holding the
   instruction, the demonstrations, the annotation schema version and enabled set, the model, the data
   digests, every scored configuration and the spend.
2. When the hunter runs, the Learning Loop shall record the program id and the annotation set on every
   suspicion it emits.
3. The Learning Loop shall route every hunter model call through a cached, metered caller, so that a
   rerun of the same program on the same inputs reproduces the same answers at no cost.
4. The Learning Loop shall keep the scorer, the labels and the held-out data outside every surface the
   compile step may edit, so that a proposal cannot read its own answer key.
5. If a run exhausts its budget before finishing, the Learning Loop shall write no program artifact and
   shall report the run as unfinished with the spend so far.
6. The Learning Loop shall cap the instruction length per family, and shall reject a proposal that
   exceeds the cap regardless of its score.

### Requirement 6: Accepting or rejecting a change

**Objective:** As the maintainer, I want a prompt, demonstration or annotation-set change kept only when
it helps on data it was not tuned on, so that the loop cannot overfit its way to a better number.

#### Acceptance Criteria
1. When a candidate program is scored, the Learning Loop shall score it on the compile folds and on the
   held-out folds separately, per family, and shall report both.
2. The Learning Loop shall accept a candidate only when its compile-fold and held-out-fold results are
   both non-negative against the current program and at least one is strictly positive.
3. If any family's held-out result falls below its regression budget, the Learning Loop shall reject the
   candidate, whatever the aggregate shows.
4. If a candidate ties the current program within the pre-registered tolerance, the Learning Loop shall
   reject it.
5. The Learning Loop shall report every result with its sample count and a 95% interval, and shall not
   accept a candidate on a point estimate alone.
6. The Learning Loop shall keep rejected candidates and their scores where the next proposal round can
   see them, and shall never show the held-out results to the proposer.
7. When a candidate is accepted, the Learning Loop shall record the comparison (both programs' ids, both
   fold results, the decision rule) in the new program's artifact.
8. The Learning Loop shall change one thing per round (one annotation, or one instruction, or one
   demonstration set), so that an accepted gain is attributable.

### Requirement 7: Two stages, reported for what each owns

**Objective:** As the maintainer, I want the search stage and the classifier stage measured separately,
so that we fix the search problem before paying for proof.

#### Acceptance Criteria
1. The Learning Loop shall report the search stage on recall over verified fix sites (did a suspicion land
   on the fix site with the right family) and on suspicions per ordinary push, per family.
2. The Learning Loop shall report the classifier stage on precision over the suspicions the search stage
   emitted, and on the push-level false alarms per 100 ordinary pushes after it, per family.
3. The Learning Loop shall report the combined push-level result as recall, false alarms per 100 pushes
   and precision with 95% intervals, in the benchmark's names and no coined ones.
4. The Learning Loop shall report the gate distance on every run: the recall reached at 10 false alarms
   per 100 pushes and the false alarms at 90% recall, read off the curve, as a report and not as a tuned
   operating point.
5. The Learning Loop shall not retrain or recompile the classifier stage within this spec; a classifier
   change is a separate experiment.

### Requirement 8: Measuring the gain on the pilot

**Objective:** As the maintainer, I want one number that says what the loop bought, measured on the data
it never saw, so that the decision to put the hunter on pre-push rests on evidence.

#### Acceptance Criteria
1. When a compiled hunter is accepted, the Learning Loop shall run it once over the held-out pilot's 252
   changes with the same scorer and metrics as the pilot, and shall write the result next to the pilot's
   measurement.
2. The Learning Loop shall report the gain as the before-and-after of search recall, suspicions per
   ordinary push, push-level recall, false alarms per 100 pushes and precision, per family, with
   intervals, against the pilot's recorded hunter numbers.
3. The Learning Loop shall report, for the same run, the number of suspicions the proof arm would have to
   handle per 100 pushes, so that proof's workload is a measured count.
4. The Learning Loop shall prove its instrument in every pilot run: for each change it shall record bytes
   read per changed file and the verified base and head, and shall mark a change with nothing readable as
   an instrument failure rather than a clean result.
5. If a pilot run's instrument failures exceed 5% of changes, the Learning Loop shall report the run as
   invalid and shall not quote its numbers.
6. The Learning Loop shall run the pilot at most once per accepted program, and shall record each run, so
   that the pilot is not used as a tuning surface.

### Requirement 9: Cost, secrets and unattended runs

**Objective:** As the operator, I want ablation and compile runs to stay inside a budget, keep the model
key out of every record, and finish without me, so that the loop can run overnight on the research host.

#### Acceptance Criteria
1. The Learning Loop shall take a pre-registered budget in money and calls per run and shall stop at the
   first exceeded bound.
2. The Learning Loop shall never write a model key, or an exception message that could carry one, into a
   record, a log or an artifact; an error is recorded by its type.
3. When a run is interrupted, the Learning Loop shall resume from its recorded progress without repeating
   finished model calls.
4. The Learning Loop shall write its outputs outside the repository checkout and shall keep each record
   once, so that an overnight run cannot fill the host's disk with duplicates.
5. The Learning Loop shall report, at the end of every run, the spend, the calls, the replay hits and the
   wall time.
