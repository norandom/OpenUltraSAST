# Requirements Document

## Introduction

OpenUltraSAST's detection numbers cannot be trusted and cannot be improved. The static machinery is treated as the detector while the model with tools already outperforms it (12/14 versus 5/14 pair-correct on the vibe-py holdout once scoring is keyed on class and function), the pair scorer keys detection on text tokens rather than on a vulnerability class, the improve loop learns from its own holdout pairs, and no change is attributed to the class it targets, so an improvement in one class silently degrades another. This feature turns the tool into a learning harness: an auto-classifier assigns every labeled pair, finding and code region to one of ten verifier-aligned families; one detector configuration per family is evolved round by round from structured failure facts; a class-aware, pair-wise scorer with unscorable denominators and a measured per-family noise floor decides acceptance; only verifier-confirmed claims are reported above suspicion; and the train/holdout split is enforced by construction. Context, measurements and sources: `brief.md`, `research.md`, `benchmarks/measurements/2026-09-06-*`.

## Boundary Context

- **In scope**: the class taxonomy and its classifier; the class-aware pair scorer and unscorable-row accounting; split enforcement for every learning path; per-family detector configurations and their routing; class-keyed verifiers and reporting rungs; the round-based evolve loop with attribution; the corpus repairs the loop needs; publishing every number with its denominator and noise floor.
- **Out of scope**: finding bugs in JavaScript interpreters, WebGL renderers or browser engines; memory-safety fuzzing or crash oracles for C and C++ (the vfc slice stays a measured, non-gating slice under one coarse family); new hand-written static shape families; changes to the evidence ladder or dispositions; merge gates on non-local slices; vendoring new pairs beyond re-harvesting existing recipes; fine-tuning model weights.
- **Adjacent expectations**: the pair corpus (`pair-corpus-honesty`) keeps owning labels, tiers, splits and `known_limit`; `corpus-seeded-mechanisms` keeps its exporter, leave-one-out and lever, which this feature subordinates to the split and the class attribution; `authorization-obligations` keeps its checker, whose corpus tasks 4.3 and 6.1 move here and whose lever task 5 becomes the access-control family's first round; the local detection, map and pair gates stay byte-identical; HarnessX and tree-sitter grammars remain optional extras and every step that needs them degrades to a recorded reason without them.

## Requirements

### Requirement 1: A closed, versioned class taxonomy aligned to verifiers

**Objective:** As a maintainer, I want every unit of detection work to belong to one of a small set of named families, so that detection, silence, leaks and improvements have a definite meaning.

#### Acceptance Criteria

1. The Learning Harness shall define a closed, versioned taxonomy of exactly these families: injection into a query or command; file path from user input; deserialization of untrusted data; access control; output encoding; server-side request forgery; prototype pollution and unsafe object merge; permissive configuration and secrets; memory safety; unknown.
2. The Learning Harness shall record for every family the CWE identifiers it covers, the mechanism ids it covers, and the verifier that can confirm a claim in that family or the statement that none exists.
3. When the taxonomy changes, the Learning Harness shall bump its version and every published number shall name the taxonomy version it was scored under.
4. The Learning Harness shall treat CWE identifiers and mechanism ids as attributes of a family and shall never use them as the key that routes work or scores a pair.

### Requirement 2: An auto-classifier that is measured on its own

**Objective:** As a maintainer, I want a classifier that assigns families to pairs, findings and code regions and reports its own accuracy, so that routing errors are visible instead of hidden inside detector numbers.

#### Acceptance Criteria

1. When given a labeled pair, a finding or a code region, the Learning Harness shall return zero or more families plus, when nothing is admitted, the `unknown` family, and shall record which tier decided each answer: deterministic static signals, a model judgment, or none.
2. The Learning Harness shall attempt deterministic classification from static signals before consulting a model, and shall consult a model only for what static signals cannot place.
3. When the classifier is evaluated, the Learning Harness shall report agreement with maintainer labels on reviewed pairs with partial credit for a parent–child relation and no credit for a lateral or fabricated family, a confusion matrix per family, and its accuracy against both a random router and an oracle router.
4. When the classifier disagrees with a maintainer label, the Learning Harness shall queue the disagreement for review and shall not change the label.
5. The Learning Harness shall classify every labeled row in the corpus, including rows whose current class is free text or `other`, and shall report the count classified per family and the count left `unknown`.

### Requirement 3: A class-aware, pair-wise scorer

**Objective:** As a maintainer, I want pairs scored on whether the labeled family was found in the labeled function, so that a detector is credited for the bug it was asked about and nothing else.

#### Acceptance Criteria

1. When scoring the vulnerable side, the Learning Harness shall count a detection only for a finding inside the labeled function whose family matches the labeled family, with partial credit for a parent–child relation and the maximum penalty for a fabricated family.
2. When scoring the fixed side, the Learning Harness shall count silence only when no finding of the labeled family lies inside the labeled function, and shall report findings of other families or outside the function separately, never as leaks.
3. The Learning Harness shall report every pair as exactly one of pair-correct, both-sides-flagged, both-sides-silent, or reversed, and shall report per family and per slice the counts of each outcome, recall, silence, Youden and a directional-bias index.
4. The Learning Harness shall report a fixed-false-positive-rate view per family beside Youden.
5. When a detector is evaluated, the Learning Harness shall run it at least three times per pair and shall report a change against the last blessed round only when a reliable-change test passes, together with the negative-flip count per family.
6. The Learning Harness shall never count a text token, a CWE string or a sink name in a finding's text as evidence of detection.

### Requirement 4: Unscorable rows and corpus hygiene

**Objective:** As a maintainer, I want rows that cannot be scored removed from every denominator with a stated reason, so that no number carries a permanent loss that no detector could avoid.

#### Acceptance Criteria

1. The Learning Harness shall mark a pair unscorable with one of these reasons: identical twin, unsupported language, unresolved function label, missing registration context, or a maintainer-declared known limit; and shall exclude it from recall, silence, Youden and negative-flip denominators while still listing it.
2. The Learning Harness shall never delete a catalog row; an unscorable row shall keep its reason in the catalog.
3. When pairs are loaded, the Learning Harness shall detect identical twins by comparing normalized excerpt bodies with headers stripped, and shall report duplicates across pairs before any split is applied.
4. The Learning Harness shall assign train and holdout membership by repository and in date order, so that no two pairs from one repository straddle the split.
5. When a published number is shown, the Learning Harness shall show the scorable count, the unscorable count by reason, and the taxonomy version beside it.

### Requirement 5: The split is enforced by construction

**Objective:** As a maintainer, I want it impossible for any learning path to see a holdout pair, so that a holdout number means what it says.

#### Acceptance Criteria

1. When any exporter, lever or evolve round seeds, proposes or validates from pairs, the Learning Harness shall use only train-split pairs as teachers.
2. If a candidate change was taught by, or touches, any holdout pair, then the Learning Harness shall refuse it and record the refusal with the pair names.
3. The Learning Harness shall re-measure the existing mechanism lever under this rule and shall publish the corrected holdout number in place of the earlier one.
4. While an evolve round proposes changes, the Learning Harness shall not expose holdout inputs, outputs or scores to the proposer.

### Requirement 6: One detector configuration per family

**Objective:** As a maintainer, I want each family to have its own detector configuration that other families' changes cannot alter, so that improvements do not interfere.

#### Acceptance Criteria

1. The Learning Harness shall hold one detector configuration per family consisting of a prompt under a stated length cap, a skills set, a curated tool set, a step budget, a cost budget, an evidence checklist and a set of hard negatives and counterexamples.
2. While a round evolves one family, the Learning Harness shall keep every other family's configuration unchanged.
3. When a code region is classified, the Learning Harness shall run the detector of every admitted family plus a generalist detector, and shall record on each finding the family, the detector configuration version and the verifier outcome.
4. The Learning Harness shall give a detector the whole file of a region and the files its curated tools resolve, not only an excerpt around a hotspot.
5. The Learning Harness shall expose to a detector only curated tools that read, search and resolve symbols within the scanned repository, and no general shell.
6. The Learning Harness shall run detectors, the classifier's model tier and the evolve proposer on a configurable chat endpoint that is independent of the embedding endpoint, with a cheap model as the default and a stronger model reserved for the second judge and for review-queue disagreements.

### Requirement 7: Only a verifier raises a claim above suspicion

**Objective:** As an operator, I want to know that anything reported above suspicion was confirmed by something other than the model, so that reports stay honest.

#### Acceptance Criteria

1. The Learning Harness shall report a detector claim at `suspicion` unless a verifier keyed to the claim's family confirms it.
2. Where a family has a sandbox oracle, the Learning Harness shall confirm a claim by executing a family-specific snippet whose oracle is a canary observable only through the vulnerability (a canary row for injection, a canary file for command execution and traversal, a canary object for deserialization).
3. Where a family has only static corroboration (access control through the obligations checker), the Learning Harness shall raise a claim no higher than static corroboration.
4. Where a family has no verifier, the Learning Harness shall report at `suspicion` only and shall still score that family class-aware on the corpus.
5. When a claim is reported as proven, the Learning Harness shall obtain a second, independent judgment before publishing it as proven.
6. The Learning Harness shall keep verifier code, oracles and gold labels outside every surface an evolve round can edit.

### Requirement 8: Round zero establishes the baseline and the noise floor

**Objective:** As a maintainer, I want a controlled baseline and a measured noise floor per family before any learning, so that later gains and regressions are distinguishable from noise.

#### Acceptance Criteria

1. When round zero runs, the Learning Harness shall clone the current hunter into every family's configuration unchanged.
2. When round zero runs, the Learning Harness shall run each family's detector five times over the scorable vendored pairs at deterministic settings and shall record the per-family negative-flip rate between runs as that family's regression budget.
3. The Learning Harness shall publish round zero's per-family outcomes, noise floors and cost per pair before the first evolve round.
4. The Learning Harness shall run round zero first on the web families over the vibe-py and agent-vfc slices; the memory-safety family over the vfc slice is measured but never gates a round.

### Requirement 9: An evolve round improves one family under attribution

**Objective:** As a maintainer, I want each round to change one thing for one family and to be accepted only when the change helps that family without hurting any other, so that the system cannot degrade in ways nobody predicted.

#### Acceptance Criteria

1. When a round starts, the Learning Harness shall give the proposer structured failure facts for the target family (which pair, which function, which sink or check, which line, which verifier outcome) and the buffer of previously rejected proposals, and shall not give it free-form self-critique or holdout material.
2. The Learning Harness shall accept at most one change to one family per round, and the change shall be a tool, a checklist, a counterexample, a memory entry, or a prompt edit within the family's length cap.
3. When a round records its proposal, the Learning Harness shall journal a hypothesis, the levers changed, the family predicted to improve, and the families predicted to be at risk.
4. When a round is evaluated, the Learning Harness shall score the target family on a train minibatch, then on the target family's full holdout, then sweep every other family's holdout.
5. If the target family's train score or holdout score decreases, or neither strictly increases, or any other family's negative flips exceed its regression budget, then the Learning Harness shall reject the round, revert the change and record the reason.
6. When a round is accepted or rejected, the Learning Harness shall record attribution: which pairs flipped in the predicted family, which flipped in unpredicted families, and the resulting precision of the prediction.
7. The Learning Harness shall keep, per family, an archive of which configuration wins which pair, rather than one champion configuration.
8. If a round exceeds its cost cap, then the Learning Harness shall stop it, revert it and record the overrun.
9. The Learning Harness shall retain a model-authored skill, tool or prompt edit only after it passed the acceptance rule and was journaled with its attribution.

### Requirement 10: Corpus repairs the loop depends on

**Objective:** As a maintainer, I want the corpus defects that cap every number fixed before detectors are tuned against it, so that a detector change and a corpus artifact are distinguishable.

#### Acceptance Criteria

1. The Learning Harness shall parse TypeScript rows so that they are scorable rather than counted as unsupported.
2. When absence-labeled rows are re-harvested, the Learning Harness shall keep each handler with its decorators and registration statements, and every re-harvested excerpt shall keep its license line and pass redaction.
3. The Learning Harness shall mark the five byte-identical vibe-py twins unscorable with the reason identical twin.
4. If a unit-test fixture is strictly easier than the corpus rows its test names (fewer binding hops to the identity source, registration present when the corpus rows lack it), then the Learning Harness shall fail that check.
5. The Learning Harness shall carry a slice of pairs dated after the detector model's training cutoff and shall report it separately.

### Requirement 11: Publishing and operations

**Objective:** As a maintainer, I want every number regenerated from one command with its denominator, noise floor and cost, so that the roadmap cannot drift from the measurement.

#### Acceptance Criteria

1. When the roadmap numbers are regenerated, the Learning Harness shall produce them from one command and shall write the command, the taxonomy version, the scorable and unscorable counts, the noise floor and the cost per point beside every number.
2. The Learning Harness shall commit the raw measurement artifacts of every published number.
3. The Learning Harness shall persist every detector trajectory and every round's journal, redacted, so that a round can be replayed.
4. If a budget cap, a failing endpoint or a missing optional extra interrupts a run, then the Learning Harness shall record the reason and complete the remaining steps that do not depend on it.
5. The Learning Harness shall leave the local detection, map and pair gate outputs byte-identical to the pre-feature commit.
