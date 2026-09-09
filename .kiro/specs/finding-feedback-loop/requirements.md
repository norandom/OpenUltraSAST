# Requirements Document: finding-feedback-loop

## Introduction

Nine engine defects were found in one session against two repositories. **Three were the same bug in three
matchers** — a spec token matched as a substring rather than a word: `resolve` inside `resolveUrl` in the
sanitizer matcher, `user` inside `users` in the discharger matcher, `gets` inside `fgets` in the sink matcher.
Each was found by a measurement, fixed locally, and left no trace; the third survived until an 89k-line C
library made it visible as 26 identical false positives.

Nothing in the system remembers that a finding was wrong. There is no artifact saying *this site, at this
rung, is not a defect, and here is why* — so a class recurs, and each recurrence costs another measurement.

Two audiences want that artifact for different reasons. A maintainer wants the *propagation* automated: two of
the three matcher bugs needed no judgement at all, only the fix carried across. A developer wants to dismiss a
finding in their own repository, have it stay dismissed, and have the reason reviewable beside the code — a
tool that cannot be told it is wrong is one they stop running.

This feature is bounded by a rule the project has held from the start and a leak that shows why. An optimiser
may evolve **the question** — the judge and residual prompts, which are how we ask. It may never author **the
facts** — tables, rulesets, the declared policy file, which are what we claim. On 2026-09-05 the improve lever
admitted candidate shapes because they "recover a currently missed holdout pair"; five of eleven were taught by
the holdout pairs they then recovered, and a holdout Youden of **−0.059 was reported as +0.059**.

Context: `brief.md`, `.kiro/specs/contributor-scan/` (Req 8 on overfitting, Req 10 on baselines), the memory
`closed-loop-train-on-test-leak`, and the measurements
`2026-09-09-repo-vampi-authz-precision.json` and `2026-09-09-repo-libpng-bounds.json`.

## Requirements

### Requirement 1: A dismissal the developer owns

**Objective:** As a developer, I want to record that a finding is not a defect in my repository, so it stays
recorded and my colleagues can see why.

#### Acceptance Criteria

1. The system shall read dismissals from a declarative file in the **target** repository, and shall never
   write to it — the same rule the declared policy file already follows.
2. A dismissal shall carry the site it concerns, the rung it was dismissed at, a reason, and an author.
3. The system shall reject a dismissal that carries no reason, because a suppression list without reasons is
   a graveyard nobody can audit.
4. The system shall report a dismissed finding as dismissed, with its reason, rather than omitting it — so a
   stale dismissal is visible rather than silent.
5. When a dismissal no longer matches any finding, the system shall say so, because a dismissal that has
   stopped applying is either a fixed bug or a moved target and both are worth knowing.

### Requirement 2: A counter-example ledger the maintainer can group

**Objective:** As a maintainer, I want every rejected finding recorded with what produced it, so a recurring
cause is visible as a cause rather than as five separate bugs.

#### Acceptance Criteria

1. When a finding is contradicted — by a dismissal, by the judge with coverage, or by a declared contract —
   the system shall record the site, the rung, the witness, the spec tokens that produced it, and the commit.
2. Each ledger entry shall be runnable as a regression case: this site, at this commit, shall not be reported
   at that rung.
3. The ledger's regression cases shall run offline in CI, so that re-introducing a fixed cause fails a test
   rather than a repository scan four weeks later.
4. The system shall group ledger entries by what they share — spec token, matcher clause, family, witness
   shape — and report the groups by size.
5. The ledger shall be committed evidence, not a local artifact.

### Requirement 3: A model may propose a cause, and only propose it

**Objective:** As a maintainer, I want the model to do the part that needs judgement — naming what a group of
counter-examples has in common — without it deciding anything.

#### Acceptance Criteria

1. Given a group of counter-examples, the system shall ask a model for a hypothesis: what these share, and
   what change would remove all of them.
2. The model's output shall be written to a review queue, and shall never be written to a fact table, a
   ruleset, or the declared policy file.
3. An adoption shall require a human commit, exactly as any other change to those files does.
4. The system shall be validated by reverting the three known matcher fixes and measuring how many of their
   groups it recovers and what it proposes. A model that cannot rediscover a cause already known shall not be
   trusted to propose one that is not.

### Requirement 4: Dismissals are a labelled evaluation set

**Objective:** As a maintainer, I want a repository's dismissals and its known vulnerabilities to form one
evaluation set, so an optimiser has both classes rather than only the negatives.

#### Acceptance Criteria

1. The system shall build a per-repository evaluation set from a `benchmarks/repos/` recipe's known
   vulnerabilities and that repository's dismissals.
2. The evaluation set shall declare a train/holdout split.
3. The system shall not read the holdout during optimisation, and a test shall assert it.
4. The system shall report the size of both classes, because an evaluation set of negatives alone can only
   teach silence.

### Requirement 5: Evolution targets the question, never the facts

**Objective:** As a maintainer, I want the prompts to improve against real rejections without the fact tables
ever being authored by a model.

#### Acceptance Criteria

1. The system shall support reflective evolution over the judge and residual questions only.
2. The system shall not modify sources, sinks, sanitizers, obligations, dischargers, rulesets or the declared
   policy file by any automated means.
3. An evolved prompt shall be scored on the train split alone.
4. An evolved prompt shall be adopted only when it affirms fewer dismissed sites **and** loses no known
   vulnerability.
5. The three gates shall stay byte-identical across an adoption, or the adoption is a regression wearing a
   fix's clothes.

### Requirement 6: An adoption reports what it cost

**Objective:** As a maintainer, I want to see what an adoption traded, because a false-positive reducer that
quietly loses recall is worse than none.

#### Acceptance Criteria

1. Every adoption shall record precision and recall before and after, on the pinned repositories and on the
   pair corpus.
2. Every adoption shall record which counter-examples it removed and which it did not.
3. A net-negative adoption shall be reverted automatically rather than argued about.
4. The system shall record what a target repository's evolved state learned and what it was measured against,
   so per-repository tuning is legible rather than a black box.

### Requirement 7: The loop inherits the corpus's blind spot

**Objective:** As a maintainer, I want this loop measured on the evidence that can actually see its failures.

#### Acceptance Criteria

1. The evaluation set shall include whole repositories, not pairs alone: the pair corpus could not see any of
   the nine defects that motivate this feature, and the gates stayed byte-identical through every fix.
2. The system shall state how many repositories its evidence base contains, because two — one of which has
   never produced a true positive — is very little to tune against.
3. Where an adoption is measured on one repository only, the system shall label it as such rather than
   reporting it as a general improvement.
