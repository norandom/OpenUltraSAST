# Requirements Document

## Introduction

The detector's instability is structural, not statistical. Measured on 2026-09-06 over twelve injection pairs at
temperature 0 with thinking disabled, **120 runs produced 120 distinct tool-call trajectories** — not one repeat —
and outcome disagreement tracks trajectory divergence (30.9% at low similarity against 4.2% at mid). The model
spends its budget searching: 555 `grep_repo` calls against 71 `entry_points`, guessing where sinks are while the
semantic IR already knows. So `learning-harness`'s K runs are an ensemble of distinct search procedures rather than
repeated measurements, and the noise floor it derives a regression budget from measures how often an unconstrained
search happens to reach the sink.

This feature removes the freedom instead of averaging over it. A deterministic pass enumerates the candidate sites
inside the labeled region from the IR; the model is asked one bounded, typed question per candidate with no tools
and no choice of what to look at; and the predicates the scorer already applies after the fact are enforced at
generation time with a bounded retry. The candidate generator was measured before anything was built: the pattern
ruleset caps recall at 12.1%, below the 64.9% the unconstrained loop already reaches, while the semantic IR caps it
at 96.6% with a median of ten sites per labeled function.

Baseline to beat, `deepseek-v4-flash`, K = 5, 57 scorable web pairs: **detection 64.9%, leak 12.3%, pair-correct
52.6%** — and 83.3% detection on hand-written vibe-py against 44.4% on agent-written agent-vfc, which is the gap
this feature must close rather than widen. Context and measurements: `brief.md`,
`benchmarks/measurements/2026-09-06-trajectory-divergence.json`, `2026-09-06-candidate-ceiling.json`.

## Boundary Context

- **In scope**: candidate enumeration from the semantic IR, per family shape; the typed, toolless judgment step;
  constraint predicates enforced at generation time with a bounded retry; the evidence that decides whether the
  K-run and noise-floor machinery still earns its place; per-slice reporting that keeps real-world code in front.
- **Out of scope**: the family taxonomy, the classifier, the pair scorer's outcome rules, the split, the verifier
  boundary and write roots, redaction, the three gates, and the publication machinery — all of which stand and are
  what made this feature's measurements possible. Also out: prompt optimisation, reflective evolution and any
  optimiser (deferred to a later spec, on this feature's evidence); finding bugs in JavaScript interpreters, WebGL
  renderers or browser engines; memory-safety fuzzing for C and C++; fine-tuning model weights; adopting DSPy as a
  dependency.
- **Adjacent expectations**: `learning-harness` keeps owning the taxonomy, the scorer, the split and publication;
  its Req 3.5 (K runs), 8.2 (noise floor) and 9.5 (acceptance) are amended by this feature only on evidence it
  produces, never on argument. The pair corpus keeps owning labels, tiers and splits. The unconstrained tool hunter
  stays as the generalist and as the baseline this feature is measured against.

## Requirements

### Requirement 1: Candidates come from the semantic IR, and the enumerator's ceiling is published

**Objective:** As a maintainer, I want the sites a detector judges to be enumerated deterministically, so that the
model stops searching and the limit of what it can possibly find is a number rather than a hope.

#### Acceptance Criteria

1. The Constrained Detector shall enumerate candidate sites for a region from the semantic IR — call sites and
   bindings — and shall not use the pattern ruleset as its candidate generator.
2. The Constrained Detector shall shape candidates by family: a call site for injection, path, deserialization,
   untrusted destination and prototype; an operation on a protected resource with the guards in scope for access
   control; a configuration assignment or literal for permissive configuration and secrets.
3. The Constrained Detector shall publish, per family and per slice, the fraction of labeled functions for which at
   least one candidate was enumerated, and shall name that fraction as the ceiling on its recall.
4. If the semantic IR cannot parse a side, then the Constrained Detector shall record `unsupported_language` and
   shall score nothing for that pair rather than falling back to a search.
5. If a labeled function yields no candidate site, then the Constrained Detector shall record `no_candidate` and
   report that pair as unscorable with that reason rather than as a miss.
6. While enumerating, the Constrained Detector shall bound the candidates handed to one judgment call and shall
   record the bound and the number discarded when a region exceeds it.

### Requirement 2: One bounded, typed question per candidate, with no search

**Objective:** As a maintainer, I want the model to answer only what a model is needed for, so that two runs of the
same detector on the same input take the same path.

#### Acceptance Criteria

1. The Constrained Detector shall call the model with the candidate site, its enclosing function, the binding chain
   the IR resolved for its arguments, and the guards in scope, and shall offer it no tools.
2. The Constrained Detector shall require a typed answer per candidate: a verdict, the expression it believes
   carries untrusted input, the guard it found or the statement that there is none, and the family.
3. The Constrained Detector shall derive every finding from a typed answer and shall never parse a finding out of
   free prose.
4. When the detector is run twice on the same input with the same configuration, the sequence of model calls shall
   be identical, and a test shall assert this.
5. The Constrained Detector shall record, for every claim, the candidate that produced it, so that a claim is
   traceable to the site it was asked about.

### Requirement 3: Real-world code decides, and the gap to teaching code is published

**Objective:** As a maintainer, I want changes judged on code from real projects rather than on hand-written
teaching examples, so that the tool is not tuned for cases nobody has.

#### Acceptance Criteria

1. The Constrained Detector shall report every number per slice and shall never publish an aggregate across slices
   without the per-slice numbers beside it.
2. The Constrained Detector shall designate the slices harvested from real projects — agent-vfc, vfc-js, vfc and
   github — as the deciding slices, and the hand-written vibe-py slice as a development slice that cannot on its
   own justify accepting a change.
3. If a change improves the development slice and regresses any deciding slice, then the Constrained Detector shall
   reject it, and the rejection shall name the slice that regressed.
4. The Constrained Detector shall publish the **overfitting gap** — development-slice detection minus deciding-slice
   detection — beside every headline number, and shall state that the baseline gap is 83.3% against 44.4%.
5. The Constrained Detector shall measure and publish the candidate ceiling separately for the real-world slices,
   because the functions there are larger than the teaching corpus's and the enumerator's behaviour on them is not
   implied by its behaviour on vibe-py.
6. While the deciding slices carry no pair a learning path may teach from, the Constrained Detector shall state that
   with every number it publishes rather than presenting the development slice as if it were the corpus.
7. The Constrained Detector shall keep memory safety measured and non-gating, and shall not let the 176 vfc rows
   dominate an aggregate that a reader would take as the tool's web-taxonomy performance.

### Requirement 4: The predicates that score a finding also constrain it

**Objective:** As a maintainer, I want the checks that decide whether a finding counts applied while it is being
made, so that a violation is corrected rather than silently discarded.

#### Acceptance Criteria

1. The Constrained Detector shall express as predicates the checks the scorer already applies: the reported line
   falls inside a parsed function, the named sink occurs at that line, the claimed family is in the taxonomy, and
   the claimed source expression appears in the enclosing function.
2. When a predicate fails, the Constrained Detector shall retry the judgment once with the failed answer and the
   predicate that rejected it, and shall not retry more than once per candidate.
3. If a retry also fails a predicate, then the Constrained Detector shall discard the claim and record the predicate
   that rejected it, and shall count that discard in a published tally.
4. The Constrained Detector shall apply the same predicates at generation time and at scoring time from one
   definition, so the two cannot drift apart.

### Requirement 5: The noise machinery is re-measured, and kept only if it earns its place

**Objective:** As a maintainer, I want the K runs, the noise floor and the regression budget re-measured against a
constrained detector, so that machinery built for an unconstrained one is deleted rather than maintained.

#### Acceptance Criteria

1. The Constrained Detector shall re-run the trajectory measurement against itself and shall publish the resulting
   distinct-trajectory count per pair.
2. The Constrained Detector shall re-measure the per-family noise floor at the same K as the baseline and shall
   publish it beside the baseline's floor.
3. If the re-measured floor is zero for a family, then the Constrained Detector shall report that family's K-run
   requirement and its regression budget as unnecessary and shall name the `learning-harness` requirements that
   would be amended.
4. The Constrained Detector shall state, wherever a K-run number is published, whether the runs were repeated
   measurements or an ensemble of distinct procedures.

### Requirement 6: The constrained detector is measured against the unconstrained one, on the same corpus

**Objective:** As a maintainer, I want one comparison that says whether this was worth building.

#### Acceptance Criteria

1. The Constrained Detector shall be scored by the existing class-aware pair scorer, with the same denominators,
   the same unscorable vocabulary and the same split, and shall introduce no scoring rule of its own.
2. The Constrained Detector shall publish detection, leak and pair-correct rates against the recorded baseline of
   64.9%, 12.3% and 52.6%, per slice and in total.
3. The Constrained Detector shall publish its cost per correct pair against the baseline's $0.030 on vibe-py and
   $0.136 on agent-vfc.
4. If the constrained detector's detection rate is below the unconstrained loop's on any deciding slice, then that
   shall be published as the headline of the comparison rather than as a footnote.
5. The Constrained Detector shall keep the unconstrained tool hunter available and shall not remove it while it
   scores higher on any deciding slice.

### Requirement 7: Degradation, budget and boundaries

**Objective:** As a maintainer, I want the same operational contract the rest of the tool has.

#### Acceptance Criteria

1. The Constrained Detector shall run behind the existing chat endpoint resolution and shall record
   `learning_endpoint_unavailable` and score nothing rather than fall back to another provider.
2. The Constrained Detector shall meter its own spend through the client's meter and shall stop when a configured
   cap is crossed, recording what it had spent.
3. The Constrained Detector shall leave the detection, map and local pair gate outputs byte-identical.
4. The Constrained Detector shall keep the core install at zero dependencies, and every optional capability it uses
   shall degrade to a recorded reason without its extra.
5. The Constrained Detector shall pass every prompt and every persisted trajectory through redaction.
